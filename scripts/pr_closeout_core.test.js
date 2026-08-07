const assert = require('node:assert/strict');
const test = require('node:test');

const {
  MANDATORY_CHECKS,
  buildCheckPlan,
  classifyOutput,
  findCommandFailureNeutralizer,
  scanSuppressionText,
  validateEngineChecks,
} = require('./pr_closeout_core');

const EXPECTED_IDS = [
  'git-diff-check',
  'pnpm-audit',
  'prisma-validate',
  'prisma-generate',
  'queue-registry-tests',
  'producer-tests',
  'worker-tests',
  'api-route-tests',
  'redis-integration',
  'biome-touched',
  'typecheck',
  'playwright-smoke',
  'grafana-render',
  'make-smoke',
  'make-sbom',
  'make-audit',
  'grafana-live-render',
  'hunter-build',
  'make-pr-check',
];

test('defines the exact mandatory 19-check closeout matrix in order', () => {
  assert.deepEqual(MANDATORY_CHECKS.map(({ id }) => id), EXPECTED_IDS);
  const fixed = Object.fromEntries(
    MANDATORY_CHECKS.filter(({ fixed: isFixed }) => isFixed).map(({ id, command }) => [id, command]),
  );
  // git-diff-check must inspect the committed PR range via the live
  // {mergeBaseSha} placeholder (expanded at plan build time), not a
  // hard-coded origin/main or the empty working-tree diff.
  assert.match(fixed['git-diff-check'], /git diff --check/);
  assert.match(fixed['git-diff-check'], /\{mergeBaseSha\}/);
  assert.match(fixed['git-diff-check'], /\.\.\.HEAD/);
  assert.deepEqual(
    Object.fromEntries(Object.entries(fixed).filter(([id]) => id !== 'git-diff-check')),
    {
      'pnpm-audit': 'pnpm audit --audit-level high',
      'prisma-validate': 'pnpm prisma validate',
      'prisma-generate': 'pnpm prisma generate',
      'make-smoke': 'make smoke',
      'make-sbom': 'make sbom',
      'make-audit': 'make audit',
      'hunter-build': 'docker compose up -d --build hunter',
      'make-pr-check': 'make pr-check',
    },
  );
});

test('discovers authoritative named checks and refuses fixed-command overrides', () => {
  const plan = buildCheckPlan({
    config: {
      commands: {
        'git-diff-check': 'git diff --check --cached',
        'redis-integration': 'pnpm test:redis:real',
      },
    },
    packageScripts: {
      'test:queue-registry': 'vitest queue-registry',
      typecheck: 'tsc --noEmit',
    },
    makeTargets: ['grafana-render'],
    touchedFiles: ['src/a.ts', 'src/space name.ts'],
    mergeBaseSha: 'abc123mergebase',
  });

  assert.match(plan.errors.join('\n'), /cannot override fixed check git-diff-check/i);
  assert.match(
    plan.checks.find(({ id }) => id === 'git-diff-check').command,
    /git diff --check 'abc123mergebase'\.\.\.HEAD/,
  );
  assert.equal(
    plan.checks.find(({ id }) => id === 'queue-registry-tests').command,
    'pnpm run test:queue-registry',
  );
  assert.equal(plan.checks.find(({ id }) => id === 'redis-integration').resolution, 'configured');
  assert.equal(plan.checks.find(({ id }) => id === 'grafana-render').command, 'make grafana-render');
  assert.equal(plan.checks.find(({ id }) => id === 'producer-tests').status, 'BLOCKED');
});

test('expands dash-prefixed root files as operands rather than command options', () => {
  const plan = buildCheckPlan({
    config: { commands: { 'biome-touched': 'biome check {touchedFiles}' } },
    touchedFiles: ['--write', 'src/normal.js'],
  });
  assert.equal(
    plan.checks.find(({ id }) => id === 'biome-touched').command,
    "biome check './--write' 'src/normal.js'",
  );
});

test('treats warning-like output as failure but accepts canonical zero summaries', () => {
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'Tests: 42 passed, 0 failed, 0 skipped\nWarnings: 0' }).status, 'PASS');
  assert.equal(classifyOutput({ exitCode: 0, stdout: '4 passed; 0 failed; 0 ignored' }).status, 'PASS');
  assert.equal(classifyOutput({ exitCode: 0, stdout: '4 passed, 0 deselected' }).status, 'PASS');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'warning: deprecated dependency' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stderr: 'BLOCKED: Redis unavailable' }).status, 'BLOCKED');
  assert.equal(classifyOutput({ exitCode: 1, stderr: 'ordinary command failure' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: null, timedOut: true }).status, 'BLOCKED');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'src/a.ts(2,4): warning TS1234: unsafe' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stderr: 'DeprecationWarning: legacy API' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stderr: 'UserWarning: unsafe fallback' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stderr: '(node:123) ExperimentalWarning: unstable API' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'warning deprecated package' }).status, 'FAIL');
  // Runner-native skip buckets (Rust ignored, pytest deselected) must FAIL.
  assert.equal(classifyOutput({ exitCode: 0, stdout: '4 passed; 0 failed; 1 ignored' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stdout: '4 passed, 1 deselected' }).status, 'FAIL');
  assert.equal(
    classifyOutput({ exitCode: 1, stderr: 'BLOCKED: command reached a real failure' }).status,
    'FAIL',
  );
});

test('normalizes ANSI, carriage-return progress, and npm warning output', () => {
  const result = classifyOutput({
    exitCode: 0,
    stdout: '\u001b[33mnpm WARN deprecated unsafe-package\u001b[0m\rprogress complete',
    stderr: '',
  });
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /npm WARN/i);
});

test('uses failure precedence when warning and blocked signals coexist', () => {
  const result = classifyOutput({
    exitCode: 0,
    stdout: 'BLOCKED: Redis is unavailable\nWarning: validation drift detected',
    stderr: '',
  });
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /Warning/i);
});

test('distinguishes status signals from passing failure-path test names', () => {
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'failure-mode tests passed\nerror recovery tests passed' }).status,
    'PASS',
  );
  // Passing TAP/Node titles that mention TypeError must not be runtime FAIL.
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'ok 1 - handles TypeError: invalid value' }).status,
    'PASS',
  );
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: '# Subtest: handles TypeError: invalid value' }).status,
    'PASS',
  );
  // A summary key is not a passing test title: it can contain a real failed
  // count later on the same line and must keep that signal visible.
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'passed: 0 failed: 2' }).status,
    'FAIL',
  );
  // A real runtime diagnostic still fails.
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'TypeError: invalid value\n    at Object.<anonymous>' }).status,
    'FAIL',
  );
  // Node-style diagnostics with a bracketed error code before the colon must
  // also fail (e.g. TypeError [ERR_INVALID_ARG_TYPE]: ...).
  assert.equal(
    classifyOutput({
      exitCode: 0,
      stdout: 'TypeError [ERR_INVALID_ARG_TYPE]: The "path" argument must be of type string',
    }).status,
    'FAIL',
  );
  assert.equal(
    classifyOutput({
      exitCode: 0,
      stderr: 'RangeError [ERR_OUT_OF_RANGE]: The value of "offset" is out of range',
    }).status,
    'FAIL',
  );
  // Passing TAP titles that mention the bracketed form still must not fail.
  assert.equal(
    classifyOutput({
      exitCode: 0,
      stdout: 'ok 1 - handles TypeError [ERR_INVALID_ARG_TYPE]: invalid value',
    }).status,
    'PASS',
  );
  // Bare Error / Warning diagnostics (with and without bracketed codes).
  assert.equal(
    classifyOutput({
      exitCode: 0,
      stdout: 'Error: something went wrong\n    at Object.<anonymous>',
    }).status,
    'FAIL',
  );
  assert.equal(
    classifyOutput({
      exitCode: 0,
      stdout: 'Error [ERR_MODULE_NOT_FOUND]: Cannot find module',
    }).status,
    'FAIL',
  );
  assert.equal(
    classifyOutput({
      exitCode: 0,
      stderr: 'Warning: experimental feature enabled',
    }).status,
    'FAIL',
  );
  // Passing TAP titles that mention bare Error still must not fail.
  assert.equal(
    classifyOutput({
      exitCode: 0,
      stdout: 'ok 1 - handles Error [ERR_MODULE_NOT_FOUND]: missing',
    }).status,
    'PASS',
  );
  // Passing titles that embed incidental counted/npm signals must not FAIL
  // (Codex M6UFnGH): failure-path test names routinely mention `N errors` or
  // `npm WARN`, and only runtimeHit previously honored the passing-title
  // prefix. A real counted/uppercase signal on a non-title line still fails.
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'ok 1 - reports 2 errors for malformed config' }).status,
    'PASS',
  );
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: '# Subtest: ignores npm WARN fixture' }).status,
    'PASS',
  );
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'ok 3 - covers 3 problems and 5 warnings edge case' }).status,
    'PASS',
  );
  // The same words outside a passing title still FAIL.
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'found 2 errors while validating config' }).status,
    'FAIL',
  );
  assert.equal(
    classifyOutput({ exitCode: 0, stderr: 'npm WARN deprecated package' }).status,
    'FAIL',
  );
  // Failing TAP counterpart of the passing-title exemption must still FAIL.
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'not ok 1 - handles TypeError: invalid value' }).status,
    'FAIL',
  );
  assert.equal(
    classifyOutput({
      exitCode: 0,
      stdout: '  TypeError [ERR_INVALID_ARG_TYPE]: indented diagnostic',
    }).status,
    'FAIL',
  );
  // Go test SKIP records exit 0 while omitting coverage.
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: '--- SKIP: TestNeedsDocker (0.00s)' }).status,
    'FAIL',
  );
  // Zero-work summaries from Go, Rust, and Python unittest runners.
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: '?   \texample.com/mod\t[no test files]' }).status,
    'FAIL',
  );
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'running 0 tests\n\ntest result: ok. 0 passed; 0 failed' }).status,
    'FAIL',
  );
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'Ran 0 tests in 0.001s\n\nOK' }).status,
    'FAIL',
  );
  assert.equal(classifyOutput({ exitCode: 0, stdout: '1 skipped' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'todo: 2' }).status, 'FAIL');
});

test('treats mocha-style passing summary with failing tests as a failure signal', () => {
  // Mocha prints `passing: N`/`failing: N` summary lines. When a wrapper or
  // npm script masks the underlying test runner's exit code, the closeout
  // classifier must still catch `1 failing` (or `failing: 1`) on stdout.
  assert.equal(classifyOutput({ exitCode: 0, stdout: '  1 failing' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'failing: 3' }).status, 'FAIL');
  // Zero-failing summaries remain PASS.
  assert.equal(classifyOutput({ exitCode: 0, stdout: '  0 failing' }).status, 'PASS');
  // Failure precedence must hold even when a blocked-style line coexists.
  const mixed = classifyOutput({ exitCode: 0, stdout: '3 blocked\n1 failing' });
  assert.equal(mixed.status, 'FAIL');
  assert.match(mixed.evidence, /failing/i);
});

test('treats a no-test run as a failure even when the runner exits 0', () => {
  // Jest/Vitest print "No tests found, exiting with code 0" when a misconfigured
  // glob matches nothing. The closeout gate requires authoritative test
  // evidence (it rejects passWithNoTests-style weakening), so a no-work run
  // must not fall through to PASS.
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'No tests found, exiting with code 0' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'No test files found ["src/**/*.spec.ts"]' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stderr: 'no tests to run' }).status, 'FAIL');
  // Numeric no-work summaries (Node TAP "# tests 0" / "# pass 0", Vitest
  // "Tests 0 passed (0)" / "Test Files 0") must also be treated as no-work.
  assert.equal(classifyOutput({ exitCode: 0, stdout: '# tests 0\n# pass 0' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'Test Files  0 (0)     Tests  0 passed (0)' }).status, 'FAIL');
  // A normal "no tests were skipped" passing summary must NOT be flagged.
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'no tests were skipped' }).status, 'PASS');
});

test('accepts zero-count failure buckets when real tests passed', () => {
  // `Test Files 0 failed | 2 passed (2)` reports zero failed files alongside
  // real passes — the `Test Files 0` prefix is a bucket count, not a zero
  // total, so it must not be treated as a no-work summary.
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'Test Files 0 failed | 2 passed (2)' }).status, 'PASS');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'Test Files 0 skipped | 2 passed (2)' }).status, 'PASS');
  // A zero TOTAL remains a no-work failure.
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'Test Files 0 passed (0)' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'Test Files  0 (0)     Tests  0 passed (0)' }).status, 'FAIL');
  // Go/cargo workspace: empty packages print no-test markers next to real
  // packages that ran tests — mixed output must PASS when evidence exists.
  assert.equal(classifyOutput({
    exitCode: 0,
    stdout: '[no test files]\nok\tcloud.google.com/go/storage/v2\t0.219s\n',
  }).status, 'PASS');
  assert.equal(classifyOutput({
    exitCode: 0,
    stdout: 'running 0 tests\ntest result: ok. 0 passed; 0 failed\nrunning 0 tests\ntest result: ok. 2 passed; 0 failed\n',
  }).status, 'PASS');
  // Pure Go/Rust no-work (no accompanying authoritative pass) still FAILs.
  assert.equal(classifyOutput({
    exitCode: 0,
    stdout: '[no test files]\n',
  }).status, 'FAIL');
  assert.equal(classifyOutput({
    exitCode: 0,
    stdout: 'running 0 tests\ntest result: ok. 0 passed; 0 failed\n',
  }).status, 'FAIL');
  // Empty TAP plan / zero-pass summary alone must not PASS.
  assert.equal(classifyOutput({ exitCode: 0, stdout: '1..0\n' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stdout: '# pass 0\n' }).status, 'FAIL');
});

test('flags focused or skipped tests in touched test files', () => {
  // A PR can focus or skip tests in an ordinary touched test file and still
  // exit 0 from the reduced command; the closeout scanner must catch that
  // weakening without relying on the test file being a gate file.
  const findings = scanSuppressionText('src/foo.test.js', [
    'describe.only("focused suite", () => {});',
    'it.skip("skipped test");',
    'test.todo("unfinished test");',
    'context.only("another focused suite");',
    'suite.only("mocha tdd focused suite", () => {});',
    'function runTest() {} // not a weakening',
  ].join('\n'));
  const matches = findings.filter(({ category }) => category === 'test-weakening');
  assert.equal(matches.length, 5, `expected 5 test-weakening findings, got: ${JSON.stringify(matches)}`);
  // A non-test source file with the same body must not produce test-weakening
  // findings (the detection is scoped to test-like filenames).
  const nonTest = scanSuppressionText('src/foo.js', 'it.skip("not in a test file");');
  assert.deepEqual(nonTest, []);
  // This regression file itself embeds fixture literals; scanning it must not
  // report those string-literal fixtures as active test-weakening.
  const selfScan = scanSuppressionText(
    'scripts/pr_closeout_core.test.js',
    require('node:fs').readFileSync(__filename, 'utf8'),
  ).filter(({ category }) => category === 'test-weakening');
  assert.equal(selfScan.length, 0, `scanner test fixtures must not self-flag: ${JSON.stringify(selfScan)}`);
  // A contraction inside a preceding block comment must not open a bogus quote
  // that hides a real, executable .skip/.only call on the same line.
  const commentApostrophe = scanSuppressionText(
    'src/foo.test.js',
    "/* don't remove this */ it.skip(\"temporarily disabled\");",
  ).filter(({ category }) => category === 'test-weakening');
  assert.equal(
    commentApostrophe.length,
    1,
    `real it.skip after a contraction block-comment must be flagged: ${JSON.stringify(commentApostrophe)}`,
  );
  // Pure line-comment examples are inert and must not fail closeout.
  assert.equal(
    scanSuppressionText('src/foo.test.js', "// it.only('example', () => {})")
      .filter(({ category }) => category === 'test-weakening').length,
    0,
  );
});

test('flags focused or skipped tests in __tests__/ files without a test/spec filename', () => {
  // Standard Jest layout: src/__tests__/foo.js has no test/spec token in the
  // filename, so without path-aware detection weakening markers in it would
  // bypass the scan. The closeout scanner must still catch them.
  const findings = scanSuppressionText('src/__tests__/foo.js', 'it.skip("skipped test");');
  assert.equal(findings.length, 1);
  assert.equal(findings[0].category, 'test-weakening');
  assert.match(findings[0].match, /it\.skip/i);
  // A non-test path that merely contains the substring still must not match.
  assert.deepEqual(scanSuppressionText('src/__tests_data__/foo.js', 'it.skip("no match");'), []);
});

test('flags Jasmine fit/fdescribe/xit/xdescribe aliases in touched test files', () => {
  // Jasmine-native aliases focus (fit/fdescribe) or skip (xit/xdescribe) tests
  // without any .only/.skip modifier, so the modifier-only scan misses them.
  const findings = scanSuppressionText('src/foo.test.js', [
    'fit("focused test", () => {});',
    'fdescribe("focused suite", () => {});',
    'xit("skipped test", () => {});',
    'xdescribe("skipped suite", () => {});',
  ].join('\n'));
  const matches = findings.filter(({ category }) => category === 'test-weakening');
  assert.equal(matches.length, 4, `expected 4 test-weakening findings, got: ${JSON.stringify(matches)}`);
  // Aliases must be standalone calls: member calls and larger words that
  // merely contain the token are not weakening.
  for (const line of ['const p = profit(seed);', 'curve.fit(data);']) {
    assert.deepEqual(
      scanSuppressionText('src/foo.test.js', line).filter(({ category }) => category === 'test-weakening'),
      [],
      `${line} must not be flagged`,
    );
  }
  // Outside a test file the aliases are not flagged.
  assert.deepEqual(scanSuppressionText('src/foo.js', 'fit("not a test file");'), []);
});

test('flags weakening markers in test directory files without a test/spec filename', () => {
  // tests/foo.js has no test/spec token in the filename, so a filename-only
  // predicate misses it; standard test directories must count as test-like.
  for (const path of ['tests/foo.js', 'test/foo.js', 'spec/foo.js', 'src/specs/foo.js']) {
    const findings = scanSuppressionText(path, 'it.skip("skipped test");');
    assert.ok(
      findings.some(({ category }) => category === 'test-weakening'),
      `${path} must be treated as a test file`,
    );
  }
  // Lookalike directory segments must not be treated as test directories.
  for (const path of ['src/contest/foo.js', 'src/test-utils/foo.js', 'src/latest/foo.js']) {
    assert.deepEqual(scanSuppressionText(path, 'it.skip("no match");'), [], `${path} must not match`);
  }
});

test('flags computed-property focus/skip forms in touched test files', () => {
  // Bracket member access (it['only'] / describe["skip"] / test[`only`]) still
  // focuses or skips tests at runtime, so a reduced command can exit 0 and
  // bypass the weakening scan. These must be flagged like the dot form.
  const fixtures = [
    "it['only'](\"focused\");",
    'describe["skip"]("suite");',
    'test[`only`]("focused");',
    "context['todo'](\"unfinished\");",
    "test?.['only'](\"focused\");",
    'describe?.["skip"]("suite");',
  ];
  for (const line of fixtures) {
    const matches = scanSuppressionText('src/foo.test.js', line)
      .filter(({ category }) => category === 'test-weakening');
    assert.equal(matches.length, 1, `${line} must be flagged, got: ${JSON.stringify(matches)}`);
  }
  // Bracket access on an unrelated callee is not test-weakening.
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', "result['only'] = 1;")
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  // Outside a test file the bracket forms are not flagged.
  assert.deepEqual(
    scanSuppressionText('src/foo.js', "it['only']('nope');")
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
});

test('does not flag focused tests inside a multi-line block comment', () => {
  // A focused test sketched inside a /* ... */ block that spans lines is never
  // executed by the runner, so it must not be flagged as test-weakening. Block
  // comment state must be carried across lines.
  const blocked = scanSuppressionText('src/foo.test.js', [
    '/*',
    'it.only("sketched, not active");',
    'describe.skip("also sketched");',
    '*/',
  ].join('\n')).filter(({ category }) => category === 'test-weakening');
  assert.deepEqual(blocked, [], `block-commented focus must not flag: ${JSON.stringify(blocked)}`);
  // A real call after the block comment closes (on a later line) still flags.
  const afterClose = scanSuppressionText('src/foo.test.js', [
    '/* comment */',
    'it.only("active");',
  ].join('\n')).filter(({ category }) => category === 'test-weakening');
  assert.equal(afterClose.length, 1, `real it.only after a closed block comment must flag: ${JSON.stringify(afterClose)}`);
});

test('parses regex character classes before quote checks', () => {
  // A regex literal like /[/']/ contains both `/` and a quote inside its
  // character class; the scanner must track the class so it does not end the
  // regex at the class `/` and let the apostrophe open a bogus string that
  // hides a later real .only call.
  const flagged = scanSuppressionText('src/foo.test.js', "const r = /[/']/; it.only(\"after regex\");")
    .filter(({ category }) => category === 'test-weakening');
  assert.equal(flagged.length, 1, `real it.only after a char-class regex must be flagged: ${JSON.stringify(flagged)}`);
  // A regex with a class containing only `/` must not leave a dangling state.
  const flags2 = scanSuppressionText('src/foo.test.js', "const re = /[/]/; test.skip(\"after\");")
    .filter(({ category }) => category === 'test-weakening');
  assert.equal(flags2.length, 1);
});

test('treats regex literals in keyword context (return /.../) so they cannot hide a later .only', () => {
  // A `/` that follows a regex-context keyword like `return` begins a regex
  // literal (not division). The scanner must consume the whole literal —
  // including an apostrophe inside it — so the apostrophe does not open a bogus
  // string that hides a later active it.only call. The keyword context is
  // detected from the preceding word token, not a single character.
  const cases = [
    "return /it's ok/; it.only(\"x\");",
    "return /it's ok/; describe.skip(\"x\");",
    "typeof x; /don't/; it.only(\"x\");",
    "const z = a / b; it.only(\"division then call\");",
  ];
  for (const line of cases) {
    const matches = scanSuppressionText('src/foo.test.js', line)
      .filter(({ category }) => category === 'test-weakening');
    assert.equal(matches.length, 1, `${line} must flag exactly one weakening, got: ${JSON.stringify(matches)}`);
  }
});

test('flags optional-chaining focus/skip forms and Cypress spec files', () => {
  // it?.only(...) still focuses at runtime when `it` is defined (it?.only ===
  // it.only), and Cypress honors it.only/describe.skip in *.cy.ts/*.cy.js spec
  // files even outside a test/ directory. Both must be scanned.
  for (const line of ["it?.only(\"focused\");", "describe?.skip(\"suite\");", "test?.todo(\"unfinished\");"]) {
    const matches = scanSuppressionText('src/foo.test.js', line)
      .filter(({ category }) => category === 'test-weakening');
    assert.equal(matches.length, 1, `${line} must be flagged, got: ${JSON.stringify(matches)}`);
  }
  // Cypress spec naming is detected as test-like.
  const cy = scanSuppressionText('cypress/e2e/login.cy.ts', 'it.only("focused e2e");')
    .filter(({ category }) => category === 'test-weakening');
  assert.equal(cy.length, 1, `cypress *.cy.ts focus must be flagged: ${JSON.stringify(cy)}`);
  // A lookalike non-spec extension must not be treated as a Cypress spec.
  assert.deepEqual(
    scanSuppressionText('src/login.cy.map.js', 'it.only("nope");')
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
});

test('flags focus/skip after parameterized-test factories (.each(...).only)', () => {
  // Jest/Vitest `.each(table)` returns a factory whose `.only`/`.skip` member
  // still focuses/skips the suite; the call between the receiver chain and
  // the weakening member must not evade the scan (Codex M6UFnGV).
  const cases = [
    'test.each(cases).only("focused parameterized");',
    'describe.each(table).skip("skipped parameterized");',
    'it.each([1, 2, 3]).only("row focus");',
    'test.concurrent.each(rows).only("concurrent focus");',
    // A computed table with a NESTED call (cases.map(makeCase)) puts parens
    // inside the .each(...) argument; [^()]* used to stop at that inner call
    // and miss the trailing .only, silently excluding the rest of the suite
    // (Codex Uz6Ak).
    'test.each(cases.map(makeCase)).only("nested-call focus");',
    'describe.each(table.filter(Boolean)).skip("nested-call skip");',
  ];
  for (const line of cases) {
    const matches = scanSuppressionText('src/foo.test.js', line)
      .filter(({ category }) => category === 'test-weakening');
    assert.equal(matches.length, 1, `${line} must be flagged, got: ${JSON.stringify(matches)}`);
  }
  // The non-weakening `.each(...)` call without a trailing .only/.skip must
  // NOT be flagged, and a plain receiver member call is still inert in a
  // non-test file.
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', 'test.each(cases)("normal run");')
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  assert.deepEqual(
    scanSuppressionText('src/foo.js', 'test.each(cases).only("not a test file");')
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
});

test('rejects framework-native skip, pending, xfail, and TAP failure output', () => {
  const failures = [
    'ok 1 - feature # SKIP unavailable',
    '# skipped 1',
    '1 xfailed, 3 passed',
    '1 pending',
    'not ok 1 - worker starts',
    'skipped integration tests because Redis is unavailable',
    'failed to initialize worker',
  ];
  for (const stdout of failures) {
    assert.equal(
      classifyOutput({ exitCode: 0, stdout }).status,
      'FAIL',
      `${stdout} must not pass`,
    );
  }
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'blocked by missing Docker' }).status,
    'BLOCKED',
  );
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: '# skipped 0\n0 pending\n0 xfailed' }).status,
    'PASS',
  );
});

test('detects every forbidden suppression family and config-level silencing', () => {
  const text = [
    '// skipcq',
    '// biome-ignore lint/suspicious/noExplicitAny',
    '// eslint-disable-next-line',
    '// @ts-ignore',
    '// @ts-expect-error',
    '# noqa',
    '# nosec',
    '# type: ignore',
    'continue-on-error: true',
    'passWithNoTests: true',
    'rules: { dangerousRule: "off" }',
  ].join('\n');

  const findings = scanSuppressionText('config.yml', text);
  assert.equal(findings.length, 11);
  assert.deepEqual(new Set(findings.map(({ category }) => category)), new Set(['marker', 'config-silencing']));
});

test('scans shell validation helpers for failure-neutralizing constructs', () => {
  // Codex #4781637950: .sh helpers invoked by make smoke must not hide || true.
  const shell = scanSuppressionText('ci/check.sh', 'npm test || true\n');
  assert.ok(
    shell.some(({ category, match }) => category === 'config-silencing' && /\|\|\s*true/i.test(match)),
    JSON.stringify(shell),
  );
  // Ordinary source .js is still not config-like for this construct.
  assert.deepEqual(
    scanSuppressionText('src/util.js', 'const x = a || true;\n').filter(({ category }) => category === 'config-silencing'),
    [],
  );
});

test('detects extended suppression markers and flexible type-ignore whitespace', () => {
  const markers = [
    '/* istanbul ignore next */',
    '/* c8 ignore next */',
    '# pylint: disable=unused-import',
    '//nolint:gosec',
    '# shellcheck disable=SC2086',
    '/* stylelint-disable color-no-invalid-hex */',
    '# rubocop:disable Metrics/MethodLength',
    '// NOSONAR',
    '# type:    ignore[assignment]',
  ];
  const findings = scanSuppressionText('src/example.txt', markers.join('\n'));
  assert.equal(findings.length, markers.length);
  assert.ok(findings.every(({ category }) => category === 'marker'));
});

test('does not match suppression markers as substrings of larger words', () => {
  const falsePositives = [
    'const delay = nanoseconds(timeout);',
    'export function fetchNoqaTokens() {',
    'return options.nocheck;',
    'function disableNolintHooks() {}',
    'pipelineRubocop:disabledByConfig',
  ];
  for (const line of falsePositives) {
    assert.deepEqual(
      scanSuppressionText('src/code.ts', line),
      [],
      `${line} must not match a suppression marker`,
    );
  }
});

test('still matches suppression markers when preceded by comment syntax or whitespace', () => {
  const truePositives = [
    '# nosec',
    '// noqa: E501',
    '/* istanbul ignore next */',
    '// @ts-ignore',
    '# shellcheck disable=SC2086',
    '// NOSONAR',
    '  # nosec',
    '\t# type: ignore',
  ];
  for (const line of truePositives) {
    assert.ok(
      scanSuppressionText('src/code.ts', line).some(({ category }) => category === 'marker'),
      `${line} must match a suppression marker`,
    );
  }
});

test('does not flag suppression vocabulary that is sole quoted-string data', () => {
  // The scanner's own MARKERS vocabulary and quoted test fixtures are data,
  // not active directives. A line whose content is a single quoted string
  // must not self-flag, while the same marker used as a real directive is
  // still detected. Split marker tokens below so this test file stays clean
  // under a full-file scanSuppressionText pass (CI touched-file gate).
  const deepSource = 'skip' + 'cq';
  const ruff = 'no' + 'qa';
  const eslint = 'eslint' + '-disable';
  assert.deepEqual(scanSuppressionText('scripts/pr_closeout_core.js', `  '${deepSource}',`), []);
  assert.deepEqual(scanSuppressionText('scripts/pr_closeout_core.js', `  '// ${ruff}',`), []);
  assert.deepEqual(scanSuppressionText('scripts/pr_closeout_core.js', `  \`${eslint}\`,`), []);
  const directiveLine = [
    `// ${deepSource}`,
  ].join('\n');
  const directive = scanSuppressionText('src/code.ts', directiveLine);
  assert.ok(
    directive.some(({ category }) => category === 'marker'),
    'real directive comment must still be detected',
  );
  assert.match(directive.find(({ category }) => category === 'marker').match, new RegExp(deepSource, 'i'));
});

test('does not flag marker vocabulary in markdown inline-code spans', () => {
  // Documentation that lists the marker vocabulary in markdown inline-code
  // must not self-flag: a marker wrapped in backticks is an example, not a
  // directive. Real bare directives in prose are not wrapped and are still
  // detected. Split tokens so this file remains clean under the CI scan.
  const deepSource = 'skip' + 'cq';
  const eslint = 'eslint' + '-disable';
  const biome = 'biome' + '-ignore';
  assert.deepEqual(scanSuppressionText('references/pr-closeout-validation.md', `- \`${deepSource}\``), []);
  assert.deepEqual(scanSuppressionText('README.md', `Use \`${eslint}\` only as a last resort.`), []);
  assert.deepEqual(scanSuppressionText('docs.md', `Token wrapping (\`${biome}\`) is discouraged.`), []);
  const proseLine = [
    `Remember: // ${deepSource} is forbidden.`,
  ].join('\n');
  assert.ok(
    scanSuppressionText('notes.md', proseLine).some(({ category }) => category === 'marker'),
    'a real bare directive in prose must still be detected',
  );
});

test('detects common config-level compiler, framework, linter, and ignore-file silencing', () => {
  const cases = [
    ['tsconfig.json', '{"compilerOptions":{"skipLibCheck":true},"exclude":["generated"]}'],
    ['next.config.js', 'module.exports = { typescript: { ignoreBuildErrors: true } };'],
    ['biome.json', '{"linter": {"enabled": false}}'],
    ['.eslintignore', 'generated/**'],
  ];
  for (const [file, text] of cases) {
    assert.ok(
      scanSuppressionText(file, text).length > 0,
      `${file} must expose config-level silencing`,
    );
  }
});

test('does not treat ordinary source-code fields as config silencing', () => {
  assert.deepEqual(scanSuppressionText('src/options.ts', 'const ignore = request.ignore;'), []);
});

test('does not flag benign ignore/exclude keys targeting build output, only source/test globs', () => {
  // Routine tsconfig/CI exclude keys (dist, node_modules, build) must not
  // produce config-silencing findings; only values that suppress source/test
  // paths (src/**, **/*.test.ts) are flagged, so clean PRs touching a
  // tsconfig.json or a CI matrix are not blocked.
  const benign = scanSuppressionText('tsconfig.json', '{"exclude": ["dist", "node_modules"]}');
  assert.deepEqual(
    benign.filter((finding) => finding.category === 'config-silencing'),
    [],
    'benign build-output exclude must not be flagged',
  );
  // CI matrix exclusions routinely use os values like windows-latest/ubuntu-latest,
  // which contain "test" as a substring of "latest". The src/test/spec match must
  // be word-boundary anchored so these ordinary excludes are NOT flagged.
  const matrix = scanSuppressionText('.github/workflows/ci.yml', [
    'strategy:',
    '  matrix:',
    '    exclude:',
    '      - os: windows-latest',
    '      - os: ubuntu-latest',
  ].join('\n'));
  assert.deepEqual(
    matrix.filter((finding) => finding.category === 'config-silencing'),
    [],
    'CI matrix exclude with windows-latest/ubuntu-latest must not be flagged',
  );
  const suppressing = scanSuppressionText('tsconfig.json', '{"exclude": ["src/**/*.test.ts"]}');
  assert.ok(
    suppressing.some((finding) => finding.category === 'config-silencing'),
    'src/test-targeting exclude must be flagged',
  );
});

test('flags extension-only ignore globs as config silencing', () => {
  // ignorePatterns: ["**/*.ts"] names no src/test/spec token, yet it
  // suppresses every TypeScript file from the lint gate; bare
  // source-extension globs in ignore/exclude values must be flagged.
  const cases = [
    ['package.json', '{"eslintConfig":{"ignorePatterns":["**/*.ts"]}}'],
    ['.eslintrc.json', '{"ignorePatterns": ["**/*.js"]}'],
    ['biome.json', '{"linter":{"ignore":["**/*.tsx"]}}'],
  ];
  for (const [file, text] of cases) {
    assert.ok(
      scanSuppressionText(file, text).some((finding) => finding.category === 'config-silencing'),
      `${file} with an extension-only ignore glob must be flagged`,
    );
  }
  // Build-artifact and declaration globs stay benign.
  const benign = scanSuppressionText('tsconfig.json', '{"exclude": ["**/*.d.ts", "dist", "node_modules"]}');
  assert.deepEqual(
    benign.filter((finding) => finding.category === 'config-silencing'),
    [],
    'build-artifact globs must not be flagged',
  );
});

test('flags brace-expanded extension-only ignore globs as config silencing', () => {
  // A single-extension glob (**/*.ts) is flagged above, but the same
  // whole-language exclusion can hide behind brace expansion
  // (**/*.{js,ts}) -- the char right after the literal dot is `{`, not a
  // recognized extension letter, so the single-extension alternative never
  // matched this form (Codex UeHJ_).
  const cases = [
    ['package.json', '{"eslintConfig":{"ignorePatterns":["**/*.{js,ts}"]}}'],
    ['.eslintrc.json', '{"ignorePatterns": ["**/*.{jsx,tsx}"]}'],
    // The flagged extension need not be the first item in the brace list.
    ['biome.json', '{"linter":{"ignore":["**/*.{py,rb,go}"]}}'],
  ];
  for (const [file, text] of cases) {
    assert.ok(
      scanSuppressionText(file, text).some((finding) => finding.category === 'config-silencing'),
      `${file} with a brace-expanded extension-only ignore glob must be flagged`,
    );
  }
  // A brace group whose only source-like item is a declaration/build
  // artifact extension (*.d.ts) must stay benign, matching the existing
  // **/*.d.ts exemption for the non-brace form.
  const benign = scanSuppressionText('tsconfig.json', '{"exclude": ["**/*.{d.ts,map}", "dist", "node_modules"]}');
  assert.deepEqual(
    benign.filter((finding) => finding.category === 'config-silencing'),
    [],
    'a brace group containing only build-artifact extensions must not be flagged',
  );
});

test('detects disabled rules beyond a multi-kilobyte rules object', () => {
  // A realistic .eslintrc can put `"no-console": "off"` many KB after the
  // opening `rules` key. A fixed 4 KB scan window would miss it and accept
  // config-level rule disabling under the zero-suppression policy.
  const padding = `${'x'.repeat(80)},\n`.repeat(80); // well past 4 KB
  const largeRules = [
    'module.exports = {',
    '  rules: {',
    padding,
    '    "no-console": "off",',
    '  },',
    '};',
  ].join('\n');
  assert.ok(
    largeRules.length > 5000,
    `fixture must exceed 4 KB (got ${largeRules.length})`,
  );
  assert.ok(
    scanSuppressionText('.eslintrc.js', largeRules).some((f) => f.category === 'config-silencing'),
    'disabled rule past 4 KB after rules: must be flagged',
  );
  // Independent kebab rule-id form (override block without a nearby rules key
  // in the same 4 KB window — the assignment itself is the signal).
  assert.ok(
    scanSuppressionText('.eslintrc.js', '{ "no-debugger": 0 }').some((f) => f.category === 'config-silencing'),
    'standalone no-* rule set to 0 must be flagged',
  );
  assert.ok(
    scanSuppressionText('.eslintrc.js', '{ "@typescript-eslint/no-explicit-any": "off" }').some((f) => f.category === 'config-silencing'),
    'scoped plugin rule set to off must be flagged',
  );
});

test('detects quoted enabled/disabled JSON gate switches and --quiet lint scripts', () => {
  // JSON config disables a gate via a QUOTED key: "enabled":false. The pattern
  // must tolerate the closing quote before the colon so package.json-style
  // {"typecheck":{"enabled":false}} is flagged.
  assert.ok(
    scanSuppressionText('package.json', '{"typecheck":{"enabled":false}}').some((f) => f.category === 'config-silencing'),
    'quoted "enabled":false must be flagged',
  );
  assert.ok(
    scanSuppressionText('package.json', '{"lint":{"disabled":true}}').some((f) => f.category === 'config-silencing'),
    'quoted "disabled":true must be flagged',
  );
  // eslint/biome --quiet hides warnings the closeout gate treats as failing.
  assert.ok(
    scanSuppressionText('package.json', '{"scripts":{"lint:touched":"eslint . --quiet"}}').some((f) => f.category === 'config-silencing'),
    '--quiet lint script must be flagged',
  );
  // Non-lint --quiet probes (git diff --quiet) must not be config-silencing.
  assert.equal(
    scanSuppressionText('.github/workflows/validate.yml', 'run: git diff --quiet')
      .filter((f) => f.category === 'config-silencing').length,
    0,
    'git diff --quiet must not be flagged as config silencing',
  );
  // Shell zero-exit neutralizers beyond || true.
  assert.ok(
    scanSuppressionText('package.json', JSON.stringify({ scripts: { t: 'jest || exit 0' } }))
      .some((f) => f.category === 'config-silencing'),
    '|| exit 0 must be flagged',
  );
  assert.ok(
    scanSuppressionText('package.json', JSON.stringify({ scripts: { t: 'jest || :' } }))
      .some((f) => f.category === 'config-silencing'),
    '|| : must be flagged',
  );
  // Direct pipeline tails mask left-hand failure without pipefail
  // (CodeRabbit #4780344655).
  assert.ok(
    scanSuppressionText('package.json', JSON.stringify({ scripts: { t: 'jest | true' } }))
      .some((f) => f.category === 'config-silencing'),
    '| true must be flagged',
  );
  assert.ok(
    scanSuppressionText('package.json', JSON.stringify({ scripts: { t: 'jest | :' } }))
      .some((f) => f.category === 'config-silencing'),
    '| : must be flagged',
  );
  assert.ok(
    scanSuppressionText('package.json', JSON.stringify({ scripts: { t: 'jest | exit 0' } }))
      .some((f) => f.category === 'config-silencing'),
    '| exit 0 must be flagged',
  );
  assert.ok(
    scanSuppressionText('package.json', JSON.stringify({ scripts: { t: 'jest || echo ok' } }))
      .some((f) => f.category === 'config-silencing'),
    '|| echo ok must be flagged',
  );
  // Array-form ESLint severity zero (Codex #4781366510).
  assert.ok(
    scanSuppressionText('eslint.config.js', "module.exports = { rules: { 'no-console': [0, { allow: ['warn'] }] } };")
      .some((f) => f.category === 'config-silencing'),
    "array-form 'no-console': [0, ...] must be flagged",
  );
  // Long ignore arrays still catch a late source exclusion.
  const longIgnore = `ignorePatterns: [${Array.from({ length: 40 }, (_, i) => `"generated-${i}/**"`).join(', ')}, "src/**"]`;
  assert.ok(
    scanSuppressionText('eslint.config.js', longIgnore)
      .some((f) => f.category === 'config-silencing'),
    'source exclusion after a long ignore list must be flagged',
  );
  // Workflow step disable.
  assert.ok(
    scanSuppressionText('.github/workflows/validate.yml', '  - name: Run tests\n    if: false\n    run: npm test')
      .some((f) => f.category === 'config-silencing'),
    'if: false must be flagged',
  );
});

test('flags active test-weakening after a quoted fixture on the same line', () => {
  const findings = scanSuppressionText(
    'tests/foo.js',
    'const s = "it.skip"; it.only("real", () => {});',
  ).filter(({ category }) => category === 'test-weakening');
  assert.equal(findings.length, 1);
  assert.match(findings[0].match, /it\.only/i);
});

test('flags active test-weakening after a block-comment apostrophe on the same line', () => {
  const findings = scanSuppressionText(
    'src/foo.test.js',
    "/* don't */ it.only('real', () => {});",
  ).filter(({ category }) => category === 'test-weakening');
  assert.equal(findings.length, 1, JSON.stringify(findings));
  assert.match(findings[0].match, /it\.only/i);
});

test('flags optional-chaining computed focus/skip members', () => {
  // One finding per line is intentional; put each form on its own line so a
  // single-branch regex regression fails the test (CodeRabbit #4781498400).
  const findings = scanSuppressionText(
    'tests/foo.test.js',
    "test?.['only']('focused', () => {});\ndescribe?.[\"skip\"]('x', () => {});",
  ).filter(({ category }) => category === 'test-weakening');
  assert.equal(findings.length, 2, JSON.stringify(findings));
  assert.ok(
    findings.some(({ match }) => /only/i.test(match)),
    `expected test?.['only'] finding: ${JSON.stringify(findings)}`,
  );
  assert.ok(
    findings.some(({ match }) => /skip/i.test(match)),
    `expected describe?.["skip"] finding: ${JSON.stringify(findings)}`,
  );
});

test('flags multiline focused/skipped test member access', () => {
  const only = 'on' + 'ly';
  const multiline = [
    'test',
    `  .${only}('focused', () => {});`,
  ].join('\n');
  const findings = scanSuppressionText('src/foo.test.js', multiline);
  assert.ok(
    findings.some(({ category }) => category === 'test-weakening'),
    'test\\n  .only must be detected',
  );
  const withComment = [
    'describe /* gap */',
    `  .skip('skipped', () => {});`,
  ].join('\n');
  assert.ok(
    scanSuppressionText('src/foo.test.js', withComment).some(({ category }) => category === 'test-weakening'),
    'describe /* gap */ .skip must be detected',
  );
  // Same-line whitespace / comment between receiver and focus member.
  assert.ok(
    scanSuppressionText('src/foo.test.js', `test . ${only}("focused");`)
      .some(({ category }) => category === 'test-weakening'),
    'test . only must be detected',
  );
  assert.ok(
    scanSuppressionText('src/foo.test.js', `test /* note */.${only}("focused");`)
      .some(({ category }) => category === 'test-weakening'),
    'test /* note */.only must be detected',
  );
  // Negative: an unrelated identifier ending a line followed by an
  // unrelated .only-named method must not false-positive.
  const benign = [
    'const value = compute(test',
    '  .onlyIfEnabled);',
  ].join('\n');
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', benign)
      .filter(({ category }) => category === 'test-weakening'),
    [],
    'benign multiline .onlyIfEnabled must not flag',
  );
});

test('classifies e2e and integration suite filenames as test-like', () => {
  const only = 'on' + 'ly';
  for (const file of [
    'src/login.e2e.ts',
    'src/redis.integration.js',
    'src/foo.unit.ts',
    'e2e/checkout.js',
    'integration/api.js',
  ]) {
    assert.ok(
      scanSuppressionText(file, `it.${only}("focused");`)
        .some(({ category }) => category === 'test-weakening'),
      `${file} must be scanned for test-weakening`,
    );
  }
});

test('flags focus/skip calls inside template-literal interpolations', () => {
  // Static template text is inert, but `${test.only(...)}` executes and must
  // be scanned as live JavaScript. Split the focus token so this test file
  // itself stays clean under a full-file suppression scan.
  const only = 'on' + 'ly';
  const line = [
    'const marker = `${test.' + only + '("focused", fn)}`;',
  ].join('\n');
  const findings = scanSuppressionText('src/foo.test.js', line);
  assert.ok(
    findings.some(({ category }) => category === 'test-weakening'),
    'template interpolation must still detect active focus/skip calls',
  );
  // Pure static template text with a lookalike must not flag.
  const staticOnly = scanSuppressionText(
    'src/foo.test.js',
    'const msg = `call test.' + only + ' in docs`;',
  );
  assert.deepEqual(
    staticOnly.filter(({ category }) => category === 'test-weakening'),
    [],
  );
  // Multiline receiver split inside a template interpolation must still flag.
  // A naive backtick-strip on the multiline window would erase `${test\n  .only}`
  // and miss this active focus call. Build the fixture via concat so this test
  // file itself does not embed an active test.only call for full-file scans.
  const multilineInterp = [
    'const s = `${test',
    '  .' + only + "('focused')}`;",
  ].join('\n');
  assert.ok(
    scanSuppressionText('src/foo.test.js', multilineInterp).some(
      ({ category }) => category === 'test-weakening',
    ),
    'multiline template interpolation ${test\\n  .only} must be detected',
  );
  // Static multiline template text that only *looks* like a receiver split
  // must not flag (no live ${...} expression).
  const staticMultiline = [
    'const msg = `call test',
    '  .' + only + ' in docs`;',
  ].join('\n');
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', staticMultiline)
      .filter(({ category }) => category === 'test-weakening'),
    [],
    'static multiline template text must not flag',
  );
});

test('flags chained Jest/Vitest focus and skip modifiers', () => {
  // Runner modifier chains (concurrent + only/skip/each) must still flag.
  for (const line of [
    'test.concurrent.only("focused concurrent", () => {});',
    'test.concurrent.skip("skipped concurrent", () => {});',
    'it.only.each([[1]])("table", () => {});',
    'describe.only.each([["a"]])("suite", () => {});',
  ]) {
    const findings = scanSuppressionText('src/foo.test.js', line)
      .filter(({ category }) => category === 'test-weakening');
    assert.equal(findings.length, 1, `expected flag for: ${line} got ${JSON.stringify(findings)}`);
  }
});

test('flags test-weakening after a regex literal with an apostrophe', () => {
  // Apostrophes inside a regex literal must not open a quote that hides focus.
  const findings = scanSuppressionText(
    'src/foo.test.js',
    "const r = /don't/; it.only('real', () => {});",
  ).filter(({ category }) => category === 'test-weakening');
  assert.equal(findings.length, 1, JSON.stringify(findings));
  assert.match(findings[0].match, /it\.only/i);
});

test('flags test-weakening after a return-preceded regex with an apostrophe', () => {
  // Keyword context (return/typeof/...) must be recognized as a full word, not a
  // single character, or a return-preceded regex with an apostrophe hides focus.
  const findings = scanSuppressionText(
    'src/foo.test.js',
    "return /it's ok/; it.only('real', () => {});",
  ).filter(({ category }) => category === 'test-weakening');
  assert.equal(findings.length, 1, JSON.stringify(findings));
  assert.match(findings[0].match, /it\.only/i);
});

test('rejects Mocha zero-passing summaries as no-work', () => {
  assert.equal(classifyOutput({ exitCode: 0, stdout: '0 passing' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stdout: '  0 passing (12ms)' }).status, 'FAIL');
});

test('flags unconditional exit 0 and Next.js ignoreDuringBuilds', () => {
  assert.ok(
    scanSuppressionText('package.json', JSON.stringify({ scripts: { t: 'jest >/dev/null 2>&1; exit 0' } }))
      .some((f) => f.category === 'config-silencing'),
    'unconditional exit 0 must be flagged',
  );
  assert.ok(
    scanSuppressionText('next.config.js', 'module.exports = { eslint: { ignoreDuringBuilds: true } }')
      .some((f) => f.category === 'config-silencing'),
    'ignoreDuringBuilds must be flagged',
  );
});

test('detects multiline config rule disabling', () => {
  const findings = scanSuppressionText('.eslintrc.json', [
    '{',
    '  "rules": {',
    '    "security/no-danger": "off"',
    '  }',
    '}',
  ].join('\n'));
  assert.ok(findings.some(({ category }) => category === 'config-silencing'));
});

test('detects numeric ESLint rule disabling in executable config files', () => {
  for (const file of ['.eslintrc.js', '.eslintrc.cjs', '.eslintrc.mjs']) {
    const findings = scanSuppressionText(file, [
      'module.exports = {',
      '  rules: {',
      "    'security/no-danger': 0,",
      '  },',
      '};',
    ].join('\n'));
    assert.ok(
      findings.some(({ category }) => category === 'config-silencing'),
      `${file} should expose numeric rule disabling`,
    );
  }
});

test('requires explicit qualification opt-in and postcondition proofs', () => {
  const plan = buildCheckPlan({
    config: {
      commands: { typecheck: 'pnpm typecheck' },
      qualificationSafe: ['typecheck'],
      resourceGroups: { typecheck: 'node-heavy' },
    },
  });
  const typecheck = plan.checks.find(({ id }) => id === 'typecheck');
  assert.equal(typecheck.qualificationSafe, true);
  assert.equal(typecheck.resourceGroup, 'node-heavy');
  assert.equal(plan.checks.find(({ id }) => id === 'prisma-validate').qualificationSafe, false);
  assert.equal(plan.checks.find(({ id }) => id === 'make-sbom').status, 'BLOCKED');
  assert.match(plan.checks.find(({ id }) => id === 'make-sbom').evidence, /artifact postcondition proof/i);
});

test('keeps example placeholders blocked instead of treating them as commands', () => {
  const plan = buildCheckPlan({
    config: { commands: { 'producer-tests': '<authoritative focused producer command>' } },
  });
  const producer = plan.checks.find(({ id }) => id === 'producer-tests');
  assert.equal(producer.status, 'BLOCKED');
  assert.equal(producer.resolution, 'placeholder');
});

test('blocks auto-discovered package scripts that neutralize failures', () => {
  // Codex #4781560042: package-script resolution must inspect script bodies.
  const plan = buildCheckPlan({
    packageScripts: {
      'test:queue-registry': 'vitest run queue-registry || true',
      typecheck: 'tsc --noEmit',
    },
  });
  const queue = plan.checks.find(({ id }) => id === 'queue-registry-tests');
  assert.equal(queue.status, 'BLOCKED', JSON.stringify(queue));
  assert.equal(queue.resolution, 'package-script');
  assert.match(queue.evidence, /neutralizes failures/i);
  assert.match(queue.evidence, /\|\|\s*true/i);
  // Benign package script is the negative control for findCommandFailureNeutralizer
  // (CodeRabbit #4781622077).
  const typecheck = plan.checks.find(({ id }) => id === 'typecheck');
  assert.equal(typecheck.resolution, 'package-script');
  assert.notEqual(typecheck.status, 'BLOCKED', JSON.stringify(typecheck));
});

test('blocks configured commands that neutralize failures', () => {
  // Closeout config may live outside the checkout; the touched-file scanner
  // never sees it. Failure-hiding shell constructs must be rejected at plan
  // build time (Codex #4780229514 / Qodo #4780249069 / CodeRabbit #4780269384).
  assert.ok(findCommandFailureNeutralizer('pnpm test || true'));
  assert.ok(findCommandFailureNeutralizer('actual-test >/dev/null 2>&1 || true'));
  // `|| :` with redirects/pipes still yields exit 0.
  assert.ok(findCommandFailureNeutralizer('actual-test || :>/dev/null'));
  assert.ok(findCommandFailureNeutralizer('actual-test || :| cat'));
  // Semicolon-chained success no-ops.
  assert.ok(findCommandFailureNeutralizer('actual-test; true'));
  assert.ok(findCommandFailureNeutralizer('actual-test; :'));
  assert.ok(findCommandFailureNeutralizer('actual-test; exit 0'));
  // Direct pipeline tails to always-success (no pipefail) — CodeRabbit #4780344655.
  assert.ok(findCommandFailureNeutralizer('actual-test | true'));
  assert.ok(findCommandFailureNeutralizer('actual-test | :'));
  assert.ok(findCommandFailureNeutralizer('actual-test | exit 0'));
  // `|| echo ok` also forces zero exit after a failed left-hand command.
  assert.ok(findCommandFailureNeutralizer('npm test || echo ok'));
  // Sequential success tail (Codex U3a2X): a `;`-separated list's exit status
  // is its LAST command's, so `cmd; echo done` / `cmd; printf ok` masks the
  // earlier failure; `cmd && echo done` (short-circuits on failure) does not,
  // and `echo start; npm test` (the real check is the LAST command) is clean.
  assert.ok(findCommandFailureNeutralizer('npm test; echo done'));
  assert.ok(findCommandFailureNeutralizer('npm test; printf done'));
  assert.ok(findCommandFailureNeutralizer('lint; test; echo passed'));
  assert.equal(findCommandFailureNeutralizer('npm test && echo done'), null);
  assert.equal(findCommandFailureNeutralizer('echo start; npm test'), null);
  // Background operator (Codex U4u-o): a single `&` backgrounds the preceding
  // command, so `npm test & echo done` returns the foreground echo's exit 0
  // while the test keeps running (then is terminated by cleanup); `&&`
  // (logical AND) and `&>` / `2>&1` (redirects) are not background operators.
  assert.ok(findCommandFailureNeutralizer('npm test >/dev/null 2>&1 & echo completed'));
  assert.ok(findCommandFailureNeutralizer('npm test& echo ok'));
  assert.ok(findCommandFailureNeutralizer('npm test &'));
  assert.equal(findCommandFailureNeutralizer('npm test && echo done'), null);
  assert.equal(findCommandFailureNeutralizer('node build &> build.log'), null);
  assert.equal(findCommandFailureNeutralizer('node build 2>&1 | tee log'), null);
  // `&& exit 0` short-circuits on failure — not a neutralizer.
  assert.equal(findCommandFailureNeutralizer('pnpm test && exit 0'), null);
  assert.equal(findCommandFailureNeutralizer('pnpm test'), null);
  // Ordinary pipelines are not failure neutralizers.
  assert.equal(findCommandFailureNeutralizer('actual-test | cat'), null);

  const plan = buildCheckPlan({
    config: {
      commands: {
        typecheck: 'pnpm typecheck || true',
        'producer-tests': 'actual-test >/dev/null 2>&1 || true',
      },
      proofs: {
        'make-sbom': {
          type: 'command',
          command: 'make sbom || exit 0',
          expectedPattern: 'literal:ok',
        },
      },
      baselineSetupCommand: 'pnpm install || true',
    },
  });
  const typecheck = plan.checks.find(({ id }) => id === 'typecheck');
  assert.equal(typecheck.status, 'BLOCKED');
  assert.match(typecheck.evidence, /neutralizes failures/i);
  const producer = plan.checks.find(({ id }) => id === 'producer-tests');
  assert.equal(producer.status, 'BLOCKED');
  const sbom = plan.checks.find(({ id }) => id === 'make-sbom');
  assert.equal(sbom.status, 'BLOCKED');
  assert.match(sbom.evidence, /neutralizes failures|postcondition proof/i);
  assert.ok(plan.errors.some((error) => /baselineSetupCommand/i.test(error)));
});

test('preserves the first BLOCKED reason when a check hits multiple BLOCKED conditions', () => {
  // grafana-live-render can be BLOCKED three ways when nothing is configured:
  // unresolved command (first map), missing artifact proof (second map), and
  // missing live Grafana service URL (second map). The second pass must
  // preserve and append to the unresolved-command evidence instead of
  // overwriting it, so reviewers see the real root cause.
  const plan = buildCheckPlan({ config: {} });
  const grafana = plan.checks.find(({ id }) => id === 'grafana-live-render');
  assert.equal(grafana.status, 'BLOCKED');
  assert.match(grafana.evidence, /No authoritative command resolved/i);
  assert.match(grafana.evidence, /postcondition proof/i);
  assert.match(grafana.evidence, /Grafana health probe/i);
});


test('scopes shell-helper config scanning to validation helper locations', () => {
  // CodeRabbit discussion_r3652923133: an ordinary application/deploy shell
  // script is not a validation helper, so neutralizing constructs in it must
  // NOT be reclassified as config-silencing. Helper locations stay in scope.
  assert.deepEqual(
    scanSuppressionText('src/deploy.sh', 'deploy || true\n')
      .filter(({ category }) => category === 'config-silencing'),
    [],
    'out-of-scope src/deploy.sh must not be treated as config-like',
  );
  assert.ok(
    scanSuppressionText('ci/check.sh', 'npm test || true\n')
      .some(({ category }) => category === 'config-silencing'),
    'ci/check.sh must stay config-like',
  );
  assert.ok(
    scanSuppressionText('tools/run.bash', 'npm test || true\n')
      .some(({ category }) => category === 'config-silencing'),
    'tools/*.bash helper must stay config-like',
  );
  assert.ok(
    scanSuppressionText('tools/validate', '#!/bin/sh\nnpm test || true\n')
      .some(({ category }) => category === 'config-silencing'),
    'extensionless validation helpers with a shell shebang must stay config-like',
  );
  assert.deepEqual(
    scanSuppressionText('tools/fixture', 'const sample = `\n#!/bin/sh\nnpm test || true\n`;\n')
      .filter(({ category }) => category === 'config-silencing'),
    [],
    'a shell-like line after line one must not classify a fixture as a shell helper',
  );
  assert.ok(
    scanSuppressionText('install.sh', 'npm test || true\n')
      .some(({ category }) => category === 'config-silencing'),
    'install.sh must stay config-like',
  );
});

test('blocks whitespace-padded hunter proof policies at plan time', () => {
  // Qodo discussion_r3652936843: the executor exact-compares the RAW
  // expectedPattern for the hunter semantic policy, so a padded policy that
  // would deterministically fail at runtime must fail closed at plan time.
  const padded = buildCheckPlan({
    config: {
      proofs: {
        'hunter-build': {
          type: 'command',
          command: 'docker compose ps --format json hunter',
          expectedPattern: 'semantic:docker-compose-running-healthy ',
        },
      },
    },
  });
  const blockedHunter = padded.checks.find(({ id }) => id === 'hunter-build');
  assert.equal(blockedHunter.status, 'BLOCKED');
  assert.match(blockedHunter.evidence, /semantic:docker-compose-running-healthy/i);
  // The exact (unpadded) semantic policy remains admissible.
  const exact = buildCheckPlan({
    config: {
      proofs: {
        'hunter-build': {
          type: 'command',
          command: 'docker compose ps --format json hunter',
          expectedPattern: 'semantic:docker-compose-running-healthy',
        },
      },
    },
  });
  const admittedHunter = exact.checks.find(({ id }) => id === 'hunter-build');
  assert.notEqual(admittedHunter.status, 'BLOCKED', JSON.stringify(admittedHunter));
});

test('flags OR-list fallbacks whose right operand does not provably re-fail', () => {
  // Codex discussion_r3652957333: bash exempts the left side of `||` from
  // errexit and the OR-list exits with the RIGHT operand's status, so an
  // arbitrary right operand (printf, a function call, ...) masks the failure
  // exactly like `|| true` does. Only right operands that themselves
  // guarantee a nonzero exit keep the failure visible and stay allowed.
  assert.ok(findCommandFailureNeutralizer('validator || printf ok'));
  assert.ok(findCommandFailureNeutralizer('validator || logger -t ci failed'));
  assert.equal(findCommandFailureNeutralizer('validator || exit 1'), null);
  assert.equal(findCommandFailureNeutralizer('validator || exit 2'), null);
  assert.equal(findCommandFailureNeutralizer('validator || false'), null);
  assert.equal(findCommandFailureNeutralizer('validator || return 1'), null);
  // `|| exit $?` / `|| return $?` propagate the left operand's own nonzero
  // status, so the failure stays fully visible (CodeRabbit UC4ND).
  assert.equal(findCommandFailureNeutralizer('pnpm test || exit $?'), null);
  assert.equal(findCommandFailureNeutralizer('pnpm test || return $?'), null);
  // Zero-exit and output-only fallbacks stay flagged.
  assert.ok(findCommandFailureNeutralizer('pnpm test || exit 0'));
  assert.ok(findCommandFailureNeutralizer('pnpm test || true'));
  assert.ok(findCommandFailureNeutralizer('pnpm test || echo ok'));
  // Plan-level: a configured command with a masking OR-list is BLOCKED.
  const plan = buildCheckPlan({
    config: { commands: { typecheck: 'validator || printf ok' } },
  });
  const typecheck = plan.checks.find(({ id }) => id === 'typecheck');
  assert.equal(typecheck.status, 'BLOCKED');
  assert.match(typecheck.evidence, /neutralizes failures/i);
});

test('flags a receiver split across deep blank/comment padding', () => {
  // Codex discussion_r3652957336: the multiline receiver lookahead counts
  // code-bearing lines only, so blank/comment padding cannot push `.only`
  // out of the window. Build the focus token via concat so this test file
  // itself stays clean under a full-file suppression scan.
  const only = 'on' + 'ly';
  const padding = Array.from(
    { length: 20 },
    (unused, index) => (index % 2 ? '// padding comment' : ''),
  ).join('\n');
  const text = ['test', padding, `  .${only}('x', function () {});`].join('\n');
  const findings = scanSuppressionText('src/foo.test.js', text)
    .filter(({ category }) => category === 'test-weakening');
  assert.equal(
    findings.length,
    1,
    `padded receiver split must be flagged: ${JSON.stringify(findings)}`,
  );
  assert.equal(findings[0].line, 1);
});

test('does not strip the label prefix from zero-count diagnostic prose', () => {
  // Codex discussion_r3652957339: label-first zero-summary removal only
  // applies to complete count buckets. `Error: 0 is not a valid threshold`
  // and `Warning: 0-byte artifact was ignored` are diagnostics, not buckets;
  // stripping their `Error:`/`Warning:` prefix would let them slip to PASS.
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'Error: 0 is not a valid threshold' }).status,
    'FAIL',
  );
  assert.equal(
    classifyOutput({ exitCode: 0, stdout: 'Warning: 0-byte artifact was ignored' }).status,
    'FAIL',
  );
  // Genuine zero summaries are still stripped (end-of-line or summary
  // delimiter after the zero).
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'errors: 0' }).status, 'PASS');
  assert.equal(classifyOutput({ exitCode: 0, stdout: '0 warnings' }).status, 'PASS');
  assert.equal(classifyOutput({ exitCode: 0, stdout: '# fail 0' }).status, 'PASS');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'errors: 0, warnings: 0' }).status, 'PASS');
});

test('strips label-first zero summaries followed by a period', () => {
  // Qodo UC056: a trailing period is summary punctuation (`errors: 0.`), not
  // a numeric continuation; the bucket must strip like `errors: 0` while a
  // decimal tail (`0.5`) is never stripped and stays a failure signal.
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'errors: 0.' }).status, 'PASS');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'warnings: 0.' }).status, 'PASS');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'errors: 0.5' }).status, 'FAIL');
});

test('blocks shell options that disable failure propagation', () => {
  // Codex UDDQR: `set +e` / `set +o errexit` override the executor's
  // prepended `set -e` so a later command exits 0 after a failure, and
  // `set +o pipefail` lets a successful pipeline tail hide a failed leg.
  assert.ok(findCommandFailureNeutralizer('set +e; false; printf ok'));
  assert.ok(findCommandFailureNeutralizer('set   +e; pnpm test'));
  assert.ok(findCommandFailureNeutralizer('set +ex; pnpm test'));
  assert.ok(findCommandFailureNeutralizer('set +eo pipefail; pnpm test'));
  assert.ok(findCommandFailureNeutralizer('set +o errexit; pnpm test'));
  assert.ok(findCommandFailureNeutralizer('set +o pipefail; pnpm test | tail'));
  // The hardening forms (`set -e`, `set -o pipefail`) are not neutralizers.
  assert.equal(findCommandFailureNeutralizer('set -e; pnpm test'), null);
  assert.equal(findCommandFailureNeutralizer('set -o pipefail; pnpm test'), null);
  assert.equal(findCommandFailureNeutralizer('set -eo pipefail; pnpm test'), null);
  // Scanned validation helpers flag the same options as config-silencing.
  assert.ok(
    scanSuppressionText('ci/check.sh', 'set +e\nfalse\nprintf ok\n')
      .some(({ category }) => category === 'config-silencing'),
  );
  assert.ok(
    scanSuppressionText('ci/check.sh', 'set +ex\nfalse\nprintf ok\n')
      .some(({ category }) => category === 'config-silencing'),
  );
  assert.deepEqual(
    scanSuppressionText('ci/check.sh', 'set -e\npnpm test\n')
      .filter(({ category }) => category === 'config-silencing'),
    [],
  );
  // Plan level: a configured check using `set +e` is BLOCKED.
  const plan = buildCheckPlan({
    config: { commands: { typecheck: 'set +e; tsc --noEmit' } },
  });
  const typecheck = plan.checks.find(({ id }) => id === 'typecheck');
  assert.equal(typecheck.status, 'BLOCKED');
  assert.match(typecheck.evidence, /neutralizes failures/i);
});

test('rejects shell negation (!) that inverts a validation failure', () => {
  // Codex UnYb3: bash exempts a `!`-negated command from errexit and inverts
  // its exit status, so `! (npm test) >/dev/null 2>&1` exits 0 precisely when
  // the wrapped command fails — the same failure-hiding effect as `|| true`.
  assert.ok(findCommandFailureNeutralizer('! (npm test) >/dev/null 2>&1'));
  assert.ok(findCommandFailureNeutralizer('!  npm test'));
  assert.ok(findCommandFailureNeutralizer('pnpm build && ! pnpm test'));
  assert.ok(findCommandFailureNeutralizer('pnpm build; ! pnpm test'));
  assert.ok(findCommandFailureNeutralizer('! { pnpm test; }'));
  // `!=` (inequality) and a word merely containing `!` are not neutralizers.
  assert.equal(findCommandFailureNeutralizer('[ "$x" != "y" ] && pnpm test'), null);
  assert.equal(findCommandFailureNeutralizer('echo "important!" && pnpm test'), null);
  assert.equal(findCommandFailureNeutralizer('pnpm test'), null);
  // Plan level: a configured check negating its own command is BLOCKED.
  const negatedPlan = buildCheckPlan({
    config: { commands: { typecheck: '! (tsc --noEmit) >/dev/null 2>&1' } },
  });
  const negated = negatedPlan.checks.find(({ id }) => id === 'typecheck');
  assert.equal(negated.status, 'BLOCKED', JSON.stringify(negated));
  assert.match(negated.evidence, /neutralizes failures/i);
});

test('rejects shell keyword-prefixed negation (if!/elif!/while!/until!)', () => {
  // CodeRabbit UptWH: the punctuation-only anchor set (`^`, `;`, `&`, `|`,
  // newline, `(`, `{`) never matches a `!` immediately after a shell keyword
  // that itself introduces a command, so `if ! npm test; then echo skipped; fi`
  // hid a failure exactly like `! npm test` but went undetected.
  assert.ok(findCommandFailureNeutralizer('if ! npm test; then echo skipped; fi'));
  assert.ok(findCommandFailureNeutralizer('elif ! pnpm test; then true; fi'));
  assert.ok(findCommandFailureNeutralizer('while ! pnpm test; do sleep 1; done'));
  assert.ok(findCommandFailureNeutralizer('until ! pnpm test; do sleep 1; done'));
  // The remaining reserved-word anchors (Codex UrL45): `then`/`do`/`else` cover
  // the negation appearing in a taken branch, not only right after the
  // introducing keyword itself.
  assert.ok(findCommandFailureNeutralizer('if x; then ! pnpm test; fi'));
  assert.ok(findCommandFailureNeutralizer('for f in a; do ! pnpm test; done'));
  assert.ok(findCommandFailureNeutralizer('if x; then y; else ! pnpm test; fi'));
  // A command argument `!` (not a shell reserved word) must stay clean.
  assert.equal(findCommandFailureNeutralizer('find . ! -name x'), null);
  assert.equal(findCommandFailureNeutralizer('[ ! -f x ]'), null);
  assert.equal(findCommandFailureNeutralizer('[[ ! -f x ]] && pnpm test'), null);
  // Plan level: an `if !`-guarded configured command is BLOCKED too.
  const negatedIfPlan = buildCheckPlan({
    config: { commands: { typecheck: 'if ! pnpm test; then true; fi' } },
  });
  const negatedIf = negatedIfPlan.checks.find(({ id }) => id === 'typecheck');
  assert.equal(negatedIf.status, 'BLOCKED', JSON.stringify(negatedIf));
  assert.match(negatedIf.evidence, /neutralizes failures/i);
});

test('rejects conditional bodies that swallow a failing condition (Codex UrfC9)', () => {
  // Bash exempts any command tested by if/while/until from errexit; a
  // no-op-only branch (`:` / `true`) with no elif/else to re-raise leaves the
  // whole compound statement's own exit status at 0 regardless of whether the
  // condition command itself failed -- no `!` negation involved at all.
  assert.ok(findCommandFailureNeutralizer('if npm test >/dev/null 2>&1; then :; fi'));
  assert.ok(findCommandFailureNeutralizer('while pnpm test; do true; done'));
  assert.ok(findCommandFailureNeutralizer('until make check; do :; done'));
  // A success-yielding body (echo / printf / exit 0), not just ':' or 'true',
  // also masks a failing condition command tested by if/while/until: the
  // body's own always-0 exit status becomes the compound statement's exit
  // status (Codex Uz6AY).
  assert.ok(findCommandFailureNeutralizer('if npm test >/dev/null 2>&1; then echo ok; fi'));
  assert.ok(findCommandFailureNeutralizer('if pnpm test; then printf done; fi'));
  assert.ok(findCommandFailureNeutralizer('while make check; do echo running; done'));
  // A guard whose taken branch runs the real check (or whose else branch
  // re-raises the failure) still propagates and must stay clean.
  assert.equal(findCommandFailureNeutralizer('if [ -f package.json ]; then npm test; fi'), null);
  assert.equal(findCommandFailureNeutralizer('if npm test; then echo pass; else exit 1; fi'), null);
  assert.equal(findCommandFailureNeutralizer('pnpm test'), null);
  // Plan level: a configured check wrapped in a swallowing conditional is
  // BLOCKED too.
  const swallowedPlan = buildCheckPlan({
    config: { commands: { typecheck: 'if pnpm test >/dev/null 2>&1; then :; fi' } },
  });
  const swallowed = swallowedPlan.checks.find(({ id }) => id === 'typecheck');
  assert.equal(swallowed.status, 'BLOCKED', JSON.stringify(swallowed));
  assert.match(swallowed.evidence, /neutralizes failures/i);
});

test('flags a no-op evaluation script that provides no test-execution evidence (Codex Uz6A0)', () => {
  // A command whose entire body is an empty/whitespace-only `node -e ""` /
  // `node --eval ''` exits 0 with no output: it provides no authoritative
  // test-execution evidence -- the same do-nothing effect passWithNoTests has
  // -- so a test row can become clean without running anything. The WHOLE
  // command must be that no-op (an optional ENV=val prefix is allowed); a real
  // evaluation body, or a composed command whose failure still short-circuits
  // and propagates, stays clean.
  assert.ok(findCommandFailureNeutralizer('node -e ""'));
  assert.ok(findCommandFailureNeutralizer("node -e ''"));
  assert.ok(findCommandFailureNeutralizer('node --eval "  "'));
  assert.ok(findCommandFailureNeutralizer('FOO=bar node -e ""'));
  assert.equal(findCommandFailureNeutralizer('node -e "console.log(1)"'), null);
  assert.equal(findCommandFailureNeutralizer('node --eval "process.exit(0)"'), null);
  assert.equal(findCommandFailureNeutralizer('npm test && node -e ""'), null);
});

test('flags pytest, Go, and Rust native skip forms in touched test files', () => {
  // Codex UDDQN: the weakening scan only knew JavaScript/Jest forms; the
  // native skip forms of the other test ecosystems the scanner treats as
  // test-like must be caught under the same gating and finding shape.
  const python = scanSuppressionText('tests/test_api.py', [
    '@pytest.mark.skip(reason="slow")',
    '@pytest.mark.skipif(sys.platform == "win32")',
    '@pytest.mark.xfail(reason="broken")',
    'pytest.skip("not supported")',
    'pytestmark = pytest.mark.skip(reason="module disabled")',
  ].join('\n')).filter(({ category }) => category === 'test-weakening');
  assert.equal(python.length, 5, `expected 5 pytest findings: ${JSON.stringify(python)}`);
  const go = scanSuppressionText('pkg/foo_test.go', [
    't.Skip("skip this")',
    't.Skipf("skip %d", 1)',
    't.SkipNow()',
  ].join('\n')).filter(({ category }) => category === 'test-weakening');
  assert.equal(go.length, 3, `expected 3 Go findings: ${JSON.stringify(go)}`);
  const rust = scanSuppressionText('tests/lib.rs', '#[ignore]')
    .filter(({ category }) => category === 'test-weakening');
  assert.equal(rust.length, 1, `expected 1 Rust finding: ${JSON.stringify(rust)}`);
  // Gating is unchanged: the same text outside a test-like file, or inert
  // inside a string, produces no finding.
  assert.deepEqual(
    scanSuppressionText('src/api.py', '@pytest.mark.skip(reason="slow")')
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  assert.deepEqual(
    scanSuppressionText('tests/test_api.py', '# @pytest.mark.skip(reason="documented")')
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', 'const s = "pytest.mark.skip";')
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
});

test('flags node:test context skip (lowercase t.skip) as test-weakening', () => {
  // CodeRabbit UnYb2: node:test's TestContext#skip() is a real runtime skip,
  // not merely a "legitimate conditional platform gate" — an unconditional
  // `t.skip()` reports the test as skipped and `node --test` exits 0
  // regardless of what unreachable code follows, so a PR can replace a real
  // assertion with a bare skip call and keep the suppression scan silent.
  const hidden = scanSuppressionText(
    'src/foo.test.js',
    "test('hidden', t => { t.skip(); throw new Error('never checked'); });",
  ).filter(({ category }) => category === 'test-weakening');
  assert.equal(hidden.length, 1, `expected 1 finding: ${JSON.stringify(hidden)}`);
  // A message argument is also caught.
  assert.equal(
    scanSuppressionText('src/foo.test.js', "test('x', (t) => { t.skip('reason'); });")
      .filter(({ category }) => category === 'test-weakening').length,
    1,
  );
  // Gating is unchanged: outside a test-like file, or inert inside a comment
  // or string, the same text produces no finding; an unrelated receiver whose
  // name merely ends in "t" (e.g. "test.skip", "context.skip") is a distinct,
  // already-covered dot-member form and must not double-count here.
  assert.deepEqual(
    scanSuppressionText('src/foo.js', 't.skip();').filter(({ category }) => category === 'test-weakening'),
    [],
  );
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', '// t.skip();').filter(({ category }) => category === 'test-weakening'),
    [],
  );
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', 'const s = "t.skip();";').filter(({ category }) => category === 'test-weakening'),
    [],
  );
});

test('classifies a root-level test_*.py module as test-like (pytest prefix convention)', () => {
  // Codex UgisO: pytest's OTHER default discovery glob (python_files =
  // test_*.py *_test.py) is a prefix form. A root-level test_example.py has
  // no tests/ directory ancestor and no *_test.py suffix, so it previously
  // fell through testLike entirely and the native pytest scan never ran.
  const findings = scanSuppressionText(
    'test_example.py',
    '@pytest.mark.skip\ndef test_x(): pass',
  ).filter(({ category }) => category === 'test-weakening');
  assert.equal(findings.length, 1, `expected 1 finding: ${JSON.stringify(findings)}`);
  // A non-test module with an unrelated "test_" substring mid-name, or a
  // module that merely contains the word test_ but does not start with it,
  // must not be swept in by the new branch.
  assert.deepEqual(
    scanSuppressionText('latest_example.py', '@pytest.mark.skip\ndef test_x(): pass')
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  assert.deepEqual(
    scanSuppressionText('contest_data.py', '@pytest.mark.skip\ndef test_x(): pass')
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
});

test('flags option-object, this.skip(), and .skipIf() executable test-skip forms', () => {
  // Codex Ugisa: the weakening patterns only covered a literal .skip/.only/
  // .todo terminal member, missing three forms that skip at runtime without
  // ever writing that member: Node's own options-object skip, Mocha's
  // this.skip() called from inside a running test body, and Vitest's
  // .skipIf(cond)(...) conditional-skip call chain.
  assert.equal(
    scanSuppressionText('src/foo.test.js', "test('x', { skip: true }, () => {});")
      .filter(({ category }) => category === 'test-weakening').length,
    1,
  );
  // A test TITLE that contains a comma must not defeat option-object skip
  // detection: the lazy comma-tolerant prefix spans the whole title arg before
  // landing on the options `{` (CodeRabbit U3Q0c). The unconditional `skip:
  // true` is still flagged, and the `skip: false` falsy exemption still holds
  // through a comma-bearing title.
  assert.equal(
    scanSuppressionText('src/foo.test.js', "test('handles a, b, and c', { skip: true }, () => {});")
      .filter(({ category }) => category === 'test-weakening').length,
    1,
  );
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', "test('handles a, b, and c', { skip: false }, () => {});")
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  assert.equal(
    scanSuppressionText('src/foo.test.js', "test('x', { skip: 'not ready' }, () => {});")
      .filter(({ category }) => category === 'test-weakening').length,
    1,
  );
  assert.equal(
    scanSuppressionText('src/foo.test.js', "it('x', function () { this.skip(); });")
      .filter(({ category }) => category === 'test-weakening').length,
    1,
  );
  assert.equal(
    scanSuppressionText('src/foo.test.js', 'describe.skipIf(cond)("x", () => {});')
      .filter(({ category }) => category === 'test-weakening').length,
    1,
  );
  assert.equal(
    scanSuppressionText('src/foo.test.js', 'it.skipIf(cond)("x", () => {});')
      .filter(({ category }) => category === 'test-weakening').length,
    1,
  );
  // Optional-chaining Vitest skip: `it?.skipIf(cond)(...)` still skips at
  // runtime when `it` is defined and must be detected too (Codex UiTMl: the
  // prior regex accepted `?.` only when followed by a redundant literal `.`,
  // so this valid real-world form was a dead branch that never matched).
  assert.equal(
    scanSuppressionText('src/foo.test.js', 'it?.skipIf(cond)("x", () => {});')
      .filter(({ category }) => category === 'test-weakening').length,
    1,
  );
  // Gating and false-positive controls: outside a test-like file, or inert
  // inside a comment/string, none of these forms should be flagged; nor
  // should an unrelated this.<name>() call or a plain object literal that
  // merely happens to have a `skip` key.
  assert.deepEqual(
    scanSuppressionText('src/foo.js', "test('x', { skip: true }, () => {});")
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', "// test('x', { skip: true }, () => {});")
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', 'this.skipValidation();')
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', 'const cfg = { skip: true };')
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  // A runtime-truthy BARE reference (Codex Uz6Ag): node:test skips whenever
  // the skip value is truthy, so a bare always-truthy value with no falsy
  // escape -- `skip: process.env.CI`, `skip: flags.quiet`, `skip: SHOULD_SKIP`
  // -- skips the test in CI while the scan reports clean.
  for (const line of [
    "test('x', { skip: process.env.CI }, () => {});",
    'test("y", { skip: flags.quiet }, fn);',
    "test('z', { skip: SHOULD_SKIP }, fn);",
  ]) {
    const matches = scanSuppressionText('src/foo.test.js', line)
      .filter(({ category }) => category === 'test-weakening');
    assert.equal(matches.length, 1, `${line} must be flagged as a runtime-truthy skip, got: ${JSON.stringify(matches)}`);
  }
  // A provably-falsy value (false / null / undefined) does NOT skip under
  // node:test and must not be flagged; nor must a value that carries a falsy
  // escape via a ternary / short-circuit / comparison -- this repo's own test
  // suite gates POSIX/Windows-only tests with exactly those forms, and a
  // static scanner cannot evaluate them, so they are legitimate platform
  // gates rather than unconditional weakening.
  for (const line of [
    "test('a', { skip: false }, () => {});",
    'test("b", { skip: null }, fn);',
    "test('c', { skip: undefined }, fn);",
    "test('p', { skip: process.platform === 'win32' ? 'posix-only' : false }, fn);",
    "test('q', { skip: !available && 'feature unavailable' }, fn);",
    "test('r', { skip: cond ? 'reason' : false }, fn);",
  ]) {
    const matches = scanSuppressionText('src/foo.test.js', line)
      .filter(({ category }) => category === 'test-weakening');
    assert.deepEqual(matches, [], `${line} must not be flagged (falsy or legitimate platform gate)`,);
  }
  // An empty-string skip reason is falsy under node:test, so the test still
  // runs — `skip: ''` and `skip: ""` must NOT be flagged (Codex UiTMl false
  // positive), while `skip: true` and a non-empty reason (asserted above) do.
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', "test('x', { skip: '' }, () => {});")
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', 'test(\'x\', { skip: "" }, () => {});')
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
});

test('flags multiline option-object skip test forms', () => {
  // Codex UiNu2: a node:test option-object skip split across lines —
  //   test('name', {
  //     skip: true,
  //   }, fn)
  // begins with a line that ends in `{`, not a bare receiver, so the multiline
  // fallback never opened a rescan window and the reassembled `skip: true`
  // evaded detection even though the single-line form is flagged. The window
  // must now also open on an unclosed option-object test call.
  const multilineSkip = "test('name', {\n  skip: true,\n}, async () => {});";
  assert.equal(
    scanSuppressionText('src/foo.test.js', multilineSkip)
      .filter(({ category }) => category === 'test-weakening').length,
    1,
    `multiline option-object skip must be flagged: ${JSON.stringify(scanSuppressionText('src/foo.test.js', multilineSkip))}`,
  );
  // Control: a multiline options object with no skip must NOT be flagged — the
  // window opening on an unclosed option-object call must not itself trip.
  assert.deepEqual(
    scanSuppressionText('src/foo.test.js', "test('name', {\n  timeout: 5000,\n}, () => {});")
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
  // Outside a test-like file the same multiline form is not test-weakening.
  assert.deepEqual(
    scanSuppressionText('src/foo.js', multilineSkip)
      .filter(({ category }) => category === 'test-weakening'),
    [],
  );
});

test('rules silencing stays within the rules object and ignores sibling zeros', () => {
  // A sibling numeric zero outside the rules object must NOT be flagged as a
  // disabled rule (Codex M6UFnGF): the old unbounded `rules? [\s\S]*?` regex
  // crossed the closing brace and matched `server.port:0`.
  const clean = scanSuppressionText('config.json', '{"rules":{"retry":3},"server":{"port":0}}')
    .filter((f) => f.category === 'config-silencing');
  assert.equal(clean.length, 0, `sibling zero must not be flagged, got: ${JSON.stringify(clean)}`);

  // A real disabled rule inside the rules object (JSON, nested, and at depth)
  // is still detected — including the array-form severity zero.
  for (const text of [
    '{"rules":{"no-console":"off"}}',
    '{ "rules": { "extends": { "meta": { "docs": {} }, "no-console": 0 } } }',
    "rules: { 'no-console': [0, { allow: ['warn'] }] }",
    'rules:\n  no-console: "off"\nserver:\n  port: 0',
  ]) {
    const flagged = scanSuppressionText('.eslintrc.json', text)
      .some((f) => f.category === 'config-silencing');
    assert.equal(flagged, true, `disabled rule must be flagged: ${text}`);
  }

  const lineAware = scanSuppressionText('.eslintrc.json', [
    '{',
    '  "rules": {',
    '    "no-console": "off"',
    '  }',
    '}',
  ].join('\n')).find((f) => f.category === 'config-silencing' && f.match.includes('rules'));
  assert.equal(lineAware?.line, 2, `rules finding should report its key line: ${JSON.stringify(lineAware)}`);

  // The multi-KB-distance case must still work: a disabled rule many KB after
  // the rules key, with an unrelated sibling zero after the object closes.
  const large = ['{', '  "rules": {']
    .concat(Array.from({ length: 2000 }, (_, i) => `    "filler${i}": ${i},`))
    .concat(['    "no-console": "off"', '  },', '  "server": { "port": 0 }', '}'])
    .join('\n');
  const farFlags = scanSuppressionText('.eslintrc.json', large)
    .filter((f) => f.category === 'config-silencing');
  assert.ok(farFlags.length > 0, 'a disabled rule far inside the rules object must be flagged');
});

test('scans an adversarial single-line receiver input in linear time', () => {
  // CodeRabbit UmlJL: the multiline option-object opener (opensOptionObjectCall)
  // re-walked to end-of-line for every `test(`/`describe(` match, making it
  // O(matches x length) — quadratic on one long line up to the 5 MB scan cap.
  // A minified line of tens of thousands of bare `test(` tokens has no
  // `.skip`/`.only`, so the per-line pass finds nothing and the multiline
  // fallback runs the opener on the whole line. The single-pass rewrite is
  // linear; the old code took several seconds on this input.
  //
  // CodeRabbit (3dfe49fa): a raw `elapsedMs < 3000` wall-clock threshold
  // measures the CI machine, not the algorithm, and is a flake source on a
  // loaded shared runner. Compare two input sizes instead: doubling the input
  // roughly doubles a linear scan's cost but roughly quadruples a quadratic
  // one, so the ratio — not the absolute time — is what proves linearity.
  const timeScan = (tokens) => {
    const input = 'test('.repeat(tokens);
    const started = process.hrtime.bigint();
    const found = scanSuppressionText('src/adversarial.test.js', input)
      .filter(({ category }) => category === 'test-weakening');
    return { found, ms: Number(process.hrtime.bigint() - started) / 1e6 };
  };
  const small = timeScan(20000); // ~100 KB, ~20k receiver tokens
  const large = timeScan(40000); // ~200 KB, ~40k receiver tokens
  // Behavior is unchanged — no skip/only/option-object skip is present, so
  // nothing is flagged; only the cost changed.
  assert.deepEqual(small.found, [], JSON.stringify(small.found));
  assert.deepEqual(large.found, [], JSON.stringify(large.found));
  // A quadratic regression costs ~4x for a 2x input, not ~2x; allow generous
  // slack (3x plus a flat floor) so a slow/loaded runner cannot flake a
  // genuinely linear implementation.
  assert.ok(
    large.ms < Math.max(small.ms * 3 + 50, 250),
    `adversarial single-line scan must stay near-linear, not quadratic: ${small.ms.toFixed(1)}ms (20k) -> ${large.ms.toFixed(1)}ms (40k)`,
  );

  // Equivalence under load: a real option-object skip after heavy receiver
  // padding is still opened and flagged by the linear rewrite (the opener must
  // preserve the previous behavior, not just the cost).
  const paddedSkip = `${'test( , );'.repeat(5000)}\ntest('name', {\n  skip: true,\n}, () => {});`;
  assert.equal(
    scanSuppressionText('src/adversarial.test.js', paddedSkip)
      .filter(({ category }) => category === 'test-weakening').length,
    1,
    'a real option-object skip after heavy padding must still be flagged',
  );
});

test('blocks auto-discovered make targets whose recipe neutralizes failures', () => {
  // Codex Ummss: make-target resolution trusts the target NAME, but the recipe
  // body is not covered by the touched-file scan when the Makefile is
  // unchanged. A recipe must be rejected the same way an auto-discovered
  // package script is (see the package-script test above) — including Make's
  // leading `-` ignore-error prefix, which makes `make <target>` exit 0 even
  // when the command fails.
  const dashPlan = buildCheckPlan({
    makeTargets: ['grafana-render'],
    makeRecipes: { 'grafana-render': '\t-node scripts/render-grafana.js' },
  });
  const dash = dashPlan.checks.find(({ id }) => id === 'grafana-render');
  assert.equal(dash.status, 'BLOCKED', JSON.stringify(dash));
  assert.equal(dash.resolution, 'make-target');
  assert.equal(dash.command, 'make grafana-render');
  assert.match(dash.evidence, /neutralizes failures \(-\)/i);

  // A shared shell neutralizer (`|| true`) inside a recipe is rejected too.
  const orPlan = buildCheckPlan({
    makeTargets: ['grafana-render'],
    makeRecipes: { 'grafana-render': 'node scripts/render-grafana.js || true' },
  });
  const or = orPlan.checks.find(({ id }) => id === 'grafana-render');
  assert.equal(or.status, 'BLOCKED', JSON.stringify(or));
  assert.match(or.evidence, /neutralizes failures/i);
  assert.match(or.evidence, /\|\|\s*true/i);

  // Negative control: a benign recipe still resolves to the make target and is
  // not blocked by the recipe check. A valid artifact proof is supplied so the
  // independent REQUIRED_PROOFS block for grafana-render does not confound the
  // status assertion.
  const cleanPlan = buildCheckPlan({
    makeTargets: ['grafana-render'],
    makeRecipes: { 'grafana-render': 'node scripts/render-grafana.js' },
    config: { proofs: { 'grafana-render': { type: 'artifact', path: 'artifacts/grafana.png' } } },
  });
  const clean = cleanPlan.checks.find(({ id }) => id === 'grafana-render');
  assert.equal(clean.command, 'make grafana-render');
  assert.equal(clean.resolution, 'make-target');
  assert.notEqual(clean.status, 'BLOCKED', JSON.stringify(clean));
});

test('blocks a resolved make target whose recipe text was never captured', () => {
  // CodeRabbit 26020f13: findMakeRecipeNeutralizer(undefined) returns null,
  // so a make target resolved by name but missing a makeRecipes[target]
  // entry (empty body, or a recipe whose capture was interrupted) previously
  // resolved as clean without its recipe ever being inspected — fail-open for
  // the exact class of failure-hiding recipe this check exists to catch.
  const noRecipePlan = buildCheckPlan({
    makeTargets: ['grafana-render'],
    makeRecipes: {},
  });
  const noRecipe = noRecipePlan.checks.find(({ id }) => id === 'grafana-render');
  assert.equal(noRecipe.status, 'BLOCKED', JSON.stringify(noRecipe));
  assert.equal(noRecipe.resolution, 'make-target');
  assert.equal(noRecipe.command, 'make grafana-render');
  assert.match(noRecipe.evidence, /no recipe text was captured/i);
  // Omitting makeRecipes entirely (the default {}) is the same case.
  const omittedPlan = buildCheckPlan({ makeTargets: ['grafana-render'] });
  assert.equal(
    omittedPlan.checks.find(({ id }) => id === 'grafana-render').status,
    'BLOCKED',
  );
  // Negative control: a captured (even trivially short) recipe still resolves
  // normally — this case is not affected by the fail-closed check above.
  const capturedPlan = buildCheckPlan({
    makeTargets: ['grafana-render'],
    makeRecipes: { 'grafana-render': 'node scripts/render-grafana.js' },
    config: { proofs: { 'grafana-render': { type: 'artifact', path: 'artifacts/grafana.png' } } },
  });
  const captured = capturedPlan.checks.find(({ id }) => id === 'grafana-render');
  assert.notEqual(captured.status, 'BLOCKED', JSON.stringify(captured));
});

test('flags a source exclusion padded beyond the old ignore-array scan window', () => {
  // Codex UnKZ_: the previous ignore/exclude patterns bridged the key to its
  // value with a bounded `(?:\[[\s\S]{0,50000}?)?` window. Padding an ignore
  // array with >50000 chars of benign globs before the real `"src/**"` entry
  // pushed the source exclusion outside the window, so the scan missed it. The
  // bracket-aware helper walks the complete array, so array length no longer
  // bounds detection.
  const pad = Array.from({ length: 3000 }, (_, i) => `"generated-directory-number-${i}/**"`).join(', ');
  const evasive = `{"ignorePatterns": [${pad}, "src/**"]}`;
  assert.ok(evasive.length > 60000, `fixture must exceed the old 50000 window (got ${evasive.length})`);
  assert.ok(
    scanSuppressionText('.eslintrc.json', evasive).some((f) => f.category === 'config-silencing'),
    'a src/** exclusion padded past 50000 chars must still be flagged',
  );
  // The benign padding alone (no source exclusion) stays unflagged, so the
  // helper is not simply flagging any long ignore array.
  const benign = `{"ignorePatterns": [${pad}]}`;
  assert.deepEqual(
    scanSuppressionText('.eslintrc.json', benign).filter((f) => f.category === 'config-silencing'),
    [],
    'a long ignore array of only benign globs must not be flagged',
  );
});

test('flags a YAML native block-sequence ignorePatterns list (Codex UrfDK)', () => {
  // A touched `.eslintrc.yml` using ESLint's native YAML block-sequence form
  // (`ignorePatterns:` followed by indented `- "..."` items) is neither a
  // `[...]` array nor a direct quoted scalar, so it previously yielded no
  // scanned region at all and a `src/**` exclusion went undetected.
  const yamlSuppressing = ['ignorePatterns:', '  - "src/**"', '  - "generated/**"'].join('\n');
  assert.ok(
    scanSuppressionText('.eslintrc.yml', yamlSuppressing).some((f) => f.category === 'config-silencing'),
    'a YAML block-sequence src/** exclusion must be flagged',
  );
  // Benign block-sequence entries (build artifacts only) stay unflagged.
  const yamlBenign = ['ignorePatterns:', '  - "dist/**"', '  - "coverage/**"'].join('\n');
  assert.deepEqual(
    scanSuppressionText('.eslintrc.yml', yamlBenign).filter((f) => f.category === 'config-silencing'),
    [],
    'a YAML block-sequence of only benign globs must not be flagged',
  );
  // A sibling key at or below the ignorePatterns indentation ends the block,
  // so its content (even a src/** mention) is not swallowed into the scanned
  // region as if it were one more ignore entry.
  const yamlSibling = ['ignorePatterns:', '  - "dist/**"', 'notes: "unrelated src/** mention"'].join('\n');
  assert.deepEqual(
    scanSuppressionText('.eslintrc.yml', yamlSibling).filter((f) => f.category === 'config-silencing'),
    [],
    'a sibling key at or below the ignorePatterns indentation must end the block',
  );
  // A real-world shape -- ignorePatterns followed by a sibling rules: block --
  // still gets the rules key scanned independently and correctly. (The
  // findRulesScopedSilencings finding is a fixed "rules: { ... }" template,
  // never the matched rule id, so this checks category + the rules: prefix
  // rather than a literal rule-name substring.)
  const yamlRealistic = ['ignorePatterns:', '  - "dist/**"', 'rules:', '  no-console: "off"'].join('\n');
  assert.ok(
    scanSuppressionText('.eslintrc.yml', yamlRealistic)
      .some((f) => f.category === 'config-silencing' && f.match.startsWith('rules:')),
    'a rules: key following an ignorePatterns block must still be scanned on its own',
  );
});

test('blocks fixed Make checks whose recipe neutralizes failure', () => {
  // The fixed-check branch (make-smoke/make-sbom/make-audit/make-pr-check)
  // previously returned before ever consulting makeRecipes, so a fixed
  // target's recipe was never inspected -- unlike an auto-discovered
  // makeCandidates target just below it in buildCheckPlan, which already
  // rejects a failure-hiding recipe. An unchanged base Makefile defining
  // `pr-check` as `npm test >/dev/null 2>&1 || true` therefore let
  // `make pr-check` exit 0, unexamined, even with failing tests (Codex:
  // "Inspect recipes behind fixed Make checks").
  const swallowedPlan = buildCheckPlan({
    makeRecipes: { 'pr-check': 'npm test >/dev/null 2>&1 || true' },
  });
  const swallowed = swallowedPlan.checks.find(({ id }) => id === 'make-pr-check');
  assert.equal(swallowed.status, 'BLOCKED', JSON.stringify(swallowed));
  assert.equal(swallowed.resolution, 'fixed');
  assert.match(swallowed.evidence, /neutralizes failures/i);
  assert.match(swallowed.evidence, /\|\|\s*true/i);

  // A fixed Make target whose recipe text was never captured fails closed
  // too, the same way an unresolved makeCandidates recipe already does.
  const noRecipe = buildCheckPlan({ makeRecipes: {} })
    .checks.find(({ id }) => id === 'make-smoke');
  assert.equal(noRecipe.status, 'BLOCKED', JSON.stringify(noRecipe));
  assert.equal(noRecipe.resolution, 'fixed');
  assert.match(noRecipe.evidence, /no recipe text was captured/i);
  // Omitting makeRecipes entirely (the default {}) is the same case.
  assert.equal(
    buildCheckPlan({}).checks.find(({ id }) => id === 'make-audit').status,
    'BLOCKED',
  );

  // Negative control: a fixed Make check with a clean, captured recipe still
  // resolves normally and is not blocked by this check (no false positive).
  // make-sbom independently requires its own artifact proof (REQUIRED_PROOFS),
  // so one is supplied to isolate this assertion to the recipe-neutralizer
  // check, mirroring the equivalent makeCandidates clean-recipe control above.
  const cleanPlan = buildCheckPlan({
    makeRecipes: {
      smoke: 'node scripts/smoke.js',
      sbom: 'node scripts/sbom.js',
      audit: 'node scripts/audit.js',
      'pr-check': 'npm test',
    },
    config: { proofs: { 'make-sbom': { type: 'artifact', path: 'artifacts/sbom.json' } } },
  });
  for (const id of ['make-smoke', 'make-sbom', 'make-audit', 'make-pr-check']) {
    const check = cleanPlan.checks.find((c) => c.id === id);
    assert.notEqual(check.status, 'BLOCKED', JSON.stringify(check));
    assert.equal(check.resolution, 'fixed');
  }
});

test('validateEngineChecks normalizes a valid matrix', () => {
  const defs = validateEngineChecks([
    { id: 'unit', command: 'cargo test' },
    { id: 'lint', label: 'Lint', scripts: ['lint', 'lint:all'], baselineSafe: true, timeoutMs: 60000 },
  ]);
  assert.deepEqual(defs[0], {
    id: 'unit', label: 'unit', command: 'cargo test', baselineSafe: false, generator: false, engine: true,
  });
  assert.deepEqual(defs[1], {
    id: 'lint', label: 'Lint', packageCandidates: ['lint', 'lint:all'], baselineSafe: true, generator: false, timeoutMs: 60000, engine: true,
  });
});

test('validateEngineChecks fails closed on every malformed shape', () => {
  assert.throws(() => validateEngineChecks(undefined), /non-empty array/);
  assert.throws(() => validateEngineChecks([]), /non-empty array/);
  assert.throws(() => validateEngineChecks(['x']), /must be an object/);
  assert.throws(() => validateEngineChecks([{ command: 'x' }]), /non-empty string id/);
  assert.throws(() => validateEngineChecks([{ id: ' padded ', command: 'x' }]), /leading or trailing whitespace/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x' }, { id: 'a', command: 'y' }]), /unique/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', fixed: true }]), /unknown field "fixed"/);
  assert.throws(() => validateEngineChecks([{ id: 'a' }]), /exactly one of "command" or "scripts"/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', scripts: ['y'] }]), /exactly one of "command" or "scripts"/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: '   ' }]), /command must be a non-empty string/);
  assert.throws(() => validateEngineChecks([{ id: 'a', scripts: [] }]), /non-empty array of non-empty script names/);
  assert.throws(() => validateEngineChecks([{ id: 'a', scripts: ['ok', 42] }]), /non-empty array of non-empty script names/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', label: '' }]), /label must be a non-empty string/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', baselineSafe: 'yes' }]), /baselineSafe must be a boolean/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', timeoutMs: 0 }]), /timeoutMs must be a positive integer/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', timeoutMs: 1.5 }]), /timeoutMs must be a positive integer/);
});

test('validateEngineChecks hardening: id charset, prototype collisions, timer bound, read-once fields', () => {
  for (const id of ['bad\nid', 'a\tb', '.dot-start', '-dash-start', 'sp ace', '__proto__']) {
    assert.throws(
      () => validateEngineChecks([{ id, command: 'x' }]),
      /must start alphanumeric|collides with an Object\.prototype member/,
    );
  }
  for (const id of ['constructor', 'toString', 'valueOf', 'hasOwnProperty']) {
    assert.throws(
      () => validateEngineChecks([{ id, command: 'x' }]),
      /collides with an Object\.prototype member/,
    );
  }
  assert.equal(validateEngineChecks([{ id: 'ok.check_1-x', command: 'x' }])[0].id, 'ok.check_1-x');
  assert.throws(
    () => validateEngineChecks([{ id: 'big', command: 'x', timeoutMs: 2147483648 }]),
    /no greater than 2147483647/,
  );
  // Read-once: a getter that swaps its value after the first read cannot
  // sneak a different command past validation into the emitted definition.
  let reads = 0;
  const swapped = validateEngineChecks([{
    id: 'g1',
    get command() { reads += 1; return reads === 1 ? 'safe command' : 'npm test || true'; },
  }])[0];
  assert.equal(swapped.command, 'safe command');
  const scriptsSource = ['ok'];
  const proxied = validateEngineChecks([new Proxy({ id: 'p1', scripts: scriptsSource }, {
    get(target, property) {
      if (property === 'scripts') return [...scriptsSource];
      return target[property];
    },
  })])[0];
  assert.deepEqual(proxied.packageCandidates, ['ok']);
});

test('strict mode rejects engine-only config keys as weakening attempts, never ignores them', () => {
  const withMatrix = buildCheckPlan({ config: { engineChecks: [{ id: 'a', command: 'x' }] } });
  assert.match(withMatrix.errors.join('\n'), /engineChecks is only valid with --mode engine/);
  const withRunner = buildCheckPlan({ config: { scriptRunner: 'npm run' } });
  assert.match(withRunner.errors.join('\n'), /scriptRunner is only valid with --mode engine/);
  // The strict matrix itself still resolves; the error rides alongside.
  assert.equal(withMatrix.checks.length, MANDATORY_CHECKS.length);
});

test('engine mode resolves inline commands and script discovery through the shared pipeline', () => {
  const plan = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [
        { id: 'unit', command: 'cargo test --workspace' },
        { id: 'lint', scripts: ['lint:ci', 'lint'] },
        { id: 'ghost', scripts: ['does-not-exist'] },
      ],
    },
    packageScripts: { lint: 'eslint .' },
  });
  assert.deepEqual(plan.errors, []);
  assert.deepEqual(plan.checks.map(({ id }) => id), ['unit', 'lint', 'ghost']);
  const unit = plan.checks.find(({ id }) => id === 'unit');
  assert.equal(unit.command, 'cargo test --workspace');
  assert.equal(unit.resolution, 'engine-command');
  assert.equal(unit.status, undefined);
  const lint = plan.checks.find(({ id }) => id === 'lint');
  assert.equal(lint.command, 'npm run lint');
  assert.equal(lint.resolution, 'package-script');
  const ghost = plan.checks.find(({ id }) => id === 'ghost');
  assert.equal(ghost.status, 'BLOCKED');
  assert.equal(ghost.resolution, 'unresolved');
});

test('engine mode never trusts user-supplied commands: placeholder, neutralizer, and make-recipe validation', () => {
  const plan = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [
        { id: 'todo', command: '<replace me>' },
        { id: 'hidden', command: 'npm test || true' },
        { id: 'uncaptured', command: 'make smoke' },
        { id: 'neutralized', command: 'make lie' },
      ],
    },
    makeRecipes: { lie: '-npm test' },
  });
  assert.equal(plan.checks.find(({ id }) => id === 'todo').status, 'BLOCKED');
  assert.match(plan.checks.find(({ id }) => id === 'todo').evidence, /placeholder/i);
  assert.equal(plan.checks.find(({ id }) => id === 'hidden').status, 'BLOCKED');
  assert.match(plan.checks.find(({ id }) => id === 'hidden').evidence, /neutralizes failures/);
  assert.equal(plan.checks.find(({ id }) => id === 'uncaptured').status, 'BLOCKED');
  assert.match(plan.checks.find(({ id }) => id === 'uncaptured').evidence, /No recipe text was captured/);
  assert.equal(plan.checks.find(({ id }) => id === 'neutralized').status, 'BLOCKED');
  assert.match(plan.checks.find(({ id }) => id === 'neutralized').evidence, /neutralizes failures/);
});

test('engine mode fails closed at the matrix level: invalid matrix or forbidden keys yield BLOCKED-empty plans', () => {
  const invalid = buildCheckPlan({ mode: 'engine', config: { engineChecks: [{ id: 'a' }] } });
  assert.deepEqual(invalid.checks, []);
  assert.match(invalid.errors.join('\n'), /exactly one of "command" or "scripts"/);
  const missing = buildCheckPlan({ mode: 'engine', config: {} });
  assert.deepEqual(missing.checks, []);
  assert.match(missing.errors.join('\n'), /non-empty array/);
  const withCommands = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'a', command: 'x' }], commands: { a: 'y' } },
  });
  assert.match(withCommands.errors.join('\n'), /config\.commands is not accepted in engine mode/);
  const badMode = buildCheckPlan({ mode: 'lenient' });
  assert.deepEqual(badMode.checks, []);
  assert.match(badMode.errors.join('\n'), /Unknown closeout mode/);
});

test('engine scriptRunner is validated and applied; strict package-script output is untouched', () => {
  const custom = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: 'pnpm run' },
    packageScripts: { lint: 'eslint .' },
  });
  assert.equal(custom.checks.find(({ id }) => id === 'lint').command, 'pnpm run lint');
  const neutralizing = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: 'npm run || true &&' },
    packageScripts: { lint: 'eslint .' },
  });
  assert.match(neutralizing.errors.join('\n'), /scriptRunner neutralizes failures/);
  const multiline = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: 'npm\nrun' },
    packageScripts: { lint: 'eslint .' },
  });
  assert.match(multiline.errors.join('\n'), /single-line non-empty string/);
  // Strict path still emits pnpm run — byte-identical to today.
  const strict = buildCheckPlan({ packageScripts: { typecheck: 'tsc --noEmit' } });
  assert.equal(strict.checks.find(({ id }) => id === 'typecheck').command, 'pnpm run typecheck');
});

test('engine mode validates voluntarily attached proofs at plan time; strict proof behavior unchanged', () => {
  const badShape = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'artifact', path: '' } },
    },
  });
  assert.equal(badShape.checks.find(({ id }) => id === 'render').status, 'BLOCKED');
  assert.match(badShape.checks.find(({ id }) => id === 'render').evidence, /proof/i);
  const escaping = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'artifact', path: '../outside.json' } },
    },
  });
  assert.match(escaping.checks.find(({ id }) => id === 'render').evidence, /relative worktree path without ".."/);
  const good = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'artifact', path: 'artifacts/render.json' } },
    },
  });
  assert.equal(good.checks.find(({ id }) => id === 'render').status, undefined);
  assert.deepEqual(good.checks.find(({ id }) => id === 'render').proof, { type: 'artifact', path: 'artifacts/render.json' });
});

test('engine mode never consults a smuggled config.commands entry: the map is structurally dead, not just error-flagged', () => {
  const smuggled = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], commands: { lint: 'make lie' } },
    packageScripts: { lint: 'eslint .' },
  });
  assert.match(smuggled.errors.join('\n'), /config\.commands is not accepted in engine mode/);
  const lint = smuggled.checks.find(({ id }) => id === 'lint');
  assert.equal(lint.resolution, 'package-script');
  assert.equal(lint.command, 'npm run lint');
});

test('engine-command make gate blocks every non-bare-make dodge shape on the resolved command', () => {
  const makeRecipes = { lie: '-npm test', good: 'npm test' };
  const dodges = [
    'make lie && true',
    'make -s lie',
    'env make lie',
    'cd x && make lie',
    'make lie MYVAR=1',
    '/usr/bin/make lie',
    'make lie&&echo ok',
  ];
  const plan = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: dodges.map((command, index) => ({ id: `dodge${index}`, command })),
    },
    makeRecipes,
  });
  for (const [index, command] of dodges.entries()) {
    const check = plan.checks.find(({ id }) => id === `dodge${index}`);
    assert.equal(check.status, 'BLOCKED', `expected BLOCKED for "${command}"`);
    assert.match(check.evidence, /wraps or argument-extends make and cannot be admitted uninspected/);
  }
  const pureLie = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'pure-lie', command: 'make lie' }] },
    makeRecipes,
  });
  const lieCheck = pureLie.checks.find(({ id }) => id === 'pure-lie');
  assert.equal(lieCheck.status, 'BLOCKED');
  assert.match(lieCheck.evidence, /neutralizes failures/);
  const pureGood = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'pure-good', command: 'make good' }] },
    makeRecipes,
  });
  const goodCheck = pureGood.checks.find(({ id }) => id === 'pure-good');
  assert.equal(goodCheck.status, undefined);
  assert.equal(goodCheck.command, 'make good');
  const notGated = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [
        { id: 'cmake-build', command: 'cmake build' },
        { id: 'make-docs', command: 'make-docs generate' },
      ],
    },
    makeRecipes,
  });
  assert.equal(notGated.checks.find(({ id }) => id === 'cmake-build').status, undefined);
  assert.equal(notGated.checks.find(({ id }) => id === 'make-docs').status, undefined);
});

test('engine package-script branch runs the resolved command through the same make gate', () => {
  const pure = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: 'make' },
    packageScripts: { lint: 'eslint .' },
    makeRecipes: { lint: '-eslint .' },
  });
  const pureCheck = pure.checks.find(({ id }) => id === 'lint');
  assert.equal(pureCheck.command, 'make lint');
  assert.equal(pureCheck.status, 'BLOCKED');
  assert.match(pureCheck.evidence, /neutralizes failures/);
  const wrapped = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: 'nice -n 19 make' },
    packageScripts: { lint: 'eslint .' },
    makeRecipes: { lint: '-eslint .' },
  });
  const wrappedCheck = wrapped.checks.find(({ id }) => id === 'lint');
  assert.equal(wrappedCheck.status, 'BLOCKED');
  assert.match(wrappedCheck.evidence, /wraps or argument-extends make and cannot be admitted uninspected/);
  // Strict path with the same packageScripts is unchanged: still pnpm run, ungated
  // (a strict def is never `engine`, so the gate never runs for it, no matter
  // what makeRecipes contains).
  const strict = buildCheckPlan({
    packageScripts: { typecheck: 'tsc --noEmit' },
    makeRecipes: { typecheck: '-tsc --noEmit' },
  });
  const strictCheck = strict.checks.find(({ id }) => id === 'typecheck');
  assert.equal(strictCheck.command, 'pnpm run typecheck');
  assert.equal(strictCheck.status, undefined);
});

test('engine command proofs get strict parity: neutralizer and literal-policy validation at plan time', () => {
  const neutralizing = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'command', command: 'check.sh || true', expectedPattern: 'literal:ok' } },
    },
  });
  const neutralizingCheck = neutralizing.checks.find(({ id }) => id === 'render');
  assert.equal(neutralizingCheck.status, 'BLOCKED');
  assert.match(neutralizingCheck.evidence, /Postcondition proof command for .* neutralizes failures \(\|\| true\)\./);
  const anyPattern = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'command', command: 'check.sh', expectedPattern: 'anything-at-all' } },
    },
  });
  assert.match(
    anyPattern.checks.find(({ id }) => id === 'render').evidence,
    /must be a literal: policy with a non-empty value/,
  );
  const emptyLiteral = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'command', command: 'check.sh', expectedPattern: 'literal:' } },
    },
  });
  assert.match(
    emptyLiteral.checks.find(({ id }) => id === 'render').evidence,
    /must be a literal: policy with a non-empty value/,
  );
  const good = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'command', command: 'check.sh', expectedPattern: 'literal:ok' } },
    },
  });
  const goodCheck = good.checks.find(({ id }) => id === 'render');
  assert.equal(goodCheck.status, undefined);
  assert.deepEqual(goodCheck.proof, { type: 'command', command: 'check.sh', expectedPattern: 'literal:ok' });
});

test('scriptRunner rejects tabs and quote characters, not just newlines', () => {
  const tabForm = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: 'npm\trun' },
    packageScripts: { lint: 'eslint .' },
  });
  assert.match(tabForm.errors.join('\n'), /single-line non-empty string/);
  const doubleQuoteForm = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: 'npm run "x"' },
    packageScripts: { lint: 'eslint .' },
  });
  assert.match(doubleQuoteForm.errors.join('\n'), /single-line non-empty string/);
  const singleQuoteForm = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: "npm run 'x'" },
    packageScripts: { lint: 'eslint .' },
  });
  assert.match(singleQuoteForm.errors.join('\n'), /single-line non-empty string/);
  // Existing valid runners are unaffected.
  const valid = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: 'pnpm run' },
    packageScripts: { lint: 'eslint .' },
  });
  assert.equal(valid.checks.find(({ id }) => id === 'lint').command, 'pnpm run lint');
});

test('engine make gate blocks shell-quoting/substitution dodges and make aliases (measured fix)', () => {
  // Clean recipe: every dodge below must block on SHAPE (it never reaches
  // the pure `make <target>` branch), not on recipe content.
  const makeRecipes = { lie: 'npm test' };
  const dodges = [
    ['backtick-wrapped', '`make lie`'],
    ['double-quoted make', '"make" lie'],
    ['single-quoted make', "'make' lie"],
    ['bash -c double-quoted', 'bash -c "make lie"'],
    ['sh -c single-quoted', "sh -c 'make lie'"],
    ['eval double-quoted', 'eval "make lie"'],
    ['brace group', '{make lie;}'],
    ['assignment + backtick substitution', 'x=`make lie`'],
    ['gmake alias', 'gmake lie'],
    ['make.exe alias', 'make.exe lie'],
    ['mingw32-make alias', 'mingw32-make lie'],
    ['pathed .exe alias', '/usr/bin/make.exe lie'],
  ];
  const plan = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: dodges.map(([, command], index) => ({ id: `dodge${index}`, command })),
    },
    makeRecipes,
  });
  for (const [index, [name, command]] of dodges.entries()) {
    const check = plan.checks.find(({ id }) => id === `dodge${index}`);
    assert.equal(check.status, 'BLOCKED', `expected BLOCKED for ${name}: "${command}"`);
    assert.match(
      check.evidence,
      /wraps or argument-extends make and cannot be admitted uninspected/,
      `expected wrap-form evidence for ${name}: "${command}"`,
    );
  }
});

test('original make-gate dodge corpus remains BLOCKED after the alias/quoting fix (spot-check)', () => {
  const makeRecipes = { lie: '-npm test' };
  const spotChecks = ['make lie && true', '/usr/bin/make lie', 'cd x && make lie'];
  const plan = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: spotChecks.map((command, index) => ({ id: `orig${index}`, command })) },
    makeRecipes,
  });
  for (const [index, command] of spotChecks.entries()) {
    const check = plan.checks.find(({ id }) => id === `orig${index}`);
    assert.equal(check.status, 'BLOCKED', `expected BLOCKED for "${command}"`);
  }
});

test('make gate false-positive guards remain clean: cmake, make-docs, make.js, a makerelease script', () => {
  const plan = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [
        { id: 'cmake-build', command: 'cmake --build .' },
        { id: 'make-docs', command: 'make-docs build' },
        { id: 'node-make-js', command: 'node make.js' },
        { id: 'makerelease-script', command: './scripts/makerelease.sh' },
      ],
    },
  });
  for (const id of ['cmake-build', 'make-docs', 'node-make-js', 'makerelease-script']) {
    assert.equal(plan.checks.find((check) => check.id === id).status, undefined, `expected ${id} to resolve cleanly`);
  }
});

test('gmake alias is blocked as wrap-form, not treated as a pure recipe-inspectable target', () => {
  const plan = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'gm', command: 'gmake lint' }] },
    // Recipe is clean: if the pure-form regex mistakenly matched `gmake
    // lint`, this would resolve PASS-eligible instead of BLOCKED.
    makeRecipes: { lint: 'eslint .' },
  });
  const check = plan.checks.find(({ id }) => id === 'gm');
  assert.equal(check.status, 'BLOCKED');
  assert.match(check.evidence, /wraps or argument-extends make and cannot be admitted uninspected/);
  assert.doesNotMatch(check.evidence, /neutralizes failures/);
  assert.doesNotMatch(check.evidence, /No recipe text was captured/);
});

test('engine command proof literal-policy parity: bounded length and no control characters', () => {
  const tooLong = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'command', command: 'check.sh', expectedPattern: `literal:${'z'.repeat(300)}` } },
    },
  });
  assert.match(
    tooLong.checks.find(({ id }) => id === 'render').evidence,
    /must be a literal: policy with a non-empty value/,
  );
  const controlChar = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'command', command: 'check.sh', expectedPattern: 'literal:a\tb' } },
    },
  });
  assert.match(
    controlChar.checks.find(({ id }) => id === 'render').evidence,
    /must be a literal: policy with a non-empty value/,
  );
  const good = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'command', command: 'check.sh', expectedPattern: 'literal:ok' } },
    },
  });
  assert.equal(good.checks.find(({ id }) => id === 'render').status, undefined);
});

test('make-gate wrap-form evidence includes an actionable hint for a package script literally named "make"', () => {
  const plan = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'make-script', scripts: ['make'] }] },
    packageScripts: { make: 'echo building' },
  });
  const check = plan.checks.find(({ id }) => id === 'make-script');
  assert.equal(check.status, 'BLOCKED');
  assert.match(
    check.evidence,
    /If this is a package script named "make" rather than a make invocation, rename the script\./,
  );
});
