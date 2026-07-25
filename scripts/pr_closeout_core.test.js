const assert = require('node:assert/strict');
const test = require('node:test');

const {
  MANDATORY_CHECKS,
  buildCheckPlan,
  classifyOutput,
  findCommandFailureNeutralizer,
  scanSuppressionText,
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
  // `&& exit 0` short-circuits on failure — not a neutralizer.
  assert.equal(findCommandFailureNeutralizer('pnpm test && exit 0'), null);
  assert.equal(findCommandFailureNeutralizer('pnpm test'), null);

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
          expectedPattern: 'ok',
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
