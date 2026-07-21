const assert = require('node:assert/strict');
const test = require('node:test');

const {
  MANDATORY_CHECKS,
  buildCheckPlan,
  classifyOutput,
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
  assert.deepEqual(
    Object.fromEntries(MANDATORY_CHECKS.filter(({ fixed }) => fixed).map(({ id, command }) => [id, command])),
    {
      'git-diff-check': 'git diff --check',
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
  });

  assert.match(plan.errors.join('\n'), /cannot override fixed check git-diff-check/i);
  assert.equal(plan.checks.find(({ id }) => id === 'git-diff-check').command, 'git diff --check');
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
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'warning: deprecated dependency' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stderr: 'BLOCKED: Redis unavailable' }).status, 'BLOCKED');
  assert.equal(classifyOutput({ exitCode: 1, stderr: 'ordinary command failure' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: null, timedOut: true }).status, 'BLOCKED');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'src/a.ts(2,4): warning TS1234: unsafe' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stderr: 'DeprecationWarning: legacy API' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stderr: 'UserWarning: unsafe fallback' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stderr: '(node:123) ExperimentalWarning: unstable API' }).status, 'FAIL');
  assert.equal(classifyOutput({ exitCode: 0, stdout: 'warning deprecated package' }).status, 'FAIL');
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

test('flags focused or skipped tests in touched test files', () => {
  // A PR can focus or skip tests in an ordinary touched test file and still
  // exit 0 from the reduced command; the closeout scanner must catch that
  // weakening without relying on the test file being a gate file.
  const findings = scanSuppressionText('src/foo.test.js', [
    'describe.only("focused suite", () => {});',
    'it.skip("skipped test");',
    'test.todo("unfinished test");',
    'context.only("another focused suite");',
    'function runTest() {} // not a weakening',
  ].join('\n'));
  const matches = findings.filter(({ category }) => category === 'test-weakening');
  assert.equal(matches.length, 4, `expected 4 test-weakening findings, got: ${JSON.stringify(matches)}`);
  // A non-test source file with the same body must not produce test-weakening
  // findings (the detection is scoped to test-like filenames).
  const nonTest = scanSuppressionText('src/foo.js', 'it.skip("not in a test file");');
  assert.deepEqual(nonTest, []);
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
  // (e.g. `'skipcq',` or `'// noqa',`) must not self-flag, while the same
  // marker used as a real directive is still detected.
  assert.deepEqual(scanSuppressionText('scripts/pr_closeout_core.js', "  'skipcq',"), []);
  assert.deepEqual(scanSuppressionText('scripts/pr_closeout_core.js', "  '// noqa',"), []);
  assert.deepEqual(scanSuppressionText('scripts/pr_closeout_core.js', '  `eslint-disable`,'), []);
  const directive = scanSuppressionText('src/code.ts', '// skipcq');
  assert.ok(
    directive.some(({ category }) => category === 'marker'),
    'real // skipcq directive must still be detected',
  );
  assert.match(directive.find(({ category }) => category === 'marker').match, /skipcq/i);
});

test('does not flag marker vocabulary in markdown inline-code spans', () => {
  // Documentation that lists the marker vocabulary in markdown inline-code
  // (e.g. references/pr-closeout-validation.md) must not self-flag: a marker
  // wrapped in backticks is an example, not a directive. Real directives in
  // prose (// skipcq, # noqa) are not wrapped and are still detected.
  assert.deepEqual(scanSuppressionText('references/pr-closeout-validation.md', '- `skipcq`'), []);
  assert.deepEqual(scanSuppressionText('README.md', 'Use `eslint-disable` only as a last resort.'), []);
  assert.deepEqual(scanSuppressionText('docs.md', 'Token wrapping (`biome-ignore`) is discouraged.'), []);
  assert.ok(
    scanSuppressionText('notes.md', 'Remember: // skipcq is forbidden.').some(({ category }) => category === 'marker'),
    'a real // skipcq directive in prose must still be detected',
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
