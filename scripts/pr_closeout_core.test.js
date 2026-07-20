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
