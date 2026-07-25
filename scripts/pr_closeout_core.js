const MARKERS = [
  'skipcq',
  'biome-ignore',
  'eslint-disable',
  '@ts-ignore',
  '@ts-expect-error',
  '@ts-nocheck',
  'noqa',
  'nosec',
  '# type: ignore',
  'istanbul ignore',
  'c8 ignore',
  'pylint: disable',
  'nolint',
  'shellcheck disable',
  'stylelint-disable',
  'rubocop:disable',
  'NOSONAR',
];

const CONFIG_SILENCING = [
  /continue-on-error["']?\s*[:=]\s*true/i,
  /passWithNoTests["']?\s*[:=]\s*true/i,
  /allowNoTests["']?\s*[:=]\s*true/i,
  // Accept both `maxWarnings: N` / `max-warnings=N` (JSON/YAML) and the
  // common CLI form `--max-warnings N` (space-separated) so a PR cannot
  // silently raise the lint warning budget via a package-scripts entry.
  /max[-_]?warnings["']?\s*[:=]\s*(?:-1|[1-9]\d*)/i,
  /--max-warnings\s+(?:-1|[1-9]\d*)\b/i,
  // Increase the rules-object scan window so disabled rules are still caught
  // when they sit more than 1000 chars after the `rules:` key in real-world
  // ESLint/Biome configs. The bound stays finite to keep the regex linear.
  /["']?rules?["']?\s*[:=][\s\S]{0,4000}?["']off["']/i,
  /["']?rules?["']?\s*[:=][\s\S]{0,4000}?["'][^"'\r\n]+["']\s*:\s*0\b/i,
  /(?:lint|typecheck|audit|test|coverage)[^\n]*(?:enabled["']?\s*[:=]\s*false|disabled["']?\s*[:=]\s*true)/i,
  /["']?linter["']?\s*:\s*\{[\s\S]{0,4000}?["']?enabled["']?\s*:\s*false/i,
  /["']?skipLibCheck["']?\s*:\s*true/i,
  /["']?ignoreBuildErrors["']?\s*:\s*true/i,
  // Next.js: eslint.ignoreDuringBuilds lets production builds pass with ESLint errors.
  /["']?ignoreDuringBuilds["']?\s*:\s*true/i,
  // eslint/biome (and peer linters) --quiet suppresses warning output; since
  // the closeout gate treats warnings as a failing signal, adding --quiet to a
  // touched lint script hides exactly the warnings that would otherwise block
  // closeout. Scope to lint-tool context so legitimate probes such as
  // `git diff --quiet` are not classified as config silencing.
  /\b(?:eslint|biome|stylelint|prettier|ruff|pylint|flake8|rubocop)\b[^\n]*--quiet\b/i,
  // Consume the optional closing quote on the JSON key (e.g. "enabled":false,
  // "ignorePatterns":[...], "exclude":[...]) so config-level disabling in
  // tsconfig/eslint/biome JSON no longer slips past the scan.
  // Only flag ignore/exclude keys whose value targets source/test/spec paths.
  // A bare `"exclude":` key fires on routine config (nearly every tsconfig.json
  // excludes "dist"/"node_modules"; CI matrices use strategy.matrix.exclude),
  // producing false config-silencing findings on clean PRs. Require the value
  // to reference src/test/spec globs so only genuine source/test suppression
  // is flagged. The alternation is anchored with \b so common values that only
  // contain the token as a substring (windows-latest, attestation, contest)
  // do not false-positive.
  /["']?(?:ignore|exclude)(?:s|d|Files|Patterns)?["']?\s*[:=]\s*(?:\[[\s\S]{0,200}?)?["'][^"'\r\n]*\b(?:src|test|spec)\b[^"'\r\n]*["']/i,
  // Extension-only ignore globs (e.g. ignorePatterns: ["**/*.ts"]) suppress an
  // entire source language from the lint gate without naming a src/test/spec
  // directory, so the token-based pattern above never fires. Flag ignore /
  // exclude values that are bare source-extension globs; build artifacts such
  // as **/*.d.ts, dist, or node_modules stay unflagged.
  /["']?(?:ignore|exclude)(?:s|d|Files|Patterns)?["']?\s*[:=]\s*(?:\[[\s\S]{0,200}?)?["'](?:\*\*\/|\.\/)?\*\.(?:[cm]?[jt]sx?|py|go|rs|rb|java|php|cs)\b/i,
  /\|\|\s*true\b/i,
  // Shell zero-exit neutralizers that hide command failure from classifyOutput
  // the same way `|| true` does: `|| :` (POSIX no-op) and `|| exit 0`.
  /\|\|\s*:(?=\s|$|[;"'`&;\n])/i,
  /\|\|\s*exit\s+0\b/i,
  // Unconditional zero-exit tails that do not need ||, e.g. `jest; exit 0`.
  /(?:^|[;&\n])\s*exit\s+0\b/i,
];

const define = (id, label, options = {}) => ({ id, label, ...options });

const MANDATORY_CHECKS = [
  // {mergeBaseSha} is expanded from the live PR merge-base at plan build time
  // (not hard-coded origin/main) so release-branch PRs and non-main bases are correct.
  define('git-diff-check', 'git diff --check', { fixed: true, command: 'git diff --check {mergeBaseSha}...HEAD', qualificationSafe: true, baselineSafe: true }),
  define('pnpm-audit', 'pnpm high-severity audit', { fixed: true, command: 'pnpm audit --audit-level high', qualificationSafe: true, baselineSafe: true }),
  define('prisma-validate', 'Prisma schema validation', { fixed: true, command: 'pnpm prisma validate', baselineSafe: true }),
  define('prisma-generate', 'Prisma generation', { fixed: true, command: 'pnpm prisma generate', generator: true, baselineSafe: true }),
  define('queue-registry-tests', 'Focused queue registry tests', { packageCandidates: ['test:queue-registry', 'test:queues'], baselineSafe: true }),
  define('producer-tests', 'Focused producer tests', { packageCandidates: ['test:producers', 'test:producer'], baselineSafe: true }),
  define('worker-tests', 'Focused worker tests', { packageCandidates: ['test:workers', 'test:worker'], baselineSafe: true }),
  define('api-route-tests', 'Focused API route tests', { packageCandidates: ['test:api-routes', 'test:api'], baselineSafe: true }),
  define('redis-integration', 'Real Redis integration test', { packageCandidates: ['test:redis:integration', 'test:integration:redis'], baselineSafe: false }),
  define('biome-touched', 'Biome on touched files', { packageCandidates: ['biome:touched', 'lint:touched'], baselineSafe: true }),
  define('typecheck', 'Authoritative typecheck', { packageCandidates: ['typecheck', 'type-check', 'check:types'], baselineSafe: true }),
  define('playwright-smoke', 'Playwright smoke', { packageCandidates: ['playwright-smoke', 'test:e2e:smoke', 'test:smoke'], baselineSafe: false }),
  define('grafana-render', 'Deterministic Grafana render', { packageCandidates: ['grafana-render', 'render:grafana'], makeCandidates: ['grafana-render'], baselineSafe: true }),
  define('make-smoke', 'make smoke', { fixed: true, command: 'make smoke', baselineSafe: true }),
  define('make-sbom', 'make sbom', { fixed: true, command: 'make sbom', baselineSafe: true }),
  define('make-audit', 'make audit', { fixed: true, command: 'make audit', baselineSafe: true }),
  define('grafana-live-render', 'True live Grafana render', { packageCandidates: ['grafana-live-render', 'render:grafana-live'], makeCandidates: ['grafana-live-render'], baselineSafe: false }),
  define('hunter-build', 'Build and start hunter', { fixed: true, command: 'docker compose up -d --build hunter', baselineSafe: false }),
  define('make-pr-check', 'Complete PR gate', { fixed: true, command: 'make pr-check', baselineSafe: true }),
];

const REQUIRED_PROOFS = {
  'grafana-render': 'artifact',
  'make-sbom': 'artifact',
  'grafana-live-render': 'artifact',
  'hunter-build': 'command',
};

/**
 * POSIX single-quote a value for safe interpolation into a shell command
 * string: wraps it in `'...'`, and for each embedded `'` closes the quote,
 * inserts an escaped literal quote, and reopens it (the standard `'\''`
 * pattern). Used by expandCommand to splice touched file paths into a
 * configured check command.
 * @param {*} value - Value to quote (coerced to a string).
 * @returns {string} The single-quoted, shell-safe string.
 */
const shellQuote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;

/**
 * Substitute plan-time placeholders in a configured command string:
 * - `{touchedFiles}` → shell-quoted, space-joined touched paths
 * - `{mergeBaseSha}` → the live PR merge-base SHA (shell-quoted)
 * so fixed range checks (e.g. git-diff-check) and touched-file commands use
 * the already-resolved closeout state rather than hard-coded branch names.
 * @param {string} command - Configured command template.
 * @param {string[]} touchedFiles - Repo-relative touched file paths.
 * @param {{mergeBaseSha?: string}} [options]
 * @returns {string} The command with placeholders expanded.
 */
const expandCommand = (command, touchedFiles, { mergeBaseSha } = {}) => {
  let expanded = String(command).replaceAll(
    '{touchedFiles}',
    touchedFiles.map(shellQuote).join(' '),
  );
  if (mergeBaseSha) {
    expanded = expanded.replaceAll('{mergeBaseSha}', shellQuote(mergeBaseSha));
  }
  return expanded;
};

/**
 * Resolve every MANDATORY_CHECKS definition into either a runnable command
 * or a documented BLOCKED reason. Resolution order per check: a `fixed`
 * check always uses its own hardcoded command (a config override is an
 * error, not a silent ignore); otherwise an explicit `config.commands[id]`
 * wins (a placeholder like `<...>` or `REPLACE_...` is rejected as BLOCKED
 * rather than run), then the first matching `package.json` script, then the
 * first matching Makefile target; a check that resolves nothing is BLOCKED
 * as "unresolved". A second pass then attaches `qualificationSafe`,
 * `resourceGroup`, and `proof` from config, and independently BLOCKs a check
 * that requires a postcondition proof (REQUIRED_PROOFS) without a valid one
 * configured, `redis-integration` without a `services.redis` probe, and
 * `grafana-live-render` without a `services.grafana.url` probe — a check can
 * end up BLOCKED for more than one reason, in which case the first BLOCKED
 * evidence is extended rather than replaced. A config that sets
 * `gateIntegrityReview` (self-attestation) always produces a top-level
 * error, since only a live GitHub PR review attestation is accepted.
 * @param {{config?: object, packageScripts?: Record<string, string>, makeTargets?: string[], touchedFiles?: string[], mergeBaseSha?: string}} options
 * @returns {{checks: object[], errors: string[]}}
 */
const buildCheckPlan = ({ config = {}, packageScripts = {}, makeTargets = [], touchedFiles = [], mergeBaseSha } = {}) => {
  const commands = config.commands || {};
  const qualificationSafe = new Set(config.qualificationSafe || []);
  const resourceGroups = config.resourceGroups || {};
  const targets = new Set(makeTargets);
  const errors = [];
  if (Object.hasOwn(config, 'gateIntegrityReview')) {
    errors.push('gateIntegrityReview self-attestation is forbidden; use the required live GitHub PR review attestation.');
  }
  const expand = (command) => expandCommand(command, touchedFiles, { mergeBaseSha });
  const checks = MANDATORY_CHECKS.map((definition) => {
    const configured = commands[definition.id];
    if (definition.fixed) {
      if (configured !== undefined && configured !== definition.command) {
        errors.push(`Configuration cannot override fixed check ${definition.id}.`);
      }
      if (definition.command.includes('{mergeBaseSha}') && !mergeBaseSha) {
        return {
          ...definition,
          status: 'BLOCKED',
          resolution: 'fixed',
          evidence: 'Live merge-base SHA is required to expand the fixed git-diff-check range.',
        };
      }
      return { ...definition, command: expand(definition.command), resolution: 'fixed' };
    }
    if (typeof configured === 'string' && configured.trim()) {
      if (/^(?:<[^>]+>|REPLACE(?:_|\b))/i.test(configured.trim())) {
        return {
          ...definition,
          status: 'BLOCKED',
          resolution: 'placeholder',
          evidence: `Replace the example placeholder for ${definition.label}.`,
        };
      }
      return { ...definition, command: expand(configured.trim()), resolution: 'configured' };
    }
    const packageScript = definition.packageCandidates?.find((candidate) => packageScripts[candidate]);
    if (packageScript) {
      return { ...definition, command: `pnpm run ${packageScript}`, resolution: 'package-script' };
    }
    const makeTarget = definition.makeCandidates?.find((candidate) => targets.has(candidate));
    if (makeTarget) {
      return { ...definition, command: `make ${makeTarget}`, resolution: 'make-target' };
    }
    return {
      ...definition,
      status: 'BLOCKED',
      resolution: 'unresolved',
      evidence: `No authoritative command resolved for ${definition.label}.`,
    };
  }).map((check) => {
    const proofType = REQUIRED_PROOFS[check.id];
    const proof = config.proofs?.[check.id];
    const validArtifact = proofType === 'artifact' && proof?.type === 'artifact'
      && typeof proof.path === 'string' && proof.path.trim();
    const validCommand = proofType === 'command' && proof?.type === 'command'
      && typeof proof.command === 'string' && proof.command.trim()
      && typeof proof.expectedPattern === 'string' && proof.expectedPattern.trim();
    let resolved = {
      ...check,
      qualificationSafe: Boolean(check.qualificationSafe || qualificationSafe.has(check.id)),
      resourceGroup: resourceGroups[check.id] || null,
      proof: proof || null,
    };
    if (proofType && !validArtifact && !validCommand) {
      const proofEvidence = `A ${proofType} postcondition proof is required for ${check.label}.`;
      resolved = resolved.status === 'BLOCKED'
        ? { ...resolved, evidence: `${resolved.evidence} ${proofEvidence}` }
        : { ...resolved, status: 'BLOCKED', evidence: proofEvidence };
    }
    if (check.id === 'redis-integration' && !config.services?.redis) {
      const serviceEvidence = 'A real Redis service probe is required.';
      resolved = resolved.status === 'BLOCKED'
        ? { ...resolved, evidence: `${resolved.evidence} ${serviceEvidence}` }
        : { ...resolved, status: 'BLOCKED', evidence: serviceEvidence };
    }
    if (check.id === 'grafana-live-render' && !config.services?.grafana?.url) {
      const serviceEvidence = 'A live Grafana health probe is required.';
      resolved = resolved.status === 'BLOCKED'
        ? { ...resolved, evidence: `${resolved.evidence} ${serviceEvidence}` }
        : { ...resolved, status: 'BLOCKED', evidence: serviceEvidence };
    }
    return resolved;
  });
  return { checks, errors };
};

/**
 * Strip zero-count / no-problem status summaries (`0 warnings`, `errors: 0`,
 * `no failures`, ...) out of text before it reaches statusSignal. Some of
 * statusSignal's patterns (e.g. a line simply labelled `Failed:`) don't
 * require a nonzero count, so without this pass a clean run's own summary
 * line could be misread as reporting a failure.
 * @param {string} text - Raw text to clean.
 * @returns {string} Text with zero-count status phrases removed.
 */
const cleanZeroSummaries = (text) => text
  .replace(/\b0\s+(?:warnings?|errors?|problems?|fail(?:ed|ures?|ing)?|skips?|skipped|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)\b/gi, '')
  .replace(/\b(?:warnings?|errors?|problems?|fail(?:ed|ures?|ing)?|skips?|skipped|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)\s*(?::|=|\s)\s*0\b/gi, '')
  .replace(/\bno\s+(?:warnings?|errors?|problems?|failures?|failing|skips?|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)\b/gi, '');

const STATUS_TERM = '(?:warn(?:ing)?s?|errors?|problems?|fail(?:ed|ures?|ing)?|skips?|skipped|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)';
const COUNTED_SIGNAL = new RegExp(`(?:\\b[1-9]\\d*\\s+${STATUS_TERM}\\b|\\b${STATUS_TERM}\\s*(?::|=|\\s)\\s*[1-9]\\d*\\b)`, 'i');
const BRACKETED_SIGNAL = new RegExp(`^\\s*(?:[-*]\\s*)?\\[${STATUS_TERM}\\]`, 'i');
const LABELLED_SIGNAL = new RegExp(`^\\s*(?:[-*]\\s*)?${STATUS_TERM}\\s*[:=]`, 'i');
/**
 * Classify a single output line as a status signal worth surfacing, by
 * OR-ing several independent pattern families: a leading `✖`; a nonzero
 * counted term (`3 errors`, `errors: 3`, via COUNTED_SIGNAL); a bracketed tag
 * (`[FAIL]`) or labelled line (`Warnings:`) at line start; an all-caps
 * leading status word; compiler-style diagnostics (`file.js:12:3: warning
 * ...`); a runtime `SomeWarning:`/`SomeError:` class name; a leading
 * `warning` word (including Node's `(node:1234) Warning:` form); `npm WARN`;
 * and TAP/test-framework markers (`not ok`, `# skip`, bare
 * `skipped`/`failed`/`blocked`/`pending`/`xfailed`/`xpassed`, or `ok N ... #
 * skip`).
 * @param {string} line - A single line of command output (already ANSI-stripped).
 * @returns {boolean} True if the line matches any status-signal pattern.
 */
const statusSignal = (line) => {
  const uppercase = /^\s*(?:[-*]\s*)?(?:WARN(?:ING)?S?|ERRORS?|PROBLEMS?|FAIL(?:ED|URES?|ING)?|SKIPS?|SKIPPED|TODOS?|BLOCKS?|BLOCKED)\b/;
  const compiler = /(?:^|\s)(?:[^\s:]+(?:\(\d+(?:,\d+)?\)|:\d+(?::\d+)?)):\s*(?:warning|error)\b/i;
  const runtime = /\b(?:[A-Za-z]+Warning|[A-Za-z]+Error):/i;
  const warning = /^\s*(?:[-*]\s*)?(?:\([^)]*\)\s*)?warning\b(?:\s+|:)/i;
  const npmWarning = /\bnpm\s+WARN\b/i;
  const framework = /(?:^\s*(?:not ok\b|#\s*(?:skip|skipped)\b|(?:skipped|failed|blocked|pending|xfailed|xpassed)\b)|\bok\s+\d+\b.*#\s*skip\b)/i;
  return /^\s*✖/u.test(line) || COUNTED_SIGNAL.test(line) || BRACKETED_SIGNAL.test(line)
    || LABELLED_SIGNAL.test(line) || uppercase.test(line) || compiler.test(line)
    || runtime.test(line) || warning.test(line) || npmWarning.test(line) || framework.test(line);
};

/**
 * Extract every line of `text` worth surfacing as evidence: strips ANSI
 * escape codes, normalizes CR (both CRLF and lone-CR progress output) to LF,
 * removes zero-count summaries (cleanZeroSummaries) so they cannot be
 * mistaken for real signals, drops blank lines, and keeps only lines
 * statusSignal classifies as an actual warning/error/skip/block/failure
 * signal.
 * @param {string} text - Raw combined stdout+stderr.
 * @returns {string[]} The matching lines, in order.
 */
const findStatusSignals = (text) => cleanZeroSummaries(String(text ?? '')
  .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
  .replaceAll('\r', '\n'))
  .split(/\n/)
  .filter((line) => line.trim())
  .filter(statusSignal);

/**
 * The single authoritative PASS/FAIL/BLOCKED classifier for a command's raw
 * result, applied in strict precedence: a timeout, or a missing exit code,
 * BLOCKs (incomplete proof); a nonzero exit FAILs; otherwise `stdout`+
 * `stderr` are scanned via findStatusSignals and merged with any
 * caller-supplied `detectedSignals` — a warning/error/fail/skip/todo/xfail/
 * xpass/pending/"not ok" signal FAILs, a `block(ed)` signal BLOCKs, and any
 * other detected-but-uncategorized signal still FAILs rather than passing
 * through. An exit-0 run with zero signals is not automatically a PASS:
 * output matching "no tests found/executed" phrasing, or a numeric no-work
 * summary (TAP `# tests 0`, Vitest `Tests 0 passed`/`Test Files 0` when that
 * isn't a zero-failures bucket inside a fuller summary, Mocha `0 passing`)
 * also FAILs, because closeout requires authoritative evidence that
 * something actually ran — an empty suite exiting 0 must not count as a
 * passing check.
 * @param {{exitCode: number|null|undefined, stdout?: string, stderr?: string, timedOut?: boolean, detectedSignals?: string[]}} result
 * @returns {{status: 'PASS'|'FAIL'|'BLOCKED', evidence: string}}
 */
const classifyOutput = ({
  exitCode,
  stdout = '',
  stderr = '',
  timedOut = false,
  detectedSignals = [],
}) => {
  if (timedOut) return { status: 'BLOCKED', evidence: 'Command timed out before producing complete proof.' };
  if (exitCode === null || exitCode === undefined) {
    return { status: 'BLOCKED', evidence: 'Command did not return an exit code.' };
  }
  if (exitCode !== 0) return { status: 'FAIL', evidence: `Command exited ${exitCode}.` };
  const signals = [...new Set([
    ...findStatusSignals(`${stdout}\n${stderr}`),
    ...detectedSignals.filter((line) => typeof line === 'string' && line.trim()),
  ])];
  const failures = signals.filter((line) => /(?:\b(?:warn(?:ing)?s?|errors?|problems?|fail(?:ed|ures?|ing)?|skips?|skipped|todos?|xfails?|xfailed|xpassed|pending)\b|\bnot ok\b)/i.test(line));
  if (failures.length) return { status: 'FAIL', evidence: failures.slice(0, 5).join(' | ') };
  const blocked = signals.filter((line) => /\bblocks?|blocked\b/i.test(line));
  if (blocked.length) return { status: 'BLOCKED', evidence: blocked.slice(0, 5).join(' | ') };
  if (signals.length) return { status: 'FAIL', evidence: signals.slice(0, 5).join(' | ') };
  // A test runner that exits 0 after doing no work (e.g. Jest/Vitest "No tests
  // found, exiting with code 0") provides no authoritative test evidence. The
  // closeout gate explicitly rejects passWithNoTests-style weakening, so a
  // no-test run must not fall through to PASS. Targeted at the no-work
  // summaries; ordinary "no tests were skipped" is not matched.
  const combined = `${stdout}\n${stderr}`;
  if (/\bno\s+tests?\s+(?:found|executed|ran|were run|to run)\b/i.test(combined) || /\bno\s+test\s+files?\s+found\b/i.test(combined)) {
    return { status: 'FAIL', evidence: 'Test runner reported no tests found/executed; closeout requires authoritative test evidence.' };
  }
  // Numeric no-work summaries from common runners: Node's TAP `# tests 0` /
  // `# pass 0` and Vitest's `Tests 0 passed (0)` / `Test Files 0`. These exit 0
  // while doing no work; the closeout gate requires authoritative test evidence.
  // `Test Files 0` only counts as a zero total when it is not a bucket count in
  // a richer summary: `Test Files 0 failed | 2 passed (2)` reports zero failed
  // files alongside real passes, which IS authoritative test evidence.
  if (/^[ \t]*#\s*tests?\s+0\b/im.test(combined)
    || /\btests?\s+0\s+passed\b/i.test(combined)
    || new RegExp(`\\btest\\s+files?\\s+0(?!\\s+${STATUS_TERM}\\b)`, 'i').test(combined)
    // Mocha-style no-work: "0 passing" with exit 0 (not "N passing" with failures).
    || /(?:^|\n)\s*0\s+passing\b/i.test(combined)) {
    return { status: 'FAIL', evidence: 'Test runner reported zero tests as the total; closeout requires authoritative test evidence.' };
  }
  return { status: 'PASS', evidence: 'Exit 0 with no warning, error, block, problem, skip, or failure signal.' };
};

/**
 * Scan one file's text for three independent categories of gate-weakening.
 * Suppression markers (the MARKERS vocabulary: DeepSource, ESLint, Biome,
 * TypeScript, Ruff, and peer-tool directives) are checked in every file.
 * Config-level silencing (CONFIG_SILENCING
 * — continue-on-error, a raised --max-warnings budget, a rule turned "off",
 * ignoreBuildErrors, || true, and similar) is only checked in files
 * classified as config/workflow/ignore-file-shaped, plus every non-comment
 * line of a dedicated *ignore file is itself flagged. Runner-native test
 * focus/skip (describe.only, it.skip, fit/xdescribe, and their
 * optional-chaining, computed-property, and modifier-chain variants) is only
 * checked in test/spec-shaped files. The marker pass is quote-aware only: a
 * bare quoted-string line is skipped outright (so this scanner's own MARKERS
 * vocabulary and quoted test fixtures don't self-flag) and a marker wrapped
 * in matching quotes or backticks is treated as inert prose — a marker
 * inside a line or block comment, or inside a regex literal, is still
 * reported, which is intentional: a suppression directive is a directive
 * regardless of what comment sits next to it. The test-weakening pass is,
 * unlike the marker pass, comment- and regex-literal-aware: its matches are
 * checked against a per-line inertness map (see the nested
 * scanLineInertness) that tracks strings, line/block comments, and regex
 * literals, so a lookalike call inside a comment or string is ignored while
 * a real active call sharing the line is still caught. At most one finding
 * per line per pass is recorded.
 * @param {string} file - Repo-relative path; drives classification (config-like / ignore-file / test-like) and is echoed into each finding.
 * @param {string} text - Full decoded file content to scan.
 * @returns {Array<{file: string, line: number, category: 'marker'|'config-silencing'|'test-weakening', match: string}>}
 */
const scanSuppressionText = (file, text) => {
  const findings = [];
  const normalized = String(file).replaceAll('\\', '/').toLowerCase();
  const base = normalized.split('/').at(-1);
  const ignoreFile = /^\.(?:eslint|biome|prettier|stylelint|ruff)ignore$/.test(base);
  const configLike = ignoreFile || /\.(?:jsonc?|ya?ml|toml|ini|conf)$/.test(base)
    || /(?:^|\.)config\.[a-z0-9]+$/.test(base)
    || /^\.(?:eslintrc|biomerc)(?:\.[a-z0-9]+)?$/.test(base)
    || ['package.json', 'makefile', '.eslintrc', '.biomerc'].includes(base)
    || normalized.startsWith('.github/workflows/');
  // Treat touched test files as candidates for test-only weakening markers
  // (.skip/.only/.todo) so a PR cannot focus or skip tests in an ordinary
  // touched test file and still pass the closeout scan if the reduced test
  // command exits 0.
  const testLike = /(?:^|[._-])(?:test|spec)s?\.[a-z0-9]+$/i.test(base)
    || /\.(?:test|spec)\.[a-z0-9]+$/i.test(base)
    // Cypress E2E spec naming (*.cy.ts / *.cy.js) is honored by the runner for
    // it.only/describe.skip, so focused/skipped E2E coverage in a touched
    // cypress/e2e/login.cy.ts file must be scanned even outside a test/ dir.
    || /\.cy\.[a-z0-9]+$/i.test(base)
    // Also classify files inside standard test directories (__tests__/ — a
    // standard Jest layout — plus test/, tests/, spec/, and specs/) as test
    // files even when the filename has no test/spec token, so weakening
    // markers (describe.only/it.skip/test.todo) in tests/foo.js are scanned.
    // The segment must match in full so lookalikes such as contest/, latest/,
    // test-utils/, or __tests_data__/ do not false-positive.
    || /(?:^|\/)(?:tests?|specs?|__tests__)\//i.test(normalized);
  const escape = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const markerPattern = new RegExp(MARKERS
    .map((marker) => `(?<![\\w$])${marker.split(/\s+/).map(escape).join('\\s+')}(?![\\w$])`)
    .join('|'), 'i');
  // A line whose non-whitespace content is a single quoted string literal
  // (with an optional trailing comma/semicolon) is data, not an active
  // directive: the scanner's own MARKERS vocabulary (quoted marker names),
  // quoted test fixtures, and sole-string data would otherwise self-flag and
  // block implementation changes to this tool. Real suppression directives
  // and real focused/skipped calls are never sole quoted strings, so skipping
  // these lines preserves directive detection while avoiding self-referential
  // false positives. Allow the other quote style inside the outer quotes so
  // fixtures like 'describe.only("focused suite")', match.
  // (Do not spell bare marker tokens in these comments: this file is itself
  // scanned when touched.)
  const isStringLiteralData = (line) => (
    /^\s*'([^'\\]|\\.)*'[,;]?\s*$/.test(line)
    || /^\s*"([^"\\]|\\.)*"[,;]?\s*$/.test(line)
    || /^\s*`([^`\\]|\\.)*`[,;]?\s*$/.test(line)
  );
  const lines = text.split(/\r?\n/);
  // Compile the global scan pattern once per file, not once per line;
  // matchAll clones the regex internally, so sharing it across lines is safe.
  const globalPattern = new RegExp(markerPattern.source, 'gi');
  lines.forEach((line, index) => {
    if (isStringLiteralData(line)) return;
    // Iterate every marker occurrence so each can be assessed independently.
    for (const match of line.matchAll(globalPattern)) {
      // A marker wrapped in matching quote/backtick characters is data, not a
      // directive (markdown inline-code, quoted tokens, template literals).
      // Real directives are never wrapped that way, so skipping wrapped
      // matches preserves directive detection while exempting documented
      // vocabulary from self-flagging.
      const before = line[match.index - 1];
      const after = line[match.index + match[0].length];
      if (before && after && before === after && '\'`""'.includes(before)) continue;
      findings.push({ file, line: index + 1, category: 'marker', match: match[0] });
      break;
    }
  });
  if (ignoreFile) {
    lines.forEach((line, index) => {
      const active = line.trim();
      if (active && !active.startsWith('#') && !active.startsWith('!')) {
        findings.push({ file, line: index + 1, category: 'config-silencing', match: active });
      }
    });
  }
  if (configLike) {
    for (const pattern of CONFIG_SILENCING) {
      const match = text.match(pattern);
      if (!match) continue;
      const line = text.slice(0, match.index).split(/\r?\n/).length;
      findings.push({ file, line, category: 'config-silencing', match: match[0].trim() });
    }
  }
  if (testLike) {
    // Jasmine/Jest aliases fit/fdescribe (focus) and xit/xdescribe (skip) are
    // runner-native weakening equivalents of .only/.skip. The lookbehind
    // requires a standalone call so member calls such as curve.fit(data) do
    // not false-positive. Skip sole string-literal fixture lines and matches
    // that sit inside string/template literals so this scanner's own
    // regression tests (e.g. scanSuppressionText(..., 'it.skip("x")')) do
    // not self-flag as active test-weakening.
    // Allow runner modifier chains (Jest/Vitest): test.concurrent.only / it.only.each, etc.
    // Dot-member chains (describe.only / it.skip / test.todo) and the
    // computed-property equivalents (it['only'] / describe["skip"] /
    // test[`only`]) are runner-native focus/skip forms; the bracket form still
    // focuses/skips at runtime, so a reduced test command can exit 0 and bypass
    // the closeout weakening scan. Allow runner modifier chains
    // (test.concurrent.only / it.only.each) on the dot form.
    // Dot-member chains (describe.only / it.skip / test.todo) — including the
    // optional-chaining form it?.only which still focuses at runtime when `it`
    // is defined — plus the computed-property equivalents (it['only'] /
    // describe["skip"] / test[`only`]) are runner-native focus/skip forms. Allow
    // runner modifier chains (test.concurrent.only / it.only.each) on the dot
    // form. `\??\.` accepts both `.` and `?.` so it?.only / describe?.skip match.
    const testWeakening = /\b(?:describe|it|test|context)(?:\??\.[A-Za-z_]\w*)*\??\.(?:skip|only|todo)\b|\b(?:describe|it|test|context)\s*\[\s*['"`](?:skip|only|todo)['"`]\s*\]|(?<![\w$.])(?:fit|fdescribe|xit|xdescribe)\s*\(/i;
    /**
     * Scan a whole source line and mark every character position that is
     * inert (inside a string, a line/block comment, or a regex literal), so
     * a test-weakening match the runner could never actually execute is not
     * flagged. Block-comment state carries across lines: a `/*` opened on a
     * previous line makes this entire line inert until the comment closes,
     * so a focused test merely sketched inside a multi-line block comment is
     * not flagged. Regex character classes are tracked too, so `/[/']/`
     * does not terminate early and let the `'` inside it open a bogus string
     * around a later, real `.only` call.
     * @param {string} line - One line of source text.
     * @param {boolean} carryBlockComment - Whether a block comment opened on a prior line is still open entering this line.
     * @returns {{inert: boolean[], blockComment: boolean}} Per-character inertness map, and whether a block comment is still open at line end (to carry into the next call).
     */
    const scanLineInertness = (line, carryBlockComment) => {
      const inert = new Array(line.length).fill(false);
      let blockComment = Boolean(carryBlockComment);
      let quote = null;
      let escaped = false;
      let lineComment = false;
      let i = 0;
      const prevSignificant = (from) => {
        for (let j = from - 1; j >= 0; j -= 1) {
          if (!/\s/.test(line[j])) return line[j];
        }
        return '';
      };
      while (i < line.length) {
        const ch = line[i];
        if (blockComment) {
          const close = line.indexOf('*/', i);
          if (close === -1) {
            inert.fill(true, i);
            return { inert, blockComment: true };
          }
          inert.fill(true, i, close + 2);
          i = close + 2;
          blockComment = false;
          continue;
        }
        if (lineComment) {
          inert[i] = true;
          i += 1;
          continue;
        }
        if (quote) {
          inert[i] = true;
          if (escaped) {
            escaped = false;
          } else if (ch === '\\') {
            escaped = true;
          } else if (ch === quote) {
            quote = null;
          }
          i += 1;
          continue;
        }
        if (ch === '/' && line[i + 1] === '/') {
          lineComment = true;
          inert[i] = true;
          inert[i + 1] = true;
          i += 2;
          continue;
        }
        if (ch === '/' && line[i + 1] === '*') {
          blockComment = true;
          inert[i] = true;
          inert[i + 1] = true;
          i += 2;
          continue;
        }
        // Regex literals (e.g. /don't/) must not open a quote on the
        // apostrophe. Heuristic: `/` after punctuation or a keyword that
        // typically precedes a regex, not after an identifier (division).
        if (ch === '/' && line[i + 1] && line[i + 1] !== '/' && line[i + 1] !== '*') {
          const prev = prevSignificant(i);
          const prevWord = line.slice(0, i).match(/([A-Za-z_$][\w$]*)\s*$/)?.[1];
          const regexContextKeyword = prevWord
            ? /^(?:return|typeof|instanceof|in|of|new|do|else|yield|await|case|void|delete|throw)$/.test(prevWord)
            : false;
          if (!prev || /[=(:,;[!&|?{~+\-*%^<>]/.test(prev) || regexContextKeyword) {
            inert[i] = true;
            let k = i + 1;
            let reEsc = false;
            let inClass = false;
            while (k < line.length) {
              const rc = line[k];
              inert[k] = true;
              if (reEsc) { reEsc = false; k += 1; continue; }
              if (rc === '\\') { reEsc = true; k += 1; continue; }
              // A `[...]` class can contain `/` and quotes without ending the
              // regex or opening a string; only an unescaped `/` outside a
              // class closes the literal.
              if (rc === '[' && !inClass) { inClass = true; k += 1; continue; }
              if (rc === ']' && inClass) { inClass = false; k += 1; continue; }
              if (rc === '/' && !inClass) {
                k += 1;
                while (k < line.length && /[a-z]/i.test(line[k])) { inert[k] = true; k += 1; }
                break;
              }
              if (rc === '\n') break;
              k += 1;
            }
            i = k;
            continue;
          }
        }
        if (ch === "'" || ch === '"' || ch === '`') {
          quote = ch;
          inert[i] = true;
          i += 1;
          continue;
        }
        i += 1;
      }
      return { inert, blockComment };
    };
    const globalWeakening = new RegExp(testWeakening.source, 'gi');
    let blockComment = false;
    lines.forEach((line, index) => {
      const { inert, blockComment: outgoing } = scanLineInertness(line, blockComment);
      blockComment = outgoing;
      // Inspect every occurrence: a quoted fixture before a real call on the
      // same line must not hide the later active .skip/.only.
      for (const match of line.matchAll(globalWeakening)) {
        if (inert[match.index ?? 0]) continue;
        findings.push({ file, line: index + 1, category: 'test-weakening', match: match[0] });
        break;
      }
    });
  }
  return findings;
};

module.exports = {
  CONFIG_SILENCING,
  MANDATORY_CHECKS,
  MARKERS,
  REQUIRED_PROOFS,
  buildCheckPlan,
  classifyOutput,
  findStatusSignals,
  scanSuppressionText,
  shellQuote,
};
