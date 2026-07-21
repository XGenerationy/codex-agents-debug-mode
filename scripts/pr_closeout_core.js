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
];

const define = (id, label, options = {}) => ({ id, label, ...options });

const MANDATORY_CHECKS = [
  define('git-diff-check', 'git diff --check', { fixed: true, command: 'git diff --check', qualificationSafe: true, baselineSafe: true }),
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

const shellQuote = (value) => `'${String(value).replaceAll("'", "'\\''")}'`;

const expandCommand = (command, touchedFiles) => command.replaceAll(
  '{touchedFiles}',
  touchedFiles.map(shellQuote).join(' '),
);

const buildCheckPlan = ({ config = {}, packageScripts = {}, makeTargets = [], touchedFiles = [] } = {}) => {
  const commands = config.commands || {};
  const qualificationSafe = new Set(config.qualificationSafe || []);
  const resourceGroups = config.resourceGroups || {};
  const targets = new Set(makeTargets);
  const errors = [];
  if (Object.hasOwn(config, 'gateIntegrityReview')) {
    errors.push('gateIntegrityReview self-attestation is forbidden; use the required live GitHub PR review attestation.');
  }
  const checks = MANDATORY_CHECKS.map((definition) => {
    const configured = commands[definition.id];
    if (definition.fixed) {
      if (configured !== undefined && configured !== definition.command) {
        errors.push(`Configuration cannot override fixed check ${definition.id}.`);
      }
      return { ...definition, resolution: 'fixed' };
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
      return { ...definition, command: expandCommand(configured.trim(), touchedFiles), resolution: 'configured' };
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

const cleanZeroSummaries = (text) => text
  .replace(/\b0\s+(?:warnings?|errors?|problems?|fail(?:ed|ures?|ing)?|skips?|skipped|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)\b/gi, '')
  .replace(/\b(?:warnings?|errors?|problems?|fail(?:ed|ures?|ing)?|skips?|skipped|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)\s*(?::|=|\s)\s*0\b/gi, '')
  .replace(/\bno\s+(?:warnings?|errors?|problems?|failures?|failing|skips?|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)\b/gi, '');

const STATUS_TERM = '(?:warn(?:ing)?s?|errors?|problems?|fail(?:ed|ures?|ing)?|skips?|skipped|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)';
const COUNTED_SIGNAL = new RegExp(`(?:\\b[1-9]\\d*\\s+${STATUS_TERM}\\b|\\b${STATUS_TERM}\\s*(?::|=|\\s)\\s*[1-9]\\d*\\b)`, 'i');
const BRACKETED_SIGNAL = new RegExp(`^\\s*(?:[-*]\\s*)?\\[${STATUS_TERM}\\]`, 'i');
const LABELLED_SIGNAL = new RegExp(`^\\s*(?:[-*]\\s*)?${STATUS_TERM}\\s*[:=]`, 'i');
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

const findStatusSignals = (text) => cleanZeroSummaries(String(text ?? '')
  .replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, '')
  .replaceAll('\r', '\n'))
  .split(/\n/)
  .filter((line) => line.trim())
  .filter(statusSignal);

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
    || new RegExp(`\\btest\\s+files?\\s+0(?!\\s+${STATUS_TERM}\\b)`, 'i').test(combined)) {
    return { status: 'FAIL', evidence: 'Test runner reported zero tests as the total; closeout requires authoritative test evidence.' };
  }
  return { status: 'PASS', evidence: 'Exit 0 with no warning, error, block, problem, skip, or failure signal.' };
};

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
  // directive: the scanner's own MARKERS vocabulary (`'skipcq',`), quoted
  // test fixtures (`'// noqa',`, `'describe.only("x")',`), would otherwise
  // self-flag and block implementation changes to this tool. Real
  // suppression directives (`// skipcq`, `# noqa`) and real focused/skipped
  // calls (`it.skip("x")`) are never sole quoted strings, so skipping these
  // lines preserves directive detection while avoiding self-referential
  // false positives. Allow the other quote style inside the outer quotes so
  // fixtures like 'describe.only("focused suite")', match.
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
      // directive: a markdown inline-code span (`skipcq`) in documentation, a
      // quoted token, or a template literal. Real directives (// skipcq,
      // # noqa, <!-- biome-ignore -->) are never wrapped this way, so skipping
      // wrapped matches preserves directive detection while exempting the
      // scanner's own documented vocabulary from self-flagging.
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
    const testWeakening = /\b(?:describe|it|test|context)\.(?:skip|only|todo)\b|(?<![\w$.])(?:fit|fdescribe|xit|xdescribe)\s*\(/i;
    const isInsideQuotes = (line, at) => {
      let quote = null;
      let escaped = false;
      for (let i = 0; i < at; i += 1) {
        const ch = line[i];
        if (escaped) {
          escaped = false;
          continue;
        }
        if (quote) {
          if (ch === '\\') {
            escaped = true;
            continue;
          }
          if (ch === quote) quote = null;
          continue;
        }
        // An unquoted `//` starts a line comment. Real string literals cannot
        // span past it, so any earlier raw apostrophe (e.g. "don't" in a
        // comment) was never a quote-open — stop and treat the match as code.
        if (ch === '/' && line[i + 1] === '/') return false;
        if (ch === "'" || ch === '"' || ch === '`') quote = ch;
      }
      return quote !== null;
    };
    lines.forEach((line, index) => {
      if (isStringLiteralData(line)) return;
      const match = line.match(testWeakening);
      if (match && !isInsideQuotes(line, match.index ?? 0)) {
        findings.push({ file, line: index + 1, category: 'test-weakening', match: match[0] });
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
