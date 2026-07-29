const path = require('node:path');

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
  // Disabled rules under a `rules`/`rule` key are detected by the
  // brace/indentation-aware `findRulesScopedSilencings` helper (applied in
  // scanSuppressionText) instead of an unbounded `rules? [\s\S]*?` regex,
  // which crossed closing braces and false-positive on an unrelated sibling
  // zero such as `{"rules":{...},"server":{"port":0}}` (Codex M6UFnGF).
  // Standalone rule-id → "off"/"0" assignments (override blocks / flat
  // config) are still matched by the scoped/`no-*` patterns below without a
  // nearby `rules` key — rule ids are kebab/scoped forms, not bare words.
  // Scoped (@org/rule) and plugin/rule ids — one slash is enough for ESLint.
  // Do not put \b after a closing quote of "off" (quote is non-word, so \b
  // fails between " and ,/}). Use an explicit "off" alternative instead.
  /["']@[\w.-]+\/[\w./-]+["']\s*:\s*(?:["']off["']|\b0\b|\[\s*0\b)/i,
  /["'][\w.-]+\/[\w./-]+["']\s*:\s*(?:["']off["']|\b0\b|\[\s*0\b)/i,
  /["'](?:no|prefer|require|max|min|eqeqeq|curly|strict|camelcase|semi|quotes|indent)-[\w-]+["']\s*:\s*(?:["']off["']|\b0\b|\[\s*0\b)/i,
  // ESLint array-form severity zero ('no-console': [0, { allow: ['warn'] }])
  // and any other disabled/zero rule inside a `rules`/`rule` object are
  // detected by findRulesScopedSilencings (Codex #4781366510 array form).
  /(?:lint|typecheck|audit|test|coverage)[^\n]*(?:enabled["']?\s*[:=]\s*false|disabled["']?\s*[:=]\s*true)/i,
  // GitHub Actions step disable: `if: false` / `if: ${{ false }}` silences a
  // validation step without touching continue-on-error (Codex open finding).
  /\bif\s*:\s*(?:false\b|["']false["']|\$\{\{\s*false\s*\}\})/i,

  /["']?linter["']?\s*:\s*\{[\s\S]*?["']?enabled["']?\s*:\s*false/i,
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
  // Ignore/exclude keys whose value suppresses source/test/spec paths -- a
  // src/test/spec-targeting glob (e.g. "src/**", "**/*.test.ts") or a bare
  // source-extension glob (**/*.ts, **/*.{js,ts}) -- are detected by the
  // bracket-aware `findIgnoreScopedSilencings` helper (applied in
  // scanSuppressionText), not a regex here. The previous patterns bridged the
  // key to its value with a bounded `(?:\[[\s\S]{0,50000}?)?` window, which an
  // adversary evades by padding >50000 chars of benign entries before the real
  // `"src/**"` exclusion (Codex UnKZ_). The helper walks the complete ignore
  // array with a string-aware bracket match, so array length no longer bounds
  // detection; build artifacts (dist, node_modules, **/*.d.ts) still stay
  // unflagged and the src/test/spec token stays \b-anchored so substrings like
  // windows-latest do not false-positive. See its JSDoc for the full rules.
  /\|\|\s*true\b/i,
  // Shell zero-exit neutralizers that hide command failure from classifyOutput
  // the same way `|| true` does. `|| :` matches even with redirects/pipes
  // (`|| :>/dev/null`). Trailing `; true` / `; :` / `; exit 0` are covered
  // without anchoring on bare `&` (which would false-positive on `&&`).
  // `|| echo …` also forces zero exit and must be flagged.
  /\|\|\s*:/i,
  /\|\|\s*exit\s+0\b/i,
  /\|\|\s*echo\b/i,
  /(?:^|[;\n])\s*true\b/i,
  /(?:^|[;\n])\s*:/i,
  /(?:^|[;\n])\s*exit\s+0\b/i,
  // Direct pipeline tails to always-success commands. Without `pipefail`,
  // `cmd | true` / `cmd | :` / `cmd | exit 0` report the right-hand exit
  // status and mask a failed left-hand command (CodeRabbit #4780344655).
  // Single-pipe only: lookaround excludes `||` which is handled above.
  /(?<!\|)\|(?!\|)\s*(?:true\b|:|exit\s+0\b)/i,
  // `set +e` / `set +o errexit` / `set +o pipefail` in a scanned validation
  // helper disable failure propagation the same way (Codex UDDQR).
  /\bset\s+\+[a-z]*e[a-z]*\b/i,
  /\bset\s+\+o\s+(?:errexit|pipefail)\b/i,
];

/**
 * Shell / runner constructs that force a zero exit (or hide failures) so
 * classifyOutput would report PASS even when the real check failed. Applied
 * to configured closeout commands and proof commands — including config
 * stored outside the checkout, which the touched-file suppression scanner
 * never sees.
 *
 * OR-lists are handled conservatively (Codex discussion_r3652957333): bash
 * exempts the left side of `||` from errexit and the OR-list exits with the
 * RIGHT operand's status, so ANY `||` fallback is flagged unless the right
 * operand provably re-fails — `exit N` with N != 0, `false`, or `return N`
 * with N != 0. `exit $?` / `return $?` are admitted too: they propagate the
 * left operand's own nonzero status (CodeRabbit UC4ND). Those allowed forms
 * keep the failure visible to the executor (nonzero exit status), so they
 * are not neutralizers; everything else
 * (`|| true`, `|| :`, `|| echo ok`, `|| printf ok`, arbitrary commands)
 * masks it. The specific patterns run before the catch-all so the reported
 * fragment names the exact neutralizer.
 */
const COMMAND_FAILURE_NEUTRALIZERS = [
  // OR-list success: `cmd || true`, `cmd || exit 0`, `cmd || echo ok`
  /\|\|\s*true\b/i,
  // POSIX no-op after || — including redirects/pipes: `|| :`, `|| :>/dev/null`,
  // `|| :| cat`. `:` is a complete always-success command; trailing I/O still
  // yields exit 0 and must not evade the detector.
  /\|\|\s*:/i,
  /\|\|\s*exit\s+0\b/i,
  // `|| echo …` always yields exit 0 after a failed left-hand command.
  /\|\|\s*echo\b/i,
  // Trailing/chained success no-ops: `cmd; true`, `cmd; :`, or a lone `true`/
  // `:` as the configured command. Anchored on start / `;` / newline only —
  // not bare `&` — so `cmd && exit 0` (short-circuits on failure) is not a
  // false positive.
  /(?:^|[;\n])\s*true\b/i,
  /(?:^|[;\n])\s*:/i,
  /(?:^|[;\n])\s*exit\s+0\b/i,
  // Direct pipeline tails to always-success commands. Without `pipefail`,
  // `cmd | true` / `cmd | :` / `cmd | exit 0` report the right-hand exit
  // status and mask a failed left-hand command (CodeRabbit #4780344655).
  // Single-pipe only: lookaround excludes `||` which is handled above.
  /(?<!\|)\|(?!\|)\s*(?:true\b|:|exit\s+0\b)/i,
  // Shell option flips that disable failure propagation (Codex UDDQR):
  // `set +e` / `set +o errexit` override the executor's prepended `set -e`,
  // so a failing command no longer aborts the script and a later always-
  // success command can exit 0; `set +o pipefail` lets a successful pipeline
  // tail hide a failed leg. The literal `+` is required, so the hardening
  // forms `set -e` / `set -o pipefail` are not flagged.
  /\bset\s+\+[a-z]*e[a-z]*\b/i,
  /\bset\s+\+o\s+(?:errexit|pipefail)\b/i,
  // Shell negation (Codex UnYb3; CodeRabbit UptWH): a `!` reserved word before
  // a command, pipeline, or compound command inverts its exit status AND —
  // per Bash's documented `-e` behavior — exempts the negated command from
  // errexit, so `! (npm test) >/dev/null 2>&1` exits 0 precisely when the
  // wrapped command fails, the same failure-hiding effect as the `|| true`
  // family above. Anchored like the bare `true`/`:` neutralizers above (start
  // of string, or right after `;`/`&`/`|`/newline/`(`/`{`) OR after a shell
  // keyword that itself introduces a command (`if`/`elif`/`while`/`until`/
  // `then`/`do`/`else`): `if ! npm test; then echo skipped; fi` hides a
  // failure exactly like a bare `! npm test`, but the punctuation anchors
  // alone never matched it. The keyword alternative is deliberately narrow
  // (word-bounded, not "any preceding whitespace") so `find . ! -name x` and
  // `[ ! -f x ]` — where `!` is a command argument, not a shell reserved word —
  // stay clean; whitespace is still required before the next token so `!=`
  // (inequality) and a bare word containing `!` are not false positives.
  /(?:^|[;&|\n(){]|\b(?:if|elif|while|until|then|do|else)\b)\s*!\s+\S/,
  // Conditional-body failure swallow (Codex UrfC9): placing the validation
  // command directly in an if/while/until CONDITION — no `!` involved — hides
  // its failure the same way, because Bash's documented `-e` behavior exempts
  // any command tested by if/while/until from errexit, and a no-op-only
  // branch (`:` / `true`) with no elif/else to re-raise leaves the whole
  // compound statement's own exit status at 0 regardless of the condition's
  // result: `if npm test >/dev/null 2>&1; then :; fi` never surfaces a
  // failing npm test. Matched conservatively like the OR-list catch-all
  // below: an inert `if`/`while`/`until` guard ahead of a separately
  // propagating real check would also match, which is intentional — closeout
  // BLOCKs rather than risks admitting a genuine failure-hiding conditional.
  /\b(?:if|elif|while|until)\b[\s\S]{0,4000}?\b(?:then|do)\b\s*;?\s*(?::|true\b|echo\b[^\n;]*|printf\b[^\n;]*|exit\s+0\b)\s*;?\s*(?:fi\b|done\b)/,
  // Catch-all OR-list rule (Codex discussion_r3652957333): flag every `||`
  // whose right operand does not provably re-fail — see the JSDoc above for
  // the rationale. The negative lookahead admits only `false`,
  // `exit <nonzero>`, `return <nonzero>`, and the status-propagating
  // `exit $?` / `return $?` (CodeRabbit UC4ND); `|| true`, `|| :`,
  // `|| exit 0`, and `|| echo …` still match their specific patterns above,
  // which run first so the reported fragment names the exact neutralizer.
  /\|\|(?!\s*(?:false\b|exit\s*(?:[1-9]\d*\b|\$\?)|return\s*(?:[1-9]\d*\b|\$\?)))/i,
  /\bpassWithNoTests\b/i,
  /\ballowNoTests\b/i,
  /\b--passWithNoTests\b/i,
  // No-op evaluation script (Codex Uz6A0): a command whose whole body is an
  // empty/whitespace-only node -e "" / node --eval '' exits 0 with no output,
  // providing no authoritative test-execution evidence -- the same do-nothing
  // effect passWithNoTests has, so a test row can become clean without running
  // anything. Matched only when the WHOLE command is that no-op (optionally
  // prefixed by ENV=val assignments), so 'npm test && node -e ""' -- whose
  // failure still short-circuits and propagates -- is not a false positive,
  // and a non-empty body (node -e "console.log(1)") stays clean.
  /^\s*(?:[A-Za-z_]\w*=\S+\s+)*node\s+(?:-e|--eval)\s+(['"])\s*\1\s*$/,
];

/**
 * @param {string} command
 * @returns {string|null} matched neutralizer fragment, or null if clean
 */
const findCommandFailureNeutralizer = (command) => {
  const text = String(command ?? '');
  if (!text.trim()) return null;
  for (const pattern of COMMAND_FAILURE_NEUTRALIZERS) {
    const match = text.match(pattern);
    if (match) return match[0].trim();
  }
  return null;
};

/**
 * Detect a Make recipe body that neutralizes failure so `make <target>` exits 0
 * even when a command inside it fails (Codex Ummss). Unlike a package script,
 * a resolved make target is trusted by NAME and its recipe is never covered by
 * the touched-file suppression scan when the Makefile is unchanged. Two ways a
 * recipe hides failure are checked per line: Make's own leading `-` ignore-
 * error prefix (a `-` among the leading `@`/`+`/`-` modifiers makes that
 * command's nonzero exit non-fatal), and the shared shell neutralizers
 * (`|| true`, `set +e`, pipeline-to-`:` …) via findCommandFailureNeutralizer.
 * A leading `-` in a recipe is always Make's prefix, not a shell token: a real
 * command never begins with `-`.
 * @param {string} recipe - Recipe body (one or more command lines).
 * @returns {string|null} matched neutralizer fragment, or null if clean.
 */
const findMakeRecipeNeutralizer = (recipe) => {
  const text = String(recipe ?? '');
  if (!text.trim()) return null;
  for (const rawLine of text.split(/\r?\n/)) {
    const ignorePrefix = rawLine.match(/^\s*[@+]*-/);
    if (ignorePrefix) return ignorePrefix[0].trim();
    const shellNeutralizer = findCommandFailureNeutralizer(rawLine);
    if (shellNeutralizer) return shellNeutralizer;
  }
  return null;
};

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
  // Generic `test:smoke` is intentionally excluded: many repos use that name
  // for unit/API smoke that never launches a browser. Map browser smoke via
  // playwright-/e2e-named scripts or an explicit check override.
  define('playwright-smoke', 'Playwright smoke', { packageCandidates: ['playwright-smoke', 'test:e2e:smoke', 'test:playwright:smoke', 'playwright:smoke'], baselineSafe: false }),
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
    // Shell quoting prevents injection, but it does not stop an operand such
    // as `--write` from being interpreted as a program option. Git emits
    // repo-relative paths, so only a root-level dash needs `./` disambiguation.
    touchedFiles.map((file) => shellQuote(String(file).startsWith('-') ? `./${file}` : file)).join(' '),
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
 * error, not a silent ignore) — and when that hardcoded command is a bare
 * `make <target>` invocation (make-smoke/make-sbom/make-audit/make-pr-check),
 * its recipe body is validated against `makeRecipes` the exact same way a
 * makeCandidates-resolved target is, below, rather than being trusted
 * unexamined; otherwise an explicit `config.commands[id]`
 * wins (a placeholder like `<...>` or `REPLACE_...` is rejected as BLOCKED
 * rather than run), then the first matching `package.json` script, then the
 * first matching Makefile target — whose recipe body, when supplied in
 * `makeRecipes`, is rejected as BLOCKED if it neutralizes failure (Make's
 * leading `-` ignore-error prefix or a shared shell neutralizer), the same way
 * an auto-discovered package script is; a check that resolves nothing is
 * BLOCKED as "unresolved". A second pass then attaches `qualificationSafe`,
 * `resourceGroup`, and `proof` from config, and independently BLOCKs a check
 * that requires a postcondition proof (REQUIRED_PROOFS) without a valid one
 * configured, `redis-integration` without a `services.redis` probe, and
 * `grafana-live-render` without a `services.grafana.url` probe — a check can
 * end up BLOCKED for more than one reason, in which case the first BLOCKED
 * evidence is extended rather than replaced. A config that sets
 * `gateIntegrityReview` (self-attestation) always produces a top-level
 * error, since only a live GitHub PR review attestation is accepted.
 * @param {{config?: object, packageScripts?: Record<string, string>, makeTargets?: string[], makeRecipes?: Record<string, string>, touchedFiles?: string[], mergeBaseSha?: string}} options
 * @returns {{checks: object[], errors: string[]}}
 */
const buildCheckPlan = ({ config = {}, packageScripts = {}, makeTargets = [], makeRecipes = {}, touchedFiles = [], mergeBaseSha } = {}) => {
  const commands = config.commands || {};
  const qualificationSafe = new Set(config.qualificationSafe || []);
  const resourceGroups = config.resourceGroups || {};
  const targets = new Set(makeTargets);
  const errors = [];
  if (Object.hasOwn(config, 'gateIntegrityReview')) {
    errors.push('gateIntegrityReview self-attestation is forbidden; use the required live GitHub PR review attestation.');
  }
  if (typeof config.baselineSetupCommand === 'string' && config.baselineSetupCommand.trim()) {
    const baselineNeutralizer = findCommandFailureNeutralizer(config.baselineSetupCommand);
    if (baselineNeutralizer) {
      errors.push(
        `baselineSetupCommand neutralizes failures (${baselineNeutralizer}); closeout cannot admit a failure-hiding setup command.`,
      );
    }
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
      // Fixed checks that invoke `make <target>` (make-smoke, make-sbom,
      // make-audit, make-pr-check) are trusted by NAME exactly like an
      // auto-discovered makeCandidates target is below: an unchanged base
      // Makefile's recipe is never covered by the touched-file suppression
      // scan, so without this validation the fixed branch would return
      // PASS-eligible for, e.g., a `pr-check` recipe of
      // `npm test >/dev/null 2>&1 || true` without the recipe ever being
      // inspected (Codex: "Inspect recipes behind fixed Make checks"). Apply
      // the identical makeRecipes validation the makeCandidates path performs
      // below: fail closed when the recipe was never captured, and BLOCK
      // when it neutralizes failure.
      const fixedMakeTarget = /^make\s+(\S+)/.exec(definition.command)?.[1];
      if (fixedMakeTarget) {
        if (!Object.hasOwn(makeRecipes, fixedMakeTarget)) {
          return {
            ...definition,
            status: 'BLOCKED',
            resolution: 'fixed',
            evidence: `No recipe text was captured for make target "${fixedMakeTarget}" (${definition.label}); closeout cannot trust an uninspected recipe.`,
          };
        }
        const recipeNeutralizer = findMakeRecipeNeutralizer(makeRecipes[fixedMakeTarget]);
        if (recipeNeutralizer) {
          return {
            ...definition,
            status: 'BLOCKED',
            resolution: 'fixed',
            evidence: `Make recipe for ${definition.label} neutralizes failures (${recipeNeutralizer}); closeout cannot admit a failure-hiding recipe.`,
          };
        }
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
      const configuredCommand = expand(configured.trim());
      const neutralizer = findCommandFailureNeutralizer(configuredCommand);
      if (neutralizer) {
        return {
          ...definition,
          command: configuredCommand,
          status: 'BLOCKED',
          resolution: 'configured',
          evidence: `Configured command for ${definition.label} neutralizes failures (${neutralizer}); closeout cannot admit a failure-hiding command.`,
        };
      }
      return { ...definition, command: configuredCommand, resolution: 'configured' };
    }
    const packageScript = definition.packageCandidates?.find((candidate) => packageScripts[candidate]);
    if (packageScript) {
      // Auto-discovered scripts are not covered by the touched-file scan when
      // package.json is untouched. Reject failure-hiding bodies (e.g. vitest
      // || true) the same way as explicitly configured commands (Codex
      // #4781560042).
      const scriptBody = packageScripts[packageScript];
      const packageNeutralizer = findCommandFailureNeutralizer(scriptBody);
      if (packageNeutralizer) {
        return {
          ...definition,
          command: `pnpm run ${packageScript}`,
          status: 'BLOCKED',
          resolution: 'package-script',
          evidence: `Package script "${packageScript}" for ${definition.label} neutralizes failures (${packageNeutralizer}); closeout cannot admit a failure-hiding package script.`,
        };
      }
      return { ...definition, command: `pnpm run ${packageScript}`, resolution: 'package-script' };
    }
    const makeTarget = definition.makeCandidates?.find((candidate) => targets.has(candidate));
    if (makeTarget) {
      // A resolved make target is trusted by NAME; its recipe body is not
      // covered by the touched-file scan when the Makefile is unchanged. Reject
      // a recipe that neutralizes failure (Make's leading `-` ignore-error
      // prefix, or a shared shell neutralizer) the same way as an
      // auto-discovered package script (Codex Ummss).
      // readProjectMetadata only records a makeRecipes[target] entry when it
      // captured at least one recipe line, so an absent entry is
      // indistinguishable from a recipe whose capture was interrupted
      // (CodeRabbit 26020f13): findMakeRecipeNeutralizer(undefined) returns
      // null, which previously let the target resolve as clean even though
      // its recipe was never actually inspected. Fail closed instead of
      // trusting an uninspected recipe the same way a neutralizing one is
      // rejected below.
      if (!Object.hasOwn(makeRecipes, makeTarget)) {
        return {
          ...definition,
          command: `make ${makeTarget}`,
          status: 'BLOCKED',
          resolution: 'make-target',
          evidence: `No recipe text was captured for make target "${makeTarget}" (${definition.label}); closeout cannot trust an uninspected recipe.`,
        };
      }
      const recipeNeutralizer = findMakeRecipeNeutralizer(makeRecipes[makeTarget]);
      if (recipeNeutralizer) {
        return {
          ...definition,
          command: `make ${makeTarget}`,
          status: 'BLOCKED',
          resolution: 'make-target',
          evidence: `Make recipe for ${definition.label} neutralizes failures (${recipeNeutralizer}); closeout cannot admit a failure-hiding recipe.`,
        };
      }
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
    // Validate proof policies at plan time so unusable proofs cannot be
    // attested as admissible (Codex #4782132804). Mirrors executor rules.
    if (validArtifact) {
      const rel = String(proof.path).replaceAll('\\', '/').trim();
      if (path.isAbsolute(proof.path) || rel.startsWith('/') || /^[A-Za-z]:\//.test(rel)
        || rel.split('/').includes('..') || rel.startsWith('../')) {
        const proofEvidence = `Artifact proof path must be a relative worktree path without "..": ${proof.path}`;
        resolved = resolved.status === 'BLOCKED'
          ? { ...resolved, evidence: `${resolved.evidence} ${proofEvidence}` }
          : { ...resolved, status: 'BLOCKED', evidence: proofEvidence };
      }
      if (check.id === 'grafana-live-render' && proof.semantic !== 'grafana-live-result') {
        const proofEvidence = 'Grafana live proof requires semantic=grafana-live-result at plan time.';
        resolved = resolved.status === 'BLOCKED'
          ? { ...resolved, evidence: `${resolved.evidence} ${proofEvidence}` }
          : { ...resolved, status: 'BLOCKED', evidence: proofEvidence };
      }
    }
    if (validCommand) {
      const proofNeutralizer = findCommandFailureNeutralizer(proof.command);
      if (proofNeutralizer) {
        const proofEvidence = `Postcondition proof command for ${check.label} neutralizes failures (${proofNeutralizer}).`;
        resolved = resolved.status === 'BLOCKED'
          ? { ...resolved, evidence: `${resolved.evidence} ${proofEvidence}` }
          : { ...resolved, status: 'BLOCKED', evidence: proofEvidence };
      }
      // Validate the RAW configured string: the executor
      // (pr_closeout_process.js evaluateCommandProof) exact-compares the
      // untrimmed expectedPattern for the hunter semantic policy, so trimming
      // here would admit a whitespace-padded policy at plan time that
      // deterministically fails at runtime. Plan admissibility must mirror
      // executor rules and fail closed (Qodo discussion_r3652936843).
      const policy = String(proof.expectedPattern || '');
      const hunterOk = check.id === 'hunter-build'
        && policy === 'semantic:docker-compose-running-healthy';
      const literalOk = policy.startsWith('literal:')
        && policy.length <= 264
        && policy.length > 'literal:'.length
        && !/[\u0000-\u001f\u007f]/u.test(policy);
      if (!hunterOk && !literalOk) {
        const proofEvidence = check.id === 'hunter-build'
          ? 'Hunter proof requires expectedPattern semantic:docker-compose-running-healthy at plan time.'
          : 'Command proof expectedPattern must use a bounded literal:<text> policy or a supported semantic policy at plan time.';
        resolved = resolved.status === 'BLOCKED'
          ? { ...resolved, evidence: `${resolved.evidence} ${proofEvidence}` }
          : { ...resolved, status: 'BLOCKED', evidence: proofEvidence };
      }
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
// Include runner-native skip buckets: Rust `ignored`, pytest `deselected`.
// The label-first form (`errors: 0`) only strips COMPLETE count buckets: the
// zero must be followed by end-of-line or a summary delimiter (`, ; | ) ] }`),
// never by arbitrary prose or a `-byte`-style continuation. A single trailing
// period counts as summary punctuation (`errors: 0.`), but a decimal tail is
// not punctuation — `0.5` is never stripped (Qodo UC056). Otherwise
// diagnostics like `Error: 0 is not a valid threshold` or
// `Warning: 0-byte artifact was ignored` would lose their `Error:`/`Warning:`
// prefix, the remainder would no longer match statusSignal, and
// classifyOutput would misreport the run as PASS (Codex
// discussion_r3652957339). The count-first form (`0 warnings`) needs no such
// guard: the count precedes the label, so it cannot consume a diagnostic's
// `Label:` prefix.
const cleanZeroSummaries = (text) => text
  .replace(/(?<!:\s)\b0\s+(?:warnings?|errors?|problems?|fail(?:ed|ures?|ing)?|skips?|skipped|ignored|deselected|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)\b/gi, '')
  .replace(/\b(?:warnings?|errors?|problems?|fail(?:ed|ures?|ing)?|skips?|skipped|ignored|deselected|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)\s*(?::|=|\s)\s*0[ \t]*\.?(?=$|[,;|)\]}])/gim, '')
  .replace(/\bno\s+(?:warnings?|errors?|problems?|failures?|failing|skips?|ignored|deselected|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)\b/gi, '');

const STATUS_TERM = '(?:warn(?:ing)?s?|errors?|problems?|fail(?:ed|ures?|ing)?|skips?|skipped|ignored|deselected|todos?|blocks?|blocked|xfails?|xfailed|xpassed|pending)';
const COUNTED_SIGNAL = new RegExp(`(?:\\b[1-9]\\d*\\s+${STATUS_TERM}\\b|\\b${STATUS_TERM}\\s*(?::|=|\\s)\\s*[1-9]\\d*\\b)`, 'i');
const BRACKETED_SIGNAL = new RegExp(`^\\s*(?:[-*]\\s*)?\\[${STATUS_TERM}\\]`, 'i');
const LABELLED_SIGNAL = new RegExp(`^\\s*(?:[-*]\\s*)?${STATUS_TERM}\\s*[:=]`, 'i');
/**
 * Classify a single output line as a status signal worth surfacing, by
 * OR-ing several independent pattern families: a leading `✖`; a nonzero
 * counted term (`3 errors`, `errors: 3`, via COUNTED_SIGNAL); a bracketed tag
 * (`[FAIL]`) or labelled line (`Warnings:`) at line start; an all-caps
 * leading status word; compiler-style diagnostics (`file.js:12:3: warning
 * ...`); a runtime `SomeWarning:`/`SomeError:` class name (including Node's
 * `TypeError [ERR_...]: ...` bracketed-code form); a leading `warning` word
 * (including Node's `(node:1234) Warning:` form); `npm WARN`; and
 * TAP/test-framework markers (`not ok`, `# skip`, bare
 * `skipped`/`failed`/`blocked`/`pending`/`xfailed`/`xpassed`, or `ok N ... #
 * skip`).
 * @param {string} line - A single line of command output (already ANSI-stripped).
 * @returns {boolean} True if the line matches any status-signal pattern.
 */
const statusSignal = (line) => {
  const uppercase = /^\s*(?:[-*]\s*)?(?:WARN(?:ING)?S?|ERRORS?|PROBLEMS?|FAIL(?:ED|URES?|ING)?|SKIPS?|SKIPPED|TODOS?|BLOCKS?|BLOCKED)\b/;
  const compiler = /(?:^|\s)(?:[^\s:]+(?:\(\d+(?:,\d+)?\)|:\d+(?::\d+)?)):\s*(?:warning|error)\b/i;
  // Runtime diagnostics like `TypeError: ...`, bare `Error: ...`, and Node's
  // bracketed-code form `Error [ERR_INVALID_ARG_TYPE]: ...` / `TypeError
  // [ERR_*]: ...`. Do not match passing test titles that merely mention those
  // words (TAP `ok 1 - handles TypeError:` or Node `# Subtest: handles
  // TypeError: ...`).
  const runtime = /(?:^|[^A-Za-z0-9_])(?:[A-Za-z]+(?:Warning|Error)|Warning|Error)(?:\s+\[[^\]]+\])?:\s*\S/;
  const passingTestTitle = /^\s*(?:ok\s+\d+\b|#\s*Subtest:|✓|√|✔|PASS\b|passed\b(?!\s*:))/i;
  const warning = /^\s*(?:[-*]\s*)?(?:\([^)]*\)\s*)?warning\b(?:\s+|:)/i;
  const npmWarning = /\bnpm\s+WARN\b/i;
  // Go test SKIP records (`--- SKIP: TestFoo`) exit 0 while omitting coverage.
  const goSkip = /^\s*---\s*SKIP:\s+\S/;
  const framework = /(?:^\s*(?:not ok\b|#\s*(?:skip|skipped)\b|(?:skipped|failed|blocked|pending|xfailed|xpassed)\b)|\bok\s+\d+\b.*#\s*skip\b)/i;
  const isPassingTitle = passingTestTitle.test(line);
  const runtimeHit = runtime.test(line) && !isPassingTitle;
  // Passing test titles (TAP `ok 1 -`, Node `# Subtest:`, ✓/√/✔, `PASS`/`passed`)
  // routinely embed status words in fixture/prose text — e.g.
  // `ok 1 - reports 2 errors for malformed config` or
  // `# Subtest: ignores npm WARN fixture`. Previously only runtimeHit honored
  // the title, so the other detectors misread a green suite with failure-path
  // tests as FAIL. Apply the same exclusion to the incidental
  // counted/bracketed/labelled/compiler/npm detectors (Codex M6UFnGH).
  // NOT excluded: the explicit ✖ fail marker; anchored uppercase/`warning:`
  // headers (a line that actually starts with WARN/ERROR/warning is never a
  // passing title); and real TAP/Go SKIP markers (framework/goSkip) —
  // `ok N ... # skip` is a genuine TAP skip even though it also matches the
  // passing-title prefix.
  return /^\s*✖/u.test(line)
    || (COUNTED_SIGNAL.test(line) && !isPassingTitle)
    || (BRACKETED_SIGNAL.test(line) && !isPassingTitle)
    || (LABELLED_SIGNAL.test(line) && !isPassingTitle)
    || uppercase.test(line)
    || (compiler.test(line) && !isPassingTitle)
    || runtimeHit
    || warning.test(line)
    || (npmWarning.test(line) && !isPassingTitle)
    || goSkip.test(line)
    || framework.test(line);
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
  const failures = signals.filter((line) => /(?:\b(?:warn(?:ing)?s?|errors?|problems?|fail(?:ed|ures?|ing)?|skips?|skipped|ignored|deselected|todos?|xfails?|xfailed|xpassed|pending)\b|\bnot ok\b)/i.test(line));
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
  // Go `go test ./...` and cargo workspace runs print per-package "no tests"
  // lines alongside real `ok` / `N passed` evidence. Those mixed runs still
  // have authoritative tests and must not be failed for the empty packages.
  const hasAuthoritativeTestEvidence = (
    /\bok\t\S+/m.test(combined)
    || /test result:\s*ok\.\s*[1-9]\d*\s+passed/i.test(combined)
    || /\btests?\s+[1-9]\d*\s+passed\b/i.test(combined)
    || /^[ \t]*#\s*tests?\s+[1-9]/im.test(combined)
    || /(?:^|\n)\s*[1-9]\d*\s+passing\b/i.test(combined)
  );
  const pureNoWork = /\bno\s+tests?\s+(?:found|executed|ran|were run|to run)\b/i.test(combined)
    || /\bno\s+test\s+files?\s+found\b/i.test(combined)
    // Python unittest: `Ran 0 tests`
    || /\bran\s+0\s+tests?\b/i.test(combined)
    || /\b0\s+tests?\s+(?:run|ran|executed)\b/i.test(combined);
  // Go/Rust package-level empty markers: only pure-no-work when no real tests
  // ran elsewhere in the same output stream.
  const goRustEmptyPackage = /\[no test files\]/i.test(combined)
    || /\bno tests to run\b/i.test(combined)
    || /\brunning\s+0\s+tests?\b/i.test(combined);
  if (pureNoWork || (goRustEmptyPackage && !hasAuthoritativeTestEvidence)) {
    return { status: 'FAIL', evidence: 'Test runner reported no tests found/executed; closeout requires authoritative test evidence.' };
  }
  // Numeric no-work summaries from common runners: Node's TAP `# tests 0` /
  // `# pass 0` / plan `1..0`, and Vitest's `Tests 0 passed (0)` / `Test Files 0`.
  // These exit 0 while doing no work; the closeout gate requires authoritative
  // test evidence. `Test Files 0` only counts as a zero total when it is not a
  // bucket count in a richer summary: `Test Files 0 failed | 2 passed (2)`
  // reports zero failed files alongside real passes, which IS authoritative.
  // Empty TAP plan / `# pass 0` alone also FAILs unless independent evidence
  // shows tests actually ran (mixed runners can emit a zero plan for a subfile).
  const emptyTapPlan = /^[ \t]*1\.\.0\b/m.test(combined)
    || /^[ \t]*#\s*pass\s+0\b/im.test(combined);
  if (/^[ \t]*#\s*tests?\s+0\b/im.test(combined)
    || /\btests?\s+0\s+passed\b/i.test(combined)
    || new RegExp(`\\btest\\s+files?\\s+0(?!\\s+${STATUS_TERM}\\b)`, 'i').test(combined)
    // Mocha-style no-work: "0 passing" with exit 0 (not "N passing" with failures).
    || /(?:^|\n)\s*0\s+passing\b/i.test(combined)
    || (emptyTapPlan && !hasAuthoritativeTestEvidence)) {
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
 * optional-chaining, computed-property, and modifier-chain variants, plus the
 * native skip forms of the other test stacks: pytest mark decorators and
 * pytest.skip, Go t.Skip/t.Skipf, Rust #[ignore]) is only
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
/**
 * Brace/indentation-aware `rules`/`rule` silencing detector (Codex M6UFnGF).
 * Replaces the unbounded `rules? [\s\S]*? off/0` regex, which crossed
 * closing braces and flagged an unrelated sibling setting such as
 * `{"rules":{...},"server":{"port":0}}`. For a brace-delimited
 * (JSON/JSONC/JS object) value the rules object is brace-matched (string-
 * aware, so braces inside string values do not corrupt depth) and scanned for
 * a disabled/zero rule entry at any depth or distance; for an indentation-
 * scoped (YAML) value only the more-indented block under the key is scanned.
 * An unrelated sibling zero outside the rules object no longer matches.
 * @param {string} text
 * @returns {{index: number, match: string}[]} concise fragments and source
 *   offsets for each disabled/zero rule found inside a `rules`/`rule` scope.
 */
const findRulesScopedSilencings = (text) => {
  const findings = [];
  const keyRe = /(["']?rules?["']?)\s*[:=]/g;
  // A disabled/zero rule entry: "rule-id": "off" | 0 | [0, ...].
  const disabledRule = /["']?[A-Za-z_][\w./-]*["']?\s*:\s*(?:["']off["']|\b0\b|\[\s*0\b)/i;
  let km;
  while ((km = keyRe.exec(text)) !== null) {
    const afterKey = km.index + km[0].length;
    let i = afterKey;
    while (i < text.length && (text[i] === ' ' || text[i] === '\t')) i += 1;
    let scope = '';
    let consumedTo = i;
    if (text[i] === '{') {
      // String-aware brace match so `{`/`}` inside string values do not
      // corrupt the depth count (e.g. a rule named "a}b").
      let depth = 0;
      let inStr = null;
      const start = i;
      for (; i < text.length; i += 1) {
        const ch = text[i];
        if (inStr) {
          if (ch === '\\') { i += 1; continue; }
          if (ch === inStr) inStr = null;
          continue;
        }
        if (ch === '"' || ch === "'") { inStr = ch; continue; }
        if (ch === '{') depth += 1;
        else if (ch === '}') {
          depth -= 1;
          if (depth === 0) { i += 1; break; }
        }
      }
      scope = text.slice(start, i);
      consumedTo = i;
    } else {
      // Indentation-scoped (YAML): take following non-blank lines that are
      // strictly more indented than the `rules:` key line.
      const lineStart = text.lastIndexOf('\n', km.index - 1) + 1;
      const keyIndent = text.slice(lineStart, km.index).match(/^[ \t]*/)[0].length;
      const restLines = text.slice(afterKey).split(/\r?\n/);
      const block = [];
      for (const ln of restLines) {
        if (ln.trim() === '') continue;
        const ind = ln.match(/^[ \t]*/)[0].length;
        if (ind <= keyIndent) break;
        block.push(ln);
      }
      scope = block.join('\n');
      consumedTo = afterKey;
    }
    if (scope && disabledRule.test(scope)) {
      findings.push({
        index: km.index,
        match: `${km[1].replace(/\s+$/, '')}: { ...disabled/zero rule ... }`,
      });
    }
    // Skip past the consumed brace scope so a `rules` key nested inside this
    // object is not re-evaluated against an outer scope.
    if (consumedTo > keyRe.lastIndex) keyRe.lastIndex = consumedTo;
  }
  return findings;
};

/**
 * Bracket-aware `ignore`/`exclude` source-suppression detector (Codex UnKZ_).
 * Replaces two CONFIG_SILENCING regexes that bridged the key to its value with
 * a bounded `(?:\[[\s\S]{0,50000}?)?` window: padding an ignore array with
 * >50000 chars of benign globs before the real `"src/**"` entry pushed the
 * source exclusion outside the window, so the scan missed it. For each
 * `ignore`/`exclude` key this walks the COMPLETE following value — a
 * string-aware bracket match for an array literal, or the single quoted string
 * for a direct value — so array length no longer bounds detection. A value is
 * flagged when it contains either a src/test/spec-targeting quoted glob
 * (`srcToken`, \b-anchored so substrings like windows-latest / contest do not
 * false-positive) or a bare source-extension glob (`extGlob`: a `*.ts` tail and
 * the brace-expanded `*.{js,ts}` form, each item bounded by `(?<=[{,])`/`(?=[,}])`
 * so `{d.ts,map}` still matches nothing). Build artifacts (dist, node_modules,
 * a `*.d.ts` declaration tail) stay unflagged. A YAML block sequence (native
 * `ignorePatterns:` form: `- "src/**"` items indented under the key, neither
 * a `[...]` array nor a direct scalar) is walked the same indentation-scoped
 * way findRulesScopedSilencings already walks a `rules:` block (Codex
 * UrfDK) — a touched `.eslintrc.yml` using this form was previously invisible
 * to this scanner. Any other non-quoted/non-array value (`const ignore =
 * x.ignore`) still yields no region, ignored.
 * @param {string} text - Full file content to scan.
 * @returns {{index: number, match: string}[]} source offset + concise fragment
 *   for each ignore/exclude value that suppresses source/test/spec paths.
 */
const findIgnoreScopedSilencings = (text) => {
  const findings = [];
  const keyRe = /["']?(?:ignore|exclude)(?:s|d|Files|Patterns)?["']?\s*[:=]/gi;
  const srcToken = /["'][^"'\r\n]*\b(?:src|test|spec)\b[^"'\r\n]*["']/i;
  const extGlob = /["'](?:\*\*\/|\.\/)?\*\.(?:(?:[cm]?[jt]sx?|py|go|rs|rb|java|php|cs)\b|\{[^{}]{0,200}(?<=[{,])(?:[cm]?[jt]sx?|py|go|rs|rb|java|php|cs)(?=[,}])[^{}]{0,200}\})/i;
  let km;
  while ((km = keyRe.exec(text)) !== null) {
    let i = km.index + km[0].length;
    while (i < text.length && /\s/.test(text[i])) i += 1;
    let region = '';
    let consumedTo = i;
    if (text[i] === '[') {
      // String-aware bracket match: quotes and nested `[`/`]` inside string
      // items (e.g. a char-class glob "*.[jt]sx") do not corrupt the depth.
      let depth = 0;
      let inStr = null;
      const start = i;
      for (; i < text.length; i += 1) {
        const ch = text[i];
        if (inStr) {
          if (ch === '\\') { i += 1; continue; }
          if (ch === inStr) inStr = null;
          continue;
        }
        if (ch === '"' || ch === "'" || ch === '`') { inStr = ch; continue; }
        if (ch === '[') depth += 1;
        else if (ch === ']') {
          depth -= 1;
          if (depth === 0) { i += 1; break; }
        }
      }
      region = text.slice(start, i);
      consumedTo = i;
    } else if (text[i] === '"' || text[i] === "'" || text[i] === '`') {
      // Direct string value: "exclude": "src/**".
      const q = text[i];
      const start = i;
      i += 1;
      for (; i < text.length; i += 1) {
        const ch = text[i];
        if (ch === '\\') { i += 1; continue; }
        if (ch === q) { i += 1; break; }
      }
      region = text.slice(start, i);
      consumedTo = i;
    } else if (text[i] === '-' && /^-(?:[ \t]|$)/.test(text.slice(i, i + 2))) {
      // Indentation-scoped YAML block sequence (Codex UrfDK): collect every
      // following non-blank line more indented than the key's own line, the
      // same way findRulesScopedSilencings collects a `rules:` block.
      const lineStart = text.lastIndexOf('\n', km.index - 1) + 1;
      const keyIndent = text.slice(lineStart, km.index).match(/^[ \t]*/)[0].length;
      const blockStart = text.lastIndexOf('\n', i - 1) + 1;
      const restLines = text.slice(blockStart).split(/\r?\n/);
      const block = [];
      for (const ln of restLines) {
        if (ln.trim() === '') continue;
        const ind = ln.match(/^[ \t]*/)[0].length;
        if (ind <= keyIndent) break;
        block.push(ln);
      }
      region = block.join('\n');
      consumedTo = i;
    }
    if (region) {
      const m = region.match(srcToken) || region.match(extGlob);
      if (m) findings.push({ index: km.index, match: m[0].trim() });
    }
    // Skip past the consumed value so a nested ignore/exclude key is not
    // re-evaluated against an outer value.
    if (consumedTo > keyRe.lastIndex) keyRe.lastIndex = consumedTo;
  }
  return findings;
};

const scanSuppressionText = (file, text) => {
  const findings = [];
  const normalized = String(file).replaceAll('\\', '/').toLowerCase();
  const base = normalized.split('/').at(-1);
  const ignoreFile = /^\.(?:eslint|biome|prettier|stylelint|ruff)ignore$/.test(base);
  // Shell validation helpers — install.sh and shell scripts located under
  // ci/, scripts/, tools/, or bin/ — can neutralize failures with `|| true` /
  // `set +e` and still return 0 to make smoke/audit targets. Treat them as
  // config-like so CONFIG_SILENCING applies (Codex #4781637950). The scoping
  // is deliberately location-based: matching every shell extension would
  // reclassify ordinary application/deploy scripts (e.g. src/deploy.sh) as
  // config, running config-silencing neutrality checks on shell code that is
  // not a validation helper (CodeRabbit discussion_r3652923133).
  const helperDirectory = /(?:^|\/)(?:ci|scripts|tools|bin)\//.test(normalized);
  // A shebang is meaningful only at byte zero. A later heredoc or fixture
  // line that resembles one must not reclassify a non-shell helper.
  const shellShebang = /^#!\s*(?:(?:\/usr\/bin\/env)\s+|(?:\/\S+\/))?(?:ba)?(?:sh|zsh|ksh)\b/.test(text);
  const shellHelper = base === 'install.sh'
    || helperDirectory && (/\.(?:sh|bash|zsh|ksh)$/.test(base) || shellShebang);
  const configLike = ignoreFile || shellHelper
    || /\.(?:jsonc?|ya?ml|toml|ini|conf)$/.test(base)
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
    // Playwright/Jest-style suite suffixes that are not named *.test.* but
    // still execute under the project test runner when touched.
    || /\.(?:e2e|integration|unit|accept(?:ance)?|functional|system)\.[a-z0-9]+$/i.test(base)
    // pytest's OTHER default discovery pattern (python_files = test_*.py
    // *_test.py) is a prefix, not a suffix: the *_test.py suffix form is
    // already caught by the first pattern above, but a root-level
    // test_example.py has no test/ directory ancestor and no *_test.py suffix
    // to match, so it fell through this predicate entirely (Codex UgisO).
    || /^test_.*\.py$/i.test(base)
    // Also classify files inside standard test directories (__tests__/ — a
    // standard Jest layout — plus test/, tests/, spec/, and specs/) as test
    // files even when the filename has no test/spec token, so weakening
    // markers (describe.only/it.skip/test.todo) in tests/foo.js are scanned.
    // The segment must match in full so lookalikes such as contest/, latest/,
    // test-utils/, or __tests_data__/ do not false-positive.
    || /(?:^|\/)(?:tests?|specs?|__tests__|e2e|integration)\//i.test(normalized);
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
    // Brace/indentation-aware `rules`/`rule` silencing (Codex M6UFnGF):
    // scans only inside the rules object/block so an unrelated sibling zero
    // (e.g. `server.port:0`) no longer false-positives while a disabled rule
    // at any depth/distance is still detected.
    for (const frag of findRulesScopedSilencings(text)) {
      const line = text.slice(0, frag.index).split(/\r?\n/).length;
      findings.push({ file, line, category: 'config-silencing', match: frag.match });
    }
    // Bracket-aware ignore/exclude source-suppression (Codex UnKZ_): walks the
    // complete ignore array so a `"src/**"` exclusion padded behind >50000
    // chars of benign globs is still detected, unlike the bounded-window
    // regexes this replaced.
    for (const frag of findIgnoreScopedSilencings(text)) {
      const line = text.slice(0, frag.index).split(/\r?\n/).length;
      findings.push({ file, line, category: 'config-silencing', match: frag.match });
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
    // Allow optional whitespace/comments between the receiver, dots, and the
    // focus/skip/todo member so `test . only(...)` / `test /* x */.only(...)`
    // cannot evade the scan. Multiline receiver splits are handled below.
    // Include Mocha TDD / Vitest `suite` alias alongside describe/it/test/context
    // so suite.only / suite.skip cannot focus a suite while the scan reports clean.
    // Optional chaining before computed members: test?.['only'] / describe?.["skip"]
    // is `?.[` (question + dot + bracket), not bare `?[` (Codex open finding).
    // Non-JavaScript ecosystems (Codex UDDQN): pytest mark decorators
    // (@pytest.mark.skip/.skipif/.xfail — also the bare pytest.mark.* form so a
    // module-level pytestmark assignment is caught), a plain pytest.skip(...)
    // call, Go's t.Skip(/t.Skipf(, and Rust's #[ignore] attribute are the
    // native skip forms of the other test stacks this scanner classifies as
    // test-like. They run under the same testLike gating and inertness map, so
    // quoted mentions (e.g. "pytest.mark.skip" in a JS string) stay unflagged.
    // node:test's own TestContext#skip([message]) (lowercase `t.skip(`) is
    // ALSO a native runtime skip, not merely a "legitimate conditional
    // platform gate": `test('x', t => { t.skip(); throw new Error('never
    // checked'); })` is reported as skipped and `node --test` exits 0
    // regardless of what unreachable code follows (CodeRabbit UnYb2). Flag it
    // unconditionally, the same way `this.skip()` and `.skipIf(cond)` above
    // are flagged regardless of whether their call site happens to be
    // conditionally guarded — this scanner surfaces every skip mechanism for
    // human review rather than trying to tell a legitimate platform gate from
    // an abused one. Go's abort method keeps its own capital-S alternative
    // (`t.Skip(`/`t.Skipf(`/`t.SkipNow(`) since Go has no lowercase form.
    const nativeTestWeakening = /\bpytest\s*\.\s*mark\s*\.\s*(?:skip|skipif|xfail)\b|\bpytest\s*\.\s*skip\s*\(|\bt\s*\.\s*Skip(?:Now|f)?\s*\(|\bt\s*\.\s*skip\s*\(|#\s*\[\s*ignore\b/;
    const isPythonFile = /\.pyi?$/i.test(base);
    // The optional `(?:\s*\([^()]*\))?` after an intermediate chain member lets
  // the parameterized-test factory forms `test.each(cases).only(...)` /
  // `describe.each(cases).skip(...)` match: Jest/Vitest return a new test
  // function from `.each(...)`, and `.only`/`.skip` on THAT member still
  // focuses/skips the suite, so a chain with a call between the receiver and
  // the weakening member must not evade the scan (Codex M6UFnGV).
  // These dot/bracket/bare-function forms are all STATIC receiver.modifier
  // shapes; they miss three RUNTIME skip forms that never write a literal
  // `.skip`/`.only`/`.todo` member access (Codex Ugisa):
  //   - Node's own options-object skip: test('x', { skip: true }, fn) / a
  //     truthy string reason, per node:test's documented API.
  //   - Mocha's this.skip() called from inside a running test/suite body --
  //     invisible to any static describe/it scan since it names no suite.
  //   - Vitest's describe.skipIf(cond)(...) / it.skipIf(cond)(...) conditional
  //     skip call-chain, distinct from the unconditional `.skip` already
  //     covered above.
  // A `skip:` option skips under node:test whenever its value is TRUTHY, not
  // only for literal `true` or a non-empty string reason: a runtime-truthy
  // bare reference such as `skip: process.env.CI` or `skip: flags.quiet` skips
  // the test in CI while this scan reports clean (Codex Uz6Ag). Flag a skip
  // value that is not PROVABLY falsy AND has no conditional/comparison
  // operator: a negative lookahead admits the falsy literals (`false`,
  // `null`, `undefined`) and the empty-string reasons (`''` / `""`), which
  // node:test treats as falsy and does not skip on; a second negative
  // lookahead admits a value that contains a ternary (`?`), short-circuit
  // (`&&` / `||`), or comparison (`===` / `!==` / `==` / `!=`) operator,
  // because this repo's own test suite gates POSIX/Windows-only tests with
  // exactly those forms (e.g. `skip: process.platform === 'win32' ? 'reason'
  // : false`, `skip: !available && 'reason'`) -- a static scanner cannot
  // evaluate them, but they carry a falsy escape and are legitimate platform
  // gates, not unconditional weakening. Only a bare always-truthy value (true,
  // a non-empty string, or a bare env/flag reference with no falsy escape) is
  // flagged, preserving the empty-reason and false exemptions (Codex UiTMl).
  const optionObjectSkip = /\b(?:describe|it|test|context|suite)\s*\(\s*(?:[^,(){}]*,\s*)?\{[^{}]*\bskip\s*:\s*(?!false\b|undefined\b|null\b|''|"")(?![^,}\n]*(?:\?|&&|\|\||===|!==|==|!=))\S/;
  const mochaRuntimeSkip = /\bthis\s*\.\s*skip\s*\(\s*\)/;
  // Accept exactly ONE separator before skipIf — a bare `.` OR the optional-
  // chaining `?.` — via `\??\.`. The prior `(?:\?\.)?\s*\.` consumed an
  // optional `?.` and then STILL required a literal `.`, so the only `?.` form
  // it could match was the syntactically-invalid `it?..skipIf(`; the real
  // `it?.skipIf(cond)(...)` fell through undetected (Codex UiTMl dead branch).
  const vitestSkipIf = /\b(?:describe|it|test|context|suite)\s*\??\.\s*skipIf\s*\(/;
  const testWeakening = new RegExp(
    [
      /\b(?:describe|it|test|context|suite)(?:\s*(?:\/\*[\s\S]*?\*\/\s*)*\??\.\s*(?:\/\*[\s\S]*?\*\/\s*)*[A-Za-z_]\w*(?:\s*\((?:[^()]|\((?:[^()]|\([^()]*\))*\))*\))?)*(?:\s*(?:\/\*[\s\S]*?\*\/\s*)*\??\.\s*(?:\/\*[\s\S]*?\*\/\s*)*(?:skip|only|todo))\b/.source,
      /\b(?:describe|it|test|context|suite)\s*(?:\?\.)?\s*\[\s*['"`](?:skip|only|todo)['"`]\s*\]/.source,
      /(?<![\w$.])(?:fit|fdescribe|xit|xdescribe)\s*\(/.source,
      optionObjectSkip.source,
      mochaRuntimeSkip.source,
      vitestSkipIf.source,
    ].join('|'),
    'i',
  );
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
          // Template literals: static text is inert, but `${...}` interpolations
          // execute as JavaScript and can register focus/skip calls. Scan the
          // expression body as live code (non-inert) while keeping the
          // surrounding backticks and static segments inert.
          if (quote === '`') {
            if (escaped) {
              inert[i] = true;
              escaped = false;
              i += 1;
              continue;
            }
            if (ch === '\\') {
              inert[i] = true;
              escaped = true;
              i += 1;
              continue;
            }
            if (ch === '`') {
              inert[i] = true;
              quote = null;
              i += 1;
              continue;
            }
            if (ch === '$' && line[i + 1] === '{') {
              inert[i] = true;
              inert[i + 1] = true;
              i += 2;
              let depth = 1;
              let interpQuote = null;
              let interpEscaped = false;
              while (i < line.length && depth > 0) {
                const ic = line[i];
                if (interpQuote) {
                  // Nested string inside the interpolation is inert; the
                  // surrounding expression is still executable, but we only
                  // need inertness for quotes so .only inside them is ignored.
                  inert[i] = true;
                  if (interpEscaped) {
                    interpEscaped = false;
                  } else if (ic === '\\') {
                    interpEscaped = true;
                  } else if (ic === interpQuote) {
                    interpQuote = null;
                  }
                  i += 1;
                  continue;
                }
                if (ic === "'" || ic === '"' || ic === '`') {
                  inert[i] = true;
                  interpQuote = ic;
                  i += 1;
                  continue;
                }
                if (ic === '{') {
                  depth += 1;
                  i += 1;
                  continue;
                }
                if (ic === '}') {
                  depth -= 1;
                  if (depth === 0) {
                    inert[i] = true; // closing brace of ${...}
                    i += 1;
                    break;
                  }
                  i += 1;
                  continue;
                }
                // Expression body: leave inert[i] false so test.only is live.
                i += 1;
              }
              continue;
            }
            inert[i] = true;
            i += 1;
            continue;
          }
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
        if (isPythonFile && ch === '#') {
          lineComment = true;
          inert[i] = true;
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
    const globalNativeWeakening = new RegExp(nativeTestWeakening.source, 'g');
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
      for (const match of line.matchAll(globalNativeWeakening)) {
        if (inert[match.index ?? 0]) continue;
        findings.push({ file, line: index + 1, category: 'test-weakening', match: match[0] });
        break;
      }
    });
    // Multiline member access: `test\n  .only(...)` or `describe /* gap */ .skip`
    // is not visible to the per-line pass. Only start a window when the line
    // ends with a bare test receiver (so quoted fixtures like
    // `'describe.only(...)'` on a single line are not re-scanned without
    // string inertness). Collapse comments/whitespace across at most 3 lines.
    //
    // Quote stripping must not erase executable template interpolations: a
    // naive backtick strip would drop `${test\n  .only(...)}` entirely and
    // re-open a multiline bypass. Single/double-quoted strings are removed
    // wholesale; template literals keep only their `${...}` expression bodies
    // (static template text is inert and discarded). Line and block comments
    // are blanked in the SAME lexical pass: stripping comments with a
    // quote-blind regex first would cut `//`/`/*` sequences inside string
    // literals and leave unterminated quotes that corrupt every following
    // line of the whole-file strip (Codex discussion_r3652957336). Newlines
    // consumed inside strings/templates/comments are re-emitted so the
    // stripped output stays line-aligned with the source — the multiline
    // fallback below indexes code-bearing lines across the whole file.
    const stripQuotesPreserveTemplateExpr = (text) => {
      let out = '';
      let i = 0;
      while (i < text.length) {
        const ch = text[i];
        if (ch === '/' && text[i + 1] === '/') {
          // Line comment: consume to end of line; the newline itself is
          // emitted by the ordinary-char path, keeping line alignment.
          while (i < text.length && text[i] !== '\n') i += 1;
          continue;
        }
        if (ch === '/' && text[i + 1] === '*') {
          // Block comment: consume through the closer, preserving newlines.
          i += 2;
          while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) {
            if (text[i] === '\n') out += '\n';
            i += 1;
          }
          i = Math.min(i + 2, text.length);
          out += ' ';
          continue;
        }
        if (ch === "'" || ch === '"') {
          const quote = ch;
          i += 1;
          while (i < text.length) {
            if (text[i] === '\n') out += '\n';
            if (text[i] === '\\') {
              i += 2;
              continue;
            }
            if (text[i] === quote) {
              i += 1;
              break;
            }
            i += 1;
          }
          out += ' ';
          continue;
        }
        if (ch === '`') {
          i += 1;
          while (i < text.length) {
            if (text[i] === '\\') {
              i += 2;
              continue;
            }
            if (text[i] === '`') {
              i += 1;
              break;
            }
            if (text[i] === '$' && text[i + 1] === '{') {
              i += 2;
              let depth = 1;
              let start = i;
              let nestedQuote = null;
              let nestedEscaped = false;
              while (i < text.length && depth > 0) {
                const c = text[i];
                if (nestedQuote) {
                  if (nestedEscaped) {
                    nestedEscaped = false;
                  } else if (c === '\\') {
                    nestedEscaped = true;
                  } else if (c === nestedQuote) {
                    nestedQuote = null;
                  }
                  i += 1;
                  continue;
                }
                if (c === "'" || c === '"' || c === '`') {
                  nestedQuote = c;
                  i += 1;
                  continue;
                }
                if (c === '{') {
                  depth += 1;
                  i += 1;
                  continue;
                }
                if (c === '}') {
                  depth -= 1;
                  if (depth === 0) {
                    // Recurse so nested templates inside the expression also
                    // preserve only their live ${...} bodies.
                    out += stripQuotesPreserveTemplateExpr(text.slice(start, i));
                    i += 1;
                    break;
                  }
                  i += 1;
                  continue;
                }
                i += 1;
              }
              // Unclosed `${` at end of the scan window (receiver split across
              // the window boundary): still emit the partial expression so a
              // bare `test` inside `${test` can open the multiline fallback.
              if (depth > 0) {
                out += stripQuotesPreserveTemplateExpr(text.slice(start, i));
              }
              continue;
            }
            // Static template text is inert — drop it, but keep newlines so
            // the stripped output stays line-aligned with the source.
            if (text[i] === '\n') out += '\n';
            i += 1;
          }
          out += ' ';
          continue;
        }
        out += ch;
        i += 1;
      }
      return out;
    };
    if (!findings.some((f) => f.category === 'test-weakening' && f.file === file)) {
      const windowWeakening = new RegExp(testWeakening.source, 'i');
      const bareReceiver = /\b(?:describe|it|test|context|suite)\s*(?:\/\*[\s\S]*?\*\/\s*)*$/;
      // A node:test-style option-object skip opens the multiline window
      // differently from the `test\n.only` member-access split: its first line
      // is `test('name', {` — it ends in an open brace, NOT a bare receiver, so
      // `bareReceiver` never fires and the collapsed-window rescan (which
      // includes optionObjectSkip) never runs on the reassembled text (Codex
      // UiNu2). Detect the other opener too: a receiver call
      // `(describe|it|test|context|suite)(` whose parentheses are still open at
      // end of the stripped line AND that already has an options-object `{`
      // open inside them. strippedLines already have strings/templates/comments
      // removed, so a plain paren/brace depth walk cannot be fooled by braces
      // or parens sitting inside a quoted argument.
      const opensOptionObjectCall = (stripped) => {
        // Single left-to-right pass so a long/minified line with many receiver
        // tokens stays linear instead of re-walking to end-of-line for every
        // `test(`/`describe(`/… match (CodeRabbit UmlJL: the per-match rewalk
        // was O(matches × length), quadratic on adversarial input up to
        // MAX_SUPPRESSION_SCAN_BYTES). The original per-match condition — an
        // unclosed receiver call that still has an options-object `{` open at
        // end of line — is equivalent to: the innermost still-open `{` was
        // opened at or after the earliest still-open receiver call's `(`.
        // (Verified behavior-identical to the previous rewalk against the
        // multiline option-object fixtures and a 200k-case fuzz.)
        const receiver = /\b(?:describe|it|test|context|suite)\s*\(/g;
        const openParens = []; // { isReceiver, start } for each unmatched `(`
        const openBraces = []; // index of each unmatched `{`
        let m = receiver.exec(stripped);
        for (let k = 0; k < stripped.length; k += 1) {
          let receiverHere = false;
          // The receiver match ends on its `(`; mark that paren as a receiver
          // call. Distinct matches end at distinct positions, so the guard
          // fires at most once per index.
          while (m && m.index + m[0].length === k + 1) {
            receiverHere = true;
            m = receiver.exec(stripped);
          }
          const ch = stripped[k];
          if (ch === '(') openParens.push({ isReceiver: receiverHere, start: k + 1 });
          else if (ch === ')') openParens.pop();
          else if (ch === '{') openBraces.push(k);
          else if (ch === '}') { if (openBraces.length) openBraces.pop(); }
        }
        if (!openBraces.length) return false;
        const innermostOpenBrace = openBraces[openBraces.length - 1];
        return openParens.some((p) => p.isReceiver && p.start <= innermostOpenBrace);
      };
      // Lookahead window for bare-receiver splits, counted in CODE-BEARING
      // lines (non-blank after comment/quote stripping) rather than raw lines:
      // a raw line-count cap is reachable purely by blank/comment padding, so
      // `test` followed by >=cap padding lines and then `.only(...)` would
      // escape detection (Codex discussion_r3652957336). Blank and
      // comment-only lines therefore do not consume the window. The whole
      // file is stripped once (linear in file size) and each window covers at
      // most RECEIVER_LOOKAHEAD code-bearing lines, so the fallback stays
      // O(lines × RECEIVER_LOOKAHEAD) on huge files.
      const RECEIVER_LOOKAHEAD = 16;
      // Blank comments and quotes across the full file once (single lexical
      // pass, so comment markers inside string literals cannot unbalance the
      // quote handling) so a live receiver that only becomes visible after
      // `${...}` extraction (e.g. `${test` on one line and `.only(...)}` on
      // the next) can open the fallback. Static template text is discarded
      // and cannot open a window.
      const strippedLines = stripQuotesPreserveTemplateExpr(lines.join('\n')).split('\n');
      const codeIndices = [];
      strippedLines.forEach((stripped, index) => {
        if (stripped.trim()) codeIndices.push(index);
      });
      for (let c = 0; c < codeIndices.length; c += 1) {
        const i = codeIndices[c];
        // Start a window when the stripped line ends with a bare test receiver
        // (the `test\n.only` member-access split — quoted fixtures like
        // `'describe.only(...)'` on a single line are not re-scanned without
        // string inertness) OR when it opens an unclosed option-object test
        // call (the multiline `test('name', {\n skip: true\n}, fn)` form).
        if (!bareReceiver.test(strippedLines[i].trimEnd())
          && !opensOptionObjectCall(strippedLines[i])) continue;
        const windowText = codeIndices.slice(c, c + RECEIVER_LOOKAHEAD)
          .map((index) => strippedLines[index])
          .join('\n')
          .replace(/\s+/g, ' ')
          // Join `test .only` / `describe .skip` / `suite .only` after collapse.
          .replace(/\b(describe|it|test|context|suite)\s+\./gi, '$1.');
        const match = windowText.match(windowWeakening);
        if (!match) continue;
        findings.push({
          file,
          line: i + 1,
          category: 'test-weakening',
          match: match[0].replace(/\s+/g, ' ').slice(0, 80),
        });
        break;
      }
    }
  }
  return findings;
};

module.exports = {
  COMMAND_FAILURE_NEUTRALIZERS,
  CONFIG_SILENCING,
  MANDATORY_CHECKS,
  MARKERS,
  REQUIRED_PROOFS,
  STATUS_TERM,
  buildCheckPlan,
  classifyOutput,
  findCommandFailureNeutralizer,
  findStatusSignals,
  scanSuppressionText,
  shellQuote,
};
