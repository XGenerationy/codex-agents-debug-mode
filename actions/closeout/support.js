'use strict';

// Support script for the closeout composite action. The action.yml is pure
// wiring; every decision lives here so it is hermetically testable. Zero
// dependencies, same repo conventions as the gate scripts it wraps. The gate
// CLI itself (scripts/pr_closeout.js) is consumed as-is, never modified.

const {
  appendFileSync, chmodSync, closeSync, constants, fchmodSync, fstatSync, lstatSync, mkdirSync,
  readFileSync, realpathSync, rmSync, statSync, unlinkSync, writeFileSync, writeSync,
} = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
// protectWindowsPrivateFile/isSameFileIdentity are UTILITIES the gate CLI
// already exports and uses on its own evidence writes (report.json/report.md
// in pr_closeout_report.js, evidence logs in pr_closeout_process.js) —
// reusing them here is not a modification to scripts/pr_closeout_* (still
// consumed as merged), just consuming their existing public surface the same
// way the CLI's own code does (Codex PR7 review, "Protect wrapper evidence
// with a Windows DACL"; chatgpt-codex-connector PR7 #6YaIaZ).
const { isSameFileIdentity, openNoFollowSync, protectWindowsPrivateFile } = require('../../scripts/pr_closeout_fs.js');

// Patterns for credential-shaped values that can leak into CLI stderr (e.g. a
// git remote URL embedding x-access-token:TOKEN, or a gh error echoing an
// Authorization header). Applied to stderr before it reaches the Step Summary
// or any other rendered surface. The patterns mirror the gate CLI's own
// secret-detection set, kept deliberately broad: a false positive (replacing a
// non-secret token-shaped string) is harmless, while a miss is a credential
// exposure. Mirrors the existing decision that gate error text stays on
// run-log-equivalent surfaces — but those surfaces still must not carry raw
// credentials.
const REDACT_PATTERNS = [
  // PEM-encoded secrets that span multiple physical lines: a private_key /
  // signing_key value is commonly a `-----BEGIN <TYPE>-----` ... `-----END
  // <TYPE>-----` block. The line-scoped key-name pattern below redacts only
  // the first line of such a value (its `.+$/m` stops at the newline), so the
  // block's continuation lines (the base64 body and the END marker) would
  // leak into stderr/Step Summary/JSON error records. This pattern consumes
  // the ENTIRE assignment — from the credential key, through the BEGIN..END
  // span (including embedded newlines) — so nothing is left for the line-
  // scoped key-name pattern to re-match and downgrade. `[\s\S]` matches any
  // char including newlines, non-greedy to the END. Anchored to a preceding
  // `key=`/`key:` so it does not swallow an unquoted PEM in arbitrary prose.
  [/(\b(?:private[_-]?key|signing[_-]?key|client[_-]?secret|certificate|cert)\s*[:=]\s*)-{5}BEGIN [A-Z0-9 -]+-{5}[\s\S]*?-{5}END [A-Z0-9 -]+-{5}/g, '[REDACTED:pem-block]'],
  // A PEM block with NO key-name prefix — a child process (or a CLI diagnostic)
  // can emit a raw `-----BEGIN …-----` block. The keyed pattern above only
  // matches after `key=`/`key:`, so this generic fallback catches an un-prefixed
  // block. Runs AFTER the keyed pattern so `key=-----BEGIN…` is consumed with its
  // key first (CodeRabbit 3745322356).
  [/-{5}BEGIN [A-Z0-9 -]+-{5}[\s\S]*?-{5}END [A-Z0-9 -]+-{5}/g, '[REDACTED:pem-block]'],
  // GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_), with a word boundary
  // so a short false-positive prefix does not match.
  [/(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}/g, '[REDACTED:token]'],
  // Credential embedding in a URL: scheme://user:pass@host or user:pass@host.
  // Replace the credential part only, preserving the scheme and host for
  // diagnostics (the host is not secret — the credential is).
  [/(?:(?:https?|git|ssh):\/\/)[^\s@/]+@[^\s/]+/g, '[REDACTED:url-credential]@'],
  [/(x-access-token):[^\s@/]+@/g, '$1=[REDACTED:credential]@'],
  // Generic key=value pairs where the key looks credential-shaped, including
  // the full auth-scheme value (Authorization: Bearer eyJ... → all redacted).
  // The key-name families mirror the gate CLI's SENSITIVE_ENV_PATTERN (and the
  // denylist): token/password/secret/credential PLUS the *_key spellings
  // (api_key, access_key, private_key, signing_key) and client_secret, which a
  // diagnostic can echo as `api_key=...`/`access_key=...` after an invalid
  // input or a spawn failure. Underscore AND hyphen separators are matched so
  // `api-key=` is covered too. Without these, the terminal catch and the
  // failure summary/state artifact could emit a raw *_key value verbatim.
  // A standard space-delimited Bearer credential (`Bearer eyJ...` with no
  // colon or equals sign) — every alternation above requires `[:=]`, so a raw
  // bearer token emitted by a child process diagnostic would leak. Match the
  // RFC 6750 scheme form and redact the credential following it (CodeRabbit
  // #6X72Zq). Runs before the generic key=value pattern so the longer match
  // wins; case-insensitive; the credential is the first non-space token after
  // the scheme name.
  [/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED:token]'],
  [/(Authorization|Bearer|token|password|secret|credential|api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key|client[_-]?secret)\s*[:=]\s*.+$/gim, '$1=[REDACTED]'],
];

const redactSecrets = (text) => REDACT_PATTERNS.reduce(
  (acc, [pattern, replacement]) => acc.replace(pattern, replacement),
  String(text ?? ''),
);

const RUN_VALUES = new Set(['plan', 'full']);
const MODE_VALUES = new Set(['strict', 'engine']);
const BOOL_VALUES = new Map([['true', true], ['false', false]]);

/**
 * Validates the action's discretionary inputs fail-closed. Empty/absent means
 * the action.yml default; anything outside the exact accepted set is a named
 * error BEFORE the gate CLI is spawned. Casing is not forgiven — the CLI is
 * case-sensitive and the action must never widen what the CLI accepts.
 * @param {{run?: string, mode?: string, prComment?: string}} inputs
 * @returns {{run: 'plan'|'full', mode: 'strict'|'engine', prComment: boolean}}
 */
const validateActionInputs = ({ run = '', mode = '', prComment = '' } = {}) => {
  const runValue = run === '' ? 'plan' : run;
  if (!RUN_VALUES.has(runValue)) throw new Error(`Unknown run input value: ${runValue}. Use plan or full.`);
  const modeValue = mode === '' ? 'strict' : mode;
  if (!MODE_VALUES.has(modeValue)) throw new Error(`Unknown mode input value: ${modeValue}. Use strict or engine.`);
  const commentValue = prComment === '' ? 'false' : prComment;
  if (!BOOL_VALUES.has(commentValue)) throw new Error(`Unknown pr-comment input value: ${commentValue}. Use true or false.`);
  return { run: runValue, mode: modeValue, prComment: BOOL_VALUES.get(commentValue) };
};

/**
 * Resolves the live PR base ref down the spec's fail-closed ladder:
 * explicit input, then GITHUB_BASE_REF (set on pull_request events), then the
 * event payload's pull_request.base.ref (pull_request_review events), then
 * (CodeRabbit PR7 #6YW9UP) the same field nested under workflow_run's own
 * associated-PR shape — GITHUB_BASE_REF is not set for workflow_run events,
 * and their payload has no top-level pull_request, only
 * workflow_run.pull_requests[0] (populated for a same-repo PR; empty for a
 * fork PR, in which case this rung is skipped and the ladder falls through)
 * — else null, in which case the CLI's own config.baseRef-or-error contract
 * applies and the failure is the gate's honest named error, not a guess.
 * @param {{inputBaseRef?: string, env: object, event: object}} options
 * @returns {string|null}
 */
const resolveBaseRef = ({ inputBaseRef = '', env = {}, event = {} } = {}) => {
  if (inputBaseRef) return inputBaseRef;
  if (env.GITHUB_BASE_REF) return `origin/${env.GITHUB_BASE_REF}`;
  const eventBase = event?.pull_request?.base?.ref;
  if (typeof eventBase === 'string' && eventBase) return `origin/${eventBase}`;
  const workflowRunBase = event?.workflow_run?.pull_requests?.[0]?.base?.ref;
  if (typeof workflowRunBase === 'string' && workflowRunBase) return `origin/${workflowRunBase}`;
  return null;
};

/**
 * Rejects an evidence output directory that resolves inside the repository
 * being validated, BEFORE any mkdir or state write. The gate CLI has its own
 * `assertOutputOutsideRepository` check, but the plan tier returns before
 * the CLI reaches it, and the wrapper itself calls `mkdirSync(outputDir)`
 * and writes `plan.json`/`action-state.json` there — so a caller that sets
 * `output-dir` to `.` or any workspace-relative path would dirty the
 * checkout and have those files uploaded as evidence. Both the plain
 * resolved path and the symlink-resolved physical path are compared against
 * the workspace root, mirroring the CLI's own symlink defense; a realpath
 * failure fails closed (the path cannot be proven safe).
 * @param {{outputDir: string, workspace?: string}} options
 */
const assertOutputOutsideWorkspace = ({ outputDir, workspace = '' }) => {
  const root = workspace || process.cwd();
  const rootResolved = path.resolve(root);
  // Relative output paths resolve against the workspace root (on the runner
  // the cwd IS GITHUB_WORKSPACE), so resolve the candidate there before
  // comparing — `output-dir: .` must be caught, not interpreted against an
  // arbitrary local cwd.
  const resolveAgainstWorkspace = (candidate) => (path.isAbsolute(candidate)
    ? candidate
    : path.resolve(rootResolved, candidate));
  const inside = (rootBase, candidate) => {
    const relative = path.relative(rootBase, candidate);
    return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
  };
  // Logical containment check: catch `output-dir: .`, workspace-relative
  // paths, and `..` escapes against the workspace root as configured.
  if (inside(rootResolved, resolveAgainstWorkspace(outputDir))) {
    throw new Error(`Evidence output directory must be outside the repository workspace: ${outputDir}`);
  }
  // Physical containment check: a symlinked workspace root (common on some
  // self-hosted runners, or when GITHUB_WORKSPACE points through a link) makes
  // the logical comparison meaningless for the realpath-resolved output path.
  // realpath BOTH the workspace root and the output target so the comparison
  // is physical-against-physical; a realpath failure of the root falls back to
  // the longest existing ancestor (the workspace root normally exists, but
  // fail-closed rather than trusting the logical path if it does not).
  const rootPhysical = realpathAncestor(rootResolved);
  let physical;
  try {
    physical = realpathSync(resolveAgainstWorkspace(outputDir));
  } catch {
    // The directory may not exist yet (the CLI mkdirs it later). realpath
    // the EXISTING ancestor closest to it so a symlink planted on an
    // ancestor can't smuggle an inside-workspace target past this check.
    physical = realpathAncestor(resolveAgainstWorkspace(outputDir));
  }
  if (inside(rootPhysical, physical)) {
    throw new Error(`Evidence output directory resolves inside the repository workspace (via symlink): ${outputDir}`);
  }
};

/**
 * realpathSync the longest existing ancestor of `candidate` so a symlink on
 * an existing ancestor is resolved even when the target leaf does not yet
 * exist. Returns the resolved path of that ancestor, or `candidate` itself
 * if nothing along the chain exists yet (the CLI's own check still runs and
 * fails closed for a fully nonexistent absolute path that lands inside).
 */
const realpathAncestor = (candidate) => {
  let current = candidate;
  while (current && current !== path.dirname(current)) {
    try {
      return realpathSync(current);
    } catch {
      current = path.dirname(current);
    }
  }
  return candidate;
};

/**
 * Extracts the LAST parseable JSON object line from captured stdout. The gate
 * writes exactly one JSON line, but the scan is last-to-first so incidental
 * earlier output can never shadow the record. Scalars are not records.
 * @param {string} stdout
 * @returns {object|null}
 */
const parseLastJsonLine = (stdout) => {
  const lines = String(stdout ?? '').split(/\r?\n/).filter((line) => line.trim() !== '');
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try {
      const value = JSON.parse(lines[index]);
      // An own __proto__ key is inert on the parse itself but hijacks the
      // prototype of any later Object.assign copy; the gate never emits
      // one, so such a record can only be hostile or garbled — skip it.
      if (
        value && typeof value === 'object' && !Array.isArray(value)
        && !Object.prototype.hasOwnProperty.call(value, '__proto__')
      ) return value;
    } catch {
      // Not JSON; keep scanning upward.
    }
  }
  return null;
};

/**
 * The spec's exit decision table. Full tier: the CLI's exit code propagates
 * verbatim (the job is the enforcing gate). Plan tier: success iff a REAL
 * plan was captured — an object with a string planStatus — regardless of
 * exit code or planStatus value, because "not ready yet" is the preview's
 * normal honest state; a missing/unparseable plan (including the CLI's
 * init-failure BLOCKED record, which has no planStatus) fails loudly.
 * @param {{run: 'plan'|'full', cliExitCode: number|null, parsed: object|null}} options
 * @returns {{success: boolean, exitCode: number, reason: string}}
 */
const decideExit = ({ run, cliExitCode, parsed }) => {
  if (run === 'full') {
    const code = Number.isInteger(cliExitCode) ? cliExitCode : 3;
    const label = parsed?.status || parsed?.overallStatus || 'unknown';
    if (code === 0) {
      // The gate always writes one JSON line; exit 0 with nothing parseable
      // means the wrapper or stdout path broke. Never report PASS on
      // missing evidence (review decision, Task 2 round).
      return parsed
        ? { success: true, exitCode: 0, reason: 'gate PASS' }
        : { success: false, exitCode: 3, reason: 'gate exited 0 but produced no JSON record' };
    }
    return { success: false, exitCode: code, reason: `gate ${label} (exit ${code})` };
  }
  // Fail CLOSED on anything that is not exactly the plan tier: an
  // unvalidated run value must never fall into the more permissive branch
  // and report success for a failing full gate. Unreachable through
  // validateActionInputs — which is exactly why it is closed here too.
  if (run !== 'plan') {
    return { success: false, exitCode: 3, reason: `unknown run tier: ${run}` };
  }
  if (parsed && typeof parsed.planStatus === 'string') {
    return { success: true, exitCode: 0, reason: `plan captured (planStatus=${parsed.planStatus})` };
  }
  return {
    success: false,
    exitCode: 3,
    reason: `preview produced no plan JSON (exit ${cliExitCode ?? 'null'}${parsed?.error ? `: ${parsed.error}` : ''})`,
  };
};

/**
 * Escapes one evidence-derived value for markdown a human will trust: the
 * EXACT transform of the gate renderer's safeText (pr_closeout_report.js:13)
 * — newlines collapse to a visible return mark, then every character
 * outside the safeText allowlist (letters, digits, space, dot, underscore,
 * the return mark, dash) becomes a numeric HTML entity, control bytes
 * included (an allowlist cannot miss a control byte). This replaced a
 * partial denylist in review: strikethrough tildes, tilde code fences, and
 * GFM autolinked URLs all rendered active through it while its comment
 * claimed safeText parity. Accepted residuals, identical to the gate's own
 * reports: the allowlisted underscore, dot, and dash keep their rare
 * markdown meanings and a bare www.-prefixed word can still autolink —
 * escaping dots would destroy every path and digest in the output. The
 * gate-rendered report.md is embedded verbatim elsewhere and never
 * re-escaped.
 * @param {unknown} value
 * @returns {string}
 */
const escapeActionText = (value) => String(value ?? '')
  .replace(/\r\n?|\n/g, ' \u23CE ')
  .replace(/[^A-Za-z0-9 ._\u23CE-]/gu, (character) => `&#${character.codePointAt(0)};`);

// Step Summary hard limit is 1 MiB; the spec caps the embedded report at
// 512 KiB so the summary chrome around it can never push past the limit.
const SUMMARY_EMBED_CAP_BYTES = 512 * 1024;
const COMMENT_CAP_BYTES = 60 * 1024;

/**
 * Byte-length cap with an in-band truncation notice pointing at the evidence
 * artifact — silent truncation would read as "that was everything".
 * @param {string} text
 * @param {number} maxBytes
 * @param {string} artifactName
 * @returns {{text: string, truncated: boolean}}
 */
const capText = (text, maxBytes, artifactName) => {
  const value = String(text ?? '');
  if (Buffer.byteLength(value, 'utf8') <= maxBytes) return { text: value, truncated: false };
  // The notice fits INSIDE the budget: content is clipped to what remains
  // after it, so the returned text never exceeds maxBytes whenever the
  // notice itself fits inside it — which both configured caps guarantee by
  // orders of magnitude; a degenerate cap smaller than the notice ships the
  // notice alone (a truncated truncation notice would be worse). Task 3
  // feeds this straight into GitHub's hard 65536-character comment limit
  // and an over-budget comment is rejected outright at exactly the moment
  // the operator most needs it (review decision, Task 2 round). The
  // artifact name is escaped here for the same reason it is escaped in the
  // full summary: one value, one rendering, in every surface.
  const notice = `\n\n---\n\n**Output truncated at ${maxBytes} bytes.** The complete evidence is in the \`${escapeActionText(artifactName)}\` artifact.\n`;
  const budget = Math.max(0, maxBytes - Buffer.byteLength(notice, 'utf8'));
  const clipped = Buffer.from(value, 'utf8').subarray(0, budget).toString('utf8');
  // Drop a possibly-split trailing code point (replacement char from a cut
  // multibyte sequence) rather than shipping mojibake.
  const clean = clipped.endsWith('\uFFFD') ? clipped.slice(0, -1) : clipped;
  return { text: `${clean}${notice}`, truncated: true };
};

const ATTESTATION_LABELS = new Map([
  ['present', 'present — a mode-matched attestation covers this exact snapshot'],
  ['weakened', '\u26A0 weakened — an attestation for this snapshot records a WEAKENED decision'],
  ['absent', 'absent — no matching approving review yet (normal before review)'],
  ['unavailable', 'unavailable — the attestation lookup itself could not complete'],
]);

/**
 * Renders the plan-preview Step Summary: mode/planStatus/digest header, the
 * resolved base ref, the four-state admission table (weakened is visually
 * distinct — it must never read like absent), preflight detail rows, plan
 * errors, and the check id list. Every gate-sourced string passes through
 * escapeActionText; job color stays green for honest not-ready states, so
 * this rendering IS the preview's signal.
 * @param {object} plan the captured plan JSON.
 * @param {{baseRef?: string|null}} [context]
 * @returns {string}
 */
const renderPlanSummary = (plan, { baseRef = null, artifactName = 'plan.json' } = {}) => {
  // Null-tolerant: the renderers must never be the crash site when a caller
  // hands them a missing record (review decision, Task 2 round) — the
  // failure story belongs to decideExit, not a TypeError in a summary step.
  const record = plan || {};
  const admission = record.admission || {};
  const attestation = admission.attestation || {};
  const label = ATTESTATION_LABELS.get(attestation.status) || `unknown state: ${escapeActionText(attestation.status)}`;
  const lines = [
    '## Closeout plan preview',
    '',
    `- Mode: ${escapeActionText(record.mode || 'strict')}`,
    `- planStatus: **${escapeActionText(record.planStatus || 'unknown')}**`,
    `- Configuration digest: ${escapeActionText(record.configDigest || 'unresolved')}`,
    `- Base ref: ${escapeActionText(baseRef || 'from config')}`,
    '',
    '### Admission readiness',
    '',
    '| Probe | Status | Evidence |',
    '|---|---|---|',
    `| attestation | ${label.split(' — ')[0]} | ${escapeActionText(attestation.evidence || label)} |`,
    `| clean tree | ${escapeActionText(admission.cleanTree?.status || 'unknown')} | ${escapeActionText(admission.cleanTree?.evidence || '')} |`,
    `| preflight | ${escapeActionText(admission.preflight?.status || 'unknown')} | ${escapeActionText(admission.preflight?.evidence || '')} |`,
  ];
  lines.push('', `- Attestation detail: ${label}`);
  const preflightChecks = Array.isArray(admission.preflight?.checks) ? admission.preflight.checks : [];
  const failingProbes = preflightChecks.filter((entry) => entry.status !== 'PASS');
  for (const check of failingProbes.slice(0, 20)) {
    lines.push(`- preflight ${escapeActionText(check.name)}: ${escapeActionText(check.status)} — ${escapeActionText(check.evidence || '')}`);
  }
  // Row caps are ANNOUNCED, never silent (review decision, Task 2 round):
  // a clipped error list read as complete makes the operator conclude the
  // gate invents new errors on the next push.
  if (failingProbes.length > 20) {
    lines.push(`- …and ${failingProbes.length - 20} more non-PASS preflight probes (full detail in the artifact).`);
  }
  const errors = Array.isArray(record.errors) ? record.errors : [];
  if (errors.length > 0) {
    lines.push('', '### Plan errors', '');
    for (const error of errors.slice(0, 50)) lines.push(`- ${escapeActionText(error)}`);
    if (errors.length > 50) {
      lines.push(`- …and ${errors.length - 50} more (full list in the plan JSON in the artifact).`);
    }
  }
  const checks = Array.isArray(record.checks) ? record.checks : [];
  lines.push('', `### Resolved checks (${checks.length})`, '');
  lines.push(checks.slice(0, 50).map((check) => escapeActionText(check.id)).join(', ') || '(none)');
  lines.push('');
  // Apply a total byte cap with an in-band artifact pointer, mirroring
  // renderFullSummary's SUMMARY_EMBED_CAP_BYTES discipline (CodeRabbit #6XsD7q).
  // Row caps above are per-section; a PR-controlled engine config can still
  // produce a single error string that expands to more than 1 MiB through
  // escapeActionText, exceeding GitHub's 1 MiB Step Summary limit and
  // preventing the preview's primary readiness signal from being uploaded.
  // The full plan is always in the plan.json artifact, so truncation is
  // lossless from the operator's perspective.
  return capText(lines.join('\n'), SUMMARY_EMBED_CAP_BYTES, artifactName).text;
};

/**
 * Renders the full-run Step Summary: key fields from report.json, then the
 * gate-written report.md embedded VERBATIM below a divider (it already went
 * through the gate's own safeText pipeline — re-escaping would corrupt it),
 * capped at SUMMARY_EMBED_CAP_BYTES with an in-band truncation notice.
 * @param {object} report parsed report.json (only top-level fields read).
 * @param {string} reportMarkdown gate-written report.md content.
 * @param {{artifactName: string}} options
 * @returns {string}
 */
const renderFullSummary = (report, reportMarkdown, { artifactName }) => {
  const record = report || {};
  const embed = capText(reportMarkdown, SUMMARY_EMBED_CAP_BYTES, artifactName);
  return [
    '## Closeout gate result',
    '',
    `- Overall status: **${escapeActionText(record.overallStatus || 'unknown')}**`,
    `- Mode: ${escapeActionText(record.mode || 'strict')}`,
    `- Configuration digest: ${escapeActionText(record.configDigest || 'unresolved')}`,
    `- Evidence artifact: \`${escapeActionText(artifactName)}\``,
    '',
    '---',
    '',
    embed.text,
  ].join('\n');
};

// First line of every action-authored PR comment; the upsert finds and
// replaces the comment whose body starts with this exact marker. Stable
// across releases — changing it would orphan old comments.
const ACTION_MARKER = '<!-- closeout-action-preview -->';

/**
 * PR context from env + event payload: both GITHUB_REPOSITORY (owner/repo)
 * and a pull_request.number must be present, else null — the comment step
 * skips with a notice outside PR context, never guesses.
 * @param {{env: object, event: object}} options
 * @returns {{owner: string, repo: string, prNumber: number}|null}
 */
const readPrContext = ({ env = {}, event = {} } = {}) => {
  const repository = env.GITHUB_REPOSITORY || '';
  const [owner, repo, ...rest] = repository.split('/');
  // workflow_run events carry no top-level pull_request; a same-repo PR's
  // number instead lives at workflow_run.pull_requests[] (empty for a fork
  // PR — not populated there). Mirrors the same fallback, and the same
  // fail-closed exactly-one-entry rule, already applied in
  // readActionsPrNumber (CodeRabbit PR7 #6YZkn9) — without this, a
  // workflow_run-triggered run with pr-comment enabled silently skips its
  // comment instead of updating it (chatgpt-codex-connector PR7 #6YZpdA).
  const workflowRunPrs = event?.workflow_run?.pull_requests;
  const prNumber = event?.pull_request?.number
    ?? (Array.isArray(workflowRunPrs) && workflowRunPrs.length === 1 ? workflowRunPrs[0]?.number : undefined);
  // PR numbers are >= 1; zero/negative would target issues/0 — fail closed.
  if (!owner || !repo || rest.length > 0 || !Number.isInteger(prNumber) || prNumber < 1) return null;
  return { owner, repo, prNumber };
};

/**
 * Comment body = marker line + the tier's rendered summary, capped at the
 * spec's 60 KiB comment limit with the in-band truncation notice. Full runs
 * pass the key-fields rendering, never the embedded report.md.
 * @param {{tier: string, rendered: string, artifactName: string}} options
 * @returns {string}
 */
const buildCommentBody = ({ rendered, artifactName }) => {
  const capped = capText(rendered, COMMENT_CAP_BYTES, artifactName);
  // The 33-byte marker line rides outside the cap. Safe: UTF-8 byte count
  // >= UTF-16 unit count always, so 61440+33 bytes bounds the comment at
  // ~4000 units under GitHub's 65536-CHARACTER limit.
  return `${ACTION_MARKER}\n${capped.text}`;
};

/**
 * Upserts the action's PR comment via the injectable gh seam. The list call
 * walks EVERY page (`--paginate`; the issue-comments API returns
 * oldest-first with a 30-per-page default, so the action's newest comment
 * is exactly what a first-page-only read would miss — every later run
 * would then POST a duplicate on precisely the busiest PRs) and `--slurp`
 * folds the pages into one parseable JSON array of page arrays (gh >= 2.31;
 * GitHub-hosted runners ship newer). The PATCH target must carry the marker
 * AND be authored by the workflow token's own bot identity: the marker is
 * an invisible HTML comment anyone can post or innocently copy-paste, and
 * without the author check a drive-by comment posted before the action's
 * first run either gets silently overwritten under the attacker's name or
 * fails the step forever (review decision, Task 3 round).
 * @param {{context: {owner, repo, prNumber}, body: string, runGh: Function}} options
 * @returns {Promise<void>}
 */
const upsertPrComment = async ({ context, body, runGh }) => {
  const { owner, repo, prNumber } = context;
  const listed = await runGh(['api', '--paginate', '--slurp', `repos/${owner}/${repo}/issues/${prNumber}/comments`]);
  const comments = Array.isArray(listed) ? listed.flat() : [];
  // The exact-login pin is valid ONLY while action.yml hardcodes
  // GH_TOKEN to github.token. Adding a `token` input (e.g. for App tokens
  // that author as `my-app[bot]`) without revisiting this check would make
  // every run miss its own comment and POST an unbounded duplicate stream.
  // Select the NEWEST matching marker comment by id: the issue-comments API
  // returns oldest-first, so Array.find would PATCH the oldest and leave
  // newer duplicates stale (from rerun races, prior duplication, or a
  // drive-by marker comment). GitHub comment ids are globally monotonic, so
  // the largest id is the newest regardless of page order after flattening.
  const mine = comments
    .filter((comment) => typeof comment?.body === 'string'
      && comment.body.startsWith(ACTION_MARKER)
      && comment.user?.type === 'Bot'
      && comment.user?.login === 'github-actions[bot]')
    .reduce(
      (newest, comment) => (newest === null || Number(comment.id) > Number(newest.id) ? comment : newest),
      null,
    );
  if (mine) {
    await runGh(['api', '--method', 'PATCH', `repos/${owner}/${repo}/issues/comments/${mine.id}`, '-f', `body=${body}`]);
    return;
  }
  await runGh(['api', '--method', 'POST', `repos/${owner}/${repo}/issues/${prNumber}/comments`, '-f', `body=${body}`]);
};

// NOTE: the real runGh (Task 4) owns JSON parsing; these functions only ever
// see parsed values.

const GATE_CLI = path.join(__dirname, '..', '..', 'scripts', 'pr_closeout.js');
const STATE_FILE = 'action-state.json';

/**
 * Sanitizes one output value to a single line (newlines/CR collapse to a
 * space) and appends plain name=value lines to the GITHUB_OUTPUT file — no
 * multiline heredoc form, so there is no delimiter-collision surface.
 * @param {string} outputFile
 * @param {Record<string, unknown>} pairs
 */
const writeOutputs = (outputFile, pairs) => {
  const lines = Object.entries(pairs)
    .map(([name, value]) => `${name}=${String(value ?? '').replace(/\r?\n|\r/g, ' ')}`)
    .join('\n');
  appendFileSync(outputFile, `${lines}\n`);
};

const readEventPayload = (env) => {
  if (!env.GITHUB_EVENT_PATH) return {};
  try {
    return JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, 'utf8'));
  } catch {
    return {};
  }
};

const defaultSpawnCli = (args, { env }) => spawnSync(process.execPath, [GATE_CLI, ...args], {
  encoding: 'utf8',
  env,
  maxBuffer: 64 * 1024 * 1024,
});

/**
 * The `run` step: validates inputs, resolves the base ref, spawns the gate
 * CLI, captures its one JSON line, renders the tier's Step Summary, writes
 * the action outputs, and records the exit decision in the state file for
 * `finish`. Returns 0 for every GATE outcome — the job's failure is applied
 * by `finish` AFTER the artifact upload and optional comment steps have run.
 * Only input-validation errors throw out of here (fail before spawning).
 * @returns {Promise<number>} process exit code for this step.
 */
const runSubcommand = async ({
  inputs, inputBaseRef = '', config = '', outputDir, artifactName,
  env = process.env, event = null, spawnCli = defaultSpawnCli, nonce = randomUUID(),
}) => {
  // Bind this invocation's eventual finish verdict to THIS run, not whatever
  // action-state.json happens to contain when finish reads it (CodeRabbit
  // #6YW9UL): when a plan and full invocation share an output-dir (already a
  // documented limitation — the composite cannot compute a unique per-step
  // default path) and overlap, the plan's decision is intentionally recorded
  // with success:true even for a non-PASS planStatus (a preview must never
  // fail its own job). If the plan overwrites action-state.json after the
  // full run recorded a FAILING decision but before the full invocation's
  // "finish" step reads it, finish would apply the plan's success — the
  // enforcing full job could go green on a gate that actually failed. The
  // nonce is exported via GITHUB_ENV (persists to later steps in the SAME
  // job only — a different job's parallel invocation never sees it, and a
  // later invocation in the SAME job overwrites it before its own finish
  // step runs) and written into the state file; finish rejects a state
  // record whose nonce does not match its own job's current value.
  if (env.GITHUB_ENV) writeOutputs(env.GITHUB_ENV, { CLOSEOUT_INVOCATION_NONCE: nonce });
  // Stale-state cleanup must run BEFORE input validation (CodeRabbit #6XsD7s):
  // if an allowed pre-existing external output-dir carries action-state.json
  // from a PRIOR run and the current `run`/`mode`/`pr-comment` value is
  // invalid, validateActionInputs would throw below and the composite's
  // always() artifact/comment/finish steps would read the STALE state and
  // announce the previous PASS. Clearing first guarantees a failed run step
  // cannot leave a previous PASS state in place for the comment step to post.
  //
  // The output-directory containment check still runs FIRST of all: an inside-
  // workspace output-dir must fail without touching the checkout, not delete a
  // tracked action-state.json first.
  assertOutputOutsideWorkspace({ outputDir, workspace: env.GITHUB_WORKSPACE });
  // Only the benign "no previous state" (ENOENT) case is ignored: any other
  // unlink failure (EACCES/EPERM, or the path being a directory/symlink the
  // safety checks did not catch) must FAIL the run step rather than silently
  // leave the old state in place for the comment step to post (Qodo #13).
  //
  // action-state.json alone is not enough when output-dir is REUSED across
  // invocations (CodeRabbit #6YT0KA): if THIS invocation fails before
  // regenerating its own evidence — e.g. a plan run returns no parseable
  // JSON, so plan.json below is never rewritten — a prior invocation's
  // plan.json / report.json / report.md (the full tier's files, written by
  // the spawned CLI) stay on disk and the composite's unconditional artifact
  // upload publishes them alongside the new failure state, presenting stale
  // results as current evidence for a run that never produced them. Clear
  // every known evidence filename up front, same ENOENT-only discipline.
  //
  // Snapshot whether this directory shows real evidence of a prior
  // invocation of THIS action, BEFORE the loop below deletes any of these
  // filenames (CodeRabbit PR7 #6YYcNT / chatgpt-codex-connector PR7
  // #6YZpcz): a caller-supplied broad output-dir (e.g. /tmp,
  // ${{ runner.temp }}) may have never hosted this action, and "plan.json"
  // / "report.json" are generic enough names that an unrelated tool could
  // plausibly also drop a file by either name — mere filename presence is
  // not proof of ownership for those two. action-state.json is different:
  // it is written ONLY by this action (never by the spawned gate CLI
  // itself, unlike plan.json/report.json/report.md), with a shape no other
  // tool would coincidentally produce. Require it to both exist AND parse
  // as that authenticated shape (a known `tier` value plus a `nonce`
  // string) before trusting this directory as this action's own.
  const hadPriorEvidence = (() => {
    let state;
    try {
      state = JSON.parse(readFileSync(path.join(outputDir, STATE_FILE), 'utf8'));
    } catch (error) {
      if (error?.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error;
      return false;
    }
    return Boolean(state) && typeof state === 'object' && RUN_VALUES.has(state.tier) && typeof state.nonce === 'string' && state.nonce !== '';
  })();
  // The file-loop cleanup itself is now ALSO gated on hadPriorEvidence
  // (chatgpt-codex-connector PR7 #6YaIal): it previously ran unconditionally
  // — the round-9 ownership-marker fix (#6YYcNT) only gated the logs/ purge
  // below, leaving the SAME "unrelated tool's same-named file gets deleted"
  // risk this snapshot exists to rule out. Every scenario the loop was
  // originally built for (CodeRabbit #6YT0KA: a REUSED output-dir where a
  // prior invocation of THIS action left stale plan.json/report.json/
  // report.md) already implies a genuine prior action-state.json, so
  // gating here does not narrow that case at all — it only stops deleting
  // when there is no real evidence this directory is this action's own.
  if (hadPriorEvidence) {
    for (const staleName of [STATE_FILE, 'plan.json', 'report.json', 'report.md']) {
      try {
        unlinkSync(path.join(outputDir, staleName));
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
    }
  }
  // The gate CLI's full tier also populates outputDir/logs (a DIRECTORY of
  // per-check probe log files, scripts/pr_closeout_process.js), which the
  // file-by-file cleanup above cannot reach. If this invocation is blocked
  // before the CLI regenerates its own logs, a prior invocation's stale log
  // files stay behind and the composite's unconditional artifact upload
  // presents them as evidence for the new, unrelated run (CodeRabbit
  // #6YXkRN). Same ENOENT-only-swallow discipline as the loop above. Gated
  // on hadPriorEvidence (see above, CodeRabbit PR7 #6YYcNT): this directory
  // must already show signs of a prior invocation of THIS action before its
  // logs/ subdirectory is treated as stale evidence rather than unrelated
  // caller content.
  //
  // lstat FIRST, never trust a recursive remove to be symlink-safe on its
  // own: if a check plants outputDir/logs as a symlink to an unrelated
  // directory, unlink only the link entry (mirrors writeEvidenceFile's
  // symlink discipline elsewhere in this file) — a recursive rm must only
  // ever run against a confirmed real, non-symlinked directory.
  try {
    const logsPath = path.join(outputDir, 'logs');
    const logsInfo = lstatSync(logsPath);
    if (!hadPriorEvidence) {
      // logs/ exists but nothing else here looks like this action's own
      // output — do not touch a directory we have no ownership signal over.
    } else if (logsInfo.isDirectory()) {
      rmSync(logsPath, { recursive: true });
    } else {
      unlinkSync(logsPath);
    }
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  const { run, mode } = validateActionInputs(inputs);
  const eventPayload = event ?? readEventPayload(env);
  const baseRef = resolveBaseRef({ inputBaseRef, env, event: eventPayload });
  // Owner-only mode (0o700) matches the gate CLI's prepareOutputDirectory
  // discipline: the evidence dir can hold unredacted runner paths / base refs
  // before the CLI's own redaction runs, and on a multi-user self-hosted
  // runner the default umask (typically 0755) would expose them.
  //
  // FIX (Qodo #6): mkdirSync's `mode` only applies when the directory is
  // CREATED — a pre-existing permissive outputDir would keep its old mode.
  // FIX (CodeRabbit #6X72Z2): fail closed on POSIX when chmod is ineffective.
  //
  // FIX (CodeRabbit #6YFOVK): chmodding a caller-supplied PRE-EXISTING broad
  // directory (e.g. /tmp, runner.temp) mutates a directory this invocation
  // may not own and can break later steps on a self-hosted runner. When the
  // directory pre-existed, capture its original mode and RESTORE it in the
  // finally block below once the CLI has taken over (the CLI re-applies its
  // own owner-only perms to the files it writes). This keeps the Qodo #6
  // owner-only guarantee during the window the wrapper writes, without
  // permanently changing a caller-owned directory's mode.
  // Capture the FULL mode including special bits (sticky/setgid/setuid) so
  // restore is faithful: a caller-supplied /tmp (01777) must be restored to
  // 01777, not 0777 (CodeRabbit #6YTfjs). Mask 0o7777, not 0o777.
  //
  // Use statSync (follows symlinks), NOT lstatSync, so a symlinked outputDir
  // captures the TARGET directory's real mode. lstatSync would capture the
  // symlink's OWN mode instead — typically 0777, since most platforms ignore
  // permission bits on the link itself — and both chmodSync calls below
  // follow the link to the target. Restoring a 0700 target to a captured
  // 0777 would broaden it, exposing or making writable whatever else lives
  // there (CodeRabbit #6YT0Js).
  const priorMode = (() => { try { return statSync(outputDir).mode & 0o7777; } catch { return null; } })();
 const restorePriorMode = () => {
   if (priorMode === null || process.platform === 'win32') return;
   try { chmodSync(outputDir, priorMode); } catch { /* best-effort restore */ }
 };
 mkdirSync(outputDir, { recursive: true, mode: 0o700 });
  if (process.platform !== 'win32') {
    try {
      chmodSync(outputDir, 0o700);
    } catch (error) {
      throw new Error(`failed to secure evidence directory ${outputDir} (mode 0o700): ${error.message}`);
    }
  } else {
    try {
      chmodSync(outputDir, 0o700);
    } catch {
      // Windows ignores POSIX directory modes; the failure carries no signal.
    }
  }
  const args = ['--repo', env.GITHUB_WORKSPACE || process.cwd(), '--mode', mode, '--output-dir', outputDir];
  if (baseRef) args.push('--base-ref', baseRef);
  if (config) args.push('--config', config);
  if (run === 'plan') args.push('--plan');
  // Restore the caller-owned directory's original mode only AFTER every write
  // to it has finished, not before handing off to the CLI (CodeRabbit
  // #6YT0Jo). The spawned CLI itself re-chmods the directory to 0o700 while
  // writing evidence (writeEvidenceReport, scripts/pr_closeout_report.js),
  // and the wrapper's OWN writes below (plan.json, action-state.json) all
  // happen AFTER spawnCli returns — restoring before spawnCli left the
  // directory at the CLI's 0o700 rather than the caller's original mode once
  // the full run actually finished. The try/finally covers every exit path,
  // including a thrown error.
  try {
  const result = spawnCli(args, { env });
  const cliExitCode = result.status;
  const parsed = parseLastJsonLine(result.stdout);
  let decision = decideExit({ run, cliExitCode, parsed });
  // A real spawn failure (ENOENT, maxBuffer) must be named, not reported as
  // a generic missing-JSON — the operator cannot diagnose "no plan JSON"
  // when the actual cause is a missing CLI (review, Task 4 round 2).
  const spawnNote = result.error ? ` Spawn error: ${result.error.message}.` : '';

  let renderedSummary;
  let renderedComment = '';
  let reportJsonPath = '';
  let reportMode = '';
  let attestation = '';
  let status = '';
  if (run === 'plan') {
    if (parsed && typeof parsed.planStatus === 'string') {
      renderedSummary = renderPlanSummary(parsed, { baseRef, artifactName });
      // Plan comments equal the plan summary: gate-redacted content only.
      renderedComment = renderedSummary;
      status = parsed.planStatus;
      reportMode = parsed.mode || '';
      attestation = parsed.admission?.attestation?.status || '';
      const planPath = path.join(outputDir, 'plan.json');
      writeEvidenceFile(outputDir, 'plan.json', `${JSON.stringify(parsed)}\n`);
      reportJsonPath = planPath;
    } else {
      renderedSummary = [
        '## Closeout plan preview',
        '',
        `**The preview itself failed** — ${escapeActionText(redactSecrets(decision.reason + spawnNote))}`,
        '',
        `stderr: ${escapeActionText(redactSecrets(String(result.stderr || '').slice(0, 4000)))}`,
        '',
      ].join('\n');
      // Gate error text (raw stderr; parsed.error inside decision.reason)
      // is NOT redacted by the CLI's top-level catch — its audience was a
      // terminal. It stays on run-log-equivalent surfaces (Step Summary,
      // artifact) but credential-shaped values in it are REDACTED by
      // redactSecrets above so a token echoed by a git remote URL or gh
      // Authorization header cannot leak. The COMMENT is permanent and
      // notifies every subscriber, so it carries a fixed-shape pointer only
      // (review decision, Task 4 round 2).
      renderedComment = [
        '## Closeout plan preview',
        '',
        '**The preview itself failed.** See the workflow Step Summary and run log for detail.',
        '',
      ].join('\n');
      status = 'BLOCKED';
    }
  } else {
    let report = {};
    let reportMarkdown = '';
    let reportUnreadable = false;
    if (parsed?.report?.json) {
      reportJsonPath = path.isAbsolute(parsed.report.json) ? parsed.report.json : path.join(outputDir, parsed.report.json);
      try {
        report = JSON.parse(readFileSync(reportJsonPath, 'utf8'));
        // A record that parses but is not a gate report (e.g. `{}`) is not
        // valid evidence — the success record claimed a report was written, so
        // a missing overallStatus means the report is schema-invalid.
        if (!report || typeof report !== 'object' || Array.isArray(report)
          || typeof report.overallStatus !== 'string') {
          report = {}; reportUnreadable = true;
        }
      } catch { report = {}; reportUnreadable = true; }
      const markdownPath = path.isAbsolute(parsed.report.markdown || '') ? parsed.report.markdown : path.join(outputDir, parsed.report.markdown || 'report.md');
      try { reportMarkdown = readFileSync(markdownPath, 'utf8'); } catch { reportMarkdown = '(report.md could not be read)'; }
    } else {
      // A full-tier success record that omits the report.json path entirely is
      // not valid evidence — the gate always writes a report on a real run, so
      // its absence means the record is incomplete or hostile.
      reportUnreadable = true;
    }
    status = report.overallStatus || parsed?.status || 'BLOCKED';
    // Integrity guard: a full tier that exited 0 (claimed success) but whose
    // report.json is missing, malformed, or schema-invalid (no overallStatus)
    // cannot be trusted. Fail the decision closed AND force the status output
    // to BLOCKED — otherwise status could read PASS (from parsed.status) while
    // finish fails the job, so the Step Summary/output and the exit code would
    // disagree. Mirrors decideExit's "exit 0 with no parseable record" guard.
    if (reportUnreadable) {
      if (decision.success) {
        decision = { success: false, exitCode: 3, reason: 'gate reported success but report.json was missing, malformed, or schema-invalid' };
      }
      status = 'BLOCKED';
    } else if (decision.success && status !== 'PASS') {
      // Integrity guard: the CLI exited 0 (success) but the readable report
      // says FAIL or BLOCKED — the exit code and the report disagree. This can
      // happen if a shared output-dir is reused and a second invocation
      // overwrites the report after the first CLI releases its lock. Fail the
      // decision closed so finish does not propagate exit 0 against a FAIL
      // report.
      decision = { success: false, exitCode: 3, reason: `gate exited 0 but report overallStatus is ${status}` };
    } else if (!decision.success && status === 'PASS') {
      // Integrity guard (inverse): the CLI exited non-zero (failure) but the
      // readable report says PASS — the exit code and the report disagree in
      // the opposite direction. This can happen if two invocations reuse an
      // explicit output directory: the first (failed, exit 2) reads the second
      // invocation's PASS report after it overwrites report.json, then
      // publishes status=PASS and renders a PASS summary even though finish
      // fails the job. Force the surfaced status to BLOCKED so the Step
      // Summary/output cannot announce PASS against a failing exit code
      // (CodeRabbit #6YE6QC).
      status = 'BLOCKED';
      decision = { success: false, exitCode: decision.exitCode || 3, reason: `gate exited ${decision.exitCode} but report overallStatus is PASS — integrity mismatch forced to BLOCKED` };
    }
    reportMode = report.mode || '';
    // The report is the source of truth for the tier label when readable;
    // when it is NOT, the action still knows the tier it INVOKED — an
    // engine run must never be labeled strict by the renderer's fallback
    // (review decision, Task 4 round 2; same rule as sub-project A's
    // matrixSource tell). The machine `mode` output stays report-sourced:
    // empty-when-unknown is honest for consumers keying on it.
    const labelMode = report.mode || mode;
    renderedSummary = renderFullSummary(
      { overallStatus: status, mode: labelMode, configDigest: report.configDigest },
      reportMarkdown || `(no report was written; CLI said: ${redactSecrets(parsed?.error || 'nothing')}${redactSecrets(spawnNote)})`,
      { artifactName },
    );
    // Full-tier COMMENTS never carry the embedded report.md (spec): key
    // fields plus a pointer only — the full report lives in the Step
    // Summary and the artifact. The pointer line is a fixed literal so no
    // operator input rides in it unescaped, and no gate error text ever
    // reaches a comment.
    renderedComment = renderFullSummary(
      { overallStatus: status, mode: labelMode, configDigest: report.configDigest },
      'See report.md in the evidence artifact named above.',
      { artifactName },
    );
  }

  if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `${renderedSummary}\n`);
  if (env.GITHUB_OUTPUT) {
    // Aggregate admission status (CodeRabbit #6X_pwM): planStatus can read PASS
    // (the engine matrix resolved) while admission is actually blocked (missing
    // required tool, preflight failure, dirty tree). Compute a dedicated output
    // so consumers can distinguish matrix-resolution PASS from fully-admissible
    // PASS without parsing the Step Summary. The aggregate is the WORST of the
    // admission sub-probes; if any is non-PASS the aggregate mirrors it.
    // Every probe key is REQUIRED once `admission` is present at all — a
    // record silently missing cleanTree/preflight (a malformed or truncated
    // CLI report) must not just vanish from the reduction. The prior
    // `.filter(probe => probe && ...)` dropped absent/malformed probes before
    // aggregating, so a record containing only `attestation: {status:
    // "present"}` made `every(probePasses)` vacuously true over a
    // single-element array and published PASS despite cleanTree/preflight
    // never having run (chatgpt-codex-connector PR7 #6YaxWb). Mapping every
    // required key — substituting a non-passing, non-failing 'missing'
    // placeholder status for anything absent or malformed — keeps the
    // reduction below fail-closed: 'missing' satisfies neither probePasses
    // nor probeFails, so it forces the aggregate to BLOCKED rather than
    // letting the incomplete record dodge the check entirely.
    const ADMISSION_PROBE_KEYS = ['attestation', 'cleanTree', 'preflight'];
    const admissionProbes = parsed?.admission
      ? ADMISSION_PROBE_KEYS.map((key) => {
        const probe = parsed.admission[key];
        return (probe && typeof probe.status === 'string') ? probe : { status: 'missing' };
      })
      : [];
    // resolvePlanAdmission (scripts/pr_closeout_workflow.js) uses a DIFFERENT
    // status vocabulary for the attestation probe (present | weakened | absent
    // | unavailable) than cleanTree/preflight (PASS | FAIL | BLOCKED) — 'PASS'
    // never appears for attestation, so requiring every probe to literally
    // equal 'PASS' meant a fully-ready plan (attestation present, tree clean,
    // preflight passing) could never aggregate to PASS; it always fell to
    // BLOCKED (CodeRabbit #6YT0J4). Map the passing/failing attestation
    // states onto the PASS/FAIL vocabulary before reducing.
    const probePasses = (probe) => probe.status === 'PASS' || probe.status === 'present';
    const probeFails = (probe) => probe.status === 'FAIL' || probe.status === 'weakened';
    const admissionStatus = admissionProbes.length
      ? admissionProbes.every(probePasses) ? 'PASS' : admissionProbes.some(probeFails) ? 'FAIL' : 'BLOCKED'
      : (run === 'plan' ? 'unavailable' : '');
    writeOutputs(env.GITHUB_OUTPUT, {
      status, mode: reportMode, attestation, 'report-path': reportJsonPath,
      ...(admissionStatus ? { 'admission-status': admissionStatus } : {}),
    });
  }
  writeEvidenceFile(outputDir, STATE_FILE, `${JSON.stringify({
    tier: run, mode: reportMode, baseRef, cliExitCode, decision, artifactName, renderedSummary, renderedComment, reportJsonPath, nonce,
  })}\n`);
  process.stdout.write(`closeout-action: ${redactSecrets(decision.reason)}\n`);
  return 0;
  } finally {
    restorePriorMode();
  }
};

/**
 * Writes a file in the evidence dir without ever following an existing symlink
 * at the destination. A repository-defined check that predicts the output dir
 * could plant action-state.json (or plan.json) as a symlink to a tracked
 * workspace file; a plain writeFileSync would follow it and overwrite the
 * workspace file. lstat first: if the destination exists as a symlink (or
 * anything that is not a regular file), unlink it — unlinking removes the link
 * itself, never the target. The fresh write then creates a regular file. The
 * output dir is owner-only (0o700), so nothing else can re-plant the link in
 * the unlink/write window.
 * @param {string} outputDir
 * @param {string} name - file name inside the evidence dir
 * @param {string} content
 */
const writeEvidenceFile = (outputDir, name, content) => {
  const target = path.join(outputDir, name);
  // A hard link (nlink > 1) to a tracked workspace file reports as a regular
  // file but shares an inode — a write through it would mutate the workspace
  // file after the CLI's final seal. Replace it (unlinking removes THIS
  // directory entry, not the linked target) so the fresh write creates a new
  // inode owned only by the evidence dir.
  //
  // The catch is scoped to ENOENT ONLY: lstatSync throws ENOENT when nothing
  // exists at the destination (the normal case — the write creates it fresh).
  // If an unsafe entry IS present, lstatSync succeeds and the conditional
  // unlinkSync runs; an unlink FAILURE here (EPERM/EACCES/EBUSY, or the entry
  // being a directory) must NOT be swallowed, because the code would then
  // fall through to writeFileSync(target) and write THROUGH the still-linked
  // target — exactly the workspace mutation this function exists to prevent.
  // Any non-ENOENT error propagates and fails the run step fail-closed.
  let info;
  try {
    info = lstatSync(target);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    info = null;
  }
  if (info && (info.isSymbolicLink() || !info.isFile() || info.nlink > 1)) {
    try {
      unlinkSync(target);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
  // Owner-only mode (0o600) on the evidence files themselves, so the wrapper's
  // writes are confidential regardless of the surrounding directory's mode.
  // This decouples file confidentiality from the directory-mode restore window
  // (CodeRabbit #6YTfjs): even if the caller-owned outputDir has been restored
  // to its original broader mode before this write, the file content (which can
  // hold unredacted runner paths / base refs / error text) is still owner-only.
  //
  // Open ONE descriptor and hold it through ACL setup and the content write,
  // rather than two separate path-based writeFileSync calls (chatgpt-codex-
  // connector PR7 #6YaIaZ, following writeNoFollow's identical pattern in
  // pr_closeout_report.js): protectWindowsPrivateFile is an EXTERNAL
  // PowerShell process operating on `target` BY PATH, so between it starting
  // and returning, another account on a multi-user Windows runner could
  // replace the path with a symlink or a different file. A subsequent
  // path-based write would then write THROUGH that replacement instead of
  // the file whose DACL was actually verified. Writing through the SAME fd
  // opened here — before the ACL call, established as a regular single-link
  // file by the symlink/hardlink guard above — is immune to that: even if
  // the path is later swapped, this descriptor still refers to the original
  // on-disk file. The identity recheck below is an additional fail-closed
  // net: it detects a swap during the ACL call and refuses rather than
  // leave a case where the file at the PATH other tooling would read is
  // unprotected while the KNOWN-good original silently isn't the one still
  // reachable there.
  //
  // openNoFollowSync (not a plain openSync) closes the remaining gap between
  // the lstatSync guard above and this open call: on platforms with
  // O_NOFOLLOW, the OPEN itself refuses to follow a symlink an attacker
  // replanted at `target` in that window, instead of only detecting one
  // after the fact via the identity recheck below (chatgpt-codex-connector
  // PR7 #6Yawd4). Where O_NOFOLLOW is unavailable (some Windows builds
  // report it as 0), the lstatSync guard above remains the primary defense,
  // matching openNoFollow's own documented contract for its async callers.
  //
  // requireNoFollow: true (chatgpt-codex-connector PR7 #6Yb1dD): this is a
  // destructive O_TRUNC write, so if the platform DOES claim real O_NOFOLLOW
  // support but the OS rejects every attempt that carries it, this must fail
  // closed rather than silently fall through to a fully bare, link-following
  // open — unlike a read, a truncating write cannot be undone after the fact
  // once the open succeeds. Harmless on platforms where O_NOFOLLOW is
  // entirely unavailable (e.g. Windows): the lstatSync guard above is
  // already documented as the primary defense there, unaffected by this.
  const fd = openNoFollowSync(target, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC, 0o600, true);
  try {
    const preInfo = fstatSync(fd);
    // fchmodSync's mode argument on open only applies when the OPEN call
    // CREATES the file — an ordinary pre-existing regular single-link file
    // (the guard above only unlinks a symlink/non-file/hardlink, not a plain
    // reused file) is opened with O_TRUNC and keeps whatever permissive mode
    // it already had, e.g. 0o644 from a prior invocation of a reused
    // output-dir. fchmodSync unconditionally closes that gap before
    // anything is written; it is a cheap no-op when the file was freshly
    // created at 0o600 already (CodeRabbit #6YT0Jx).
    fchmodSync(fd, 0o600);
    // chmodSync/fchmodSync(0o600) only clears Windows' read-only attribute
    // bit — it does NOT establish real access control there, so this file
    // would still inherit whatever DACL the surrounding --output-dir has on
    // a multi-user Windows runner, readable (and writable) by any other
    // local account. The gate CLI already solves exactly this for its own
    // evidence writes — report.json/report.md (pr_closeout_report.js) and
    // evidence logs (pr_closeout_process.js) — via protectWindowsPrivateFile:
    // a verified, owner-only Windows DACL, no-op on non-Windows. Apply the
    // same guard here, fail-closed on any failure to establish it, and
    // BEFORE any content is written (Codex PR7 review, "Protect wrapper
    // evidence with a Windows DACL"; chatgpt-codex-connector PR7 #6YZpcv).
    try {
      protectWindowsPrivateFile(target);
    } catch (error) {
      throw new Error(`failed to protect evidence file with an owner-only ACL: ${target}`, { cause: error });
    }
    if (process.platform === 'win32') {
      let postInfo;
      try {
        postInfo = lstatSync(target);
      } catch {
        throw new Error(`Refusing to write evidence file with an unverifiable identity: ${target}`);
      }
      if (!isSameFileIdentity(preInfo, postInfo)) {
        throw new Error(`Refusing to write evidence file through a path swapped during ACL protection: ${target}`);
      }
    }
    writeSync(fd, content, null, 'utf8');
  } finally {
    closeSync(fd);
  }
};

const readState = (outputDir) => {
  try {
    return JSON.parse(readFileSync(path.join(outputDir, STATE_FILE), 'utf8'));
  } catch {
    return null;
  }
};

/**
 * The `finish` step: applies the exit decision recorded by `run`, failing
 * the job only now — after artifact upload and the optional comment step
 * have already surfaced the evidence. Missing state fails closed.
 * @returns {number} process exit code.
 */
const finishSubcommand = ({ outputDir, env = process.env }) => {
  const state = readState(outputDir);
  if (!state?.decision) {
    process.stderr.write('closeout-action: no recorded state; the run step never completed.\n');
    return 3;
  }
  // Reject a state record that does not belong to THIS job's invocation
  // (CodeRabbit #6YW9UL): a shared output-dir can be overwritten by a
  // different (e.g. plan-tier) invocation between this job's "run" and
  // "finish" steps. GITHUB_ENV persists CLOSEOUT_INVOCATION_NONCE within this
  // job only, so only check when this job has its own nonce — but a MISSING
  // nonce on the state record is now rejected too, not just a mismatched one
  // (chatgpt-codex-connector PR7 #6YaIao): "run" exports its nonce to
  // GITHUB_ENV as its very first action, before assertOutputOutsideWorkspace
  // or input validation, so if either of those then rejects the invocation
  // and throws, THIS run never reaches its own writeEvidenceFile(STATE_FILE)
  // call — action-state.json is left exactly as it was found. A pre-existing
  // (or, for an inside-workspace output-dir, attacker-plantable) state
  // record with no nonce field — e.g. one committed to the repository at the
  // exact path an attacker points output-dir to — would previously bypass
  // this check entirely (the `state.nonce &&` short-circuited to false) and
  // could carry a fabricated `decision.success: true`, turning a genuinely
  // rejected invocation green. A state record is now trusted only when it
  // carries a nonce that EXACTLY matches this job's own.
  if (env.CLOSEOUT_INVOCATION_NONCE && state.nonce !== env.CLOSEOUT_INVOCATION_NONCE) {
    process.stderr.write('closeout-action: recorded state does not carry this invocation\'s nonce (output-dir was overwritten by a concurrent run, or never written by this run at all); refusing to trust it.\n');
    return 3;
  }
  process.stdout.write(`closeout-action: ${redactSecrets(state.decision.reason)}\n`);
  return state.decision.success ? 0 : (Number.isInteger(state.decision.exitCode) ? state.decision.exitCode : 3);
};

// Bounded timeout for gh API calls so a hung GitHub API request fails the
// comment step promptly rather than blocking the workflow until the job-level
// timeout. 60s is generous for a paginated comment list + one PATCH/POST.
const GH_TIMEOUT_MS = 60_000;

const defaultRunGh = async (args) => {
  const result = spawnSync('gh', args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, timeout: GH_TIMEOUT_MS });
  if (result.error) throw result.error;
  if (result.signal === 'SIGTERM') throw new Error(`gh timed out after ${GH_TIMEOUT_MS / 1000}s (args redacted)`);
  if (result.status !== 0) throw new Error(redactSecrets(String(result.stderr || `gh exited ${result.status}`).trim()));
  const stdout = String(result.stdout || '').trim();
  if (!stdout) return null;
  try { return JSON.parse(stdout); } catch { return stdout; }
};

/**
 * The `comment` step: upserts the marker-tagged PR comment with the tier's
 * rendered summary. Outside PR context (no repo/PR number) it prints a
 * notice and succeeds — never fails, never guesses. An API failure DOES
 * fail the step: the consumer opted into the comment and silence would be
 * a lie; summary and artifact are already written regardless.
 * @returns {Promise<number>} process exit code.
 */
const commentSubcommand = async ({ outputDir, env = process.env, event = null, runGh = defaultRunGh }) => {
  const state = readState(outputDir);
  if (!state) {
    process.stderr.write('closeout-action: no recorded state; skipping comment.\n');
    return 0;
  }
  // Same nonce check finishSubcommand applies, including the missing-nonce
  // case (CodeRabbit #6YW9UL, chatgpt-codex-connector PR7 #6YaIao): a shared
  // output-dir can be overwritten by a different (e.g. plan-tier) invocation
  // between this job's "run" and "comment" steps, or contain a pre-existing
  // record this run's own "run" step never got to overwrite. Without this
  // check here too, the comment step would upsert the PR comment with the
  // FOREIGN or stale invocation's tier/status/artifact pointer — an
  // externally visible side effect that finishSubcommand's own later nonce
  // check cannot undo after the fact (chatgpt-codex-connector PR7 #6YZpc6).
  if (env.CLOSEOUT_INVOCATION_NONCE && state.nonce !== env.CLOSEOUT_INVOCATION_NONCE) {
    process.stderr.write('closeout-action: recorded state does not carry this invocation\'s nonce (output-dir was overwritten by a concurrent run, or never written by this run at all); refusing to comment with it.\n');
    return 3;
  }
  const eventPayload = event ?? readEventPayload(env);
  const context = readPrContext({ env, event: eventPayload });
  if (!context) {
    process.stdout.write('closeout-action: not a pull-request context; comment skipped.\n');
    return 0;
  }
  const body = buildCommentBody({
    tier: state.tier,
    // renderedComment is the comment-specific rendering (full tier: key
    // fields + pointer, never the embedded report.md); the summary is only
    // a fallback for a state written by an older run step.
    rendered: state.renderedComment || state.renderedSummary || '',
    artifactName: state.artifactName || 'closeout-evidence',
  });
  await upsertPrComment({ context, body, runGh });
  process.stdout.write(`closeout-action: comment upserted on PR #${context.prNumber}.\n`);
  return 0;
};

const main = async () => {
  const [subcommand] = process.argv.slice(2);
  const env = process.env;
  const common = { outputDir: env.CLOSEOUT_OUTPUT_DIR || path.join(env.RUNNER_TEMP || os.tmpdir(), 'closeout-evidence') };
  try {
    if (subcommand === 'run') {
      process.exitCode = await runSubcommand({
        ...common,
        inputs: { run: env.CLOSEOUT_RUN || '', mode: env.CLOSEOUT_MODE || '', prComment: env.CLOSEOUT_PR_COMMENT || '' },
        inputBaseRef: env.CLOSEOUT_BASE_REF || '',
        config: env.CLOSEOUT_CONFIG || '',
        artifactName: env.CLOSEOUT_ARTIFACT_NAME || 'closeout-evidence',
      });
    } else if (subcommand === 'finish') {
      process.exitCode = finishSubcommand(common);
    } else if (subcommand === 'comment') {
      process.exitCode = await commentSubcommand(common);
    } else {
      throw new Error(`Unknown subcommand: ${subcommand ?? '(none)'}. Use run, comment, or finish.`);
    }
  } catch (error) {
    // The thrown message can carry credential-shaped values that bypassed
    // every upstream redaction point: an invalid action input (e.g. a base-ref
    // or config value a caller built from a leaked token), or an Error
    // constructed from raw child-process stderr that echoed a git remote URL
    // embedding x-access-token:SECRET. Every other surface that emits
    // untrusted/CLI-derived text already routes through redactSecrets (see
    // runSubcommand's stderr handling and upsertPrComment); this terminal
    // catch is the last place a message reaches a log before exit, so it MUST
    // redact too — otherwise a single unredacted throw undoes all of them.
    // Coerce to a string BEFORE redaction: a non-Error throw (null, undefined,
    // a bare string/number, or a thenable rejected with a non-Error) has no
    // .message, and dereferencing it would throw a TypeError INSIDE this
    // catch — bypassing the redaction and the exitCode=1, leaving the process
    // to die with an unstructured stack and a 0 exit. Fall back to String(error)
    // so the catch is total: every thrown shape reaches the redactor.
    process.stderr.write(`closeout-action: ${redactSecrets(error?.message ?? String(error))}\n`);
    process.exitCode = 1;
  }
};

if (require.main === module) void main();

module.exports = {
  ACTION_MARKER,
  assertOutputOutsideWorkspace,
  buildCommentBody,
  capText,
  commentSubcommand,
  decideExit,
  escapeActionText,
  finishSubcommand,
  parseLastJsonLine,
  readPrContext,
  renderFullSummary,
  renderPlanSummary,
  resolveBaseRef,
  runSubcommand,
  upsertPrComment,
  validateActionInputs,
  writeEvidenceFile,
  writeOutputs,
};
