'use strict';

// Support script for the closeout composite action. The action.yml is pure
// wiring; every decision lives here so it is hermetically testable. Zero
// dependencies, same repo conventions as the gate scripts it wraps. The gate
// CLI itself (scripts/pr_closeout.js) is consumed as-is, never modified.

const {
  appendFileSync, chmodSync, closeSync, constants, fchmodSync, fstatSync, lstatSync, mkdirSync,
  readFileSync, realpathSync, renameSync, rmSync, unlinkSync, writeFileSync, writeSync,
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
 * the CLI reaches it, and the wrapper itself mkdirs the evidence child under
 * outputDir (recursively creating outputDir too when absent) and writes
 * `plan.json`/`action-state.json` inside that child — so a caller that sets
 * `output-dir` to `.` or any workspace-relative path would dirty the
 * checkout and have those files uploaded as evidence. The check runs on the
 * CALLER's value: the fixed child segment cannot escape a contained parent,
 * so parent-outside implies child-outside (a symlink planted AT the child
 * name is refused separately by prepareEvidenceDirectory's lstat). Both the
 * plain resolved path and the symlink-resolved physical path are compared
 * against the workspace root, mirroring the CLI's own symlink defense; a
 * realpath failure fails closed (the path cannot be proven safe).
 *
 * Also rejects an embedded CR or LF in `outputDir` before any of that
 * (chatgpt-codex-connector PR7 #Yb3lN): this same string flows unmodified
 * into action.yml's own `Upload evidence artifact` step as
 * `actions/upload-artifact`'s `path:` input, which (via @actions/glob)
 * treats a multi-line value as SEPARATE search patterns, one per line, not
 * as one literal path. Node's fs calls (mkdirSync/writeFileSync here) have
 * no such convention — a newline is just an ordinary path-segment
 * character to them — so `output-dir: "/tmp/closeout-evidence\n."` passes
 * every check below as one literal outside-workspace path, the gate writes
 * evidence there successfully, and the step exits 0; the uploader then
 * reads the SAME string as two patterns, the second (`.`) resolving inside
 * GITHUB_WORKSPACE, and publishes the checkout (and anything earlier steps
 * left there) as if it were evidence. Verified against
 * @actions/glob's own newline-splitting `getSearchPaths`/create() contract.
 * @param {{outputDir: string, workspace?: string}} options
 */
const assertOutputOutsideWorkspace = ({ outputDir, workspace = '' }) => {
  if (/[\r\n]/.test(String(outputDir ?? ''))) {
    throw new Error(`Evidence output directory must not contain a CR or LF (upload-artifact reads a multi-line path as multiple patterns): ${JSON.stringify(outputDir)}`);
  }
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
  // Surface the exact marker a reviewer must paste into an APPROVED review
  // body (chatgpt-codex-connector PR7 #6Yb3lW, P2): the plan record always
  // carries it at gateIntegrityAttestationRequired.marker, but until now
  // this summary never printed it, so the reviewer had to separately
  // discover and download plan.json from the artifact just to get a
  // copy-pasteable string, even though the README documents the Step
  // Summary as the primary place to check attestation readiness. Rendered
  // in a fenced code block, NOT through escapeActionText: the marker's `=`
  // characters would become HTML entities under that allowlist, corrupting
  // the exact byte sequence classifyGateAttestation compares against — and
  // there is nothing here to defend against in the first place, since the
  // marker is this action's OWN fixed-template output over base/head SHAs
  // and a config digest, never free-form PR-controlled text. Shown whenever
  // a matching attestation is not already in place (absent/weakened/
  // unavailable) — a 'present' status means one already satisfies this
  // snapshot, so showing "paste this" again would be confusing noise.
  const requiredMarker = record.gateIntegrityAttestationRequired?.marker;
  if (attestation.status !== 'present' && typeof requiredMarker === 'string' && requiredMarker) {
    lines.push(
      '',
      '### Required attestation marker',
      '',
      'Paste this line verbatim into an APPROVED review body to satisfy admission:',
      '',
      '```',
      requiredMarker,
      '```',
    );
  }
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

// Name of the action-created private child directory, under the caller's
// `output-dir`, that ALL evidence lives in — both the wrapper's own files
// (plan.json, action-state.json) and everything the spawned gate CLI writes
// (report.json, report.md, logs/), because the CLI receives this child as
// its --output-dir (chatgpt-codex-connector PR7 #6Yd4Qx). The name is FIXED,
// not per-invocation: action.yml's "Upload evidence artifact" step must glob
// it with static YAML (a composite action's expressions cannot embed a
// per-invocation value — the same limitation that already prevents a unique
// output-dir default, see README), and the `comment`/`finish` subcommands run
// as SEPARATE PROCESSES that must re-derive the evidence location from
// CLOSEOUT_OUTPUT_DIR alone. Consequence, unchanged from before this child
// existed: two invocations that share an output-dir also share this child —
// the README's "distinct output-dir per invocation" requirement stands.
const EVIDENCE_SUBDIR = 'closeout-action-evidence';

/**
 * The single mapping from the caller-facing `output-dir` to the directory
 * evidence actually lives in. `run`, `comment`, and `finish` each execute as
 * a separate process receiving only CLOSEOUT_OUTPUT_DIR, so this must stay a
 * pure function of that value — no state, no filesystem probing.
 * @param {string} outputDir
 * @returns {string}
 */
const resolveEvidenceDir = (outputDir) => path.join(outputDir, EVIDENCE_SUBDIR);

/**
 * Creates and verifies the private evidence child directory under the
 * caller's `output-dir` (chatgpt-codex-connector PR7 #6Yd4Qx, P2). Evidence
 * is written HERE, never directly into the caller's directory, so a
 * PRE-EXISTING caller directory's mode is NEVER modified: no chmod, no
 * temporary narrowing — and therefore no window (previously the gate's
 * whole run, up to the configured timeout) during which a shared caller
 * directory such as /tmp (01777) or ${{ runner.temp }} is unreadable to
 * concurrent jobs, and no restore step whose failure could leave it
 * narrowed. (A caller directory that does not exist yet is CREATED
 * owner-only — see the mkdir note below — which mutates nothing anyone
 * could already be using.) This retires the
 * entire capture/restore chain that guarded the old in-place chmod —
 * #6YFOVK (restore the pre-existing mode), #6YTfjs (capture the FULL 0o7777
 * mode so /tmp's sticky bit restores faithfully), #6YT0Js (statSync, not
 * lstatSync, so a symlinked outputDir captured the TARGET's mode and the
 * restore could not broaden a 0700 target), and #6YT0Jo (restore only after
 * the final write) — deleted rather than kept as dead code: with no
 * modification there is nothing to capture or restore, and a symlinked
 * outputDir's target mode is simply never touched at all.
 *
 * The owner-only requirement itself is unchanged and now applies to the
 * child: evidence can hold unredacted runner paths and base refs before the
 * CLI's redaction runs, so on a multi-user runner the directory must not be
 * default-umask readable. mkdirSync's `mode` only applies when the directory
 * is CREATED (Qodo #6), so a pre-existing child — an output-dir reused
 * across invocations — is explicitly re-chmodded to 0o700, and on POSIX a
 * chmod failure fails closed (CodeRabbit #6X72Z2). Both invariants are the
 * same ones the old in-place code enforced, retargeted.
 *
 * Because the child's NAME is fixed and its parent may be a shared,
 * world-writable directory, the path is verified before any use — including
 * before the stale-evidence probe/cleanup in runSubcommand, which reads and
 * deletes through it: a hostile local user could pre-plant
 * `<output-dir>/closeout-action-evidence` as a symlink (redirecting every
 * later read, delete, and write to a directory of their choosing — the same
 * attack class #6Yb44Sj closed for the state file itself) or as their OWN
 * real directory (which a root runner's chmod would "secure" without
 * changing its ownership, leaving it readable by the planter). lstatSync
 * (never following a link) must see a real directory, and on POSIX it must
 * be owned by this process's own uid.
 *
 * What IS guaranteed: a pre-existing caller directory's mode is never
 * modified by this action or by the CLI it spawns (an absent one is created
 * owner-only, once, and never re-chmodded), and on POSIX the evidence directory is a
 * real, caller-uid-owned, mode-0o700 directory at the moment this returns —
 * in a sticky-bit parent (/tmp) other users cannot subsequently rename or
 * remove that entry, so the verification holds for the run. What is NOT
 * guaranteed: a world-writable NON-sticky parent lets any local user swap
 * the entry after verification (file-level defenses — writeEvidenceFile's
 * O_EXCL staging and identity re-checks, and the CLI's equivalents — still
 * apply, but directory-level trust does not survive such a parent); and on
 * Windows the child directory itself carries no verified DACL (unchanged
 * from the old in-place scheme — the chmod stays best-effort there), each
 * evidence FILE being individually protected instead
 * (protectWindowsPrivateFile in writeEvidenceFile and in the CLI).
 * @param {string} outputDir caller-facing output directory.
 * @returns {string} the verified evidence directory (resolveEvidenceDir(outputDir)).
 */
const prepareEvidenceDirectory = (outputDir) => {
  const evidenceDir = resolveEvidenceDir(outputDir);
  // recursive: also creates the caller's output-dir itself when it does not
  // exist yet (the default `${{ runner.temp }}/closeout-evidence` case).
  // Node's recursive mkdir applies `mode` to EVERY component it creates, so
  // a freshly-created output-dir starts owner-only too (umask-masked) — the
  // conservative default, and NOT a #6Yd4Qx violation: that finding is about
  // mutating a PRE-EXISTING caller-owned directory out from under concurrent
  // users, and a directory that did not exist has no users to break. The
  // precise contract: an output-dir that already exists is never chmodded,
  // in no branch, ever (mkdirSync's mode has no effect on existing
  // directories — the Qodo #6 limitation, load-bearing here in reverse);
  // one this call creates starts at 0o700 and is likewise never re-chmodded
  // afterwards, so a caller who later loosens their own directory keeps
  // whatever mode they set.
  mkdirSync(evidenceDir, { recursive: true, mode: 0o700 });
  let info;
  try {
    info = lstatSync(evidenceDir);
  } catch (error) {
    throw new Error(`failed to verify evidence directory ${evidenceDir}: ${error.message}`);
  }
  // lstat never follows: a pre-planted symlink at the well-known child name
  // (which recursive mkdirSync silently accepts when it points at a
  // directory) is refused here, closing the mkdir-swallowed-EEXIST gap.
  if (!info.isDirectory()) {
    throw new Error(`Refusing to use a pre-existing non-directory (symlink or file) as the evidence directory: ${evidenceDir}`);
  }
  // Ownership, not just mode: chmod succeeding is NOT proof the directory is
  // ours — a runner executing as root chmods anyone's directory without
  // error, so a pre-planted directory owned by another local user would pass
  // the fail-closed chmod below while staying readable by its planter.
  if (typeof process.getuid === 'function' && info.uid !== process.getuid()) {
    throw new Error(`Refusing to use an evidence directory owned by another user (uid ${info.uid}): ${evidenceDir}`);
  }
  if (process.platform !== 'win32') {
    try {
      chmodSync(evidenceDir, 0o700);
    } catch (error) {
      throw new Error(`failed to secure evidence directory ${evidenceDir} (mode 0o700): ${error.message}`);
    }
  } else {
    try {
      chmodSync(evidenceDir, 0o700);
    } catch {
      // Windows ignores POSIX directory modes; the failure carries no signal.
    }
  }
  return evidenceDir;
};

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
 * Only validation errors — bad inputs, an inside-workspace output-dir, or an
 * unverifiable evidence child directory — throw out of here (fail before
 * spawning). `outputDir` is the CALLER-facing directory; every evidence file
 * is written to its private child, resolveEvidenceDir(outputDir), and the
 * caller directory itself is never chmodded (chatgpt-codex-connector PR7
 * #6Yd4Qx; see prepareEvidenceDirectory).
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
  // tracked action-state.json first. It runs against the CALLER's directory —
  // the fixed child segment appended below cannot escape it, and the caller
  // value is also what flows into action.yml's upload `path:` lines, so the
  // CR/LF rejection (#Yb3lN) must apply to it, not to the joined path.
  assertOutputOutsideWorkspace({ outputDir, workspace: env.GITHUB_WORKSPACE });
  // ALL evidence lives in a private, action-created child of the caller's
  // output-dir (chatgpt-codex-connector PR7 #6Yd4Qx; see
  // prepareEvidenceDirectory for the full contract). Created and VERIFIED
  // before the ownership probe and stale-evidence cleanup below, because both
  // read and delete THROUGH this path — with a fixed, well-known child name
  // inside a possibly shared parent, a pre-planted symlink at it could
  // otherwise aim the cleanup at a directory this action never wrote (the
  // same class #6Yb44Sj closed for the state file itself). Creating an
  // (empty, owner-only) directory before input validation is side-effect-
  // harmless; the #6XsD7s ordering requirement — stale-state cleanup before
  // validateActionInputs — is preserved below.
  const evidenceDir = prepareEvidenceDirectory(outputDir);
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
  //
  // No-follow, both layers (chatgpt-codex-connector PR7 #6Yb44Sj, P1): a
  // plain `readFileSync` follows a symlink, so `action-state.json` planted
  // as a symlink to an ATTACKER-CHOSEN file elsewhere — content entirely
  // outside this directory — could forge this shape trivially and drive the
  // recursive `logs/` removal and the plan.json/report.json/report.md
  // unlinks below against a directory this run never actually populated.
  // lstatSync first (the primary, platform-independent guard, matching every
  // other symlink check in this file): a non-regular-file entry is refused
  // outright, before any read. openNoFollowSync (requireNoFollow: true) is
  // defense-in-depth on top of that against the lstat-to-open race itself —
  // treated with the SAME fail-closed rigor as a destructive write, because
  // although this call only READS, its result gates a destructive delete
  // rather than being consumed and discarded on its own, so "a read's
  // result can simply be discarded" does not apply here the way it does for
  // an ordinary read.
  const hadPriorEvidence = (() => {
    const statePath = path.join(evidenceDir, STATE_FILE);
    let preInfo;
    try {
      preInfo = lstatSync(statePath);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      return false;
    }
    if (!preInfo.isFile()) return false;
    let fd;
    try {
      fd = openNoFollowSync(statePath, constants.O_RDONLY, 0o666, true);
    } catch {
      return false;
    }
    try {
      if (!fstatSync(fd).isFile()) return false;
      const state = JSON.parse(readFileSync(fd, 'utf8'));
      return Boolean(state) && typeof state === 'object' && RUN_VALUES.has(state.tier) && typeof state.nonce === 'string' && state.nonce !== '';
    } catch (error) {
      if (error instanceof SyntaxError) return false;
      throw error;
    } finally {
      closeSync(fd);
    }
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
        unlinkSync(path.join(evidenceDir, staleName));
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
    }
  }
  // The gate CLI's full tier also populates the evidence dir's logs/ (a
  // DIRECTORY of per-check probe log files, scripts/pr_closeout_process.js
  // — under evidenceDir, since that is the --output-dir the CLI is given),
  // which the
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
  // own: if a check plants the evidence dir's logs/ as a symlink to an
  // unrelated directory, unlink only the link entry (mirrors writeEvidenceFile's
  // symlink discipline elsewhere in this file) — a recursive rm must only
  // ever run against a confirmed real, non-symlinked directory.
  try {
    const logsPath = path.join(evidenceDir, 'logs');
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
  // The spawned CLI receives the private CHILD as its --output-dir, never the
  // caller's own directory (chatgpt-codex-connector PR7 #6Yd4Qx): the CLI's
  // own prepareOutputDirectory/writeEvidenceReport chmod their --output-dir
  // to 0o700 for the duration of the run, so handing it the caller's
  // directory would narrow a shared /tmp-style path for up to the gate's
  // whole run no matter what the wrapper did. With the child, both the
  // wrapper's writes and the CLI's land in the action-owned directory
  // prepareEvidenceDirectory verified above, and the caller's directory mode
  // is never modified by anything in this process tree. The old capture/
  // restore chain (#6YFOVK/#6YTfjs/#6YT0Js/#6YT0Jo) is retired with it —
  // see prepareEvidenceDirectory.
  const args = ['--repo', env.GITHUB_WORKSPACE || process.cwd(), '--mode', mode, '--output-dir', evidenceDir];
  if (baseRef) args.push('--base-ref', baseRef);
  if (config) args.push('--config', config);
  if (run === 'plan') args.push('--plan');
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
      const planPath = path.join(evidenceDir, 'plan.json');
      writeEvidenceFile(evidenceDir, 'plan.json', `${JSON.stringify(parsed)}\n`);
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
      // A relative report path from the CLI resolves against the directory
      // the CLI was actually given — the evidence child, not the caller dir.
      reportJsonPath = path.isAbsolute(parsed.report.json) ? parsed.report.json : path.join(evidenceDir, parsed.report.json);
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
      const markdownPath = path.isAbsolute(parsed.report.markdown || '') ? parsed.report.markdown : path.join(evidenceDir, parsed.report.markdown || 'report.md');
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
  writeEvidenceFile(evidenceDir, STATE_FILE, `${JSON.stringify({
    tier: run, mode: reportMode, baseRef, cliExitCode, decision, artifactName, renderedSummary, renderedComment, reportJsonPath, nonce,
  })}\n`);
  process.stdout.write(`closeout-action: ${redactSecrets(decision.reason)}\n`);
  return 0;
};

/**
 * Writes a file in the evidence dir without ever writing THROUGH an existing
 * or raced-in symlink/hard link at the destination. Stages content to an
 * exclusively-created temp file in the same directory, then atomically
 * renames it into place — mirroring writeNoFollow/writeEvidenceReport's
 * identical pattern in pr_closeout_report.js, ported synchronously.
 *
 * Earlier rounds of this function opened `target` directly (after an lstat +
 * conditional-unlink guard, then O_NOFOLLOW). That closed the SYMLINK case,
 * but O_NOFOLLOW does not reject a HARD LINK — a hard link is a second
 * directory entry for an existing inode, not a link that gets "followed", so
 * opening one with O_TRUNC truncates whatever regular file it points to
 * immediately, before any post-open identity check can react (chatgpt-codex-
 * connector PR7 #6Yb1dK). O_EXCL closes this differently and completely: it
 * refuses to open ANY pre-existing path (hard link, symlink, regular file,
 * whatever) — the call either creates a brand-new, guaranteed-fresh, nlink=1
 * inode, or fails with EEXIST. A predictable temp name (pid + timestamp) is
 * therefore still safe: an attacker who pre-plants a hard link at that exact
 * path only turns our create into a clean, fail-closed EEXIST, never a
 * truncating open through it.
 *
 * The final rename() is also safe regardless of what currently occupies
 * `target`: POSIX rename() replaces the destination's directory ENTRY
 * atomically — for a destination that is a symlink, "the link will be
 * removed" (POSIX rename(2)), not followed — so it can never write through
 * an existing link at `target`, unlike a direct open ever could. This makes
 * the earlier lstat/unlink pre-check on `target` itself obsolete; it has
 * been removed rather than kept as no-op residual complexity.
 * @param {string} outputDir
 * @param {string} name - file name inside the evidence dir
 * @param {string} content
 */
const writeEvidenceFile = (outputDir, name, content) => {
  const target = path.join(outputDir, name);
  const tempPath = path.join(outputDir, `.${name}.${process.pid}.${Date.now()}.tmp`);
  // requireNoFollow: true (chatgpt-codex-connector PR7 #6Yb1dD): this is a
  // destructive write, so if the platform DOES claim real O_NOFOLLOW support
  // but the OS rejects every attempt that carries it, fail closed rather
  // than silently degrade. O_EXCL is the primary defense here regardless
  // (see above); O_NOFOLLOW is defense-in-depth on top of it.
  let fd;
  try {
    fd = openNoFollowSync(
      tempPath,
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
      0o600,
      true,
    );
  } catch (error) {
    if (error?.code === 'ELOOP') {
      throw new Error(`Refusing to write evidence file through an existing symlink: ${tempPath}`);
    }
    if (error?.code === 'EEXIST') {
      throw new Error(`Refusing to write evidence file through a pre-existing path: ${tempPath}`);
    }
    throw error;
  }
  let info;
  try {
    // fchmodSync is a cheap no-op here (O_CREAT|O_EXCL always CREATES the
    // file at the requested mode already) — kept for the same defense-in-
    // depth reasoning as the prior direct-open version, cheap insurance
    // against a platform ignoring the open-time mode argument.
    fchmodSync(fd, 0o600);
    info = fstatSync(fd);
    if (!info.isFile() || info.nlink !== 1) {
      throw new Error(`Refusing to stage evidence file through a non-private file (nlink=${info.nlink}): ${tempPath}`);
    }
    // chmodSync/fchmodSync(0o600) only clears Windows' read-only attribute
    // bit — it does NOT establish real access control there, so this file
    // would still inherit whatever DACL the surrounding --output-dir has on
    // a multi-user Windows runner, readable (and writable) by any other
    // local account. The gate CLI already solves exactly this for its own
    // evidence writes — report.json/report.md (pr_closeout_report.js) and
    // evidence logs (pr_closeout_process.js) — via protectWindowsPrivateFile:
    // a verified, owner-only Windows DACL, no-op on non-Windows. Apply it to
    // the STAGED file (a same-volume rename preserves NTFS security
    // descriptors, so this DACL travels with it to `target`), fail-closed
    // on any failure to establish it, and BEFORE any content is written
    // (Codex PR7 review, "Protect wrapper evidence with a Windows DACL";
    // chatgpt-codex-connector PR7 #6YZpcv).
    try {
      protectWindowsPrivateFile(tempPath);
    } catch (error) {
      throw new Error(`failed to protect evidence file with an owner-only ACL: ${tempPath}`, { cause: error });
    }
    if (process.platform === 'win32') {
      // protectWindowsPrivateFile re-resolves tempPath by name in a separate
      // PowerShell process; re-verify identity immediately after, same
      // reasoning as the prior direct-open version (CodeRabbit #6YaIaZ).
      let postInfo;
      try {
        postInfo = lstatSync(tempPath);
      } catch {
        throw new Error(`Refusing to write evidence file with an unverifiable identity: ${tempPath}`);
      }
      if (!isSameFileIdentity(info, postInfo)) {
        throw new Error(`Refusing to write evidence file through a path swapped during ACL protection: ${tempPath}`);
      }
    }
    writeSync(fd, content, null, 'utf8');
  } catch (error) {
    try { unlinkSync(tempPath); } catch { /* best-effort cleanup */ }
    throw error;
  } finally {
    closeSync(fd);
  }
  try {
    // Re-verify the staged file's identity immediately before rename: the
    // fd closed above, and the temp name is predictable, so a concurrent
    // writer with outputDir access could in principle replace it in this
    // gap (mirrors assertStagedIdentity in pr_closeout_report.js).
    let stagedInfo;
    try {
      stagedInfo = lstatSync(tempPath);
    } catch {
      throw new Error(`Refusing to write evidence file with an unverifiable staged identity: ${tempPath}`);
    }
    if (!isSameFileIdentity(info, stagedInfo)) {
      throw new Error(`Refusing to write evidence file through a staged path swapped before rename: ${tempPath}`);
    }
    renameSync(tempPath, target);
    // rename() is path-based, not bound to the identity just checked: a
    // concurrent writer could still swap tempPath for a replacement in the
    // instant between that check and this rename call, in which case
    // rename() commits the replacement — never the validated content — as
    // `target`. Re-verify the destination's identity right after commit and
    // remove it if it doesn't match, rather than trust a possible swap
    // (mirrors assertCommittedIdentity in pr_closeout_report.js).
    let committedInfo;
    try {
      committedInfo = lstatSync(target);
    } catch {
      throw new Error(`Refusing to trust evidence file with an unverifiable post-rename identity: ${target}`);
    }
    if (!isSameFileIdentity(info, committedInfo)) {
      try { unlinkSync(target); } catch { /* best-effort cleanup */ }
      throw new Error(`Refusing to trust evidence file through a path swapped during its rename into place: ${target}`);
    }
  } catch (error) {
    try { unlinkSync(tempPath); } catch { /* best-effort cleanup; no-op once renamed */ }
    throw error;
  }
};

// Takes the EVIDENCE directory (resolveEvidenceDir of the caller-facing
// output-dir) — callers derive it, keeping this a dumb read.
const readState = (evidenceDir) => {
  try {
    return JSON.parse(readFileSync(path.join(evidenceDir, STATE_FILE), 'utf8'));
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
  // End-of-job sweep of the delegated token file (chatgpt-codex-connector PR7
  // #6Yd4Qv). Runs unconditionally, before any early return, so the staged
  // secret is removed whichever verdict path finish takes. In the plan tier
  // the file is normally already gone (revoked before its probe); this covers
  // the full tier and any run that failed before the CLI consumed it.
  cleanupDelegatedTokenFile(env);
  // `outputDir` is the caller-facing CLOSEOUT_OUTPUT_DIR; the state file
  // lives in the action's private evidence child of it (chatgpt-codex-
  // connector PR7 #6Yd4Qx), re-derived here because finish runs as a
  // separate process from `run`.
  const state = readState(resolveEvidenceDir(outputDir));
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

// Prefix of the delegated-token filename (chatgpt-codex-connector PR7
// #6Yd4Qv). A per-invocation random suffix makes the path unpredictable, and
// the file is written OUTSIDE the evidence output-dir so it is never captured
// by the artifact upload.
const TOKEN_FILE_PREFIX = 'closeout-gh-token-';

/**
 * Best-effort removal of the delegated-token file named by
 * CLOSEOUT_GH_TOKEN_FILE. Used by `finish` as the end-of-job sweep. Non-fatal:
 * a token file that cannot be removed here must not change the gate verdict
 * `finish` exists to report (unlike the mid-run revoke in resolvePlanAdmission,
 * which gates untrusted execution and therefore fails closed). ENOENT is the
 * normal case — the plan tier already revoked the file before its probe ran.
 * @param {NodeJS.ProcessEnv} env
 */
const cleanupDelegatedTokenFile = (env) => {
  const file = env.CLOSEOUT_GH_TOKEN_FILE;
  if (!file) return;
  try {
    unlinkSync(file);
  } catch (error) {
    if (error?.code !== 'ENOENT') {
      // Do not leak the path shape or fail the verdict; just note it. On a
      // hosted runner RUNNER_TEMP is torn down per job; a self-hosted operator
      // owns runner hygiene (README), so this is a diagnostic, not an error.
      process.stderr.write('closeout-action: could not remove the delegated token file during finish; relying on runner temp cleanup.\n');
    }
  }
};

/**
 * The `stage-token` step: runs in a SEPARATE, earlier composite step that (and
 * only that step) carries GH_TOKEN in its environment, and hands the token to
 * the tokenless gate step OFF-ENVIRONMENT (chatgpt-codex-connector PR7
 * #6Yd4Qv, P1). It writes the workflow token to an owner-only file outside the
 * evidence directory and exports only that file's PATH (never the token
 * itself) to GITHUB_ENV as CLOSEOUT_GH_TOKEN_FILE, so later steps in this job
 * inherit the path but not the secret.
 *
 * Why a whole separate step, not just a different env on the gate step: a
 * process's /proc/<pid>/environ is the snapshot captured at its OWN execve()
 * and is readable by any same-UID process (subject to ptrace policy),
 * including a descendant. If GH_TOKEN were in the gate step's env it would sit
 * in the exec-time environ of the gate shell, this support.js process, and the
 * spawned gate CLI — every one of which is an ANCESTOR of the repository-
 * controlled plan-preflight probe, which could then read it from procfs even
 * though its own spawn env is scrubbed. This step's process DOES hold the token
 * in its environ, but it spawns no untrusted probe and has fully exited before
 * the gate step starts, so it is never in the probe's ancestry.
 *
 * A no-op (exit 0) when there is no token to stage or nowhere to hand off the
 * path — the gate step then simply runs unauthenticated and the plan reports
 * an honest "attestation unavailable" rather than failing the preview.
 * @returns {number} process exit code.
 */
const stageTokenSubcommand = ({ env = process.env } = {}) => {
  const token = String(env.GH_TOKEN || env.GITHUB_TOKEN || '').trim();
  if (!token) {
    process.stdout.write('closeout-action: no workflow token to stage; the gate will run unauthenticated.\n');
    return 0;
  }
  if (!env.GITHUB_ENV) {
    // Without GITHUB_ENV there is no channel to hand the path to the gate step,
    // so staging a file would only leave an unreferenced secret on disk. Skip.
    process.stderr.write('closeout-action: GITHUB_ENV is unset; cannot hand off a staged token, skipping.\n');
    return 0;
  }
  const tokenDir = env.RUNNER_TEMP || os.tmpdir();
  const tokenName = `${TOKEN_FILE_PREFIX}${randomUUID()}`;
  const tokenPath = path.join(tokenDir, tokenName);
  // Reuse the wrapper's hardened writer: owner-only mode, no-follow O_EXCL
  // staging, hard-link/symlink refusal, and a verified Windows owner-only DACL
  // — the same discipline every evidence write uses, here applied to a secret.
  writeEvidenceFile(tokenDir, tokenName, token);
  // Export only the PATH (not the token) so later steps in THIS job inherit
  // the location. The path is not a secret; the file it names is owner-only
  // and is revoked before any untrusted probe (resolvePlanAdmission) and swept
  // by `finish`.
  writeOutputs(env.GITHUB_ENV, { CLOSEOUT_GH_TOKEN_FILE: tokenPath });
  process.stdout.write('closeout-action: workflow token staged off-environment for the gate step.\n');
  return 0;
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
  // Same evidence-child derivation as finishSubcommand (chatgpt-codex-
  // connector PR7 #6Yd4Qx): `run` wrote the state file into
  // resolveEvidenceDir(outputDir), and this separate process must look there.
  const state = readState(resolveEvidenceDir(outputDir));
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
    } else if (subcommand === 'stage-token') {
      // No output-dir needed — the token file lives outside it (see
      // stageTokenSubcommand). chatgpt-codex-connector PR7 #6Yd4Qv.
      process.exitCode = stageTokenSubcommand({ env });
    } else {
      throw new Error(`Unknown subcommand: ${subcommand ?? '(none)'}. Use run, stage-token, comment, or finish.`);
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
  EVIDENCE_SUBDIR,
  assertOutputOutsideWorkspace,
  buildCommentBody,
  capText,
  commentSubcommand,
  decideExit,
  escapeActionText,
  finishSubcommand,
  parseLastJsonLine,
  readPrContext,
  cleanupDelegatedTokenFile,
  renderFullSummary,
  renderPlanSummary,
  resolveBaseRef,
  resolveEvidenceDir,
  runSubcommand,
  stageTokenSubcommand,
  upsertPrComment,
  validateActionInputs,
  writeEvidenceFile,
  writeOutputs,
};
