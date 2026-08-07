'use strict';

// Support script for the closeout composite action. The action.yml is pure
// wiring; every decision lives here so it is hermetically testable. Zero
// dependencies, same repo conventions as the gate scripts it wraps. The gate
// CLI itself (scripts/pr_closeout.js) is consumed as-is, never modified.

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
 * event payload's pull_request.base.ref (pull_request_review events), else
 * null — in which case the CLI's own config.baseRef-or-error contract
 * applies and the failure is the gate's honest named error, not a guess.
 * @param {{inputBaseRef?: string, env: object, event: object}} options
 * @returns {string|null}
 */
const resolveBaseRef = ({ inputBaseRef = '', env = {}, event = {} } = {}) => {
  if (inputBaseRef) return inputBaseRef;
  if (env.GITHUB_BASE_REF) return `origin/${env.GITHUB_BASE_REF}`;
  const eventBase = event?.pull_request?.base?.ref;
  if (typeof eventBase === 'string' && eventBase) return `origin/${eventBase}`;
  return null;
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
const renderPlanSummary = (plan, { baseRef = null } = {}) => {
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
  return lines.join('\n');
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
  const prNumber = event?.pull_request?.number;
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
  const mine = comments.find((comment) => typeof comment?.body === 'string'
    && comment.body.startsWith(ACTION_MARKER)
    && comment.user?.type === 'Bot'
    && comment.user?.login === 'github-actions[bot]');
  if (mine) {
    await runGh(['api', '--method', 'PATCH', `repos/${owner}/${repo}/issues/comments/${mine.id}`, '-f', `body=${body}`]);
    return;
  }
  await runGh(['api', '--method', 'POST', `repos/${owner}/${repo}/issues/${prNumber}/comments`, '-f', `body=${body}`]);
};

// NOTE: the real runGh (Task 4) owns JSON parsing; these functions only ever
// see parsed values.

module.exports = {
  ACTION_MARKER,
  buildCommentBody,
  capText,
  decideExit,
  escapeActionText,
  parseLastJsonLine,
  readPrContext,
  renderFullSummary,
  renderPlanSummary,
  resolveBaseRef,
  upsertPrComment,
  validateActionInputs,
};
