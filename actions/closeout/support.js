'use strict';

// Support script for the closeout composite action. The action.yml is pure
// wiring; every decision lives here so it is hermetically testable. Zero
// dependencies, same repo conventions as the gate scripts it wraps. The gate
// CLI itself (scripts/pr_closeout.js) is consumed as-is, never modified.

const { appendFileSync, mkdirSync, readFileSync, realpathSync, writeFileSync } = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

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
  env = process.env, event = null, spawnCli = defaultSpawnCli,
}) => {
  const { run, mode } = validateActionInputs(inputs);
  const eventPayload = event ?? readEventPayload(env);
  const baseRef = resolveBaseRef({ inputBaseRef, env, event: eventPayload });
  assertOutputOutsideWorkspace({ outputDir, workspace: env.GITHUB_WORKSPACE });
  mkdirSync(outputDir, { recursive: true });
  const args = ['--repo', env.GITHUB_WORKSPACE || process.cwd(), '--mode', mode, '--output-dir', outputDir];
  if (baseRef) args.push('--base-ref', baseRef);
  if (config) args.push('--config', config);
  if (run === 'plan') args.push('--plan');
  const result = spawnCli(args, { env });
  const cliExitCode = result.status;
  const parsed = parseLastJsonLine(result.stdout);
  const decision = decideExit({ run, cliExitCode, parsed });
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
      renderedSummary = renderPlanSummary(parsed, { baseRef });
      // Plan comments equal the plan summary: gate-redacted content only.
      renderedComment = renderedSummary;
      status = parsed.planStatus;
      reportMode = parsed.mode || '';
      attestation = parsed.admission?.attestation?.status || '';
      const planPath = path.join(outputDir, 'plan.json');
      writeFileSync(planPath, `${JSON.stringify(parsed)}\n`);
      reportJsonPath = planPath;
    } else {
      renderedSummary = [
        '## Closeout plan preview',
        '',
        `**The preview itself failed** — ${escapeActionText(decision.reason + spawnNote)}`,
        '',
        `stderr: ${escapeActionText(String(result.stderr || '').slice(0, 4000))}`,
        '',
      ].join('\n');
      // Gate error text (raw stderr; parsed.error inside decision.reason)
      // is NOT redacted by the CLI's top-level catch — its audience was a
      // terminal. It stays on run-log-equivalent surfaces (Step Summary,
      // artifact); the COMMENT is permanent and notifies every subscriber,
      // so it carries a fixed-shape pointer only (review decision, Task 4
      // round 2).
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
    if (parsed?.report?.json) {
      reportJsonPath = path.isAbsolute(parsed.report.json) ? parsed.report.json : path.join(outputDir, parsed.report.json);
      try { report = JSON.parse(readFileSync(reportJsonPath, 'utf8')); } catch { report = {}; }
      const markdownPath = path.isAbsolute(parsed.report.markdown || '') ? parsed.report.markdown : path.join(outputDir, parsed.report.markdown || 'report.md');
      try { reportMarkdown = readFileSync(markdownPath, 'utf8'); } catch { reportMarkdown = '(report.md could not be read)'; }
    }
    status = report.overallStatus || parsed?.status || 'BLOCKED';
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
      reportMarkdown || `(no report was written; CLI said: ${parsed?.error || 'nothing'}${spawnNote})`,
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
    writeOutputs(env.GITHUB_OUTPUT, {
      status, mode: reportMode, attestation, 'report-path': reportJsonPath,
    });
  }
  writeFileSync(path.join(outputDir, STATE_FILE), `${JSON.stringify({
    tier: run, mode: reportMode, baseRef, cliExitCode, decision, artifactName, renderedSummary, renderedComment, reportJsonPath,
  })}\n`);
  process.stdout.write(`closeout-action: ${decision.reason}\n`);
  return 0;
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
const finishSubcommand = ({ outputDir }) => {
  const state = readState(outputDir);
  if (!state?.decision) {
    process.stderr.write('closeout-action: no recorded state; the run step never completed.\n');
    return 3;
  }
  process.stdout.write(`closeout-action: ${state.decision.reason}\n`);
  return state.decision.success ? 0 : (Number.isInteger(state.decision.exitCode) ? state.decision.exitCode : 3);
};

const defaultRunGh = async (args) => {
  const result = spawnSync('gh', args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(String(result.stderr || `gh exited ${result.status}`).trim());
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
    process.stderr.write(`closeout-action: ${error.message}\n`);
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
  writeOutputs,
};
