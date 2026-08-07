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
    return code === 0
      ? { success: true, exitCode: 0, reason: 'gate PASS' }
      : { success: false, exitCode: code, reason: `gate ${label} (exit ${code})` };
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

// Markdown-active characters neutralized when the support script itself
// interpolates evidence-derived text into summaries/comments. Mirrors the
// gate renderer's safeText semantics (allowlist by escaping the actives);
// the gate-rendered report.md is embedded verbatim and NOT re-escaped.
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

module.exports = {
  decideExit,
  escapeActionText,
  parseLastJsonLine,
  resolveBaseRef,
  validateActionInputs,
};
