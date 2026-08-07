'use strict';

// Support script for the closeout composite action. The action.yml is pure
// wiring; every decision lives here so it is hermetically testable. Zero
// dependencies, same repo conventions as the gate scripts it wraps. The gate
// CLI itself (scripts/pr_closeout.js) is consumed as-is, never modified.

const { appendFileSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs');
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
      if (value && typeof value === 'object' && !Array.isArray(value)) return value;
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
const MARKDOWN_ESCAPES = new Map([
  ['&', '&amp;'], ['<', '&lt;'], ['>', '&#62;'], ['|', '&#124;'], ['*', '&#42;'],
  ['_', '&#95;'], ['`', '&#96;'], ['[', '&#91;'], [']', '&#93;'], ['#', '&#35;'],
]);

/**
 * Escapes one evidence-derived value for safe interpolation into markdown a
 * human will trust: entity-escapes markdown-active characters, renders
 * newlines as a visible return mark, and replaces every other control byte
 * with a space (charCode scan — no control-character regex literals).
 * @param {unknown} value
 * @returns {string}
 */
const escapeActionText = (value) => {
  const text = value === undefined || value === null ? '' : String(value);
  let out = '';
  for (const char of text.replace(/\r\n/g, '\n')) {
    if (char === '\n') { out += ' \u23CE '; continue; }
    const code = char.charCodeAt(0);
    if (code < 32 || code === 127) { out += ' '; continue; }
    out += MARKDOWN_ESCAPES.get(char) ?? char;
  }
  return out;
};

module.exports = {
  decideExit,
  escapeActionText,
  parseLastJsonLine,
  resolveBaseRef,
  validateActionInputs,
};
