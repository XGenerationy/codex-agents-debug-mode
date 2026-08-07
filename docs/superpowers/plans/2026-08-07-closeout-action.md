# Closeout Composite Action Implementation Plan (Cycle 3, Sub-project B)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package the PR closeout gate as a reusable composite GitHub Action (`actions/closeout/`) with a hermetically tested support script, two dogfood workflows, validator hygiene checks, and consumer docs.

**Architecture:** The composite `action.yml` is pure wiring; every decision lives in `actions/closeout/support.js` (zero dependencies, subcommands `run`/`comment`/`finish`, all env-file paths and process seams injectable). Two new workflows dogfood the action on this repo's own PRs. `tools/workflow_checks.js` gives the validator permanent SHA-pin and permissions checks.

**Tech Stack:** Node.js (zero runtime dependencies), `node:test` with `--test-concurrency=1`, GitHub composite actions, gh CLI (injectable seam in tests).

**Authoritative spec:** `docs/superpowers/specs/2026-08-07-closeout-action-design.md`. The `pr_closeout_*` gate scripts are NOT modified by this sub-project — the gate is consumed as merged (`0a2ddd1`).

**Ground rules (every task):**
- `node --test --test-concurrency=1`, ONE invocation at a time, foreground, sequentially — never concurrent (this machine throws spurious access violations otherwise).
- Zero new dependencies. Hermetic tests: no network, no real `gh`, temp files for all GitHub env files.
- Never put raw ESC (0x1B) or other control bytes in source files or shell commands — build control characters with `String.fromCharCode` in tests.
- `scripts/pr_closeout_process.js` (3,888 lines) and `scripts/pr_closeout_workflow.js` (~1,700 lines) must not be read whole or modified.
- Do NOT create files under `scripts/`, `assets/`, `references/`, `agents/`, or touch `SKILL.md` — the validator's payload count (37) must not change.
- Commits end with exactly these two trailers:
  `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`
  `Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp`

**CLI contract being wrapped (verified against `scripts/pr_closeout.js` at `0a2ddd1`):**
- Flags: `--repo <path>` (default cwd), `--base-ref <ref>` (required via flag or `config.baseRef`), `--config <path>`, `--output-dir <path>`, `--mode strict|engine`, `--plan`.
- Always writes ONE JSON line to stdout. `--plan`: the full plan object (has `planStatus`, `mode`, `admission`, `configDigest`, `errors`, `checks`, ...), exit 0 iff `planStatus === 'PASS'`, else exit 2. Full run: `{status, headSha, report: {json, markdown}}`, exit 0 iff PASS else 2. Init failure (bad args/repo/config): stderr line + stdout JSON `{status: 'BLOCKED', overallStatus: 'BLOCKED', error}` + exit 3. A real plan is distinguished from the init-failure record by the presence of a string `planStatus` field.
- `admission` (plan runs): `{attestation: {status: 'present'|'weakened'|'absent'|'unavailable', evidence}, cleanTree: {status, evidence}, preflight: {status, checks?, toolVersions?, evidence?}}`.

---

### Task 1: Support script foundation — input validation, base-ref ladder, JSON-line parsing, exit decisions

**Files:**
- Create: `actions/closeout/support.js`
- Create: `actions/closeout/support.test.js`

- [ ] **Step 1: Write the failing tests**

Create `actions/closeout/support.test.js`:

```js
'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  decideExit,
  escapeActionText,
  parseLastJsonLine,
  resolveBaseRef,
  validateActionInputs,
} = require('./support');

test('validateActionInputs applies defaults and rejects unknown values fail-closed', () => {
  const defaults = validateActionInputs({});
  assert.deepEqual(defaults, { run: 'plan', mode: 'strict', prComment: false });

  const explicit = validateActionInputs({ run: 'full', mode: 'engine', prComment: 'true' });
  assert.deepEqual(explicit, { run: 'full', mode: 'engine', prComment: true });

  assert.throws(() => validateActionInputs({ run: 'preview' }), /Unknown run input value: preview/);
  assert.throws(() => validateActionInputs({ mode: 'lenient' }), /Unknown mode input value: lenient/);
  assert.throws(() => validateActionInputs({ prComment: 'yes' }), /Unknown pr-comment input value: yes/);
  // Casing is not forgiven: the gate CLI is case-sensitive and the action
  // must never widen what the CLI accepts.
  assert.throws(() => validateActionInputs({ mode: 'Engine' }), /Unknown mode input value: Engine/);
});

test('resolveBaseRef walks the ladder: input, GITHUB_BASE_REF, event payload, then null', () => {
  assert.equal(resolveBaseRef({ inputBaseRef: 'origin/dev', env: {}, event: {} }), 'origin/dev');
  assert.equal(resolveBaseRef({ inputBaseRef: '', env: { GITHUB_BASE_REF: 'main' }, event: {} }), 'origin/main');
  assert.equal(
    resolveBaseRef({ inputBaseRef: '', env: {}, event: { pull_request: { base: { ref: 'release' } } } }),
    'origin/release',
  );
  assert.equal(resolveBaseRef({ inputBaseRef: '', env: {}, event: {} }), null);
  // The env branch wins over the event branch when both exist.
  assert.equal(
    resolveBaseRef({ inputBaseRef: '', env: { GITHUB_BASE_REF: 'main' }, event: { pull_request: { base: { ref: 'other' } } } }),
    'origin/main',
  );
});

test('parseLastJsonLine returns the last parseable JSON object line, else null', () => {
  assert.deepEqual(parseLastJsonLine('{"a":1}\n'), { a: 1 });
  assert.deepEqual(parseLastJsonLine('noise\n{"a":1}\n{"b":2}\n'), { b: 2 });
  assert.equal(parseLastJsonLine('no json here\n'), null);
  assert.equal(parseLastJsonLine(''), null);
  // A JSON scalar line is not a record.
  assert.equal(parseLastJsonLine('42\n'), null);
  // A record with an own __proto__ key can only be hostile or garbled — the
  // gate never emits one. Rejected structurally so no later consumer can be
  // prototype-tricked by an Object.assign-style copy (review decision).
  assert.equal(parseLastJsonLine('{"__proto__":{"planStatus":"PASS"}}\n'), null);
});

test('decideExit implements the spec exit decision table exactly', () => {
  const plan = { planStatus: 'FAIL', mode: 'strict' };
  // Plan tier: success iff a real plan (string planStatus) was captured,
  // regardless of exit code or planStatus value.
  assert.deepEqual(decideExit({ run: 'plan', cliExitCode: 2, parsed: plan }), { success: true, exitCode: 0, reason: 'plan captured (planStatus=FAIL)' });
  assert.deepEqual(decideExit({ run: 'plan', cliExitCode: 0, parsed: { planStatus: 'PASS' } }), { success: true, exitCode: 0, reason: 'plan captured (planStatus=PASS)' });
  const broken = decideExit({ run: 'plan', cliExitCode: 3, parsed: { status: 'BLOCKED', error: 'bad repo' } });
  assert.equal(broken.success, false);
  assert.equal(broken.exitCode, 3);
  assert.match(broken.reason, /no plan JSON/i);
  const silent = decideExit({ run: 'plan', cliExitCode: 0, parsed: null });
  assert.equal(silent.success, false);
  assert.equal(silent.exitCode, 3);
  // Full tier: the CLI's exit code propagates verbatim.
  assert.deepEqual(decideExit({ run: 'full', cliExitCode: 0, parsed: { status: 'PASS' } }), { success: true, exitCode: 0, reason: 'gate PASS' });
  const fail = decideExit({ run: 'full', cliExitCode: 2, parsed: { status: 'FAIL' } });
  assert.deepEqual([fail.success, fail.exitCode], [false, 2]);
  const blocked = decideExit({ run: 'full', cliExitCode: 3, parsed: { status: 'BLOCKED' } });
  assert.deepEqual([blocked.success, blocked.exitCode], [false, 3]);
  // Unknown tier fails CLOSED (review decision, Task 1 round): an
  // unvalidated run value must never fall into the more permissive plan
  // branch and report success for a failing full gate.
  const mixedCase = decideExit({ run: 'FULL', cliExitCode: 0, parsed: { planStatus: 'PASS' } });
  assert.deepEqual([mixedCase.success, mixedCase.exitCode], [false, 3]);
  assert.match(mixedCase.reason, /unknown run tier/i);
  const missingTier = decideExit({ run: undefined, cliExitCode: 2, parsed: { planStatus: 'PASS' } });
  assert.deepEqual([missingTier.success, missingTier.exitCode], [false, 3]);
});

test('escapeActionText is the gate safeText allowlist: everything non-allowlisted becomes a numeric entity', () => {
  assert.equal(escapeActionText('plain text 123 file.name_ok-1'), 'plain text 123 file.name_ok-1');
  assert.equal(escapeActionText('a & b'), 'a &#38; b');
  assert.equal(escapeActionText('<img>'), '&#60;img&#62;');
  assert.equal(escapeActionText('x | y'), 'x &#124; y');
  assert.equal(escapeActionText('# heading'), '&#35; heading');
  assert.equal(escapeActionText('~~FAILED~~ ~~~js'), '&#126;&#126;FAILED&#126;&#126; &#126;&#126;&#126;js');
  assert.equal(escapeActionText('https://evil.example/x'), 'https&#58;&#47;&#47;evil.example&#47;x');
  assert.equal(
    escapeActionText('> quote **bold** `c` [l](u)'),
    '&#62; quote &#42;&#42;bold&#42;&#42; &#96;c&#96; &#91;l&#93;&#40;u&#41;',
  );
  assert.equal(escapeActionText('line1\nline2\r\nline3'), 'line1 \u23CE line2 \u23CE line3');
  const hostile = `bad${String.fromCharCode(27)}[31mansi${String.fromCharCode(0)}nul`;
  const escaped = escapeActionText(hostile);
  assert.match(escaped, /&#27;/);
  assert.match(escaped, /&#0;/);
  for (let index = 0; index < escaped.length; index += 1) {
    const code = escaped.charCodeAt(index);
    assert.ok(code >= 32 && code !== 127, `control byte survived at ${index}`);
  }
  assert.equal(escapeActionText(undefined), '');
  assert.equal(escapeActionText(42), '42');
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test --test-concurrency=1 actions/closeout/support.test.js`
Expected: FAIL — cannot find module `./support`.

- [ ] **Step 3: Implement the foundation**

Create `actions/closeout/support.js`:

```js
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
```

(Task 1 needs NO node imports — all five functions are pure. Tasks 3–4 introduce their own `node:fs`/`node:path`/`node:child_process` requires when they wire I/O; a foundation file that a reviewer reads to understand the trust boundary must not import `spawnSync` it never calls — review decision, Task 1 round.)

- [ ] **Step 4: Run to verify green**

Run: `node --test --test-concurrency=1 actions/closeout/support.test.js`
Expected: all 5 tests pass. Also `node --check actions/closeout/support.js`.

- [ ] **Step 5: Commit**

```bash
git add actions/closeout/support.js actions/closeout/support.test.js
git commit -m "feat(action): closeout action support foundation — inputs, base-ref ladder, exit table"
```

(with the standard two trailers)

---

### Task 2: Summary rendering — plan admission table, full report embed, caps, hostile fixtures

**Files:**
- Modify: `actions/closeout/support.js` (append functions + exports)
- Modify: `actions/closeout/support.test.js` (append)

- [ ] **Step 1: Write the failing tests**

Append to `actions/closeout/support.test.js` (extend the top require with `capText, renderFullSummary, renderPlanSummary`):

```js
const hostilePlan = () => ({
  planStatus: 'FAIL',
  mode: 'engine',
  configDigest: 'digest-abc',
  errors: ['# forged heading\n> **STRICT MODE** claim | pipe'],
  checks: [{ id: 'unit' }, { id: 'lint' }],
  admission: {
    attestation: { status: 'weakened', evidence: 'decision **weakened** by [review](x)' },
    cleanTree: { status: 'PASS', evidence: 'clean' },
    preflight: { status: 'BLOCKED', checks: [{ name: 'docker', status: 'BLOCKED', evidence: 'daemon | down' }] },
  },
});

test('renderPlanSummary renders all four attestation states distinctly and escapes hostile evidence', () => {
  const markdown = renderPlanSummary(hostilePlan(), { baseRef: 'origin/main' });
  assert.match(markdown, /Closeout plan preview/);
  assert.match(markdown, /Mode.*engine/);
  assert.match(markdown, /planStatus.*FAIL/);
  assert.match(markdown, /digest-abc/);
  // The base ref passes through the safeText-style escaper: '/' is not
  // allowlisted, so it renders as its numeric entity.
  assert.match(markdown, /origin&#47;main/);
  // Weakened must be visually distinct from absent, not just different text.
  assert.match(markdown, /\u26A0.*weakened/i);
  // Hostile evidence is neutralized: no forged heading or blockquote line.
  assert.equal(markdown.split('\n').some((line) => line.startsWith('# forged')), false);
  assert.equal(markdown.split('\n').filter((line) => line.startsWith('>')).length, 0);
  assert.doesNotMatch(markdown, /\*\*STRICT MODE\*\*/);

  for (const status of ['present', 'absent', 'unavailable']) {
    const plan = hostilePlan();
    plan.admission.attestation = { status, evidence: `state ${status}` };
    assert.match(renderPlanSummary(plan, {}), new RegExp(`attestation.*${status}`, 'i'));
  }
});

test('renderFullSummary embeds the gate report verbatim and caps with an in-band notice', () => {
  const report = { overallStatus: 'FAIL', mode: 'engine', configDigest: 'd1' };
  const small = renderFullSummary(report, '## Gate Report\n\n> **ENGINE MODE** banner line\n', { artifactName: 'closeout-evidence' });
  // The gate-rendered markdown is embedded verbatim — NOT double-escaped.
  assert.match(small, /## Gate Report/);
  assert.match(small, /> \*\*ENGINE MODE\*\* banner line/);
  assert.match(small, /FAIL/);

  const big = renderFullSummary(report, 'x'.repeat(600 * 1024), { artifactName: 'closeout-evidence' });
  assert.ok(Buffer.byteLength(big, 'utf8') <= 524288 + 2048, 'summary exceeds cap plus notice allowance');
  assert.match(big, /truncated/i);
  assert.match(big, /closeout-evidence/);
});

test('capText truncates on byte length with a notice and passes short text through', () => {
  const short = capText('hello', 1024, 'artifact-name');
  assert.deepEqual(short, { text: 'hello', truncated: false });
  const long = capText('y'.repeat(2048), 1024, 'artifact-name');
  assert.equal(long.truncated, true);
  assert.ok(Buffer.byteLength(long.text, 'utf8') <= 1024 + 2048);
  assert.match(long.text, /truncated/i);
  assert.match(long.text, /artifact-name/);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test --test-concurrency=1 actions/closeout/support.test.js`
Expected: new tests fail (functions not exported); Task 1 tests still pass.

- [ ] **Step 3: Implement**

Append to `actions/closeout/support.js` (before `module.exports`, and add the three names to the export object):

```js
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
  const clipped = Buffer.from(value, 'utf8').subarray(0, maxBytes).toString('utf8');
  // Drop a possibly-split trailing code point (replacement char from a cut
  // multibyte sequence) rather than shipping mojibake.
  const clean = clipped.endsWith('\uFFFD') ? clipped.slice(0, -1) : clipped;
  return {
    text: `${clean}\n\n---\n\n**Output truncated at ${maxBytes} bytes.** The complete evidence is in the \`${artifactName}\` artifact.\n`,
    truncated: true,
  };
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
  const admission = plan.admission || {};
  const attestation = admission.attestation || {};
  const label = ATTESTATION_LABELS.get(attestation.status) || `unknown state: ${escapeActionText(attestation.status)}`;
  const lines = [
    '## Closeout plan preview',
    '',
    `- Mode: ${escapeActionText(plan.mode || 'strict')}`,
    `- planStatus: **${escapeActionText(plan.planStatus)}**`,
    `- Configuration digest: ${escapeActionText(plan.configDigest || 'unresolved')}`,
    `- Base ref: ${escapeActionText(baseRef || 'from config')}`,
    '',
    '### Admission readiness',
    '',
    '| Probe | Status | Evidence |',
    '|---|---|---|',
    `| attestation | ${label.split(' \u2014 ')[0]} | ${escapeActionText(attestation.evidence || label)} |`,
    `| clean tree | ${escapeActionText(admission.cleanTree?.status || 'unknown')} | ${escapeActionText(admission.cleanTree?.evidence || '')} |`,
    `| preflight | ${escapeActionText(admission.preflight?.status || 'unknown')} | ${escapeActionText(admission.preflight?.evidence || '')} |`,
  ];
  lines.push('', `- Attestation detail: ${label}`);
  const preflightChecks = Array.isArray(admission.preflight?.checks) ? admission.preflight.checks : [];
  for (const check of preflightChecks.filter((entry) => entry.status !== 'PASS').slice(0, 20)) {
    lines.push(`- preflight ${escapeActionText(check.name)}: ${escapeActionText(check.status)} — ${escapeActionText(check.evidence || '')}`);
  }
  const errors = Array.isArray(plan.errors) ? plan.errors : [];
  if (errors.length > 0) {
    lines.push('', '### Plan errors', '');
    for (const error of errors.slice(0, 50)) lines.push(`- ${escapeActionText(error)}`);
  }
  const checks = Array.isArray(plan.checks) ? plan.checks : [];
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
  const embed = capText(reportMarkdown, SUMMARY_EMBED_CAP_BYTES, artifactName);
  return [
    '## Closeout gate result',
    '',
    `- Overall status: **${escapeActionText(report.overallStatus)}**`,
    `- Mode: ${escapeActionText(report.mode || 'strict')}`,
    `- Configuration digest: ${escapeActionText(report.configDigest || 'unresolved')}`,
    `- Evidence artifact: \`${escapeActionText(artifactName)}\``,
    '',
    '---',
    '',
    embed.text,
  ].join('\n');
};
```

- [ ] **Step 4: Run to verify green**

Run: `node --test --test-concurrency=1 actions/closeout/support.test.js`
Expected: all pass. `node --check actions/closeout/support.js` clean.

- [ ] **Step 5: Commit**

```bash
git add actions/closeout/support.js actions/closeout/support.test.js
git commit -m "feat(action): plan and full-run summary rendering with caps and escaping"
```

(with the standard two trailers)

---

### Task 3: PR comment — marker, body, upsert via injectable gh seam, PR-context detection

**Files:**
- Modify: `actions/closeout/support.js` (append + exports)
- Modify: `actions/closeout/support.test.js` (append)

- [ ] **Step 1: Write the failing tests**

Append (extend the require with `ACTION_MARKER, buildCommentBody, readPrContext, upsertPrComment`):

```js
test('readPrContext extracts repo and PR number from env plus event payload, else null', () => {
  const context = readPrContext({
    env: { GITHUB_REPOSITORY: 'owner/repo' },
    event: { pull_request: { number: 42 } },
  });
  assert.deepEqual(context, { owner: 'owner', repo: 'repo', prNumber: 42 });
  assert.equal(readPrContext({ env: { GITHUB_REPOSITORY: 'owner/repo' }, event: {} }), null);
  assert.equal(readPrContext({ env: {}, event: { pull_request: { number: 42 } } }), null);
  assert.equal(readPrContext({ env: { GITHUB_REPOSITORY: 'malformed' }, event: { pull_request: { number: 42 } } }), null);
});

test('buildCommentBody starts with the stable marker and caps at the comment limit', () => {
  const body = buildCommentBody({ tier: 'plan', rendered: renderPlanSummary(hostilePlan(), {}), artifactName: 'ev' });
  assert.ok(body.startsWith(ACTION_MARKER), 'marker must be the first line for upsert matching');
  assert.match(body, /Closeout plan preview/);
  const big = buildCommentBody({ tier: 'full', rendered: 'z'.repeat(80 * 1024), artifactName: 'ev' });
  assert.ok(Buffer.byteLength(big, 'utf8') <= 60 * 1024 + 4096);
  assert.match(big, /truncated/i);
});

test('upsertPrComment PATCHes an existing marker comment and POSTs otherwise', async () => {
  const calls = [];
  const existing = [{ id: 7, body: `${ACTION_MARKER}\nold` }, { id: 8, body: 'unrelated' }];
  const patchingGh = async (args) => {
    calls.push(args);
    if (args.includes('--method') === false) return existing; // list call
    return { id: 7 };
  };
  await upsertPrComment({
    context: { owner: 'o', repo: 'r', prNumber: 5 },
    body: `${ACTION_MARKER}\nnew`,
    runGh: patchingGh,
  });
  assert.equal(calls.length, 2);
  assert.ok(calls[0].join(' ').includes('issues/5/comments'), 'first call lists comments');
  assert.ok(calls[1].join(' ').includes('issues/comments/7'), 'second call PATCHes the marker comment');
  assert.ok(calls[1].includes('PATCH'));

  const posts = [];
  await upsertPrComment({
    context: { owner: 'o', repo: 'r', prNumber: 5 },
    body: `${ACTION_MARKER}\nnew`,
    runGh: async (args) => { posts.push(args); return args.includes('POST') ? { id: 9 } : []; },
  });
  assert.ok(posts[1].includes('POST'), 'no marker comment found: POST a new one');
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test --test-concurrency=1 actions/closeout/support.test.js`
Expected: new tests fail; earlier ones pass.

- [ ] **Step 3: Implement**

Append to `actions/closeout/support.js` (and export the four new names):

```js
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
  if (!owner || !repo || rest.length > 0 || !Number.isInteger(prNumber)) return null;
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
  return `${ACTION_MARKER}\n${capped.text}`;
};

/**
 * Upserts the marker-tagged PR comment via the injectable gh seam: list the
 * first page of issue comments, PATCH the one whose body starts with the
 * marker, else POST a new one. First-page-only matching is a documented
 * bound — the action's own comment stays near the top of any real PR's
 * comment count, and a miss degrades to one duplicate comment, never a lost
 * result.
 * @param {{context: {owner, repo, prNumber}, body: string, runGh: Function}} options
 * @returns {Promise<void>}
 */
const upsertPrComment = async ({ context, body, runGh }) => {
  const { owner, repo, prNumber } = context;
  const listed = await runGh(['api', `repos/${owner}/${repo}/issues/${prNumber}/comments`, '--jq', '.']);
  const comments = Array.isArray(listed) ? listed : [];
  const mine = comments.find((comment) => typeof comment?.body === 'string' && comment.body.startsWith(ACTION_MARKER));
  if (mine) {
    await runGh(['api', '--method', 'PATCH', `repos/${owner}/${repo}/issues/comments/${mine.id}`, '-f', `body=${body}`]);
    return;
  }
  await runGh(['api', '--method', 'POST', `repos/${owner}/${repo}/issues/${prNumber}/comments`, '-f', `body=${body}`]);
};
```

NOTE: the test's fake list call returns a plain array; if `gh api --jq .` in the real
path returns a JSON string, `runGh`'s real implementation (Task 4) owns parsing —
these functions only ever see parsed values.

- [ ] **Step 4: Run to verify green**

Run: `node --test --test-concurrency=1 actions/closeout/support.test.js`
Expected: all pass. `node --check` clean.

- [ ] **Step 5: Commit**

```bash
git add actions/closeout/support.js actions/closeout/support.test.js
git commit -m "feat(action): marker-tagged PR comment upsert behind injectable gh seam"
```

(with the standard two trailers)

---

### Task 4: Orchestration — outputs, state file, run/comment/finish subcommands, main dispatch

**Files:**
- Modify: `actions/closeout/support.js` (append + exports + main dispatch)
- Modify: `actions/closeout/support.test.js` (append)

State contract between steps: `run` writes `<output-dir>/action-state.json` —
`{tier, mode, baseRef, cliExitCode, decision, parsed, reportJsonPath?, artifactName}` —
and `comment`/`finish` read it. All GitHub env-file paths (`GITHUB_OUTPUT`,
`GITHUB_STEP_SUMMARY`) and the spawn/gh/env/event seams are injectable.

- [ ] **Step 1: Write the failing tests**

Append (extend the require with `runSubcommand, finishSubcommand, commentSubcommand, writeOutputs`; add at top of file `const { mkdtempSync, readFileSync: readFs, writeFileSync: writeFs } = require('node:fs'); const { tmpdir } = require('node:os'); const path = require('node:path');` — matching names to avoid clashing with existing requires):

```js
const makeTempDir = () => mkdtempSync(path.join(tmpdir(), 'closeout-action-'));

test('writeOutputs appends sanitized single-line name=value pairs', () => {
  const dir = makeTempDir();
  const outputFile = path.join(dir, 'gh-output');
  writeFs(outputFile, 'existing=1\n');
  writeOutputs(outputFile, { status: 'FAIL', mode: 'engine', attestation: 'absent', 'report-path': 'C:\\x\\report.json' });
  writeOutputs(outputFile, { extra: 'line1\nline2' });
  const content = readFs(outputFile, 'utf8');
  assert.match(content, /^existing=1$/m);
  assert.match(content, /^status=FAIL$/m);
  assert.match(content, /^mode=engine$/m);
  assert.match(content, /^attestation=absent$/m);
  assert.match(content, /^extra=line1 line2$/m);
  assert.equal(content.split('\n').every((line) => !line.includes('\r')), true);
});

test('runSubcommand end-to-end (plan tier): spawns the CLI, writes summary, outputs, and state', async () => {
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const summaryFile = path.join(dir, 'summary');
  const outputFile = path.join(dir, 'output');
  const plan = { planStatus: 'FAIL', mode: 'strict', configDigest: 'd', errors: [], checks: [],
    admission: { attestation: { status: 'absent', evidence: 'none yet' }, cleanTree: { status: 'PASS', evidence: 'clean' }, preflight: { status: 'PASS' } } };
  let spawnedArgs;
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: summaryFile },
    event: {},
    spawnCli: (args) => { spawnedArgs = args; return { status: 2, stdout: `${JSON.stringify(plan)}\n`, stderr: '' }; },
  });
  assert.equal(exit, 0, 'run never fails the job for gate outcomes; finish decides');
  assert.ok(spawnedArgs.includes('--plan'));
  assert.ok(spawnedArgs.includes('--mode'));
  assert.deepEqual(spawnedArgs.slice(spawnedArgs.indexOf('--base-ref'), spawnedArgs.indexOf('--base-ref') + 2), ['--base-ref', 'origin/main']);
  const summary = readFs(summaryFile, 'utf8');
  assert.match(summary, /Closeout plan preview/);
  assert.match(summary, /absent/);
  const outputs = readFs(outputFile, 'utf8');
  assert.match(outputs, /^status=FAIL$/m);
  assert.match(outputs, /^attestation=absent$/m);
  const state = JSON.parse(readFs(path.join(outputDir, 'action-state.json'), 'utf8'));
  assert.equal(state.tier, 'plan');
  assert.equal(state.decision.success, true);
});

test('runSubcommand end-to-end (full tier): reads report.json/report.md and records the failing decision', async () => {
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const summaryFile = path.join(dir, 'summary');
  const outputFile = path.join(dir, 'output');
  const reportDir = makeTempDir();
  const reportJson = path.join(reportDir, 'report.json');
  const reportMd = path.join(reportDir, 'report.md');
  writeFs(reportJson, JSON.stringify({ overallStatus: 'FAIL', mode: 'engine', configDigest: 'd9', matrixSource: { checkCount: 1 } }));
  writeFs(reportMd, '# PR Closeout Evidence\n\n> **ENGINE MODE** banner\n');
  const exit = await runSubcommand({
    inputs: { run: 'full', mode: 'engine', prComment: 'false' },
    inputBaseRef: 'origin/main', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: summaryFile },
    event: {},
    spawnCli: () => ({ status: 2, stdout: `${JSON.stringify({ status: 'FAIL', headSha: 'h', report: { json: reportJson, markdown: reportMd } })}\n`, stderr: '' }),
  });
  assert.equal(exit, 0);
  const summary = readFs(summaryFile, 'utf8');
  assert.match(summary, /Closeout gate result/);
  assert.match(summary, /> \*\*ENGINE MODE\*\* banner/);
  const outputs = readFs(outputFile, 'utf8');
  assert.match(outputs, /^status=FAIL$/m);
  assert.match(outputs, /^mode=engine$/m);
  const state = JSON.parse(readFs(path.join(outputDir, 'action-state.json'), 'utf8'));
  assert.deepEqual([state.decision.success, state.decision.exitCode], [false, 2]);
});

test('finishSubcommand exits with the recorded decision', () => {
  const dir = makeTempDir();
  writeFs(path.join(dir, 'action-state.json'), JSON.stringify({ decision: { success: false, exitCode: 2, reason: 'gate FAIL (exit 2)' } }));
  assert.equal(finishSubcommand({ outputDir: dir }), 2);
  writeFs(path.join(dir, 'action-state.json'), JSON.stringify({ decision: { success: true, exitCode: 0, reason: 'ok' } }));
  assert.equal(finishSubcommand({ outputDir: dir }), 0);
  // Missing state means run never completed: fail closed.
  assert.equal(finishSubcommand({ outputDir: makeTempDir() }), 3);
});

test('commentSubcommand upserts in PR context and skips with a notice otherwise', async () => {
  const dir = makeTempDir();
  writeFs(path.join(dir, 'action-state.json'), JSON.stringify({
    tier: 'plan', artifactName: 'ev', renderedSummary: '## Closeout plan preview\nbody', decision: { success: true, exitCode: 0 },
  }));
  const calls = [];
  const code = await commentSubcommand({
    outputDir: dir,
    env: { GITHUB_REPOSITORY: 'o/r' },
    event: { pull_request: { number: 3 } },
    runGh: async (args) => { calls.push(args); return args.includes('POST') ? { id: 1 } : []; },
  });
  assert.equal(code, 0);
  assert.equal(calls.length, 2);

  const skipped = await commentSubcommand({ outputDir: dir, env: {}, event: {}, runGh: async () => { throw new Error('must not be called'); } });
  assert.equal(skipped, 0, 'outside PR context the comment step skips, never fails');
});

test('a hostile base-ref stays one argv element — never a shell string', async () => {
  // resolveBaseRef returns input verbatim; that is safe ONLY because the CLI
  // is spawned with an argv array. Pin it (quality-review note, Task 1).
  const dir = makeTempDir();
  let spawnedArgs;
  await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: 'main --mode engine', config: '', outputDir: path.join(dir, 'e'), artifactName: 'ev',
    env: { GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: (args) => { spawnedArgs = args; return { status: 3, stdout: '{"status":"BLOCKED","error":"x"}\n', stderr: '' }; },
  });
  const at = spawnedArgs.indexOf('--base-ref');
  assert.equal(spawnedArgs[at + 1], 'main --mode engine', 'the hostile value is exactly one argv element');
  assert.equal(spawnedArgs.filter((a) => a === '--mode').length, 1, 'no injected second --mode flag');
});

test('a comment API failure propagates — the consumer opted in, silence would lie', async () => {
  const dir = makeTempDir();
  writeFs(path.join(dir, 'action-state.json'), JSON.stringify({
    tier: 'plan', artifactName: 'ev', renderedSummary: 'body', decision: { success: true, exitCode: 0 },
  }));
  await assert.rejects(
    commentSubcommand({
      outputDir: dir,
      env: { GITHUB_REPOSITORY: 'o/r' },
      event: { pull_request: { number: 3 } },
      runGh: async () => { throw new Error('gh: HTTP 403 Resource not accessible'); },
    }),
    /HTTP 403/,
  );
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test --test-concurrency=1 actions/closeout/support.test.js`
Expected: new tests fail; earlier pass.

- [ ] **Step 3: Implement**

First add the node imports this task introduces (Task 1 deliberately shipped with
none — review decision) at the top of `actions/closeout/support.js`:

```js
const { appendFileSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
```

Then append (exports extended; `GATE_CLI` computed from `__dirname`):

```js
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
  mkdirSync(outputDir, { recursive: true });
  const args = ['--repo', env.GITHUB_WORKSPACE || process.cwd(), '--mode', mode, '--output-dir', outputDir];
  if (baseRef) args.push('--base-ref', baseRef);
  if (config) args.push('--config', config);
  if (run === 'plan') args.push('--plan');
  const result = spawnCli(args, { env });
  const cliExitCode = result.status;
  const parsed = parseLastJsonLine(result.stdout);
  const decision = decideExit({ run, cliExitCode, parsed });

  let renderedSummary;
  let reportJsonPath = '';
  let reportMode = '';
  let attestation = '';
  let status = '';
  if (run === 'plan') {
    if (parsed && typeof parsed.planStatus === 'string') {
      renderedSummary = renderPlanSummary(parsed, { baseRef });
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
        `**The preview itself failed** — ${escapeActionText(decision.reason)}`,
        '',
        `stderr: ${escapeActionText(String(result.stderr || '').slice(0, 4000))}`,
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
    renderedSummary = renderFullSummary(
      { overallStatus: status, mode: report.mode, configDigest: report.configDigest },
      reportMarkdown || `(no report was written; CLI said: ${parsed?.error || 'nothing'})`,
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
    tier: run, mode: reportMode, baseRef, cliExitCode, decision, artifactName, renderedSummary, reportJsonPath,
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
  const body = buildCommentBody({ tier: state.tier, rendered: state.renderedSummary || '', artifactName: state.artifactName || 'closeout-evidence' });
  await upsertPrComment({ context, body, runGh });
  process.stdout.write(`closeout-action: comment upserted on PR #${context.prNumber}.\n`);
  return 0;
};

const main = async () => {
  const [subcommand] = process.argv.slice(2);
  const env = process.env;
  const common = { outputDir: env.CLOSEOUT_OUTPUT_DIR || path.join(env.RUNNER_TEMP || require('node:os').tmpdir(), 'closeout-evidence') };
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
```

- [ ] **Step 4: Run to verify green**

Run: `node --test --test-concurrency=1 actions/closeout/support.test.js`
Expected: all pass. `node --check actions/closeout/support.js` clean.

- [ ] **Step 5: Commit**

```bash
git add actions/closeout/support.js actions/closeout/support.test.js
git commit -m "feat(action): run/comment/finish orchestration with injectable seams"
```

(with the standard two trailers)

---

### Task 5: Composite action.yml + the two dogfood workflows

**Files:**
- Create: `actions/closeout/action.yml`
- Create: `.github/workflows/closeout-preview.yml`
- Create: `.github/workflows/closeout-gate.yml`

- [ ] **Step 1: Resolve the upload-artifact pin**

Run: `gh api repos/actions/upload-artifact/commits/v4 --jq '.sha'` and note the SHA plus
the current v4.x tag name (`gh api repos/actions/upload-artifact/tags --jq '.[0].name'`).
Do NOT invent a SHA. The checkout and setup-node pins below are reused verbatim from
this repo's `validate.yml`.

- [ ] **Step 2: Create `actions/closeout/action.yml`**

```yaml
name: PR Closeout Gate
description: >-
  Evidence-first PR closeout gate: strict 19-check tier or repo-defined engine
  tier, as a plan preview or the full enforcing run. All logic lives in
  support.js; this file is wiring only.

inputs:
  run:
    description: "plan (read-only preview) or full (enforcing gate)"
    default: plan
  mode:
    description: "strict (19-check gate) or engine (config.engineChecks)"
    default: strict
  base-ref:
    description: "Live PR base ref; empty resolves via GITHUB_BASE_REF or the event payload"
    default: ""
  config:
    description: "Path to a closeout config JSON"
    default: ""
  output-dir:
    description: "Evidence directory (must be outside the repository)"
    default: ""
  node-version:
    description: "Node.js version for the gate"
    default: "24"
  pr-comment:
    description: "true to upsert a marker-tagged PR comment (needs pull-requests: write)"
    default: "false"
  artifact-name:
    description: "Evidence artifact name"
    default: closeout-evidence

outputs:
  status:
    description: "overallStatus (full) or planStatus (plan)"
    value: ${{ steps.gate.outputs.status }}
  mode:
    description: "The gate-reported mode of the run"
    value: ${{ steps.gate.outputs.mode }}
  attestation:
    description: "Plan runs: present | weakened | absent | unavailable"
    value: ${{ steps.gate.outputs.attestation }}
  report-path:
    description: "Path of report.json (full) or the captured plan JSON (plan)"
    value: ${{ steps.gate.outputs.report-path }}

runs:
  using: composite
  steps:
    - name: Set up Node.js
      uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6.5.0
      with:
        node-version: ${{ inputs.node-version }}

    - name: Run closeout gate
      id: gate
      shell: bash
      env:
        CLOSEOUT_RUN: ${{ inputs.run }}
        CLOSEOUT_MODE: ${{ inputs.mode }}
        CLOSEOUT_BASE_REF: ${{ inputs.base-ref }}
        CLOSEOUT_CONFIG: ${{ inputs.config }}
        CLOSEOUT_OUTPUT_DIR: ${{ inputs.output-dir || format('{0}/closeout-evidence', runner.temp) }}
        CLOSEOUT_PR_COMMENT: ${{ inputs.pr-comment }}
        CLOSEOUT_ARTIFACT_NAME: ${{ inputs.artifact-name }}
        GH_TOKEN: ${{ github.token }}
      run: node "${{ github.action_path }}/support.js" run

    - name: Upload evidence artifact
      if: always()
      uses: actions/upload-artifact@<SHA-FROM-STEP-1> # <v4.x tag from step 1>
      with:
        name: ${{ inputs.artifact-name }}
        path: ${{ inputs.output-dir || format('{0}/closeout-evidence', runner.temp) }}
        if-no-files-found: ignore

    - name: Upsert PR comment
      if: ${{ always() && inputs.pr-comment == 'true' }}
      shell: bash
      env:
        CLOSEOUT_OUTPUT_DIR: ${{ inputs.output-dir || format('{0}/closeout-evidence', runner.temp) }}
        GH_TOKEN: ${{ github.token }}
      run: node "${{ github.action_path }}/support.js" comment

    - name: Apply gate verdict
      if: always()
      shell: bash
      env:
        CLOSEOUT_OUTPUT_DIR: ${{ inputs.output-dir || format('{0}/closeout-evidence', runner.temp) }}
      run: node "${{ github.action_path }}/support.js" finish
```

- [ ] **Step 3: Create `.github/workflows/closeout-preview.yml`**

```yaml
name: Closeout preview

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: read

concurrency:
  group: closeout-preview-${{ github.ref }}
  cancel-in-progress: true

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          # Full history: the gate resolves merge-base and diffs the whole
          # PR range, not just the tip commit.
          fetch-depth: 0

      # Fork-PR note: this preview is read-only by design, so the reduced
      # fork token is sufficient. The pr-comment opt-in would NOT work from
      # a fork; this repo reads Step Summaries instead.
      - name: Closeout plan preview
        uses: ./actions/closeout
        with:
          run: plan
```

- [ ] **Step 4: Create `.github/workflows/closeout-gate.yml`**

```yaml
name: Closeout gate

on:
  pull_request_review:
    types: [submitted]
  workflow_dispatch:
    inputs:
      base-ref:
        description: "Live PR base ref (dispatch runs have no PR context)"
        default: origin/main

permissions:
  contents: read
  pull-requests: read

concurrency:
  group: closeout-gate-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

jobs:
  gate:
    # Cost guard only: the gate independently re-verifies the live review
    # state, head SHA, and attestation through gh — this condition just
    # avoids spending a full run on comment-only review events.
    if: ${{ github.event_name == 'workflow_dispatch' || github.event.review.state == 'approved' }}
    runs-on: ubuntu-latest
    steps:
      - name: Check out reviewed head
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          # The gate re-verifies the live head via gh and BLOCKS stale
          # snapshots; the checkout must present the head being attested.
          ref: ${{ github.event.pull_request.head.sha || github.ref }}
          fetch-depth: 0

      - name: Closeout gate
        uses: ./actions/closeout
        with:
          run: full
          base-ref: ${{ github.event.inputs.base-ref || '' }}
```

- [ ] **Step 5: Sanity checks and commit**

`node --check` does not apply to YAML; instead confirm each file round-trips as text and
that every `uses:` line is either `./`-local or `@`-pinned to the 40-hex SHAs used above
(Task 6's validator checks will enforce this permanently). Placeholder `<SHA-FROM-STEP-1>`
MUST be replaced with the real resolved SHA before committing — grep the file for `<` to
confirm no placeholder survives.

```bash
git add actions/closeout/action.yml .github/workflows/closeout-preview.yml .github/workflows/closeout-gate.yml
git commit -m "feat(action): composite closeout action and dogfood preview/gate workflows"
```

(with the standard two trailers)

---

### Task 6: Validator hygiene checks — `tools/workflow_checks.js` + wiring + tests

**Files:**
- Create: `tools/workflow_checks.js`
- Create: `tools/workflow_checks.test.js`
- Modify: `tools/validate_repository.js` (append checks after the JavaScript syntax loop, before the failure rollup at ~line 242)

- [ ] **Step 1: Write the failing tests**

Create `tools/workflow_checks.test.js`:

```js
'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');

const { findUnpinnedUses, hasTopLevelPermissions } = require('./workflow_checks');

test('findUnpinnedUses flags tags, branches, and docker refs but not 40-hex pins or local paths', () => {
  const pinned = 'steps:\n  - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3\n';
  assert.deepEqual(findUnpinnedUses(pinned), []);
  const quoted = "  - uses: 'actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10'\n";
  assert.deepEqual(findUnpinnedUses(quoted), []);
  const local = '  - uses: ./actions/closeout\n';
  assert.deepEqual(findUnpinnedUses(local), []);

  const tag = '  - uses: actions/checkout@v6\n';
  assert.equal(findUnpinnedUses(tag).length, 1);
  assert.equal(findUnpinnedUses(tag)[0].ref, 'actions/checkout@v6');
  const branch = '  - uses: someone/thing@main\n';
  assert.equal(findUnpinnedUses(branch).length, 1);
  const short = '  - uses: actions/checkout@df4cb1c\n';
  assert.equal(findUnpinnedUses(short).length, 1);
  // Docker refs are flagged fail-closed: pin-by-digest is out of scope, and
  // an unpinned image is exactly what this check exists to catch.
  const docker = '  - uses: docker://alpine:3.20\n';
  assert.equal(findUnpinnedUses(docker).length, 1);
  // Line numbers are 1-indexed for actionable failure messages.
  const multi = 'a: 1\n  - uses: x/y@v1\n';
  assert.equal(findUnpinnedUses(multi)[0].line, 2);
});

test('hasTopLevelPermissions requires a column-zero permissions block', () => {
  assert.equal(hasTopLevelPermissions('name: x\npermissions:\n  contents: read\n'), true);
  assert.equal(hasTopLevelPermissions('name: x\npermissions: {}\n'), true);
  assert.equal(hasTopLevelPermissions('jobs:\n  a:\n    permissions:\n      contents: read\n'), false);
  assert.equal(hasTopLevelPermissions('name: x\n'), false);
});

test('the real validator passes on this repository (integration)', () => {
  const result = spawnSync(process.execPath, [path.join(__dirname, 'validate_repository.js')], { encoding: 'utf8' });
  assert.equal(result.status, 0, `validator failed:\n${result.stderr}`);
  assert.match(result.stdout, /"status":"PASS"/);
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test --test-concurrency=1 tools/workflow_checks.test.js`
Expected: FAIL — module missing.

- [ ] **Step 3: Create `tools/workflow_checks.js`**

```js
'use strict';

// Shallow, zero-dependency workflow hygiene predicates for the repository
// validator. Deliberately regex-level — no YAML parser exists in a
// zero-dependency repo — and honest about it: these catch the failure modes
// that matter (a mutable action ref, a workflow with no permissions
// declaration) without claiming to understand YAML structure.

const USES_LINE = /^\s*(?:-\s+)?uses:\s*(['"]?)([^\s#]+)\1\s*(?:#.*)?$/;
const PINNED_REF = /@[0-9a-f]{40}$/;

/**
 * Returns one violation per `uses:` line whose reference is neither a
 * same-repo local path (`./...`) nor pinned to a 40-hex commit SHA. Docker
 * references are flagged fail-closed. Line numbers are 1-indexed.
 * @param {string} content workflow or action YAML text.
 * @returns {Array<{line: number, ref: string}>}
 */
const findUnpinnedUses = (content) => {
  const violations = [];
  String(content ?? '').split(/\r?\n/).forEach((text, index) => {
    const match = USES_LINE.exec(text);
    if (!match) return;
    const ref = match[2];
    if (ref.startsWith('./')) return;
    if (!PINNED_REF.test(ref)) violations.push({ line: index + 1, ref });
  });
  return violations;
};

/**
 * True when the document declares a column-zero `permissions:` block — the
 * house convention (validate.yml) that every workflow states its token
 * scope explicitly instead of inheriting the default.
 * @param {string} content workflow YAML text.
 * @returns {boolean}
 */
const hasTopLevelPermissions = (content) => /^permissions:(\s|$)/m.test(String(content ?? ''));

module.exports = { findUnpinnedUses, hasTopLevelPermissions };
```

- [ ] **Step 4: Wire into `tools/validate_repository.js`**

Insert AFTER the JavaScript syntax-check loop (after line ~240, before the
`if (failures.length > 0)` rollup), reusing the existing `safetyScanFiles`
census (already lstat-vetted regular files):

```js
// Workflow hygiene: every action reference is immutable (40-hex pin) and
// every workflow declares its token scope. Shallow regex checks by design —
// see tools/workflow_checks.js.
const { findUnpinnedUses, hasTopLevelPermissions } = require('./workflow_checks');
const workflowFiles = safetyScanFiles.filter(
  (name) => name.startsWith('.github/workflows/') && (name.endsWith('.yml') || name.endsWith('.yaml')),
);
const actionMetadataFiles = safetyScanFiles.filter((name) => /^actions\/[^/]+\/action\.ya?ml$/.test(name));
for (const file of [...workflowFiles, ...actionMetadataFiles]) {
  let content;
  try {
    content = readFileSync(path.join(root, file), 'utf8');
  } catch (error) {
    failures.push(`Workflow hygiene target cannot be read: ${file}: ${error.message}`);
    continue;
  }
  for (const violation of findUnpinnedUses(content)) {
    failures.push(`${file}:${violation.line} uses unpinned action reference: ${violation.ref}`);
  }
  if (workflowFiles.includes(file) && !hasTopLevelPermissions(content)) {
    failures.push(`${file} is missing a top-level permissions block`);
  }
}
```

(NOTE: the `require` line for `workflow_checks` may be hoisted to the top of the file
with the other requires — follow the file's existing layout; the git-tracked census
means new workflow files enter these checks automatically.)

- [ ] **Step 5: Run to verify green**

Run: `node --test --test-concurrency=1 tools/workflow_checks.test.js`
Expected: all pass, including the integration spawn (validator PASS on the real repo —
proving `validate.yml` and Task 5's three YAML files all satisfy both checks).
Then run `npm run validate` once directly and confirm `{"status":"PASS","payloadFiles":37,...}` —
payload count UNCHANGED at 37 (nothing entered the payload roots).

- [ ] **Step 6: Commit**

```bash
git add tools/workflow_checks.js tools/workflow_checks.test.js tools/validate_repository.js
git commit -m "feat(validate): SHA-pin and permissions hygiene checks for workflows and actions"
```

(with the standard two trailers)

---

### Task 7: Consumer docs — action README + main README pointer

**Files:**
- Create: `actions/closeout/README.md`
- Modify: `README.md` (one new section; find the section listing repository tooling — after the closeout gate description — and add a short pointer)

- [ ] **Step 1: Create `actions/closeout/README.md`**

Content requirements (write full prose, embedding the ACTUAL committed workflow files
from Task 5 as the examples — copy their final text verbatim into fenced blocks):

1. **What it is:** two-tier closeout gate as a composite action; strict = the 19-check
   evidence-first gate; engine = the same integrity engine over `config.engineChecks`,
   explicitly labeled a different, weaker guarantee.
2. **Quick start:** both workflow examples verbatim (preview + review-triggered gate),
   with the `uses: XGenerationy/codex-agents-debug-mode/actions/closeout@<commit-sha>`
   remote form shown alongside the local `./actions/closeout` dogfood form, and an
   explicit instruction to pin the action by commit SHA (practice what the validator
   preaches).
3. **Inputs/outputs:** tables matching action.yml exactly (every input, default, and
   output — keep in lockstep).
4. **Permissions matrix:** base `contents: read` + `pull-requests: read`;
   `pr-comment: true` additionally needs `pull-requests: write`; fork-PR note (preview
   works read-only; comment opt-in does not fire from forks).
5. **Failure semantics:** the exit decision table from the spec, in consumer terms —
   plan never fails for honest not-ready states; full propagates the gate verdict
   after evidence is surfaced.
6. **Attestation model:** review-triggered, head-SHA-bound, digest-bound; the
   four attestation states with the note that `weakened` is defensive-only today;
   machine consumers key on `status`/`attestation` outputs, never prose.
7. **Engine mode section:** a complete example `closeout.config.json` with
   `engineChecks` AND `requiredTools` (non-pnpm repos need it or preflight blocks),
   the make-gate rule stated honestly ("use `make <target>` or don't use make"),
   and the one-time digest migration note for consumers upgrading across it.
8. **Preview cost note:** strict plan runs the full 8-probe preflight (~27s measured
   with a running Docker daemon); engine narrows via `requiredTools`.
9. **Checkout requirements (consumer contract):** the gate needs full history —
   `fetch-depth: 0` on the consumer's checkout step is REQUIRED (the default depth-1
   checkout has no `origin/<branch>` refs and the gate errors); and an explicit
   `base-ref` input is passed to the CLI verbatim (no `origin/` prefixing — the
   operator's value is authoritative), while the automatic ladder branches prefix
   `origin/` because env/event carry bare branch names. State both explicitly.

Safety constraints for the doc itself: no credential-shaped strings (the validator's
`sk-`/`ghp_` patterns — write example tokens as `<your-token>`), no personal paths, no
raw control bytes. Any example digest strings must not collide with the credential
regex (`[A-Za-z0-9_-]{20,}` after `sk-`/`gh[pousr]_` prefixes — plain hex digests are
safe).

- [ ] **Step 2: Add the main README pointer**

In `README.md`, after the PR-closeout gate description section, add a short subsection:

```markdown
### Run the gate in CI

The gate ships as a composite GitHub Action at `actions/closeout/` — a read-only
plan preview for ordinary PR pushes and a review-triggered full gate, in strict or
engine mode. See [`actions/closeout/README.md`](actions/closeout/README.md); this
repository dogfoods both workflows (`closeout-preview.yml`, `closeout-gate.yml`).
```

(Adjust placement to the file's actual structure — read the README's table of
contents/section flow first; keep the addition to one subsection.)

- [ ] **Step 3: Verify and commit**

Run: `npm run validate` — expect PASS with payloadFiles still 37 (README.md is scanned
but not payload; the new action README enters the safety scan automatically).

```bash
git add actions/closeout/README.md README.md
git commit -m "docs(action): consumer README with permissions matrix, engine guidance, and dogfood examples"
```

(with the standard two trailers)

---

### Task 8: Full verification + review handoff

- [ ] **Step 1:** `npm test` — foreground, ONCE, 10-minute timeout; expect 0 fail
  (37+ platform skips OK; the count grows only by the new support/workflow-checks
  tests). Every pre-existing test passes unmodified.
- [ ] **Step 2:** `git diff codex/publish-debug-skill...HEAD --stat` — confirm ONLY:
  `actions/closeout/{action.yml,support.js,support.test.js,README.md}`,
  `.github/workflows/closeout-preview.yml`, `.github/workflows/closeout-gate.yml`,
  `tools/workflow_checks.js`, `tools/workflow_checks.test.js`,
  `tools/validate_repository.js`, `README.md`, the spec, and this plan. ZERO lines in
  any `scripts/pr_closeout_*` file, `scripts/debug_*`, `SKILL.md`, `agents/`,
  `assets/`, `references/`.
- [ ] **Step 3:** `npm run validate` → PASS with `payloadFiles: 37` (unchanged);
  `npm run scan:suppressions` → no findings; the gate-scan advisory prints for the
  validator change — expected and honest, report verbatim.
- [ ] **Step 4:** Append-only check over pre-existing test files:
  `git diff codex/publish-debug-skill...HEAD -- 'scripts/*.test.js' 'tools/scan_touched_suppressions.test.js' | grep '^-' | grep -v '^---'`
  must output nothing.
- [ ] **Step 5:** Report results to the coordinator; the final whole-implementation
  review follows via the coordinator's standing reviewer, then
  superpowers:finishing-a-development-branch.

---

## Spec test-group traceability

| Spec test group | Where |
|---|---|
| 1. Input validation fail-closed | Task 1 (`validateActionInputs` incl. casing; nothing spawns on invalid input — Task 4's runSubcommand validates before spawnCli) |
| 2. Exit decision table | Task 1 (`decideExit` all rows) + Task 4 (end-to-end: run records, finish applies) |
| 3. Summary rendering | Task 2 (four states distinct, weakened ≠ absent; verbatim embed; 512 KiB cap; hostile fixtures incl. control bytes via fromCharCode) |
| 4. Comment body + upsert | Task 3 (marker stability, PATCH-vs-POST, non-PR skip, 60 KiB cap) + Task 4 (commentSubcommand context detection; API failure propagates to a failing step via main's catch) |
| 5. Outputs | Task 4 (`writeOutputs` sanitization + per-tier population in both end-to-end tests) |
| 6. Validator | Task 6 (seeded violations as fixture strings; local `./` exempt; integration spawn proves the repo's own files pass; payload count pinned unchanged) |
| 7. Regression battery | Task 8 |

The composite YAML's runner-time behavior is integration-tested by the dogfood
workflows on this repo's own PRs (spec: recorded honestly; no pretend YAML unit test).
