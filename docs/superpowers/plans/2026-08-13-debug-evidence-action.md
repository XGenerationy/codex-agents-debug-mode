# Debug Evidence Action Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Package the debug collector + evidence tools as a composite GitHub Action at `actions/debug-evidence/` that wraps one failing command in an instrumented session, plus a new dual-mode single-session renderer `scripts/debug_report.js`.

**Architecture:** Clone the `actions/closeout` composite pattern — wiring-only `action.yml`, all logic in a zero-dependency `support.js` driven by `DEBUG_ACTION_*` env vars, state between steps in `action-state.json` at the output-dir root (never uploaded), evidence staged into an enumerated child dir. The collector runs programmatically via a detached boot shim (`collector_boot.js`) because only `createDebugServer` accepts limit overrides.

**Tech Stack:** Node ≥20 (`node:test`, `node:http`, `node:child_process`), zero npm dependencies, composite GitHub Action YAML, bash steps.

**Spec:** `docs/superpowers/specs/2026-08-13-debug-evidence-action-design.md` (as amended through commit `29570db`) is the requirements authority. This plan is the byte authority for code. On conflict: stop and escalate to the controller; do not silently pick one.

**Branch:** `feat/debug-evidence-action`. Every commit message ends with these two trailer lines exactly:

```
Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp
```

**Battery discipline:** run ONE test invocation at a time, foreground, never piped through `head`/`tail` (pipes mask exit codes and can cancel in-flight node tests). Targeted runs use `node --test <file>`; the full battery is `npm test`.

---

## Ground truth (verified against the working tree — do NOT re-derive from the 2,600-line server file)

**Collector (`scripts/debug_server.js`) facts:**
- `createDebugServer({ projectRoot, token, instanceId, allowedOrigins, limits, redactionEnv = { ...process.env }, redactionNames, redactionMaxTokens })` returns an UNSTARTED `node:http` server. There is **no port option** — the caller binds via `server.listen(port, '127.0.0.1', cb)`. Extra props: `collectorToken`, `collectorInstanceId`, `collectorProjectHash`, and `markCollectorReady()` which latches `/health`'s `ready: true`.
- `limits` merges over `DEFAULT_LIMITS`: `{ maxBodyBytes: 65536, bodyTimeoutMs: 30000, maxSessions: 32, sessionIdleTimeoutMs: 900000, maxEventsPerSession: 2000, maxTotalBytes: 16777216 }`.
- `POST /session` — header `Authorization: Bearer <launch token>`, body `{"name":"..."}` → `201 { session_id, session_token, log_file: ".debug/debug-<session_id>.log" }`. Session logs are `.log` files (NDJSON content), named `debug-<id>.log`.
- `POST /log` — session auth via header `x-debug-session-token` (or body `sessionToken`/`session_token`); session selected by body `sessionId`/`session_id`; `msg` required non-empty string; optional allowlisted fields `data`, `hypothesisId`, `loc`, `runId` → `202 {"status":"recorded"}`. Stored line: `{ ts: <server ISO>, msg, [data], [hypothesisId], [loc], [runId] }` — **no `type` field** (untyped lines classify as `event`).
- `POST /hypothesis` — **launch-token bearer auth only** (the session token cannot post hypotheses). Body `{ sessionId, hypothesisId, status ∈ {OPEN, CONFIRMED, REJECTED, INCONCLUSIVE}, [title], [note], [runId] }` → `202`. Stored line: `{ ts, type: 'hypothesis', hypothesisId, status, [title], [note], [runId] }`.
- `GET /health` (unauthenticated) → `{ service: 'codex-debug-collector', version: 1, instance_id, project_hash, ready, redaction_tokens, redaction_max_tokens }`.
- Exported probes: `probeServer(port, { deadlineMs = 2000 })` → identity object or null, never rejects; `probeReadyCollector(port, expectedProjectHash, { delayMs = 50, deadlineMs = 10000 })` → identity when ready+hash-matched, identity early on hash MISMATCH, null on deadline.
- Env parsing: `DEBUG_PORT` (integer 1–65535), `DEBUG_REDACT_NAMES` (comma-separated names), `DEBUG_ALLOWED_ORIGIN`. Redaction's env snapshot defaults to `{ ...process.env }` at `createDebugServer` call time — the shim must inherit the job env.
- `.debug/` contents written by the SERVER during operation: `project_salt` (private), session logs `debug-<id>.log` (sensitive). The CLI-only files (`collector_token`, `collector_port`, `collector_claim`) are NOT created on the programmatic path — the boot shim never writes them.

**Evidence core (`scripts/debug_evidence.js`) facts:**
- Exports: `createSessionTail, discoverCollector, escapeEvidenceText, filterEntries, foldHypotheses, listSessions, parseSessionText, readSessionFile, readSessionLive, resolveSessionRef`.
- `readSessionFile(filePath)` → `[{ raw, parsed }]`, drops a torn tail after the last newline, throws `malformed_session_line:<n>` on any bad line (fail closed).
- `resolveSessionRef(projectRoot, ref)`: refs ending `.log` pass through unchanged (file-path mode); otherwise `[A-Za-z0-9_-]+` ids map to `<root>/.debug/debug-<ref>.log`.
- `foldHypotheses(entries)` → `Map<hypothesisId, { hypothesisId, title, status, note, ts, history: [] }>`; only `type === 'hypothesis'` lines fold; latest wins for status/note/ts; first non-empty title wins. **Verdicts ARE the folded statuses** — there is no separate verdict type.
- `escapeEvidenceText(value)`: `JSON.stringify(String(value)).slice(1, -1)` then replaces U+2028/U+2029 with ` `/` ` escape text. Owner: debug_evidence.js.
- `debug_diff.js` layers a module-private `escapeText` on top: `escapeEvidenceText(value).replaceAll('│', '¦').replace(/[*_`\[\]()!<>&]/g, '\\$&')` — Task 1 promotes this to the shared core.
- CLI conventions: `debug_diff` uses equals-form `--format=<v>` ONLY (space form rejected); exit codes 0 success / 2 usage / 1 runtime (single clean stderr line, no stack). `debug_report.js` adopts the diff convention.

**Closeout action conventions to clone (`actions/closeout/`):**
- Pinned lines (copy byte-exact):
  - `uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6.5.0`
  - `uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2`
  - `uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3` (workflows only)
- `writeOutputs(outputFile, pairs)` helper (env-file path as first arg = the injectable seam); `GITHUB_STEP_SUMMARY` gets a guarded direct `appendFileSync`.
- Subcommand dispatch on `process.argv[2]`; terminal catch prefixes the action name and redacts secrets; `if (require.main === module) void main();` then alphabetized `module.exports`.
- Nonce protocol: the first subcommand exports `<PREFIX>_INVOCATION_NONCE` via `GITHUB_ENV` and records it in state; later subcommands reject a state whose nonce mismatches (return 3).
- Output-dir default expression is repeated verbatim at every use site: `${{ inputs.output-dir || format('{0}/debug-evidence', runner.temp) }}` for this action.
- Upload path blocks enumerate exact well-known filenames inside the evidence child — never a bare directory.
- Tests: `makeTempDir = () => mkdtempSync(path.join(tmpdir(), 'debug-evidence-action-'))`; action.yml asserted as plain text with regex (no YAML parser); secret-containment tests spawn the real entry point and build tokens by array-join so the validator's credential scan never trips on test source.

**Repo integration facts:**
- `tools/validate_repository.js` census: `payloadEntries = ['SKILL.md', 'agents', 'assets', 'references', 'scripts']`, currently `!== 41` fails. Test files under `scripts/` count. Task 2 bumps 41 → 43 with a history comment.
- `actions/debug-evidence/action.yml` is automatically pin-checked (actionMetadataFiles regex `/(?:^|\/)action\.ya?ml$/` excluding workflows); it does NOT need a `permissions:` block. Any new `.github/workflows/*.yml` DOES need top-level `permissions:` + 40-hex pins.
- Gate retry-forwarder: `.github/workflows/closeout-gate.yml` line ~70 `workflows: ["Validate", "Closeout preview"]` — Task 7 adds `"Debug evidence demo"` (spec amendment: the forwarder un-sticks the GATE after it blocked on a pending sibling check; the demo is such a sibling).
- Gate self-exclusion collides only on identical workflow+job display names — the demo uses distinct names (`Debug evidence demo` / `demo`), nothing else needed.
- `package.json` test script: `node --test --test-concurrency=1` (recursive `*.test.js` discovery — new colocated test files are auto-discovered).

## File structure

| File | Status | Responsibility |
|---|---|---|
| `scripts/debug_evidence.js` | modify | gains shared `escapeMarkdownText` (promoted from debug_diff) |
| `scripts/debug_diff.js` | modify | drops its private `escapeText`, imports the shared one |
| `scripts/debug_report.js` | create | dual-mode single-session renderer (payload) |
| `scripts/debug_report.test.js` | create | renderer + CLI tests (payload) |
| `tools/validate_repository.js` | modify | census 41 → 43 |
| `actions/debug-evidence/collector_boot.js` | create | detached programmatic collector shim |
| `actions/debug-evidence/support.js` | create | all action logic: start/run/report/teardown/finish |
| `actions/debug-evidence/support.test.js` | create | hermetic subcommand + structural action.yml tests |
| `actions/debug-evidence/action.yml` | create | pure wiring |
| `actions/debug-evidence/demo/repro.js` | create | deterministic demo repro (action-local, non-payload) |
| `actions/debug-evidence/README.md` | create | consumer docs |
| `.github/workflows/debug-evidence-demo.yml` | create | dogfood workflow |
| `.github/workflows/closeout-gate.yml` | modify | retry-forwarder list + comment |
| `README.md`, `SKILL.md` | modify | document debug_report + CI action |

---

### Task 1: Promote markdown escaping into the shared evidence core

**Files:**
- Modify: `scripts/debug_evidence.js` (add `escapeMarkdownText`, export it)
- Modify: `scripts/debug_diff.js` (use the shared helper)
- Test: `scripts/debug_evidence.test.js` (append new tests)

- [ ] **Step 1: Write the failing test** — append to `scripts/debug_evidence.test.js` (find the existing `escapeEvidenceText` describe/test block and add alongside, matching the file's existing test style):

```js
test('escapeMarkdownText escapes markdown punctuation, box-drawing pipes, and control text on top of escapeEvidenceText', () => {
  const { escapeMarkdownText } = require('./debug_evidence');
  assert.equal(escapeMarkdownText('a*b_c`d[e]f(g)h!i<j>k&l'), 'a\\*b\\_c\\`d\\[e\\]f\\(g\\)h\\!i\\<j\\>k\\&l');
  assert.equal(escapeMarkdownText('col│umn'), 'col¦umn');
  // escapeEvidenceText layer still applies underneath: newline stays escaped text
  assert.equal(escapeMarkdownText('line1\nline2'), 'line1\\nline2');
});

test('escapeMarkdownText output is byte-identical to debug_diff\'s previous private escapeText for a hostile sample', () => {
  const { escapeMarkdownText } = require('./debug_evidence');
  const hostile = '│ **bold** [link](x) <img> & `tick` \n end';
  const expected = require('./debug_evidence').escapeEvidenceText(hostile)
    .replaceAll('│', '¦')
    .replace(/[*_`\[\]()!<>&]/g, '\\$&');
  assert.equal(escapeMarkdownText(hostile), expected);
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `node --test scripts/debug_evidence.test.js`
Expected: FAIL — `escapeMarkdownText` is not a function (not exported).

- [ ] **Step 3: Implement in `scripts/debug_evidence.js`** — add below `escapeEvidenceText` (keep its comment style), and add the export:

```js
// Markdown-surface escaping layered on the core helper: box-drawing pipes
// would break diff/report tables, and markdown punctuation in stored log
// content could restyle the surrounding document. Owned here so every
// markdown renderer (debug_diff, debug_report) shares one transform.
const MARKDOWN_PUNCTUATION = /[*_`\[\]()!<>&]/g;
const escapeMarkdownText = (value) => escapeEvidenceText(value)
  .replaceAll('│', '¦')
  .replace(MARKDOWN_PUNCTUATION, '\\$&');
```

Add `escapeMarkdownText,` to `module.exports` (keep alphabetical order: after `escapeEvidenceText`).

- [ ] **Step 4: Rewire `scripts/debug_diff.js`** — delete its module-local `MARKDOWN_PUNCTUATION` const and `escapeText` function; change its require of the core to also destructure the shared helper, and alias it so every call site stays untouched:

```js
const { escapeMarkdownText, foldHypotheses, parseSessionText, readSessionFile, resolveSessionRef } = require('./debug_evidence');
const escapeText = escapeMarkdownText;
```

(Match the actual destructuring list currently in debug_diff.js — add `escapeMarkdownText`, remove nothing else. If debug_diff currently imports `escapeEvidenceText` solely for its private escapeText, drop that name from the destructure.)

- [ ] **Step 5: Run both test files**

Run: `node --test scripts/debug_evidence.test.js`  → Expected: PASS
Run: `node --test scripts/debug_diff.test.js`      → Expected: PASS (output byte-identical; no diff test changes)

- [ ] **Step 6: Commit**

```bash
git add scripts/debug_evidence.js scripts/debug_diff.js scripts/debug_evidence.test.js
git commit -m "refactor(evidence): promote markdown escaping into the shared core for report/diff parity"
```

#### Task 1 fix round 1 — Codex review decisions (recorded before code moves)

Codex verdict on `b3ef193`: Issues (Minor ×3). Decisions:

1. **Golden-bytes parity test.** The parity test recomputed the old formula from the same
   building block (self-referential). Replace the reconstruction with HARDCODED expected
   output bytes for the hostile sample (compute once, paste the literal) so the test is a
   genuine regression pin independent of the implementation.
2. **Edge coverage.** Add one test pinning `escapeMarkdownText` for: `''` (empty → `''`),
   `'││'` (→ `'¦¦'`), pre-escaped `'\*'` input (backslash doubles then `*` escapes →
   `'\\\\\*'` as source-literal, i.e. backslash-backslash-backslash-asterisk in bytes),
   and an astral pair `'😀*'` (emoji passes through, `*` escaped). Pin exact bytes.
3. **Move the rationale comment.** Trim `scripts/debug_diff.js:120–146` to only the
   diff-renderer-specific rationale (why the TABLE renderer needs `¦`, the quoted-text
   call-site concern) plus a one-line pointer to `debug_evidence.js` as the transform
   owner — both reviewers agree the full normative copy would drift. No wording changes
   to what remains beyond the trim itself.

Fix commit message: `test(evidence): golden-byte parity + edge pins for escapeMarkdownText; trim diff-side comment (Codex T1 minors)`.

**Fix round 2 (Codex re-review of `6c20f91`):** all three fixes verified byte-for-byte
(golden literals match the live implementation; backslash case is `5c 5c 5c 2a`; exactly
one raw U+2028 in the hostile literal). One remaining Minor: the retained sentence at
`scripts/debug_diff.js:126` — "the one exception" — lost its antecedent in the trim.
Decision: reword that one sentence to Codex's suggested form, "Unlike Markdown
punctuation, the box-drawing pipe must become a DIFFERENT character (¦), …" keeping the
rest of the retained comment untouched. Commit message:
`docs(diff): fix dangling antecedent in escaping rationale (Codex T1 re-review)`.

---

### Task 2: `scripts/debug_report.js` — dual-mode single-session renderer (+ census 41 → 43)

**Files:**
- Create: `scripts/debug_report.js`
- Create: `scripts/debug_report.test.js`
- Modify: `tools/validate_repository.js` (census block)

- [ ] **Step 1: Write the failing tests** — create `scripts/debug_report.test.js`:

```js
'use strict';

const assert = require('node:assert');
const { execFile } = require('node:child_process');
const { mkdtemp, mkdir, rm, writeFile } = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const REPORT = path.join(__dirname, 'debug_report.js');
const { parseSessionText } = require('./debug_evidence');
const { buildReport, renderJson, renderMarkdown, renderText } = require('./debug_report');

const line = (object) => `${JSON.stringify(object)}\n`;

const run = (args) => new Promise((resolve) => {
  execFile(process.execPath, [REPORT, ...args], (error, stdout, stderr) => {
    resolve({ code: error ? error.code : 0, stdout, stderr });
  });
});

const SESSION = parseSessionText(
  line({ ts: '2026-08-13T10:00:01.000Z', msg: 'userId=null on first render', hypothesisId: 'H1' })
  + line({ ts: '2026-08-13T10:00:02.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'OPEN', title: 'null id' })
  + line({ ts: '2026-08-13T10:00:03.000Z', msg: 'render ok', hypothesisId: 'H1' })
  + line({ ts: '2026-08-13T10:00:04.000Z', msg: 'untagged noise' }),
);

test('buildReport counts events vs hypothesis lines and groups tagged events per hypothesis', () => {
  const report = buildReport(SESSION, { sessionId: 'demo-abc' });
  assert.equal(report.schema, 1);
  assert.equal(report.session.id, 'demo-abc');
  assert.equal(report.session.entries, 4);
  assert.equal(report.session.events, 3);
  assert.equal(report.session.hypothesisLines, 1);
  assert.equal(report.untaggedEvents, 1);
  assert.equal(report.hypotheses.length, 1);
  const h1 = report.hypotheses[0];
  assert.equal(h1.id, 'H1');
  assert.equal(h1.status, 'OPEN');
  assert.equal(h1.title, 'null id');
  assert.equal(h1.events, 2);
});

test('buildReport renders recorded statuses only — it never invents a verdict', () => {
  const report = buildReport(SESSION, { sessionId: null });
  assert.equal(report.hypotheses[0].status, 'OPEN');
  assert.ok(!('verdict' in report.hypotheses[0]), 'no synthesized verdict field');
});

test('excerpts keep the LAST events, cap at 20, and announce the overflow — no announce at exactly the cap', () => {
  const many = [];
  for (let i = 1; i <= 20; i += 1) many.push(line({ ts: '2026-08-13T10:00:05.000Z', msg: `m${i}` }));
  const exact = buildReport(parseSessionText(many.join('')), { sessionId: null });
  assert.equal(exact.excerpts.length, 20);
  assert.equal(exact.excerptsTruncated, 0);
  many.push(line({ ts: '2026-08-13T10:00:06.000Z', msg: 'm21' }));
  const over = buildReport(parseSessionText(many.join('')), { sessionId: null });
  assert.equal(over.excerpts.length, 20);
  assert.equal(over.excerpts[19], 'm21');
  assert.equal(over.excerpts[0], 'm2');
  assert.equal(over.excerptsTruncated, 1);
  const md = renderMarkdown(over);
  assert.ok(md.includes('…and 1 more earlier event'), 'announced overflow');
  assert.ok(!renderMarkdown(exact).includes('more earlier event'), 'no announce at exactly the cap');
});

test('renderMarkdown escapes hostile log content — structure reflects the renderer, never the log', () => {
  const hostile = buildReport(parseSessionText(
    line({ ts: '2026-08-13T10:00:01.000Z', msg: '## injected heading\n**bold** │ <img>' }),
  ), { sessionId: 'x' });
  const md = renderMarkdown(hostile);
  assert.ok(!md.includes('\n## injected heading'), 'stored newline must not open a real heading line');
  assert.ok(md.includes('\\*\\*bold\\*\\*'), 'markdown punctuation escaped');
  assert.ok(md.includes('¦'), 'box-drawing pipe swapped');
});

test('renderJson is verbatim machine output with schema 1 and no escaping layer', () => {
  const report = buildReport(SESSION, { sessionId: 'demo-abc' });
  const parsed = JSON.parse(renderJson(report));
  assert.equal(parsed.schema, 1);
  assert.equal(parsed.excerpts[0], 'userId=null on first render');
});

test('renderText and renderMarkdown are deterministic for identical input', () => {
  const a = buildReport(SESSION, { sessionId: 'demo-abc' });
  const b = buildReport(SESSION, { sessionId: 'demo-abc' });
  assert.equal(renderText(a), renderText(b));
  assert.equal(renderMarkdown(a), renderMarkdown(b));
});

const withSessionDir = async (fn) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'report-'));
  try {
    await mkdir(path.join(root, '.debug'));
    await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
};

test('CLI: piped default is markdown; --format=json parses with schema 1; session id derived from the filename', async () => {
  await withSessionDir(async (root) => {
    const file = path.join(root, '.debug', 'debug-demo-abc.log');
    await writeFile(file, SESSION.map((e) => `${e.raw}\n`).join(''), 'utf8');
    const md = await run(['demo-abc', root]);
    assert.equal(md.code, 0);
    assert.ok(md.stdout.startsWith('## Debug evidence report'), 'piped default renders markdown');
    const json = await run([file, '--format=json']);
    assert.equal(json.code, 0);
    assert.equal(JSON.parse(json.stdout).schema, 1);
    assert.equal(JSON.parse(json.stdout).session.id, 'demo-abc');
  });
});

test('CLI usage errors exit 2: unknown flag, space-form format, bad format value, wrong positional count', async () => {
  for (const args of [['a', '--nope'], ['a', '--format', 'md'], ['a', '--format=xml'], []]) {
    const result = await run(args);
    assert.equal(result.code, 2, `args ${JSON.stringify(args)} must exit 2`);
    assert.ok(result.stderr.includes('Usage:'), 'usage printed');
  }
});

test('CLI runtime failure exits 1 with one clean stderr line and no stack', async () => {
  await withSessionDir(async (root) => {
    const result = await run(['missing-session', root]);
    assert.equal(result.code, 1);
    const stderrLines = result.stderr.split('\n').filter(Boolean);
    assert.equal(stderrLines.length, 1);
    assert.ok(!result.stderr.includes(' at '), 'no stack frames');
  });
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test scripts/debug_report.test.js`
Expected: FAIL — `Cannot find module './debug_report'`.

- [ ] **Step 3: Create `scripts/debug_report.js`:**

```js
#!/usr/bin/env node
'use strict';

// Single-session evidence report: the CI/step-summary sibling of
// debug_viewer (live analysis) and debug_diff (two-session verify).
// Dual mode: interactive TTY gets a human text summary; piped output
// defaults to markdown (Step Summary use case); --format=json is the
// machine surface. The renderer never classifies — it folds and counts
// exactly what the session recorded.

const path = require('node:path');
const {
  escapeMarkdownText,
  foldHypotheses,
  readSessionFile,
  resolveSessionRef,
} = require('./debug_evidence');

const USAGE = 'Usage: debug_report.js <sessionRef> [projectRoot] [--format=text|md|json]';
const EXCERPT_CAP = 20;
const SESSION_FILE_PATTERN = /^debug-([A-Za-z0-9_-]+)\.log$/;

// Same equals-only convention as debug_diff (space-form values rejected).
const parseArgs = (args) => {
  const positional = [];
  let format;
  let formatSeen = false;
  for (const arg of args) {
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    if (arg.startsWith('--format=')) {
      if (formatSeen) return { error: 'duplicate --format flag' };
      formatSeen = true;
      format = arg.slice('--format='.length);
      continue;
    }
    if (arg === '--format') {
      return { error: '--format requires a value: --format=<text|md|json>' };
    }
    return { error: `unknown flag: ${arg}` };
  }
  return { positional, format };
};

const buildReport = (entries, { sessionId = null } = {}) => {
  const folded = foldHypotheses(entries);
  let events = 0;
  let hypothesisLines = 0;
  let untaggedEvents = 0;
  const taggedCounts = new Map();
  const allEventMsgs = [];
  for (const { parsed } of entries) {
    if (parsed.type === 'hypothesis') {
      hypothesisLines += 1;
      continue;
    }
    events += 1;
    allEventMsgs.push(typeof parsed.msg === 'string' ? parsed.msg : String(parsed.msg));
    if (typeof parsed.hypothesisId === 'string' && parsed.hypothesisId !== '') {
      taggedCounts.set(parsed.hypothesisId, (taggedCounts.get(parsed.hypothesisId) ?? 0) + 1);
    } else {
      untaggedEvents += 1;
    }
  }
  const ids = [...new Set([...folded.keys(), ...taggedCounts.keys()])]
    .filter((id) => typeof id === 'string' && id !== '')
    .sort();
  const hypotheses = ids.map((id) => {
    const record = folded.get(id);
    return {
      id,
      title: typeof record?.title === 'string' ? record.title : null,
      status: typeof record?.status === 'string' ? record.status : null,
      note: typeof record?.note === 'string' ? record.note : null,
      lines: record ? record.history.length : 0,
      events: taggedCounts.get(id) ?? 0,
    };
  });
  // Keep the LAST events — the tail is where a failing run's story ends.
  const excerpts = allEventMsgs.slice(-EXCERPT_CAP);
  return {
    schema: 1,
    session: { id: sessionId, entries: entries.length, events, hypothesisLines },
    hypotheses,
    untaggedEvents,
    excerpts,
    excerptsTruncated: Math.max(0, allEventMsgs.length - EXCERPT_CAP),
  };
};

const renderJson = (report) => `${JSON.stringify(report, null, 2)}\n`;

const statusOr = (status) => (status === null ? '—' : escapeMarkdownText(status));

const renderMarkdown = (report) => {
  const lines = ['## Debug evidence report', ''];
  const id = report.session.id === null ? '(file)' : escapeMarkdownText(report.session.id);
  lines.push(`_session ${id} · ${report.session.events} events · ${report.session.hypothesisLines} hypothesis lines_`);
  lines.push('');
  for (const h of report.hypotheses) {
    const title = h.title ? ` — ${escapeMarkdownText(h.title)}` : '';
    lines.push(`**${escapeMarkdownText(h.id)}${title}**  ${statusOr(h.status)}`);
    lines.push('');
    lines.push(`- events ${h.events} · hypothesis lines ${h.lines}`);
    if (h.note) lines.push(`- note: "${escapeMarkdownText(h.note)}"`);
    lines.push('');
  }
  if (report.untaggedEvents > 0) {
    lines.push(`_untagged events: ${report.untaggedEvents}_`);
    lines.push('');
  }
  if (report.excerpts.length > 0) {
    lines.push('**Last events**');
    lines.push('');
    for (const msg of report.excerpts) lines.push(`- "${escapeMarkdownText(msg)}"`);
    if (report.excerptsTruncated > 0) lines.push(`- …and ${report.excerptsTruncated} more earlier event${report.excerptsTruncated === 1 ? '' : 's'}`);
    lines.push('');
  }
  return `${lines.join('\n')}\n`;
};

const renderText = (report) => {
  const lines = [];
  const id = report.session.id === null ? '(file)' : escapeMarkdownText(report.session.id);
  lines.push(`Debug evidence report — session ${id}`);
  lines.push(`entries ${report.session.entries} · events ${report.session.events} · hypothesis lines ${report.session.hypothesisLines} · untagged ${report.untaggedEvents}`);
  lines.push('');
  for (const h of report.hypotheses) {
    const title = h.title ? ` — ${escapeMarkdownText(h.title)}` : '';
    lines.push(`${escapeMarkdownText(h.id)}${title}  [${statusOr(h.status)}]  events ${h.events}`);
    if (h.note) lines.push(`  note: ${escapeMarkdownText(h.note)}`);
  }
  if (report.hypotheses.length > 0) lines.push('');
  if (report.excerpts.length > 0) {
    lines.push('last events:');
    for (const msg of report.excerpts) lines.push(`  - ${escapeMarkdownText(msg)}`);
    if (report.excerptsTruncated > 0) lines.push(`  …and ${report.excerptsTruncated} more earlier`);
  }
  return `${lines.join('\n')}\n`;
};

const deriveSessionId = (resolvedPath) => {
  const match = SESSION_FILE_PATTERN.exec(path.basename(resolvedPath));
  return match ? match[1] : null;
};

const main = async () => {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.error) {
    process.stderr.write(`debug_report: ${parsed.error}\n${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const { positional } = parsed;
  if (positional.length < 1 || positional.length > 2) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const format = parsed.format ?? (process.stdout.isTTY ? 'text' : 'md');
  if (!['text', 'md', 'json'].includes(format)) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const [ref, projectRoot = process.cwd()] = positional;
  const filePath = resolveSessionRef(projectRoot, ref);
  let entries;
  try {
    entries = await readSessionFile(filePath);
  } catch (error) {
    process.stderr.write(`debug_report: cannot read session (${ref}): ${error.message}\n`);
    process.exitCode = 1;
    return;
  }
  const report = buildReport(entries, { sessionId: deriveSessionId(filePath) });
  if (format === 'json') process.stdout.write(renderJson(report));
  else if (format === 'md') process.stdout.write(renderMarkdown(report));
  else process.stdout.write(renderText(report));
};

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { buildReport, parseArgs, renderJson, renderMarkdown, renderText };
```

- [ ] **Step 4: Run tests**

Run: `node --test scripts/debug_report.test.js`
Expected: PASS (all tests).

- [ ] **Step 5: Bump the payload census** — in `tools/validate_repository.js`, extend the history comment and change both literals `41` in the census block to `43`:

```js
// 37 -> 41: pr_closeout_retry.js + gate_retry_cli.js (workflow_run retry /
// base-branch-drift gate re-verification, chatgpt-codex-connector PR7
// #6YaxWe / #6YbMwY) plus their two test modules.
// 41 -> 43: debug_report.js (single-session CI/Step Summary renderer,
// cycle 4 debug-evidence action) + debug_report.test.js.
if (payloadFiles.length !== 43) {
  failures.push(`Expected 43 skill payload files, found ${payloadFiles.length}`);
}
```

- [ ] **Step 6: Run the validator**

Run: `npm run validate`
Expected: `{"status":"PASS","payloadFiles":43,...}` (safetyScanFiles/javascriptFiles counts will also rise — any FAIL line means a stray untracked file under a payload root; investigate, don't force).

- [ ] **Step 7: Commit**

```bash
git add scripts/debug_report.js scripts/debug_report.test.js tools/validate_repository.js
git commit -m "feat(report): dual-mode single-session evidence renderer + census 43"
```

#### Task 2 fix round 1 — Codex review decisions (recorded before code moves)

Codex verdict on `a5cf2c0`: Issues (Important ×4, Minor ×1). All accepted:

1. **Verbatim-safe msg rendering.** `buildReport` must never `String()`-coerce:
   `typeof parsed.msg === 'string' ? parsed.msg : parsed.msg === undefined ? '(missing msg)' : JSON.stringify(parsed.msg)`.
   Values from `JSON.parse` cannot be circular, so `JSON.stringify` is total once
   `undefined` is handled first. Pins: `{msg:{x:1}}` → `'{"x":1}'`; missing msg →
   `'(missing msg)'`; `{msg:{toString:null}}` renders without throwing.
2. **Forward-compatible line classification** (parity with the shared core and
   `GET /sessions/:id/logs`): `parsed.type === undefined` → event; `'hypothesis'` →
   hypothesis line; ANY other type → counted only in a new `session.otherTypedLines`
   field (still in `entries`), never in events or excerpts. Schema stays `1`
   (pre-release). Update the counts test; add a typed-line fixture test.
3. **Announced render caps** bound md/text output (GitHub Step Summary is 1 MiB):
   `EXCERPT_CHAR_CAP = 500` per excerpt msg, `FIELD_CHAR_CAP = 200` for title/note —
   applied at RENDER time in `renderMarkdown`/`renderText` via a `capped(value, cap)`
   helper (over-cap → slice to cap−1 chars + `…`, total length exactly cap; at exactly
   cap → unchanged). `renderJson` stays verbatim — the machine surface is bounded by the
   collector's own 16 MB session limits. Boundary tests both sides of each cap.
4. **Add `~` to the shared `MARKDOWN_PUNCTUATION`** in `scripts/debug_evidence.js`
   (→ `/[*_`\[\]()!<>&~]/g`) — closes GFM strikethrough forging. Extend the Task 1
   escaping test with `'a~b'` → `'a\~b'` and `'~~x~~'` → `'\~\~x\~\~'`. The Task 1
   golden hostile literal contains no `~`, so it stays valid (verify). `debug_diff`'s
   changed behavior on `~` content is intentional hardening; its tests exercise no `~`
   (verify; adjust only if a pin actually trips, and report it).
5. **One-line stderr always**: both catch paths collapse newlines in the message
   (`.replace(/\r?\n|\r/g, ' ')`) before writing. Test: a ref that resolves to an error
   message with an embedded newline still produces exactly one stderr line.

Files: `scripts/debug_report.js`, `scripts/debug_report.test.js`,
`scripts/debug_evidence.js`, `scripts/debug_evidence.test.js`
(+ `scripts/debug_diff.test.js` only if a pin trips — report it).
Fix commit message:
`fix(report): verbatim-safe msg, typed-line parity, announced render caps, tilde escaping, one-line stderr (Codex T2)`.

**Fix round 2 (Codex re-review of `ab15cc0`):** usage-path newline residue ruled
acceptable (caller-controlled, deliberately two lines, not evidence-derived). Two
remaining findings, both accepted:

1. **Report-level render bound (Important).** Per-field caps don't bound the document —
   a collector-valid 2,000-hypothesis session measured 1,732,966 bytes of markdown.
   Decisions: `HYPOTHESIS_RENDER_CAP = 100` hypothesis blocks in md/text, announced
   (`…and N more hypotheses (full list in report.json)` — md footer italic, text plain;
   no announce at exactly 100); additionally cap the ESCAPED id at `FIELD_CHAR_CAP`
   (200) and the escaped status at 40 via the same `capped()` helper, in both human
   renderers. Worst case is then ~100 KB, safely under GitHub's 1 MiB. `renderJson`
   stays verbatim. Boundary tests at 100/101 hypotheses plus long-id/long-status pins.
2. **Surrogate-safe truncation (Minor).** `capped()` must not split a surrogate pair:
   after slicing, if the last code unit is an unpaired high surrogate (0xD800–0xDBFF),
   drop it before appending `…` (result length cap−1 is acceptable in that case). Pin
   with an emoji-boundary test (e.g. 101 × `😀` title: no replacement character in the
   UTF-8 output, ends with a whole emoji then `…`).

Fix commit message:
`fix(report): report-level render bound + surrogate-safe truncation (Codex T2 r2)`.

**Fix round 3 (Codex re-review of `caeb57d`):** cap design and arithmetic verified
(corrected ceiling ≈ 228,968 bytes, 4.58× margin); announce placement approved;
uncapped `session.id` accepted (CLI-bounded; renderer not a public API). One Minor,
overriding this plan's own literal: pluralize the hypothesis announce —
`…and ${n} more ${n === 1 ? 'hypothesis' : 'hypotheses'} (full list in report.json)`
in both human renderers, matching the excerpt announce's pluralization; update the
pinned test. Commit: `fix(report): pluralize hypothesis overflow announce (Codex T2 r3)`.

---

### Task 3: Action foundation — boot shim, `start`, `teardown`, state, validation

**Files:**
- Create: `actions/debug-evidence/collector_boot.js`
- Create: `actions/debug-evidence/support.js`
- Create: `actions/debug-evidence/support.test.js`

- [ ] **Step 1: Create `actions/debug-evidence/collector_boot.js`** (no test of its own — it is exercised through `startSubcommand` with the real spawn):

```js
'use strict';

// Boot shim for actions/debug-evidence: runs the collector PROGRAMMATICALLY
// (the CLI has no limit overrides) as a detached child of the `start` step.
// stdout is a PRIVATE pipe read once by support.js — the launch token in the
// startup line below never reaches step logs, outputs, or the artifact.
// The CLI's .debug/collector_token / collector_port / collector_claim files
// are deliberately NOT written: the only credential handoff is this pipe.

const path = require('node:path');
const { createDebugServer } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_server.js'));

const fail = (reason) => {
  process.stderr.write(`${JSON.stringify({ status: 'error', reason })}\n`);
  process.exitCode = 1;
};

const parsePositiveInt = (value) => {
  if (!value) return undefined;
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 ? n : null;
};

const main = () => {
  const projectRoot = process.argv[2] || process.cwd();
  const port = Number(process.env.DEBUG_PORT || 8787);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return fail('invalid_port');
  const limits = {};
  const maxEvents = parsePositiveInt(process.env.DEBUG_ACTION_MAX_EVENTS);
  const maxBytes = parsePositiveInt(process.env.DEBUG_ACTION_MAX_BYTES);
  if (maxEvents === null || maxBytes === null) return fail('invalid_limits');
  if (maxEvents !== undefined) limits.maxEventsPerSession = maxEvents;
  if (maxBytes !== undefined) limits.maxTotalBytes = maxBytes;
  // redactionEnv defaults to { ...process.env } inside createDebugServer, and
  // this shim inherits the full job env from `start` — that inheritance is the
  // redaction guarantee for job secrets (spec Security invariant 3).
  const server = createDebugServer({
    projectRoot,
    limits,
    redactionNames: String(process.env.DEBUG_REDACT_NAMES ?? '')
      .split(',').map((name) => name.trim()).filter(Boolean),
  });
  server.on('error', (error) => {
    fail(error?.code === 'EADDRINUSE' ? 'port_in_use' : 'listen_failed');
  });
  server.listen(port, '127.0.0.1', () => {
    server.markCollectorReady();
    process.stdout.write(`${JSON.stringify({
      status: 'started',
      port,
      pid: process.pid,
      project_hash: server.collectorProjectHash,
      launch_token: server.collectorToken,
    })}\n`);
  });
};

main();
```

- [ ] **Step 2: Write the failing tests** — create `actions/debug-evidence/support.test.js`:

```js
'use strict';

const assert = require('node:assert');
const { readFileSync, writeFileSync, mkdtempSync } = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  finishSubcommand,
  readState,
  redactKnownSecrets,
  reportSubcommand,
  resolveEvidenceDir,
  runSubcommand,
  startSubcommand,
  teardownSubcommand,
  validateActionInputs,
  writeOutputs,
  writeState,
} = require('./support');

const makeTempDir = () => mkdtempSync(path.join(os.tmpdir(), 'debug-evidence-action-'));

const getFreePort = () => new Promise((resolve) => {
  const srv = net.createServer();
  srv.listen(0, '127.0.0.1', () => {
    const { port } = srv.address();
    srv.close(() => resolve(port));
  });
});

const baseInputs = (overrides = {}) => ({
  runCommand: 'true',
  sessionName: 'ci-debug',
  workingDirectory: '.',
  failOnCommandFailure: 'true',
  port: '8787',
  redactNames: '',
  maxEvents: '',
  maxBytes: '',
  hypothesisId: '',
  hypothesisTitle: '',
  ...overrides,
});

test('validateActionInputs accepts the defaults and rejects each malformed field', () => {
  assert.deepEqual(validateActionInputs({ ...baseInputs(), outputDir: '/tmp/x', workspace: '' }), []);
  const cases = [
    [{ runCommand: '  ' }, /run: a command is required/],
    [{ sessionName: 'bad name!' }, /session-name/],
    [{ failOnCommandFailure: 'yes' }, /fail-on-command-failure/],
    [{ port: '70000' }, /port/],
    [{ port: 'abc' }, /port/],
    [{ maxEvents: '0' }, /max-events/],
    [{ maxBytes: '-5' }, /max-bytes/],
    [{ hypothesisId: 'has space' }, /hypothesis-id/],
  ];
  for (const [override, pattern] of cases) {
    const errors = validateActionInputs({ ...baseInputs(override), outputDir: '/tmp/x', workspace: '' });
    assert.ok(errors.some((e) => pattern.test(e)), `expected ${pattern} in ${JSON.stringify(errors)}`);
  }
});

test('validateActionInputs rejects an output-dir inside the workspace and CR/LF in paths', () => {
  const workspace = makeTempDir();
  const inside = validateActionInputs({ ...baseInputs(), outputDir: path.join(workspace, 'evidence'), workspace });
  assert.ok(inside.some((e) => /outside the repository workspace/.test(e)));
  const crlf = validateActionInputs({ ...baseInputs(), outputDir: '/tmp/x\ny', workspace: '' });
  assert.ok(crlf.some((e) => /must not contain a CR or LF/.test(e)));
});

test('start boots a real collector, records state outside the evidence subdir, and never echoes the token', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const port = await getFreePort();
  const githubEnv = path.join(outputDir, 'github_env');
  writeFileSync(githubEnv, '');
  const code = await startSubcommand({
    inputs: baseInputs({ port: String(port) }),
    outputDir,
    projectRoot,
    env: { GITHUB_ENV: githubEnv },
  });
  assert.equal(code, 0);
  const state = readState(outputDir);
  try {
    assert.equal(state.port, port);
    assert.ok(Number.isInteger(state.pid) && state.pid > 0);
    assert.ok(typeof state.launchToken === 'string' && state.launchToken.length >= 32);
    assert.ok(!path.dirname(path.join(outputDir, 'action-state.json')).includes(resolveEvidenceDir(outputDir)),
      'state lives at the output-dir root, not inside the evidence child');
    const envFile = readFileSync(githubEnv, 'utf8');
    assert.match(envFile, /DEBUG_ACTION_INVOCATION_NONCE=/);
    assert.ok(!envFile.includes(state.launchToken), 'launch token never enters GITHUB_ENV');
  } finally {
    teardownSubcommand({ outputDir, env: {} });
  }
});

test('teardown is idempotent: dead pid is success, missing state is success, nonce mismatch is 3', async () => {
  const outputDir = makeTempDir();
  assert.equal(teardownSubcommand({ outputDir, env: {} }), 0, 'missing state = start never ran = success');
  writeState(outputDir, { nonce: 'n1', pid: 999999999 });
  assert.equal(teardownSubcommand({ outputDir, env: {} }), 0, 'ESRCH on a dead pid is success');
  assert.equal(teardownSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'other' } }), 3, 'nonce mismatch refuses to trust state');
});

test('start surfaces a shim error line as a failure and start timeout kills the child', async () => {
  const outputDir = makeTempDir();
  const silent = { stdout: { on: () => {}, destroy: () => {} }, stderr: { on: () => {}, destroy: () => {} }, on: () => {}, kill: () => {}, unref: () => {} };
  await assert.rejects(
    () => startSubcommand({
      inputs: baseInputs(), outputDir, projectRoot: makeTempDir(), env: {},
      spawnShim: () => silent, readyTimeoutMs: 200,
    }),
    /did not report startup/,
  );
});

test('redactKnownSecrets replaces every occurrence of each known token and ignores short values', () => {
  const secret = ['tok', 'en-', 'abcdefghij'].join('');
  assert.equal(redactKnownSecrets(`x ${secret} y ${secret}`, [secret, 'short']),
    'x [REDACTED] y [REDACTED]');
});
```

- [ ] **Step 3: Run to verify failure**

Run: `node --test actions/debug-evidence/support.test.js`
Expected: FAIL — `Cannot find module './support'`.

- [ ] **Step 4: Create `actions/debug-evidence/support.js`** with the foundation (Task 4 and Task 5 append `runSubcommand` / `reportSubcommand` / `finishSubcommand`; create them now as stubs that throw `not implemented` so the export list is stable):

```js
'use strict';

// All logic for actions/debug-evidence lives here; action.yml is wiring only.
// Subcommands: start | run | report | teardown | finish, driven by
// DEBUG_ACTION_* env vars. State travels via action-state.json at the
// OUTPUT-DIR ROOT — deliberately outside the evidence child, because it
// carries the collector launch token and must never be uploaded.

const { appendFileSync, copyFileSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { spawn, spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const { probeReadyCollector, probeServer } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_server.js'));

const STATE_FILE = 'action-state.json';
const EVIDENCE_SUBDIR = 'debug-evidence-files';
const BOOT_SHIM = path.join(__dirname, 'collector_boot.js');
const REPORT_CLI = path.join(__dirname, '..', '..', 'scripts', 'debug_report.js');
const NAME_PATTERN = /^[A-Za-z0-9_-]+$/;

const resolveEvidenceDir = (outputDir) => path.join(outputDir, EVIDENCE_SUBDIR);

// Same helper contract as actions/closeout: the env-file path is the first
// argument so tests inject a temp file instead of the real GITHUB_OUTPUT.
const writeOutputs = (outputFile, pairs) => {
  const lines = Object.entries(pairs)
    .map(([name, value]) => `${name}=${String(value ?? '').replace(/\r?\n|\r/g, ' ')}`)
    .join('\n');
  appendFileSync(outputFile, `${lines}\n`);
};

const redactKnownSecrets = (text, secrets) => {
  let result = String(text);
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 8) {
      result = result.split(secret).join('[REDACTED]');
    }
  }
  return result;
};

const validateActionInputs = ({
  runCommand, sessionName, failOnCommandFailure, port, maxEvents, maxBytes,
  hypothesisId, workingDirectory = '.', outputDir = '', workspace = '',
}) => {
  const errors = [];
  if (!runCommand || !runCommand.trim()) errors.push('run: a command is required');
  if (!NAME_PATTERN.test(sessionName)) errors.push('session-name: must match [A-Za-z0-9_-]+');
  if (failOnCommandFailure !== 'true' && failOnCommandFailure !== 'false') {
    errors.push("fail-on-command-failure: must be 'true' or 'false'");
  }
  const portNumber = Number(port);
  if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
    errors.push('port: must be an integer between 1 and 65535');
  }
  for (const [name, value] of [['max-events', maxEvents], ['max-bytes', maxBytes]]) {
    if (value !== '' && (!/^\d+$/.test(value) || Number(value) < 1)) {
      errors.push(`${name}: must be a positive integer or empty`);
    }
  }
  if (hypothesisId !== '' && !NAME_PATTERN.test(hypothesisId)) {
    errors.push('hypothesis-id: must match [A-Za-z0-9_-]+ or be empty');
  }
  if (/[\r\n]/.test(workingDirectory) || /[\r\n]/.test(outputDir)) {
    errors.push('working-directory/output-dir: must not contain a CR or LF');
  }
  if (workspace) {
    const relative = path.relative(path.resolve(workspace), path.resolve(outputDir));
    if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) {
      errors.push('output-dir: must be outside the repository workspace');
    }
  }
  return errors;
};

const writeState = (outputDir, state) => {
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(path.join(outputDir, STATE_FILE), `${JSON.stringify(state)}\n`, { mode: 0o600 });
};

const readState = (outputDir) => {
  try {
    return JSON.parse(readFileSync(path.join(outputDir, STATE_FILE), 'utf8'));
  } catch {
    return null;
  }
};

const rejectForeignNonce = (state, env, subcommand) => {
  if (env.DEBUG_ACTION_INVOCATION_NONCE && state.nonce !== env.DEBUG_ACTION_INVOCATION_NONCE) {
    process.stderr.write(`debug-evidence-action: ${subcommand}: recorded state does not carry this invocation's nonce (output-dir overwritten by a concurrent run, or never written by this run); refusing to trust it.\n`);
    return true;
  }
  return false;
};

const defaultSpawnShim = (args, { env }) => spawn(process.execPath, [BOOT_SHIM, ...args], {
  env,
  detached: true,
  stdio: ['ignore', 'pipe', 'pipe'],
});

// Read the shim's single startup line (private pipe). Resolves the parsed
// JSON object; rejects on timeout, child exit, or unparsable output.
const readShimStartLine = (child, timeoutMs) => new Promise((resolve, reject) => {
  let settled = false;
  let stdout = '';
  let stderr = '';
  const settle = (fn, value) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    fn(value);
  };
  const timer = setTimeout(() => {
    settle(reject, new Error(`collector shim did not report startup within ${timeoutMs}ms`));
  }, timeoutMs);
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
    const newline = stdout.indexOf('\n');
    if (newline === -1) return;
    try {
      settle(resolve, JSON.parse(stdout.slice(0, newline)));
    } catch {
      settle(reject, new Error('collector shim printed an unparsable startup line'));
    }
  });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.on('exit', () => {
    let reason = 'exited before startup';
    try { reason = JSON.parse(stderr.split('\n')[0]).reason ?? reason; } catch {}
    settle(reject, new Error(`collector shim did not report startup: ${reason}`));
  });
});

const startSubcommand = async ({
  inputs, outputDir, env = process.env, projectRoot = process.cwd(),
  spawnShim = defaultSpawnShim, probeReady = probeReadyCollector,
  nonce = randomUUID(), readyTimeoutMs = Number(env.DEBUG_ACTION_READY_TIMEOUT_MS || 15_000),
}) => {
  const errors = validateActionInputs({ ...inputs, outputDir, workspace: env.GITHUB_WORKSPACE || '' });
  if (errors.length > 0) throw new Error(`invalid inputs: ${errors.join('; ')}`);
  if (env.GITHUB_ENV) writeOutputs(env.GITHUB_ENV, { DEBUG_ACTION_INVOCATION_NONCE: nonce });
  const shimEnv = { ...env, DEBUG_PORT: inputs.port };
  if (inputs.maxEvents) shimEnv.DEBUG_ACTION_MAX_EVENTS = inputs.maxEvents;
  if (inputs.maxBytes) shimEnv.DEBUG_ACTION_MAX_BYTES = inputs.maxBytes;
  // Input redact-names EXTENDS (never replaces) any job-level DEBUG_REDACT_NAMES.
  if (inputs.redactNames) {
    shimEnv.DEBUG_REDACT_NAMES = [env.DEBUG_REDACT_NAMES, inputs.redactNames].filter(Boolean).join(',');
  }
  const child = spawnShim([projectRoot], { env: shimEnv });
  let startLine;
  try {
    startLine = await readShimStartLine(child, readyTimeoutMs);
  } catch (error) {
    try { child.kill(); } catch {}
    throw error;
  }
  if (startLine.status !== 'started') {
    throw new Error(`collector failed to start: ${startLine.reason ?? 'unknown'}`);
  }
  const identity = await probeReady(Number(inputs.port), startLine.project_hash, { deadlineMs: readyTimeoutMs });
  if (!identity || identity.project_hash !== startLine.project_hash || identity.ready !== true) {
    try { process.kill(startLine.pid); } catch {}
    throw new Error('collector did not become ready before the timeout');
  }
  child.stdout.destroy();
  child.stderr.destroy();
  child.unref();
  writeState(outputDir, {
    nonce,
    pid: startLine.pid,
    port: Number(inputs.port),
    launchToken: startLine.launch_token,
    projectRoot,
    sessionName: inputs.sessionName,
    hypothesisId: inputs.hypothesisId,
    hypothesisTitle: inputs.hypothesisTitle,
    failOnCommandFailure: inputs.failOnCommandFailure,
  });
  return 0;
};

const teardownSubcommand = ({ outputDir, env = process.env, kill = process.kill }) => {
  const state = readState(outputDir);
  if (!state) return 0; // start never wrote state — nothing to tear down
  if (rejectForeignNonce(state, env, 'teardown')) return 3;
  if (!Number.isInteger(state.pid) || state.pid < 1) {
    process.stderr.write('debug-evidence-action: teardown: recorded state carries no usable pid.\n');
    return 3;
  }
  try {
    kill(state.pid);
  } catch (error) {
    if (error?.code === 'ESRCH') return 0; // already gone — success, not a leak
    process.stderr.write(`debug-evidence-action: teardown: failed to stop collector pid ${state.pid}: ${error?.code ?? error}\n`);
    return 3;
  }
  return 0;
};

// Implemented in later tasks — stable export surface from day one.
const runSubcommand = async () => { throw new Error('not implemented: runSubcommand (Task 4)'); };
const reportSubcommand = async () => { throw new Error('not implemented: reportSubcommand (Task 5)'); };
const finishSubcommand = () => { throw new Error('not implemented: finishSubcommand (Task 5)'); };

const collectStateSecrets = (state) => [state?.launchToken, state?.sessionToken].filter(Boolean);

const main = async () => {
  const [subcommand] = process.argv.slice(2);
  const env = process.env;
  const outputDir = env.DEBUG_ACTION_OUTPUT_DIR
    || path.join(env.RUNNER_TEMP || os.tmpdir(), 'debug-evidence');
  const inputs = {
    runCommand: env.DEBUG_ACTION_RUN || '',
    sessionName: env.DEBUG_ACTION_SESSION_NAME || 'ci-debug',
    workingDirectory: env.DEBUG_ACTION_WORKDIR || '.',
    failOnCommandFailure: env.DEBUG_ACTION_FAIL_ON_COMMAND_FAILURE || 'true',
    port: env.DEBUG_ACTION_PORT || '8787',
    redactNames: env.DEBUG_ACTION_REDACT_NAMES || '',
    maxEvents: env.DEBUG_ACTION_MAX_EVENTS_INPUT || '',
    maxBytes: env.DEBUG_ACTION_MAX_BYTES_INPUT || '',
    hypothesisId: env.DEBUG_ACTION_HYPOTHESIS_ID || '',
    hypothesisTitle: env.DEBUG_ACTION_HYPOTHESIS_TITLE || '',
  };
  try {
    if (subcommand === 'start') {
      process.exitCode = await startSubcommand({ inputs, outputDir, env, projectRoot: env.GITHUB_WORKSPACE || process.cwd() });
    } else if (subcommand === 'run') {
      process.exitCode = await runSubcommand({ inputs, outputDir, env });
    } else if (subcommand === 'report') {
      process.exitCode = await reportSubcommand({ outputDir, env });
    } else if (subcommand === 'teardown') {
      process.exitCode = teardownSubcommand({ outputDir, env });
    } else if (subcommand === 'finish') {
      process.exitCode = finishSubcommand({ outputDir, env });
    } else {
      throw new Error(`Unknown subcommand: ${subcommand ?? '(none)'}. Use start, run, report, teardown, or finish.`);
    }
  } catch (error) {
    const secrets = collectStateSecrets(readState(outputDir));
    process.stderr.write(`debug-evidence-action: ${redactKnownSecrets(error?.message ?? String(error), secrets)}\n`);
    process.exitCode = 1;
  }
};

if (require.main === module) void main();

module.exports = {
  finishSubcommand,
  readShimStartLine,
  readState,
  redactKnownSecrets,
  reportSubcommand,
  resolveEvidenceDir,
  runSubcommand,
  startSubcommand,
  teardownSubcommand,
  validateActionInputs,
  writeOutputs,
  writeState,
};
```

Note the deliberate env-name split: the *step wiring* passes limit inputs as `DEBUG_ACTION_MAX_EVENTS_INPUT`/`DEBUG_ACTION_MAX_BYTES_INPUT`, and `start` re-exports them to the SHIM as `DEBUG_ACTION_MAX_EVENTS`/`DEBUG_ACTION_MAX_BYTES` — otherwise the shim would also see unrelated `DEBUG_ACTION_*` wiring vars, and the two consumers' contracts stay independent.

- [ ] **Step 5: Run the tests**

Run: `node --test actions/debug-evidence/support.test.js`
Expected: PASS (start/teardown tests boot a real collector on a free port; ~2–5s).

- [ ] **Step 6: Commit**

```bash
git add actions/debug-evidence/collector_boot.js actions/debug-evidence/support.js actions/debug-evidence/support.test.js
git commit -m "feat(action): debug-evidence foundation — boot shim, start/teardown, state + validation"
```

#### Task 3 fix round 1 — Codex review decisions (recorded before code moves)

Codex verdict on `5e3b69f`: Issues (Important ×5, Minor ×2), all with adversarial
reproductions. All accepted. Ruled fine: hex/whitespace port strings (resolve to valid
ports; contract says integer), the unreachable non-`started` branch, unbound
`process.kill`, held Task-4/5 scaffolding.

1. **EPIPE survival (Important).** The collector outlives the `start` step, so any
   post-start diagnostic write to a dead pipe could kill it. Two layers: (a) in
   `collector_boot.js`, after constructing the server, attach no-op `'error'` handlers
   to `process.stdout` and `process.stderr` so EPIPE is swallowed for the collector's
   lifetime; (b) in `startSubcommand`, release the pipes with
   `removeAllListeners('data')` + `.resume()` + `.unref()` on both streams — never
   `.destroy()` — then `child.unref()`.
2. **No orphan on persistence failure (Important).** Reorder `startSubcommand`:
   handshake → ready-probe → `writeState` (wrapped: on ANY throw, `process.kill(pid)`
   best-effort, then rethrow) → release pipes → `unref`. Test: injected state-write
   failure (unwritable outputDir) must record a kill.
3. **Correct workspace containment (Important).** Replace the `startsWith('..')` logic:
   inside-workspace iff `rel === ''` OR (`!rel.startsWith('..' + path.sep)` AND
   `rel !== '..'` AND `!path.isAbsolute(rel)`) — fixes the `..cache` bypass. Layer 2:
   in `startSubcommand` (before spawning), `mkdirSync(outputDir, {recursive: true})`
   then re-check containment on `realpathSync(outputDir)` vs
   `realpathSync(workspace)` (only when workspace is set and exists) — closes the
   symlink route. Tests: `..cache`-style sibling passes validation; a symlink inside
   the workspace pointing outside (and vice versa) is caught by the realpath layer
   (skip the symlink test with the repo's standard symlink-privilege skip option on
   Windows if needed).
4. **Private, symlink-safe state writes (Important).** Replace bare `writeFileSync` in
   `writeState` with the closeout discipline: `lstatSync` the target (existing symlink
   or non-regular-file ⇒ throw, never follow); write a temp sibling
   `.action-state.<pid>.<Date.now()>.tmp` opened `O_WRONLY|O_CREAT|O_EXCL` mode 0600;
   `renameSync` over the target (on `EEXIST`/`EPERM` — Windows rename-over-existing —
   `unlinkSync` target then rename; Linux runners take the atomic path). Windows DACL
   limits stay documented via the spec's Linux-first posture (non-goal 6).
5. **redact-names separator (Important).** The spec promises comma/space-separated;
   the shim splits commas only. Fix in `collector_boot.js`: split on `/[\s,]+/`.
   Pin: `'A B,C'` yields three names (test via a start with redactNames and asserting
   the collector's snapshot redacts all three — or unit-level if simpler, but the split
   itself must be pinned).
6. **readShimStartLine robustness (Minor).** Add a `child.on('error', …)` rejection
   (spawn failure must not become an uncaught exception) and use `'close'` (streams
   drained) rather than `'exit'` for the failure path so a final structured stderr
   line isn't lost to the generic message.
7. **Test gaps (Minor).** The timeout test's fake `kill()` must record and assert the
   kill happened; add the shim-error-line case (fake child emits a structured stderr
   reason then closes → error message carries that reason).

Files: `actions/debug-evidence/collector_boot.js`, `actions/debug-evidence/support.js`,
`actions/debug-evidence/support.test.js`.
Fix commit message:
`fix(action): EPIPE-safe shim, orphan-proof start, real containment, exclusive state writes, redact-name split (Codex T3)`.

**Fix round 2 (Codex re-review of `6fea3ba`):** the seven fixes hold; residuals ruled —
untested shim EPIPE layer acceptable (simple, correctly placed, parent layer pinned),
held scaffolding acceptable, empty-dir validation side effect acceptable. One remaining
Important: `writeState`'s `writeSync()` return value is ignored, so a legal short write
renames truncated JSON into place — `start` succeeds while `readState()` → null and
teardown silently orphans the collector (seam-reproduced: 1 of 85 bytes). Decision:
write via `writeFileSync(fd, payload)` (retries partial writes) on the O_EXCL fd, plus
a seam test pinning that a short-write cannot produce a committed-but-unparsable state
file. Commit: `fix(action): full-write state persistence (Codex T3 r2)`.

---

### Task 4: `run` — session mint, optional hypothesis OPEN, wrapped command execution

**Files:**
- Modify: `actions/debug-evidence/support.js` (replace the `runSubcommand` stub; add `httpRequestJson`, `defaultSpawnCommand`)
- Test: `actions/debug-evidence/support.test.js` (append)

- [ ] **Step 1: Write the failing tests** — append to `support.test.js`:

```js
const startReal = async (overrides = {}) => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const port = await getFreePort();
  const inputs = baseInputs({ port: String(port), ...overrides });
  const code = await startSubcommand({ inputs, outputDir, projectRoot, env: {} });
  assert.equal(code, 0);
  return { outputDir, projectRoot, port, inputs };
};

test('run mints a session, injects exactly the documented env, records the exit code, and never fails on command failure', async () => {
  const { outputDir, projectRoot, inputs } = await startReal();
  try {
    const githubOutput = path.join(outputDir, 'github_output');
    writeFileSync(githubOutput, '');
    // The wrapped command posts one event using ONLY the injected env, then exits 7.
    const probe = 'node -e "' + [
      'const assert = require(\'node:assert\');',
      'assert.ok(process.env.DEBUG_LOG_URL.startsWith(\'http://127.0.0.1:\'));',
      'assert.ok(process.env.DEBUG_SESSION_ID);',
      'assert.ok(process.env.DEBUG_SESSION_TOKEN);',
      'assert.equal(process.env.DEBUG_HYPOTHESIS_ID, undefined);',
      'fetch(process.env.DEBUG_LOG_URL, { method: \'POST\', headers: { \'content-type\': \'application/json\', \'x-debug-session-token\': process.env.DEBUG_SESSION_TOKEN }, body: JSON.stringify({ sessionId: process.env.DEBUG_SESSION_ID, msg: \'probe event\' }) }).then((r) => process.exit(r.status === 202 ? 7 : 99));',
    ].join('') + '"';
    const code = await runSubcommand({
      inputs: { ...inputs, runCommand: probe },
      outputDir,
      env: { GITHUB_OUTPUT: githubOutput },
    });
    assert.equal(code, 0, 'run itself succeeds; finish owns the verdict');
    const state = readState(outputDir);
    assert.equal(state.commandExitCode, 7);
    assert.ok(state.sessionId.startsWith('ci-debug-'));
    const sessionLog = readFileSync(path.join(projectRoot, '.debug', `debug-${state.sessionId}.log`), 'utf8');
    assert.ok(sessionLog.includes('probe event'), 'wrapped command reached the collector');
    const outputs = readFileSync(githubOutput, 'utf8');
    assert.match(outputs, /command-exit-code=7/);
    assert.match(outputs, new RegExp(`session-id=${state.sessionId}`));
    assert.ok(!outputs.includes(state.launchToken), 'launch token never enters GITHUB_OUTPUT');
    assert.ok(!outputs.includes(state.sessionToken), 'session token never enters GITHUB_OUTPUT');
  } finally {
    teardownSubcommand({ outputDir, env: {} });
  }
});

test('run posts one OPEN hypothesis line and injects DEBUG_HYPOTHESIS_ID when hypothesis-id is set — and never any other status', async () => {
  const { outputDir, projectRoot, inputs } = await startReal({ hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' });
  try {
    const probe = 'node -e "process.exit(process.env.DEBUG_HYPOTHESIS_ID === \'H-demo\' ? 0 : 90)"';
    const code = await runSubcommand({ inputs: { ...inputs, runCommand: probe }, outputDir, env: {} });
    assert.equal(code, 0);
    const state = readState(outputDir);
    assert.equal(state.commandExitCode, 0);
    const sessionLog = readFileSync(path.join(projectRoot, '.debug', `debug-${state.sessionId}.log`), 'utf8');
    const hypothesisLines = sessionLog.split('\n').filter((l) => l.includes('"type":"hypothesis"'));
    assert.equal(hypothesisLines.length, 1);
    const parsed = JSON.parse(hypothesisLines[0]);
    assert.equal(parsed.status, 'OPEN');
    assert.equal(parsed.hypothesisId, 'H-demo');
    assert.equal(parsed.title, 'seeded demo');
  } finally {
    teardownSubcommand({ outputDir, env: {} });
  }
});

test('run without state (start never completed) is a 3-class refusal; nonce mismatch likewise', async () => {
  const outputDir = makeTempDir();
  assert.equal(await runSubcommand({ inputs: baseInputs(), outputDir, env: {} }), 3);
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43) });
  assert.equal(await runSubcommand({ inputs: baseInputs(), outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'other' } }), 3);
});

test('run surfaces a session-mint failure as 3 without executing the command', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43), sessionName: 'ci-debug' });
  let commandRan = false;
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: {},
    request: async () => ({ status: 401, json: { error: 'unauthorized' } }),
    spawnCommand: () => { commandRan = true; return { status: 0 }; },
  });
  assert.equal(code, 3);
  assert.equal(commandRan, false, 'no command execution after a failed mint');
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test actions/debug-evidence/support.test.js`
Expected: FAIL — `not implemented: runSubcommand (Task 4)`.

- [ ] **Step 3: Implement in `support.js`** — replace the `runSubcommand` stub with:

```js
// Minimal JSON-over-loopback helper (node:http; fetch is avoided so tests can
// inject `request` and so no keep-alive agent outlives the subcommand).
const httpRequestJson = ({ port, method, path: requestPath, headers = {}, body }) => new Promise((resolve, reject) => {
  const payload = body === undefined ? null : JSON.stringify(body);
  const request = http.request({
    host: '127.0.0.1',
    port,
    method,
    path: requestPath,
    headers: payload === null ? headers : { ...headers, 'content-type': 'application/json' },
  }, (response) => {
    let text = '';
    response.on('data', (chunk) => { text += chunk; });
    response.on('end', () => {
      let json = null;
      try { json = JSON.parse(text); } catch {}
      resolve({ status: response.statusCode, json });
    });
  });
  request.on('error', reject);
  request.setTimeout(5_000, () => request.destroy(new Error('collector request timed out')));
  if (payload !== null) request.write(payload);
  request.end();
});

// stdio: 'inherit' — the wrapped command's output belongs in the step log.
const defaultSpawnCommand = (command, { cwd, env }) => spawnSync('bash', ['-c', command], { cwd, env, stdio: 'inherit' });

const runSubcommand = async ({
  inputs, outputDir, env = process.env,
  request = httpRequestJson, spawnCommand = defaultSpawnCommand,
}) => {
  const state = readState(outputDir);
  if (!state) {
    process.stderr.write('debug-evidence-action: run: no recorded state; the start step never completed.\n');
    return 3;
  }
  if (rejectForeignNonce(state, env, 'run')) return 3;
  const mint = await request({
    port: state.port,
    method: 'POST',
    path: '/session',
    headers: { Authorization: `Bearer ${state.launchToken}` },
    body: { name: state.sessionName },
  });
  if (mint.status !== 201 || !mint.json?.session_id || !mint.json?.session_token) {
    process.stderr.write(`debug-evidence-action: run: session mint failed (HTTP ${mint.status ?? 'no response'}).\n`);
    return 3;
  }
  const sessionId = mint.json.session_id;
  const sessionToken = mint.json.session_token;
  if (state.hypothesisId) {
    // POST /hypothesis is a LAUNCH-token capability the wrapped command never
    // holds; the action records intent (OPEN) here and never any verdict —
    // judgment stays with humans/agents (spec amendment, planning round).
    const hypothesis = await request({
      port: state.port,
      method: 'POST',
      path: '/hypothesis',
      headers: { Authorization: `Bearer ${state.launchToken}` },
      body: {
        sessionId,
        hypothesisId: state.hypothesisId,
        status: 'OPEN',
        ...(state.hypothesisTitle ? { title: state.hypothesisTitle } : {}),
      },
    });
    if (hypothesis.status !== 202) {
      process.stderr.write(`debug-evidence-action: run: hypothesis post failed (HTTP ${hypothesis.status ?? 'no response'}).\n`);
      return 3;
    }
  }
  const commandEnv = {
    ...env,
    DEBUG_LOG_URL: `http://127.0.0.1:${state.port}/log`,
    DEBUG_SESSION_ID: sessionId,
    DEBUG_SESSION_TOKEN: sessionToken,
  };
  if (state.hypothesisId) commandEnv.DEBUG_HYPOTHESIS_ID = state.hypothesisId;
  const result = spawnCommand(inputs.runCommand, { cwd: inputs.workingDirectory, env: commandEnv });
  const commandExitCode = result.error ? 127 : (result.status ?? 128);
  writeState(outputDir, {
    ...state,
    sessionId,
    sessionToken,
    commandExitCode,
    commandSignal: result.signal ?? null,
    commandError: result.error ? String(result.error.message) : null,
  });
  if (env.GITHUB_OUTPUT) {
    writeOutputs(env.GITHUB_OUTPUT, { 'command-exit-code': commandExitCode, 'session-id': sessionId });
  }
  return 0; // command failure is finish's decision, never run's
};
```

Also add `httpRequestJson,` and `defaultSpawnCommand,` to `module.exports` (alphabetical).

> **Recorded dispositions (Task 4 spec review of `c415344`):** (1) the exit-class split
> at mint time is deliberate: a TRANSPORT-level failure (dead collector, timeout)
> propagates to the terminal catch and exits 1 (infra-crash class), while an HTTP-level
> refusal returns 3; both are fail-closed end-to-end because a run that never recorded
> `commandExitCode` makes `finish` return 3. Do not "unify" these. (2) Task 5 additionally
> adds one hermetic signal seam test: `spawnCommand: () => ({ status: null,
> signal: 'SIGKILL' })` → `commandExitCode === 128`, `commandSignal === 'SIGKILL'`.

- [ ] **Step 4: Run the tests**

Run: `node --test actions/debug-evidence/support.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add actions/debug-evidence/support.js actions/debug-evidence/support.test.js
git commit -m "feat(action): run subcommand — mint, optional OPEN hypothesis, injected env, exit-code capture"
```

#### Task 4 fix round 1 — Codex review decisions (recorded before code moves)

Codex verdict on `c415344`: Issues (Important ×5, reproductions for the first two).
All accepted:

1. **Mask tokens on the runner log channel.** `NODE_DEBUG=http` in the job env makes
   Node print the full `Authorization` header into the step log (reproduced). Add a
   `maskValue(env, value)` helper that writes `::add-mask::<value>\n` to stdout ONLY
   when `env.GITHUB_ACTIONS === 'true'`; `start` masks the launch token immediately
   after the shim handshake (before any state write), `run` masks the session token
   immediately after mint (before hypothesis post / spawn). Tests: helper unit test
   both gated states; integration pins via an injectable stdout seam or child capture.
2. **Bounded, settle-guaranteed `httpRequestJson`.** Add: response `'aborted'`,
   `'error'`, and premature-`'close'` rejection; a `RESPONSE_BYTE_CAP = 1 MiB` (reject
   over-cap, destroy); a wall-clock deadline (10 s) covering the whole exchange,
   cleared on settle — the existing 5 s inactivity timeout stays. Tests with a raw
   `net`/`http` fake peer: lying Content-Length (headers + partial body + close) must
   reject, trickle-forever must reject at the deadline.
3. **Close the nonce lost-update race.** `run` re-reads state after the wrapped command
   and compares nonces immediately before its final `writeState`; mismatch ⇒ stderr +
   return 3 WITHOUT writing or emitting outputs (never restore a stale snapshot over a
   newer invocation's state). Task 5's `report` must apply the same
   re-read-before-write guard. Test: mutate the state file (new nonce) while the
   wrapped command runs (seam command does the mutation) ⇒ 3, file untouched.
4. **Authenticate the port occupant before sending the bearer token.** Before mint,
   `run` calls `probeLaunchToken(state.port, state.launchToken)` (exported by
   debug_server; non-mutating HMAC challenge — a rebound foreign process cannot answer
   without the token). Injectable seam `probeToken = probeLaunchToken`; `false` ⇒
   stderr `collector identity could not be verified` + return 3, no Authorization
   header ever sent. Test: fake probe false ⇒ 3 and `request` never called.
5. **Never inherit `DEBUG_HYPOTHESIS_ID`.** When `state.hypothesisId` is falsy,
   explicitly `delete commandEnv.DEBUG_HYPOTHESIS_ID` (job-level values must not
   attribute events to a hypothesis this action never posted). Collision test: caller
   env pre-sets it, input unset ⇒ wrapped command sees it undefined.

Fix commit message:
`fix(action): token masking, bounded http, nonce CAS, port-occupant auth, env hygiene (Codex T4)`.

---

### Task 5: `report` + `finish` — capture, render, and the exit taxonomy

**Files:**
- Modify: `actions/debug-evidence/support.js` (replace both stubs; add `defaultSpawnReport`)
- Test: `actions/debug-evidence/support.test.js` (append)

- [ ] **Step 1: Write the failing tests** — append:

```js
const fullLifecycle = async () => {
  const context = await startReal({ hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' });
  const githubOutput = path.join(context.outputDir, 'github_output');
  const stepSummary = path.join(context.outputDir, 'step_summary');
  writeFileSync(githubOutput, '');
  writeFileSync(stepSummary, '');
  const probe = 'node -e "' + [
    'fetch(process.env.DEBUG_LOG_URL, { method: \'POST\', headers: { \'content-type\': \'application/json\', \'x-debug-session-token\': process.env.DEBUG_SESSION_TOKEN }, body: JSON.stringify({ sessionId: process.env.DEBUG_SESSION_ID, msg: \'demo event\', hypothesisId: process.env.DEBUG_HYPOTHESIS_ID }) }).then((r) => process.exit(r.status === 202 ? 1 : 99));',
  ].join('') + '"';
  const runCode = await runSubcommand({
    inputs: { ...context.inputs, runCommand: probe },
    outputDir: context.outputDir,
    env: { GITHUB_OUTPUT: githubOutput },
  });
  assert.equal(runCode, 0);
  return { ...context, githubOutput, stepSummary };
};

test('report copies the session log, renders md+json, appends the summary, and emits outputs — token bytes never enter the evidence child', async () => {
  const context = await fullLifecycle();
  try {
    const code = await reportSubcommand({
      outputDir: context.outputDir,
      env: { GITHUB_OUTPUT: context.githubOutput, GITHUB_STEP_SUMMARY: context.stepSummary },
    });
    assert.equal(code, 0);
    const evidenceDir = resolveEvidenceDir(context.outputDir);
    const state = readState(context.outputDir);
    const copied = readFileSync(path.join(evidenceDir, 'session.log'), 'utf8');
    assert.ok(copied.includes('demo event'));
    const reportMd = readFileSync(path.join(evidenceDir, 'report.md'), 'utf8');
    assert.ok(reportMd.startsWith('## Debug evidence report'));
    assert.ok(reportMd.includes('H-demo'));
    const reportJson = JSON.parse(readFileSync(path.join(evidenceDir, 'report.json'), 'utf8'));
    assert.equal(reportJson.schema, 1);
    assert.equal(reportJson.hypotheses[0].status, 'OPEN');
    assert.ok(readFileSync(context.stepSummary, 'utf8').includes('## Debug evidence report'));
    const outputs = readFileSync(context.githubOutput, 'utf8');
    assert.match(outputs, /event-count=\d+/);
    assert.match(outputs, /report-path=.+report\.md/);
    for (const file of ['session.log', 'report.md', 'report.json']) {
      const bytes = readFileSync(path.join(evidenceDir, file), 'utf8');
      assert.ok(!bytes.includes(state.launchToken), `${file} must not contain the launch token`);
      assert.ok(!bytes.includes(state.sessionToken), `${file} must not contain the session token`);
    }
    assert.equal(state.collectorAlive, true);
    assert.equal(state.evidenceCopied, true);
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: {} });
  }
});

test('report with no state no-ops successfully (finish owns start failures); report after run-skip no-ops too', async () => {
  const outputDir = makeTempDir();
  assert.equal(await reportSubcommand({ outputDir, env: {} }), 0);
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43) });
  assert.equal(await reportSubcommand({ outputDir, env: {} }), 0, 'no sessionId — run never completed; nothing to capture');
});

test('finish taxonomy: missing state 3; missing exit code 3; dead collector 3; command failure mirrors or is waived by the toggle', async () => {
  const outputDir = makeTempDir();
  assert.equal(finishSubcommand({ outputDir, env: {} }), 3, 'no state');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true' });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 3, 'run never recorded an exit code');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 0, collectorAlive: false, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 3, 'collector died before capture');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 7, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 7, 'mirrors the command exit code');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'false', commandExitCode: 7, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 0, 'toggle waives the failure');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'maybe', commandExitCode: 7, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 7, 'anything but the literal string false mirrors (fail closed)');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 300, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 1, 'out-of-range exit codes clamp to 1');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 0, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 0, 'green run');
});

test('the terminal main() catch redacts state tokens from stderr', async () => {
  const { spawnSync: spawnSyncChild } = require('node:child_process');
  const outputDir = makeTempDir();
  const token = ['fake-launch-', 'token-', 'abcdefghijklmnop'].join('');
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, launchToken: token });
  const result = spawnSyncChild(process.execPath, [path.join(__dirname, 'support.js'), 'bogus-subcommand'], {
    env: { ...process.env, DEBUG_ACTION_OUTPUT_DIR: outputDir },
    encoding: 'utf8',
    timeout: 20000,
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /debug-evidence-action:/);
  assert.match(result.stderr, /Unknown subcommand/);
  assert.ok(!result.stderr.includes(token), 'known state tokens are redacted from the terminal catch');
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test actions/debug-evidence/support.test.js`
Expected: FAIL — `not implemented: reportSubcommand (Task 5)`.

- [ ] **Step 3: Implement** — replace both stubs in `support.js`:

```js
const defaultSpawnReport = (args) => spawnSync(process.execPath, [REPORT_CLI, ...args], {
  encoding: 'utf8',
  maxBuffer: 64 * 1024 * 1024,
});

const reportSubcommand = async ({
  outputDir, env = process.env,
  spawnReport = defaultSpawnReport, probe = probeServer,
}) => {
  const state = readState(outputDir);
  if (!state) return 0; // start never completed; finish owns that failure
  if (rejectForeignNonce(state, env, 'report')) return 3;
  if (!state.sessionId) {
    process.stderr.write('debug-evidence-action: report: the run step never completed; nothing to capture.\n');
    return 0; // finish fails on the missing commandExitCode
  }
  const identity = await probe(state.port, { deadlineMs: 2_000 });
  const collectorAlive = identity !== null && identity.ready === true;
  const evidenceDir = resolveEvidenceDir(outputDir);
  mkdirSync(evidenceDir, { recursive: true });
  const sessionSource = path.join(state.projectRoot, '.debug', `debug-${state.sessionId}.log`);
  let evidenceCopied = false;
  try {
    copyFileSync(sessionSource, path.join(evidenceDir, 'session.log'));
    evidenceCopied = true;
  } catch (error) {
    process.stderr.write(`debug-evidence-action: report: session log unreadable (${error?.code ?? error}).\n`);
  }
  let reportRendered = false;
  if (evidenceCopied) {
    const sessionCopy = path.join(evidenceDir, 'session.log');
    const markdown = spawnReport([sessionCopy, '--format=md']);
    const json = spawnReport([sessionCopy, '--format=json']);
    if (markdown.status === 0 && json.status === 0) {
      writeFileSync(path.join(evidenceDir, 'report.md'), markdown.stdout);
      writeFileSync(path.join(evidenceDir, 'report.json'), json.stdout);
      reportRendered = true;
      if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `${markdown.stdout}\n`);
      if (env.GITHUB_OUTPUT) {
        let eventCount = '';
        try { eventCount = String(JSON.parse(json.stdout).session.events); } catch {}
        writeOutputs(env.GITHUB_OUTPUT, {
          'event-count': eventCount,
          'report-path': path.join(evidenceDir, 'report.md'),
        });
      }
    } else {
      process.stderr.write(`debug-evidence-action: report: renderer failed (md ${markdown.status}, json ${json.status}).\n`);
    }
  }
  writeState(outputDir, { ...state, collectorAlive, evidenceCopied, reportRendered });
  return evidenceCopied && reportRendered ? 0 : 3; // capture is the product — fail closed
};

const finishSubcommand = ({ outputDir, env = process.env }) => {
  const state = readState(outputDir);
  if (!state) {
    process.stderr.write('debug-evidence-action: finish: no recorded state; the start step never completed.\n');
    return 3;
  }
  if (rejectForeignNonce(state, env, 'finish')) return 3;
  if (!Number.isInteger(state.commandExitCode)) {
    process.stderr.write('debug-evidence-action: finish: the run step never completed.\n');
    return 3;
  }
  if (state.collectorAlive !== true) {
    process.stderr.write('debug-evidence-action: finish: the collector was not alive and ready at capture time; evidence may be incomplete.\n');
    return 3;
  }
  if (state.evidenceCopied !== true || state.reportRendered !== true) {
    process.stderr.write('debug-evidence-action: finish: evidence capture or report rendering failed.\n');
    return 3;
  }
  if (state.commandExitCode !== 0) {
    if (state.failOnCommandFailure === 'false') {
      process.stderr.write(`debug-evidence-action: wrapped command exited ${state.commandExitCode}; fail-on-command-failure is false, so the action succeeds. Evidence is in the artifact.\n`);
      return 0;
    }
    // Anything but the literal 'false' mirrors — fail closed on unknowns.
    process.stderr.write(`debug-evidence-action: wrapped command exited ${state.commandExitCode}.\n`);
    return state.commandExitCode >= 1 && state.commandExitCode <= 255 ? state.commandExitCode : 1;
  }
  return 0;
};
```

Add `defaultSpawnReport,` to `module.exports` (alphabetical).

- [ ] **Step 4: Run the tests**

Run: `node --test actions/debug-evidence/support.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add actions/debug-evidence/support.js actions/debug-evidence/support.test.js
git commit -m "feat(action): report + finish — clean-by-construction capture and the fail-closed exit taxonomy"
```

---

### Task 6: `action.yml` — pure wiring, with structural pins

**Files:**
- Create: `actions/debug-evidence/action.yml`
- Test: `actions/debug-evidence/support.test.js` (append structural tests)

- [ ] **Step 1: Write the failing structural tests** — append to `support.test.js` (plain-text regex assertions, no YAML parser — repo convention):

```js
const ACTION_YML = () => readFileSync(path.join(__dirname, 'action.yml'), 'utf8');
const OUTPUT_DIR_EXPR = "${{ inputs.output-dir || format('{0}/debug-evidence', runner.temp) }}";

test('action.yml is wiring-only: every run line calls support.js with a known subcommand', () => {
  const runLines = ACTION_YML().split('\n').filter((l) => l.trim().startsWith('run:'));
  assert.ok(runLines.length >= 5, 'start/run/report/teardown/finish steps exist');
  for (const lineText of runLines) {
    assert.match(lineText.trim(),
      /^run: node "\$\{\{ github\.action_path \}\}\/support\.js" (start|run|report|teardown|finish)$/,
      `wiring-only violated: ${lineText.trim()}`);
  }
});

test('action.yml pins third-party actions to the closeout SHAs', () => {
  const text = ACTION_YML();
  assert.ok(text.includes('uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6.5.0'));
  assert.ok(text.includes('uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2'));
  assert.ok(!/uses:\s+[^.@\s]+\/[^@\s]+@(?![0-9a-f]{40})/.test(text), 'no unpinned remote uses');
});

test('action.yml repeats the output-dir default expression identically at every use site', () => {
  const text = ACTION_YML();
  const occurrences = text.split(OUTPUT_DIR_EXPR).length - 1;
  assert.ok(occurrences >= 6, `expected the default expression in start/run/report/upload/teardown/finish env + upload paths, found ${occurrences}`);
  assert.ok(!text.includes("format('{0}/debug-evidence',runner.temp"), 'no whitespace variant of the expression');
});

test('action.yml uploads only enumerated evidence files — never the bare dir, never action-state.json', () => {
  const text = ACTION_YML();
  const uploadIndex = text.indexOf('Upload evidence artifact');
  assert.notEqual(uploadIndex, -1);
  const pathBlock = /path:\s*\|\r?\n((?:[ \t]+\S.*\r?\n?)+)/.exec(text.slice(uploadIndex));
  assert.ok(pathBlock, 'path: must be a multi-line block scalar');
  const lines = pathBlock[1].split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  for (const name of ['session.log', 'report.md', 'report.json']) {
    assert.ok(lines.some((l) => l.endsWith(`/debug-evidence-files/${name}`)), `enumerates ${name}`);
  }
  for (const l of lines) {
    assert.ok(!l.includes('action-state.json'), 'the state file (launch token) must never be uploaded');
    assert.notEqual(l, OUTPUT_DIR_EXPR, 'never the bare output dir');
  }
});

test('action.yml guards report/upload/teardown/finish with always()', () => {
  const text = ACTION_YML();
  for (const step of ['Render evidence report', 'Upload evidence artifact', 'Stop collector', 'Apply verdict']) {
    const index = text.indexOf(step);
    assert.notEqual(index, -1, `step ${step} exists`);
    const slice = text.slice(index, index + 400);
    assert.match(slice, /if: \$\{\{ always\(\)/, `${step} runs on failure paths too`);
  }
});
```

- [ ] **Step 2: Run to verify failure**

Run: `node --test actions/debug-evidence/support.test.js`
Expected: FAIL — action.yml missing (ENOENT).

- [ ] **Step 3: Create `actions/debug-evidence/action.yml`:**

```yaml
name: "Debug Evidence Session"
description: >-
  Wrap one failing command in an instrumented debug-collector session:
  capture evidence, render a Step Summary report, upload the evidence
  artifact, and tear the collector down. All logic lives in support.js;
  this file is wiring only.

inputs:
  run:
    description: "Command to execute under instrumentation (bash -c)"
    required: true
  working-directory:
    description: "Directory the wrapped command runs in"
    required: false
    default: "."
  session-name:
    description: "Session label ([A-Za-z0-9_-]+); the session id derives from it"
    required: false
    default: "ci-debug"
  fail-on-command-failure:
    description: >-
      'true' (default): the action fails when the wrapped command exits
      non-zero. 'false': the failure is reported in the summary/outputs only.
      Evidence capture, artifact upload, and teardown happen regardless.
    required: false
    default: "true"
  output-dir:
    description: "Evidence staging dir (MUST be outside the workspace); becomes the artifact"
    required: false
    default: ""
  artifact-name:
    description: "Uploaded evidence artifact name"
    required: false
    default: "debug-evidence"
  node-version:
    description: "Node.js version for the collector and renderer"
    required: false
    default: "24"
  port:
    description: "Collector port (loopback only). Self-hosted runners sharing a host must pick distinct ports."
    required: false
    default: "8787"
  redact-names:
    description: "Comma-separated extra env-var names to always redact (extends DEBUG_REDACT_NAMES)"
    required: false
    default: ""
  max-events:
    description: "Per-session event limit override (collector default 2000)"
    required: false
    default: ""
  max-bytes:
    description: "Total evidence byte limit override (collector default 16MB)"
    required: false
    default: ""
  hypothesis-id:
    description: >-
      Optional: when set, the action posts one status OPEN hypothesis line
      (a launch-token capability the wrapped command does not hold) and
      injects DEBUG_HYPOTHESIS_ID into the wrapped command's environment.
      The action never posts any other status — verdicts stay with you.
    required: false
    default: ""
  hypothesis-title:
    description: "Optional title for the hypothesis line; ignored without hypothesis-id"
    required: false
    default: ""

outputs:
  command-exit-code:
    description: "Exit code of the wrapped command; empty until the run step has run"
    value: ${{ steps.run.outputs.command-exit-code }}
  session-id:
    description: "Collector session id; empty until the run step has run"
    value: ${{ steps.run.outputs.session-id }}
  event-count:
    description: "Events captured in the session; empty until the report step has run"
    value: ${{ steps.report.outputs.event-count }}
  report-path:
    description: "Absolute path of report.md in the staged evidence; empty until the report step has run"
    value: ${{ steps.report.outputs.report-path }}

runs:
  using: composite
  steps:
    - name: Set up Node.js
      uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6.5.0
      with:
        node-version: ${{ inputs.node-version }}

    # The collector inherits THIS step's full environment: its redaction
    # snapshot must include the job's secrets so anything the wrapped
    # command logs is scrubbed (spec Security invariant 3). Do not strip
    # the env here.
    - name: Start collector
      id: start
      shell: bash
      env:
        DEBUG_ACTION_RUN: ${{ inputs.run }}
        DEBUG_ACTION_SESSION_NAME: ${{ inputs.session-name }}
        DEBUG_ACTION_WORKDIR: ${{ inputs.working-directory }}
        DEBUG_ACTION_FAIL_ON_COMMAND_FAILURE: ${{ inputs.fail-on-command-failure }}
        DEBUG_ACTION_OUTPUT_DIR: ${{ inputs.output-dir || format('{0}/debug-evidence', runner.temp) }}
        DEBUG_ACTION_ARTIFACT_NAME: ${{ inputs.artifact-name }}
        DEBUG_ACTION_PORT: ${{ inputs.port }}
        DEBUG_ACTION_REDACT_NAMES: ${{ inputs.redact-names }}
        DEBUG_ACTION_MAX_EVENTS_INPUT: ${{ inputs.max-events }}
        DEBUG_ACTION_MAX_BYTES_INPUT: ${{ inputs.max-bytes }}
        DEBUG_ACTION_HYPOTHESIS_ID: ${{ inputs.hypothesis-id }}
        DEBUG_ACTION_HYPOTHESIS_TITLE: ${{ inputs.hypothesis-title }}
      run: node "${{ github.action_path }}/support.js" start

    - name: Run wrapped command
      id: run
      shell: bash
      env:
        DEBUG_ACTION_RUN: ${{ inputs.run }}
        DEBUG_ACTION_WORKDIR: ${{ inputs.working-directory }}
        DEBUG_ACTION_OUTPUT_DIR: ${{ inputs.output-dir || format('{0}/debug-evidence', runner.temp) }}
      run: node "${{ github.action_path }}/support.js" run

    - name: Render evidence report
      id: report
      if: ${{ always() && steps.start.outcome != 'skipped' }}
      shell: bash
      env:
        DEBUG_ACTION_OUTPUT_DIR: ${{ inputs.output-dir || format('{0}/debug-evidence', runner.temp) }}
      run: node "${{ github.action_path }}/support.js" report

    - name: Upload evidence artifact
      if: ${{ always() && steps.start.outcome != 'skipped' }}
      uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2
      with:
        name: ${{ inputs.artifact-name }}
        path: |
          ${{ inputs.output-dir || format('{0}/debug-evidence', runner.temp) }}/debug-evidence-files/session.log
          ${{ inputs.output-dir || format('{0}/debug-evidence', runner.temp) }}/debug-evidence-files/report.md
          ${{ inputs.output-dir || format('{0}/debug-evidence', runner.temp) }}/debug-evidence-files/report.json
        if-no-files-found: ignore

    - name: Stop collector
      if: ${{ always() && steps.start.outcome != 'skipped' }}
      shell: bash
      env:
        DEBUG_ACTION_OUTPUT_DIR: ${{ inputs.output-dir || format('{0}/debug-evidence', runner.temp) }}
      run: node "${{ github.action_path }}/support.js" teardown

    - name: Apply verdict
      if: ${{ always() && steps.start.outcome != 'skipped' }}
      shell: bash
      env:
        DEBUG_ACTION_OUTPUT_DIR: ${{ inputs.output-dir || format('{0}/debug-evidence', runner.temp) }}
      run: node "${{ github.action_path }}/support.js" finish
```

- [ ] **Step 4: Run the structural tests**

Run: `node --test actions/debug-evidence/support.test.js`
Expected: PASS.

- [ ] **Step 5: Validate the repo picks it up**

Run: `npm run validate`
Expected: PASS — the new `action.yml` enters the pin scan via the actionMetadataFiles regex automatically (no census change: `actions/` is outside the payload).

- [ ] **Step 6: Commit**

```bash
git add actions/debug-evidence/action.yml actions/debug-evidence/support.test.js
git commit -m "feat(action): debug-evidence composite wiring with structural pins"
```

---

### Task 7: Demo repro, dogfood workflow, gate forwarder amendment

**Files:**
- Create: `actions/debug-evidence/demo/repro.js`
- Create: `.github/workflows/debug-evidence-demo.yml`
- Modify: `.github/workflows/closeout-gate.yml` (workflow_run list + its comment)
- Test: `actions/debug-evidence/support.test.js` (append demo lifecycle test)

- [ ] **Step 1: Create `actions/debug-evidence/demo/repro.js`:**

```js
'use strict';

// DEMO repro for the debug-evidence dogfood workflow. Deterministic by
// design: fixed messages, seeded "bug", exit 1. It authenticates with ONLY
// the injected session env (DEBUG_LOG_URL / DEBUG_SESSION_ID /
// DEBUG_SESSION_TOKEN / DEBUG_HYPOTHESIS_ID) — exactly what a consumer's
// wrapped command gets. NOT part of the skill payload.

const post = async (body) => {
  const response = await fetch(process.env.DEBUG_LOG_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-debug-session-token': process.env.DEBUG_SESSION_TOKEN,
    },
    body: JSON.stringify({ sessionId: process.env.DEBUG_SESSION_ID, ...body }),
  });
  if (response.status !== 202) throw new Error(`collector rejected event: HTTP ${response.status}`);
};

const main = async () => {
  const hypothesisId = process.env.DEBUG_HYPOTHESIS_ID;
  // Seeded bug: userId is "lost" between fetch and render.
  await post({ msg: 'DEMO fetch: userId=42 loaded from fixture', hypothesisId });
  await post({ msg: 'DEMO render: userId=null on first render', hypothesisId, data: { userId: null } });
  // Redaction proof: the raw secret value must NEVER appear in the artifact.
  await post({ msg: `DEMO config dump: token=${process.env.DEMO_FAKE_SECRET}`, hypothesisId });
  await post({ msg: 'DEMO unrelated background noise' });
  process.stderr.write('DEMO: seeded failure — exiting 1 so the report shows a red run\n');
  process.exitCode = 1;
};

main().catch((error) => {
  process.stderr.write(`DEMO repro failed unexpectedly: ${error.message}\n`);
  process.exitCode = 99; // 99 = demo infrastructure broke (≠ the seeded 1)
});
```

- [ ] **Step 2: Write the failing demo lifecycle test** — append to `support.test.js`:

```js
test('demo repro drives the full lifecycle: seeded exit 1, redacted secret, deterministic report content', async () => {
  const secret = ['demo-fake-', 'secret-value-', '0123456789'].join('');
  const context = await startReal({ hypothesisId: 'DEMO-H1', hypothesisTitle: 'seeded demo failure', redactNames: 'DEMO_FAKE_SECRET' });
  try {
    const runCode = await runSubcommand({
      inputs: { ...context.inputs, runCommand: `node "${path.join(__dirname, 'demo', 'repro.js')}"` },
      outputDir: context.outputDir,
      env: { DEMO_FAKE_SECRET: secret },
    });
    assert.equal(runCode, 0);
    const state = readState(context.outputDir);
    assert.equal(state.commandExitCode, 1, 'the seeded failure, not the 99 infra code');
    const reportCode = await reportSubcommand({ outputDir: context.outputDir, env: {} });
    assert.equal(reportCode, 0);
    const evidenceDir = resolveEvidenceDir(context.outputDir);
    const sessionLog = readFileSync(path.join(evidenceDir, 'session.log'), 'utf8');
    assert.ok(!sessionLog.includes(secret), 'redaction scrubbed the fake secret from persisted evidence');
    assert.ok(sessionLog.includes('[REDACTED]'), 'redaction marker present');
    const reportJson = JSON.parse(readFileSync(path.join(evidenceDir, 'report.json'), 'utf8'));
    assert.equal(reportJson.hypotheses[0].id, 'DEMO-H1');
    assert.equal(reportJson.hypotheses[0].status, 'OPEN');
    assert.equal(reportJson.hypotheses[0].events, 3);
    assert.equal(reportJson.untaggedEvents, 1);
    assert.equal(finishSubcommand({ outputDir: context.outputDir, env: {} }), 1, 'default mirrors the seeded failure');
    writeState(context.outputDir, { ...readState(context.outputDir), failOnCommandFailure: 'false' });
    assert.equal(finishSubcommand({ outputDir: context.outputDir, env: {} }), 0, 'the dogfood toggle waives it');
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: {} });
  }
});
```

Note: `startReal` must pass `redactNames` through — it already spreads overrides into `baseInputs`, and `startSubcommand` forwards `inputs.redactNames` to the shim env; the shim env must ALSO carry `DEMO_FAKE_SECRET` for the snapshot. Amend `startReal` to accept an env override:

```js
// replace startReal's startSubcommand call with:
  const code = await startSubcommand({ inputs, outputDir, projectRoot, env: overrides.__env ?? {} });
```

and pass `__env: { DEMO_FAKE_SECRET: secret }` from this test (the name is stripped by `baseInputs` spread — filter `__env` out of inputs: `const { __env, ...rest } = overrides; const inputs = baseInputs(rest);`).

- [ ] **Step 3: Run to verify failure, then green**

Run: `node --test actions/debug-evidence/support.test.js`
Expected: first run FAILS (repro.js missing → exit 99 path); after creating the file in Step 1 order it PASSES. If the redaction assertion fails, the collector's env snapshot did not include `DEMO_FAKE_SECRET` — check the `__env` threading, do not weaken the assertion.

- [ ] **Step 4: Create `.github/workflows/debug-evidence-demo.yml`:**

```yaml
name: Debug evidence demo

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

# Advisory demo — cancellation on a new push is safe (unlike the enforcing
# gate, which must never cancel-then-skip an in-flight verdict).
concurrency:
  group: debug-evidence-demo-${{ github.ref }}
  cancel-in-progress: true

jobs:
  demo:
    runs-on: ubuntu-latest
    env:
      # A fixed dummy value whose ONLY job is to prove redaction end-to-end:
      # the artifact's session.log must contain [REDACTED] where this value
      # was logged. Deliberately not a real secret.
      DEMO_FAKE_SECRET: demo-fake-secret-value-0123456789
    steps:
      - name: Check out repository
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          # The action needs no git history — shallow is enough.
          fetch-depth: 1
          persist-credentials: false

      - name: Debug evidence demo session
        uses: ./actions/debug-evidence
        with:
          run: node actions/debug-evidence/demo/repro.js
          session-name: demo
          hypothesis-id: DEMO-H1
          hypothesis-title: seeded demo failure
          redact-names: DEMO_FAKE_SECRET
          # The demo fails BY DESIGN (seeded exit 1); the action must stay
          # green so the demo job reads as "action works", not "repo broken".
          fail-on-command-failure: "false"
          artifact-name: debug-evidence-demo
```

- [ ] **Step 5: Amend the gate's retry-forwarder list** — in `.github/workflows/closeout-gate.yml`, change the `workflow_run` trigger line:

```yaml
  workflow_run:
    workflows: ["Validate", "Closeout preview", "Debug evidence demo"]
    types: [completed]
```

and update the comment above it: replace the sentence fragment naming only the two workflows (`Deliberately named-scoped to ONLY these two sibling workflows`) with:

```yaml
  # completion.  Deliberately name-scoped to ONLY these sibling workflows
  # ("Validate", "Closeout preview", "Debug evidence demo" — the cycle 4
  # demo is a per-PR sibling check the gate can block on, exactly like the
  # other two), NOT "Closeout gate" itself: none of them has a
```

(Match the existing comment's wording precisely when editing — read the block first; the invariant to preserve is the explanation that the gate itself is excluded so no retrigger loop exists.)

- [ ] **Step 6: Validate workflows**

Run: `npm run validate`
Expected: PASS — new workflow has top-level `permissions:` and pinned `uses:`; gate edit keeps its pins.

- [ ] **Step 7: Commit**

```bash
git add actions/debug-evidence/demo/repro.js .github/workflows/debug-evidence-demo.yml .github/workflows/closeout-gate.yml actions/debug-evidence/support.test.js
git commit -m "feat(dogfood): deterministic demo session workflow + gate retry-forwarder coverage"
```

---

### Task 8: Documentation — action README, repo README, SKILL.md

**Files:**
- Create: `actions/debug-evidence/README.md`
- Modify: `README.md` (Evidence tools section + CI pointer)
- Modify: `SKILL.md` (Analyze & Verify Tooling section)

- [ ] **Step 1: Create `actions/debug-evidence/README.md`** covering, in this order (write complete prose for each — this list is the required table of contents, not placeholder text; every factual claim must match the shipped code):

1. **What it does** — one action call wraps one command in an instrumented session; artifact + Step Summary; links to the skill's evidence-first workflow.
2. **Quick start** — the minimal consumer YAML (checkout pinned, then `uses: <owner>/<repo>/actions/debug-evidence@<40-hex-sha>` with `run:`). State plainly: pin a 40-hex commit SHA, never a branch.
3. **Inputs / Outputs** — tables mirroring `action.yml` exactly (same defaults, same wording for the hypothesis-id caveat).
4. **What the wrapped command receives** — `DEBUG_LOG_URL`, `DEBUG_SESSION_ID`, `DEBUG_SESSION_TOKEN`, optional `DEBUG_HYPOTHESIS_ID`; one fetch-based POST example (copy the demo's `post` helper shape); note the launch token is never exposed.
5. **Evidence artifact** — exactly `session.log`, `report.md`, `report.json` under `debug-evidence-files/`; state file is never uploaded; `.debug/` internals never leave the runner.
6. **Redaction invariant** — the collector inherits the job env by design; `redact-names` extends coverage; warn that starting the collector with a stripped env would leave job secrets unredacted (that is why the action offers no "clean env" option).
7. **Exit semantics** — the spec's table, verbatim behavior.
8. **Permissions** — the action needs NO GitHub token and makes no API calls; the calling job needs only `contents: read` (checkout). Fork PRs: fully functional (nothing token-gated).
9. **Self-hosted runners** — teardown relies on the `always()` step plus the collector's 15-minute idle timeout backstop; hosted runners also reap the job's process tree; pick distinct `port` values for shared hosts.
10. **Demo** — point at `.github/workflows/debug-evidence-demo.yml` and `demo/repro.js`; the demo fails by design (`fail-on-command-failure: false`) and proves redaction via `DEMO_FAKE_SECRET` → `[REDACTED]`.

- [ ] **Step 2: Update `README.md`** — in `### Evidence tools` (lines ~150–159), after the existing sentence about the diff, extend the paragraph:

```markdown
`scripts/debug_report.js` renders a single session the same way (TTY text for
humans; markdown when piped — Step Summary ready; `--format=json` with
`schema: 1` for machines) and backs the `actions/debug-evidence` composite
action, which wraps one failing CI command in an instrumented session and
publishes the report plus an evidence artifact (see
`actions/debug-evidence/README.md`).
```

- [ ] **Step 3: Update `SKILL.md`** — in `## Analyze & Verify Tooling`, after the Phase 7 debug_diff block, add:

```markdown
Single-session report (CI or local) — summarize one session without a baseline:

```bash
# Human summary on a TTY; markdown when piped (Step Summary ready)
node /path/to/debug/scripts/debug_report.js <session-id> "$PROJECT"
# Machine surface (stable schema: 1)
node /path/to/debug/scripts/debug_report.js <session-id> "$PROJECT" --format=json
```

In CI, the `actions/debug-evidence` composite action wraps a failing command
in a session and renders this report into the Step Summary automatically.
```

Keep the section's existing "Guarantees both tools keep" list intact; extend its intro to "all three tools" only if the guarantees hold for debug_report (they do: escaping in human surfaces, no severity classification, deterministic output) — update the bullet wording accordingly.

- [ ] **Step 4: Validate** (SKILL.md edits can break the trigger scan; README edits are safety-scanned)

Run: `npm run validate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add actions/debug-evidence/README.md README.md SKILL.md
git commit -m "docs(action): debug-evidence consumer README + repo README/SKILL.md wiring"
```

---

### Task 9: Full battery, scope proof, and handoff

- [ ] **Step 1: Full test battery** (one invocation, foreground, no pipes)

Run: `npm test`
Expected: 0 fail, 0 cancelled. The suite grows by the debug_report + debug-evidence-action tests (~25–35 new tests). Pre-existing timing-sensitive suites (`debug_server` collector-claim, `pr_closeout_process` symlink) can flake under machine load — a failure there needs an isolation rerun of THAT file before it is called real.

- [ ] **Step 2: Validator + suppression scan**

Run: `npm run validate`
Expected: `{"status":"PASS","payloadFiles":43,...}`.

Run: `npm run scan:suppressions`
Expected: clean (or the designed additive-only gate-scan advisory when run through the gate).

- [ ] **Step 3: Scope proof**

Run: `git diff codex/publish-debug-skill...HEAD --stat`
Expected: ONLY these paths — `docs/superpowers/{specs,plans}/2026-08-13-*`, `scripts/debug_evidence.js`, `scripts/debug_diff.js`, `scripts/debug_report.js`, `scripts/debug_report.test.js`, `scripts/debug_evidence.test.js`, `tools/validate_repository.js`, `actions/debug-evidence/**`, `.github/workflows/debug-evidence-demo.yml`, `.github/workflows/closeout-gate.yml`, `README.md`, `SKILL.md`. ZERO deletions outside the two modified script files' internal edits; NOTHING under `scripts/pr_closeout*` or `actions/closeout/`.

- [ ] **Step 4: Commit any stragglers, then report**

Report to the controller: battery numbers (tests/pass/fail/skips), validator JSON, scope stat, and any deviations from this plan (each needs a recorded amendment before it ships).

---

## Plan self-review record (writing-plans checklist)

- **Spec coverage:** consumer surface → Task 6; lifecycle engine → Tasks 3–5; clean-by-construction artifact → Tasks 5–6 (state at root, enumerated uploads, containment tests); security invariants 1–6 → Tasks 3–7 (loopback bind, token scoping, env inheritance, shared escaping, pins/permissions, announced caps); renderer → Tasks 1–2; demo + integration decisions → Task 7 (forwarder list per amended spec; distinct display names cover self-exclusion); census → Task 2; docs → Task 8; testing strategy → every task + Task 9.
- **Known deliberate deviations from closeout conventions** (implementers: these are decisions, not oversights): no `stage-token` step (this action holds no GitHub token); state file at output-dir ROOT not inside the evidence child (it carries the launch token; closeout's state is secret-free and ships in its artifact — ours must not); `run` records outputs itself (closeout's gate step does the same via `steps.gate`).
- **Type consistency check:** `readState(outputDir)` everywhere (never evidenceDir — differs from closeout deliberately, documented in Task 3); state keys `{ nonce, pid, port, launchToken, projectRoot, sessionName, hypothesisId, hypothesisTitle, failOnCommandFailure, sessionId, sessionToken, commandExitCode, commandSignal, commandError, collectorAlive, evidenceCopied, reportRendered }` — grep any new reference against this list; report JSON key `session.events` feeds the `event-count` output.
- **Placeholder scan:** Task 8 Step 1 is a required-contents list for prose the implementer writes (not code) — every claim it requires is pinned by a Task 3–7 test; no TBD/TODO remains anywhere.

