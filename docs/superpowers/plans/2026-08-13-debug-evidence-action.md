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
- Exported probes: `probeServer(port, { deadlineMs = 2000 })` → identity object or null, never rejects; `probeReadyCollector(port, expectedProjectHash, { delayMs = 50, deadlineMs = 10000 })` → identity when ready+hash-matched, identity early on hash MISMATCH, null on deadline; `probeLaunchToken(port, token)` → `Promise<boolean>`, resolve-only (never rejects; false on timeout/refused/non-200/bad proof) — non-mutating HMAC challenge (`GET /auth?challenge=…`, proof verified locally, 500 ms inactivity timeout + its own deadline) proving the port occupant KNOWS the launch token without ever sending it. *(Added during Task 4 fix round; source: debug_server.js:1843, exported at :2674.)*
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

**Fix round 2 (Codex re-review of `2e2eb74`):** four fixes sound; residuals ruled —
slow-collector refusal acceptable (correct fail-closed tradeoff), transport exit-1
class acceptable (finish still fail-closed), strict `=== 'true'` masking gate correct
per GitHub's documented contract. One remaining Important: the nonce "CAS" is
check-then-act — between `run`'s re-read/compare and `writeState`'s unconditional
rename, a second invocation can write, and the first then clobbers it (orphan hazard
persists). Decision: a real critical section honored by EVERY state writer —
`withStateLock(outputDir, fn)` acquiring `action-state.lock` via `O_CREAT|O_EXCL`
(retry ~10 × 50 ms; a lock older than 30 s is stale → unlink and retry once; final
acquisition failure ⇒ throw, landing in the terminal catch), releasing in `finally`.
`start`'s initial write and `run`'s read-compare-write go under the lock now; Task 5's
`report` write must use it too. Tests: (1) a pre-held fresh lock makes `run`'s commit
path fail bounded (not hang); (2) a stale lock is reaped; (3) the interleave test now
drives the wrapped command's state mutation through the locked API and asserts
serialization (loser refuses, winner's state survives).
Commit: `fix(action): state-lock critical sections for nonce ownership (Codex T4 r2)`.

**Fix round 3 (Codex re-review of `7407458`):** ordinary nonce race fixed; contention
posture and lock-free provisional read ruled acceptable. One Important, FIX NOW: the
stale sweep plus the owner-blind release recreate the clobber (two reapers both
observe a >30 s lock; one wins the O_EXCL re-create; the loser's unlink — or the
original holder's `finally` — removes the winner's fresh lock, admitting a third
writer). Decisions:
1. Lock files carry OWNERSHIP CONTENT: `${pid}\n${randomUUID()}\n` written into the
   O_EXCL fd at creation.
2. Normal release unlinks ONLY if the lock's current content equals this holder's own
   token (read immediately before unlink; mismatch ⇒ skip unlink — ownership was lost
   to a reaper, and the successor's lock must survive).
3. Stale reap unlinks ONLY if the content read immediately before unlink still equals
   the exact stale content observed when staleness was established (replacement between
   observation and deletion ⇒ do not unlink; resume retrying).
4. A deterministic two-reaper test uses an injectable seam (e.g. an `onStaleObserved`
   hook or injected `now`) to FORCE replacement between observation and deletion and
   asserts the fresh lock survives and the loser retries/fails bounded rather than
   unlinking it.
5. The round-2 report's 8-holder concurrency probe was scratch-only (Codex: not in the
   commit) — commit it as a real test this round or drop the claim from the record;
   committing it is preferred.
Commit: `fix(action): ownership-verified lock release and reap (Codex T4 r3)`.

**Fix round 4 (Codex re-review of `64864d9`):** ownership stamps, both deletion-site
guards, the committed tests, and the seam all verified/accepted. One Important, FIX
NOW: the staleness observation itself is unbound — mtime (stat by path) and ownership
bytes (read by path) are taken in separate operations that can straddle a replacement,
a wider race than the acknowledged final check-to-unlink window. Decision: take the
observation from ONE descriptor — open the lock `O_RDONLY`, `fstatSync(fd)` for the
timestamp and read the content from that same fd (same inode by construction), close,
then proceed with the existing observed-content re-check before unlink. The remaining
single-syscall micro-window is then ACCEPTED for this portable, misconfiguration-only
lock (Codex ruling). Adjust/extend the forced-replacement test if the seam's call
point moves. Commit:
`fix(action): inode-bound staleness observation (Codex T4 r4)`.

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

#### Task 5 fix round 1 — Codex review decisions (recorded before code moves)

Codex verdict on `9a7c83a`: Critical ×1, Important ×2, Minor ×1. All accepted:

1. **Authenticated capture (Critical).** The wrapped command can replace
   `.debug/debug-<id>.log` (it knows the session id and shares the filesystem), and
   pathname-copy renders the forgery — including verdict lines it could never POST.
   Decision: evidence is captured FROM THE COLLECTOR, not the filesystem. `report`:
   - `authProbe = probeToken(state.port, state.launchToken)` (seam, default
     `probeLaunchToken`) — replaces the identity-blind `probeServer` liveness check
     (also closing Important #2: `collectorAlive` now means *authenticated* alive).
   - If authenticated: fetch the authoritative NDJSON via `readSessionLive({ port,
     token: launchToken, sessionId, timeoutMs: 5000 })` (from
     `scripts/debug_evidence.js`; injectable seam) and write
     `entries.map((e) => e.raw).join('\n') + '\n'` as the evidence child's
     `session.log`. A live-read throw (`live_read_log_replaced`,
     `live_read_unknown_session`, …) is an evidence-integrity failure: stderr,
     `evidenceCopied: false`, return 3 — the collector's own identity protection is
     now load-bearing.
   - If NOT authenticated: `collectorAlive: false`; best-effort filesystem copy as
     labeled PARTIAL evidence (`evidenceAuthentic: false` recorded in state); render
     what was staged; `finish` still fails via `collectorAlive !== true`, so forged
     bytes can never ride a green run.
   Tests: forged-log swap by the wrapped command (seam command rewrites the session
   log) yields either a live-read capture that ignores the forged file (authenticated
   path — staged bytes match the collector's view, not the disk file) or, with a dead
   collector, a partial capture that `finish` fails; a `live_read_log_replaced`
   rejection maps to 3.
2. **Validate renderer output before committing (Important).** Parse the JSON render's
   stdout BEFORE writing either file or setting `reportRendered`: require
   `schema === 1` and `Number.isInteger(session.events) && session.events >= 0`;
   failure ⇒ renderer-failure path (3), nothing written, no outputs. `event-count`
   comes from the validated object (the `catch {}` fallback dies). Tests: status-0
   malformed JSON, wrong schema, negative events.
3. **Toggle validated on green runs too (Minor).** `finish` rejects a
   `failOnCommandFailure` outside {'true','false'} with 3 REGARDLESS of
   `commandExitCode` (fail-closed applies to forged/corrupt state on green runs as
   well). Test: unknown toggle + exit 0 ⇒ 3.

Fix commit message:
`fix(action): collector-authenticated evidence capture, validated renders, strict toggle (Codex T5)`.

#### Task 5 fix round 2 — Codex re-review decisions (recorded before code moves)

Codex on `e6b5087`: renderer validation and strict toggle sound; residual (c) nothing
required; but Critical ×2 + Important ×1 block approval. All accepted:

1. **Launch-token theft via the state file (Critical).** `commandEnv` inherits
   `DEBUG_ACTION_OUTPUT_DIR`; the wrapped command (same OS user — 0600 is no boundary)
   reads `action-state.json`, takes the launch token, and posts forged verdicts through
   the front door, which authenticated capture then blesses. Two layers:
   (i) strip every `DEBUG_ACTION_*` key from `commandEnv` (the wiring vars are not part
   of the injected contract; the path must not be handed over — though stripping alone
   is insufficient since the default path is guessable);
   (ii) THE LOAD-BEARING LAYER — evidence hypothesis-set validation in `report`: the
   captured entries' hypothesis lines must be EXACTLY the action's own posted set —
   empty when no `hypothesis-id` input, or precisely one line whose
   `hypothesisId === state.hypothesisId`, `status === 'OPEN'`, and (when set)
   `title === state.hypothesisTitle` — any other hypothesis line, wrong status, wrong
   id, or duplicate ⇒ evidence-integrity failure: stderr, nothing staged, return 3.
   Rationale: in the wrap-one-command model the action is the only legitimate
   launch-token holder, so any hypothesis line it didn't post is forged BY DEFINITION;
   events remain attacker-authored by design (they come from the instrumented
   process). Token theft then yields nothing capture will bless.
   Tests: the forged-verdict-via-stolen-token scenario re-run with a
   PRODUCTION-SHAPED env (including `DEBUG_ACTION_OUTPUT_DIR`) posting a forged
   CONFIRMED via the real `/hypothesis` endpoint with the stolen token ⇒ report 3;
   plus hermetic pins for wrong-status/wrong-id/duplicate/unexpected lines; plus the
   env-strip pin (wrapped command sees no `DEBUG_ACTION_*`).
2. **Collector content digest (Critical — doc-note disposition REJECTED).** A
   same-length in-place rewrite passes `verifyLogIdentity` (metadata + byte count, no
   digest). Collector-side fix in `scripts/debug_server.js`: each session keeps an
   incremental SHA-256 of every byte the collector has appended (update at append
   time, in memory); `GET /sessions/:id/logs` (the serve path) hashes the on-disk
   content up to `bytesWritten` and refuses on mismatch with the existing 409
   replaced-class response (new reason string `session_log_tampered`), which
   `readSessionLive` already surfaces as `live_read_log_replaced` (verify the
   mapping). Implementation discipline: debug_server.js is ~2,600 lines and its test
   file larger — TARGETED reads/edits only at the session-append and logs-serve
   sites; append new tests to `scripts/debug_server.test.js` (in-place same-size
   rewrite ⇒ serve refused; ordinary append/read unaffected; the identity checks
   stay). No new files — census stays 43.
3. **Invocation-scoped staging (Important).** After `report`'s entry guards (state +
   nonce) and BEFORE capture: unlink the evidence child's three well-known files
   (`session.log`, `report.md`, `report.json`; ENOENT-tolerant), so a reused
   output-dir can never upload a previous invocation's evidence as this run's. Test:
   pre-planted stale files are gone after a failed capture (upload would find
   nothing).

Spec amendments (same commit as this note): Security invariants gain (7) the
hypothesis-set equality contract and (8) the collector content digest; the trust-model
sentence about `verifyLogIdentity` strength is superseded.

Fix commit message:
`fix(action+collector): hypothesis-set evidence contract, append digests, invocation-scoped staging (Codex T5 r2)`.

#### Task 5 fix round 3 — Codex re-review decisions (recorded before code moves)

Codex on `6d33180`: digest + contract mechanics verified; rulings (a)/(c)/(e) accepted
with T8 notes, (d) optional. Critical ×1 + Important ×2 remain. Decisions:

1. **Launch token never persisted (Important #1 — the architectural fix).** The
   expected-set contract was derived from attacker-writable state; the root cause is
   the launch token at rest. Restructure:
   - `start` absorbs the mint and the optional hypothesis `OPEN` post: handshake →
     mask launch token → occupant auth (`probeLaunchToken`, while the token lives) →
     `POST /session` → mask session token → optional `POST /hypothesis` (`OPEN`) →
     write state WITH `sessionId`/`sessionToken` and WITHOUT `launchToken` — the
     launch token lives and dies in `start`'s process memory.
   - Collector change (`scripts/debug_server.js`, targeted edit at the logs-serve
     auth site + tests): `GET /sessions/:id/logs` additionally accepts the session's
     OWN token via `x-debug-session-token` (launch token still works). Everything
     else stays launch-only — so after `start` returns, NO credential that can post
     hypothesis lines exists anywhere in the job. The hypothesis-set contract becomes
     STRUCTURAL; the report-side check stays as belt.
   - `run` simplifies: no mint, no `probeToken` — inject env from state, execute,
     record. `report` authenticates its live read with the session token
     (`readSessionLive({ token: sessionToken })` — verify debug_evidence sends it as
     Bearer; the collector must accept the session token for this route via either
     header; adapt the collector edit accordingly and document which channel is used).
     `collectorAlive` := successful authenticated read (401 from a foreign occupant
     fails it).
   - State-file consequences: `launchToken` gone from every state shape and from
     `collectStateSecrets` (session token stays); T3/T4 tests referencing it adapt.
2. **Staging-window detectability (Critical — prevention impossible in same-job
   composite staging; Codex's threat-model option taken WITH teeth).** After staging,
   `report` computes SHA-256 of each staged file and (a) prints
   `evidence-sha256 session.log=<hex> report.md=<hex> report.json=<hex>` to stdout —
   the step log is streamed and immutable once emitted — and (b) writes them to
   `GITHUB_OUTPUT` as `evidence-digest`. T8 documents: a detached child CAN rewrite
   staged files before upload (inherent to same-user staging); the logged digests
   make any such swap detectable by comparing the artifact against the step log.
3. **Cleanup hoisted (Important #2).** The invocation-scoped unlink of the three
   well-known staged files moves to the TOP of `report` (before the state/nonce
   guards): a failed start, absent state, or foreign nonce must also leave nothing
   uploadable. The shared-output-dir byte race stays as already ruled.

Spec amendments (same commit): invariant 2 rewritten (launch token exists only in
`start`'s memory; session token is the wrapped command's only credential and gains
same-session read scope), state-file field list updated, lifecycle bullets updated
(mint in `start`), staging-window detectability added to the artifact section.

Fix commit message:
`fix(action+collector): memory-only launch token, session-token read scope, staged digests, entry cleanup (Codex T5 r3)`.

#### Task 5 fix round 4 — Codex re-review decisions (recorded before code moves)

Codex on `9fca375`: memory-only launch token verified real; rulings — (i) keep
`throw -> 1` for start-phase machinery failures (document the three moved classes;
purge the spec's stale "run mints/posts" text), (ii) no retry required but the live
read must gain a real deadline, (iii) session token at rest acceptable as a scoped
capability but writable state must never anchor capture trust, (iv) the pre-auth idle
sweep is acceptable. Critical x2 + Important x1 remain. Decisions:

1. **Responder-authenticated capture (Critical #1 — counterfeit collector).**
   `report` trusted `port`/`sessionId`/`sessionToken` from attacker-writable state, so
   a wrapped command could point capture at a counterfeit listener serving
   contract-shaped NDJSON with a 200 — Bearer proves the client to the listener;
   nothing proved the listener to the action. The only cross-step channel a same-user
   process can neither read nor rewrite is RUNNER MEMORY: a step output written by
   `start` is parsed out of its `GITHUB_OUTPUT` file when the start step ends — before
   the wrapped command exists — and interpolated into later steps' env from the runner
   process itself. Structure:
   - `collector_boot.js` mints a **responder HMAC key** at boot (crypto-random, held
     beside the launch token, authorizes NOTHING — it only signs responses), passes it
     into `createDebugServer` (new option), and adds it to the private handshake line.
   - `start` captures it, masks it, and emits it as step output `collector-hmac-key`
     via `GITHUB_OUTPUT`. It is NEVER written to state. T6 wires
     `DEBUG_ACTION_COLLECTOR_HMAC_KEY: ${{ steps.start.outputs.collector-hmac-key }}`
     into the **report step only** (queued T6 note; `start` needs an `id:`; the
     action's public outputs never expose it).
   - Collector (`scripts/debug_server.js`, logs-serve site): a request carrying
     `x-debug-challenge: <nonce>` gets the response header
     `x-debug-proof: hex(HMAC-SHA256(key, nonce + '.' + sha256hex(servedBytes)))`,
     computed over the exact bytes written to the response.
   - `report` sends a fresh crypto-random nonce per capture and verifies the proof
     over the exact received bytes (`timingSafeEqual`). A missing or wrong proof is an
     INTEGRITY failure -> 3, nothing staged — never the unreachable-fallback class. A
     valid-state entry with no key in env is the same integrity class (wiring broke).
     State's `port`/`sessionId`/`sessionToken` remain routing data only (ruling iii).
   - Tests: counterfeit 200-with-contract-shaped-NDJSON listener (no proof, then
     wrong-key proof) -> 3, nothing staged; replay — a recorded `(body, proof)` pair
     from an earlier challenge fails a fresh nonce; honest lifecycle green with the
     proof verified (harness delivers the key to `report` the way `action.yml` will:
     env seam); key absent from state and from every staged byte.
2. **In-memory render + digest (Critical #2 — staged-pathname race).** Staging, then
   rendering FROM the staged path, then re-reading to hash let a detached child swap
   bytes so reports and all three digests consistently described the forgery. New
   `report` flow: capture -> validate hypothesis set from the in-memory bytes ->
   render `report.md`/`report.json` FROM THE SAME in-memory buffer (import the
   renderer programmatically from `scripts/debug_report.js` — precedent:
   `collector_boot` requires `debug_server` — or pipe the buffer to its stdin; the
   renderer's input must never be a re-read of a shared pathname) -> SHA-256 all three
   payloads from memory -> only then write the staged files (write-only sinks) ->
   print digest lines -> locked CAS -> outputs. The r3 detectability disposition
   becomes sound: digests describe INTENDED bytes, so any post-write swap mismatches
   the step log. Tests: corrupt each staged file after `report` returns and assert the
   logged/output digests still describe the intended bytes; corrupt the staged
   session.log between write and return to prove render/hash never re-read it.
3. **Bounded live read (Important).** `readSessionLive` (`scripts/debug_evidence.js` —
   in scope: Codex implicated it by line) gains httpRequestJson's settle-guaranteed
   discipline: absolute wall-clock deadline + response byte cap + the existing idle
   timeout; every rejection path settles. Constants sized generously above the
   collector's max session size (implementer picks; document beside the constants).
   Tests in `debug_evidence.test.js`: a one-byte-per-interval drip rejected by the
   deadline; an over-cap response rejected; both settle. Census stays 43 (existing
   payload files edited, none added).
4. **Ruling (i) spec purge + T8 note.** Spec step chain and lifecycle bullets
   rewritten so mint/occupant-auth/OPEN-post live in `start` (`run` = spawn + record
   only); the T8 queue gains: the three start-phase classes exit 1 (infra-throw), and
   the 1-vs-3 taxonomy documentation names them.

Spec amendments (same commit): new Security invariant 9 (responder authentication;
writable state never anchors capture trust), invariant 2 gains the responder-key
clause (signs responses, authorizes nothing), the boot-handshake line gains the key,
the artifact staging paragraph now says digests are computed from in-memory bytes
before staging, and the stale `run` mint/post text is removed from the step chain and
lifecycle bullets.

Fix commit message:
`fix(action+collector+evidence): responder-authenticated capture, in-memory render digests, bounded live reads (Codex T5 r4)`.

#### Task 5 fix round 5 — Codex re-review decisions (recorded before code moves)

Codex on `d727315`: memory-first rendering/digests and the bounded reader are sound;
rulings — (A) idle-timeout classification acceptable (fallback stays unauthenticated
and `finish -> 3`; operational, not fail-open), (B) renderer import coupling
acceptable WITH a sentinel pin + T8 note, (C) superseded — see Critical #2. Critical
x2 remain. Decisions:

1. **Asymmetric responder proof (Critical #2 + ruling C).** A symmetric HMAC key in
   `report`'s process environment is readable by a surviving same-user detached child
   (process-environment disclosure; GitHub masking protects logs, not processes) —
   and a same-user reader can then SIGN forged responses. Replace HMAC with Ed25519:
   - `collector_boot.js` generates the keypair at boot
     (`crypto.generateKeyPairSync('ed25519')`). The PRIVATE key never leaves the
     collector process (it is passed into `createDebugServer` and is never
     serialized — not in the handshake line, not in state, not in any output). The
     handshake line carries the PUBLIC verification key (single-line SPKI DER
     base64) instead of the HMAC key.
   - `start` emits the public key as step output `collector-verify-key` (replaces
     `collector-hmac-key`; T6 note updated below). It is NOT masked — it is public
     by design. The runner-memory channel now guards the key's INTEGRITY, not its
     secrecy: disclosure is harmless, but only runner memory prevents a same-user
     process from substituting its own keypair. The key must NEVER be read from
     state or any attacker-writable file (test: a key-shaped field planted in state
     is ignored; a counterfeit signing with its own keypair -> 3).
   - `report` verifies with `crypto.verify(null, canonicalRecord, publicKey, sig)`;
     env var becomes `DEBUG_ACTION_COLLECTOR_VERIFY_KEY`.
2. **Signature bound to the unfiltered request target (Critical #1).** The logs
   route accepts query filters, and the r4 proof bound only `nonce + bodyhash` — so
   a counterfeit could forward `report`'s fresh challenge to the REAL collector with
   `?limit=1`/`?type=event` and return the validly signed SUBSET (the collector was
   an online signing oracle for incomplete responses; with the expected-hypothesis
   state cleared, a green incomplete report resulted). Fix: the collector signs a
   domain-separated canonical record — versioned prefix, method, the EXACT request
   target as received (`req.url` verbatim, path + query), the challenge nonce, and
   `sha256hex(servedBytes)` — in a fixed field order with an unambiguous encoding
   (newline-delimited; digest/nonce fields fixed-length hex). `report` reconstructs
   the record from what it INTENDED — `GET /sessions/<sessionId>/logs` with NO query
   string, its own nonce, the hash of the received bytes — and verifies the
   signature over that reconstruction: a filtered relay signs a different target and
   fails verification with no extra comparison logic. Tests: a live-relay
   counterfeit that forwards the real challenge to the real collector with a filter
   and returns the signed subset -> 3, nothing staged; the four r4 counterfeit
   strategies and the replay test adapt to the signature form; a pin that the
   handshake JSON and state contain no private-key material.
3. **Ruling B sentinel pin.** A test pins `debug_report.js`'s imported export
   surface (`buildReport`/`renderMarkdown`/`renderJson`) so a payload refactor fails
   the suite loudly, not capture at run time. T8 queue gains the coupling note.
4. **T6 note update (supersedes the r4 wiring note).** `start` keeps its `id:`; the
   report step env line becomes
   `DEBUG_ACTION_COLLECTOR_VERIFY_KEY: ${{ steps.start.outputs.collector-verify-key }}`;
   the action's public outputs still never expose it.

Spec amendments (same commit): Security invariant 9 rewritten (asymmetric proof;
integrity-not-secrecy channel; target binding), invariant 2 cross-reference and the
boot-handshake bullet updated (public verification key), step-chain item 2 wording
updated.

Fix commit message:
`fix(action+collector): asymmetric responder proof bound to the unfiltered request target (Codex T5 r5)`.

#### Task 5 fix round 6 — Codex re-review decisions (recorded before code moves)

Codex on `769b729`: Ed25519 private-key confinement and exact request-target
binding "look correct"; rulings — (b) collector-death-makes-evidence-unverifiable
accepted (fails closed), (c) challenge charset accepted with a T8 protocol note,
(a) REJECTED: the step-output-integrity concern is exploitable from the CURRENT
wrapped command, not a hypothetical future refactor. Critical ×1. Decisions:

1. **Capture moves into the `run` step — the only trusted process that spans
   command execution (the Critical).** The attack: `runSubcommand` passes the
   runner's full env (including `GITHUB_ENV`) to the wrapped command, which
   appends `BASH_ENV=/tmp/attacker.sh`. GitHub applies the env file to SUBSEQUENT
   steps; non-interactive bash sources `BASH_ENV` at shell startup — i.e. inside
   the report step, AFTER the runner resolved step-level `env:` — so the attacker
   script overwrites `DEBUG_ACTION_COLLECTOR_VERIFY_KEY` and a counterfeit
   collector signs the intended canonical record with its matching private key.
   Step-env precedence does not help; target binding does not help. Structure:
   - `action.yml` (T6) wires
     `DEBUG_ACTION_COLLECTOR_VERIFY_KEY: ${{ steps.start.outputs.collector-verify-key }}`
     into the **run** step, NOT the report step. The run step's shell starts and
     its env resolves BEFORE the wrapped command exists, so no `BASH_ENV` written
     by that command can reach it; a child cannot rewrite its parent's memory.
     The key stays PUBLIC, so the child reading `/proc/<ppid>/environ` learns
     nothing useful — this is precisely what round 5's asymmetric switch bought.
   - `run` therefore performs, in one process, in order: invocation-scoped
     cleanup of stale staged files → spawn the wrapped command (sanitized env) →
     await exit → authenticated bounded capture → hypothesis-set validation →
     in-memory render → in-memory digests → stage → print digest lines → write
     outputs → locked CAS. Every round-2..round-5 property moves with it
     unchanged; only the hosting step changes.
   - **`run` exits 3 on any integrity failure** (counterfeit/unverified/relayed
     response, tampered log, hypothesis-set deviation, render/validation
     failure, missing verify key), staging nothing. This is the decisive part: a
     composite step that fails makes the action fail, and NO later step can undo
     it — so even a fully poisoned `report`/`finish` cannot turn a failed
     verification green. Command-failure semantics stay deferred to `finish`
     (unchanged, and not security-critical: a hostile command can always choose
     its own exit code).
   - `report` (`if: always()`) becomes **publish-only and key-free**: append the
     staged `report.md` to the Step Summary when a capture is recorded; when none
     is, ensure no stale staged files remain and record the diagnostic for
     `finish`. It performs no capture, no verification, and holds no credential —
     nothing it can be tricked into is security-relevant.
2. **Runner control-plane hygiene (defense in depth, not a boundary).** The
   wrapped command's env additionally strips `GITHUB_ENV`, `GITHUB_PATH`,
   `GITHUB_OUTPUT`, `GITHUB_STATE`, and `GITHUB_STEP_SUMMARY` alongside
   `DEBUG_ACTION_*`. Codex is right that this is not a boundary — the child can
   still enumerate the runner's command files under `RUNNER_TEMP` — so it is
   documented as raising the bar, never as prevention. Test: the wrapped command
   sees none of those five variables while `DEBUG_SESSION_*`/`DEBUG_LOG_URL` and
   unrelated variables survive.
3. **Honest threat-model statement (T8, prominent).** A hostile wrapped command
   can poison the remainder of the JOB (BASH_ENV via runner command files) — this
   is inherent to executing an arbitrary command in GitHub Actions and applies to
   every action in that job, not only this one. The action's structural answer is
   that every evidence decision is made inside `run`, before any such poisoning
   can take effect, and that a failed `run` cannot be un-failed by a later step.
   Corollary to document: do not place a second adversarial-input invocation
   after a hostile one in the same job.
4. **Tests.** (a) THE round-6 test: the wrapped command writes a `BASH_ENV`
   payload into the runner's env-file channel and stands up a counterfeit
   collector with its own keypair; the harness applies the poisoned env to the
   POST-command steps exactly as a runner would, and capture still succeeds
   against the authentic collector because `run` already holds the real key —
   with the mutant (key read in a post-command step) going red. (b) `run` exits 3
   with nothing staged on each integrity class. (c) The five stripped control
   variables. (d) All existing round-2..round-5 capture tests move to `run` and
   keep passing. (e) `report` with no recorded capture stages nothing and leaves
   nothing stale.

Spec amendments (same commit): step-chain items 3–4 rewritten (capture in `run`;
report publish-only), invariant 9 gains the trusted-process clause, new invariant
10 (control-plane hygiene + the job-poisoning statement), exit-semantics table
gains the `run` exit-3 integrity row.

T6 note (supersedes the round-4/round-5 wiring notes): the verify key is wired
into the **run** step (`id: run` for outputs); `report` receives no key; the
action's `event-count`/`report-path`/`evidence-digest` outputs now map to
`steps.run.outputs.*`.

Fix commit message:
`fix(action): capture in the trusted run process, fail-closed exit 3, control-plane env hygiene (Codex T5 r6)`.

#### Task 5 fix round 7 — pre-empted Critical (implementer-found; recorded before code moves)

Found by the round-6 implementer on its own work at `8d65a63`, accepted by the
coordinator without waiting for Codex: the unreachable-collector path is the
round-6 Critical in a different suit, and it is reachable by the same actor.

**The hole.** When no authenticated read is possible (`live_read_connect_failed`
/ `_timeout` / `_unauthorized`), `run` stages the on-disk session log labeled
`evidenceAuthentic: false`, sets `reportRendered: true`, and returns **0**; only
`finish` fails the job, on `collectorAlive: false` read from
`action-state.json`. The wrapped command can KILL the collector (same OS user),
write a forged NDJSON log at the derivable `.debug/` path, and leave a detached
child that rewrites `action-state.json` after `run`'s CAS commit and before
`finish` reads it — flipping `collectorAlive`/`evidenceAuthentic` to true. Result:
a green job carrying wholly attacker-authored evidence. Round 6's "a failed
composite step cannot be un-failed" only protects the paths where `run` returns
3; this path returns 0 and hands the verdict to a later step through an
attacker-writable channel — exactly the shape Codex rejected in round 6.

**Decision: the unreachable class returns 3 from `run`.** This is a
where-not-what change: the exit table already rules "collector died before
capture ⇒ fail with diagnostic (partial evidence still staged if readable)", so
the job outcome is unchanged — only the deciding process moves from `finish`
(untrusted, post-command) to `run` (trusted, spans command execution).
- Staging behaviour is UNCHANGED: the labeled on-disk fallback is still staged
  and still marked `evidenceAuthentic: false`, because partial evidence a human
  can read is the point of the fallback. The label is a reader's aid, never a
  gate.
- `reportRendered` stays truthful for whatever was actually produced; `finish`
  keeps its existing checks (belt — the job is already red).
- The round-1 decision that a live-read failure MAY fall back to disk survives
  intact; what changes is that falling back can no longer yield exit 0.
- Nothing about the integrity classes changes: they still stage nothing and
  return 3.

**Tests.** (a) THE test: a wrapped command that kills the collector, writes a
forged session log at the derivable path, and leaves a detached child which
rewrites `action-state.json` to all-green after `run` commits — `run` must
return 3, and the poisoned state must not change that; `finish` in the poisoned
env is irrelevant because the action already failed. (b) The benign case: a
collector that dies without an attacker still stages the labeled partial log AND
returns 3, with the diagnostic intact. (c) Existing unreachable-path tests adapt
from expecting 0 to expecting 3, keeping their staging assertions. Mutation: the
unreachable class returning 0 again turns test (a) red.

After this round, every evidence verdict — integrity failure, unreachable
collector, and success — is decided inside `run`. `finish` retains only the
command-failure mirror and teardown reporting, neither of which is
security-critical (a hostile command chooses its own exit code regardless), which
is recorded in the spec and queued for T8.

Spec amendments (same commit): exit-table "collector died before capture" row
notes the verdict is raised by `run`; invariant 10 gains the sentence that ALL
evidence verdicts are made in `run`.

Fix commit message:
`fix(action): unreachable-collector verdict decided in run, not deferred to finish (pre-empted Critical)`.

#### Task 5 fix round 8 — Codex re-review decisions on r6+r7 (recorded before code moves)

Codex on `8d65a63` + `4ac5aeb`: **both Critical verdict bypasses are closed**, and
it independently verified the load-bearing platform property (a failed internal
composite step remains a failure unless `continue-on-error` is set, which this
design never sets). Rulings (a)–(d) below are final and feed T8. Important ×1:

1. **`report` deletes authentic evidence on the renderer-failure paths (the
   Important).** `report`'s entry cleanup equates `reportRendered !== true` with
   "nothing captured" and unlinks all three staged files. But on either
   renderer-failure class, `run` has ALREADY authenticated and staged
   `session.log` and set `evidenceCopied: true` — that is r6 adaptation 5's
   deliberate "real evidence a human can read" — leaving only
   `reportRendered: false`. Because `report` runs before the upload step, it
   destroys the authentic raw log before anyone can receive it. The r6 taxonomy
   test missed this by asserting staging immediately after `run` and never
   executing the publish step. Fix:
   - When the nonce matches AND `evidenceCopied === true`, `report` PRESERVES
     `session.log` and removes only the unavailable report surfaces
     (`report.md`, `report.json`), skipping the summary append. Every other
     entry path (absent state, foreign nonce, `evidenceCopied` false) keeps
     today's clear-everything behaviour.
   - New SEQUENCE test (the gap this exposes is a test-shape gap, not just a
     code gap): renderer failure → `runSubcommand` → `reportSubcommand` →
     assert `session.log` is still present and byte-identical for upload, and
     that the two report surfaces are gone. Mutation: restoring the
     unconditional three-file unlink turns it red.
   - Sweep the other staging assertions for the same shape: any test that
     asserts "staged after `run`" for a class whose `report` step then runs must
     assert through `report`, not before it.
2. **T8 documentation wordings — Codex's rulings, to be used close to verbatim.**
   - (a) Staging window ACCEPTABLE with precise wording: *the artifact is not
     self-authenticating*. Validate it against the trusted run-process digest in
     the step log; **duplicate or conflicting `evidence-sha256` lines invalidate
     the artifact**; treat the `evidence-digest` output as convenience, not the
     trust anchor.
   - (b) Step Summary forgeability ACCEPTABLE, but "the artifact is evidence" is
     TOO STRONG: neither the Step Summary nor the artifact alone is
     authoritative — *the artifact plus the matching trusted digest* is.
   - (c) KEEP the evidence-asserting outputs on a red `run`: they truthfully
     describe staged partial evidence. Document that **output existence does not
     imply authenticity**; the failed `run` outcome is the provenance signal.
   - (d) KEEP `finish`'s belts: they still catch ordinary corruption and wiring
     failures, their comments correctly admit they are not security boundaries,
     and `finish` remains necessary for the command-exit mirror.

Spec amendment (same commit): the artifact section's detectability paragraph
adopts wordings (a)/(b) — artifact + matching trusted digest is the unit of
trust; duplicate/conflicting digest lines invalidate.

Fix commit message:
`fix(action): preserve authenticated session.log through report's renderer-failure cleanup (Codex T5 r8)`.

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

> **TASK 5 CLOSED.** Codex approved `510a422` after eight fix rounds (five
> Criticals, two Importants, all closed). Final architecture, for reference while
> wiring: the launch token lives and dies in `start`'s memory; the collector
> proves its identity with an Ed25519 signature over a canonical record binding
> method + exact request target + challenge nonce + body hash; the verification
> key travels as a PUBLIC step output and is consumed ONLY in `run`; capture,
> validation, rendering, hashing and staging all happen inside `run`, which exits
> 3 on any integrity failure or unreachable collector; `report` is publish-only
> and key-free; `finish` keeps the command-exit mirror and honest belts.
>
> **ADAPTATION NOTE — supersedes every earlier T6 note in this plan.** The block
> below was written before rounds 3–8 and is stale in exactly these ways. Apply
> all of them:
> 1. **Outputs move to `run`.** `event-count` and `report-path` must map to
>    `steps.run.outputs.*`, NOT `steps.report.outputs.*` (capture happens in
>    `run` now). ADD a fourth output `evidence-digest`, also from
>    `steps.run.outputs.*`, described as a convenience — not the trust anchor
>    (round-8 ruling (a)).
> 2. **Verification key wired to `run` only.** The run step's env gains
>    `DEBUG_ACTION_COLLECTOR_VERIFY_KEY: ${{ steps.start.outputs.collector-verify-key }}`.
>    The report step must NOT receive it — that is the round-6 Critical, and a
>    structural test must pin the key's absence from every step but `run`.
> 3. **Nonce: inherit, never remap (Codex T6 ruling).** `start` writes
>    `DEBUG_ACTION_INVOCATION_NONCE` to `GITHUB_ENV`, which GitHub makes
>    available to subsequent steps automatically. Do NOT add
>    `${{ env.DEBUG_ACTION_INVOCATION_NONCE }}` to any step's env: the expression
>    `env` context excludes runner-inherited variables, so an explicit remap
>    resolves to empty and breaks the wiring it was meant to create. A structural
>    test pins that no such remap exists.
> 4. **`report` fails closed without the nonce (Codex T6 ruling; small
>    `support.js` change in this task).** When `report` finds no invocation nonce
>    in its env, it must clear ALL staging, emit a diagnostic, and return 3 —
>    never degrade to "state exists". Unit test + mutation (degrade-to-loose
>    turns it red).
> 5. **Reconcile the env blocks against the CODE, not this block.** `start` now
>    owns mint/occupant-auth/OPEN-post, so read `validateActionInputs` and each
>    subcommand's actual env reads and wire exactly what they consume. Report any
>    variable in the block below that the code no longer reads.
> 6. `run` can now exit 3, and the composite deliberately sets no
>    `continue-on-error` — that is what makes a failed verdict unfixable by later
>    steps (Codex verified). Keep `always()` on report/upload/teardown/finish so
>    they still run after a failed `run`, and keep the ordering
>    `run → report → upload` (round 8: `report` decides what upload sees).

**Files:**
- Create: `actions/debug-evidence/action.yml`
- Modify: `actions/debug-evidence/support.js` (report's missing-nonce path, item 4)
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

#### Task 6 fix round 1 — Codex review decisions (recorded before code moves)

Codex on `12a1a3f` (fresh thread): the shipped YAML routes the key correctly,
maps all five outputs to `steps.run`, uses the exact guards and enumerates the
intended paths; the disclosed 13-call-site test edits check out (no expected
value changed, no assertion removed, no skip added); no verify-key neutralizer
needed; the second red step after an early `start` failure is honest noise.
Important ×4. **A PREMISE THIS PLAN CARRIED IS WRONG:** the round-8 T6 ruling
that `GITHUB_ENV` values are excluded from the `env` expression context is FALSE
on the current runner — Codex verified against the runner source
(`FileCommandManager.cs`, `CompositeActionHandler.cs`). The remedy is not to add
the remap; it is to stop using a job-global channel for invocation identity.

1. **Nonce becomes an invocation-scoped step output (Important #1).** `start`
   validates inputs BEFORE replacing the nonce in `GITHUB_ENV`, and `GITHUB_ENV`
   persists to every later step of the JOB. So: invocation A leaves nonce `N1`
   and evidence in the shared default directory; invocation B fails validation
   early; B's `report` inherits `N1`, finds A's state carrying `N1`, declares it
   OWNED, and the `always()` upload publishes A's evidence under B's artifact
   name. B stays red, so this is not Critical, but invocation isolation is
   broken. Fix — remove the job-global channel entirely:
   - `start` mints the nonce and emits it as step output `invocation-nonce` as
     its FIRST action, before input validation or anything else that can fail.
   - `start` NO LONGER writes `DEBUG_ACTION_INVOCATION_NONCE` to `GITHUB_ENV`.
     Job-global pollution and the replay channel both disappear.
   - `action.yml` wires `DEBUG_ACTION_INVOCATION_NONCE: ${{ steps.start.outputs.invocation-nonce }}`
     into run/report/teardown/finish. Step outputs are per-invocation by
     construction: B's steps read B's `start`, so they can never observe A's
     value; if B's `start` died before emitting, the value is empty and the
     strict subcommands refuse. This SUPERSEDES the round-8 no-remap rule and
     the structural test that pinned it — that test must be replaced, not kept.
2. **`teardown` must be strict about the nonce (Important #2).**
   `rejectForeignNonce` accepts a missing nonce, so a fresh job whose `start`
   fails early, pointed at a REUSED custom output directory holding stale state,
   reads that state and runs `kill(state.pid)` — a pid that may belong to another
   invocation or be recycled to an unrelated process on a self-hosted runner.
   Codex: strict `teardown` is REQUIRED, strict `finish` is sensible symmetry.
   Missing nonce ⇒ do not read or act on state. Apply to both.
3. **Upload must be scoped to what THIS invocation staged (Important #3).**
   `clearStagedEvidence` throws on anything but `ENOENT` (e.g. a stale
   `session.log` that is a DIRECTORY), which fails `report` — but upload still
   runs, because its condition only checks that `start` was not skipped. The
   pinned uploader treats paths as files, directories or globs with
   `implicitDescendants` and `followSymbolicLinks` enabled, so that directory's
   descendants get uploaded. A concurrent invocation can likewise restage between
   cleanup and upload, and with `run` skipped there is no current digest to
   expose the substitution. Fix (both halves — Codex offers either; they
   compose):
   - The staged evidence child is INVOCATION-SCOPED (name derived from the
     invocation nonce), and `run` emits its absolute path as output
     `evidence-dir`. A stale sibling from another invocation can then never be
     inside this invocation's upload path set.
   - `run` emits `evidence-staged` naming exactly which payloads it staged
     (empty when none). Upload gains
     `if: ${{ always() && steps.run.outputs.evidence-staged != '' }}` and takes
     its `path:` entries from `steps.run.outputs.evidence-dir`. Do NOT gate on
     `report` succeeding — that would suppress valid evidence when only the Step
     Summary failed (Codex's explicit warning).
   - ALSO investigate and report: whether the pinned `upload-artifact` exposes a
     control for symlink following. The staging window plus `followSymbolicLinks`
     means a hostile swap could substitute a symlink to an unrelated readable
     file and pull its bytes into the artifact. If no control exists, record it
     as a T8 threat-model line (the digest mismatch detects it after the fact).
4. **The structural tests do not pin what their names claim (Important #4).**
   Codex demonstrated four mutation SURVIVORS against the committed tests:
   replacing all four exact guards with bare `${{ always() }}` passes (prefix-only
   check); adding `C:/foreign/**` to the upload block passes (requires the three
   expected paths, never rejects extras); moving the verify-key mapping into an
   INLINE comment passes (comment stripping removes only whole-line comments, so
   the carrier assertion still reports the run step while no real mapping
   exists); the output-dir expression check requires ≥6 occurrences where the
   file has 8, so two sites could diverge unnoticed. Fix: a test-local SEMANTIC
   reader (~60 lines, no dependency — the repo ships zero runtime deps) that
   walks `runs.steps` and extracts per step: `name`, `id`, `if`, `shell`, `uses`,
   `with:` paths, `env` keys AND values, `run` — stripping comments properly
   (from an unquoted `#` to end of line). Every assertion then becomes an EXACT
   `deepEqual` — env key sets, the full `if:` string, the sorted upload path
   list, the output map — so extras and near-misses fail. Keep the SHA-pin
   assertions on RAW text, since they must see the version comments. Re-run
   Codex's four mutations as regression checks and report each going red.

Fix commit message:
`fix(action): invocation-scoped nonce and staging, strict teardown/finish, semantic structural pins (Codex T6 r1)`.

Spec amendment (same commit): the artifact section records that the evidence
child is invocation-scoped and that upload is gated on a trusted `run` output;
invariant 10 notes that invocation identity travels as a step output, never
through `GITHUB_ENV` (with the corrected `env`-context fact).

#### Task 6 fix round 2 — Codex re-review decisions (recorded before code moves)

Codex on `763a2b1`: the nonce/staging flow closes last round's stale-invocation
upload path; rulings (a) document accumulation, do NOT add a sibling reaper —
cleanup belongs to callers who can prove no concurrent invocation exists;
(b) keep `evidence-dir`/`evidence-staged` internal, not public outputs;
(c) correct that `report` must not delete foreign invocation data;
(d) nonce/path discoverability is fine — the nonce is routing, not authority;
(e) deferral to Task 7 is supported by the runner source, but Task 7 MUST
explicitly test two invocations sharing an output directory with distinct
artifact names, INCLUDING a second invocation whose `start` fails. Important ×2,
Minor ×2:

1. **Post-command step outputs are not a security boundary either (Important
   #1 — deterministic, no race).** `run` publishes `evidence-dir`/`evidence-staged`
   AFTER executing the wrapped command, and `upload` trusts both. The child can
   enumerate the CURRENT step's output file under
   `RUNNER_TEMP/_runner_file_commands` (stripping the env var hides the variable,
   not the file — `support.js` already says so), pre-write `evidence-staged=x`,
   then open a heredoc whose delimiter is the exact line `run` will later write:
   `evidence-dir<<evidence-staged=session.log report.md report.json`. Every
   trusted line `run` appends afterwards is swallowed as heredoc body until that
   known line closes it, leaving an attacker-controlled multiline upload path AND
   an open gate. The runner creates these files under `_runner_file_commands`,
   processes them only after the handler returns, and supports multiline outputs
   exactly this way. Codex: *derive upload paths from a pre-command `start`
   output; do not use post-command outputs as a security boundary.* Fix:
   - `start` (which mints the nonce) emits `evidence-dir` as a step output —
     pre-command, therefore trusted by the same argument as the verification key.
   - `action.yml`'s upload step takes its `path:` entries from
     `steps.start.outputs.evidence-dir` and is guarded by
     `if: ${{ always() && steps.start.outputs.evidence-dir != '' }}` — an
     entirely pre-command gate that still closes when `start` died early.
     `if-no-files-found: ignore` covers "nothing was staged".
   - `run`'s `evidence-dir`/`evidence-staged` outputs are REMOVED (not demoted):
     per ruling (b) they are internal, and leaving them would imply a trust they
     do not carry. `run` keeps `evidence-digest`, which is already documented as
     convenience, never the trust anchor.
   - Residual, to be DOCUMENTED not prevented (it follows from same-user
     staging): a hostile command can plant files inside the invocation-scoped
     directory, so the artifact may contain payloads this action never staged.
     The already-ruled trust unit answers it — only bytes whose SHA-256 matches a
     digest line printed by the trusted `run` process are evidence; a planted
     file has no backing digest, and a `run` that staged nothing prints none.
   - Tests: a wrapped command that writes the heredoc payload into the real
     step-output file must NOT influence the upload path set (assert the parsed
     `action.yml` takes its paths from `steps.start.outputs.*` only, and that no
     `steps.run.outputs.evidence-*` reference survives anywhere); `start`
     emitting `evidence-dir` before validation; the gate closing when `start`
     fails early.
2. **The test migration silently defanged a security test (Important #2).**
   `support.test.js:2601` (state-key fallback) still passes `env: {}`, so it now
   exits at the nonce gate BEFORE testing whether a planted verification key can
   be used — a regression to `env key || state key` would pass it. Fix: supply a
   VALID nonce and omit only the verification key, so the test reaches the branch
   it advertises. Mutation: reintroduce the state fallback ⇒ red. Also re-check
   the tests at 688–705, which no longer reach their advertised no-state/no-session
   branches (duplicate matrix coverage exists elsewhere, but the names must stop
   lying). SWEEP the whole file for the same shape: any test whose env was
   mechanically updated this round and which now short-circuits before its
   advertised branch.
3. **The semantic reader still fails open outside its selected fields (Minor
   #1).** It ignores the entire `inputs:` section and every `runs:` key at indent
   2, so changing `fail-on-command-failure`'s default to `"false"` or
   `using: composite` to `using: docker` leaves the parsed structure unchanged —
   the "unfamiliar structure throws" claim is false as written. Fix: parse and
   assert `runs.using`, and parse `inputs:` with exact assertions on the
   security-relevant defaults (at minimum `fail-on-command-failure: "true"`);
   make unknown indent-2 keys under `runs:` throw. Re-run both mutations as
   regression checks.
4. **Spec contradictions (Minor #2) — FIXED BY THE COORDINATOR** in the same
   commit as this amendment, not by the implementer: state no longer described as
   carrying the launch token (it carries the session token and nonce); `report`
   no longer described as validating/rendering/hashing; the verification key
   described as delivered to and verified by `run`.

Fix commit message:
`fix(action): upload path from a pre-command start output, restore the defanged key test, tighten the structural reader (Codex T6 r2)`.

#### Task 6 fix round 3 — Codex re-review decisions (recorded before code moves)

Codex on `858e024`: **no Critical findings**; the single-invocation upload
boundary is materially improved (neither the guard nor the paths depend on
post-command outputs), the three formerly defanged branch tests reach their
intended branches, and `assertNothingStaged` closes the wrong-directory vacuity.
Rulings: (a) README disclosure ONLY, and KEEP `session-id` on `run` — moving it
to `start` would advertise sessions even when the post-command ownership CAS
rejects the invocation; document all five outputs as availability-only and
attacker-suppressible. (b) Accepted, and a correction to our note: with
`if-no-files-found: ignore` the pinned uploader reports that nothing matched and
uploads NO artifact — it does not create an empty one. (c) Accumulation stays a
documented tradeoff, no reaper; Task 7 tests two invocations for expression
NAMESPACING and must NOT label that adversarial isolation. Important ×1, Minor ×2:

1. **Scope the guarantee to the first/only invocation in a job (Important).**
   Per-instance step outputs prevent ACCIDENTAL cross-invocation inheritance; they
   do not stay trustworthy after an earlier hostile command in the same job.
   Invocation A's command sets `BASH_ENV` via its `GITHUB_ENV` file; invocation
   B's `start` step is `shell: bash`, so it sources that attacker code before
   `start` runs, and the code appends a last-wins `evidence-dir=/foreign` to B's
   own `GITHUB_OUTPUT` — B's upload then reads an attacker-selected path. Codex:
   *either require separate jobs after an instrumented command, or explicitly
   scope the security guarantee to the first/only invocation in a job; same-job
   secure reuse is not achievable with this runner channel.* Decision: SCOPE IT,
   explicitly, everywhere it is claimed.
   - `action.yml`'s comment currently claims pre-command outputs are unreachable.
     That OVERCLAIMS — correct it to state the scope: unreachable by THIS
     invocation's wrapped command; a prior instrumented command in the same job
     invalidates the guarantee.
   - Spec invariant 10 rewritten by the coordinator in this same commit (done).
   - T8 gains a prominent note: run a second instrumented command in a SEPARATE
     JOB; the guarantees are stated for the first/only invocation.
   - A structural/unit test pinning that the scope wording exists is fine, but no
     behavioural change is expected here — the fix is honesty about the boundary.
2. **The runner model accepts an impossible unterminated heredoc (Minor).** The
   test-local model consumes through EOF, but the real runner THROWS when no
   matching delimiter appears and marks the step failed, so the asserted multiline
   `evidence-dir` is not what GitHub would parse; the attack also uses a delimiter
   `run` no longer emits. Fix BOTH: make the model throw on an unterminated
   heredoc (matching the runner), then re-close the attack with a delimiter the
   child can PREDICT — Codex's suggestion, `session-id=${DEBUG_SESSION_ID}`, works
   because the child holds `DEBUG_SESSION_ID` in its own env and can therefore
   spell the exact line `run` will later write. The attack must still succeed
   against the model (proving the channel is attacker-owned) before the
   `action.yml` assertions prove the defence.
3. **Stale text (Minor).** Spec line 261 fixed by the coordinator (done). The
   implementer fixes the code-side stragglers that still assign the authenticated
   read or key consumption to `report`: `support.js:577`, `support.js:1392`,
   `support.test.js:3658`. Grep the whole action directory for the same shape
   rather than fixing only those three.

Fix commit message:
`fix(action): scope the guarantee to the first invocation, correct the runner heredoc model, purge stale report-era comments (Codex T6 r3)`.

#### Task 6 fix round 4 — Codex re-review decisions (recorded before code moves)

Codex on `c466664`: **no runtime wiring or security-boundary regression**; the
corrected heredoc attack is valid (closes on the predictable `session-id` line,
and the model now rejects a missing terminator consistently with the runner), and
both coordinator spec fixes verified correct — invariant 10 accurately
distinguishes namespacing from adversarial isolation and requires a separate job,
invariant 2 correctly assigns the authenticated read to `run`. Minor ×3, all
review-quality:

1. **The scope pin fails open on the crucial negation.** The test checks keywords
   plus the "THIS invocation" claim, so changing `does NOT survive` to
   `DOES survive` leaves every assertion green — Codex reproduced that mutation in
   memory. A pin that passes while the comment states the opposite of the truth is
   worse than no pin. Fix: assert the NEGATIVE same-job limitation and the
   separate-job requirement directly (match the polarity, not just the vocabulary),
   and re-run Codex's mutation as a regression check.
2. **The stale-text sweep missed two sites.** `collector_boot.js:44` still says a
   symmetric secret would inhabit `report`'s environment (capture is in `run`);
   `support.test.js:3661` still says upload takes the paths "`run` reports" (they
   come from `start`). Fix both, then re-run the sweep with the polarity of the
   claim in mind rather than the identifier alone.
3. **Forward reference — Codex chose option (ii).** `action.yml:213` says the
   README already contains the warning, but no tracked README does. Change it to
   future/required language ("Task 8's README must say so"), so the comment states
   an obligation rather than a false fact.

**HARD TASK 8 REQUIREMENTS (recorded here so they cannot be lost).** Task 8's
README must carry BOTH, in its own words but with the same meaning:
- **The separate-job limitation.** The integrity guarantees hold for the first (or
  only) invocation in a job; an earlier instrumented command in the same job can
  poison a later invocation's `start` through `BASH_ENV`; run a second
  instrumented command in a SEPARATE JOB.
- **The five-output availability disclosure.** `command-exit-code`, `session-id`,
  `event-count`, `report-path` and `evidence-digest` are availability-only and
  attacker-suppressible (the wrapped command can blank or garble them through the
  runner's file-command channel). Nothing security-critical rides on them: the
  verdict is `run`'s exit code, and the digest's authoritative copy is the step
  log.

Fix commit message:
`fix(action): pin the scope claim by polarity, finish the stale-text sweep, make the README reference an obligation (Codex T6 r4)`.

#### Task 6 fix round 5 — Codex re-review decisions (recorded before code moves)

Codex on `07e0441`: the polarity pins catch the demonstrated reversals, the Task 8
obligation wording is correct, invariant 10 and the `run` attribution read
correctly, and *"no later step can un-fail a failed composite step"* is accurate
within this action. Process rulings: when Task 8 lands, KEEP a positive/negative
semantic pair and update it deliberately — never delete it; and do NOT hash the
comment block (hashing detects formatting edits, not semantic reversals, and
encourages mechanical checksum updates — new security claims get explicit polarity
assertions instead). Important ×1, Minor ×1:

1. **The parent-memory boundary is conditional, and nothing establishes it (the
   Important).** `support.js:1074`, `action.yml:136` and spec:258 treat
   parent-process memory as an UNCONDITIONAL boundary against the wrapped command.
   That is false on supported Linux configurations permitting classic same-UID
   `ptrace`: Yama mode 0 allows attaching to any dumpable same-UID process, and
   the kernel documentation names arbitrary code injection as a consequence.
   Neither `run` nor the collector is made non-dumpable, the collector's pid is
   persisted in state (directly targetable), and the action neither verifies nor
   documents the required policy. A hostile native command could interfere with
   `run` or extract the collector's signing state — defeating authenticated
   evidence outright. This prerequisite silently underwrites every in-process
   guarantee built in Task 5 rounds 4–7. Codex accepts any ONE of: enforced
   non-dumpability; a fail-closed check; or an explicit threat-model restriction.
   **Decision — do the restriction, but make it OBSERVABLE rather than merely
   stated (strictly stronger than the minimum):**
   - `start` reads `/proc/sys/kernel/yama/ptrace_scope` once on Linux and records
     the result in state: `restricted` (>= 1 — prerequisite met), `permissive`
     (0), or `unknown` (file absent / unreadable / non-Linux).
   - `permissive` and `unknown` print a prominent warning to the step log AND
     stamp the rendered `report.md` / `report.json` with a line stating the
     in-process guarantees were not established on this host. The evidence carries
     its own caveat — the same doctrine as the labeled unreachable-collector
     fallback, where the label travels with the artifact.
   - Default behaviour stays PROCEED, not refuse: a permissive host is a weaker
     platform, not a detected tampering event, and refusing would break legitimate
     self-hosted callers with no escape hatch. **Ask Codex to rule** whether this
     must escalate to a fail-closed refusal (exit 3) — the coordinator's judgement
     is that labeling is proportionate and refusal is not, but the reviewer owns
     this call.
   - Spec: platform-prerequisite block added by the coordinator in this same
     commit (done); a new invariant 11 describes the detection and labeling.
   - **Wording, same finding:** *"a view of the world the command cannot
     influence"* is too broad — the command plainly influences files, state,
     collector availability and staging inputs. Only specifically protected
     in-process values can carry that claim, and only under the prerequisite
     above. Rewrite every site that overstates it, using the polarity discipline
     from round 4.
2. **`collector_boot.js:44` is factually wrong about inheritance (Minor).** It
   says the wrapped process tree "inherits" the verifying step's environment. It
   does not: `support.js:1142` copies the environment and strips every
   `DEBUG_ACTION_*` entry before spawning. The intended argument is reading a
   PARENT's environment through `/proc` where permissions allow — say that
   instead.

Fix commit message:
`fix(action): detect and label the ptrace prerequisite, scope the in-process boundary claims (Codex T6 r5)`.

#### Task 6 fix round 6 — Codex re-review decisions (recorded before code moves)

Codex on `cb4fa89`: the `collector_boot.js` inheritance wording is now accurate and
the narrowed in-process prose is materially better — but **Critical ×1** plus two
Minors, and the Critical invalidates last round's central assumption.

1. **The detector marks the principal platform as protected when it is not
   (CRITICAL).** Yama modes 1 and 2 are bypassable via `CAP_SYS_PTRACE`; only
   mode 3 forbids attachment unconditionally. **Standard VM-based GitHub-hosted
   Linux runners give workflow commands passwordless `sudo`.** So on the action's
   principal platform a hostile wrapped command can elevate, attach to the
   waiting `run` process or to the collector, and defeat the authentication
   boundary — while the detector records `restricted` and emits no warning at all.
   Codex: *this is the action's core authentication guarantee failing on its
   principal platform.* Checking the current process's effective capabilities
   would not help: the escalation path is `sudo`, not an inherited capability.
   The classifier also contradicts its own test — `"4"` or `"999"` returns
   `restricted`; unknown numeric values must stay `unknown`.
2. **RULING — refuse, do not merely label.** Refuse BEFORE launching the wrapped
   command whenever the prerequisite is not positively established — both
   `permissive` AND `unknown`. An explicit opt-out may allow clearly labeled
   best-effort evidence. The reasoning that settles it: *post-command labeling
   cannot itself be trusted on a platform where that command can rewrite `run`* —
   the adversary the caveat warns about can strip the caveat. My round-5
   judgement (labeling is proportionate) was wrong for exactly that reason.

**Decisions.**
- **Honest classification.** `readPtraceScope` returns `unconditional` (mode 3
  only), `privilege-bypassable` (1 or 2), `permissive` (0), or `unknown`
  (anything else — non-numeric, out-of-range including `4`/`999`, unreadable,
  non-Linux). The prerequisite is POSITIVELY ESTABLISHED only for
  `unconditional`. No vocabulary anywhere may call 1 or 2 "restricted",
  "protected" or "met".
- **New input `evidence-trust`, default `strict`.** `strict`: when the
  prerequisite is not positively established, `start` REFUSES before the wrapped
  command runs (exit 3) with a diagnostic naming the detected policy, the reason
  (modes 1/2 are bypassable and hosted runners grant passwordless `sudo`), and
  the two ways forward. `best-effort`: proceed, and emit the qualification in
  THREE places — (i) `start`'s step log BEFORE the command runs (the trustworthy
  copy: immutable once streamed, and the command cannot retract it), (ii) `run`'s
  own log immediately before its digest line (ruling (b): the qualification
  belongs beside the authoritative trust-unit record, including renderer-failure
  cases where only `session.log` is uploaded), and (iii) the report caveat as
  today — documented as the strippable copy, useful for honest runs only.
- **Consequence, stated plainly and put back to Codex for confirmation:**
  default `strict` means the action REFUSES on a standard GitHub-hosted VM runner
  (`ptrace_scope` 1 + passwordless `sudo`), which is the documented principal
  platform. Every hosted-runner caller — including this repo's own Task 7 demo —
  must set `evidence-trust: best-effort`. The coordinator follows Codex's ruling
  because silent over-trust is a worse failure than a loud, documented refusal,
  and a caller who sets `best-effort` has consciously accepted the model. Codex
  is asked to confirm the default given that consequence.
- **Ordering (Minor).** `readPtraceScope()` currently evaluates as a DEFAULT
  PARAMETER, i.e. before the function body and therefore before the nonce and
  evidence-directory outputs — contradicting `start`'s own "ahead of any
  filesystem work" invariant and the tests that pin it. Move detection AFTER
  publishing the two identity outputs, through an injected reader so the ordering
  is testable.
- **Ruling (c).** Re-reading in `run` is defense-in-depth only, never a fix, and
  the comment claiming the policy "cannot change" is FALSE — a privileged actor
  can change modes 0–2 at runtime, including after any pre-command re-read. Fix
  that comment; do not add the re-read as a security measure.
- **Ruling (a).** The `caveats` JSON field is acceptable as additive, provided
  Task 8 documents it. **Added to the hard Task 8 requirements**, alongside the
  separate-job limitation and the five-output availability disclosure: Task 8
  must document `evidence-trust`, why `strict` refuses on hosted runners, and
  what `best-effort` costs.
- **Task 7 note:** the demo workflow must set `evidence-trust: best-effort` and
  say why in a comment — the repo's own dogfood becomes the worked example of the
  limitation.

Fix commit message:
`fix(action): refuse unless the ptrace boundary is positively established, honest mode classification (Codex T6 r6)`.

#### Task 6 fix round 7 — Codex re-review decisions (recorded before code moves)

Codex on `99d4d0e`: the strict refusal placement, the no-spawn proof, the
identity-before-detection ordering, the three qualification copies and the
disclosed test adaptations all check out, and the corrected platform-prerequisite
block reads correctly. Rulings: **(a) keep `strict` as the default** — reversing
it would recreate silent over-trust; (b) Task 8 documents that the DEFAULT hosted
configuration refuses, but must NOT claim strict is unreachable — include the
mode-3 hardening route; (c) the open upload gate after a refusal is acceptable
(the invocation directory is empty, `if-no-files-found: ignore` uploads nothing,
and retaining the pre-validation output preserves the identity invariant);
(d) a Task 8 grammar note suffices for the log prefixes, but it must distinguish
strict from best-effort and eventually define step provenance plus
duplicate/conflicting-line handling. Important ×1, Minor ×3:

1. **Best-effort inherits strict-mode trust claims (the Important).** Adding a
   second trust regime left every trust claim unconditional: `action.yml:78` calls
   `run` the process "whose account … can be trusted", lines 95–100 call its log
   authoritative, `support.js:1486` repeats it, and spec:243 said artifact plus the
   trusted `run` digest IS the unit of trust. Those hold only after a successful
   STRICT admission. In best-effort the stated threat is exactly that the command
   may rewrite `run`, forge its digest, or suppress its qualification. Make the
   contract CONDITIONAL everywhere it appears:
   - successful strict admission ⇒ artifact plus matching `run` digest is the
     authenticated trust unit;
   - best-effort ⇒ artifact, digest, report and post-command qualification are
     DIAGNOSTIC CLAIMS ONLY; none authenticates the evidence;
   - the pre-command `start` warning establishes ONLY that best-effort was
     consciously selected — never that the later evidence is trustworthy.
   Spec fixed by the coordinator in this same commit (done). The implementer fixes
   every code-side site, with polarity pairs on each (required conditional form;
   forbidden unconditional inverse).
2. **The mode lookup resolves inherited properties (Minor).** `PTRACE_MODES` is a
   plain object read as `PTRACE_MODES[text]`, so `__proto__`, `constructor` and
   `toString` resolve inherited values instead of falling through to `unknown`.
   The security predicate still refuses them, so it is not a boundary bypass, but
   it violates the classification contract and can put objects/functions into
   diagnostics or state. Use `Object.hasOwn`, a null-prototype object, or a `Map`,
   plus one inherited-key test.
3. **Explicit empty `evidence-trust` bypasses its own input error (Minor).**
   `validateActionInputs` correctly rejects `''`, but `main()` normalises with
   `|| 'strict'` first, so an explicitly empty action input is silently rounded
   instead of raising the promised error. Use nullish/default-by-absence handling:
   omitted ⇒ `strict`; explicit empty ⇒ validation error.
4. **"Hosted callers must use best-effort" is not categorical (Minor).**
   `action.yml:73` overstates it. A trusted EARLIER step can use the hosted
   runner's own passwordless `sudo` to set `kernel.yama.ptrace_scope=3`, and mode
   3 cannot subsequently be lowered — so strict IS reachable on hosted runners
   after deliberate hardening. Reword to "hosted callers using the default mode 1
   configuration must opt in or harden the runner first."
   **Task 7 consequence (supersedes the round-6 demo note):** the dogfood workflow
   SHOULD exercise the STRICT happy path by setting mode 3 in a prior step before
   invoking the action, with a separate best-effort scenario if desired. That is
   strictly better than demonstrating only the opt-out.

Fix commit message:
`fix(action): make the trust contract conditional on the admission mode, harden mode lookup and input defaulting (Codex T6 r7)`.

#### Task 6 fix round 8 — Codex re-review decisions (recorded before code moves)

Codex on `153bb41`: `Map` and `?? 'strict'` confirmed correct; the fourth mutation
is confirmed as THE STANDARD — required and forbidden halves must each be shown
capable of failing independently, so security-critical pairs get both mutations
when introduced; Task 8's README needs its own semantic polarity assertions, but a
LIGHTER per-section check suffices (hashing a README is brittle and proves only
that someone updated a hash). **Critical ×1** — and it overturns Codex's own
round-7 hardening suggestion — plus Important ×1 and Minor ×2:

1. **Mode 3 does not establish the boundary while the command can reach root
   (CRITICAL).** Mode 3 blocks `ptrace`, but a principal that can become root can
   load a privileged tracing BPF program and overwrite another task's userspace
   memory via `bpf_probe_write_user()` — or insert a kernel module — without ever
   calling `ptrace`. Hosted Linux VMs grant passwordless `sudo`, so the
   `sysctl -w kernel.yama.ptrace_scope=3` route recorded last round does NOT turn
   a default hosted runner into an authenticated strict path: the same `sudo` that
   sets mode 3 opens the BPF route. **Task 7's proposed sysctl-only strict
   scenario would demonstrate a FALSE GUARANTEE and is withdrawn.** Codex: strict
   admission needs real privilege/process isolation — at minimum the wrapped
   principal must have no route to root, privileged BPF, kernel modules, or
   equivalent — or hosted execution must remain best-effort. Decisions:
   - **Strict admission requires ALL of:** Yama mode 3; effective uid ≠ 0;
     passwordless `sudo` unavailable (probe `sudo -n true`, treating any
     unexpected outcome as "available" — fail closed); and no dangerous capability
     in the process's own permitted/effective set (`CAP_SYS_ADMIN`, `CAP_BPF`,
     `CAP_SYS_PTRACE`, `CAP_SYS_MODULE` via `/proc/self/status`). Any probe that
     cannot be evaluated ⇒ NOT established.
   - **These are the routes CHECKED, never a proof that none exists.** A setuid
     binary, a mounted container socket, or a writable privileged service grants
     the same power unobserved. Say exactly that wherever the prerequisite is
     described — with a polarity pair forbidding "proves no escalation path
     exists"-style claims.
   - **Hosted execution remains best-effort**, and no site may claim otherwise.
     Remove the round-7 "harden with sysctl and strict becomes reachable" wording
     from `action.yml`; replace it with the true statement that mode 3 is
     necessary but not sufficient while passwordless `sudo` remains.
   - Spec prerequisite block rewritten by the coordinator in this commit (done).
2. **The spec's artifact section contradicted its own two-regime block
   (Important).** Lines 218–226 and 237–245 still said unconditionally that "the
   trust unit answers" hostile planting, called `run` trusted, called digest
   comparison "the defence", and said recorded digests "always" make swaps
   detectable — all false under best-effort. **Fixed by the coordinator in this
   commit** (three passages now name the regime they hold in).
3. **The defaulting test infers the default from the live host (Minor).**
   `support.test.js:454` assumes the host is not mode 3, so it would FAIL on
   exactly the hardened runner strict mode is meant for. Normalise through an
   injected `main`/environment-building seam instead of reading the host's policy.
4. **The polarity block does not cover what it claims (Minor).** It scans only
   `ACTION_YML()`, not `support.js`, so the round-7 claim that it protects both
   files is wrong; and it treats the whole action file as ONE haystack, so a
   duplicate comment elsewhere can satisfy a requirement after a consumer-facing
   `description:` disappears. Assert the important surfaces SEPARATELY — at
   minimum the input/output `description:` blocks distinct from comment prose, and
   `support.js` in its own right.
5. **Ruling on `THE TRUSTED PROCESS`:** acceptable with its nearby qualification
   ONLY once strict admission actually establishes the boundary. It does not on
   the documented hosted path, so the qualification must name the checked-routes
   limitation too.

Fix commit message:
`fix(action): strict admission requires no route to root, not merely Yama mode 3 (Codex T6 r8)`.

#### Task 6 fix round 9 — Codex re-review decisions (recorded before code moves)

Codex on `09a377c`: the per-surface polarity rewrite is sound. **Critical ×1,
Important ×3, Minor ×3.** Ruling (b): the PATH-dependent `sudo` probe is NOT
acceptable, and an absolute path alone does not fix it.

1. **`sudo -n true` cannot establish that sudo is unavailable (CRITICAL).**
   Sudoers rules are COMMAND-SPECIFIC: a principal can hold
   `NOPASSWD: /usr/bin/env` while `true` is denied or prompts, so the probe clears
   and the wrapped command then escalates through the allowed command. And the
   coordinator's round-8 claim that a spoofed `sudo` could only DENY was wrong: a
   `PATH`-planted fake exiting 1 with "a password is required" GRANTS strict
   admission while the command later calls the real `/usr/bin/sudo`. Codex's sound
   policy, adopted: **deny strict whenever a `sudo` binary exists at all**, unless
   an independently trusted mechanism establishes the principal has no usable
   rule (nothing here is such a mechanism). Detection must use absolute trusted
   paths (`/usr/bin/sudo`, `/bin/sudo`, `/usr/local/bin/sudo`) and check
   EXISTENCE, never behaviour; any error or ambiguity ⇒ deny. Strict therefore
   means a genuinely locked environment — which is what "real isolation" meant.
2. **`admissionEstablished` trusts the persisted `blockers` array (Important).**
   It validates only `blockers.length === 0`, so a forged
   `{ptrace:'permissive', uid:'root', sudo:'available', capabilities:'CAP_BPF',
   blockers:[]}` — or bare `{blockers: []}` — is ADMITTED after the state
   round-trip. Fix: validate all four fields against their allowed values and
   DERIVE blockers from them; never trust the persisted array. Add the exact
   malformed shapes the current test omits.
3. **Ruling (a), sharpened: an artifact-only stamp is insufficient (Important).**
   A compromised best-effort `run` can forge the same stamp. Instead: `start`
   emits an IMMUTABLE PRE-COMMAND ADMISSION RECORD on EVERY run (step log, before
   the command exists), mirrored into the artifact/report. The trust unit becomes
   **admission record + `run` digest + artifact**, and the checked-routes
   limitation appears in EVERY copy. Spec updated by the coordinator (done).
4. **The live-host dependency is still live on Linux (Important).**
   `support.test.js:526` passes `{getuid: undefined}`, which ACTIVATES the
   parameter default `process.geteuid` instead of simulating an absent API — so on
   the Ubuntu CI matrix it returns the live uid and the test FAILS. Pass `null`.
   Sweep for every other `undefined`-as-absence seam with the same defect.
5. **Minors.** (i) Spec line 257's "Yama mode 3 or real isolation" shorthand —
   fixed by the coordinator in this commit, along with the prerequisite block's
   sudo clause. (ii) `support.js:917` still describes the admission record as the
   old scalar `unconditional`, and lines 1362–1372 retain the ptrace-only
   prerequisite explanation. (iii) `support.js:92` wrongly lists direct
   `/proc/<pid>/mem` as bypassing mode 3 — that file is guarded by a
   `PTRACE_MODE_ATTACH_FSCREDS` check; BPF and kernel modules remain correct
   examples, so drop the `/proc/<pid>/mem` claim rather than qualifying it.

Fix commit message:
`fix(action): deny strict when any sudo binary exists, derive admission from validated fields, pre-command admission record (Codex T6 r9)`.

#### Task 6 fix round 10 — Codex re-review decisions (recorded before code moves)

Codex on `57d3f7b`: the forged-`blockers` path and the behavioural sudo probe are
both closed, and the artifact/trust-unit section is now correctly
regime-conditional. **RULING ON THE DEFAULT — KEEP `strict`**, and the reasoning
is better than the coordinator's request to reverse it: *a pre-command warning is
disclosure, not enforcement; most consumers will not inspect logs before trusting
a green job. Requiring explicit `best-effort` is the correct auditable decision
point.* The input lives in the workflow file, where review and history see it; a
log line does not survive a glance at a green check. Other rulings: fixed sudo
paths are NOT acceptable as the sole check; the human-comparison limit must be
stated in the record and the README; leaving `kill`/`env`/`projectRoot` as
ordinary injectable defaults is reasonable, since explicit `undefined` there does
not silently substitute live host security evidence. **Critical ×1, Important ×1,
Minor ×2.**

1. **The fixed sudo allow-list can FALSELY GRANT strict (CRITICAL).** Codex ran
   the detector directly with `/run/current-system/sw/bin/sudo` present — a normal
   NixOS system-path location — and got `{"result":"absent"}`. A wrapped command
   could invoke that `sudo`, become root, rewrite `run`, and still receive
   `boundary=ESTABLISHED`. **The round-9 Critical forbade EXECUTING a
   `PATH`-resolved binary and interpreting its behaviour; it did NOT make
   fail-closed `PATH` INSPECTION unsafe** — the coordinator read it too broadly
   when instructing "never consults PATH". Fix: parse the inherited `PATH` in
   Node and `lstat` every `sudo` candidate, executing nothing; any candidate
   present, or any candidate that cannot be evaluated, denies. Keep the
   conventional absolute paths as well, so an empty or stripped `PATH` cannot
   shrink the check. Spec contradiction (line 294 said "no sudo binary present at
   all"/"any host where sudo exists is denied" while 313–316 admitted only three
   paths were checked) fixed by the coordinator in this commit.
2. **`best-effort` can emit an authenticated STRICT record (Important).**
   `admissionCaveats` derives `ESTABLISHED` and the trust-unit sentence solely
   from the host readings, independently of `evidenceTrust` — so clear readings
   plus `best-effort` produce
   `evidence-trust=best-effort; in-process boundary=ESTABLISHED` followed by the
   authenticated trust-unit claim, contradicting `action.yml` and the spec, which
   both say everything under best-effort stays diagnostic. Fix: the authenticated
   wording requires `evidenceTrust === 'strict' && admissionEstablished(admission)`.
   Add the missing best-effort-plus-clear-admission test.
3. **The aggregate evaluator does not honour explicit `undefined` (Minor).**
   `evaluateAdmission` immediately invokes each selected seam, so an explicit
   `undefined` probe throws `TypeError: seam(...) is not a function` instead of
   producing an unknown, denying record — the round-9 `seam()` fix covered the
   lower-level readers but not this aggregate path, and no test covers it. Use a
   probe wrapper that validates each value is callable and catches, mapping any
   failure to `unknown` ⇒ deny.
4. **The record must state its own limits (Minor).** It names the three pieces but
   not that the action verifies NONE of their correspondence — comparison is
   external and manual, and must be against the `start` record FROM THE SAME
   INVOCATION. Include the invocation nonce in the record so accidental
   cross-invocation pairing is impossible, and state the manual-comparison limit
   in the record text itself (Task 8's README repeats it).

Fix commit message:
`fix(action): inspect PATH for sudo candidates, gate authenticated wording on strict admission (Codex T6 r10)`.

#### Task 6 fix round 11 — Codex re-review decisions (recorded before code moves)

Codex on `98500b6`: the regime gate, probe wrapper, nonce propagation, PATH union
for non-empty absolute entries and the corrected spec sudo clauses all behave as
claimed. Rulings: default stays `strict`; **(a)** off-PATH, non-conventional sudo
locations are acceptable inside the bounded "routes checked, not a proof" model —
NO extra warning needed, *once the existing warning actually survives Markdown
rendering* (see the Important); **(b)** thin-but-correct `unknown` is
security-acceptable, but a FIXED SAFE reason materially improves remediation —
`unknown: empty-or-relative PATH entry`, and **never interpolate the raw PATH
component** (it is attacker-influenced text); **(c)** the record volume is
acceptable and a Task 8 rendered example is appropriate, but the oversized caveat
must be split first. **Critical ×1, Important ×1, Minor ×2.**

1. **A wholly empty `PATH` falsely clears the sudo inspection (CRITICAL).**
   `sudoCandidatePaths` skips parsing when `pathValue === ''` and returns
   `absent`, while `PATH=":"` and `PATH="/usr/bin:"` correctly return `unknown`.
   Bash defines a null PATH component as the CURRENT DIRECTORY, so `PATH=""` IS
   the null-component case — strict can be granted while `sudo` is reachable from
   the working directory. Worse, `support.test.js:837` PINS the wrong answer, so
   the suite defends the bug. Fix: an explicitly empty string is
   unresolvable ⇒ `unknown` ⇒ deny; ONLY an absent PATH means "conventional
   locations only". Update the test that pinned it, and add the three probe cases
   (`''`, `':'`, `'/usr/bin:'`) as one table so they cannot drift apart again.
2. **The record is TRUNCATED on the human artifact surface (Important).** The
   generated second caveat is 676 characters; `debug_report.js` caps each rendered
   caveat at `EXCERPT_CHAR_CAP` (500), so `report.md` ends `These are the escala…`
   — silently deleting "not a proof that no route exists" and the examples of
   unchecked escalation routes. `report.md` therefore reads STRONGER than
   `report.json` and the logs, and contradicts the spec's claim that every copy
   carries the limitation. This is a cross-component interaction: a Task 2 render
   cap eating Task 6 security text. Fix: SPLIT the generated qualification into
   several shorter caveats, each comfortably under the cap, AND add a
   renderer-level assertion that every required security statement survives in
   Markdown without truncation — assert on the RENDERED output, not the input.
3. **The strict-refusal diagnostic still describes the old three-path rule
   (Minor).** It says strict requires no sudo at `/usr/bin`, `/bin` or
   `/usr/local/bin`, omitting inherited-PATH inspection, and a test pins that
   stale wording. Update both.
4. **The spec overclaimed the nonce's enforcement (Minor).** It said a digest
   "cannot accidentally" be paired with another invocation's record. Nothing
   enforces that — the nonce lets a careful reader DETECT a mismatch. **Fixed by
   the coordinator in this commit.**

Fix commit message:
`fix(action): empty PATH denies, split the admission caveat so the limitation survives rendering (Codex T6 r11)`.

#### Task 6 fix round 12 — coordinator decisions on the round-11 residuals (recorded before code moves)

Both raised by the implementer at the end of round 11, both accepted: they are
silent-drift hazards in the PERMISSIVE direction, which is the class this cycle
has repeatedly found to be the dangerous one. No Codex finding is outstanding;
these are pre-emptive, and go to review together with round 11.

1. **The rendered-length assertion hardcodes `500`.** If `EXCERPT_CHAR_CAP` ever
   changes, the action-side assertion drifts from the renderer silently — and if
   the cap SHRINKS, it drifts permissively, exactly the direction that let the
   truncation through in the first place. Decision: **export `EXCERPT_CHAR_CAP`
   from `scripts/debug_report.js` and import it in the action test.** The
   objection (adding an export to a payload file to serve an action test) does not
   apply here: `support.js` already imports `buildReport`/`renderMarkdown`/
   `renderJson` from that module (Task 5 round 4), and Task 6 round 1 added a
   sentinel test pinning that export surface. Extending an already-pinned,
   already-load-bearing surface by one constant is coherent; leaving a magic
   number that can silently disagree with the renderer is not. Extend the sentinel
   to cover the constant so its removal fails loudly.
2. **369 characters of headroom is thin for prose that has grown every round.**
   The renderer-level assertion catches an over-cap caveat only once it exists,
   and reports it as a truncation hunt. Decision: **add a margin guard** —
   every generated caveat must be ≤ 400 characters after escaping, failing with a
   message that NAMES the offending caveat and states the remaining margin. This
   is authoring-time feedback, not a second correctness check; the truncation
   assertion remains the correctness one.

Not adopted: encoding remediation advice in the `PATH=''` reading. The literal is
fixed by Codex ruling (b) and must stay fixed; the "unset it rather than emptying
it" guidance belongs in Task 8's README, and is added to the hard T8 requirements.

Fix commit message:
`fix(action): pin the render cap by import and guard caveat authoring margin (round-11 residuals)`.

#### Task 6 fix round 13 — Codex re-review decisions on r11+r12 (recorded before code moves)

Codex on `fbaf8d6` + `f2c3ef6`: empty `PATH` is correctly denied and distinct from
an unset one; the static caveat split, regime gate, nonce wording, cap export and
margin concept all work FOR THE ENUMERATED FIXTURES; the `PATH=''` remediation
belongs in Task 8's README (placement confirmed); no duplicate test is needed in
`debug_report.test.js` — the cross-component action test is the correct owner; and
the record volume plus a rendered README example remain acceptable **once
producer-derived findings are bounded**. Important ×1, Minor ×1.

1. **The truncation class is still reachable: the sudo finding embeds raw,
   unbounded, unsanitised PATH bytes (Important).** `detectSudoBinary` joins every
   matching candidate verbatim into the reading, the vocabulary accepts arbitrary
   length and multiline values, and `admissionCaveats` inserts that value into the
   admission record. Codex's two production probes: a legitimate 362-character
   nested absolute candidate produced a **579-character caveat**, truncated by
   `report.md` at the 500 cap; and a candidate containing a **newline** produced
   `present: /tmp/evil\nFORGED-LINE/sudo`, which PASSED admission validation and
   split the supposedly single-line record. The round-11/12 guards only exercised
   short hand-written findings, so "every generated caveat stays below the cap" —
   and the spec's "each generated caveat is one short statement" — are false for
   values the real detector produces. **Note the proximate cause is ours:** round
   10 widened the sudo vocabulary from `\/\S+` to `\/[^,]+` to accommodate
   directories containing spaces, and that widening is what admitted unbounded,
   multiline content. Decisions:
   - **The persisted sudo reading becomes fixed-size and single-line.** No raw
     PATH bytes enter the admission record, the refusal diagnostic, or any
     caveat — anywhere. Vocabulary: `absent`; `present: <count> at
     sha256=<64 hex>`; `unknown: empty-or-relative PATH entry`; `unknown`. The
     hash is SHA-256 over the sorted, NUL-joined matched candidate paths, so two
     hosts with the same sudo set hash identically and an operator can recompute
     it from their own listing without us disclosing anything.
   - **The vocabulary regexes become strict and anchored** — that is what makes
     "fixed-size, single-line" enforceable rather than aspirational. Anything not
     matching is an unreadable record ⇒ deny. Round 10's lesson applies directly:
     a vocabulary widened for a display convenience is a hole.
   - **We deliberately do NOT emit the matched paths anywhere.** The actionable
     fact is "sudo exists on this host, so strict is impossible here"; the
     operator does not need our list to act, and Task 8 documents where the
     inspection looks. Emitting them sanitised would rebuild the injection surface
     for no decision-relevant gain.
   - **Sweep every other reading for the same property.** `ptrace`, `uid` and
     `capabilities` are believed bounded (fixed labels / a fixed capability set),
     but that must be PROVEN at the field level, not assumed: each reading gets an
     anchored vocabulary and a test that a producer-derived value cannot exceed
     it.
   - **Tests must run through the real producer chain**, which is the gap that
     hid this: `detectSudoBinary → evaluateAdmission → admissionCaveats →
     renderMarkdown`, with a long-absolute-path case and a newline-path case,
     asserting a single line, within the authoring margin, no raw bytes present,
     no truncation marker, and vocabulary accepted. Mutation: interpolate the raw
     paths again ⇒ both the length and the injection assertions go red.
2. **The sentinel's comment contradicts the observed mutation (Minor).** It says
   an undefined cap makes every length silently pass; in fact `length <= NaN` is
   false, so the guard fails loudly but incoherently — which is the round-12
   finding, and the comment predates it. Rewrite the comment to match.

Fix commit message:
`fix(action): bound the sudo reading to fixed-size single-line metadata (Codex T6 r13)`.

#### Task 6 fix round 14 — coordinator decision on the round-13 residual (recorded before code moves)

Raised by the implementer at the end of round 13 and adopted: **three of the four
readings were bounded by luck of construction, not by design.** The anchored
vocabularies enforce the shape of the readings that exist today, but nothing in
the code states the invariant — a fifth reading could be added tomorrow with an
unbounded value AND a matching unbounded vocabulary, and the field sweep would
only catch it if someone remembered to extend the loop. That is an ENUMERATED
defence against a class this cycle has now hit twice (round 11's `unknown` reason,
round 13's `present:` value). Make it STRUCTURAL:

1. **Every reading passes through one validator before its vocabulary is
   consulted.** A reading must be a string, ≤ 128 characters, and contain NO
   control characters at all — not merely no `\r`/`\n`, since NUL and escape
   sequences also corrupt logs, terminals and the rendered record. Today's
   maxima are ptrace 21, uid 8, sudo 85, capabilities 51, so 128 is generous
   headroom while still making an interpolated path impossible.
2. **A rejected reading becomes `unknown` and DENIES**, and is recorded as a
   distinct blocker naming the field — so an operator can tell "this host failed
   the check" from "our own reading was malformed", which are different problems
   with different fixes. It must never throw.
3. **The validator is the gate, not a lint:** the vocabulary check runs only on
   values that already passed it, so a future unbounded vocabulary cannot
   reintroduce the class on its own.
4. **Tests:** a synthetic fifth reading carrying 9000 producer bytes, one with an
   embedded newline, one with a NUL, and one non-string — each must deny, name
   its field, and never reach the vocabulary. Mutation: remove the validator ⇒
   the synthetic-reading tests go red, proving the guard rather than the
   enumerated vocabularies is what stops the class.

Also recorded from round 13, not implemented: the `present: <count>` cardinality
is producer-derived and decision-irrelevant (one sudo is enough to deny). KEPT —
it makes the digest interpretable and the vocabulary is Codex-specified; the leak
is a small integer, bounded by construction.

**Task 8 hard requirement #7** *(from round 13)*: document the EXACT digest
recipe — sort the matched candidates, join with NUL, SHA-256, lower hex, and the
candidate spelling this action derives (trailing slashes stripped, `<dir>/sudo`).
Without the recipe the digest is a number nobody can check.

Fix commit message:
`fix(action): validate every admission reading structurally, not by enumeration (round-13 residual)`.

#### Task 6 fix round 15 — Codex re-review decisions on r13+r14 (recorded before code moves)

Codex on `9f44c3b` + `4635a8b`: **no Critical, no Important — four Minors.** The
fixed-size sudo representation is called a real improvement and the implementation
is fail-closed throughout; what remains is that two advertised invariants are not
yet literally true. Rulings: keep `present: <count>` (bounded, and it makes the
fingerprint interpretable); keep genuinely historical comments; require printable
ASCII in `structurallyValid`; and Task 8 requirement #7 expands (below).

1. **The producer can emit a count the vocabulary rejects, and our stated maximum
   was wrong.** A probe with 99,999 PATH candidates plus the three conventional
   paths produced `present: 100002…`, which `admissionBlockers` then classified as
   outside the vocabulary — fail-closed, but it breaks the producer/vocabulary
   closure we claimed and degrades the best-effort record. Separately the
   arithmetic in our own report was wrong: `present: ` (9) + digits +
   ` at sha256=` (11) + 64 hex = **84 + digits**, so 85 holds only for a
   single-digit count and an ordinary two-digit count already yields 86. Fix:
   widen the anchored vocabulary to the producer's real range (1–10 digits, giving
   a 94-character worst case, comfortably inside the 128 bound) with NO clamping —
   a clamp would invent a semantics to explain. Correct every stated maximum in
   code, comments and tests, and cover one-, two-, six- and ten-digit counts.
2. **`structurallyValid` does not enforce what round 14 advertised.** It rejects
   C0/C1 and DEL but accepts `U+0085`, `U+2028`/`U+2029` line separators,
   `U+202E` bidi override, and zero-width characters — so "no control characters
   at all" and "true single-line" are both false as written. Current vocabularies
   happen to reject them, so this is not an admission bypass today, but it defeats
   precisely the future-proofing round 14 existed to provide. **Ruling: restrict
   readings to PRINTABLE ASCII now** (`\x20`–`\x7E`); every current reading is
   ASCII by construction, so there is no compatibility cost. Extend the synthetic
   fifth-field cases to cover `U+0085`, `U+2028`, `U+2029`, `U+202E` and a
   zero-width character.
3. **Two shipped explanations are still inaccurate.** `support.js:1710` describes
   the CURRENT admission condition as checking sudo only at a "trusted absolute
   path" — this is not one of the historical references, it is a live contract
   statement omitting the PATH-union mechanism, and it must be corrected. (The
   four genuinely historical comments stay: Codex confirms they are accurate as
   history and are the record of why the design is what it is.)
4. **Spec precision (fixed by the coordinator in this commit).** The round-13
   wording said producer-derived values are never interpolated, while the retained
   count and digest plainly are producer-derived. It now says raw
   producer-CONTROLLED BYTES are never interpolated; only bounded, validated
   metadata is.

**Task 8 requirement #7, expanded by ruling:** "exact recipe" must additionally
specify deduplication, JavaScript's default UTF-16 code-unit sort, UTF-8 hashing
of the NUL-joined string, and that the count represents matched candidate
SPELLINGS rather than distinct binaries or inodes. *(Corrected, round 16 — the
earlier gloss "two PATH entries resolving to the same file count twice" was
misleading in one direction.)* Precisely: candidates are deduplicated by EXACT
SPELLING before inspection, so `/usr/bin:/usr/bin` yields count 1; two DISTINCT
spellings count separately even when they resolve to the same file, so `/a/sudo`
and `/b/sudo` yield count 2 regardless of filesystem identity (no `realpath`, no
inode comparison). *(Added, round 16, verified empirically by the implementer —
without this sentence a reader recomputing the digest from their raw `PATH` gets
a different answer.)* **Deduplication happens on the DERIVED CANDIDATE, not on
the raw `PATH` entry** — after trailing-slash normalisation and after the three
conventional paths are merged in. So `/usr/bin:/usr/bin/` yields count 1, and a
`PATH` entry naming `/usr/bin` does not double-count against the conventional
`/usr/bin/sudo`.

Fix commit message:
`fix(action): accept the producer's real count range and restrict readings to printable ASCII (Codex T6 r15)`.

#### Task 6 fix round 16 — Codex re-review decisions on r15 (recorded before code moves)

Codex on `69b262b`: the six-digit producer probe succeeds end to end, every tested
Unicode case is rejected before vocabulary evaluation, and the spec's precision
wording is confirmed correct. **Minor ×2 — both shipped precision defects, one of
them the coordinator's.** Rulings:
- **Residual (a) is PROVABLY CLOSED, not merely acceptable.** `found` is a
  JavaScript Array, whose maximum length is 2³²−1 = `4294967295` — exactly TEN
  digits. An 11-digit count cannot be formatted, because growing the array past
  that throws first. The 10-digit vocabulary is therefore total, not "wide enough
  for any real host". Record that reasoning where the range is defined, so nobody
  later "tidies" it to a smaller bound.
- **Residual (b) needs no authoring-time mechanism.** Runtime denial is the
  authoritative control, and the existing producer sweep already fails if any
  current producer yields a structurally rejected value. A direct printable-ASCII
  assertion could improve the failure message but is not required.

1. **The rejection diagnostic and two comments are factually wrong (Minor).**
   `support.js:463` diagnoses EVERY structural rejection as "not a bounded
   single-line string", but a value like `cléar` is bounded and single-line — it
   is rejected for not being printable ASCII. Use "not a bounded printable-ASCII
   string." AND the comments at `support.js:395` and `support.test.js:1326` say
   the former gate excluded C1 while admitting `U+0085` NEL — **`U+0085` IS C1**.
   The old gate excluded C0 plus DEL, not C1. Correct both; this is a factual
   error in our own description of the thing we replaced, which is exactly the
   class the now/history rule exists to catch.
2. **Task 8 requirement #7 contradicted the implementation (Minor) — the
   coordinator's text, fixed in this commit.** It said two PATH entries resolving
   to the same file count twice. Candidates are deduplicated by EXACT SPELLING
   before inspection: `/usr/bin:/usr/bin` yields count 1, while distinct `/a/sudo`
   and `/b/sudo` yield count 2 even if they resolve to the same inode.

Fix commit message:
`fix(action): correct the structural-rejection diagnostic and the C0/C1 descriptions (Codex T6 r16)`.

---

### Task 7: Demo repro, dogfood workflow, gate forwarder amendment

> **TASK 6 CLOSED.** Codex approved `1c65825` after SIXTEEN fix rounds (four
> Criticals, five Importants, plus the round-14 structural generalisation). It
> independently reconstructed the digest byte-for-byte. Task 6 final state: the
> composite wires `setup-node → start → run → report → upload → teardown →
> finish`; strict admission is a four-way conjunction (Yama mode 3, non-root
> euid, no `sudo` binary at any conventional path or on the inherited `PATH`, no
> dangerous capability) with every unevaluable probe denying; `evidence-trust`
> defaults to `strict` and REFUSES on the default hosted configuration; the
> admission record streams from `start` before the wrapped command exists and is
> mirrored beside the digest and into the artifact; every reading passes one
> structural gate (printable ASCII, ≤ 128 chars) before any vocabulary is
> consulted.
>
> **TASK 9 GATES — Codex's cross-cutting checks, with its allocation. Recorded
> here because Tasks 7 and 8 must BUILD toward them rather than discover them
> late.**
> 1. **Live runner semantics** *(Task 7 absorbs)* — run the best-effort dogfood
>    and the benign two-invocation namespacing scenario on real GitHub Actions;
>    confirm per-call `steps.start.outputs.*`, `GITHUB_OUTPUT`, `always()`
>    guards, artifact paths, teardown, and output isolation on the real runner.
> 2. **Consumer-side trust-unit reconstruction** *(Task 8 absorbs)* — from a real
>    run's logs and downloaded artifact, manually select exactly one start
>    admission record and one run digest block SHARING A NONCE, reject
>    duplicate/conflicting records or digest lines, recompute every staged-file
>    SHA-256, and confirm the five action outputs are unnecessary and
>    attacker-suppressible.
> 3. **End-to-end failure matrix** *(live portion → Task 7; rest → Task 9)* —
>    invalid input, strict refusal, collector loss, authentication failure,
>    renderer failure, ordinary non-zero exit, signal termination, and
>    `fail-on-command-failure: false`. Verify no later step turns an integrity
>    failure green and that partial artifacts match the documented rules.
> 4. **Credential and artifact census** *(Task 8 absorbs)* — inspect child
>    environment, state, logs, Step Summary and the uploaded archive TOGETHER:
>    no launch token, session token, private signing material, verification-key
>    fallback, or `action-state.json` crosses an unauthorised boundary, and the
>    archive contains only the three enumerated payload names.
> 5. **Cross-module byte contract** *(Task 9)* — collector response bytes,
>    Ed25519 proof verification, in-memory rendering, report JSON/Markdown,
>    printed digests and uploaded bytes verified as ONE chain, including
>    escaping, caveat caps, malformed events and maximum-size captures.
> 6. **Documentation reconciliation** *(Task 8 absorbs)* — semantically compare
>    `action.yml`, the action README, the repo README, `SKILL.md`, the design
>    spec, the demo and the log grammar; Task 8's strict/best-effort claims need
>    their own positive-and-negative polarity pins, covering all seven hard
>    requirements.
> 7. **Residuals stay explicit** *(Task 8 absorbs)* — documentation must still
>    disclose same-job adversarial reuse, staging accumulation, command-planted
>    files, uploader symlink following, the staging race, manually compared
>    admission records, and the checked-routes-not-proof limitation.
>
> **TASK 7 ADAPTATION NOTES — the block below predates Task 6.**
> 1. The demo workflow MUST set `evidence-trust: best-effort` with a comment
>    saying why (hosted runners ship `sudo`, so strict refuses). The round-7
>    "harden with `sysctl` and demonstrate strict" scenario is WITHDRAWN — round
>    8 established mode 3 does not survive passwordless `sudo`, so a sysctl-only
>    strict demo would advertise a false guarantee.
> 2. Add a **two-invocation namespacing job**: two calls in one job sharing an
>    output directory with DISTINCT artifact names, one of them with a failing
>    `start`. Label it NAMESPACING ONLY — expression scoping, explicitly NOT
>    adversarial isolation (Codex ruling, Task 6 round 2).
> 3. The wrapped command's env contract is unchanged, but `run` now strips the
>    runner control plane (`GITHUB_ENV`/`PATH`/`OUTPUT`/`STATE`/`STEP_SUMMARY`)
>    in addition to `DEBUG_ACTION_*` — the demo must not depend on any of them.
> 4. The demo's exit-1 seeded failure now interacts with `evidence-trust`: the
>    job stays green only via `fail-on-command-failure: "false"`, and the
>    admission record will appear in the Step Summary and artifact. Expect it.

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

#### Task 7 fix round 1 (Codex review of `a320b7e`: 2 Important, 3 Minor, 4 rulings)

**The governing theme of this round: a demo that asserts the wrong things is worse than no demo, because it certifies a claim it never checked.** Four of the five findings are the same defect in different places — an assertion whose subject is not the property being advertised.

**(1) Important — the live dogfood can pass with redaction completely broken.** `debug-evidence-demo.yml`'s header advertises that "the artifact's `session.log` must then read `[REDACTED]` where repro.js logged it," but the assertion step checks only `command-exit-code`, `event-count`, a non-empty `session-id` and a non-empty `evidence-digest`. **A collector that wrote the literal fixture into all three payloads still produces `event-count=4`, a session id and valid hashes, so the job stays green while the advertised claim is false.** The unit test does check redaction; the *live* workflow — the only surface that runs on a real runner — does not. FIX: bind `report-path` in the assertion step's env, derive its staging directory, require `[REDACTED]` in `session.log`, and assert the literal `DEMO_FAKE_SECRET` value appears in NONE of `session.log` / `report.md` / `report.json`. The fixture value must reach that step through env, never interpolated into the script body.

**(2) Important — the forwarder cannot unblock the PR that introduces it.** `workflow_run` listeners execute the workflow YAML **as committed on the default branch**, which the gate file itself already states at line ~329. `origin/main` currently has neither the demo workflow nor a forwarder list naming it (verified against the remote, not assumed). So on the PR that introduces both, the gate can observe "Debug evidence demo" pending, and that demo's completion **cannot** fire the forwarder — the gate stays blocked until an unrelated event or a manual re-run. DISPOSITION: take Codex's second sanctioned option — **explicitly accept and document the one-time manual bootstrap** rather than splitting the rollout, because a split would fragment the stacked-PR chain for a cost that is paid exactly once. Add a BOOTSTRAP note to the `workflow_run` comment stating the general rule (a sibling added to this list cannot self-activate until it exists on the default branch, so the introducing PR needs one manual gate re-run), and carry it into Task 9's handoff as a merge-time action. This is a documented one-time operational cost, NOT a fix.

**(3) Minor — the pin check is semantically fail-open.** The `uses:`-pinning assertion scans RAW TEXT including comments, so commenting out a checkout step leaves its pinned `uses:` visible to the test while the parsed workflow has no checkout at all and fails live when resolving the local action. FIX: derive the `uses` entries from the PARSED structure and assert over those. Do NOT adopt `actionlint` — this repo ships `"dependencies":0` and that posture is load-bearing; the parsed-structure half is the policy-compatible fix and closes the demonstrated hole.

**(4) Minor — the invalid-start probe does not prove "stays empty."** It checks only `report.md` and `session.log`, so a created directory holding `report.json` or any other residue passes while contradicting the claim. FIX: replace both checks with `test ! -e "$evidence_dir"`, and update the matching assertion in `support.test.js`.

**(5) Minor — the amended gate comment overstates the artifact bound.** The comment models hostile PR-controlled code and then treats the artifact contents as necessarily three deterministic demo files — but the same PR controls the action, the repro AND the upload configuration, so that bound holds only for the reviewed snapshot. FIX: snapshot-qualify the artifact half (the read-only / no-repository-secrets posture is genuinely structural and stays unqualified). Line ~313's parenthetical still names only the two old siblings — add the third.

**(6) Coordinator finding, not Codex's — the stripped-variable lists are coupled by eye.** `repro.js`'s `STRIPPED_CONTROL_PLANE` and `support.js`'s `RUNNER_COMMAND_FILE_VARS` are byte-identical today and the comment invites comparing them "by eye," but NOTHING pins them: a grep of the suite returns zero hits for either name. Add a sixth command-file variable to `support.js` and the demo's exit-98 guard silently stops checking it while staying green. FIX: import both and assert deep equality — this is the cheap half of Task 9's GATE 5 (cross-module byte contract), and it belongs here because `repro.js` is Task 7's file.

**RULINGS (binding, carry forward):**

- **The no-`continue-on-error` trade is RIGHT — keep it.** GitHub's native runner-level proof is an expected-failure step with `continue-on-error` plus an assertion on `steps.<id>.outcome == failure` (GitHub distinguishes pre-suppression `outcome` from post-suppression `conclusion`). `continue-on-error: ${{ true }}` WOULD evade the scanner's regex — and using it would be deliberate gate-policy bypass, so it is forbidden. **There is no policy-compliant construct that makes a genuinely failed step green afterward.** Keep the direct probes; keep the runner-level consequence labeled a unit-test claim.
- **Strict-refusal evidence is weaker than claimed.** Exit 3, the refusal diagnostic, the sudo finding, the nonce count and the absence checks do establish the hosted refusal. But five SEPARATE greps do not prove those facts belong to ONE coherent admission record, and inspecting output afterward can never prove the nonce was emitted BEFORE admission. FIX: count exactly one admission record and match one ANCHORED record line; ordering stays a source/unit-test claim.
- **Distinct ports are operationally sound but prove nothing about teardown.** They correctly dodge the known signal-to-port-release race; consequently a first collector that IGNORES termination can stay alive while the second succeeds on 8788. Do NOT count this as live teardown coverage — it shows only that teardown returned. Real teardown proof needs bounded process-exit polling or a waiting teardown. FIX: correct the workflow comment, which currently implies more.
- **Both `repro.js` guards are good** — exit 99 prevents a vacuous redaction demonstration, exit 98 makes control-plane leakage a distinguishable failure, and the demo's expected exit 1 makes either regression red.

Codex could not re-run the Node suite (sandbox denied Node's parent-path `lstat` with `EPERM`) or reach GitHub; the coordinator re-ran `support.test.js` independently at `a320b7e` — 121 tests, 120 pass, 0 fail, 1 skip, matching the implementer's report.

#### Task 7 fix round 2 (Codex review of `1c2e2a4`: 3 Important, 1 Minor)

**Round 1 fixed the advertised-claim gap; round 2 is about assertions that are bound to the wrong SUBJECT — each one passes on a log or a file that is genuinely broken.** Two of the three Importants are the same shape as round 1's, one level deeper: the check exists, but what it checks is not what makes the claim true.

**(1) Important — the live redaction proof still fails open, two ways.** `debug-evidence-demo.yml:143` requires only that `[REDACTED]` occurs SOMEWHERE, and `:145` rejects only the COMPLETE original value. Both of these broken cases pass:
- **Partial masking**: `token=[REDACTED]secret-value-0123456789` — the marker is present and the full fixture is absent, yet most of the secret leaked.
- **A `grep` read error**: because `grep` is the CONDITION of an `if`, statuses 1 AND 2 both take the success path, and `set -e` does not rescue it. Codex REPRODUCED a status-2 error while the script continued successfully. The preceding `test -f` neither guarantees continued readability nor eliminates a check/use race — so round 1's claim that the exit-2 fail-open was "unreachable" was too strong.

FIX: parse `session.log` and require EXACTLY ONE event whose `msg` is EXACTLY `DEMO config dump: token=[REDACTED]` — an equality check on the whole field, which no partial mask satisfies. For every negative grep, capture the status and require exactly `1`: `0` means leakage, `>1` means the assertion itself failed and must not read as success.

**(2) Important — the sudo finding is still not bound to the admission record.** `:210` counts admission-record headlines and `:212` independently searches every `Findings:` line, so a log with one headline plus an unrelated second findings line still passes:

```text
ADMISSION RECORD ... boundary=NOT established ...
Findings: ... sudo binary: absent.
Findings: unrelated ... sudo binary: present: 1 at sha256=...
refusing to run ...
```

That falsely establishes this job's UNIQUE LIVE CLAIM — that the hosted runner's actual record found sudo. FIX: require exactly one findings line AND require it immediately after the matched admission headline, preferably by parsing the two-line block together. **Codex answered the over-fitting question directly: the exact headline wording is NOT over-fitted — it is an intentional byte contract, so a legitimate builder change SHOULD require updating this probe.**

**(3) Important — the branch still fails its required scanner, and BOTH proposed dispositions are rejected.**
- **(ii) a fifth allowlist helper is REJECTED.** A line-only `workflows:` helper cannot establish that the key is specifically `on.workflow_run.workflows`; it could bless a strict-superset change to an unrelated action input where ADDING entries weakens policy. `VALIDATION_REMOVAL_PATTERNS` does not repair that missing YAML-context proof. (This refutes exactly the reasoning the coordinator flagged as wanting checked.)
- **(iii) demo-first split is REJECTED — it MOVES both problems rather than resolving them.** The follow-up PR makes the identical old-line/new-line replacement, so its scan still fails; and its own completion is still evaluated by the default-branch listener that lacks the new name, so the bootstrap hole survives. The coordinator's round-1 reversal was wrong on both halves.
- **RULED: the REVERSE SPLIT.** Land the tiny forwarder amendment FIRST, with an explicit audited maintainer clearance for this known scanner false positive, THEN land the demo once the listener is already active on the default branch — which removes the bootstrap re-run entirely, because main's listener already names the demo when the demo's first run completes. If demo-first is chosen anyway, the BOOTSTRAP documentation and its tests MOVE with the forwarder amendment and must be RETAINED, because the cost remains real.
- **This is a merge-workflow decision with a manual security-gate clearance in it, so it is the repo owner's call, not the coordinator's.**

> **OWNER DECISION (2026-08-14): KEEP IT AS ONE PR.** Cycle 4 ships the demo and the forwarder amendment together, declining the reverse split. Two consequences, both accepted deliberately and both owed to Task 9's handoff as MERGE-TIME ACTIONS rather than code:
>
> 1. **The fail-closed scanner must be cleared by hand, once, against the FULL cycle-4 diff** — not the one-line diff the reverse split would have offered. The finding is the known false positive documented above (`-    workflows: ["Validate", "Closeout preview"]`): adding a sibling necessarily removes the old line, and no allowlist helper covers it. A reviewer clearing it should confirm exactly that the removed and added lines differ only by the ADDITION of `"Debug evidence demo"`, with the existing two names unchanged and in order.
> 2. **The gate needs ONE manual re-run at merge.** `workflow_run` listeners execute default-branch YAML, and main's listener does not yet name the demo, so the demo's first completion cannot fire the forwarder. This is paid exactly once; after this PR is on main the listener is active and every later run self-unblocks.
>
> Because the forwarder amendment stays in this PR, the BOOTSTRAP documentation and its four tests STAY HERE TOO — they describe a cost this PR actually incurs. Do not move or delete them.

**(4) Minor — the custom workflow reader can accept a GitHub-invalid workflow.** `support.test.js:5339` accepts any key matching its lexical pattern and `:5361` assigns it with no schema or duplicate-key check. **Renaming a job's `runs-on` to `run-on` leaves every current Task 7 assertion satisfied while GitHub has no runner definition at all.** FIX: assert the required job/step keys structurally and reject duplicate keys. Codex confirmed the parsed `uses` checks DID close the commented-checkout hole and found no remaining SHA-pin bypass — this is a broader schema gap, not a pinning defect.

**CONFIRMED SOUND, no further work:** both `repro.js` guards, the cross-module list contract, the invalid-directory assertion, the teardown wording, and the amended artifact-bound comment. Distinct ports are operationally correct and the workflow now honestly says they prove nothing about collector exit.

**RULING RE-CONFIRMED — the no-`continue-on-error` trade is correct and the search is closed.** `always()` can make later jobs or steps execute but does NOT erase the preceding failure. A separate deliberately-failing workflow plus a `workflow_run` observer could demonstrate the runner behaviour, but it would leave a red producer check or require a privileged dispatch arrangement. **There is no missed same-workflow construct that stays green, demonstrates a genuinely failed composite step, and honours this scanner policy.**

**STANDING CAVEAT for Task 9:** the PR-controlled artifact-upload posture is acceptable ONLY under the stated read-only / no-real-secret threat model, and the artifact BYTES themselves remain unverified until a live download inspection.

Codex again could not execute Node or the scanner (`EPERM: lstat C:\Users\<user>`), so it did not independently confirm the suite counts; the coordinator re-ran `support.test.js` at `1c2e2a4` (122/121/0/1) and the scanner (exit 1, unchanged). Codex did verify `6c3a693` touches only the plan's final blank line and that both `git diff --check` invocations now pass.

#### Task 7 round-2 outcome (`f10982b`) — three corrections to THIS PLAN

Round 2 implemented Importants (1) and (2) and Minor (4); Important (3) was the owner's rollout call, recorded above. Suites: `support.test.js` 125/124/0/1 (coordinator-verified), `npm test` 1122/1081/0/41, `npm run validate` PASS, scanner exit 1 with findings byte-identical to before (the known finding). Three things the round found that this plan got wrong:

**(a) The round-2 prescription for the redaction proof was itself insufficient.** The amendment above prescribes "require EXACTLY ONE event whose `msg` is EXACTLY `DEMO config dump: token=[REDACTED]`". That rule is **satisfied by a log carrying the correct event AND a partially-masked one beside it** — the correct event is present exactly once, and the whole-value sweep sees nothing. The implementer flagged this rather than silently adopting the weaker rule, and closed it with an additional count of events mentioning `token=` at all. **The lesson is the round's own theme applied to the plan: an exactly-one rule constrains the good event's multiplicity, not the bad event's existence.**

**(b) The coordinator broke `npm run validate` in the round-2 amendment commit (`306da76`).** That commit wrote a literal personal Windows path into a tracked file, which `tools/validate_repository.js:156` forbids by the rule named `personal Windows path`. Baselines quoted to the implementer were therefore taken at `1c2e2a4`, not at HEAD. Repaired in-round with the placeholder form the validator's own regex permits. **Standing rule for every future amendment: quote sandbox and tool errors WITHOUT literal user paths.**

**(c) `session.log`'s format was MEASURED, not inferred** — JSONL, one `JSON.stringify`'d event per LF-terminated line, staged byte-for-byte as the collector served it (`debug_server.js:1508` → `support.js:1925`). The real end-to-end lifecycle test now also runs the shipped step script against genuinely captured bytes, so a format change cannot leave the executor tests passing against a model of a format that no longer exists.

**Open items carried to the re-review:** one mutation (M5) SURVIVED — deleting the record-count line in the strict-refusal probe — because the `record_line=` assignment below already fails closed through `pipefail`/`set -e`. It was kept and labelled deliberately redundant. Coordinator's lean is KEEP, because the emergent fail-closed behaviour is invisible to a reader and the label removes the misreading risk; a line that cannot fail is only a defect when it reads as load-bearing. **Residual bound explicitly NOT closed:** the msg-field equality plus the whole-value sweep do not catch a partial leak in a non-`msg` field (e.g. `data`), nor a value split across a line boundary in `report.md`. `repro.js` puts the secret only in `msg` and both reports render from `session.log`, so the demo cannot exercise those channels — flagged rather than implied as covered.

#### Task 7 fix round 3 (Codex review of `f10982b`: 1 Minor, everything else ruled sound)

**One finding stands between Task 7 and closure**, and it is the same shape as round 2's Minor one level deeper: the schema pass rejects the structures it was told about and still admits GitHub-invalid ones it was not.

**(1) Minor — the schema pass still accepts GitHub-invalid workflows.** Two concrete holes:
- **Job IDs are never validated.** `support.test.js:5339` accepts a job ID such as `9.bad`, and `:5427` never checks `jobName` at all. GitHub requires a job ID to start with a letter or `_` and to contain only alphanumerics, `-`, or `_`.
- **An empty `run:` passes the XOR.** An empty `run:` parses to `null` at `:5360` but still satisfies the mere-PROPERTY-presence XOR at `:5444`, so a step with an empty command is admitted.

Both contradict the broad claim the test itself makes at `:5508` — *"rejects documents GitHub would reject."* FIX: validate job IDs against GitHub's rule, and require `uses`/`run` to be non-empty STRINGS rather than merely present keys, each with a constructed negative case. Codex offered an alternative — rename and explicitly bound this as a repository-specific structural reader — but **the fix is cheap and the claim is worth keeping, so fix rather than weaken the claim.** The general rule this keeps re-teaching: a validator's advertised scope is a claim like any other, and must be pinned by a case that would fail if the claim were false.

**RULED SOUND, no further work:**
- **The redaction pair is SUFFICIENT for the demo contract.** `exact.length === 1` plus `mentions.length === 1` means the sole `token=` message is exactly the redacted one (`debug-evidence-demo.yml:157`). **Codex confirmed the round-2 correction to its own prescription was valid.**
- **Positional findings binding is SOUND.** Missing, displaced, doubled and free-floating findings all fail closed; no relevant false-pass survives under `admissionCaveats`' deterministic one-findings-line contract.
- **M5: KEEP.** *"Mutation survival does not make documentary redundancy defective"* — clearly labelled redundancy that exposes an important invariant is acceptable. The coordinator's lean was right.
- **The non-`msg` / split-line residual is ACCEPTED.** `repro.js:89` places the fixture only in the stable `msg` channel and reports derive from the captured log. **Condition: the limitation must be re-scoped explicitly if that input contract ever changes** — i.e. if `repro.js` ever writes the fixture into `data` or any non-`msg` field, this coverage claim must be revisited in the same commit.
- **The scanner/rollout decision is ACCEPTED AS OWNER POLICY** — an external/manual gate, not an unresolved Task 7 code finding. Both merge-time actions stand as recorded.

Codex confirmed `f10982b`'s parent is `da61a21`, that `9bb2113` changes only the plan, and that the workflow and test files at HEAD are byte-identical to `f10982b`. It still could not start Node (`EPERM` on the parent path), so all suite counts remain coordinator-verified rather than independently reproduced.

---

### Task 8: Documentation — action README, repo README, SKILL.md

**Files:**
- Create: `actions/debug-evidence/README.md`
- Modify: `README.md` (Evidence tools section + CI pointer)
- Modify: `SKILL.md` (Analyze & Verify Tooling section)

> **Queued README requirements (Task 5 spec-review dispositions):** the Exit semantics
> section must document the three exit-code classes (mirrored code = your command
> failed; 3 = the action detected a problem and refused; 1 = the action crashed —
> lock/persistence/transport throws land here), the one-invocation-per-output-dir rule
> (concurrent sharers are refused fail-closed at the state level, but staged file bytes
> in the evidence child are not arbitrated), and the signal convention (a signal-killed
> command surfaces as exit 128; the signal name is recorded in state only, which is
> never uploaded).

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

> **Queued test (Task 5 spec-review disposition):** add the missing teardown
> non-ESRCH kill-failure → 3 pin (two lines with the existing `kill` seam: inject a
> kill that throws `EPERM` → assert return 3 and the diagnostic stderr line).

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
