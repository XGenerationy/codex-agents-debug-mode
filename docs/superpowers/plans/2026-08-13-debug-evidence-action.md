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

#### Task 7 round-3 outcome (`10143b1`) and the claim decision (`55dfadf`)

Round 3 closed the reported Minor and found a THIRD hole of the same class unprompted, plus two adjacent defects carrying the identical defect shape — **presence checked instead of value**:

- **Job IDs** were never validated: `9.bad`, `9bad`, `bad.id`, `-lead` all parsed clean and every Task 7 assertion then answered for them. Closed with `GITHUB_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_-]*$/`, pinned by all four bad ids AND a positive control `_ok-9` exercising every character class GitHub allows — so the rule cannot pass by being merely strict. Four mutations including both one-sided halves and an over-strict `/^[A-Za-z]+$/` that goes red on the real workflow's own `strict-refusal` job.
- **An empty `run:`** parsed to null while `Object.hasOwn` stayed true, admitting a step with no command; same for `uses:`, `run: ""`, `uses: ""`, and `run:` holding a nested mapping. The XOR now selects the present key and requires a NON-EMPTY STRING.
- **THIRD HOLE, found in-round:** `on:` with its events deleted satisfied the required-key check, so a workflow that can NEVER TRIGGER parsed clean. Hole 2 one level up. Verified with a second harness that deleting only the new rule re-admits it, so the pin is its own rather than a side effect of the `run:` fix; positive control `on: push` still accepted.
- **Two adjacent defects also pinned:** mapping-typed keys must hold mappings (`env: nope`, `with: nope`, `with:` null were all accepted), and step ids obey the job-id rule and must be unique WITHIN A JOB — with a constructed positive case of one id reused across two jobs, without which the uniqueness check could be hoisted a scope too far and silently reject a legal file.

15 mutations, 14 killed for the right reason with messages captured; the survivor is a declared EQUIVALENT-MUTANT CONTROL (reverting the XOR to `hasOwn(uses) === hasOwn(run)` is logically identical once the non-empty-string rule exists). File restored from a pristine copy after every mutation, SHA-256 verified each time.

**THE CLAIM DECISION — coordinator's, recorded after the fact because the code moved first (a deviation from this cycle's record-then-fix discipline, noted rather than glossed).** The implementer reported plainly that the test's claim was NOT true as written even after the fix, and declined to narrow it unilaterally. It is now true of every GitHub-invalidity decidable from document SHAPE, and NOT true of scalar CONTENT or cross-references: `timeout-minutes: abc`, `continue-on-error: maybe`, a malformed `if:`, `uses: hello world`, `uses:` with no `@ref`, `shell: nosuchshell`, `needs:` naming a ghost job, an unknown event, a broken cron, an unknown `permissions` scope. Deciding those needs GitHub's expression language, ref grammar, event and permission vocabularies and a cron parser — unreachable at `"dependencies":0`, and a half-implementation would be worse than an honest boundary. **DECISION: narrow the claim to "on structural grounds" and list the excluded cases AT THE POINT OF THE CLAIM** rather than leave them to be rediscovered. Several excluded cases are separately pinned for the two workflows this suite actually asserts over (the `uses:` pin requires a 40-hex SHA); they are unpinned only for arbitrary documents. This satisfies the standing rule that a validator's advertised scope is itself a claim requiring a case that would fail if it were false — the scope is now small enough that the pins cover it.

**Flagged, not fixed:** `runs-on: &r ubuntu-latest` is absorbed as a literal string rather than throwing, so the reader's "an unrecognised construct THROWS" doctrine is not literally true of YAML anchors. It is valid YAML rather than a GitHub-invalid document, and every assertion over such a value fails closed; a fix has a false-rejection edge on quoted scalars that would need its own tests. Recorded as a known limit rather than silently carried.

#### Task 7 fix round 4 (Codex review of `10143b1`+`55dfadf`: 5 Minor) — AND A REVERSED COORDINATOR DECISION

**Codex offered the same exit twice — "rename and explicitly bound this as a repository-specific structural reader" — and the coordinator declined it twice. That was wrong, and this round takes it.** The evidence that turned it: of five new findings, THREE (1, 2, 5 below) are defects only of the GENERAL claim rather than of anything this repository's own workflows do, and a fourth is a FALSE REJECTION introduced by chasing generality. When tightening a claim produces a regression against the real schema, the claim's ambition is the defect, not its implementation. **A reader that must agree with GitHub's schema everywhere is a YAML-schema project; this repo needs a reader that catches a typo in ITS OWN two workflows.**

**DISSOLVED BY SCOPING — no code, claim change only:**
- **(1) The structural/content split overclaims.** The claim says value TYPES are covered, then excludes `timeout-minutes: abc` and `continue-on-error: maybe` — which ARE number/boolean type errors, so the wording contradicts itself. It also admits `defaults:` with a typo'd child and a `uses` step carrying `shell:`/`working-directory:`, because only the outer mapping and `with` placement are checked while GitHub recursively constrains `defaults` and separates run-step keys from uses-step keys.
- **(2) `on:` is presence-checked in every representation but null.** `on: ""`, `on: []` and `on: {}` all pass, so the round-3 null rule STILL admits a workflow that cannot trigger — the exact question the coordinator asked Codex to check, answered against us.
- **(5, partly) Anchors.** `runs-on: *missing` stores a non-empty literal and passes the schema though GitHub's loader cannot resolve it.

**MUST FIX REGARDLESS OF SCOPE — these are live against this repo's own files:**
- **(4) `run: ""` IS A FALSE REJECTION, introduced by round 3.** GitHub's schema requires `uses` to be non-empty but `run` is only a required string, so the shipped rule asserts MORE than GitHub does and the test at `:5667` asserts a rejection GitHub would not make. The round-3 over-strict mutations missed it because they were aimed at this repo's workflows, not at GitHub's schema. **FIX: keep `uses` non-empty; allow an empty `run`. Null and mapping cases stay correctly rejected.**
- **(3) Step-ID uniqueness is case-sensitive locally, case-insensitive in GitHub's runner.** The plain `Set` admits `first` and `FIRST` in one job; GitHub's `ReferenceNameBuilder` uses an ordinal case-insensitive set. A real collision risk in files this repo writes. **FIX: case-fold the uniqueness check and add the case-folded duplicate mutation.** Codex confirms the lexical regex itself is sound and `_ok-9` is a valid positive control.
- **(5, the fail-closed half) Anchors must not pass silently.** The implementer's justification for flagging rather than fixing was that "every assertion over such a value fails closed" — **Codex refuted it: no demo assertion reads `runs-on` at all**, so an unresolvable alias sails through. **FIX: REJECT anchors and aliases outright.** This repo uses none, rejection is fail-closed and trivial, and it avoids the quote-aware resolution whose false-rejection edge was the reason for not fixing it before. Do NOT implement anchor resolution.

**THE CLAIM, restated honestly:** the reader validates SELECTED workflow/job/step structural checks sufficient to catch a mis-spelled or mis-shaped key in THIS repository's own workflows. It does NOT implement GitHub's schema, and the excluded classes stay listed at the point of the claim. Every previously listed exclusion stands, plus recursive `defaults`, run-step-vs-uses-step key separation, and the `on:` representations above.

**Standing lesson for Task 9 and beyond:** three consecutive rounds tightened this reader and each produced fresh divergence from a schema we do not implement. **A test's advertised scope must be no larger than the thing it is protecting** — here, two workflow files — and generality bought at the price of a false rejection is a net loss.

#### Task 7 round-4 outcome (`ab0938e`) — the scoping reversal, executed

All three code fixes landed with **16 mutations, 16 killed**. The false rejection is gone: the single rule was split so `uses` must be a non-empty string while `run` need only BE a string, matching GitHub's schema (which gives `uses` a minimum length and types `run` only as `string`). Null and mapping cases stay rejected by the pre-existing empty-key and type rules.

**AN ASSERTION WAS REMOVED, deliberately and reported:** `assert.throws(… 'run: ""' …)` is replaced by `assert.doesNotThrow` over the same input, because the old assertion **pinned a rejection GitHub does not make**. The case is still exercised with the opposite, correct expectation. The suppression scanner independently confirms no test-weakening finding.

Step-ID uniqueness is now case-folded (`toLowerCase()` IS an ordinal fold here because `GITHUB_IDENTIFIER` has already confined ids to ASCII — recorded in the comment so nobody later "fixes" it toward locale-aware folding). Anchors and aliases are refused **in the reader, not the schema pass**, by testing the first character of the UNQUOTED value — the only position YAML reads a node property.

**THE LEGAL-DOCUMENT MUTATION RULE PAID FOR ITSELF IMMEDIATELY.** Round 3's false rejection escaped because every mutation was aimed at this repo's own workflows. This round required at least one mutation per strictness rule aimed at a LEGAL document, and they caught real defects: an `includes()` anchor check died on `run: rm -rf build/*`; testing the QUOTED rather than unquoted scalar died on `run: "*.js && echo done"` — precisely the quoted-scalar false rejection that was the original reason for not fixing anchors; hoisting the step-id set to workflow scope died on a legal cross-job id reuse; and folding `-`/`_` died on three ids GitHub considers distinct. **Adopt this rule for every strictness check in Task 9 and beyond.**

**THE SELF-AUDIT CAUGHT A FOURTH INACCURATE CLAIM BEFORE IT SHIPPED.** Asked to check the restated claim against what the code enforces, the implementer disabled each of the 16 rules in turn and found that **`runs-on` must be a non-empty scalar SURVIVED — nothing tested it.** It then declined the naive fix: there is no unambiguously-invalid value reaching that line, because null is caught upstream, `*alias` by the new anchor rule, and the two remaining shapes (`runs-on: {group: …}` and the block-sequence array form) are **legal GitHub this reader refuses anyway** — so a negative case would have pinned a FALSE REJECTION, the exact defect the round exists to remove. It reworded the claim instead and stated plainly that the rule is enforced, unpinned, and stricter than GitHub. A re-run sweep reports **UNPINNED rules named by the claim: none.**

The claim now reads: *the reader validates selected workflow, job and step structural checks, sufficient to catch a mis-spelled or mis-shaped key in this repository's own two workflows; it does not implement GitHub's schema and no longer claims to.* All nine excluded cases were **verified empirically as ACCEPTED** before being written down. No `doesNotThrow` pins were added over them — deliberately, so today's gap does not become tomorrow's requirement.

**Two new limits recorded, not fixed** (out of scope, not live against this repo, both needing schema work): `runs-on`'s non-empty-scalar rule is stricter than GitHub; and `runs-on: [self-hosted, linux]` is accepted **for the wrong reason** — flow sequences are not parsed, so it is stored as a literal string.

#### Task 7 fix round 5 (Codex review of `ab0938e`: 3 Minor)

**(1) Minor — the `runs-on` non-test rationale is DEMONSTRABLY WRONG, and the coordinator endorsed it.** Round 4 declined to pin the `runs-on` non-empty-scalar rule, reasoning that no unambiguously-invalid value reaches it. **`runs-on: ""` does.** It is invalid under GitHub's schema (which permits a non-empty string, a sequence, or a mapping — never an empty string), it reaches the rule, and deleting the rule makes it accepted. The enumeration considered null, `*alias`, mapping and sequence and missed the empty string. Codex: *"Declining every pin was a gap dressed as principle."* The claim's statement that no invalid value reaches this rule is FALSE. **FIX: pin the empty-scalar rejection, WITHOUT pinning rejection of the legal mapping/sequence forms** — the false-rejection hazard was real, the blanket conclusion drawn from it was not. **Lesson: "there is no case to pin here" is itself a claim requiring the same enumeration discipline as any other, and a round that reasons its way out of a test needs its enumeration checked, not admired.**

**(2) Minor — the anchor refusal has a trivial bypass.** The check examines `rawValue[0]`, but the entry regex consumes EXACTLY ONE separator character — so `runs-on:  *missing` with TWO SPACES leaves `rawValue` beginning with a space and is stored as a non-empty literal, taking the very path the fix was meant to close. `runs-on: [*missing]` is a second bypass through the acknowledged flow-sequence hole. The claim that anchors and aliases are refused is therefore false. **Codex confirmed there is NO false rejection among the five positive controls** — at the first non-separation character, unquoted `&` and `*` are YAML indicators while quoted, embedded and block-scalar occurrences are ordinary content — so **the defect is incomplete detection, not over-rejection.** FIX: test the first NON-SEPARATION character. For `[*missing]`, either extend detection into flow-sequence elements or state it as an explicit exclusion — **do not build a flow-sequence parser**; the recorded unparsed-flow-sequence limit already exists and narrowing the claim is the proportionate answer. Implementer chooses and states which and why.

**(3) Minor — the two-workflow protection claim is unproven.** The claim says the reader protects this repository's TWO workflows, but only `debug-evidence-demo.yml` is passed through the reader; `closeout-gate.yml` is inspected only as RAW TEXT. **FIX: run `closeout-gate.yml` through the reader too** — that makes the claim true and extends structural protection to the gate, which is the more consequential of the two files. Narrowing to the singular named workflow is the fallback if the gate file uses a construct the reader refuses; if so, say which construct, because that is itself a finding.

**RULED CLEAN, no further work:** splitting `run` from `uses` is correct and lost no invalid case the combined rule caught; ASCII `toLowerCase()` after `GITHUB_IDENTIFIER` is equivalent to the runner's ordinal case-insensitive comparison, stays scoped per job, and introduces no false rejection.

**Task 7 round count is now five, on what began as one Minor about a typo'd `runs-on`.** The reader has produced findings in every round since it was introduced. If round 5 does not close it, the next step is not a sixth round of tightening but a decision about whether this reader earns its keep at all.

#### Task 7 round-5 outcome (`81cdd45`) — and a standing decision about the reader

**Pointing the reader at the second file was the substantive fix, and it immediately found a real reader defect.** `closeout-gate.yml` DID NOT PASS: the folded block scalar `description: >-` at `closeout-gate.yml:21` was unknown to a reader that knew only `|`, so `>-` was stored as the literal string `>-` and its body threw `unexpected indentation`. **Fail-closed, and therefore completely silent for as long as nobody pointed the reader at the file** — which is the whole argument for making a protection claim true rather than smaller. It was the ONLY blocking construct; with folding stubbed in, the gate parsed clean first try. Now implemented properly (`|`, `|-`, `>`, `>-`), with every other header (`|+`, `>+`, `|2`) **refused explicitly** rather than falling through — otherwise a header with an empty body is stored as the plausible non-empty scalar `|+`, which is the anchor defect in a new costume.

**The anchor bypass was fixed at the ROOT, and closed a wider latent defect.** Rather than special-casing the two-space value, the entry pattern now consumes ALL separation, so `rawValue[0]` genuinely IS the first non-separation character. That also fixed something nobody had reported: `uses:  ./actions/debug-evidence` was previously stored with a LEADING SPACE, which no exact comparison in the suite matches — **so that invocation had silently stopped being counted.** Bounded in the other direction too (`run:echo hello` → unparsed, since `foo:bar` is a plain scalar in YAML, not a key).

**The flow-collection bypass took the EXCLUSION, with the reasoning written out.** A scan for `&`/`*` anywhere in a literal refuses `paths: ['**/*.js']`, one of the commonest lines in any workflow; scanning element starts requires deciding what a comma is; a comma inside a quoted element requires tracking quote state — a flow parser under another name, which this round was told not to build. And fix (3) raised the stakes: the gate carries five flow collections and the suite now REQUIRES it to parse, so a rule reaching inside collections would have a merge-gating file to be wrong about. `[*missing]` is the already-recorded unparsed-flow-collection limit seen from another side, not a second limit. The claim is now worded "wherever this reader reads a scalar."

**THE SWEEP FOUND A THIRD DEFECT NOBODY REPORTED.** Re-running the disable-each-rule sweep over 24 rules found `unexpected indentation` UNPINNED — and it is a live fail-open, not a formality: with it inert, a key written one column too deep is silently absorbed into the job above, and **the reader answers for a job the file does not declare.** Now pinned, with the correctly-aligned key as its legal-document control.

**22 of 24 rules pinned; the two exceptions carry FULL WRITTEN ENUMERATIONS** — the discipline round 4 failed. `workflow reader stopped at line N`: the top-level loop has exactly two early exits, one impossible and one unreachable because item lines are re-indented to `indent + 2` and trip the indentation rule first; five candidate constructs were tried and confirmed refused. `step: not a mapping`: `job.steps` is only ever a mapping, a scalar, null, or an array of `parseWorkflowMapping` returns, with non-mapping sequence elements refused earlier as unparsed lines. Both enumerations live in the claim so they can be checked rather than admired. **16 mutations, 16 killed, 8 of them aimed at legal documents** covering every strictness rule touched.

> **STANDING DECISION — KEEP THE PARSER, FREEZE THE SCHEMA.** *(Conclusion stands; its RATIONALE below was corrected in round 6 — see "the ledger was flattering itself". Read both.)* The honest accounting, which the implementer volunteered: **this reader has never caught a real defect in a real workflow.** Every finding across five rounds was about the reader or its claim, and one round shipped a false rejection of a legal document. But the ledger splits, and the halves do not share a verdict.
>
> **The parser earns its keep.** It replaced substring pins that were DEMONSTRABLY PASSING WHILE WRONG — a bare `${{ always() }}` matched by prefix, an extra upload path never rejected, a mapping moved into an inline comment, two output dirs diverging under a `>= 6` count. Four real defects greps could not see. It is now also the only thing reading the gate structurally, which this round caught the `workflows:` regex being indentation-anchored rather than parent-anchored.
>
> **The schema layer is where all five rounds came from** — a hand-rolled approximation of a schema this repo does not implement, where each tightening bought a new divergence. **RULE GOING FORWARD: no new schema rule unless a workflow in this repository actually acquires the defect.** Generality here has a five-round record of costing more than it returns.
>
> **If real schema coverage is ever wanted, the answer is `actionlint`, not a sixth round** — it IS GitHub's schema, maintained elsewhere, and as a PINNED CI BINARY it costs no npm dependency, so `"dependencies":0` survives. That trade (add actionlint, delete the schema pass in the same commit, keep the parser for structural assertions) is the one to take if this ever reopens. Recorded for Task 9 and the roadmap; NOT actioned now.
>
> **Not to be shrunk: the claim comment itself.** Its precision is why these defects were findable — every round's finding was a mismatch between that comment and the code. A vaguer claim would produce fewer findings and less safety.

#### Task 7 fix round 6 (Codex review of `81cdd45`: 1 Minor, plus two corrections to round 5's own conclusions)

**(1) Minor — a real content-corruption bug: `stripYamlComment` runs BEFORE block-scalar recognition.** A block-scalar body line beginning with `#` is deleted as a comment before the block scalar is ever recognised. **The gate contains exactly that at `closeout-gate.yml:26`**, where a folded `description: >-` body wraps onto a line starting `#6Yd4Qs). Leave empty…`. The reader therefore produces `…chatgpt-codex-connector PR7 branch you have already selected…` instead of `…chatgpt-codex-connector PR7 #6Yd4Qs). Leave empty… branch you have already selected…`. Verified at source: `stripYamlComment` is applied in the line-tokenising pass (`support.test.js:5587`) while block-scalar recognition happens later (`:5372`).

**THE TEST-QUALITY FAILURE THAT HID IT, which is the round's real lesson: the gate positive control only asserts that parsing DOES NOT THROW, and the constructed folding test contains no comment-looking content — so both stay green while content is silently corrupted.** "Does not throw" is not a value assertion. Round 5 made the two-workflow claim true by running the gate through the reader, but proved only that it parses, not that it parses CORRECTLY. FIX: make comment stripping block-scalar-aware, and pin the gate's `#6Yd4Qs). Leave empty` text — or add an equivalent folded-scalar case proving `#` remains content.

**(2) CORRECTION — the round-5 ledger was flattering itself.** It attributed all five rounds to the schema layer and implied the parser was the settled half. **Codex: "separator handling, block-scalar tokenization, and comment stripping are PARSER defects."** Rounds 4, 5 and now 6 all found parser bugs. So the standing decision's CONCLUSION survives but its REASON does not: **keep the parser because the repository-specific structural assertions need it — NOT because its risk is settled.** It demonstrably is not.

**(3) CORRECTION — the actionlint framing was wrong, and the timing question is answered.** Do NOT adopt it in this Task 7 closeout: it would not fix this parser defect, and adoption is a separate CI/supply-chain change. Reach for it when someone proposes another schema rule, or when comprehensive workflow validation becomes a requirement. Also replace "it IS GitHub's schema" with **"a maintained third-party static checker for GitHub Actions syntax"** — its own documentation calls it a static checker and its release history includes parser fixes, so it is not an oracle. It does cover the relevant missing/unexpected-key and expression checks. **If adopted: pin a release artifact AND checksum, and explicitly configure its optional ShellCheck/Pyflakes integrations** rather than inheriting whatever the environment provides.

**CONFIRMED HOLDING, no work:** the all-separation regex introduces no false rejection Codex could find — it consumes YAML separation correctly while preserving spaces inside quoted values; both unpinned-rule enumerations hold (the top-level item exit stays unreachable after re-indentation, and step arrays contain only mapping-parser results); the `[*missing]` exclusion is honestly disclosed and not pinned as accepted. Suggested wording refinement, not an overclaim: **"at the start of a non-flow scalar token"** is clearer than "wherever this reader reads a scalar".

**Process note:** the previous review job HUNG — its process died 11.5 hours before the status file admitted anything, which kept reporting `running` with a ticking elapsed time, and the companion's `cancel` is broken from Git Bash (MSYS rewrites `taskkill /PID` into a path). **Liveness must be checked by log mtime plus PID existence, never by the status line.** This review was re-run on a fresh thread.

#### Task 7 round-6 outcome (`f434ead`) — the ordering audit, and a defect class found in the tests themselves

**The red was a CORRUPTED VALUE, not an exception** — the distinction this round exists to teach. A constructed folded body wrapping onto `#6Yd4Qs) and that is CONTENT` produced only `"a folded body may wrap onto a line that starts with"`. Three further constructed reds from the same defect: a `run: |` script lost both an inline and a whole-line shell comment; a heredoc body lost its `- one` / `- two` dashes; and stripping failed to resume at the dedent. On the real gate, the exact value the plan predicted.

**FIXED WITH ONE BLOCK-SCALAR-AWARE TOKENIZER (`yamlLines`) SHARED BY BOTH READERS.** Block-scalar membership is now decided ONCE, before anything that depends on it — and two transformations did: comment stripping AND the `- ` sequence-marker split. **The `- `-inside-a-block-scalar bug was NOT reported by anyone; it is the same state one token over, found while fixing the first.** `parseActionYml` carried the identical latent ordering bug (shared stripper, zero live corruptions) and is fixed by the same tokenizer. The tokenizer's end-of-body test is the SAME test the parser's body loop applies, so they cannot disagree by construction, and `BLOCK_SCALAR_HEADER` is deliberately WIDER than the set the parser agrees to read (`|+`, `|2` open a body even though the header is refused a line later).

**A DEFECT CLASS FOUND IN THE TESTS THEMSELVES — the broader sweep for "asserts only that it parsed" found 8 sites; 13 assertions promoted to value pairs and 3 presence controls added.** The most serious: **three absence scans (`secrets.` and `continue-on-error` over `workflowCode`, `continue-on-error` and `${{ env.` over `ACTION_YML_CODE`) had NO PRESENCE CONTROL — each would have certified an empty string.** An absence assertion over a derived string is vacuous unless something proves the string is non-empty and really contains what it should. Also promoted: the `*`/`&` and `|`/`>` legal loops (previously `doesNotThrow` only), the matrix-expression runner, `timeout-minutes` at the correct column (now pins that it landed ON THE JOB — absorption is the exact fail-open the indentation rule exists to stop), `run: ""`, and `on: push`. **Deliberately left acceptance-only with the reason recorded:** the three step-id scope controls, where the property under test genuinely IS "not refused" and a value pin would assert something the rule is not about.

**57 mutations, 55 killed**, restored byte-identically with SHA-256 verified after each. The two survivors are the two known unpinned rules with their written enumerations intact — and round 6 NARROWED one of them: a `- ` inside a block scalar is no longer marked as an item at all, so the top-level early exit has one fewer route than before. Sweep is now 27 rules (split finer than round 5's 24), 25 pinned.

**THE ORDERING AUDIT, written into the claim comment so it can be checked rather than re-derived.** Pipeline: split → strip trailing space → **decide block-scalar membership** → strip comments (outside only) → drop blanks → trim indent → split `- ` (outside only) → match entry → detect header → refuse anchors → unquote → schema. Confirmed empirically correct: the anchor check runs AFTER separation is consumed and BEFORE unquoting (`runs-on: *x` refused, `runs-on: "*x"` → `*x`); the header test applies to `rawValue` after the entry split, never to the line. **The one coupling to watch, named in the code:** the tokenizer's end-of-body test and the parser's body loop are the same test written in TWO PLACES — they agree today, pinned by the afterScalar case, but that is what a future edit is most likely to break silently.

**NAMED, NOT FIXED, with the reasoning that has finally been learned:** quote state in `stripYamlComment` restarts at column 0 of every line, so an apostrophe in unquoted text opens a quote that never closes — `run: don't # a real comment` keeps the comment. Fixing it requires knowing where a NODE begins, **"the same reach-one-construct-further trade that has cost this reader a false rejection every time it was taken."** Neither file contains such a line, every value they produce is now pinned exactly, the failure direction is a value too LONG (visible to an exact pin), and the worst case — multi-line quoted scalars — is refused outright by the indentation rule in both quote styles. Not pinned as accepted, per standing doctrine. **One fail-closed coverage gap:** `parseActionYml` still recognises only `path: |`, so a `>` scalar under `runs:` would throw `unparsed nested line` — fail-closed, not silent.

#### Task 7 fix round 7 (Codex review of `f434ead`: 1 Minor, two sub-cases)

**Block-scalar state can survive past YAML's actual boundary.** I asked whether the two-places end-of-body coupling could already disagree; **Codex's answer is sharper than the question — they do NOT disagree, they agree on the WRONG BOUNDARY.** Both compare against the header's LOGICAL indentation rather than the inferred CONTENT indentation. Two cases, both reproduced (the shipped tokenizer marks the offending lines `inScalar: true` while a YAML loader rejects both documents):

1. **A dedented body line is absorbed.** Once the first body line establishes content indentation 10, a later line at indentation 9 is invalid YAML — but both tokenizer and parser accept it, because they test against the header's indentation 8. YAML defines a less-indented line as terminating the block construct.
2. **A dedented comment leaks scalar state.** Such a line correctly computes `inScalar === false`, but comment stripping reaches its `continue` **without clearing `scalarIndent`** — so a subsequent indented line RESUMES a scalar that YAML already ended. YAML explicitly treats less-indented comments as trailing comments outside scalar content.

FIX: track the INFERRED CONTENT indentation (established by the first body line, not the header); clear scalar state on EVERY non-empty outside line even when comment stripping deletes that line; pin both cases.

**RULED CLEAN — the round-6 change was a net repair, confirmed:** no newly corrupted value in either workflow or `action.yml`, and the real-file changes RESTORE previously lost scalar content. The wider `BLOCK_SCALAR_HEADER` does not admit unsupported workflow headers, because the parser refuses them before a document is produced. The `[*missing]` and per-line quote-state exclusions are now honestly scoped. Commit scope and diff checks clean.

**TRAJECTORY NOTE, recorded honestly.** After round 5 this plan said that if the reader kept producing findings the next step was a decision about whether it earns its keep, not another round of tightening. Rounds 6 and 7 are a DIFFERENT CLASS from rounds 2-5: they are real parser defects causing or risking silent content corruption, not generality chased against a schema we do not implement — exactly as Codex's ledger correction predicted. `actionlint` would NOT fix them (its own ruling: it does not address parser defects, and the structural assertions still need a parser), so the adopt-actionlint exit does not apply here. The reader is now being genuinely debugged rather than inflated. **The standing rule still holds: no new SCHEMA rule without a live defect. Parser correctness is a separate ledger and is worth paying.**

#### Task 7 round-7 outcome (`4a572f7`) — and the strategic answer that reframes the whole reader question

Both cases fixed. `yamlLines` now holds `{ headerIndent, contentIndent }`: the first body line must clear `headerIndent` and ESTABLISHES `contentIndent`; every later line must reach `contentIndent`; state is cleared on every non-empty outside line, **placed before the `continue` so an erased line still closes the block**; a blank line neither closes nor establishes, at any column. The reds were wrongly-ACCEPTED documents — `run === "echo first\necho dedented"`, a program nobody wrote — not exceptions.

**UNIFICATION, and a third copy nobody had counted.** The two predicates were not corrected in parallel: the body loop now consumes `lines[cursor.i].inScalar`. A THIRD copy was then found and removed — `parseActionYml`'s own `line.indent >= blockScalar.indent` with a **hard-coded `indent: 10`**, which was *right by coincidence* (the real file's body sits at column 10) and **unfalsifiable**, because reading only from disk left the boundary untestable. Giving `parseActionYml` an optional text parameter made a body at column 9 distinguish them.

**THE SWEEP OUT-FOUND THE REVIEW AGAIN — second round running.** Re-run at 40 rules (finer split than round 6's 27): **38 pinned, 2 unpinned.** It surfaced `S8`, the `+ 2` a block-scalar header contributes on a sequence-item line (`- run: |`), as enforced-but-unpinned: neither workflow writes a header on a dash line, so nothing on disk distinguishes the key's column from the dash's, and with the `+ 2` deleted a body line at column 7 — belonging to no mapping — became script while **every case in the file stayed green.** Now pinned both directions. 54 mutations, 52 killed, 8 aimed at legal documents. **Byte-identical token stream confirmed for all three real files — 535 tokens, 0 differences — so the tightening introduces no false rejection on the real corpus.**

> **THE STRATEGIC ANSWER — asked whether to spend a deliberate round on a bounded tokenizer rewrite, the implementer argued AGAINST it, and the reasoning reframes seven rounds:**
>
> **Every parser defect in seven rounds has been LEXICAL — cross-line lexical state (block-scalar membership) that was implicit, derived from the wrong quantity, and written in more than one place. NOT ONE HAS BEEN STRUCTURAL.** The recursive descent over an indented line stream has produced ZERO defects; it is already a correct context stack, expressed as recursion. So a rewrite "with an explicit state machine and its boundary rules stated once" would re-implement the half that has never been wrong and re-derive the half round 7 just fixed. **Round 6 named the state; round 7 gave it two named fields, three transitions and one owner — that IS the bounded rewrite, applied to the only construct that needed it.** The alternative's real cost is re-validating 40 pinned rules against a new implementation, which is precisely how a round of tightening becomes a round of false rejections.
>
> **It refused to claim this is the tail of the distribution — "we fixed the last two is not evidence"** — and named instead the one concept the reader still does not model: **WHERE A NODE BEGINS.** That single absence is the root of all three disclosed exclusions (per-line quote state, the apostrophe case, flow collections): `'`, `#`, `&`, `*`, `|`, `>` are indicators ONLY at a node start, and this reader approximates that position in a different place each time it needs it. **If an eighth round finds a parser defect, that is where it lands — and that, not the tokenizer, is the rewrite worth scoping. It is smaller and retires three known limits at once.**
>
> **THE CHEAPER, MORE DECISIVE MOVE, and the one worth spending the deliberate round on: a dependency-free ROUND-TRIP PROPERTY TEST.** Every defect in seven rounds was found by a human reading code; **nothing in this suite can find one on its own.** Record each token's content indentation, re-emit the parsed document, and require it to reproduce the input's line partition modulo the three disclosed normalizations. **Both the round-6 and round-7 defects VIOLATE that invariant** — round 6's deleted `#` line vanishes from the reprint; round 7's dedented line returns at column 10 instead of 9. Drive it with generated documents over the subset's alphabet (indent deltas, block headers, comments, blanks, dashes, quotes) up to a few lines. No oracle, no dependency, no supply-chain change. **It is the first thing in this project that could answer "is this the tail" EMPIRICALLY rather than by assertion.**

#### Task 7 round-8 outcome (`c7fc1ab`) — the suite can now find its own defects

**THE INVARIANT:** for a generated document, either the reader REFUSES it, or the document it returns — reprinted onto the skeleton it was written from, **at structural columns only** — reproduces the input's line partition. Plus: a document the generator wrote as legal must not be refused (a throw there is a false rejection and fails the property). The reprint takes its SHAPE from the generator's model and its CONTENT from the reader, laying every line at a structural column rather than the column it was written in — **which is what makes a mis-assigned line visible: it comes back where the node that absorbed it lives.** Normalizations confirmed against the claim comment rather than the brief: blank lines dropped, trailing whitespace stripped, body indentation trimmed — plus three differences named as SEMANTICS not losses (a comment outside a scalar is not a line of the document; a quoted scalar returns unquoted; a `>` body folds).

**VALIDATED BY CONSTRUCTION, BY INJECTION INTO THE TRACKED FILE** — not into a copy, on the stated ground that "injecting into a copy would only have proved something about the copy." Four injections, each restored with SHA-256 verified against the pre-injection digest. Round 6's comment-stripping defect → **19,345 of 41,816 documents violate**; its `- ` marker half → 11,162; round 7's boundary defect → 6,164 including **all 648** perturbed documents. **A property test that would not have caught the defects we already know about is not worth shipping — this one catches all three.**

**AN EXTERNAL ORACLE, OFF-LINE, NOT A DEPENDENCY:** PyYAML loaded all 24,168 legal documents without error, **rejected all 648 perturbed ones**, and agreed exactly with the model on the 10,584 where normalizations do not bite. So "legal" and "YAML rejects this" are CHECKED claims, not the generator's opinion of itself. **PRESENCE CONTROLS ON THE CORPUS** (round 6's vacuous-absence lesson turned on this very test): floors asserted over 32,492 block scalars, 6,310 dash-line headers, 12,173 over-indented body lines, 831 gap comments, 4,848 in-body blanks and more — **so a generator that quietly stopped producing a shape fails here rather than reporting a clean search of nothing.** Determinism via an inline mulberry32; `dependencies: 0` intact. Cost: 1.17 s; the file goes 19.6 s → 20.9 s.

**RESULT: NOTHING FOUND.** Zero violations across 41,816 documents per run and 221,816 off-line. **The honest reading, in the implementer's words: this licenses "no defect in the searched space", NOT "no defect."** The block-scalar neighbourhood — where both recent defects landed — is searched COMPLETELY and is clean; the reader is not thereby correct.

> **THE STRATEGIC ANSWER, AND IT WAS TESTED RATHER THAN ASSERTED.** Round 7 bet an eighth defect would land in "where a node begins". Round 8 kept the bet but **decomposed it into three regions and measured two:**
> - **`|`, `>`, `*` at non-node-start positions: ALREADY ANSWERED, CLEAN.** Re-running the whole corpus with shell-like plain scalars (`echo hi > out`, `echo a | b`, `rm -rf build/*`) gave **41,816 documents, zero violations.** Not a rewrite candidate.
> - **The apostrophe / quote indicator: REACHABLE TODAY, AND IT REDS IMMEDIATELY.** The same experiment with `echo don't` gave **82 violations in 4,000 random documents**, every one the disclosed case. **The extension is a ONE-LINE change to the generator's alphabet, and it is already an executable acceptance test for a node-start fix.**
> - **Flow collections: genuinely out of reach** — the reader does not parse them, so there is no partition to reprint. Not claimed.
>
> **THE ECONOMICS HAVE INVERTED.** Round 7's case against a rewrite was that "the alternative's real cost is re-validating 40 pinned rules against a new implementation." **That cost is now 41,816 documents and 1.2 seconds, plus flipping one exclusion off. The instrument that made the rewrite too expensive to validate is the thing that just got built.**
>
> **THE REMAINING FIX IS SCOPED TO ONE FUNCTION:** `stripYamlComment` needs the single piece of context it lacks — where the value token begins on this line — which its caller in `yamlLines` already knows (after `key:` plus separation, or after `- `). **The design decision to name before anyone starts: it CANNOT be the same function used by `workflowCode`/`ACTION_YML_CODE`, which are deliberately structure-free text scans with no node start to compute.** That split is the whole of the change.

#### Task 7 fix round 9 (Codex review of `4a572f7`+`c7fc1ab`: 1 Important) — THE LAST ROUND

**(1) Important — the property's "legal document" domain is wrong, and it FREEZES THE EXCLUSIONS AS REQUIREMENTS.** `generatedWorkflow` places arbitrary maps, sequences, block scalars and keys such as `alpha` beneath `on:` and calls them legal, but GitHub requires `on` to identify supported trigger events. **This is not a prose problem: `checkAccepted` treats EVERY refusal — including a future CORRECT schema refusal — as a false rejection, so the property test pins exactly the gaps the claim states are deliberately NOT pinned** (unknown events, arbitrary `on` shapes).

**THIS IS THE THIRD APPEARANCE OF ONE DEFECT CLASS, now one level up.** Round 4 deliberately added no `doesNotThrow` pins over the disclosed exclusions, on the explicit ground that "today's gap does not become tomorrow's requirement." Round 6 found three absence scans that would have certified an empty string. **Round 8's accept-check reintroduces the same hazard wholesale — an assertion that something is ACCEPTED is a requirement, and a generator that asserts acceptance over a schema-invalid corpus silently converts every known gap into a contract.** A test built to avoid asserting things asserted the biggest thing of all.

**FIX — separate syntax from schema, which is the right decomposition anyway:**
- `parseWorkflowSyntaxText(text)` → tokenizer and structural parser ONLY.
- `parseWorkflowText(text)` → `assertWorkflowSchema(parseWorkflowSyntaxText(text))`.
- **Run the generated-YAML property against the SYNTAX function.** The property is about the PARSER; running it through the schema was the category error. Then arbitrary YAML subtrees are legitimate parser inputs without freezing GitHub-schema gaps.

**ALSO CORRECTED — the PyYAML oracle claim was overstated.** PyYAML establishes YAML GRAMMAR, not GitHub Actions validity, so it cannot repair the domain error. And its default resolver treats `on` as BOOLEAN, so the reported "exact model agreement" required undocumented loader customization. **Offline PyYAML is legitimate corroboration for YAML syntax with no dependency-policy impact — it is NOT a GitHub-workflow oracle**, and the claim must say so.

**RULED — CLOSE TASK 7 AFTER THIS, DO NOT OPEN A ROUND FOR NODE-START.** Codex: *"I would NOT require the apostrophe/node-start fix before closeout. It is absent from the real files, explicitly excluded, and fixing it risks interaction with the still-unparsed flow-collection domain. After correcting the property's parser/schema boundary, close Task 7 rather than opening round 9 for that limit."* The coordinator's lean to close was correct; the acceptance test round 8 built (82/4,000) stays as the ready-made driver if that limit is ever taken up.

**RULED SOUND, no further work:** `4a572f7` correctly closes both boundary cases and removes the duplicate predicates. **The round-trip invariant is valuable and worth its 1.2 s — the structural-column reprint, the key/type/order checks and the injected regressions make it materially stronger than example tests.** The coverage floors are meaningful, and roughly half the measured counts is a reasonable disappearance alarm.

#### Task 7 final-round outcome (`054fdb5`) — the freeze demonstrated, then removed

**THE FREEZE WAS MADE EXECUTABLE BEFORE IT WAS FIXED.** A *correct* schema tightening (every key under `on:` must name a supported trigger event) was injected into the tracked file: **36,184 of 41,816 documents violated**, reported as `the reader REFUSED a legal document: workflow: 'on' names an unsupported event 'c-d'`. **A correct fix, reported as a parser regression.** Before the split it reded ONLY the property test — 124 pass / 1 fail — with all 40 pinned rules, both real-file value pins and every schema test green, so the red was unambiguously the property's. File restored byte-identical, SHA-256 verified.

**THE SPLIT IS BEHAVIOUR-PRESERVING, verified two ways.** Structurally the non-comment diff is five lines, no existing assertion touched, and every existing caller computes literally the same expression (`assertWorkflowSchema` returns its argument). Empirically all 126 baseline tests still pass. `checkRefused` moved to the syntax half too, on the right ground: **the refusal that family demands is the PARSER's, and through the whole reader a schema refusal could certify a refusal the parser never made.** The decisive check: with the tightening re-injected, the file is now **fully green** — the gap is no longer frozen.

**A NEW BOUNDARY TEST EXISTS BECAUSE THE PROPERTY TEST CANNOT POLICE ITSELF.** Three of four mutations — pointing `checkAccepted` or `checkRefused` back at the whole reader, or re-fusing the schema into the syntax half — **leave the property test GREEN**, because its corpus is schema-invalid exactly where the schema is silent. The boundary test is pinned over a document the schema refuses for round 1's reason (a top-level key GitHub does not read) rather than over any disclosed gap, **so it freezes nothing.**

**ORACLE CLAIM CORRECTED AND THE CAVEAT VERIFIED LOCALLY:** PyYAML establishes YAML GRAMMAR, not GitHub Actions validity; it knows nothing of trigger events or `runs-on` and could not have caught this domain error. Confirmed on this machine: PyYAML 6.0.3's default resolver is YAML 1.1, where plain `on` is a **boolean** — `yaml.safe_load('name: x\non:\n  alpha: 1\n')` returns the key `True`, not `"on"` — so round 8's "exact agreement" required loader customization it never recorded. Also corrected: the generator comment claiming the corpus "stays one GitHub would accept" (false), and the invariant's "legal" now reads "legal YAML in the generator's subset".

**HANDOVER — what is NOT in the claim comment:**
1. **The boundary test is LOAD-BEARING; do not delete it as redundant.** The property test is structurally incapable of detecting which reader it calls. Delete the boundary test and the split silently decays back into this defect **with no red anywhere in the suite.**
2. **The `on:` schema gap is now cheap to close and the tightening is verified green.** The allow-list this repo's files need: `pull_request`, `pull_request_review`, `workflow_dispatch`, `workflow_run`; tests 112 and 125 red immediately if one is missing. **THE TRAP:** GitHub also allows the sequence form (`on: [push, pull_request]`) and the scalar form (`on: push`). A rule guarded on `isMapping(document.on)` silently skips both — **exactly the fail-open shape this task has now found four times**, and why 5,632 documents did not violate under the injection.
3. PyYAML 6.0.3 is installed locally, so the offline oracle is re-runnable with no setup — but a default-resolver re-run disagrees at the top-level `on` key of every document, and that is the loader, not the reader.
4. **COORDINATOR CORRECTION to the handover:** the report says `parseWorkflowSyntaxText` has exactly THREE call sites and that a fourth is a signal to re-check the boundary. **There are FOUR** (`support.test.js:5818`, `:7343`, `:7374`, `:7609`) — the fourth is the round's own boundary test, which is legitimate and is precisely the test that guards the split. Counting from **five** onward is the signal.

#### ✅ TASK 7 CLOSED — Approved at `054fdb5` (HEAD `c1e326d`) after NINE fix rounds. No Critical, Important or Minor issues.

Codex's closing confirmations: the parser/schema split is real and correctly composed; **the boundary test does NOT freeze the `on:` gap — "your injected event tightening remaining green is the decisive proof"**; moving BOTH `checkAccepted` and `checkRefused` to the syntax half is correct, because *"letting schema refusal satisfy `checkRefused` would conceal the exact parser fail-open the property is meant to detect"*; no workflow consumer was accidentally moved to the syntax-only API, and **the coordinator's four-call-site correction is accepted — "five onward is the correct maintenance alarm"**; the corrected oracle wording is honest; and the apostrophe/node-start limitation remains honestly disclosed and outside the fix.

> **TWO BINDING RULINGS FOR TASK 8, from the reviewer with all nine rounds in context:**
>
> 1. **DO NOT PUBLISH the workflow-reader, property-generator, PyYAML, anchor, flow-collection or apostrophe limitations. They are TEST-HARNESS INTERNALS** and have no place in consumer documentation.
> 2. **THE DEMO WORDING BOUNDARY — an eighth hard requirement.** Describe the demo as proving the **exact `DEMO_FAKE_SECRET → [REDACTED]` fixture**. **Do NOT inflate it into "the demo proves arbitrary secrets cannot leak."** That is a wording boundary rather than a new public limitation, and it is exactly the over-claim this task spent nine rounds learning to avoid.
>
> Otherwise the consumer-facing lessons are already covered by the seven hard requirements: strict versus best-effort trust, hosted-runner refusal, separate-job isolation, availability-only outputs, empty-`PATH` remediation, admission-record interpretation, and the exact digest reconstruction recipe.

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
9. **Self-hosted runners** — ~~teardown relies on the `always()` step plus the collector's 15-minute idle timeout backstop; hosted runners also reap the job's process tree~~ **AMENDED (Task 8 round 1, Codex; verified closed 2026-08-16).** Both halves of the original line were false and the shipped surfaces now say otherwise. The accurate contract: `Stop collector` is the action's own teardown; normal runner job cleanup ALSO attempts to kill the tracked collector on **hosted AND self-hosted** runners, because `RUNNER_TRACKING_ID` is a *runner* behaviour and this action passes the complete environment into its detached shim without ever clearing that variable; that cleanup is unavailable if process tracking was disabled or altered, or if the runner itself died; and **the collector's idle timeout NEVER terminates the process** — `retireInactiveSessions` (`scripts/debug_server.js:1129-1136`) deletes in-memory sessions only, so a later `POST /log` gets `unknown_session` while the listener keeps holding its port. Verified against `DEFAULT_LIMITS.sessionIdleTimeoutMs` (`scripts/debug_server.js:298`, 15 minutes) and the shipped prose at `README.md:625-629`. `action.yml` carries **no** idle-timeout claim at all — the false backstop line was removed rather than reworded. Pick distinct `port` values for shared hosts.
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

#### Task 8 outcome (`5654260` + `7896804`) — eleven claims scoped down, four plan contradictions, two items owed to Task 9

**The requirement-by-requirement verification was done against SHIPPED SOURCE, not the plan**, with file:line for each — and requirement 5's admission record was **generated by running `admissionCaveats()`** rather than transcribed, while requirement 7's digest recipe was **recomputed independently** (a probe with `PATH=/usr/bin:/usr/bin/:/opt/tools` produced `present: 2 at sha256=af074d76…`, byte-identical to a from-scratch derivation, confirming both trailing-slash dedup and the conventional-path merge).

**CLAIMS SCOPED DOWN AFTER READING THE CODE — the valuable output of this task.** The four that matter most:
- **"The artifact carries exactly three payload names" is FALSE as stated.** `implicitDescendants: true` means a *directory* substituted at one of the three names contributes its descendants, and `clearStagedEvidence` (`support.js:1537-1546`) only throws on a directory present BEFORE `run`, not one planted after staging. Now: "the upload step publishes exactly three enumerated payload PATHS", with the residual stating the archive is not guaranteed to hold three entries.
- **"The state file is never uploaded" is FALSE as stated.** The uploader follows symlinks unconditionally, so `report.md` → `../action-state.json` puts the state file's bytes into the archive under a payload name. Now scoped to "no path the upload step enumerates names it", with the strong form forbidden on every surface by a polarity pin.
- **The three-copy comparison instruction would have failed for every reader who tried it.** Rendering the record through `buildReport`/`renderMarkdown` returns it markdown-ESCAPED (`\(streamed by start…\)`) and capped at 500 chars (`debug_report.js:25,162`). **`report.json` is the comparable copy**, and the README now says so.
- **"1 = the action crashed" was wrong.** Invalid input IS a detected problem and a refusal, and it exits **1**, because `startSubcommand` THROWS (`support.js:1109`) rather than returns — the demo's own third-start probe asserts exactly that. The mechanical rule now documented: **a RETURNED refusal is 3, a THROWN error is 1.**

Also corrected: the signal name is printed by *nothing* (a first draft said the step log would show it — false); the 128 mapping is scoped to the spawned `bash -c` process, since a signal killing something inside the script leaves bash exiting 128+n and mirrored normally; "strict refuses on hosted runners" → "on the default hosted CONFIGURATION"; an unverifiable claim about two third-party steps replaced with the verifiable fact that this action hands them no `token:`; the uploader's glob options attributed as a reading rather than asserted; and an unverified byte-identity claim about the served/stored session log dropped. **Added, verified, and not requested: three of the four probes return `unknown` off Linux (`support.js:81,261,312`), so STRICT REFUSES ON EVERY NON-LINUX RUNNER** — a macOS or Windows consumer would otherwise discover this via an exit 3.

**FOUR PLAN CONTRADICTIONS — the plan was wrong, the code is right:**
1. **`debug-evidence-files/` does not exist.** `resolveEvidenceDir` produces `debug-evidence-files-<nonce>`, invocation-scoped since T6 r1 #3. Task 8's step-1 item 5 named the fixed form.
2. **The queued "staged file bytes are not arbitrated" disposition is stale for the same reason.** With per-invocation children, invocations never address the same path. The honest version, now documented: the STATE FILE is arbitrated by lock plus nonce; staging paths do not collide; what is unarbitrated is any same-user process.
3. **THE 15-MINUTE IDLE TIMEOUT IS NOT A TEARDOWN BACKSTOP.** `retireInactiveSessions` (`debug_server.js:1130-1138`) deletes **in-memory session credentials** and is called only from request handlers; **the process never self-terminates.** Coordinator-verified. Task 8's step-1 item 9 and **`action.yml:387-388` both say otherwise** — see Task 9 items below.
4. **The repo README's collector trust model was stale**, calling `GET /sessions/:id/logs` a launch-token capability when `debug_server.js:1604-1638` accepts EITHER credential (same-session read scope, added this cycle). Fixed in `README.md` under gate 6 — left alone, the new action README would have contradicted the repo README.

**POLARITY PINS: 29 claims, 58 mutations, all red for the right reason.** Each claim's REQUIRED form is asserted in its own named `##` section and its FORBIDDEN inverse asserted absent from **all three** documentation surfaces. The harness replaces the matched text EVERYWHERE it occurs and **reports a mutation that failed to change the file as such rather than counting it as a pass** — the exact defect that fooled two earlier rounds — and distinguishes `RED(required)` from `RED(forbidden)` by assertion message, so a required mutation going red by tripping a forbidden pattern would have been caught. One self-match was found during authoring: the residuals section quoted a forbidden phrase in order to explain why it is NOT said, and the forbidden half fired.

**GATES 2, 4, 6, 7 SATISFIED** — consumer-side trust-unit reconstruction (a six-step by-hand procedure that SELECTS exactly one record and one digest line and rejects duplicates/disagreements), the credential and artifact census, the four-surface documentation reconciliation, and the residuals section pinned by a presence sweep so a tidy-up cannot silently delete one.

**THE IMPLEMENTER'S OWN WEAKEST-CLAIM AUDIT** named the Yama-mode-1 parenthetical: *"the only sentence in the file asserting a fact about GitHub's runner images that NOTHING IN THIS REPOSITORY PINS."* The `strict-refusal` job asserts the sudo finding and the exit code, never the ptrace reading; its provenance is `action.yml:207`, not a test. **The proposed cheap fix, for Task 9's consideration: have the demo's refusal job also assert the `same-UID ptrace policy:` reading on the record's findings line**, putting it under the same live pin as the sudo finding. Runner-up: the `sha256sum` round-trip claim depends on the artifact zip preserving bytes — true, but a claim about the platform rather than this code, and untested here.

> **TWO ITEMS OWED TO TASK 9:**
> 1. **`action.yml:387-388` is factually wrong and now contradicts the shipped README** — it credits "the collector's own idle timeout as a backstop" for self-hosted teardown. Correct it. Not done here because `action.yml` was out of Task 8's scope and is pinned by structural tests.
> 2. **Consider the ptrace-reading pin** above, which would retire the README's weakest claim.

---

#### Task 8 fix round 1 (Codex review of `5654260`+`7896804`: 2 Important, 3 Minor)

**(1) IMPORTANT — THE POLARITY HARNESS CERTIFIED THE INVERSE OF THE IMPLEMENTATION.** `README.md:210` and `:525` still make the exact byte-level upload guarantee the artifact section correctly withdrew: the collector log is "not uploaded" and the state file "is never uploaded," therefore nothing leaving the runner can reveal the signal. **The documented staging-window attack replaces any enumerated payload with a symlink to either file, and the pinned uploader follows symlinks and expands directory descendants — as this README's OWN residual section says.** And it is not mere unpinned paraphrase: **`support.test.js:8830` FAILS TO FORBID "is never uploaded" while `:8894` POSITIVELY REQUIRES the false sentence.**

**This is the guard becoming the defect, for the fourth time in this cycle** — after the vacuous absence scans, the `doesNotThrow` controls, and the property test that froze its own exclusions. A harness built to stop over-claims is now pinning an over-claim as mandatory, which is strictly worse than having no pin: it will fight anyone who tries to correct the sentence. FIX: scope BOTH statements by path — the action enumerates neither file, but a symlink substitution can upload either file's bytes — and therefore **the signal name is absent from normal rendered evidence, NOT categorically unable to leave the runner.** Correct the pin in the same commit, and check the remaining 27 claims for the same shape.

**(2) IMPORTANT — self-hosted cleanup is wrong in the README, and `action.yml:384` is still wrong.** The README says hosted runners reap the job process tree while self-hosted runners do not. **That is a runner behaviour, not a hosted-image behaviour:** GitHub's runner sets `RUNNER_TRACKING_ID` and terminates matching orphan processes during job finalization, and **this action passes the complete environment into its detached shim and never clears that variable, so the collector remains tracked** on both. Meanwhile `action.yml` still advertises the idle timeout as a teardown backstop. **Gate 6 is NOT satisfied while these shipped surfaces contradict both the collector and the runner.** The accurate contract, to be documented verbatim: `Stop collector` is the action's own teardown; normal runner job cleanup ALSO attempts to kill the tracked collector on hosted AND self-hosted runners; that cleanup is unavailable if process tracking was disabled or altered, or if the runner itself died; and the collector's idle timeout NEVER terminates the process. **`action.yml` is now IN SCOPE** — it is pinned by structural tests, which must be updated with it.

**(3) Minor — the sudo-reading precedence is undocumented, so requirement 7's "exact recipe" is not exact.** The README says any empty or relative `PATH` component makes the whole reading `unknown: empty-or-relative PATH entry`. The implementation (`support.js:299`) first returns `present: <count> at sha256=…` whenever ANY candidate exists, and considers unreadable or unresolvable entries only when nothing was found — so a host with `/usr/bin/sudo` plus `PATH=""` reports **present**, not the documented `unknown`. Both deny strict, so this is not a bypass. FIX: document the precedence — **`present` outranks unreadable, which outranks empty/relative, which outranks `absent`.**

**(4) Minor — `report-path` is promised absolute and is not.** A relative custom `output-dir` such as `../debug-evidence` resolves outside the workspace and passes validation, and `resolveEvidenceDir` (`support.js:619`) plus the output assignment (`:2058`) use `path.join`, not `path.resolve`. FIX: either make the implementation absolute or **remove "Absolute" from BOTH the README and `action.yml`.** Also: `output-dir` "becomes the artifact" should read **"is the staging root"** — only the nonce child's three paths are submitted.

**(5) Minor — the Yama-mode-1 parenthetical must go or be pinned.** GitHub officially documents passwordless `sudo` on its Linux hosted runners, which independently establishes the refusal; it does NOT document the current `ptrace_scope` value. **"Because `ubuntu-latest` is a moving external image, copying the assertion from `action.yml` is not verification."** FIX: remove the parenthetical, or take the proposed live assertion in the demo's refusal job.

**CONFIRMED CORRECT:** the non-Linux refusal claim — ptrace, sudo and capability readers each return `unknown` off Linux and any one suffices to deny. **Gate 2 works when followed completely** — the run-side qualification record supplies the nonce the digest line itself lacks, and the three-copy comparison catches an invocation mismatch; refinement requested: call it a **"qualification-plus-digest block"** in step 3 so the binding is explicit. **Plan contradictions 1, 2 and 4 were correctly resolved in favour of the code; contradiction 3 was only HALF resolved** — the README fixed the idle-timeout meaning but introduced the incorrect hosted/self-hosted distinction, and `action.yml` remains false.

---

#### Task 8 round-1 outcome (`d495db2`) — the audit found SIX, and one guard was blind by construction

**THE 27-CLAIM AUDIT WAS THE ROUND'S REAL PRODUCT.** A harness loaded the live claim arrays and checked each three ways: does the required half still match its section; does the forbidden half already match a shipped surface; and — **the one that matters — does the forbidden half catch the paraphrase a careless editor would actually write** (65 synthesized inverses). **Six findings across 29 claims; two were guards that had become defects.**

1. **The assigned one.** The required half was already correct; the FORBIDDEN half listed two spellings nobody had ever written and missed the two the README actually shipped — `is never uploaded` and `Not uploaded by this action`. All three shipped paraphrases walked straight through it.
2. **THE PREDICTED SECOND ONE, and it was blind BY CONSTRUCTION.** The `report.md is escaped and capped` claim's forbidden half was `` `report\.md`[^|]{0,60}verbatim ``. The `[^|]` window was chosen so a match could not run across a table cell — **but the fidelity table is exactly where that reversal lands, and `|` is precisely what separates the filename from its fidelity there. The pin was structurally incapable of firing at the one place the claim lives.** Proven by control: with the old window, appending `| \`report.md\` | Verbatim, uncapped. |` leaves the test GREEN; under `[^.]{0,60}` it goes RED, and still does not match the README's own row.
3. `applies` was forbidden but not `apply`, so "the guarantees apply to any invocation" passed. Same gap in `action.yml`'s scope claim.
4. A forbidden half anchored on its subject let the shorter drift through ("a stripped environment would be better").
5. The alternation carried `cannot|can never|will never` but not `can ever`, so "demonstrates that no secret can ever leak" passed.
6. A CORRECT required half with **over-claiming prose attached**: "`sha256sum session.log` over the downloaded artifact reproduces it exactly" — same shape as finding 1, since under a symlink or directory substitution the archive entry is not the staged file. Scoped in prose; the regex untouched.

**23 CLAIMS CHECKED AND CLEARED against shipped source**, each named in the report — including all eight evidence-trust claims (the "before the collector is booted and before your command exists" ordering is real: `probeAdmission` and the `return 3` both precede `spawnShim`), both PATH-remediation claims, and three of four digest-recipe claims. `action.yml`'s own 24 claims audited the same way: one gap, rest clear.

**32 mutations, 31 red, 0 no-ops** — plus one deliberate GREEN control (the old blind window). A first-pass GREEN was disclosed as the harness mis-aiming at the wrong test and re-aimed, rather than reported as a pass.

**THE FIVE ITEMS:** both upload statements scoped by path, so the signal name is *absent from normal rendered evidence* rather than categorically unable to leave the runner; the teardown contract corrected on BOTH surfaces, verified against `support.js:1170` (`{ ...env, DEBUG_PORT }` — the complete environment, `RUNNER_TRACKING_ID` never cleared) and `debug_server.js:1130-1138` with all four callers being request handlers; sudo precedence documented as **`present` > unreadable > empty/relative > `absent`**, ordering verified in source rather than taken from the brief; **"Absolute" removed** rather than the behaviour changed, because `path.join` at both sites makes it a behaviour change needing its own tests in a documentation round; the Yama parenthetical **removed**, with the README now stating explicitly that nothing here asserts a current `ptrace_scope` and why, so the next editor does not re-add it. Gate 2 step 3 now selects a **"qualification-plus-digest block"** and explains why — the digest line carries no nonce of its own, the qualification lines beside it are the whole binding, and nothing enforces the adjacency.

**Only ONE structural test changed** (the sole polarity test over the two `action.yml` surfaces), with four new platform claims; every other structural test verified still passing, including the reader handling the two `description:` values converted to `>-` block scalars.

> **FLAGGED, DELIBERATELY NOT FIXED, AND OWED TO TASK 9 — the same trap one surface over.** `action.yml:215` still carries *"standard GitHub-hosted runners ship mode 1 with passwordless sudo"*, and **`support.test.js:5315` REQUIRES it** — the identical unpinnable moving-external-image assertion Codex just ruled out of the README, mandated by a required pin. Coordinator-verified at both lines. **Because it is a REQUIRED half it will fight anyone who corrects it**, exactly like finding 1. The implementer left it alone on sound grounds: item 5 was scoped to the README, the operative conclusion (hosted stays best-effort) is independently established by the live sudo pin, and **removing a required pin uninstructed is how previously-verified work gets undone.** Task 9 must rule.

---

#### Task 8 fix round 2 (Codex review of `d495db2`: 2 Important, 2 Minor)

**(1) IMPORTANT — the teardown contract contradicts itself on runner death.** `README.md:615` and `action.yml:406` say that case is covered by the `always()` teardown step. **It cannot be: if the runner process dies before that step, neither the step nor the runner's finalization cleanup executes** — `FinalizeJob` also requires a functioning runner process. Because the collector is detached and **its idle timeout never exits**, that failure can leave it listening indefinitely. The four-point contract's own bullet says cleanup is unavailable when the runner dies, and then the prose beside it says `always()` covers it. FIX, stated exactly: **the `always()` step covers preceding step failures WHILE THE RUNNER SURVIVES; normal runner finalization is a SEPARATE backstop; runner death can defeat BOTH.**

**(2) IMPORTANT — the byte-level upload overclaim survives on a third surface, and in the test commentary.** The round-1 fix corrected the two README sites and the pin but **missed `action.yml:359`** ("no path here can reach" `action-state.json`) — whose *immediately following residual* admits unconditional symlink following. Direct counterexample: replace `session.log` with a symlink to `../action-state.json` and the enumerated path reaches the state bytes. **And `support.test.js:5161`'s assertion commentary repeats the overclaim while its assertions prove only LEXICAL NON-ENUMERATION.** FIX: use the README's now-correct wording — **"no enumerated path names it"** — on both. The two rewritten README statements themselves are confirmed correctly scoped.

**(3) Minor — THE WIDENED FORBIDDEN HALVES NOW REJECT TRUTHFUL PROSE, exactly as warned.** The round-1 brief said a forbidden half that fires on legitimate prose is its own defect and that this cycle had already paid for over-tightening twice. It happened anyway. Four confirmed counterexamples, each verified to match its guard: `support.test.js:8834` rejects "**`report.md` is NOT verbatim**"; `:8884` rejects "the demo demonstrates that secrets can ever leak"; `:8920` rejects **any unrelated file** described as "not uploaded by this action"; `:8692` rejects **any unrelated rule** that "holds for every invocation." FIX: **bind each inverse to its SUBJECT and account for NEGATION.** A pin that forbids the true statement of its own claim is the mirror image of one that requires the false statement — and this task has now produced both.

**(4) Minor — RULING ON THE MODE-1 ASSERTION: REMOVE IT.** `action.yml:215`, **`support.js:47`** (a third site round 1 did not name) and `support.test.js:5315` fossilize a moving image property the live job does not measure. **"Implementer-facing commentary is not exempt from factual drift."** KEEP the general fact that modes 1 and 2 are bypassable, and the independently documented passwordless-sudo fact — which is already sufficient for the hosted best-effort conclusion. REMOVE only the claim that current hosted images use mode 1, and its required pin.

**CONFIRMED:** the `report-path` wording is now consistent with **no remaining surface promising unconditional absolute output**; the gate-2 procedure is workable for a complete rendered artifact and **fails closed when `report.json` is absent**.

---

#### Task 8 round-2 outcome (`4a7dfef`) — the two-sided audit, and a general fix nobody had named

**33 OF 92 TRUE-STATEMENT PROBES ARE REJECTED BY A GUARD.** The audit loaded all **68 live claims** (4 action.yml scope + 28 platform + 36 README) by evaluating the array literals directly, so it cannot drift from what the suite enforces, and ran 92 synthesized sentences that are true of this system or true of a subject the guard has no business policing. **The over-tightening is systemic, not the four named cases.**

> **THE GENERAL FIX, discovered rather than assigned: ADJACENT-COPULA CONSTRUCTION.** The 59 probes that pass do so for a *discoverable* reason — those guards put the copula adjacent to the predicate (`is enough`, never `is …​ enough`), so an interposed "does not" cannot match. The 33 failures share two shapes: **subject-negation**, where the negation lands on the subject and therefore outside the scanned window ("Nothing here **proves that no escalation route exists**", "**None of** the outputs are authoritative"), and **unrelated subject**, a bare predicate with no subject at all. **Adjacent-copula is what separates the working guards from the broken ones, and it is cheaper than subject-binding.** Correctly permitted today: `mode 3 alone is not sufficient`, `best-effort evidence is not authenticated`, `strict is not reachable on the default hosted runner`, `the action never verifies that the copies match`, `The idle timeout never terminates the process`.

**TWO FINDINGS BEYOND THE ASSIGNED FOUR:**
- **The same fact is guarded WRONGLY IN OPPOSITE DIRECTIONS on two surfaces.** The README's sysctl guard is *structurally blind* to the README's own sentence, because `kernel.yama.ptrace_scope` contains periods and `[^.]` cannot cross them — **the round-1 finding-#2 shape, a third time** — while it *does* reject the shorter true "No sysctl makes hosted execution strict." Its `platformClaims` sibling has the mirror defect: it **rejects the README's own true sentence verbatim**, so that sentence could never be adopted into `action.yml`.
- **`readme[25]` forbids a true sentence outright**, not merely a negated one: `resolving to the same file counts twice` is what the README asserts. The guard targets the *misleading gloss* corrected in T6 r16 ("two PATH **entries** resolving to the same file count twice", false when both entries share a spelling) but is unbound to "entries", so "two **distinct spellings** resolving to the same file counts twice" is rejected. **Reported, not changed — narrowing it is a judgement call against that round-16 ruling.**

**THE FOUR ITEMS.** The teardown contract is now three parts on both surfaces — `always()` covers an earlier step failing **only while the runner survives to run it**, finalization is a **separate** backstop, **runner death defeats both** — verified against `support.js:1170` (complete env, so `RUNNER_TRACKING_ID` is never cleared and the collector really is tracked) and the four request-handler call sites of `retireInactiveSessions`. **The fourth-site sweep found `support.js:7`** — "must never be uploaded" in the file header, on a surface the README pins never scan — now corrected and PINNED so a fifth site is impossible; sites checked and cleared are named (repo `README.md:133`, `SKILL.md`, `collector_boot.js:6`, the last sound because the launch token never reaches disk). The four widened halves are bound to their subjects with negation accounted for, using a **tempered window** that still crosses a table cell but stops dead at "not"/"never". Mode-1 is removed from `action.yml:215`, `support.js:47`, the required pin, and two commentary echoes — **coordinator-verified as zero occurrences across all three files** — with the general bypass fact and the documented passwordless-sudo fact kept and pinned, plus a forbidden half blocking re-adding *any* mode number.

**30 mutations, 30 as expected, 0 no-ops, every one TWO-DIRECTIONAL:** 9 required-half deletions RED, 11 forbidden-half false injections RED, **10 true-statement controls GREEN** including the brief's four counterexamples. Find-strings preflight-verified to resolve exactly once.

**TWO PROCESS FAILURES DISCLOSED RATHER THAN HIDDEN.** The first mutation battery used `git checkout --` to restore between mutations and **discarded uncommitted edits to all three source files**; it was detected immediately (7 no-ops and 10 wrong controls reported), the files reconstructed, the runner switched to snapshot-based restore, and the worktree diffed against the snapshot afterwards. And the implementer's **own first draft of the `always()` pins over-tightened in exactly the way this round exists to fix** — it rejected "the `always()` step covers a preceding step failing, not the runner dying" — caught by its own bidirectional probe and rewritten.

> **OWED TO TASK 9 — a decision, not just work.** The **33 remaining over-tightenings** stand, including the opposite-direction sysctl pair and `readme[25]`. They reject TRUE statements, so they are latent (they will fight a future editor) rather than shipped falsehoods. **The adjacent-copula construction is a cheap, mechanical, general fix that most guards do not use.** Decide whether to apply it across all 68 claims while the harness exists and the knowledge is fresh, or to accept the backlog with the shapes documented.

---

#### Task 8 fix round 3 (Codex review of `4a7dfef`: 1 Important, 1 Minor) — AND THE RULING THAT REFRAMES THE MECHANISM

**(1) IMPORTANT — the polarity framework is still unsound in BOTH directions, and the coordinator's proposed general fix does not fix it.** Adjacent-copula handles only predicate negation ("X is not Y"). **It does nothing for negative subjects ("None of X are Y"), modal negation ("cannot"), or unrelated subjects.** Three current, non-theoretical examples:
- **`support.test.js:8916` is the same trap, smaller.** It REJECTS the true "`report.md` **cannot** be treated as verbatim" — `cannot` is outside its negation vocabulary — and MISSES the false "`report.md` is not escaped but **is verbatim**", because the unrelated `not` stops the tempered window. **The tempered window was a smaller version of the defect it replaced.**
- **`support.test.js:9017` does leave the pre-colon form unguarded:** "`action-state.json` is not uploaded by this action" matches no alternative. **That is the exact categorical overclaim** — only "…not uploaded BY NAME" is true.
- **The sysctl pair remains broken oppositely:** `:8842` cannot cross the periods in `kernel.yama.ptrace_scope`, while `:5476` rejects the true sentence containing "does NOT make … strict".

**"These guards are the proof mechanism for Task 8's central requirement. With known false positives and false negatives, that proof is not admissible yet."**

**(2) Minor — `readme[25]` must be CHANGED, not rescued.** `support.test.js:8948` rejects the correct "two distinct candidate spellings resolving to the same file count twice". **Do not try to rescue the ambiguous current wording.** Replace it with the ACTUAL INVERSE: deduplication by realpath/inode, or distinct candidate spellings counting ONCE. The required half already pins the positive rule precisely.

> **THE RULING, which reframes what these guards are for and overrides the coordinator's lean:**
>
> **"Fix the 33 known failing guards now, but REJECT the proposed mechanical rewrite across all 68. Change only guards that fail true-statement controls, bind each to the COMPLETE AFFIRMATIVE CLAIM, and PRESERVE THOSE TRUE CONTROLS IN A TRACKED TEST. Forbidden regexes should catch KNOWN AFFIRMATIVE REGRESSIONS — not pretend to decide arbitrary English propositions."**
>
> The coordinator's lean was to apply adjacent-copula mechanically to all 68 while the harness was fresh. That is wrong twice over: the construction does not cover three of the four failure shapes, and a mechanical sweep would perpetuate the assumption that a regex can adjudicate arbitrary English. **The guards' real job is narrow and achievable — catch the specific affirmative sentence that would signal a regression.** And the true-statement probes must stop living in a scratchpad harness: **they become part of the suite**, so the bidirectional check is permanent rather than re-derived each round.

**CONFIRMED CORRECT, no further work:** the three-part teardown contract is accurate on both surfaces and agrees with GitHub's cleanup implementation; **removing the hosted mode-number claim did not weaken the conclusion** — the live workflow establishes sudo presence, the admission rule denies on that presence, and GitHub documents passwordless sudo for its hosted Linux VMs; and the upload-path claims are **now correctly lexical across all four identified sites**.

---

#### Task 8 round-3 outcome (`adb7b59`) — the audit is now a standing test, and one guard class is recommended for RETIREMENT

**THE BIDIRECTIONAL CHECK IS NOW TRACKED, AND IT COSTS NOTHING.** All **68 claims, 231 probes** (149 `accepts` that must NOT match the forbidden half, 82 `rejects` that must), plus three structural assertions — a claim with no controls fails, **a control with no claim fails so a rename cannot silently orphan its probes**, duplicate `what` strings fail — and a floor of 220 probes so a tidy-up cannot pass by deleting sentences instead of satisfying them. **Runtime 11.6 ms: 0.055% of the file's 21 s.** The two claim tables were hoisted from a test body to module scope to make it possible, verified behaviour-neutral first.

**WHAT IT WOULD HAVE CAUGHT, each verified by mutation rather than asserted:** round 1's `holds for every invocation` overshoot; **round 2's own retracted first draft** of the `always()` pin (which round 2 caught by hand, in a harness that then evaporated); round 3's `report.md` tempered window; round 3's missing `action-state.json` pre-colon branch; **the round-1 finding-#2 shape in its third recurrence** (the sysctl guard's inability to cross `kernel.yama.ptrace_scope`); and round 3's `readme[25]`. **Every finding of the last three rounds is now a standing test.**

**THE COUNT DRIFT, EXPLAINED — AND ROUND 2's AUDIT WAS NOT ACTUALLY TWO-SIDED.** Round 2's "33" was a count of rejected PROBES out of 92, never a guard count. The re-derivation found **44 failing probes — 34 false positives AND 10 FALSE NEGATIVES — concentrated in 27 guards**, growing to **32 changed** of 68 as probes were added. **The set did not shrink; it grew, and round 2 could not have seen most of it: round 2 measured ONE DIRECTION ONLY — whether guards reject true statements — and never asked whether a guard still catches its regression, so all 10 false negatives were structurally invisible to it.** That is why the sysctl blindness had to be found by hand in review. Among the new finds: `collector'?s?` missed a **curly apostrophe**, and a negative lookahead was an outright fail-open.

**THE FIXES were bound per claim — "by subject, affirmative inflection, or affirmative sentence position, chosen per claim, never applied uniformly"** — honouring the ruling against a mechanical sweep. The sysctl pair became **one shared `SYSCTL_BUYS_STRICT`, so two surfaces stating one fact cannot drift apart again**, keyed on inflection (`makes`/`does make`/`turns`) so the regex separates the reversal from "does not make" **without knowing what "not" means**, and tolerating `\.(?=\w)` so `kernel.yama.ptrace_scope` reads as an identifier rather than a sentence end. `readme[25]` was replaced, not rescued. One fail-open removed. **33 mutations, 33 as expected — including 8 that APPEND TRUE STATEMENTS to the real README and `action.yml` and leave everything GREEN.** Snapshot restore throughout, worktree proved byte-identical afterwards.

> **THE SOUNDNESS ANSWER, and it ends the patching rather than extending it: MOSTLY SOUND, WITH ONE CLASS TO RETIRE.**
>
> The mechanism works now **because the guards stopped pretending.** Three devices carry polarity and none needs a negation vocabulary — **affirmative inflection** (`makes` vs `does not make`), **subject binding** (`the check proves…` vs `nothing here proves…`), and **affirmative position** (a subject leading a sentence or cell vs being talked about). Each is a property of the ASSERTED sentence rather than a judgement about negation.
>
> **THE CLASS THAT CANNOT WORK: claims whose forbidden proposition is ITSELF NEGATIVE** — three, with a fourth of the same shape lurking. The reversal is *"the state file **cannot reach** the artifact"*: there is no affirmative inflection to key on **because the regression is a negative sentence**, and the true statement is that same sentence **being denied** (*"…which is not the same as saying it cannot reach the artifact"*). **"Distinguishing an asserted negative from a quoted-and-denied one is not a regex problem."** Today's guards buy proximity, which holds only because nobody has yet written the denial in the tight form — **"it will fail eventually, in one direction or the other."**
>
> **RECOMMENDED: retire those forbidden halves.** Keep the required halves plus the existing residual-disclosure sweep, which is already a presence check rather than a polarity pair and is the right instrument for "this fact must still be published". **The decisive argument: these are the only claims whose truth is a BEHAVIOURAL FACT THE SUITE ALREADY TESTS** — that the uploader follows symlinks is asserted by real tests, not prose. *"A prose guard that cannot decide its own proposition is worth less than the behavioural test that already proves the fact."*
>
> Two smaller admissions volunteered: `readme[23]`'s forbidden half **leans on this README's bolding convention** (asserted recipe steps are bold, prose denials are not) — honest but convention-dependent; and several forbidden halves are now **redundant with a precise required half**, belt-and-braces rather than load-bearing.

**Verification caveat disclosed rather than buried:** the first full `npm test` after the last edit reported one failure in `scripts/pr_closeout_workflow.test.js` — a file this commit does not touch, carrying its own comment about inode reuse. Coordinator-checked: it passes 74/74 on three consecutive isolated runs, which is CONSISTENT WITH a flake rather than proof of one; the clean final `npm test` (1128/1087/0/41) is the stronger evidence.

---

#### Task 8 fix round 4 (Codex review of `adb7b59`: 2 Important, 1 Minor) — and the rule that ends the pattern

**(1) IMPORTANT — the replacement devices STILL reject true statements. Fourth version of the same trap.** The shared `SYSCTL_BUYS_STRICT` guard (`support.test.js:5270`) matches the TRUE sentence *"Hardening the runner **never makes** hosted execution strict-admissible"* — **its 90-character window consumes `never`, then finds the affirmative `makes`. Inflection alone is therefore insufficient.** Likewise the `report.md` prose branch (`:9053`) rejects *"`report.md` **never claims** that it is verbatim"*, because the window consumes the matrix denial before reaching `is verbatim`. **"The report construction is still a smaller version of the same trap."**

> **THE ROOT CAUSE, NAMED AT LAST — and it retires the whole approach that produced four rounds of this: "ANY WINDOW THAT CAN CROSS A CLAUSE RECREATES THE SEMANTIC PROBLEM. KEEP THE GUARDS EXACT AND DIRECT."** Subject binding, affirmative inflection and affirmative position are useful for NARROW REGRESSION SIGNATURES — they are not a general polarity mechanism, and **the 64 non-retired guards are NOT categorically sound.** Every fix so far has widened or tempered a window; the answer is to stop having windows and match the direct regression form.

**(2) IMPORTANT — the tracked test does not enforce its own stated coverage contract, and it is the vacuous-assertion defect AGAIN.** At `support.test.js:9970`, **a control object with `accepts: []` or `rejects: []` PASSES** — so a claim need not actually be checked in both directions, which is precisely what the test was built to guarantee. And the global floor at `:9990` **permits ELEVEN of the current 231 probes to be deleted while staying green.** FIX: require BOTH arrays non-empty for every non-retired guard, and **pin the exact total — or exact per-claim counts — rather than `>= 220`.**

**(3) Minor — the `report.md` claim's POSITIVE half is too weak.** `support.test.js:9023` proves only that the copies are not byte-identical. It does not require that `report.md` is escaped and capped, nor that `report.json` is the verbatim comparison surface — **so deleting the fidelity rows leaves the claim green.** Pin both positive facts directly.

> **RETIREMENT RULING: ACCEPTED — but the coordinator's supporting argument was WRONG, and the correction matters.** I endorsed the implementer's reasoning that the residual sweep plus existing behavioural tests suffice, since the suite already proves the uploader follows symlinks. Codex's rebuttal: **"Behavioral tests establish what the code does; they cannot stop consumer prose from contradicting it."** The symlink test proves the behaviour; it does nothing to prevent the README asserting the opposite. And the existing residual sweep "checks generic symlink following and human comparison, NOT each consequence being protected."
>
> **So each retired guard needs an explicit POSITIVE DISCLOSURE requirement in its place:**
> - **State file:** no enumerated path names it **AND** symlink substitution can carry its bytes.
> - **Signal name:** absent from normal rendered evidence **AND** able to leave through substituted state bytes.
> - **Nonce:** detects a mismatch but **enforces/prevents no pairing.**
> - **Mark each claim structurally as `retired` with its NAMED REPLACEMENT PROTECTION, so removal or renaming still fails coverage.**

---

#### Task 8 round-4 outcome (`5e12d1a`) — the audit went mechanical, and the coordinator found a fifth instance

**THE CLAUSE-CROSSING DEFECT WAS DEFINED OPERATIONALLY RATHER THAN BY EYE**, which is why this round found what four rounds of reading had not: take each `rejects` probe, find the span the guard matches, **insert a denial (`never`, `does not`, `cannot`, `, which is not the same as saying that`) at every word boundary INSIDE that span, and see whether the guard still fires.** A guard that still fires skipped over the denial.

**The reviewer found 2. The mechanical audit found 14 more.** 17 guards contained a `{0,N}` window; **16 demonstrated a real clause crossing from their own regression probes.** Two were retired; the other twelve converted, and for ten a natural true sentence the old guard rejected could be constructed — "The idle timeout **never acts as** a teardown backstop", "The `always()` step **never runs** when the runner process dies", "`PATH=\"\"` **never counts as** absent", "The digest is one part; **nothing** is the trust anchor". Each conversion is proved by a paired RED reversal and GREEN true statement appended to the real surfaces.

**THE COVERAGE CONTRACT NOW ENFORCES ITSELF:** both arrays must be non-empty for every live guard (`rejects: []` and `accepts: []` **both passed before** — M9/M10 now RED); a retired claim must carry no live `forbidden`, no orphaned controls, and a replacement name that EXISTS; and the totals are **exact** (`claims 68`, `retired 4`, `probes 229`) rather than a floor that let eleven probes be deleted. The retirement registry is bound in **both** directions — a retirement pointing at nothing fails, and a disclosure nothing points at fails. The `report.md` positive half now interpolates the cap from `EXCERPT_CHAR_CAP`, **so the documentation and the renderer cannot drift**. Only the README needed new prose; `action.yml` and `support.js` already carried both halves and are unmodified. **42 mutations, 42 as expected**, snapshot restore throughout with `cmp` confirming byte-identity.

> **COORDINATOR FINDING — THE FIFTH INSTANCE, DEMONSTRATED NOT ARGUED, AND IT IS IN THE REPLACEMENT PROTECTION ITSELF.** The report claims **"Zero. All 64 live guards now contain no `{0,N}` gap at all."** That is true **only of the FORBIDDEN halves.** Ten `{0,N}` windows remain in the file, and while most are ordinary assertions or history comments, **three are the `POSITIVE_DISCLOSURES` patterns — the named replacement protection for the four retired guards** (`support.test.js:10115`, `:10123`, `:10131`) — and two are REQUIRED halves (`:5413`, `:9299`).
>
> Probed directly rather than inferred: the state-file disclosure pattern `/symlinks unconditionally[\s\S]{0,200}(?:puts the state bytes|put these bytes) into the archive/i` **matches BOTH** the honest disclosure AND its reversal — *"follows symlinks unconditionally, **but nothing here ever** puts the state bytes into the archive."* **So a README that retracted the disclosure would still satisfy the check that exists to keep it published.** The retirement escaped a mechanism that could not decide negatives by adopting a replacement carrying the same defect.
>
> The required-half case is a weaker failure (it would accept a degraded statement rather than reject a true one), but the disclosure case is the retirement's whole load-bearing half.

**THE DOCUMENTED BOUNDARY, offered instead of a fifth conversion pass and worth accepting on its own terms:** **61 of the 64 live guards also match their own regression QUOTED INSIDE A DENIAL** — "it is not true that *X*", "the claim that *X* was retracted". **A substring match cannot distinguish an asserted sentence from a mentioned one**, and anchoring further only trades that for missing real comma-continued reversals. The three exceptions are anchored to a sentence or cell start by accident of what they had to pin, not by design. The recommendation: **these guards catch inline reversals of the exact sentences this repository ships — the whole class the last four rounds actually produced — and they do not adjudicate English.** The consequence for authors is one sentence, and it is in the file: **a surface that wants to discuss a retracted claim must PARAPHRASE it rather than quote it.**

---

#### Task 8 fix round 5 (Codex review of `5e12d1a`: 2 Important, 1 Minor) — the boundary is ACCEPTED, so this closes the mechanism

**(1) IMPORTANT — the retirement replacement still fails open, CONFIRMED and worse than the coordinator found.** All three `POSITIVE_DISCLOSURES` patterns allow intervening text to negate the promised disclosure; **the coordinator's state-file counterexample "matches exactly as reported"**, and the signal pattern likewise accepts *"the symlink substitution proves that **no route can** put the state file's bytes into the archive."* **Worse: `support.test.js:10145-10155` accepts `must: []`, `where: []`, or deletion of either half — so the named replacement can EXIST WHILE CHECKING NOTHING.** That is the vacuous-assertion defect for the sixth time in this cycle, now inside the registry built to replace the retired guards.
**RULED — option (b), the coordinator's lean: direct, INDEPENDENT, surface-specific assertions**, plus structural checks for non-empty and exact `where`/`must` sets with unique half names. Two separate assertions cannot be satisfied across a clause because neither spans one.

**(2) IMPORTANT — a live forbidden guard still carries a semantic window, and it is one round 3 CELEBRATED.** `support.test.js:5402` exempts any sentence containing `strict` after the predicate — the `(?![^.]*strict)` lookahead round 3 described as "saving" that claim. **It is a fail-open:** *"The run digest is the trust anchor even without strict admission"* is NOT rejected, although the digest alone is never the trust anchor. Outside the twelve conversions, which are otherwise sound. FIX: remove the lookahead and add that sentence as a rejecting probe.

**(3) Minor — the required-half audit is incomplete, and required halves are NOT polarity-free.** The windows at `:5413` and `:9299` matter because **required halves are still executed** at `:5718` and `:9394`, including for retired claims — and both accept contradictory prose: `:5413` accepts *"The admission record is **not** part of the trust unit; only the digest and artifact matter."* There is also an unbounded equivalent at `:9164` accepting *"sorted … but **never** joined with a single NUL byte and **never** hashed as UTF-8, printed as lowercase hex."* FIX: split into direct affirmative requirements. **"Do not treat presence checks as polarity-free."**

> **THE BOUNDARY IS ACCEPTED — which caps this mechanism and ends the pattern.** *"A regex cannot reliably distinguish assertion from quotation or retraction. Documenting that historical claims must be paraphrased is preferable to another semantic-regex cycle."* The twelve converted guards are **"acceptable regression signatures — they no longer pretend to understand arbitrary English."**
>
> **AND THE FRAMING THAT PUTS FIVE ROUNDS IN PROPORTION: "The consumer prose is presently correct; these findings concern protections that can silently certify future contradictory prose."** The shipped documentation is right today. Everything since round 1 has been about whether the guards would notice if it stopped being right.

**ALSO RULED, not blocking:** the exact `68 / 4 / 229` contract is **deletion-evident, not tamper-evident** — probe substitution or duplication preserves the totals, and the disclosure registry sits outside them. Its comment accurately describes deletion protection, so the limitation stands as documented rather than as a defect.

---

#### Task 8 round-5 outcome (`95a4fc2`) — the join was REMOVED rather than tightened, and the audit is now reproducible

**The disclosures no longer join two facts across a gap — each pattern is a contiguous phrase of shipped prose CARRYING ITS OWN SUBJECT.** The reviewer's counterexample fails because subject and predicate are welded: *"replacing session.log with a link to ../action-state.json puts the state bytes into the archive"* is simply not contained in *"…but nothing here ever puts the state bytes into the archive."* Structural enforcement added: non-empty `where`/`facts`, no duplicates, `Object.keys(must)` deep-equal to `where`, per-surface half names unique AND exactly equal to `facts`, every pattern a RegExp, and an exact total of 18. **Tamper-evidence was taken inside the registry because it was cheap there — a duplicate can no longer stand in for a deletion.**

**The `(?![^.]*strict)` lookahead is gone**, replaced by the direct regression form, with the sentence it used to excuse now a tracked rejecting probe (229 → 230). **Required halves may now be lists**, feeding all three executors, with `required: []` blocked by the same vacuity check the forbidden side already had. **The sweep found 5 needing splitting — including `:9096`, which NO review named**, because it hid from round 4's line-based grep by being built with `new RegExp([...].join())`. 68 → 75 required patterns.

**THE INSTRUCTIVE MUTATION:** M10 came back GREEN until the implementer found that **`action.yml` states the three-part trust unit in TWO comment blocks, both flowing into one haystack.** Reversing both → RED; reversing one → GREEN, **which is correct**. That is a property of the surface model, not a bug, and it changes what a required half means.

**WINDOWS: ZERO, AND THIS TIME MEASURED ON REGEXP SOURCE RATHER THAN LINES** — 157 patterns audited (75 required, 64 forbidden, 18 disclosure), none containing `{0,N}`, `[^x]*`, `[\s\S]*`, `.*` or a negative lookaround. Run against the PRE-FIX file the same audit reported exactly 10 — the set the review and coordinator named, plus `:9096`. The 64 forbidden halves re-probed against their own 75 regression sentences: **0 clause crossings, so round 4's conversions hold.** Coordinator-verified independently: every surviving `{0,N}`/`[^x]*` in the file is either a history comment or an ordinary assertion outside the machinery.

> **COORDINATOR RESIDUAL — the defect class survives OUTSIDE the audited machinery.** `support.test.js:10462` asserts `/Input validation[^.]*exits [*_]*1[*_]*/i`, and probing it directly: it matches **both** *"Input validation failure exits 1 rather than 3"* AND *"Input validation **never** exits 1; it exits 3."* This is an ordinary presence assertion in the exits-section test rather than one of the 157 claim patterns — so the round's "zero" is accurate as scoped — but it is precisely the shape Codex's own ruling addressed: **"do not treat presence checks as polarity-free."** Flagged for judgment rather than fixed unilaterally.

**THE HANDOVER — six items, all genuinely undocumented, and two are traps:**
1. **The audit is a script, not a reading, and it is reproducible** — load the claim tables by appending `module.exports` to a temporary copy IN THE SAME DIRECTORY (`__dirname` must still resolve), and stub `node:test` through `Module._load`. **The stub must be a CALLABLE FUNCTION carrying the named helpers**, because the file does `const test = require('node:test')`. Roughly thirty lines; every round so far re-derived it by hand.
2. **The signal is only usable with one refinement: a crossing must STRICTLY SPAN the injected denial** (`start < i && end > i + denial.length`). Without it the audit reports ~28 artifacts — the injected word swallowed as the pattern's own leading token, or the pattern re-anchoring after the denial, which is the accepted mention boundary. **"My first pass reported 8 leaks and every one was noise. Anyone who reruns a naive version will chase ghosts and may 'fix' sound guards."**
3. **A surface is a whole-file concatenation, so deleting a sentence is not deleting a fact.** `action.yml` states the trust unit twice; `support.js` carries commentary that can satisfy a required half after the consumer-facing statement is gone. **A required half proves the fact is SOMEWHERE on the surface, not that it is where a reader will look.** Count occurrences before mutating, or a GREEN means nothing.
4. **On a prose edit, RE-LIFT the phrase; do not bridge it.** All five rounds of this defect entered the same way — the prose changed slightly and someone inserted a small `\s*`, `[^.]{0,N}` or `[\s\S]{0,N}` to reach across the change. Each was locally reasonable; each recreated the semantic problem.
5. **Do not apply "no quantifiers" mechanically.** `[*_]*` is load-bearing — it absorbs this README's `**bold**` markers and matches nothing else. **The rule is "no construct that can hold a WORD", not "no quantifier".**
6. **If the probe contract is ever hardened, copy the REGISTRY, not the counter.** `68 / 4 / 230` counts probes, so substitution and duplication survive it; the disclosure registry is duplication-evident because each half is NAMED, names must be unique, and the name set must equal a separately declared `facts` list. **Naming beats counting.**

---

#### Task 8 fix round 6 (Codex review of `95a4fc2`: 2 Important, 2 Minor) — THE LAST ROUND, with an explicit stopping condition

> **STOPPING CONDITION, set by the coordinator BEFORE this round runs.** Six rounds have now found the same defect class in successively narrower instances, and Codex's own standing note is the proportion: **"The current shipped prose is correct, but its protections still fail open in the cases above."** The consumer documentation has been right since round 1; every round since has hardened guards against FUTURE drift. **This is the last fix round. Anything still open after it is recorded as a known limitation in the plan and shipped — not carried into a seventh round.** The four items below are concrete and bounded; two are structural (deletion-evidence), which is why they are worth one more pass rather than a footnote.

**(1) IMPORTANT — a replacement disclosure still matches a direct contradiction.** `support.test.js:10265` omits the subject/copula `which is`, so this PASSES: *"which is **not** a claim about paths and not one about bytes: it is not categorically unable to leave the runner."* **Codex is explicit that this is NOT the accepted quoted-denial boundary — "it is an ordinary negation immediately before the matched fragment."** FIX: pin `which is a claim…` contiguously.

**(2) IMPORTANT — the new required halves are not all subject-bound, and their coverage is DELETABLE.** Three parts:
- `support.test.js:5448-5449` can take *"plus the matching digest"* and *"plus the artifact"* **from an unrelated sentence on the concatenated surface** — the whole-file concatenation property, biting exactly where round 5 documented it would.
- `:9228` accepts *"the candidates are **not** sorted with JavaScript's default comparison…"* **because the pattern starts after `not`.**
- **Deleting one element from any required list passes the non-empty check at `:10374-10376`** — there is no exact 75-pattern contract and no named-fact binding, so the deletion-evidence won in the registry was never extended to the required side.
FIX: surface-specific COMPLETE assertions for the trust-unit relationship; bind the digest recipe to its subject; make multi-half requirements deletion-evident.

**(3) Minor — the exact-18 registry is not duplicate-SUBSTITUTION-evident.** `:10333-10340` checks unique half NAMES, not unique pattern SOURCES. **Replacing the path-name pattern with a copy of the symlink-following pattern under the original path-name label preserves the fact set, all 18 checks, and every current match.** Codex: *"Your M5 covered duplicating the tuple, not duplicating its regex under another label."* FIX: check `(source, flags)` uniqueness per surface.

**(4) Minor — RULED: the machinery boundary is ARBITRARY, so sweep ordinary consumer-documentation assertions too.** The coordinator's `:10462` residual is confirmed — it accepts *"Input validation **never** exits 1; it exits 3."* — **and its mirror is added: `:8843` REJECTS the true *"The permissions are read-only and are **not** only for the snapshot."*** Both are word-holding windows over consumer-facing claims, and **"the accepted quoted-denial limitation does not excuse either case."** The coordinator's lean to sweep them was right.

**CONFIRMED SOUND:** the other disclosure phrases are direct, the removed `strict` lookahead is correctly pinned, and **the 64 forbidden guards remain sound within the accepted regression-signature boundary.**

#### Task 8 final-round outcome (`5fe954c`) — all four closed, and the repo's own scanner earned its keep

One file, `support.test.js` (+227 / −41). Contracts unmoved: **68 claims / 4 retired / 230 probes / 18 disclosure checks.** Claim patterns 157 → **154** (required 75 → 72) — the digest recipe collapsed 3→1 and the signal name 2→1, because the shipped prose states each in ONE sentence, so one contiguous pin is both stricter and smaller than three joinable halves.

**(1) CLOSED.** The disclosure now pins `which is a claim about paths and not one about bytes: …` with subject and copula welded on. Mutation `which is` → `which is not` on the real README: pre-fix **GREEN** (the guard certified its own contradiction); fixed **RED ×2**.

**(2) CLOSED, three ways.** (a) The trust unit is now **one complete sentence per surface**, keyed by surface name, in each surface's own wording — verified each pattern matches only its own surface. The proving mutation guts the canonical `action.yml` sentence while **leaving the `:257` recap intact**, which is round 5's M10 lesson run in reverse: pre-fix GREEN (halves matched across two comment blocks), fixed RED. (b) The digest recipe runs unbroken from its subject; a `never` at **any of the four steps** now breaks the match. (c) `required` takes one of three shapes — a single pattern, a **named list bound to a declared `facts` set**, or a **per-surface map whose keys deep-equal `where`** — and both sides reject two halves that are the same pattern under different names. Deleting an element, deleting `facts`, substituting a pattern under its own name, and dropping a surface are each RED; the same deletions were GREEN pre-fix.

**(3) CLOSED.** `(source, flags)` uniqueness per surface, keyed on `String(pattern)`. Codex's exact attack — the symlink pattern copied under the path-name label — was GREEN pre-fix and is now RED.

**(4) SWEPT: 157 ordinary regex assertions** (136 `assert.match`/`doesNotMatch` + 21 `assert(…test(…))`). **11 held a word; 3 needed changing**, all over authored consumer-facing prose: `:753` (40 chars of room for "but never" in the admission record a human reads), `:8843` (**rejected the true** read-only sentence), `:10462` (accepted "Input validation **never** exits 1"). Each now carries **its own inline both-directions probes** — the thing these assertions never had, and the reason the windows survived five rounds. The other 8 are over machine-generated output, where an editor cannot insert a denial.

> **P5a is the round's methodological find.** The first replacement used single spaces and came back **GREEN**, because the closeout-gate commentary **preserves continuation-line indentation** — a wrapped phrase arrives with a run of spaces. Fixed with `\s+`. **The mutation caught it; inspection had not.**

**One self-inflicted defect, caught by the repo:** the first substitution-uniqueness key used a literal `\u0000` separator, putting a NUL byte in the file. `tools/scan_touched_suppressions.js` rejected it (`[scan-error] Touched file contains NUL bytes`).

**COORDINATOR-VERIFIED INDEPENDENTLY**, not taken from the report: validate PASS (payloadFiles 43, safetyScanFiles 87, dependencies 0); `support.test.js` 132/131/0/1; scanner exit 1, only the known forwarder-list finding; `git diff --check` exit 0; counters read directly from the file at `:10485`/`:10610-10612`. **Two mutations re-run from scratch by the coordinator** — negating the README disclosure (**RED ×2**) and deleting one element of a named required list (**RED**) — with byte-identical restore confirmed by `git diff --quiet` after each. The disclosure prose sits at `README.md:561-562` **line-wrapped**, so it matches only because `readmeSections` collapses whitespace; that is limitation 11 below, observed in the wild.

#### Task 8 KNOWN LIMITATIONS — recorded VERBATIM from the implementer, and shipped

> *Everything I know to be still fallible here after this round. This is what a future maintainer inherits.*
>
> **Boundaries that were ruled and will not move**
>
> 1. **Quoted denial.** A surface that quotes a forbidden sentence in order to deny it trips the forbidden half. Closing it needs negation-scope parsing. Ruled out in round 5; ships as documented.
> 2. **The 64 forbidden halves are regression *signatures*, not propositional judgments.** They catch the specific affirmative sentences an editor would plausibly write. An unenumerated paraphrase walks straight through. Closing it means either unbounded enumeration or semantics. Same ruling.
> 3. **Nothing checks a probe is realistic.** The 230 `accepts`/`rejects` sentences are the implementer's guess at what a reverting editor would write. A wrong guess means a guard proved against fiction. Not automatable.
>
> **Structural gaps that remain open**
>
> 4. **A required half proves a fact is *somewhere* on the surface, not where a reader will look.** Still true. My per-surface patterns narrow this (action.yml comments vs. rendered descriptions are separate surfaces; README claims are section-scoped) but *within* a surface, position is unchecked: ~~move the canonical sentence from a `description:` into a comment and the pin stays green~~. Closing it needs a per-claim location model. Not done — bounded value for real churn.
>
>     **CORRECTED (Codex, closing review) — the struck example is IMPOSSIBLE and would have misled the next maintainer.** Moving text from an input/output `description:` into a comment crosses **two separately enforced surfaces** and therefore FAILS rather than staying green. The limitation is real but only *within* one surface. Accurate examples: moving a sentence **between two comments**, or **between two different input/output descriptions**. Verified by construction — the per-surface trust-unit patterns were each confirmed to match only their own surface.
> 5. **Single-pattern required halves (~~68~~ **69** of 72) have no name and no declared fact.** Deletion-evidence covers named lists and per-surface maps only. **Weakening** a single pattern — shortening it, dropping a clause — passes everything. Closing it means naming all ~~68~~ **69** and declaring `facts` everywhere, or a golden file of pattern sources (which just moves the trust to whoever updates the golden file). Not done: high churn, low marginal return.
>
>     **CORRECTED (Codex, closing review), and I verified the arithmetic myself with the loader rather than accepting either number:** of the 72 required patterns, **66 are ordinary single patterns, 3 are the named report list, and 3 are the unnamed per-surface trust patterns — so 69 are unnamed, not 68.** The implementer counted the per-surface trio as covered because the per-surface *map* is structurally checked; the map's keys are, but its patterns carry no names.
> 6. **`facts` is per-claim, so a per-surface `required` whose surfaces state *different* facts cannot be expressed** — the structural check would demand identical name sets. Latent: the one per-surface user has a single unnamed pattern per surface. Close by making `facts` per-surface when a second user appears.
> 7. **The exact counters (68 / 4 / 230 / 18) are deletion-evident, not tamper-evident** — round 5's ruling, unchanged. Substituting one probe for a weaker one, or duplicating a probe, preserves the totals. I extended naming to the required side and pattern-uniqueness to both, but **the probe lists themselves are still bare arrays that are counted, not named.**
> 8. **Retirement is checked for existence, not adequacy.** A retired claim must name a disclosure that exists and be pointed at in return — but nothing checks the disclosure actually covers the retired claim's proposition. A retirement pointing at an unrelated disclosure passes.
>
> 8b. **ADDED BY CODEX AT THE CLOSING REVIEW — NAMES DO NOT ESTABLISH SEMANTIC ADEQUACY, AND THIS GENERALIZES BOTH 7 AND 8.** `support.test.js:10546-10552` prevents the *same* regex appearing under two different names. **It does not prevent a named fact from being replaced by a DIFFERENT, unique, WEAKER regex that happens to match.** Uniqueness is a syntactic property; covering the named proposition is a semantic one, and nothing here checks the second. **This is the correction that matters most in the list, because it punctures the round's own headline:** naming was adopted over counting on the principle that "naming beats counting," and it does — for deletion and duplication. It buys nothing against substitution-by-weakening. **The scope is wider than limitation 5 admitted: it affects the 3 named requirements and all 18 `POSITIVE_DISCLOSURES` checks too, not merely the 69 unnamed ordinary patterns.** So every part of this mechanism — named and unnamed alike — is deletion-evident and duplication-evident, and none of it is weakening-evident.
> 9. **`POSITIVE_DISCLOSURES` builds its own surfaces.** It shares the extractors today, which is why round 5 wrote it that way, but **nothing asserts** the registry reads the same text the claim executors do. A divergence would be invisible.
>
> **Traps — read these before touching anything**
>
> 10. **THE BRITTLENESS IS THE POINT, AND IT IS ALSO THE TRAP.** The trust-unit and recipe pins now fail on any prose rewording. The fix a hurried maintainer reaches for is a small `\s*` or `[^.]{0,N}` bridge. **All six rounds of this defect entered exactly that way.** RE-LIFT the phrase from the file; never bridge it. Nothing enforces this — it is the single most likely route back to the defect class.
> 11. **THREE DIFFERENT WHITESPACE NORMALIZATIONS, AND THEY BIT ME THIS ROUND.** `readmeSections` collapses all whitespace; `platformSurfaces()` double-trims each comment line; the closeout-gate `commentary` **keeps continuation-line indentation**. A pattern written with single spaces silently under-matches on the third. Use `\s+` there (whitespace cannot hold a word). Closing it means one shared normalizer, which would touch neighbouring assertions that already compensate — not done, so it stays a trap.
> 12. **THE WINDOW AUDIT IS SYNTACTIC AND WOULD NOT HAVE CAUGHT ANY OF THIS ROUND'S FOUR FINDINGS.** Round 5 reported "157 patterns, zero windows" while all four round-6 defects were already present. Subject-omission, cross-sentence assembly and deletability are invisible to a source scan. **Never again report "zero windows" as "the guards are sound."**
> 13. **`[*_]*`, `\s+`, `['’]`, `[—-]+` are safe; `[^,]*`, `\S+`, `.{0,N}` are not.** The rule is "no construct that can hold a WORD", not "no quantifier". `\w+` after a stem (`dedup\w+`) is safe — it cannot match whitespace.
> 14. **My classification of the 8 surviving word-holding ordinary assertions is a judgment with no encoding in the repo.** If one of those output formats ever becomes prose a human authors, nothing re-checks it.
>
> **The highest-value thing that was NOT built**
>
> 15. **The audit and mutation harness lives nowhere.** Six rounds have each re-derived the `module.exports` + `Module._load` loader by hand, and this round's sweep and window audit are equally disposable. **Committing them as a test (~60 lines total, or refactor the tables into a module the audit can import) would have caught findings 2b and 4 mechanically and would make "zero windows" reproducible instead of asserted.** I did not build it because the round's scope was the four findings and the stopping condition forbids opening new work. If one item from this list is ever actioned, make it this one.
>
> **Retirement candidates — my honest read**
>
> - **Keep:** the 64 forbidden halves + 230 probes. Cheap, proven in both directions, and the only part with a real regression story.
> - **Keep:** the per-surface required patterns. They carry their weight — the trust-unit finding was real and only per-surface completeness closes it.
> - **Retire the three exact counters (68 / 4 / 230).** They are deletion-evidence only, they have been wrong-footed twice as pure bookkeeping, and naming now covers both the registry and the required side. Every round spends effort keeping them accurate for a property that review already provides.
> - **Borderline — the named-list form I just added has exactly ONE user**, and the per-surface form has one. I added ~45 lines of structural validation to protect two claims. It is correct and it generalizes, but a future maintainer who finds it more ceremony than it earns would be within their rights to collapse Form B back into contiguous per-surface patterns. **The per-surface map is the part that pays; the named list barely does.**
> - **And the blunt one:** this mechanism has cost **six review rounds and has never corrected a single line of shipped prose.** Every round confirmed the documentation was already right. Its entire value is prospective — catching drift that has not happened. For a document set edited a couple of times a year, that is plausibly a worse trade than a checklist in the PR template. I would not have built it at this size. Now that it exists and is sound within its stated boundary, keeping the cheap half is defensible; growing it further is not.

**COORDINATOR'S DISPOSITION.** Limitations 1–3 are Codex's own rulings and need no action. **4–9 ship open.** 10–14 are maintainer traps and belong in the file, not just here — 11 and 13 already are. **Item 15 is the one I agree is worth money**, and it goes to Task 9 as a candidate rather than a seventh round. On the retirement read: the implementer's judgment that **this mechanism never once corrected shipped prose** is the honest measure of it, and it is recorded here so the decision to keep or shrink it is made on evidence rather than sunk cost.

#### ✅ TASK 8 CLOSED — Approved at `5fe954c` after SIX fix rounds. No Critical or Important issues; three Minor, all against the PLAN and HANDOVER rather than the code.

> **Codex, verbatim: "No seventh code round is warranted. Record those corrections and ship."**

**THE CODE IS CONFIRMED CORRECT** on all four items: the three trust-unit patterns at `support.test.js:5497-5499` are surface-specific and complete; the required-side structural contract catches deletion, missing surfaces, duplicate names and identical-pattern substitution; the three swept ordinary assertions work in both directions; and **no claim silently under-matches today** — all claim executors ran in the 131-pass suite, and the three-normalization split is accurately documented as a future editing trap rather than a live defect.

**The three Minor corrections are recorded inline above** at limitations 4, 5 and the new 8b. All three were against text I wrote or relayed, not against the implementation. **8b is the one that matters**: naming beats counting for deletion and duplication and buys **nothing** against substitution-by-weakening, and that gap covers the named requirements and all 18 disclosure checks too — not just the unnamed ones. The round's own headline was narrower than it sounded.

**RETIREMENT — RULED, AND NARROWER THAN THE IMPLEMENTER PROPOSED.** The blunt assessment is accepted: *"the mechanism is overbuilt relative to its demonstrated value."* But **do NOT remove all three counters.** `68` and `4` are largely redundant with bidirectional name coverage; **`230` still uniquely detects deletion of a non-final unnamed probe**, exactly as limitation 7 admits. **Make no retirement change in this PR. Reassess after the next real documentation edit** — the first edit is the experiment that tells you whether the mechanism earns itself.

**ITEM 15 — RULED AGAINST COMMITTING IT NOW, AND THE REASONING CORRECTS MY OWN ENTHUSIASM.** I argued the 45-line loader was the one item worth money because I built it and it worked first try. Codex's answer: **run it as final-review EVIDENCE and record its output, but do not commit it during Task 9.** *"A permanent syntactic audit that the limitations correctly admit would have missed all four round-6 defects is not worth expanding the PR at its final gate."* That is limitation 12 turned against my own recommendation, and it is right — cheap to build is not the same as worth maintaining. **If the documentation mechanism survives its next real edit, that future cycle is the right time to extract and commit the harness.**

---

### Task 9: Full battery, scope proof, and handoff

> **Queued test (Task 5 spec-review disposition):** add the missing teardown
> non-ESRCH kill-failure → 3 pin (two lines with the existing `kill` seam: inject a
> kill that throws `EPERM` → assert return 3 and the diagnostic stderr line).

#### THE FIVE WHOLE-IMPLEMENTATION CHECKS (Codex, at the close of Task 8, answering "what should Task 9 verify that no per-task round could?")

These are additive to Steps 1–4 below, and they exist because **fifteen review rounds each validated one task in isolation.** Every one targets a seam BETWEEN tasks — the place where independently correct modules disagree — which is precisely what a per-task round structurally cannot see.

1. **Composite failure precedence.** Exercise command failure, strict refusal, renderer/report failure, and the queued teardown `EPERM` failure **through the complete action**. Assert the final job result, the staged artifact state, and — the load-bearing one — **that later `always()` steps cannot mask the run verdict.** This subsumes the remaining failure-matrix cases carried since Task 6 (gate 3's `true` mirror, collector loss, authentication failure, renderer failure, signal termination).

2. **End-to-end identity and byte lineage.** Trace ONE invocation nonce and admission record from the `start` output, through the qualification-plus-digest block, into `report.json`, the staged hashes, and **a genuinely downloaded artifact.** This is gate 5 (cross-module byte contract) made concrete, and Codex names it as *"where independently correct modules can disagree."*

3. **Secret/capability boundary.** Confirm the launch token never reaches disk, outputs, logs, reports or the artifact; verify the session credential appears **only** where documented. **Include hostile symlink substitution as a DISCLOSED RESIDUAL, not a promised prevention** — the distinction Task 8 spent six rounds getting into the prose must hold in the test's framing too.

4. **Cross-module constants, derived independently.** Compare state keys, evidence filenames, exit taxonomy, report schema and cap, stripped control-plane variables, digest recipe, and workflow upload paths. **Do NOT derive the expected set using production helpers** — a check that imports the thing it is checking proves only self-consistency. This is the same defect class as the vacuous guards, one level up.

5. **Merge-time operational proof.** Clear the full-diff scanner finding by hand; perform the accepted one-time forwarder bootstrap rerun; **then** verify exact-head checks, unresolved threads, approval state, hosted demo result, and the downloaded artifact before PR closeout. (This formalizes the two MERGE-TIME ACTIONS owed since the 2026-08-14 single-PR decision at `:3681`.)

> **RULED — item 15's harness is NOT committed during Task 9.** Run the 45-line loader as **final-review evidence** and record its output in the handoff. Codex: *"A permanent syntactic audit that the limitations correctly admit would have missed all four round-6 defects is not worth expanding the PR at its final gate."* **If the documentation mechanism survives its next real edit, that future cycle is when to extract and commit it.**

#### AMENDMENTS RECORDED DURING TASK 9, BEFORE THE CODE THEY LICENSE

**A1 — Step 3's BASE REF was wrong, and the error is invisible from its output.** The step says `git diff codex/publish-debug-skill...HEAD --stat`. The LOCAL branch of that name sits three commits behind its remote, so the three-dot merge base resolves to a point BEFORE the closeout cycle and the stat pulls in all of `actions/closeout/**`, `scripts/pr_closeout*`, `tools/workflow_checks.js` and the 2026-08-07 plan — 52 files instead of 20. A reviewer reading that output would conclude this PR touches `scripts/pr_closeout*`, which the same step forbids. **The base for this cycle's single PR is `origin/codex/publish-debug-skill` (`af89573`), which is exactly `git merge-base origin/main HEAD`.** Use that, or the merge-base form, and never the bare local branch name.

**A2 — Step 3's allowed-path list omits two paths this very plan mandates.** `scripts/debug_server.js` and `scripts/debug_server.test.js` are changed by this cycle **by design**: the collector-side work at `:1770`, `:1808` and `:1870` (per-session appended-byte digest, the logs-serve responder proof) and the instruction at `:1778` to append to `scripts/debug_server.test.js` in place. The list at Step 3 was written before those tasks and never updated. **Both paths are IN SCOPE.** The corrected list is the twelve entries already there plus `scripts/debug_server.js` and `scripts/debug_server.test.js`. Nothing else changes: `scripts/pr_closeout*` and `actions/closeout/**` remain out of scope and are untouched.

**A3 — checks 2 and 5 are split at the local/hosted boundary, and the hosted halves are NOT built.** Check 2's "a genuinely downloaded artifact" and the whole of check 5 need a hosted CI run and a real pull request. Neither is simulated, and no test pretends to either — a local stand-in would be precisely the confident claim this cycle has repeatedly found worth less than the honest limitation. **Locally the lineage stops at the staged bytes and the ENUMERATED upload paths**; the rest is the merge-time checklist below, for a human to execute at PR time.

**A5 — Step 2 said the suppression scan is "clean". It is not, and never has been.** `node tools/scan_touched_suppressions.js` exits **1** on the ONE accepted finding recorded at Task 7 — the forwarder-list line removed from `closeout-gate.yml`, which the fail-closed gate diff cannot tell from a weakening. "Expected: clean" would make a reviewer treat a correct run as a regression, or worse, treat the exit 1 as normal and stop reading the findings. Step 2 now states the exact expected output and says plainly that a SECOND finding of any kind blocks the merge.

**A4 — the residual demonstration uses a DIRECTORY symlink, not a file one.** Check 3 names "hostile symlink substitution". The implementer's host denies `SeCreateSymbolicLinkPrivilege`, so a file-symlink variant could only ever have shipped GREEN-UNTESTED — a check nobody has seen fail, which this cycle's rule 4 forbids. The shipped demonstration plants a junction at an enumerated name and reads the state file through it, which exercises the **second** sentence of the same disclosed residual (`implicitDescendants` expanding a substituted directory) and runs on the implementer's host, where it was proved red by deleting the disclosure it pairs with. The file-symlink variant is deliberately NOT shipped rather than shipped unproven.

- [x] **Step 1: Full test battery** (one invocation, foreground, no pipes)

Run: `npm test`
Expected: 0 fail, 0 cancelled. The suite grows by the debug_report + debug-evidence-action tests (~25–35 new tests). Pre-existing timing-sensitive suites (`debug_server` collector-claim, `pr_closeout_process` symlink) can flake under machine load — a failure there needs an isolation rerun of THAT file before it is called real.

- [x] **Step 2: Validator + suppression scan**

Run: `npm run validate`
Expected: `{"status":"PASS","payloadFiles":43,...}`.

Run: `npm run scan:suppressions`
Expected: the designed additive-only gate-scan advisory, and nothing else. It exits **1** on the ONE accepted finding recorded at Task 7 — the forwarder-list line `- workflows: ["Validate", "Closeout preview"]` removed from `closeout-gate.yml`, which the fail-closed gate diff cannot distinguish from a weakening. Any SECOND finding, or any marker / config-silencing / test-weakening finding, is a real regression.

- [x] **Step 3: Scope proof** *(base ref and path list corrected by amendments A1 and A2 above)*

Run: `git diff "$(git merge-base origin/main HEAD)...HEAD" --stat` — equivalently `git diff origin/codex/publish-debug-skill...HEAD --stat`. **Not** the bare local `codex/publish-debug-skill`, which is stale; see A1.
Expected: ONLY these paths — `docs/superpowers/{specs,plans}/2026-08-13-*`, `scripts/debug_evidence.js`, `scripts/debug_diff.js`, `scripts/debug_report.js`, `scripts/debug_report.test.js`, `scripts/debug_evidence.test.js`, `scripts/debug_server.js`, `scripts/debug_server.test.js`, `tools/validate_repository.js`, `actions/debug-evidence/**`, `.github/workflows/debug-evidence-demo.yml`, `.github/workflows/closeout-gate.yml`, `README.md`, `SKILL.md`. ZERO deletions outside the modified script files' internal edits; NOTHING under `scripts/pr_closeout*` or `actions/closeout/`.

- [x] **Step 4: Commit any stragglers, then report**

Report to the controller: battery numbers (tests/pass/fail/skips), validator JSON, scope stat, and any deviations from this plan (each needs a recorded amendment before it ships).

#### CHECK 5 — THE MERGE-TIME CHECKLIST (a human executes this at PR time; nothing local can stand in for it)

This is check 5 in full, plus the last hop of check 2. Every item needs the hosted runner or the real pull request, so **none of it is simulated and no test in this repo claims any of it.** Work top to bottom; each item says what a PASS looks like, because "it looked fine" is what this cycle spent fifteen rounds removing.

1. **Clear the full-diff scanner finding by hand.** `node tools/scan_touched_suppressions.js` exits 1 on one accepted finding: the deleted `- workflows: ["Validate", "Closeout preview"]` line in `.github/workflows/closeout-gate.yml`. PASS = the run prints `suppression-scan: no marker/config-silencing/test-weakening findings`, then exactly ONE `gate-scan` FAIL line, and that line is byte-identical to the one recorded here apart from `head=`. **A second finding of any kind is a real regression and blocks the merge.**
2. **Perform the accepted one-time forwarder bootstrap rerun.** The gate's forwarder list now names the demo workflow, and a forwarder cannot retry a workflow it did not know about on the run that introduced it. PASS = the gate is re-run once on the merge head AFTER the forwarder change is present, and the second run forwards the demo retry.
3. **Exact-head checks.** PASS = every required check is green **on the exact head SHA of the PR**, not on an ancestor. Re-read the SHA from the PR page after the last push; a green check attached to an earlier commit is not evidence about what merges.
4. **Unresolved review threads.** PASS = zero unresolved threads. A resolved-by-force or hidden thread is not resolved.
5. **Approval state.** PASS = an approving review that is not dismissed, and no CHANGES_REQUESTED outstanding.
6. **Hosted demo result.** PASS = `.github/workflows/debug-evidence-demo.yml` completed on the hosted runner and the `strict-refusal` probe reached the ADMISSION REFUSAL (exit 3 from `start`, the wrapped command never executed) rather than an input error. This is the one place the strict default is exercised on the platform it was written for: hosted runners ship a passwordless-sudo rule, so `strict` MUST refuse there. **A demo job that went green under `strict` means the admission check is broken, not that the runner is clean.**
7. **THE DOWNLOADED ARTIFACT — the last hop of check 2, and the only one that closes it.** Download the `debug-evidence` artifact from the demo run and check, in this order:
   a. it holds exactly `session.log`, `report.md`, `report.json` — no fourth entry, and no `action-state.json` under any name;
   b. `sha256` of each of the three equals the matching `name=` field of the `evidence-sha256` line in the **run step's log**;
   c. the `ADMISSION RECORD` line inside `report.json`'s `caveats` is byte-identical to the one the **start step's log** streamed, and both carry the SAME `invocation=` value;
   d. the artifact contains neither the session token nor the launch token — grep it for both, taking the session token from nowhere (it is not published; if you cannot obtain it, record that this sub-check was not performed rather than marking it passed).
   **The local checks stop one hop short of (a)–(d) on purpose. Do not mark check 2 complete until these are done.**
8. **Only then, PR closeout.**

#### WHAT TASK 9 SHIPPED, AND THE MUTATION THAT PROVED EACH PIECE

Six tests, all in `actions/debug-evidence/support.test.js`, plus the composite harness they share. **Every one was proved in BOTH directions**: green on the tree, and red under a mutation applied to ONE site of a counted anchor and restored byte-for-byte from a snapshot (never `git checkout --`). The ledger is the deliverable, not a footnote — a check nobody has seen fail is not evidence.

| check | proved red by |
| --- | --- |
| teardown non-ESRCH → 3 (the queued Task 5 case) | `support.js` teardown: `return 3` → `return 0` after the diagnostic |
| check 1, composite failure precedence | (a) `report`'s unreadable-staged-report `return 3` → `return 0` — the pure masking case; (b) `finish`'s command-exit mirror → `return 0`; (c) `action.yml`: the `always()` guard deleted from **Apply verdict** |
| check 2, identity and byte lineage | (a) `admissionCaveats`: `invocation=${nonce}` → a constant; (b) `payloadDigestLine`: hash input `bytes` → `name + bytes` |
| check 3, secret boundary | `start` persists `launchToken` into `action-state.json` |
| check 3 (residual), disclosure | the README residual's `follows symlinks, unconditionally` sentence reworded away |
| check 4, cross-module constants | (a) `EXCERPT_CHAR_CAP` 500 → 400 in `debug_report.js`; (b) `GITHUB_STATE` removed from `RUNNER_COMMAND_FILE_VARS`; (c) an extra key added to `run`'s state commit |

**The composite harness is the part with a future.** `driveCompositeAction` walks the REAL step list out of `action.yml`, evaluates only the two guard shapes the file actually uses (anything else THROWS — a fall-through to `true` would turn a new guard into "always runs"), resolves each step's `env:` expressions and dispatches through `main()`'s own branch table. So the model executes the shipped wiring rather than describing it, which is what mutation (c) on check 1 demonstrates: deleting a guard from `action.yml` changes what runs.

**AND THE HARNESS'S OWN LIMIT, stated because check 1 rests on it.** The three composite rules are the IMPLEMENTER'S READING of GitHub's precedence, verified against no hosted runner. The guard STRINGS are pinned by an existing test and the step list is parsed from the shipped file, so a rewiring cannot escape; what is unverified is the SEMANTICS — most sharply, that a step which never ran presents `steps.<id>.outcome` as `skipped` rather than as the empty string. If that reading is wrong, check 1's refusal case models a precedence GitHub does not implement, and every other case is unaffected because none of them turns on a skipped step. **Merge-time item 6 is what settles it**: the hosted `strict-refusal` job exercises exactly this path, and a demo run where the post-command steps behaved differently from the model is the signal to come back here.

**Check 1 carries its own presence control** — a GREEN drive asserted first, because four cases all asserting `result: 'failure'` would be satisfied by a model hard-wired to fail. Check 3's absence sweeps carry the same: the file walk asserts it found the state file and the staged evidence before asserting the launch token is in neither, and the stripped-variable loop asserts the run step's own process held all five before asserting the child holds none. **Check 1's refusal case proves the wrapped command never ran using a dump file the probe writes as its first act — absent under `strict`, PRESENT in the `best-effort` drive beside it.** That pairing is the control; without it the absence would be the vacuous-guard defect for the seventh time.

**Final-review evidence (item 15's loader, run and NOT committed, per the ruling at `:4326`):** `72` required = `66` ordinary + `3` named + `3` unnamed per-surface; `69` unnamed; `68` claims / `4` retired / `64` forbidden. The suite's own assertions carry `18` disclosure checks and `230` probes. The loader was deleted after the run.

---

## Plan self-review record (writing-plans checklist)

- **Spec coverage:** consumer surface → Task 6; lifecycle engine → Tasks 3–5; clean-by-construction artifact → Tasks 5–6 (state at root, enumerated uploads, containment tests); security invariants 1–6 → Tasks 3–7 (loopback bind, token scoping, env inheritance, shared escaping, pins/permissions, announced caps); renderer → Tasks 1–2; demo + integration decisions → Task 7 (forwarder list per amended spec; distinct display names cover self-exclusion); census → Task 2; docs → Task 8; testing strategy → every task + Task 9.
- **Known deliberate deviations from closeout conventions** (implementers: these are decisions, not oversights): no `stage-token` step (this action holds no GitHub token); state file at output-dir ROOT not inside the evidence child (it carries the launch token; closeout's state is secret-free and ships in its artifact — ours must not); `run` records outputs itself (closeout's gate step does the same via `steps.gate`).
- **Type consistency check:** `readState(outputDir)` everywhere (never evidenceDir — differs from closeout deliberately, documented in Task 3); state keys `{ nonce, pid, port, launchToken, projectRoot, sessionName, hypothesisId, hypothesisTitle, failOnCommandFailure, sessionId, sessionToken, commandExitCode, commandSignal, commandError, collectorAlive, evidenceCopied, reportRendered }` — grep any new reference against this list; report JSON key `session.events` feeds the `event-count` output.
- **Placeholder scan:** Task 8 Step 1 is a required-contents list for prose the implementer writes (not code) — every claim it requires is pinned by a Task 3–7 test; no TBD/TODO remains anywhere.
