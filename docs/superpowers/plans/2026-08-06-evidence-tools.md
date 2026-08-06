# Evidence Tools Implementation Plan (debug_evidence + debug_viewer + debug_diff)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship sub-project B: a zero-dependency shared evidence core (`scripts/debug_evidence.js`), the layout-C TUI + agent-mode viewer (`scripts/debug_viewer.js`), and the recorded-verdicts diff tool (`scripts/debug_diff.js`) with table/markdown/JSON renderers.

**Architecture:** One core owns reading (file + live GET), filtering (GET-parity guaranteed by test), and hypothesis folding; the two CLIs stay thin. TUI state transitions are pure reducers; only the ANSI painter is CI-exempt. Diff presents recorded verdicts and deterministic deltas only — no inference.

**Tech Stack:** Node.js ≥20, zero runtime dependencies, CommonJS, `node:test` via `node --test --test-concurrency=1`. New test files follow repo convention: `scripts/debug_evidence.test.js`, `scripts/debug_viewer.test.js`, `scripts/debug_diff.test.js`.

**Spec:** `docs/superpowers/specs/2026-08-06-evidence-tools-design.md` (approved, `76e10be`). Branch: `feat/evidence-tools` off `codex/publish-debug-skill` (`112a0de`).

**Conventions for every task:** strict TDD order; dense constraint-explaining comments (given in the code blocks); do NOT touch `scripts/debug_server.js` or its tests; do not push; commit messages end with the two required trailer lines exactly as shown.

---

### Task 1: Evidence core — file reading, filtering, folding, discovery

**Files:**
- Create: `scripts/debug_evidence.js`
- Create: `scripts/debug_evidence.test.js`

- [ ] **Step 1: Write the failing tests**

Create `scripts/debug_evidence.test.js`:

```js
const assert = require('node:assert/strict');
const { mkdtemp, mkdir, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  filterEntries,
  foldHypotheses,
  listSessions,
  parseSessionText,
  readSessionFile,
  resolveSessionRef,
} = require('./debug_evidence');

const line = (object) => `${JSON.stringify(object)}\n`;

const FIXTURE =
  line({ ts: '2026-08-06T10:00:01.000Z', msg: 'e1', hypothesisId: 'H1', runId: 'r1' })
  + line({ ts: '2026-08-06T10:00:02.000Z', msg: 'e2', hypothesisId: 'H2' })
  + line({ ts: '2026-08-06T10:00:03.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'OPEN', title: 'null id' })
  + line({ ts: '2026-08-06T10:00:04.000Z', msg: 'e3', runId: 'r2' })
  + line({ ts: '2026-08-06T10:00:05.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'CONFIRMED', note: 'proven' });

test('parseSessionText yields raw+parsed entries and drops nothing silently', () => {
  const entries = parseSessionText(FIXTURE);
  assert.equal(entries.length, 5);
  assert.equal(entries[0].parsed.msg, 'e1');
  assert.equal(entries[0].raw, JSON.stringify({ ts: '2026-08-06T10:00:01.000Z', msg: 'e1', hypothesisId: 'H1', runId: 'r1' }));
});

test('parseSessionText fails closed on a malformed line, naming the line number', () => {
  assert.throws(
    () => parseSessionText('{"ok":1}\nnot-json\n'),
    /malformed_session_line:2/,
  );
});

test('readSessionFile ignores an incomplete trailing line (torn tail)', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'evidence-'));
  try {
    const file = path.join(dir, 'debug-s1.log');
    await writeFile(file, `${FIXTURE}{"ts":"2026-08-06T10:00:06.000Z","msg":"torn`, 'utf8');
    const entries = await readSessionFile(file);
    assert.equal(entries.length, 5);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('filterEntries mirrors the GET route semantics', () => {
  const entries = parseSessionText(FIXTURE);
  assert.deepEqual(filterEntries(entries, {}).map((e) => e.parsed.msg ?? e.parsed.status), ['e1', 'e2', 'OPEN', 'e3', 'CONFIRMED']);
  assert.deepEqual(filterEntries(entries, { type: 'hypothesis' }).map((e) => e.parsed.status), ['OPEN', 'CONFIRMED']);
  assert.deepEqual(filterEntries(entries, { type: 'event' }).map((e) => e.parsed.msg), ['e1', 'e2', 'e3']);
  assert.deepEqual(filterEntries(entries, { hypothesisId: 'H1' }).map((e) => e.parsed.msg ?? e.parsed.status), ['e1', 'OPEN', 'CONFIRMED']);
  assert.deepEqual(filterEntries(entries, { runId: 'r2' }).map((e) => e.parsed.msg), ['e3']);
  assert.deepEqual(filterEntries(entries, { type: 'event', hypothesisId: 'H1' }).map((e) => e.parsed.msg), ['e1']);
  assert.deepEqual(filterEntries(entries, { limit: 2 }).map((e) => e.parsed.msg ?? e.parsed.status), ['e3', 'CONFIRMED']);
  assert.deepEqual(
    filterEntries(entries, { sinceTs: '2026-08-06T10:00:03.000Z' }).map((e) => e.parsed.msg ?? e.parsed.status),
    ['OPEN', 'e3', 'CONFIRMED'],
  );
  assert.deepEqual(
    filterEntries(entries, { untilTs: '2026-08-06T10:00:02.000Z' }).map((e) => e.parsed.msg),
    ['e1', 'e2'],
  );
});

test('filterEntries excludes NaN-ts lines only when a time filter is present', () => {
  const entries = parseSessionText(line({ msg: 'no-ts' }) + line({ ts: '2026-08-06T10:00:01.000Z', msg: 'ok' }));
  assert.equal(filterEntries(entries, {}).length, 2);
  assert.deepEqual(filterEntries(entries, { sinceTs: '2026-08-06T09:00:00.000Z' }).map((e) => e.parsed.msg), ['ok']);
});

test('filterEntries treats unknown future types as matching only all', () => {
  const entries = parseSessionText(line({ ts: '2026-08-06T10:00:01.000Z', type: 'future-kind', x: 1 }));
  assert.equal(filterEntries(entries, {}).length, 1);
  assert.equal(filterEntries(entries, { type: 'event' }).length, 0);
  assert.equal(filterEntries(entries, { type: 'hypothesis' }).length, 0);
});

test('filterEntries rejects unknown filter keys fail-closed', () => {
  const entries = parseSessionText(FIXTURE);
  assert.throws(() => filterEntries(entries, { surprise: 1 }), /invalid_filter/);
  assert.throws(() => filterEntries(entries, { type: 'bogus' }), /invalid_filter/);
  assert.throws(() => filterEntries(entries, { sinceTs: 'notadate' }), /invalid_filter/);
  assert.throws(() => filterEntries(entries, { limit: 0 }), /invalid_filter/);
});

test('filterEntries trims hypothesisId/runId filter values, mirroring the GET route\'s query.get(name)?.trim()', () => {
  const entries = parseSessionText(FIXTURE);
  assert.deepEqual(
    filterEntries(entries, { hypothesisId: '  H1  ' }).map((e) => e.parsed.msg ?? e.parsed.status),
    ['e1', 'OPEN', 'CONFIRMED'],
  );
  assert.deepEqual(filterEntries(entries, { runId: '  r2  ' }).map((e) => e.parsed.msg), ['e3']);
});

test('filterEntries rejects non-string hypothesisId/runId fail-closed like every other filter', () => {
  const entries = parseSessionText(FIXTURE);
  assert.throws(() => filterEntries(entries, { hypothesisId: 42 }), /invalid_filter:hypothesisId/);
  assert.throws(() => filterEntries(entries, { runId: 42 }), /invalid_filter:runId/);
});

test('filterEntries treats an empty-or-whitespace-only hypothesisId/runId as a real filter matching nothing, mirroring the route (never absent, never an error)', () => {
  const entries = parseSessionText(FIXTURE);
  assert.equal(filterEntries(entries, { hypothesisId: '   ' }).length, 0);
  assert.equal(filterEntries(entries, { runId: '' }).length, 0);
});

test('foldHypotheses derives latest-wins state with first-title retention and history', () => {
  const folded = foldHypotheses(parseSessionText(FIXTURE));
  assert.equal(folded.size, 1);
  const h1 = folded.get('H1');
  assert.equal(h1.status, 'CONFIRMED');
  assert.equal(h1.title, 'null id');
  assert.equal(h1.note, 'proven');
  assert.equal(h1.ts, '2026-08-06T10:00:05.000Z');
  assert.deepEqual(h1.history.map((entry) => entry.status), ['OPEN', 'CONFIRMED']);
});

test('foldHypotheses keeps file order as the tiebreak for same-millisecond lines', () => {
  const sameMs =
    line({ ts: '2026-08-06T10:00:01.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'OPEN' })
    + line({ ts: '2026-08-06T10:00:01.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'REJECTED' });
  assert.equal(foldHypotheses(parseSessionText(sameMs)).get('H1').status, 'REJECTED');
});

test('listSessions and resolveSessionRef enumerate and resolve .debug logs', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'evidence-'));
  try {
    await mkdir(path.join(root, '.debug'));
    await writeFile(path.join(root, '.debug', 'debug-alpha-1.log'), FIXTURE, 'utf8');
    await writeFile(path.join(root, '.debug', 'debug-beta-2.log'), '', 'utf8');
    await writeFile(path.join(root, '.debug', 'collector_token'), 'tok', 'utf8');
    const sessions = await listSessions(root);
    assert.deepEqual(sessions.map((s) => s.sessionId).sort(), ['alpha-1', 'beta-2']);
    assert.equal(resolveSessionRef(root, 'alpha-1'), path.join(root, '.debug', 'debug-alpha-1.log'));
    const direct = path.join(root, '.debug', 'debug-beta-2.log');
    assert.equal(resolveSessionRef(root, direct), direct);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('resolveSessionRef rejects path-traversal-shaped bare session ids fail-closed', () => {
  const root = path.join(tmpdir(), 'evidence-fixed-root');
  assert.throws(() => resolveSessionRef(root, '../../../etc/passwd'), /invalid_session_ref/);
  assert.throws(() => resolveSessionRef(root, 'x/../y'), /invalid_session_ref/);
  assert.equal(resolveSessionRef(root, 'alpha-1'), path.join(root, '.debug', 'debug-alpha-1.log'));
});

test('listSessions returns an empty array when the project has no .debug directory yet', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'evidence-'));
  try {
    assert.deepEqual(await listSessions(root), []);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test --test-concurrency=1 scripts/debug_evidence.test.js`
Expected: FAIL — `Cannot find module './debug_evidence'`.

- [ ] **Step 3: Implement `scripts/debug_evidence.js`**

```js
// Shared evidence core for debug_viewer.js and debug_diff.js (spec:
// docs/superpowers/specs/2026-08-06-evidence-tools-design.md). One module
// owns reading, filtering, and hypothesis folding so the two CLIs and the
// collector's GET /sessions/:id/logs route can never drift apart — the
// filter semantics here are asserted IDENTICAL to the route by a parity
// test in debug_evidence.test.js. Zero runtime dependencies.
const { readFile, readdir } = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');

// Parse complete NDJSON text into ordered { raw, parsed } entries. `raw` is
// preserved byte-for-byte so agent mode can re-emit stored lines verbatim.
// A malformed line fails closed with its 1-based line number — session logs
// are written exclusively by the collector, so a parse failure means the
// file was tampered with or truncated mid-line, and skipping it silently
// would present partial evidence as complete.
const parseSessionText = (text) => {
  const entries = [];
  let lineNumber = 0;
  for (const raw of text.split('\n')) {
    lineNumber += 1;
    if (!raw) continue;
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`malformed_session_line:${lineNumber}`);
    }
    entries.push({ raw, parsed });
  }
  return entries;
};

// Read a session log from disk. The collector terminates every persisted
// line with \n, so anything after the final newline is a torn tail from an
// in-flight append — dropped here exactly like the GET route's
// bytesWritten-bounded read never emits it.
const readSessionFile = async (filePath) => {
  const text = await readFile(filePath, 'utf8');
  const lastNewline = text.lastIndexOf('\n');
  return parseSessionText(lastNewline === -1 ? '' : text.slice(0, lastNewline + 1));
};

const FILTER_KEYS = new Set(['hypothesisId', 'type', 'sinceTs', 'untilTs', 'runId', 'limit']);
const TYPE_VALUES = new Set(['all', 'event', 'hypothesis']);

// Filter semantics MUST mirror GET /sessions/:id/logs exactly (enforced by
// the parity test): unknown keys and malformed values fail closed; `type`
// classifies lines WITHOUT a type field as events and unknown future types
// match only 'all'; time bounds are inclusive Date.parse comparisons and
// NaN-ts lines are excluded only while a time filter is active; `limit`
// keeps the LAST n matches (tail-biased). hypothesisId/runId semantics are
// documented at normalizeJoinKeyFilter below.
const filterEntries = (entries, filters = {}) => {
  for (const key of Object.keys(filters)) {
    if (!FILTER_KEYS.has(key)) throw new Error(`invalid_filter:${key}`);
  }
  const type = filters.type ?? 'all';
  if (!TYPE_VALUES.has(type)) throw new Error('invalid_filter:type');
  const parseBound = (name) => {
    if (filters[name] === undefined) return undefined;
    const parsed = Date.parse(filters[name]);
    if (Number.isNaN(parsed)) throw new Error(`invalid_filter:${name}`);
    return parsed;
  };
  const sinceTs = parseBound('sinceTs');
  const untilTs = parseBound('untilTs');
  let limit;
  if (filters.limit !== undefined) {
    if (!Number.isInteger(filters.limit) || filters.limit < 1) throw new Error('invalid_filter:limit');
    limit = filters.limit;
  }
  // Mirrors the route's `query.get(name)?.trim() ?? undefined` EXACTLY: the
  // collector also trims these join keys at write time (POST /log), so a
  // caller-supplied value must be trimmed the same way or padded input would
  // silently fail to match. Only `undefined` means "no filter" — a value
  // that is empty or whitespace-only AFTER trimming is still a real filter
  // (for the empty string) that matches nothing, because the collector
  // rejects empty join keys at ingestion (invalid_join_key) so no stored
  // line ever has one; this mirrors the route rather than treating blank
  // input as absent or raising an error. Unlike the URL route — where
  // URLSearchParams.get always yields a string — this module's filters are
  // arbitrary JS values, so a non-string hypothesisId/runId has no route
  // analog and fails closed like every other malformed filter instead of
  // silently never matching.
  const normalizeJoinKeyFilter = (name) => {
    const value = filters[name];
    if (value === undefined) return undefined;
    if (typeof value !== 'string') throw new Error(`invalid_filter:${name}`);
    return value.trim();
  };
  const hypothesisIdFilter = normalizeJoinKeyFilter('hypothesisId');
  const runIdFilter = normalizeJoinKeyFilter('runId');
  const matched = entries.filter(({ parsed }) => {
    const lineType = parsed.type === undefined ? 'event' : parsed.type;
    if (type !== 'all' && lineType !== type) return false;
    if (hypothesisIdFilter !== undefined && parsed.hypothesisId !== hypothesisIdFilter) return false;
    if (runIdFilter !== undefined && parsed.runId !== runIdFilter) return false;
    if (sinceTs !== undefined || untilTs !== undefined) {
      const lineTs = Date.parse(parsed.ts);
      if (Number.isNaN(lineTs)) return false;
      if (sinceTs !== undefined && lineTs < sinceTs) return false;
      if (untilTs !== undefined && lineTs > untilTs) return false;
    }
    return true;
  });
  return limit === undefined ? matched : matched.slice(-limit);
};

// Derive per-hypothesis state from lifecycle lines: latest line wins for
// status/note/ts (file order is the tiebreak for same-millisecond lines —
// guaranteed by the collector's per-session append chain), the FIRST
// non-empty title is retained (later status flips rarely restate it), and
// the full ordered history is preserved for audit.
const foldHypotheses = (entries) => {
  const folded = new Map();
  for (const { parsed } of entries) {
    if (parsed.type !== 'hypothesis') continue;
    const existing = folded.get(parsed.hypothesisId);
    const record = existing ?? {
      hypothesisId: parsed.hypothesisId,
      title: undefined,
      status: undefined,
      note: undefined,
      ts: undefined,
      history: [],
    };
    record.status = parsed.status;
    record.note = parsed.note;
    record.ts = parsed.ts;
    if (record.title === undefined && typeof parsed.title === 'string' && parsed.title !== '') {
      record.title = parsed.title;
    }
    record.history.push(parsed);
    if (!existing) folded.set(parsed.hypothesisId, record);
  }
  return folded;
};

const SESSION_FILE_PATTERN = /^debug-(.+)\.log$/;
// Mirrors the route's path segment pattern (GET /sessions/:id/logs matches
// `/^\/sessions\/([A-Za-z0-9_-]+)\/logs$/`) — the same documented security
// control applies here: a bare id is interpolated into a filesystem path
// below, so it must be constrained to a safe character set or a value like
// `../../../etc/passwd` would escape the .debug directory entirely.
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]+$/;

// Enumerate session logs under <projectRoot>/.debug. A project that has
// never run a debug session has no .debug directory yet — that is normal,
// not an error, so ENOENT yields an empty list; any other readdir failure
// (permissions, not-a-directory, ...) still propagates.
const listSessions = async (projectRoot) => {
  let names;
  try {
    names = await readdir(path.join(projectRoot, '.debug'));
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  const sessions = [];
  for (const name of names) {
    const match = name.match(SESSION_FILE_PATTERN);
    if (match) sessions.push({ sessionId: match[1], filePath: path.join(projectRoot, '.debug', name) });
  }
  return sessions;
};

// A ref is either a direct path to a .log file (passed through as-is — an
// explicit file path supplied by the caller, e.g. from listSessions) or a
// bare session id, which MUST match SESSION_ID_PATTERN before being
// interpolated into a path: unlike the .log passthrough, a bare id is
// untrusted input (e.g. a CLI argument) and would otherwise reach path.join
// unvalidated — `debug-../../..` would escape the .debug directory.
const resolveSessionRef = (projectRoot, ref) => {
  if (ref.endsWith('.log')) return ref;
  if (!SESSION_ID_PATTERN.test(ref)) throw new Error(`invalid_session_ref:${ref}`);
  return path.join(projectRoot, '.debug', `debug-${ref}.log`);
};

module.exports = {
  filterEntries,
  foldHypotheses,
  listSessions,
  parseSessionText,
  readSessionFile,
  resolveSessionRef,
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test --test-concurrency=1 scripts/debug_evidence.test.js`
Expected: 15/15 pass. `node --check scripts/debug_evidence.js` clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/debug_evidence.js scripts/debug_evidence.test.js
git commit -m "feat(tools): evidence core — parse, filter, fold, discover

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 2: Evidence core — live reader, poll-by-count tail, GET-parity test

**Files:**
- Modify: `scripts/debug_evidence.js` (append live functions + exports)
- Modify: `scripts/debug_evidence.test.js` (append; requires `createDebugServer` from `./debug_server`)

- [ ] **Step 1: Write the failing tests**

Append to `scripts/debug_evidence.test.js`:

```js
const { createDebugServer } = require('./debug_server');
const {
  createSessionTail,
  discoverCollector,
  readSessionLive,
} = require('./debug_evidence');

const LAUNCH = 'evidence-test-launch-token-with-entropy';

const listen = (server) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => resolve(server.address().port));
});

const close = (server) => new Promise((resolve, reject) => {
  server.close((error) => (error ? reject(error) : resolve()));
});

const httpJson = (port, pathname, { method = 'GET', headers = {}, body } = {}) =>
  new Promise((resolve, reject) => {
    const request = http.request({ hostname: '127.0.0.1', port, path: pathname, method, headers }, (response) => {
      let text = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { text += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, text }));
    });
    request.on('error', reject);
    if (body !== undefined) request.write(JSON.stringify(body));
    request.end();
  });

const http = require('node:http');

const withLiveSession = async (run) => {
  const root = await mkdtemp(path.join(tmpdir(), 'evidence-live-'));
  const server = createDebugServer({ projectRoot: root, token: LAUNCH, redactionEnv: {} });
  const port = await listen(server);
  try {
    const minted = await httpJson(port, '/session', {
      method: 'POST',
      headers: { Authorization: `Bearer ${LAUNCH}` },
      body: { name: 'live' },
    });
    const session = JSON.parse(minted.text);
    const log = (msg, extra = {}) => httpJson(port, '/log', {
      method: 'POST',
      body: { sessionId: session.session_id, sessionToken: session.session_token, msg, ...extra },
    });
    return await run({ root, port, session, log });
  } finally {
    await close(server);
    await rm(root, { recursive: true, force: true });
  }
};

test('readSessionLive matches filterEntries over the same data (GET parity)', async () => {
  await withLiveSession(async ({ root, port, session, log }) => {
    await log('e1', { hypothesisId: 'H1', runId: 'r1' });
    await log('e2', { hypothesisId: 'H2' });
    await httpJson(port, '/hypothesis', {
      method: 'POST',
      headers: { Authorization: `Bearer ${LAUNCH}` },
      body: { sessionId: session.session_id, hypothesisId: 'H1', status: 'OPEN' },
    });
    await log('e3', { runId: 'r2' });
    const filePath = path.join(root, session.log_file);
    const fileEntries = await readSessionFile(filePath);
    for (const filters of [
      {},
      { type: 'hypothesis' },
      { type: 'event' },
      { hypothesisId: 'H1' },
      { runId: 'r2' },
      { type: 'event', hypothesisId: 'H1' },
      { limit: 2 },
      // Padded values: the route trims query values before comparing; the
      // core must too. Clean fixtures alone cannot detect trim divergence.
      { hypothesisId: '  H1  ' },
      { runId: '  r2  ' },
    ]) {
      const live = await readSessionLive({ port, token: LAUNCH, sessionId: session.session_id, filters });
      const local = filterEntries(fileEntries, filters);
      assert.deepEqual(live.map((e) => e.raw), local.map((e) => e.raw), JSON.stringify(filters));
    }
  });
});

test('readSessionLive surfaces structured errors for 401 and 404', async () => {
  await withLiveSession(async ({ port, session }) => {
    await assert.rejects(
      () => readSessionLive({ port, token: 'wrong-token-entirely', sessionId: session.session_id }),
      /live_read_unauthorized/,
    );
    await assert.rejects(
      () => readSessionLive({ port, token: LAUNCH, sessionId: 'debug-nope-000000000000' }),
      /live_read_unknown_session/,
    );
  });
});

test('createSessionTail emits each entry exactly once across polls', async () => {
  await withLiveSession(async ({ port, session, log }) => {
    await log('a');
    const tail = createSessionTail({ port, token: LAUNCH, sessionId: session.session_id });
    const first = await tail.poll();
    assert.deepEqual(first.map((e) => e.parsed.msg), ['a']);
    await log('b');
    await log('c');
    const second = await tail.poll();
    assert.deepEqual(second.map((e) => e.parsed.msg), ['b', 'c']);
    const third = await tail.poll();
    assert.deepEqual(third, []);
  });
});

test('discoverCollector reads port and token from .debug', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'evidence-disc-'));
  try {
    await mkdir(path.join(root, '.debug'), { recursive: true });
    await writeFile(path.join(root, '.debug', 'collector_port'), '8787\n', 'utf8');
    await writeFile(path.join(root, '.debug', 'collector_token'), 'tok-value\n', 'utf8');
    assert.deepEqual(await discoverCollector(root), { port: 8787, token: 'tok-value' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('readSessionLive rejects a session id that would escape the /sessions/:id/logs path before making any request', async () => {
  await assert.rejects(
    () => readSessionLive({ port: 1, token: LAUNCH, sessionId: '../health?' }),
    /invalid_session_ref/,
  );
  await assert.rejects(
    () => readSessionLive({ port: 1, token: LAUNCH, sessionId: 'a b' }),
    /invalid_session_ref/,
  );
});

test('readSessionLive rejects live_read_timeout when the collector never responds', async () => {
  const server = http.createServer(() => {
    // Deliberately never write a response — simulates a hung collector.
  });
  const port = await listen(server);
  try {
    await assert.rejects(
      () => readSessionLive({ port, token: LAUNCH, sessionId: 'hang-session-1', timeoutMs: 50 }),
      /live_read_timeout/,
    );
  } finally {
    await close(server);
  }
});

test('readSessionLive rejects live_read_interrupted when the connection dies mid-body', async () => {
  const server = http.createServer((request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Content-Length': '4096' });
    response.write('{"ts":"2026-08-06T10:00:00.000Z","msg":"partial"}\n');
    // Destroy the socket mid-body: the client must surface a structured
    // live_read_* code, never a raw 'aborted'/ECONNRESET.
    setTimeout(() => response.destroy(), 10);
  });
  const port = await listen(server);
  try {
    await assert.rejects(
      () => readSessionLive({ port, token: LAUNCH, sessionId: 'interrupt-session-1' }),
      /live_read_interrupted/,
    );
  } finally {
    await close(server);
  }
});

test('createSessionTail forwards timeoutMs to each poll', async () => {
  const server = http.createServer(() => {
    // Never respond: without forwarding, the tail would use the 5s default
    // and this test would exceed its own runtime budget.
  });
  const port = await listen(server);
  try {
    const tail = createSessionTail({ port, token: LAUNCH, sessionId: 'hang-session-2', timeoutMs: 50 });
    await assert.rejects(() => tail.poll(), /live_read_timeout/);
  } finally {
    await close(server);
  }
});

test('readSessionLive rejects non-string hypothesisId/runId filters before making any request, mirroring filterEntries', async () => {
  await assert.rejects(
    () => readSessionLive({ port: 1, token: LAUNCH, sessionId: 'valid-session-1', filters: { hypothesisId: 42 } }),
    /invalid_filter:hypothesisId/,
  );
  await assert.rejects(
    () => readSessionLive({ port: 1, token: LAUNCH, sessionId: 'valid-session-1', filters: { runId: null } }),
    /invalid_filter:runId/,
  );
});

test('discoverCollector rejects collector_not_running when .debug connection files are missing', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'evidence-disc-missing-'));
  try {
    await assert.rejects(() => discoverCollector(root), /collector_not_running/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('discoverCollector rejects collector_token_invalid for an empty or whitespace-only token file', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'evidence-disc-badtoken-'));
  try {
    await mkdir(path.join(root, '.debug'), { recursive: true });
    await writeFile(path.join(root, '.debug', 'collector_port'), '8787\n', 'utf8');
    await writeFile(path.join(root, '.debug', 'collector_token'), '   \n', 'utf8');
    await assert.rejects(() => discoverCollector(root), /collector_token_invalid/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('discoverCollector rejects collector_port_invalid for a non-decimal-integer port string like scientific notation', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'evidence-disc-badport-'));
  try {
    await mkdir(path.join(root, '.debug'), { recursive: true });
    await writeFile(path.join(root, '.debug', 'collector_port'), '1e4\n', 'utf8');
    await writeFile(path.join(root, '.debug', 'collector_token'), 'tok-value\n', 'utf8');
    await assert.rejects(() => discoverCollector(root), /collector_port_invalid/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
```

NOTE: place the `const http = require('node:http');` line with the OTHER requires at the top of the test file (the block above shows it mid-file only to keep the diff excerpt together — hoist it when appending).

- [ ] **Step 2: Run to verify failures**

Run: `node --test --test-concurrency=1 scripts/debug_evidence.test.js`
Expected: the ten new tests fail (`readSessionLive`/`createSessionTail`/`discoverCollector` are not exported); Task 1's tests still pass.

- [ ] **Step 3: Implement (append to `scripts/debug_evidence.js`)**

This step also promotes `normalizeJoinKeyFilter` out of `filterEntries`'s
closure (added in Task 1) to module scope — behavior unchanged, now takes
`(filters, name)` instead of closing over `filters` — so `readSessionLive`
below can reuse the exact same validation instead of re-implementing it.
Insert it immediately above `filterEntries`:

```js
// Mirrors the route's `query.get(name)?.trim() ?? undefined` EXACTLY: the
// collector also trims these join keys at write time (POST /log), so a
// caller-supplied value must be trimmed the same way or padded input would
// silently fail to match. Only `undefined` means "no filter" — a value
// that is empty or whitespace-only AFTER trimming is still a real filter
// (for the empty string) that matches nothing, because the collector
// rejects empty join keys at ingestion (invalid_join_key) so no stored
// line ever has one; this mirrors the route rather than treating blank
// input as absent or raising an error. Unlike the URL route — where
// URLSearchParams.get always yields a string — this module's filters are
// arbitrary JS values, so a non-string hypothesisId/runId has no route
// analog and fails closed like every other malformed filter instead of
// silently never matching. Shared by filterEntries (local reads) and
// readSessionLive (live reads, applied before serializing into the query
// string) so the two paths cannot diverge on what counts as a valid
// join-key filter.
const normalizeJoinKeyFilter = (filters, name) => {
  const value = filters[name];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw new Error(`invalid_filter:${name}`);
  return value.trim();
};
```

Inside `filterEntries`, delete the old closure-local `normalizeJoinKeyFilter`
definition, change its doc comment's closing line to "documented at
normalizeJoinKeyFilter above", and change the two call sites to:

```js
  const hypothesisIdFilter = normalizeJoinKeyFilter(filters, 'hypothesisId');
  const runIdFilter = normalizeJoinKeyFilter(filters, 'runId');
```

Then append the live-read functions after `resolveSessionRef`:

```js
// Fetch a live session's filtered lines from the local collector. Filters
// are passed through to the GET route as query parameters — the server
// applies the SAME semantics filterEntries implements locally (parity test
// enforced). Errors surface as distinct codes, never swallowed: evidence
// integrity failures (409) and auth/liveness failures are actionable.
const readSessionLive = ({ port, token, sessionId, filters = {}, timeoutMs = 5000 }) => new Promise((resolve, reject) => {
  // Pre-flight, before any request setup: sessionId is interpolated
  // directly into the request path below. Mirrors resolveSessionRef's
  // bare-id guard (SESSION_ID_PATTERN, defined above) — sessionId here is
  // frequently network-sourced (e.g. from a prior /session response), and
  // without this check a value like '../health?' would escape the
  // /sessions/:id/logs route entirely, while one containing a space would
  // throw an unfiltered Node "unescaped characters" error instead of a
  // structured, catchable one. (This is a distinct guard from
  // resolveSessionRef itself — that function's .log-path passthrough branch
  // must never see a network-sourced id; this function never calls it.)
  if (!SESSION_ID_PATTERN.test(sessionId)) {
    reject(new Error(`invalid_session_ref:${sessionId}`));
    return;
  }
  // hypothesisId/runId must be validated and trimmed through the SAME
  // normalizeJoinKeyFilter helper filterEntries uses, before being
  // serialized into the query string. Without this, a non-string value
  // (e.g. 42) would silently become the query string "42" — zero matches,
  // live — while the local path throws invalid_filter:hypothesisId: a
  // parity break the parity test itself cannot generate, since it only
  // ever feeds clean fixtures through both paths. Other filter keys
  // (type/sinceTs/untilTs/limit) keep the plain String() passthrough below;
  // the route already validates those server-side.
  let hypothesisIdFilter;
  let runIdFilter;
  try {
    hypothesisIdFilter = normalizeJoinKeyFilter(filters, 'hypothesisId');
    runIdFilter = normalizeJoinKeyFilter(filters, 'runId');
  } catch (error) {
    reject(error);
    return;
  }
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (key === 'hypothesisId' || key === 'runId') continue;
    if (value !== undefined) query.set(key, String(value));
  }
  if (hypothesisIdFilter !== undefined) query.set('hypothesisId', hypothesisIdFilter);
  if (runIdFilter !== undefined) query.set('runId', runIdFilter);
  const suffix = query.size > 0 ? `?${query.toString()}` : '';
  const request = http.request({
    hostname: '127.0.0.1',
    port,
    path: `/sessions/${sessionId}/logs${suffix}`,
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` },
  }, (response) => {
    let text = '';
    response.setEncoding('utf8');
    response.on('data', (chunk) => { text += chunk; });
    // A connection that dies mid-body must carry a structured code like
    // every other failure path here — callers match /^live_read_/, and a
    // raw 'aborted'/ECONNRESET would slip past that discipline.
    response.on('error', () => reject(new Error('live_read_interrupted')));
    response.on('end', () => {
      if (response.statusCode === 200) {
        try {
          resolve(parseSessionText(text));
        } catch (error) {
          reject(error);
        }
        return;
      }
      if (response.statusCode === 401) reject(new Error('live_read_unauthorized'));
      else if (response.statusCode === 404) reject(new Error('live_read_unknown_session'));
      else if (response.statusCode === 409) reject(new Error('live_read_log_replaced'));
      else reject(new Error(`live_read_failed:${response.statusCode}`));
    });
  });
  request.on('error', reject);
  // A collector that accepts the connection and never responds (or dies
  // mid-body) would otherwise hang this promise forever — the worst case
  // for createSessionTail below, a silent freeze with no error surfaced.
  // destroy(error) routes through the 'error' handler above.
  request.setTimeout(timeoutMs, () => request.destroy(new Error('live_read_timeout')));
  request.end();
});

// Poll-by-count live tail: every poll re-fetches the full (filter-free)
// line set and emits only entries beyond the count already seen. Counting
// is immune to same-millisecond timestamps and needs no cursor state on the
// server. Filters are applied by the CALLER over the emitted entries so the
// seen-count always refers to the unfiltered stream.
// Accepted cost model: readSessionLive has no cursor/offset support, so
// each poll re-downloads the ENTIRE unfiltered log — O(session size), not
// O(new entries) — bounded in practice by the collector's maxTotalBytes cap
// on session size and now by readSessionLive's timeoutMs on any single
// poll. Task 3/4 choose their poll interval knowing this cost rather than
// polling aggressively.
const createSessionTail = ({ port, token, sessionId, timeoutMs }) => {
  let seen = 0;
  return {
    async poll() {
      const entries = await readSessionLive({ port, token, sessionId, timeoutMs });
      const fresh = entries.slice(seen);
      seen = entries.length;
      return fresh;
    },
  };
};

// Read the local collector's connection material persisted by its CLI:
// .debug/collector_port and .debug/collector_token. Fails closed with
// structured errors rather than propagating raw fs/parsing errors: a
// missing file means the collector plainly isn't running (a normal state,
// not a bug), while a present-but-garbled file is corruption a caller
// should be able to distinguish from "not running".
const discoverCollector = async (projectRoot) => {
  const debugDir = path.join(projectRoot, '.debug');
  let portText;
  let tokenText;
  try {
    [portText, tokenText] = await Promise.all([
      readFile(path.join(debugDir, 'collector_port'), 'utf8'),
      readFile(path.join(debugDir, 'collector_token'), 'utf8'),
    ]);
  } catch (error) {
    if (error?.code === 'ENOENT') throw new Error('collector_not_running');
    throw error;
  }
  const trimmedPort = portText.trim();
  // Require a plain decimal-integer string: Number() alone also accepts
  // hex ('0x10'), scientific notation ('1e4'), leading '+', etc. — none of
  // which collector_port ever legitimately contains, since the collector
  // writes it with a plain String(port).
  if (!/^\d+$/.test(trimmedPort)) throw new Error('collector_port_invalid');
  const port = Number(trimmedPort);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('collector_port_invalid');
  const token = tokenText.trim();
  if (token === '') throw new Error('collector_token_invalid');
  return { port, token };
};
```

Extend `module.exports` with `createSessionTail`, `discoverCollector`, `readSessionLive` (alphabetical).

- [ ] **Step 4: Verify green**

Run: `node --test --test-concurrency=1 scripts/debug_evidence.test.js` — 27/27 pass (15 from Task 1 + 12 new). `node --check scripts/debug_evidence.js` clean. Also confirm the collector suite is untouched: `git status` shows only the two evidence files modified.

- [ ] **Step 5: Commit**

```bash
git add scripts/debug_evidence.js scripts/debug_evidence.test.js
git commit -m "feat(tools): evidence core live reads with GET-parity guarantee

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 3: debug_viewer — CLI parsing, agent mode, pure reducers

**Files:**
- Create: `scripts/debug_viewer.js`
- Create: `scripts/debug_viewer.test.js`

- [ ] **Step 1: Write the failing tests**

Create `scripts/debug_viewer.test.js`:

```js
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { mkdtemp, mkdir, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { createInitialState, parseViewerArgs, reduce } = require('./debug_viewer');

const VIEWER = path.join(__dirname, 'debug_viewer.js');

const runViewer = (args, options = {}) => new Promise((resolve) => {
  execFile(process.execPath, [VIEWER, ...args], options, (error, stdout, stderr) => {
    resolve({ code: error ? error.code : 0, stdout, stderr });
  });
});

const line = (object) => `${JSON.stringify(object)}\n`;

const seedRoot = async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'viewer-'));
  await mkdir(path.join(root, '.debug'));
  const fixture =
    line({ ts: '2026-08-06T10:00:01.000Z', msg: 'e1', hypothesisId: 'H1' })
    + line({ ts: '2026-08-06T10:00:02.000Z', msg: 'e2', hypothesisId: 'H2' })
    + line({ ts: '2026-08-06T10:00:03.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'CONFIRMED', title: 't' });
  await writeFile(path.join(root, '.debug', 'debug-s1.log'), fixture, 'utf8');
  return { root, fixture };
};

test('parseViewerArgs maps flags to filters and modes', () => {
  const parsed = parseViewerArgs(['C:/proj', '--session', 's1', '--hypothesis', 'H1', '--type', 'event', '--limit', '5', '--json']);
  assert.equal(parsed.projectRoot, 'C:/proj');
  assert.equal(parsed.session, 's1');
  assert.deepEqual(parsed.filters, { hypothesisId: 'H1', type: 'event', limit: 5 });
  assert.equal(parsed.agentMode, true);
  assert.equal(parseViewerArgs(['--session', 's1']).projectRoot, process.cwd());
});

test('parseViewerArgs fails closed on unknown flags and bad values', () => {
  assert.throws(() => parseViewerArgs(['--surprise']), /viewer_usage/);
  assert.throws(() => parseViewerArgs(['--session', 's1', '--limit', 'abc']), /viewer_usage/);
  assert.throws(() => parseViewerArgs(['--session', 's1', '--type', 'bogus']), /viewer_usage/);
});

test('agent mode emits the selected raw lines verbatim and exits 0', async () => {
  const { root, fixture } = await seedRoot();
  try {
    const all = await runViewer([root, '--session', 's1', '--json']);
    assert.equal(all.code, 0);
    assert.equal(all.stdout, fixture);
    const filtered = await runViewer([root, '--session', 's1', '--hypothesis', 'H1', '--type', 'event', '--json']);
    assert.equal(filtered.stdout, fixture.split('\n')[0] + '\n');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('agent mode without --session is a usage error, exit 2', async () => {
  const { root } = await seedRoot();
  try {
    const result = await runViewer([root, '--json']);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /--session/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('agent mode is auto-selected when stdout is not a TTY', async () => {
  const { root, fixture } = await seedRoot();
  try {
    // execFile pipes stdout (not a TTY), so no --json flag is needed.
    const result = await runViewer([root, '--session', 's1']);
    assert.equal(result.code, 0);
    assert.equal(result.stdout, fixture);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('runtime errors (e.g. a mistyped session id) are reported as one clean line, exit 1', async () => {
  const { root } = await seedRoot();
  try {
    const result = await runViewer([root, '--session', 'doesnotexist', '--json']);
    assert.equal(result.code, 1);
    const stderrLines = result.stderr.split('\n').filter(Boolean);
    assert.equal(stderrLines.length, 1);
    assert.doesNotMatch(result.stderr, /\bat /);
    assert.doesNotMatch(result.stderr, /Node\.js v/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('agent mode rejects --live as not wired until Task 4, exit 2', async () => {
  const { root } = await seedRoot();
  try {
    const result = await runViewer([root, '--session', 's1', '--live', '--json']);
    assert.equal(result.code, 2);
    assert.match(result.stderr, /--live is not wired yet/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('parseViewerArgs rejects a flag passed twice (GET-route parity)', () => {
  assert.throws(
    () => parseViewerArgs(['--session', 's1', '--session', 's2']),
    /viewer_usage:duplicate flag --session/,
  );
});

test('parseViewerArgs rejects --flag=value syntax with a specific message', () => {
  assert.throws(
    () => parseViewerArgs(['--session=s1']),
    /viewer_usage:--session takes a space-separated value/,
  );
});

test('parseViewerArgs rejects a value-taking flag whose next token is another flag', () => {
  assert.throws(
    () => parseViewerArgs(['--session', '--json']),
    /viewer_usage:missing value for --session/,
  );
});

test('reducers: filter entry, focus toggle, pause, and quit are pure transitions', () => {
  let state = createInitialState({ sessionId: 's1' });
  assert.equal(state.focus, 'stream');
  state = reduce(state, { name: 'tab' });
  assert.equal(state.focus, 'table');
  state = reduce(state, { name: 'space' });
  assert.equal(state.paused, true);
  state = reduce(state, { name: 'f' });
  assert.equal(state.mode, 'filter-input');
  state = reduce(state, { name: 'h', sequence: 'h' });
  assert.equal(state.filterDraft, 'h');
  state = reduce(state, { name: 'return' });
  assert.equal(state.mode, 'normal');
  state = reduce(state, { name: 'q' });
  assert.equal(state.quit, true);
});

test('reduce ignores nullish or shapeless key input, returning the same state reference', () => {
  const state = createInitialState({ sessionId: 's1' });
  assert.equal(reduce(state, undefined), state);
  assert.equal(reduce(state, null), state);
});

test('reduce appends a multi-byte (surrogate-pair) sequence to the filter draft as one unit', () => {
  let state = createInitialState({ sessionId: 's1' });
  state = reduce(state, { name: 'f' });
  state = reduce(state, { name: undefined, sequence: '\u{1F600}' });
  assert.equal(state.filterDraft, '\u{1F600}');
});

test('backspace removes a whole surrogate-pair character, never leaving a lone surrogate', () => {
  let state = createInitialState({ sessionId: 's1' });
  state = reduce(state, { name: 'f' });
  state = reduce(state, { name: undefined, sequence: 'a' });
  state = reduce(state, { name: undefined, sequence: '\u{1F600}' });
  state = reduce(state, { name: 'backspace' });
  assert.equal(state.filterDraft, 'a');
  assert.equal(state.filterDraft.isWellFormed(), true);
});
```

- [ ] **Step 2: Run to verify failures**

Run: `node --test --test-concurrency=1 scripts/debug_viewer.test.js`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `scripts/debug_viewer.js`** (agent mode + reducers now; the TUI painter/loop lands in Task 4 — `main()` prints a clear "TUI arrives in Task 4" error and exits 3 when a real TTY would enter TUI mode, so this commit stays honest)

```js
// Layout-C TUI + agent-mode session viewer (spec:
// docs/superpowers/specs/2026-08-06-evidence-tools-design.md). Mode rule:
// stdout TTY -> TUI; otherwise (or --json/--plain) -> agent mode, which
// applies the shared filter engine and re-emits the selected RAW stored
// lines byte-for-byte. Zero dependencies; all interactive state changes are
// pure reducers so they can be unit-tested without a terminal.
const path = require('node:path');
const {
  filterEntries,
  foldHypotheses,
  listSessions,
  readSessionFile,
  resolveSessionRef,
} = require('./debug_evidence');

const USAGE = 'Usage: debug_viewer.js [projectRoot] --session <id|path> '
  + '[--hypothesis <id>] [--type all|event|hypothesis] [--since <ISO>] '
  + '[--until <ISO>] [--run <id>] [--limit <n>] [--live|--file] [--json|--plain]';

// Flags that take a following value — used to reject `--flag=value` syntax
// (this parser only accepts space-separated values) and to stop a value
// consuming a following flag token (see takeValue below).
const VALUE_FLAGS = new Set(['--session', '--hypothesis', '--type', '--since', '--until', '--run', '--limit']);
const EQUALS_FLAG = /^(--[a-z]+)=/;

// Fail-closed argument parsing: unknown flags, duplicate flags, `--flag=value`
// syntax, and malformed values all throw a viewer_usage error rather than
// being ignored or silently accepted (an ignored typo would silently widen
// what gets shown — same stance as the GET route, which also rejects
// duplicate query params).
const parseViewerArgs = (argv) => {
  const parsed = {
    projectRoot: process.cwd(),
    session: undefined,
    filters: {},
    agentMode: false,
    forceLive: false,
    forceFile: false,
  };
  const args = [...argv];
  if (args[0] && !args[0].startsWith('--')) parsed.projectRoot = args.shift();
  const seen = new Set();
  while (args.length > 0) {
    const flag = args.shift();
    const eqMatch = flag.match(EQUALS_FLAG);
    if (eqMatch && VALUE_FLAGS.has(eqMatch[1])) {
      throw new Error(`viewer_usage:${eqMatch[1]} takes a space-separated value`);
    }
    if (seen.has(flag)) throw new Error(`viewer_usage:duplicate flag ${flag}`);
    seen.add(flag);
    const takeValue = () => {
      const value = args[0];
      if (value === undefined || value.startsWith('--')) {
        throw new Error(`viewer_usage:missing value for ${flag}`);
      }
      return args.shift();
    };
    if (flag === '--session') parsed.session = takeValue();
    else if (flag === '--hypothesis') parsed.filters.hypothesisId = takeValue();
    else if (flag === '--type') parsed.filters.type = takeValue();
    else if (flag === '--since') parsed.filters.sinceTs = takeValue();
    else if (flag === '--until') parsed.filters.untilTs = takeValue();
    else if (flag === '--run') parsed.filters.runId = takeValue();
    else if (flag === '--limit') {
      const raw = takeValue();
      if (!/^\d+$/.test(raw) || Number(raw) < 1) throw new Error('viewer_usage:--limit must be a positive integer');
      parsed.filters.limit = Number(raw);
    } else if (flag === '--json' || flag === '--plain') parsed.agentMode = true;
    else if (flag === '--live') parsed.forceLive = true;
    else if (flag === '--file') parsed.forceFile = true;
    else throw new Error(`viewer_usage:unknown flag ${flag}`);
  }
  if (parsed.filters.type !== undefined && !['all', 'event', 'hypothesis'].includes(parsed.filters.type)) {
    throw new Error('viewer_usage:--type must be all|event|hypothesis');
  }
  return parsed;
};

// Agent mode: read, filter, emit raw lines, exit. Byte-verbatim output is
// the contract — agents in any harness parse these lines as NDJSON.
const runAgentMode = async (parsed) => {
  if (parsed.session === undefined) {
    process.stderr.write(`${USAGE}\nagent mode requires --session\n`);
    return 2;
  }
  if (parsed.forceLive) {
    // Live wiring is Task 4 by design; until then fail honestly instead of
    // silently serving stale file contents to a caller that asked to tail.
    process.stderr.write(`${USAGE}\nviewer_usage:--live is not wired yet (Task 4)\n`);
    return 2;
  }
  const filePath = resolveSessionRef(parsed.projectRoot, parsed.session);
  const entries = await readSessionFile(filePath);
  const selected = filterEntries(entries, parsed.filters);
  for (const entry of selected) process.stdout.write(`${entry.raw}\n`);
  return 0;
};

// --- Pure TUI state (layout C): stream over hypothesis table over key bar.
const createInitialState = ({ sessionId }) => ({
  sessionId,
  focus: 'stream',
  paused: false,
  quit: false,
  mode: 'normal',
  filterDraft: '',
  activeFilter: undefined,
  streamScroll: 0,
  tableScroll: 0,
  pickerOpen: false,
});

// (state, key) -> state, no side effects. Keys mirror the spec: tab focus,
// space pause, f filter entry (text until return/escape), s session picker,
// q quit. Unknown keys are no-ops — an unmapped keystroke must never
// mutate state.
const reduce = (state, key) => {
  // Nullish or shapeless key input is a no-op — never throw on a malformed
  // event, and never mutate state for something that isn't a real key.
  if (!key || typeof key !== 'object') return state;
  // Ctrl+C must quit from every mode — raw stdin swallows the terminal's
  // own SIGINT-on-Ctrl+C, so without this check filter-input mode would
  // trap the user with no way out (plain 'q' just types into the draft).
  if (key.ctrl && key.name === 'c') return { ...state, quit: true };
  if (state.mode === 'filter-input') {
    if (key.name === 'return') {
      return { ...state, mode: 'normal', activeFilter: state.filterDraft || undefined };
    }
    if (key.name === 'escape') return { ...state, mode: 'normal', filterDraft: '' };
    // Code-point slice, matching the append below — backspacing an astral
    // character must remove the whole surrogate pair, never split it (a
    // lone surrogate would poison the committed filter downstream).
    if (key.name === 'backspace') return { ...state, filterDraft: [...state.filterDraft].slice(0, -1).join('') };
    // Code-point length (not UTF-16 .length) so a single emoji/astral
    // character — a surrogate pair — still counts as one unit, while
    // multi-code-point escape sequences (arrow keys, etc.) are still
    // excluded, same as before.
    if (typeof key.sequence === 'string' && [...key.sequence].length === 1) {
      return { ...state, filterDraft: state.filterDraft + key.sequence };
    }
    return state;
  }
  if (key.name === 'q') return { ...state, quit: true };
  if (key.name === 'tab') return { ...state, focus: state.focus === 'stream' ? 'table' : 'stream' };
  if (key.name === 'space') return { ...state, paused: !state.paused };
  if (key.name === 'f') return { ...state, mode: 'filter-input', filterDraft: '' };
  if (key.name === 's') return { ...state, pickerOpen: !state.pickerOpen };
  if (key.name === 'up' || key.name === 'down') {
    const delta = key.name === 'up' ? -1 : 1;
    if (state.focus === 'stream') return { ...state, streamScroll: Math.max(0, state.streamScroll + delta) };
    return { ...state, tableScroll: Math.max(0, state.tableScroll + delta) };
  }
  return state;
};

const main = async () => {
  let parsed;
  try {
    parsed = parseViewerArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${USAGE}\n${error.message}\n`);
    process.exitCode = 2;
    return;
  }
  if (parsed.agentMode || !process.stdout.isTTY) {
    process.exitCode = await runAgentMode(parsed);
    return;
  }
  // TUI loop lands in the next task; until then a real terminal invocation
  // reports honestly instead of pretending.
  process.stderr.write('debug_viewer TUI is not wired yet (agent mode: pipe stdout or pass --json)\n');
  process.exitCode = 3;
};

if (require.main === module) {
  main().catch((error) => {
    // Runtime failures (bad session path, ENOENT, etc.) must not crash out
    // through a raw Node stack dump — one clean line on stderr, exit 1.
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  createInitialState,
  parseViewerArgs,
  reduce,
  runAgentMode,
};
```

(`foldHypotheses` and `listSessions` are intentionally imported now — Task 4's painter consumes them; if the linter-free repo style flags unused imports, keep them and note that Task 4 uses them.)

- [ ] **Step 4: Verify green**

Run: `node --test --test-concurrency=1 scripts/debug_viewer.test.js` — 14/14 pass. `node --check scripts/debug_viewer.js` clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/debug_viewer.js scripts/debug_viewer.test.js
git commit -m "feat(tools): viewer agent mode, fail-closed CLI, pure TUI reducers

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 4: debug_viewer — pure frame renderer + TUI loop + live tail

**Files:**
- Modify: `scripts/debug_viewer.js` (renderFrame + TUI loop replacing the exit-3 stub)
- Modify: `scripts/debug_viewer.test.js` (append renderer tests)

- [ ] **Step 1: Write the failing tests**

Append to `scripts/debug_viewer.test.js`. Housekeeping first: add `renderFrame` to the `./debug_viewer` destructured require, add `readFile` to the `node:fs/promises` destructure, add `const http = require('node:http');` to the top requires (alphabetical), and DELETE the now-obsolete test `agent mode rejects --live as not wired until Task 4, exit 2` (this task wires --live; the e2e below supersedes it).

```js
test('renderFrame paints layout C: stream, verdict table, key bar', () => {
  const entries = [
    { raw: '', parsed: { ts: '2026-08-06T10:00:01.000Z', msg: 'clicked', hypothesisId: 'H1' } },
    { raw: '', parsed: { ts: '2026-08-06T10:00:03.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'CONFIRMED', title: 'null id', note: 'proven' } },
  ];
  const state = createInitialState({ sessionId: 's1' });
  const frame = renderFrame(state, entries, { columns: 80, rows: 16, live: true });
  assert.match(frame, /s1/);
  assert.match(frame, /● live/);
  assert.match(frame, /clicked/);
  assert.match(frame, /◆ H1 → CONFIRMED/);
  assert.match(frame, /H1\s+CONFIRMED\s+null id/);
  assert.match(frame, /f:filter\s+s:sessions\s+tab:focus\s+space:pause\s+q:quit/);
});

test('renderFrame marks paused state and truncates to the terminal width', () => {
  const wide = { raw: '', parsed: { ts: '2026-08-06T10:00:01.000Z', msg: 'x'.repeat(300) } };
  const state = { ...createInitialState({ sessionId: 's1' }), paused: true };
  const frame = renderFrame(state, [wide], { columns: 40, rows: 12, live: false });
  assert.match(frame, /paused/);
  for (const row of frame.split('\n')) assert.equal(row.length <= 40, true);
});

test('renderFrame does not throw on negative columns and still yields the requested row count', () => {
  const state = createInitialState({ sessionId: 's1' });
  const frame = renderFrame(state, [], { columns: -5, rows: 4, live: false });
  assert.equal(frame.split('\n').length, 4);
});

test('renderFrame clips at a code-point boundary, never splitting a surrogate pair', () => {
  const wide = { raw: '', parsed: { ts: '2026-08-06T10:00:01.000Z', msg: '\u{1F600}abc' } };
  const state = createInitialState({ sessionId: 's1' });
  const frame = renderFrame(state, [wide], { columns: 10, rows: 12, live: false });
  const rows = frame.split('\n');
  assert.equal(rows.length, 12);
  for (const row of rows) assert.equal(row.isWellFormed(), true);
});

// Live collector fixture for the agent-mode --live e2e (mirrors the
// withLiveSession fixture in debug_evidence.test.js; duplicated because
// test files cannot share helpers without executing each other's tests).
const { createDebugServer } = require('./debug_server');

const LAUNCH = 'viewer-test-launch-token-with-entropy';

const listen = (server) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => resolve(server.address().port));
});

const closeServer = (server) => new Promise((resolve, reject) => {
  server.close((error) => (error ? reject(error) : resolve()));
});

const httpJson = (port, pathname, { method = 'GET', headers = {}, body } = {}) =>
  new Promise((resolve, reject) => {
    const request = http.request({ hostname: '127.0.0.1', port, path: pathname, method, headers }, (response) => {
      let text = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => { text += chunk; });
      response.on('end', () => resolve({ status: response.statusCode, text }));
    });
    request.on('error', reject);
    if (body !== undefined) request.write(JSON.stringify(body));
    request.end();
  });

test('agent mode --live emits the live session raw lines byte-verbatim', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'viewer-live-'));
  const server = createDebugServer({ projectRoot: root, token: LAUNCH, redactionEnv: {} });
  const port = await listen(server);
  try {
    const minted = await httpJson(port, '/session', {
      method: 'POST',
      headers: { Authorization: `Bearer ${LAUNCH}` },
      body: { name: 'live' },
    });
    const session = JSON.parse(minted.text);
    const log = (msg, extra = {}) => httpJson(port, '/log', {
      method: 'POST',
      body: { sessionId: session.session_id, sessionToken: session.session_token, msg, ...extra },
    });
    await log('live-e1', { hypothesisId: 'H1' });
    await log('live-e2');
    await writeFile(path.join(root, '.debug', 'collector_port'), String(port), 'utf8');
    await writeFile(path.join(root, '.debug', 'collector_token'), LAUNCH, 'utf8');
    const stored = await readFile(path.join(root, session.log_file), 'utf8');
    const result = await runViewer([root, '--session', session.session_id, '--live']);
    assert.equal(result.stderr, '');
    assert.equal(result.code, 0);
    assert.equal(result.stdout, stored);
  } finally {
    await closeServer(server);
    await rm(root, { recursive: true, force: true });
  }
});

test('agent mode --live without a running collector fails with one clean line, exit 1', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'viewer-nolive-'));
  try {
    const result = await runViewer([root, '--session', 's1', '--live']);
    assert.equal(result.code, 1);
    assert.equal(result.stdout, '');
    assert.equal(result.stderr, 'collector_not_running\n');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run to verify failures**

Run: `node --test --test-concurrency=1 scripts/debug_viewer.test.js`
Expected: the six new tests fail (the four renderer tests with `renderFrame` undefined; both --live e2e tests with the exit-2 "not wired yet" usage error); the remaining 13 prior tests pass.

- [ ] **Step 3: Implement**

Three implementation moves in this step, in order:

**(a) Wire agent-mode `--live`** (the spec requires both data sources in BOTH frontends). Extend the top-of-file `./debug_evidence` destructured require with `createSessionTail`, `discoverCollector`, `readSessionLive` (alphabetical). Also extend the `USAGE` constant so the `--live` mention reads `--live (bare session ids only; .log file paths are file-mode)` — live reads enforce the route's id pattern by design (trust-model separation), and the usage text must make that read as intentional. Then in `runAgentMode`, replace the entire `if (parsed.forceLive) { ... }` rejection block (the `viewer_usage:--live is not wired yet (Task 4)` one — keep the missing-`--session` guard above it untouched) with:

```js
  if (parsed.forceLive) {
    // Live agent read: discover the collector, let the server apply the
    // filters (GET-parity guaranteed by the core's test), emit the raw
    // stored lines byte-verbatim. Errors (collector_not_running,
    // live_read_*) propagate to main's catch: one line, exit 1.
    const collector = await discoverCollector(parsed.projectRoot);
    const entries = await readSessionLive({ ...collector, sessionId: parsed.session, filters: parsed.filters });
    for (const entry of entries) process.stdout.write(`${entry.raw}\n`);
    return 0;
  }
```

**(b) Insert `renderFrame`** (pure — string in, string out, no ANSI cursor addressing inside rows so tests stay byte-stable) above `main`, and **(c) replace the exit-3 stub with the TUI loop**:

```js
// Pure frame renderer for layout C. Returns a full-screen string of exactly
// `rows` lines, each hard-truncated to `columns` — the painter writes it in
// one stdout call, so tearing can't interleave partial rows. Kept free of
// cursor-addressing so unit tests can assert on plain text.
const formatEntryRow = (parsed) => {
  const time = typeof parsed.ts === 'string' ? parsed.ts.slice(11, 19) : '--:--:--';
  if (parsed.type === 'hypothesis') {
    const note = parsed.note ? ` "${parsed.note}"` : '';
    return `${time} ◆ ${parsed.hypothesisId} → ${parsed.status}${note}`;
  }
  const tag = parsed.hypothesisId ? `${parsed.hypothesisId} ` : '';
  const loc = parsed.loc ? `  ${parsed.loc}` : '';
  return `${time} ${tag}${parsed.msg ?? ''}${loc}`;
};

const renderFrame = (state, entries, { columns, rows, live }) => {
  // Code-point-safe clip: slicing UTF-16 units can split a surrogate pair
  // at the boundary and emit a lone surrogate. Display-width (CJK/emoji
  // rendering as double-width cells) is explicitly out of scope for a
  // zero-dependency tool — code-unit well-formedness is the guarantee.
  const clip = (text) => {
    const points = [...text];
    return points.length > columns ? points.slice(0, Math.max(0, columns)).join('') : text;
  };
  const folded = foldHypotheses(entries);
  const tableRows = [...folded.values()].map((h) => {
    const when = typeof h.ts === 'string' ? h.ts.slice(11, 16) : '';
    const detail = h.title ?? h.note ?? '';
    return `${h.hypothesisId}  ${h.status}  ${detail}  ${when}`;
  });
  const tableHeight = Math.min(Math.max(tableRows.length, 1), Math.max(3, Math.floor(rows / 3)));
  const streamHeight = rows - tableHeight - 3;
  const streamRows = entries.map((entry) => formatEntryRow(entry.parsed));
  const visibleStream = streamRows.slice(-(streamHeight + state.streamScroll), streamRows.length - state.streamScroll || undefined);
  const status = state.paused ? 'paused' : (live ? '● live' : 'file');
  const filterBadge = state.activeFilter ? `  [${state.activeFilter}]` : '';
  const lines = [];
  lines.push(clip(`─ ${state.sessionId}${filterBadge} ── ${status} ${'─'.repeat(Math.max(0, columns))}`));
  for (let i = 0; i < streamHeight; i += 1) lines.push(clip(visibleStream[i] ?? ''));
  lines.push(clip(`─ hypotheses ${'─'.repeat(Math.max(0, columns))}`));
  for (let i = 0; i < tableHeight; i += 1) lines.push(clip(tableRows[i + state.tableScroll] ?? ''));
  lines.push(clip('f:filter  s:sessions  tab:focus  space:pause  q:quit'));
  return lines.slice(0, rows).join('\n');
};
```

TUI loop replacing the stub (inside `main`'s TTY branch):

```js
  // TUI loop: raw-mode stdin -> pure reducers -> full-frame repaint on the
  // alternate screen. The painter is the ONLY untested-by-CI code (spec
  // decision); everything it renders comes from tested functions.
  const readline = require('node:readline');
  let sessionId = parsed.session;
  if (sessionId === undefined) {
    const sessions = await listSessions(parsed.projectRoot);
    if (sessions.length === 0) {
      process.stderr.write('no sessions under .debug/\n');
      process.exitCode = 1;
      return;
    }
    sessionId = sessions[sessions.length - 1].sessionId;
  }
  let state = createInitialState({ sessionId });
  let entries = [];
  let live = false;
  let tail = null;
  if (!parsed.forceFile) {
    try {
      const collector = await discoverCollector(parsed.projectRoot);
      tail = createSessionTail({ ...collector, sessionId });
      entries = await tail.poll();
      live = true;
    } catch {
      tail = null;
    }
  }
  if (!live) {
    if (parsed.forceLive) {
      process.stderr.write('collector not reachable; --live unavailable\n');
      process.exitCode = 1;
      return;
    }
    entries = await readSessionFile(resolveSessionRef(parsed.projectRoot, sessionId));
  }
  const applyActiveFilter = (current, all) => (
    current.activeFilter ? filterEntries(all, { hypothesisId: current.activeFilter }) : all
  );
  const paint = () => {
    const { columns = 80, rows = 24 } = process.stdout;
    process.stdout.write(`\u001b[2J\u001b[H${renderFrame(state, applyActiveFilter(state, entries), { columns, rows, live })}`);
  };
  process.stdout.write('\u001b[?1049h');
  // Unconditional restore: covers any uncaught throw (e.g. the poll
  // fallback below) and external kills so a failure never strands the
  // terminal on the alternate screen in raw mode; shutdown() below is
  // the clean path, this is the belt-and-suspenders one.
  process.on('exit', () => {
    process.stdout.write('\u001b[?1049l');
    if (process.stdin.isTTY) process.stdin.setRawMode(false);
  });
  readline.emitKeypressEvents(process.stdin);
  if (process.stdin.isTTY) process.stdin.setRawMode(true);
  const pollTimer = setInterval(async () => {
    if (state.paused || tail === null) return;
    try {
      const fresh = await tail.poll();
      if (fresh.length > 0) {
        entries = entries.concat(fresh);
        paint();
      }
    } catch {
      // Session retired mid-watch: fall back to the file, visibly.
      live = false;
      tail = null;
      try {
        entries = await readSessionFile(resolveSessionRef(parsed.projectRoot, sessionId));
      } catch {
        // Fallback read failed too (collector stopped AND log removed).
        // setInterval never awaits this callback, so an unhandled
        // rejection here would kill the process with the alt-screen
        // still active and raw mode still on — stale evidence beats a
        // corrupted terminal, so keep the last-known entries instead.
      }
      paint();
    }
  }, 500);
  const shutdown = () => {
    clearInterval(pollTimer);
    process.stdout.off('resize', paint);
    process.stdout.write('\u001b[?1049l');
    if (process.stdin.isTTY) process.stdin.setRawMode(false);
    process.stdin.pause();
  };
  process.stdin.on('keypress', (_, key) => {
    state = reduce(state, key ?? {});
    if (state.quit) {
      shutdown();
      return;
    }
    paint();
  });
  process.stdout.on('resize', paint);
  paint();
```

Move the `applyActiveFilter` const ABOVE `paint` (it is referenced there). Export `renderFrame` alongside the existing exports.

- [ ] **Step 4: Verify green**

Run: `node --test --test-concurrency=1 scripts/debug_viewer.test.js` — 22/22 pass (14 from Task 3 and its fix rounds, minus the retired rejection test, plus 6 from this task's Step 1, plus 3 Ctrl+C reducer tests added to `reduce()` during this task's crash-safety review round). `node --check scripts/debug_viewer.js` clean. NOTE: step (a) makes the Task 3 test `agent mode rejects --live as not wired until Task 4, exit 2` obsolete — DELETE that test in Step 1 (the new --live e2e supersedes its coverage; Task 4 is the task it was waiting for) and mention the deletion in the commit body. NOTE (review round): the poll-catch fallback read is guarded (a second failure keeps last-known entries rather than crashing an un-awaited `setInterval` callback), an unconditional `process.on('exit', ...)` restores the terminal on any uncaught throw or external kill, Ctrl+C quits from every `reduce` mode, the `--live`-unavailable message now fires before the fallback file read can throw ENOENT, and `renderFrame`'s `clip`/`'─'.repeat` are negative-columns- and surrogate-pair-safe. Manual smoke (optional, report if run): `node scripts/debug_viewer.js <root> --session <id>` in a real terminal.

- [ ] **Step 5: Commit**

```bash
git add scripts/debug_viewer.js scripts/debug_viewer.test.js
git commit -m "feat(tools): layout-C TUI frame renderer and live-tail loop

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 5: debug_diff — engine, three renderers, TTY-aware CLI

**Files:**
- Create: `scripts/debug_diff.js`
- Create: `scripts/debug_diff.test.js`

- [ ] **Step 1: Write the failing tests**

Create `scripts/debug_diff.test.js`:

```js
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { mkdtemp, mkdir, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { computeDiff, renderJson, renderMarkdown, renderTable } = require('./debug_diff');
const { parseSessionText } = require('./debug_evidence');

const DIFF = path.join(__dirname, 'debug_diff.js');
const line = (object) => `${JSON.stringify(object)}\n`;

const run = (args) => new Promise((resolve) => {
  execFile(process.execPath, [DIFF, ...args], (error, stdout, stderr) => {
    resolve({ code: error ? error.code : 0, stdout, stderr });
  });
});

// Shared fixture directory for CLI-spawned tests that don't care about the
// exact session content, only about argv handling / error paths.
const withSessionDir = async (fn) => {
  const root = await mkdtemp(path.join(tmpdir(), 'diff-'));
  try {
    await mkdir(path.join(root, '.debug'));
    await writeFile(path.join(root, '.debug', 'debug-a.log'), '', 'utf8');
    await writeFile(path.join(root, '.debug', 'debug-b.log'), '', 'utf8');
    await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
};

const BEFORE = parseSessionText(
  line({ ts: '2026-08-06T10:00:01.000Z', msg: 'userId=null', hypothesisId: 'H1' })
  + line({ ts: '2026-08-06T10:00:02.000Z', msg: 'userId=null', hypothesisId: 'H1' })
  + line({ ts: '2026-08-06T10:00:03.000Z', msg: 'render ok', hypothesisId: 'H1' })
  + line({ ts: '2026-08-06T10:00:04.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'OPEN', title: 'null id' })
  + line({ ts: '2026-08-06T10:00:05.000Z', msg: 'untagged noise' }),
);

const AFTER = parseSessionText(
  line({ ts: '2026-08-06T11:00:01.000Z', msg: 'render ok', hypothesisId: 'H1' })
  + line({ ts: '2026-08-06T11:00:02.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'CONFIRMED', note: 'fixed' })
  + line({ ts: '2026-08-06T11:00:03.000Z', msg: 'fresh path', hypothesisId: 'H3' }),
);

test('computeDiff unions hypotheses with transitions, counts, and disappeared messages', () => {
  const diff = computeDiff(BEFORE, AFTER);
  assert.equal(diff.schema, 1);
  const h1 = diff.hypotheses.find((h) => h.id === 'H1');
  assert.equal(h1.before.status, 'OPEN');
  assert.equal(h1.after.status, 'CONFIRMED');
  assert.equal(h1.before.events, 3);
  assert.equal(h1.after.events, 1);
  assert.deepEqual(h1.disappeared, ['userId=null']);
  const h3 = diff.hypotheses.find((h) => h.id === 'H3');
  assert.equal(h3.before.status, null);
  assert.equal(h3.after.status, null);
  assert.equal(h3.after.events, 1);
  assert.deepEqual(diff.untagged.disappeared, ['untagged noise']);
  assert.equal(diff.summary.verdictChanges, 1);
  assert.equal(diff.summary.newHypotheses, 1);
});

test('computeDiff caps disappeared messages per hypothesis and says so', () => {
  const noisy = parseSessionText(
    Array.from({ length: 30 }, (_, i) => line({ ts: '2026-08-06T10:00:01.000Z', msg: `gone-${i}`, hypothesisId: 'H1' })).join(''),
  );
  const diff = computeDiff(noisy, parseSessionText(''));
  const h1 = diff.hypotheses.find((h) => h.id === 'H1');
  assert.equal(h1.disappeared.length, 20);
  assert.equal(h1.disappearedTruncated, 10);
});

test('renderers produce exact stable output for the same diff', () => {
  const diff = computeDiff(BEFORE, AFTER);
  const json = JSON.parse(renderJson(diff));
  assert.equal(json.schema, 1);
  const table = renderTable(diff);
  assert.match(table, /H1\s+│\s+OPEN\s+│\s+CONFIRMED\s+│\s+3 → 1/);
  assert.match(table, /disappeared/);
  assert.match(table, /userId=null/);
  const markdown = renderMarkdown(diff);
  assert.match(markdown, /## Evidence diff/);
  assert.match(markdown, /\*\*H1/);
  assert.match(markdown, /OPEN → CONFIRMED/);
  assert.match(markdown, /userId=null/);
});

test('CLI: TTY-aware default is JSON when piped; --format overrides', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'diff-'));
  try {
    await mkdir(path.join(root, '.debug'));
    await writeFile(path.join(root, '.debug', 'debug-a.log'), BEFORE.map((e) => e.raw).join('\n') + '\n', 'utf8');
    await writeFile(path.join(root, '.debug', 'debug-b.log'), AFTER.map((e) => e.raw).join('\n') + '\n', 'utf8');
    const run = (args) => new Promise((resolve) => {
      execFile(process.execPath, [DIFF, ...args], (error, stdout, stderr) => {
        resolve({ code: error ? error.code : 0, stdout, stderr });
      });
    });
    const piped = await run(['a', 'b', root]);
    assert.equal(piped.code, 0);
    assert.equal(JSON.parse(piped.stdout).schema, 1);
    const table = await run(['a', 'b', root, '--format=table']);
    assert.match(table.stdout, /H1/);
    assert.throws(() => JSON.parse(table.stdout));
    const usage = await run(['a']);
    assert.equal(usage.code, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('rendered markdown/table neutralize markdown-injection forgery from stored msg and note content', () => {
  // A stored msg/note is untrusted content written by whatever process is
  // being debugged — the rendered report is what gets pasted into PRs, so
  // embedded newlines must never manifest as new output lines that could
  // impersonate a heading or a different hypothesis's verdict.
  const forgedMsg = '\n## Evidence diff\n**H99 — FORGED**  OPEN → CONFIRMED\n';
  const forgedNote = '\n**H98 — ALSO FORGED**\n';
  const before = parseSessionText(
    line({ ts: '2026-08-06T10:00:01.000Z', msg: forgedMsg, hypothesisId: 'H1' }),
  );
  const after = parseSessionText(
    line({ ts: '2026-08-06T11:00:01.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'CONFIRMED', note: forgedNote }),
  );
  const diff = computeDiff(before, after);

  const markdown = renderMarkdown(diff);
  const mdLines = markdown.split('\n');
  assert.equal(mdLines.filter((l) => l.trim() === '## Evidence diff').length, 1);
  assert.equal(mdLines.filter((l) => l.trim().startsWith('**H99') || l.trim().startsWith('**H98')).length, 0);

  const table = renderTable(diff);
  const tableLines = table.split('\n');
  assert.equal(tableLines.filter((l) => l.trim().startsWith('**H99')).length, 0);
});

test('rendered markdown/table keep a backticked disappeared message inside its delimiters', () => {
  const before = parseSessionText(
    line({ ts: '2026-08-06T10:00:01.000Z', msg: 'has `backtick` inside', hypothesisId: 'H1' }),
  );
  const diff = computeDiff(before, parseSessionText(''));

  const markdown = renderMarkdown(diff);
  const goneLine = markdown.split('\n').find((l) => l.startsWith('- gone: '));
  assert.equal(goneLine, '- gone: `has \\`backtick\\` inside`');

  const table = renderTable(diff);
  const tableLine = table.split('\n').find((l) => l.includes('backtick'));
  assert.equal(tableLine, '  - has \\`backtick\\` inside');
});

test('computeDiff ignores non-string/missing hypothesis ids without crashing, counts them, and renderers state it', () => {
  // Pre-validation logs (exactly what a before-ref commonly is) can carry a
  // numeric hypothesisId on an event line, or a hypothesis-lifecycle line
  // with no hypothesisId at all. The engine's contract is string ids —
  // these must be excluded from the per-hypothesis report (never crash
  // renderTable's `.padEnd`) and counted, never silently dropped.
  const malformed = parseSessionText(
    line({ ts: '2026-08-06T10:00:01.000Z', msg: 'weird event', hypothesisId: 42 })
    + line({ ts: '2026-08-06T10:00:02.000Z', type: 'hypothesis', status: 'OPEN' }),
  );
  const diff = computeDiff(malformed, parseSessionText(''));
  assert.equal(diff.summary.ignoredMalformedIds, 2);
  assert.equal(diff.hypotheses.length, 0);
  assert.doesNotThrow(() => renderTable(diff));
  assert.doesNotThrow(() => renderMarkdown(diff));
  const table = renderTable(diff);
  assert.match(table, /2 malformed hypothesis ids ignored/);
  const markdown = renderMarkdown(diff);
  assert.match(markdown, /2 malformed hypothesis ids ignored/);
  const json = JSON.parse(renderJson(diff));
  assert.equal(json.summary.ignoredMalformedIds, 2);
});

test('CLI: unknown flag fails closed with exit 2 and nothing on stdout', async () => {
  await withSessionDir(async (root) => {
    const result = await run(['a', 'b', root, '--json']);
    assert.equal(result.code, 2);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /unknown flag/);
  });
});

test('CLI: duplicate --format fails closed with exit 2 and nothing on stdout', async () => {
  await withSessionDir(async (root) => {
    const result = await run(['a', 'b', root, '--format=json', '--format=md']);
    assert.equal(result.code, 2);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /duplicate --format/);
  });
});

test('CLI: bare --format (space form) fails closed with exit 2, message names --format=<...>, and does not swallow its value as a positional', async () => {
  await withSessionDir(async (root) => {
    const result = await run(['a', 'b', root, '--format', 'md']);
    assert.equal(result.code, 2);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /--format=<table\|md\|json>/);
  });
});

test('CLI: read error names which ref failed to read', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'diff-'));
  try {
    await mkdir(path.join(root, '.debug'));
    // Only the after-ref exists; the before-ref ("missing-a") has no
    // session file, so reading it must fail — and the error must say it
    // was the BEFORE session, naming "missing-a", not a generic message.
    await writeFile(path.join(root, '.debug', 'debug-b.log'), '', 'utf8');
    const result = await run(['missing-a', 'b', root, '--format=json']);
    assert.equal(result.code, 1);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /cannot read before session \(missing-a\)/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('renderTable aligns the id column for ids of very different lengths', () => {
  const diff = computeDiff(
    parseSessionText(
      line({ ts: '2026-08-06T10:00:01.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'OPEN' })
      + line({ ts: '2026-08-06T10:00:02.000Z', type: 'hypothesis', hypothesisId: 'very-long-hypothesis-identifier', status: 'CONFIRMED' }),
    ),
    parseSessionText(''),
  );
  const table = renderTable(diff);
  // Every bordered row (top/header/divider/data/bottom, all prefixed with a
  // box-drawing character) must be the same total width — the id column
  // width must be sampled across ALL rendered ids, not just the first row.
  const borderedLines = table.split('\n').filter((l) => /^[│┌├└]/.test(l));
  const lengths = new Set(borderedLines.map((l) => l.length));
  assert.equal(lengths.size, 1);
  assert.match(table, /very-long-hypothesis-identifier/);
});

test('renderTable truncates an id over the 40-char cap with an ellipsis, still aligned', () => {
  const longId = 'H'.repeat(50);
  const diff = computeDiff(
    parseSessionText(line({ ts: '2026-08-06T10:00:01.000Z', type: 'hypothesis', hypothesisId: longId, status: 'OPEN' })),
    parseSessionText(''),
  );
  const table = renderTable(diff);
  assert.doesNotMatch(table, new RegExp(longId));
  assert.match(table, /H{39}…/);
  const borderedLines = table.split('\n').filter((l) => /^[│┌├└]/.test(l));
  const lengths = new Set(borderedLines.map((l) => l.length));
  assert.equal(lengths.size, 1);
});
```

- [ ] **Step 2: Run to verify failures**

Run: `node --test --test-concurrency=1 scripts/debug_diff.test.js`
Expected: FAIL — module missing.

- [ ] **Step 3: Implement `scripts/debug_diff.js`**

```js
// Per-hypothesis before/after session diff (spec:
// docs/superpowers/specs/2026-08-06-evidence-tools-design.md). The engine
// presents RECORDED verdicts and deterministic deltas only — no severity or
// failure classification anywhere (deciding what "looks like" a failure
// would be pattern-guessing, which this skill forbids). One engine feeds
// three renderers; the no-flag default is TTY-aware: table for humans,
// JSON (schema: 1) for pipes, because agents must never scrape tables.
const {
  foldHypotheses,
  readSessionFile,
  resolveSessionRef,
} = require('./debug_evidence');

const DISAPPEARED_CAP = 20;

const USAGE = 'Usage: debug_diff.js <beforeRef> <afterRef> [projectRoot] [--format=table|md|json]';

// Distinct event-msg texts scoped per hypothesisId (plus an untagged
// bucket) — the deterministic raw material for "what stopped happening".
const messagesByHypothesis = (entries) => {
  const buckets = new Map();
  for (const { parsed } of entries) {
    if (parsed.type !== undefined) continue;
    const key = parsed.hypothesisId ?? '';
    if (!buckets.has(key)) buckets.set(key, { messages: new Set(), events: 0 });
    const bucket = buckets.get(key);
    bucket.events += 1;
    if (typeof parsed.msg === 'string') bucket.messages.add(parsed.msg);
  }
  return buckets;
};

const diffBucket = (beforeBucket, afterBucket) => {
  const before = beforeBucket ?? { messages: new Set(), events: 0 };
  const after = afterBucket ?? { messages: new Set(), events: 0 };
  const disappeared = [...before.messages].filter((msg) => !after.messages.has(msg)).sort();
  return {
    beforeEvents: before.events,
    afterEvents: after.events,
    disappeared: disappeared.slice(0, DISAPPEARED_CAP),
    disappearedTruncated: Math.max(0, disappeared.length - DISAPPEARED_CAP),
  };
};

// The engine's contract is string hypothesis ids. Older/pre-validation
// logs can carry a non-string id (hypothesisId: 42 on an event line) or a
// hypothesis-lifecycle line with no id at all (hypothesisId: undefined) —
// either would otherwise reach renderTable's `.padEnd` and crash. The
// empty string is deliberately NOT "malformed": it is messagesByHypothesis'
// own sentinel for the untagged bucket, handled separately below.
const isValidHypothesisId = (id) => typeof id === 'string' && id !== '';

const computeDiff = (beforeEntries, afterEntries) => {
  const beforeFolded = foldHypotheses(beforeEntries);
  const afterFolded = foldHypotheses(afterEntries);
  const beforeBuckets = messagesByHypothesis(beforeEntries);
  const afterBuckets = messagesByHypothesis(afterEntries);
  const allKeys = new Set([
    ...beforeFolded.keys(), ...afterFolded.keys(),
    ...beforeBuckets.keys(), ...afterBuckets.keys(),
  ]);
  const ids = [];
  // Excluded (never silent): every non-string/empty key found anywhere in
  // the union is counted once, distinct-value basis, matching how `ids`
  // itself is deduplicated across the same four sources.
  let ignoredMalformedIds = 0;
  for (const key of allKeys) {
    if (key === '') continue;
    if (isValidHypothesisId(key)) ids.push(key);
    else ignoredMalformedIds += 1;
  }
  ids.sort();
  let verdictChanges = 0;
  let newHypotheses = 0;
  const hypotheses = ids.map((id) => {
    const before = beforeFolded.get(id);
    const after = afterFolded.get(id);
    const bucket = diffBucket(beforeBuckets.get(id), afterBuckets.get(id));
    if (before?.status !== after?.status && (before || after)) verdictChanges += 1;
    const seenBefore = before !== undefined || beforeBuckets.has(id);
    if (!seenBefore) newHypotheses += 1;
    return {
      id,
      title: after?.title ?? before?.title ?? null,
      before: { status: before?.status ?? null, note: before?.note ?? null, events: bucket.beforeEvents },
      after: { status: after?.status ?? null, note: after?.note ?? null, events: bucket.afterEvents },
      disappeared: bucket.disappeared,
      disappearedTruncated: bucket.disappearedTruncated,
    };
  });
  const untagged = diffBucket(beforeBuckets.get(''), afterBuckets.get(''));
  return {
    schema: 1,
    hypotheses,
    untagged: {
      before: { events: untagged.beforeEvents },
      after: { events: untagged.afterEvents },
      disappeared: untagged.disappeared,
      disappearedTruncated: untagged.disappearedTruncated,
    },
    summary: { verdictChanges, newHypotheses, ignoredMalformedIds },
  };
};

const renderJson = (diff) => `${JSON.stringify(diff, null, 2)}\n`;

const statusOr = (status) => status ?? '—';

// Stored msg/note/title text is untrusted — it is written by whatever
// process is being debugged, not by this tool. The rendered report IS the
// evidence that gets pasted into PRs/chat, so raw interpolation would let
// log content forge headings, verdicts, or break out of a backtick code
// span (report structure must reflect the engine, never log content).
// JSON.stringify turns embedded newlines/quotes/control chars into their
// escaped literal form (a real newline becomes the two printable
// characters "\" + "n", never an actual line break); backticks are handled
// separately since JSON.stringify does not touch them and this text can
// land inside a backtick code span. JSON output needs none of this —
// JSON.stringify(diff, ...) already escapes everything correctly there.
const escapeText = (value) => JSON.stringify(String(value)).slice(1, -1).replaceAll('`', '\\`');

// Hypothesis ids are short identifiers by convention; 40 chars comfortably
// fits real-world ids while keeping the bordered table readable if an
// oversized id somehow reaches here — truncated with an ellipsis rather
// than silently overflowing the border or wrapping.
const ID_COLUMN_MAX = 40;
const truncateId = (id) => (id.length > ID_COLUMN_MAX ? `${id.slice(0, ID_COLUMN_MAX - 1)}…` : id);

const renderTable = (diff) => {
  const displayIds = diff.hypotheses.map((h) => truncateId(h.id));
  // Width is sampled across every rendered id (not just the first row), so
  // the id column — and therefore every row's total width — stays aligned
  // regardless of which row has the longest id.
  const idWidth = Math.max(2, ...displayIds.map((id) => id.length));
  const rows = diff.hypotheses.map((h, i) => (
    `│ ${displayIds[i].padEnd(idWidth)} │ ${statusOr(h.before.status).padEnd(12)} │ ${statusOr(h.after.status).padEnd(12)} │ ${`${h.before.events} → ${h.after.events}`.padEnd(9)} │`
  ));
  const header = `│ ${'id'.padEnd(idWidth)} │ ${'before'.padEnd(12)} │ ${'after'.padEnd(12)} │ ${'events'.padEnd(9)} │`;
  // header and every row share the same column widths by construction, so
  // header's length IS the row width — no need to sample rows separately
  // (and this stays correct even when there are zero hypotheses to show).
  const width = header.length;
  const bar = '─'.repeat(Math.max(width - 2, 10));
  const lines = [`┌${bar}┐`, header, `├${bar}┤`, ...rows, `└${bar}┘`];
  for (const h of diff.hypotheses) {
    if (h.disappeared.length > 0) {
      lines.push(`disappeared after fix (${h.id}${h.disappearedTruncated ? `, +${h.disappearedTruncated} more` : ''}):`);
      for (const msg of h.disappeared) lines.push(`  - ${escapeText(msg)}`);
    }
  }
  if (diff.untagged.disappeared.length > 0) {
    lines.push('disappeared (untagged):');
    for (const msg of diff.untagged.disappeared) lines.push(`  - ${escapeText(msg)}`);
  }
  lines.push(`verdict changes: ${diff.summary.verdictChanges}  new hypotheses: ${diff.summary.newHypotheses}`);
  if (diff.summary.ignoredMalformedIds > 0) {
    lines.push(`${diff.summary.ignoredMalformedIds} malformed hypothesis ids ignored`);
  }
  return `${lines.join('\n')}\n`;
};

const renderMarkdown = (diff) => {
  const lines = ['## Evidence diff', ''];
  for (const h of diff.hypotheses) {
    const title = h.title ? ` — ${escapeText(h.title)}` : '';
    lines.push(`**${h.id}${title}**  ${statusOr(h.before.status)} → ${statusOr(h.after.status)}`);
    lines.push('');
    lines.push(`- events ${h.before.events} → ${h.after.events}`);
    for (const msg of h.disappeared) lines.push(`- gone: \`${escapeText(msg)}\``);
    if (h.disappearedTruncated > 0) lines.push(`- …and ${h.disappearedTruncated} more disappeared`);
    if (h.after.note) lines.push(`- note: "${escapeText(h.after.note)}"`);
    lines.push('');
  }
  lines.push(`_verdict changes: ${diff.summary.verdictChanges} · new hypotheses: ${diff.summary.newHypotheses}_`);
  if (diff.summary.ignoredMalformedIds > 0) {
    lines.push(`_${diff.summary.ignoredMalformedIds} malformed hypothesis ids ignored_`);
  }
  return `${lines.join('\n')}\n`;
};

// Fail-closed argv parsing, mirroring the viewer's stance: an unrecognized
// flag, a repeated --format, or the space form (`--format md`, which would
// otherwise silently swallow `md` as a positional and shift beforeRef/
// afterRef) all reject the invocation rather than guessing what was meant.
// `--format=<value>` is this tool's one canonical flag form.
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
      return { error: '--format requires a value: --format=<table|md|json>' };
    }
    return { error: `unknown flag: ${arg}` };
  }
  return { positional, format };
};

const main = async () => {
  const args = process.argv.slice(2);
  const parsed = parseArgs(args);
  if (parsed.error) {
    process.stderr.write(`debug_diff: ${parsed.error}\n${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const { positional, format: formatArg } = parsed;
  if (positional.length < 2) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const [beforeRef, afterRef, projectRoot = process.cwd()] = positional;
  const format = formatArg ?? (process.stdout.isTTY ? 'table' : 'json');
  if (!['table', 'md', 'json'].includes(format)) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  // Read before/after separately (not one shared try/catch) — a diff over
  // a missing or malformed session must never render a partial report, and
  // "cannot read session" alone leaves the operator guessing which of the
  // two refs was the problem.
  let beforeEntries;
  try {
    beforeEntries = await readSessionFile(resolveSessionRef(projectRoot, beforeRef));
  } catch (error) {
    process.stderr.write(`debug_diff: cannot read before session (${beforeRef}): ${error.message}\n`);
    process.exitCode = 1;
    return;
  }
  let afterEntries;
  try {
    afterEntries = await readSessionFile(resolveSessionRef(projectRoot, afterRef));
  } catch (error) {
    process.stderr.write(`debug_diff: cannot read after session (${afterRef}): ${error.message}\n`);
    process.exitCode = 1;
    return;
  }
  const diff = computeDiff(beforeEntries, afterEntries);
  const rendered = format === 'json' ? renderJson(diff) : format === 'md' ? renderMarkdown(diff) : renderTable(diff);
  process.stdout.write(rendered);
};

if (require.main === module) {
  main().catch((error) => {
    // Same discipline as debug_viewer: runtime failures surface as one
    // clean line on stderr, never a raw Node stack dump.
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { computeDiff, renderJson, renderMarkdown, renderTable };
```

- [ ] **Step 4: Verify green**

Run: `node --test --test-concurrency=1 scripts/debug_diff.test.js` — 13/13 pass. `node --check scripts/debug_diff.js` clean.

Post-review hardening (same Task 5 scope, folded into the fenced blocks above):
report-forgery escaping (`escapeText`) for stored msg/note/title in both human
renderers; non-string/missing hypothesis ids excluded from the report and
counted in `summary.ignoredMalformedIds` instead of crashing `renderTable`;
fail-closed CLI argv parsing (unknown flags, duplicate `--format`, and the
bare `--format` space form all exit 2); before/after read errors reported
separately, naming which ref failed; and the table's id column width is
sampled across every rendered id (capped at 40 chars, ellipsis-truncated)
instead of only the first row.

- [ ] **Step 5: Commit**

```bash
git add scripts/debug_diff.js scripts/debug_diff.test.js
git commit -m "feat(tools): debug_diff engine with table/md/json renderers

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 6: Documentation

**Files:** `SKILL.md`, `README.md`

- [ ] **Step 1: SKILL.md — "Analyze & Verify tooling" subsection**

After the Troubleshooting table's section (Grep `## Troubleshooting` and place the new `##` section immediately BEFORE it), insert:

```markdown
## Analyze & Verify Tooling

Phase 5 (Analyze) — watch and filter a session:

```bash
# Human: layout-C TUI (stream over hypothesis verdict table)
node /path/to/debug/scripts/debug_viewer.js "$PROJECT" --session <id>
# Agent: same filters, verbatim NDJSON on stdout (auto-selected when piped)
node /path/to/debug/scripts/debug_viewer.js "$PROJECT" --session <id> --hypothesis H1 --type event --json
```

Phase 7 (Verify) — compare before-fix and after-fix sessions per hypothesis:

```bash
# Piped default is stable schema:1 JSON (never scrape the table)
node /path/to/debug/scripts/debug_diff.js <before-id> <after-id> "$PROJECT"
# PR-ready markdown
node /path/to/debug/scripts/debug_diff.js <before-id> <after-id> "$PROJECT" --format=md
```

The diff reports recorded verdict transitions and deterministic deltas (event counts,
disappeared messages) only — it never classifies severity or infers failures.
```

- [ ] **Step 2: README — tools blurb**

In README, after the "Debug collector trust model" section's final paragraph, add:

```markdown
### Evidence tools

`scripts/debug_viewer.js` (layout-C TUI for humans; verbatim filtered NDJSON for agents when
piped) and `scripts/debug_diff.js` (per-hypothesis before/after report; TTY-aware default —
table interactively, versioned `schema: 1` JSON when piped; `--format=md` for PR comments)
consume session logs through the shared `scripts/debug_evidence.js` core, whose filter
semantics are test-guaranteed identical to `GET /sessions/:id/logs`.
```

- [ ] **Step 3: Validate and commit**

Run: `npm run validate` → PASS (payload gains three scripts + three test files; the validator ships `scripts/` wholesale). `node --check` all three new scripts.

```bash
git add SKILL.md README.md
git commit -m "docs(tools): viewer and diff usage for Analyze/Verify phases

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 7: Full verification

- [ ] **Step 1:** `npm test` — 0 fail (the three new test files join the suite; pre-existing skips OK).
- [ ] **Step 2:** `npm run validate` → PASS; `npm run scan:suppressions` → no findings.
- [ ] **Step 3:** `git diff 112a0de...HEAD` reviewed against the spec: three new modules + three test files + two doc files + spec/plan docs; `scripts/debug_server.js` and its tests UNTOUCHED.
- [ ] **Step 4:** Report honestly; final whole-implementation review follows via the coordinator.

