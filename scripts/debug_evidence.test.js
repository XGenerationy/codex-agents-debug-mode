const assert = require('node:assert/strict');
const { mkdtemp, mkdir, rm, writeFile } = require('node:fs/promises');
const http = require('node:http');
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
