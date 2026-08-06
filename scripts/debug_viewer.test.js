const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { mkdtemp, mkdir, readFile, rm, writeFile } = require('node:fs/promises');
const http = require('node:http');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { createInitialState, parseViewerArgs, reduce, renderFrame } = require('./debug_viewer');

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
