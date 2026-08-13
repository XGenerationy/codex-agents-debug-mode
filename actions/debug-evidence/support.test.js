'use strict';

const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const {
  closeSync, constants, existsSync, openSync, readFileSync, readdirSync, unlinkSync, utimesSync,
  writeFileSync, writeSync, mkdirSync, mkdtempSync, rmSync, symlinkSync,
} = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  defaultSpawnReport,
  finishSubcommand,
  httpRequestJson,
  maskValue,
  readState,
  redactKnownSecrets,
  reportSubcommand,
  resolveEvidenceDir,
  runSubcommand,
  startSubcommand,
  teardownSubcommand,
  validateActionInputs,
  withStateLock,
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

// A stand-in for the spawned shim: real EventEmitters (so a test drives the
// handshake by emitting), plus the stream/child methods startSubcommand calls
// on the success path, plus a kill LEDGER — an orphaned collector is exactly
// what several of these tests exist to catch, so "did it kill the child" has
// to be observable rather than assumed (Codex T3 #7).
const fakeChild = () => {
  const child = new EventEmitter();
  child.kills = [];
  child.kill = (...args) => { child.kills.push(args); return true; };
  child.unref = () => {};
  for (const name of ['stdout', 'stderr']) {
    const stream = new EventEmitter();
    stream.resume = () => {};
    stream.unref = () => {};
    stream.destroy = () => { throw new Error('the parent must RELEASE the shim pipes, never destroy them'); };
    child[name] = stream;
  }
  return child;
};

// Probe the symlink privileges once, eagerly, so the tests below declare
// their skips through the `skip` OPTION rather than an in-body t.skip() (this
// repo's suppression scanner classifies the latter as test-weakening, and an
// in-body skip also registers as a zero-assertion pass; mirrors
// scripts/pr_closeout_github.test.js). Probed separately because Windows
// treats them differently: a junction needs no privilege, a file symlink
// needs SeCreateSymbolicLinkPrivilege.
const symlinkProbeRoot = mkdtempSync(path.join(os.tmpdir(), 'debug-evidence-symlink-probe-'));
let directorySymlinkAvailable = false;
let fileSymlinkAvailable = false;
try {
  mkdirSync(path.join(symlinkProbeRoot, 'target'));
  symlinkSync(path.join(symlinkProbeRoot, 'target'), path.join(symlinkProbeRoot, 'dir-link'), 'junction');
  directorySymlinkAvailable = true;
  writeFileSync(path.join(symlinkProbeRoot, 'file'), 'probe');
  symlinkSync(path.join(symlinkProbeRoot, 'file'), path.join(symlinkProbeRoot, 'file-link'), 'file');
  fileSymlinkAvailable = true;
} catch {
  // Left at whichever privilege the platform actually granted.
} finally {
  rmSync(symlinkProbeRoot, { recursive: true, force: true });
}

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

test('containment is not fooled by a child whose name merely starts with two dots', () => {
  const workspace = makeTempDir();
  // `<workspace>/..cache` is a CHILD of the workspace, not an escape: its
  // relative path starts with '..' without being '..' or a '../' escape,
  // precisely what a naive startsWith('..') test let through (Codex T3 #3).
  const dotted = validateActionInputs({ ...baseInputs(), outputDir: path.join(workspace, '..cache'), workspace });
  assert.ok(dotted.some((e) => /outside the repository workspace/.test(e)),
    'an inside-the-workspace ..cache directory must still be rejected');
  // The genuine sibling of the same name is outside, and must stay accepted.
  const sibling = validateActionInputs({ ...baseInputs(), outputDir: path.join(workspace, '..', '..cache'), workspace });
  assert.deepEqual(sibling, []);
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

test('a shim that never reports startup times out AND is killed, not left running', async () => {
  const outputDir = makeTempDir();
  const silent = fakeChild();
  await assert.rejects(
    () => startSubcommand({
      inputs: baseInputs(), outputDir, projectRoot: makeTempDir(), env: {},
      spawnShim: () => silent, readyTimeoutMs: 200,
    }),
    /did not report startup/,
  );
  assert.equal(silent.kills.length, 1, 'the timed-out child must be killed, never abandoned');
});

test('start surfaces the shim error line: a structured stderr reason reaches the thrown message', async () => {
  const outputDir = makeTempDir();
  const child = fakeChild();
  const starting = startSubcommand({
    inputs: baseInputs(), outputDir, projectRoot: makeTempDir(), env: {},
    spawnShim: () => child, readyTimeoutMs: 5_000,
  });
  // stderr arrives, THEN the process goes away. Keying the failure path on
  // 'exit' raced this chunk and reported the generic message instead; 'close'
  // waits for the stream to drain (Codex T3 #6).
  setImmediate(() => {
    child.stderr.emit('data', `${JSON.stringify({ status: 'error', reason: 'port_in_use' })}\n`);
    child.emit('close', 1, null);
  });
  await assert.rejects(starting, /did not report startup: port_in_use/);
});

test('a spawn failure rejects instead of escaping as an uncaught error event', async () => {
  const outputDir = makeTempDir();
  const child = fakeChild();
  const starting = startSubcommand({
    inputs: baseInputs(), outputDir, projectRoot: makeTempDir(), env: {},
    spawnShim: () => child, readyTimeoutMs: 5_000,
  });
  setImmediate(() => child.emit('error', Object.assign(new Error('spawn node ENOENT'), { code: 'ENOENT' })));
  await assert.rejects(starting, /failed to spawn: spawn node ENOENT/);
});

test('start kills the collector when its state cannot be recorded, leaving no unrecorded child', async () => {
  const outputDir = makeTempDir();
  // A DIRECTORY pre-planted at the state path is a state-write failure on
  // every platform (an unwritable directory is not portable to Windows), and
  // it exercises the new no-follow lstat guard at the same time.
  mkdirSync(path.join(outputDir, 'action-state.json'));
  const child = fakeChild();
  const killed = [];
  const starting = startSubcommand({
    inputs: baseInputs(), outputDir, projectRoot: makeTempDir(), env: {},
    spawnShim: () => child,
    probeReady: async () => ({ project_hash: 'hash', ready: true }),
    kill: (pid) => { killed.push(pid); },
    readyTimeoutMs: 5_000,
  });
  setImmediate(() => child.stdout.emit('data', `${JSON.stringify({
    status: 'started', port: 8787, pid: 4242, project_hash: 'hash', launch_token: 'x'.repeat(43),
  })}\n`));
  await assert.rejects(starting, /non-regular file/);
  assert.deepEqual(killed, [4242], 'a collector whose pid was never persisted must be killed on the spot');
});

test('a healthy start records state first, then RELEASES the shim pipes instead of destroying them', async () => {
  const outputDir = makeTempDir();
  const child = fakeChild();
  const released = [];
  const killed = [];
  for (const name of ['stdout', 'stderr']) {
    child[name].resume = () => released.push(`${name}:resume`);
    child[name].unref = () => released.push(`${name}:unref`);
  }
  const starting = startSubcommand({
    inputs: baseInputs(), outputDir, projectRoot: makeTempDir(), env: {},
    spawnShim: () => child,
    probeReady: async () => ({ project_hash: 'hash', ready: true }),
    kill: (pid) => { killed.push(pid); },
    readyTimeoutMs: 5_000,
  });
  setImmediate(() => child.stdout.emit('data', `${JSON.stringify({
    status: 'started', port: 8787, pid: 4242, project_hash: 'hash', launch_token: 'x'.repeat(43),
  })}\n`));
  assert.equal(await starting, 0);
  // fakeChild's destroy() throws, so getting here at all proves neither pipe
  // was destroyed — the collector outlives this step and would take EPIPE on
  // every later write into a closed pipe (Codex T3 #1).
  assert.deepEqual(released, ['stdout:resume', 'stdout:unref', 'stderr:resume', 'stderr:unref']);
  assert.equal(child.stdout.listenerCount('data'), 0, 'the data listener is dropped so the pipe just drains');
  assert.deepEqual(killed, [], 'a healthy start never kills its own collector');
  assert.equal(readState(outputDir).pid, 4242);
});

test('writeState commits over an existing state file and leaves no staging file behind', () => {
  const outputDir = makeTempDir();
  writeState(outputDir, { nonce: 'n1' });
  writeState(outputDir, { nonce: 'n2' });
  assert.equal(readState(outputDir).nonce, 'n2', 'the rename-over-existing path must commit the new state');
  assert.deepEqual(readdirSync(outputDir), ['action-state.json'],
    'the exclusively-created temp sibling must not survive the commit');
});

test('a short write can never commit a truncated, unparsable state file', () => {
  const outputDir = makeTempDir();
  const state = { nonce: 'n1', pid: 4242, port: 8787, launchToken: 'x'.repeat(43) };
  // The seam is the writer. This one reproduces exactly what a bare
  // writeSync() does when the OS accepts only part of the buffer and the
  // caller ignores the returned count: one byte lands, the call returns, and
  // the old code renamed that truncation into place — `start` then reported
  // success while readState() returned null forever after, so teardown found
  // no pid and orphaned a live collector (Codex T3 r2).
  const shortWrite = (fd, text) => { writeSync(fd, Buffer.from(text, 'utf8').subarray(0, 1)); };
  assert.throws(() => writeState(outputDir, state, { writeAll: shortWrite }), /partially written/);
  assert.deepEqual(readdirSync(outputDir), [],
    'a truncated staging file is never committed and never left behind');
  assert.equal(readState(outputDir), null);
  // The real writer completes the payload, so the commit does happen and the
  // committed file parses back to the whole state.
  writeState(outputDir, state);
  assert.deepEqual(readState(outputDir), state);
  assert.deepEqual(readdirSync(outputDir), ['action-state.json']);
});

test('writeState refuses to follow a symlink planted at the state path', {
  skip: !fileSymlinkAvailable && 'file symlinks unavailable here (need SeCreateSymbolicLinkPrivilege on Windows)',
}, () => {
  const outputDir = makeTempDir();
  const elsewhere = path.join(makeTempDir(), 'planted.json');
  writeFileSync(elsewhere, 'untouched\n');
  symlinkSync(elsewhere, path.join(outputDir, 'action-state.json'), 'file');
  assert.throws(() => writeState(outputDir, { nonce: 'n1' }), /non-regular file/);
  assert.equal(readFileSync(elsewhere, 'utf8'), 'untouched\n',
    'the launch token must never be written through a planted symlink');
});

test('start refuses an output-dir that only lands inside the workspace once symlinks are resolved', {
  skip: !directorySymlinkAvailable && 'directory symlinks unavailable here',
}, async () => {
  const spawns = [];
  const spawnShim = () => { spawns.push(1); return fakeChild(); };
  // Case 1: the output-dir is a link that points back into the checkout.
  const workspace = makeTempDir();
  const insideTarget = path.join(workspace, 'evidence');
  mkdirSync(insideTarget);
  const link = path.join(makeTempDir(), 'looks-outside');
  symlinkSync(insideTarget, link, 'junction');
  assert.deepEqual(validateActionInputs({ ...baseInputs(), outputDir: link, workspace }), [],
    'lexically this path is outside the workspace — only realpath can tell');
  await assert.rejects(
    () => startSubcommand({
      inputs: baseInputs(), outputDir: link, projectRoot: makeTempDir(),
      env: { GITHUB_WORKSPACE: workspace }, spawnShim,
    }),
    /must be outside the repository workspace/,
  );
  // Case 2, the mirror image: the WORKSPACE is the link, and the output-dir
  // is written as a real path under the directory it points at.
  const realWorkspace = makeTempDir();
  const workspaceLink = path.join(makeTempDir(), 'ws-link');
  symlinkSync(realWorkspace, workspaceLink, 'junction');
  const nested = path.join(realWorkspace, 'evidence');
  assert.deepEqual(validateActionInputs({ ...baseInputs(), outputDir: nested, workspace: workspaceLink }), []);
  await assert.rejects(
    () => startSubcommand({
      inputs: baseInputs(), outputDir: nested, projectRoot: makeTempDir(),
      env: { GITHUB_WORKSPACE: workspaceLink }, spawnShim,
    }),
    /must be outside the repository workspace/,
  );
  assert.deepEqual(spawns, [], 'containment is settled before any collector is spawned');
});

test('the shim splits redact-names on whitespace as well as commas, so "A B,C" is three names', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const port = await getFreePort();
  // Deliberately NON-credential-looking names: anything matching the
  // collector's auto-sensitive name pattern would be redacted even if the
  // split dropped it, and the test would pass while proving nothing.
  const values = {
    ALPHA_VALUE: 'alpha1111aaaa',
    BRAVO_VALUE: 'bravo2222bbbb',
    CHARLIE_VALUE: 'charlie3333cccc',
  };
  const code = await startSubcommand({
    inputs: baseInputs({ port: String(port), redactNames: 'ALPHA_VALUE BRAVO_VALUE,CHARLIE_VALUE' }),
    outputDir,
    projectRoot,
    env: { ...values },
  });
  assert.equal(code, 0);
  const state = readState(outputDir);
  try {
    const minted = await fetch(`http://127.0.0.1:${port}/session`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', Authorization: `Bearer ${state.launchToken}` },
      body: JSON.stringify({ name: 'ci-debug' }),
    });
    assert.equal(minted.status, 201);
    const session = await minted.json();
    const recorded = await fetch(`http://127.0.0.1:${port}/log`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-debug-session-token': session.session_token },
      body: JSON.stringify({
        sessionId: session.session_id,
        msg: `leaked ${values.ALPHA_VALUE} then ${values.BRAVO_VALUE} then ${values.CHARLIE_VALUE}`,
      }),
    });
    assert.equal(recorded.status, 202);
    const line = readFileSync(path.join(projectRoot, '.debug', `debug-${session.session_id}.log`), 'utf8');
    for (const [name, value] of Object.entries(values)) {
      assert.ok(!line.includes(value), `${name}: a comma-only split would have left this value in the log`);
    }
    assert.match(line, /\[REDACTED\]/);
  } finally {
    teardownSubcommand({ outputDir, env: {} });
  }
});

test('redactKnownSecrets replaces every occurrence of each known token and ignores short values', () => {
  const secret = ['tok', 'en-', 'abcdefghij'].join('');
  assert.equal(redactKnownSecrets(`x ${secret} y ${secret}`, [secret, 'short']),
    'x [REDACTED] y [REDACTED]');
});

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
    // Occupant auth now runs first and would reject port 1 on its own, which
    // would make this test pass while proving nothing about the mint path.
    probeToken: async () => true,
    request: async () => ({ status: 401, json: { error: 'unauthorized' } }),
    spawnCommand: () => { commandRan = true; return { status: 0 }; },
  });
  assert.equal(code, 3);
  assert.equal(commandRan, false, 'no command execution after a failed mint');
});

// A raw TCP peer that speaks just enough HTTP to be hostile. node:http cannot
// produce these responses on the server side — it will not promise a
// Content-Length it then declines to honour — so the bad-peer cases below
// drive a socket directly.
const rawHttpPeer = async (respond) => {
  const sockets = [];
  const server = net.createServer((socket) => {
    sockets.push(socket);
    socket.on('error', () => {}); // the client hangs up on us by design
    socket.once('data', () => respond(socket));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolve) => server.close(resolve));
    },
  };
};

test('maskValue registers a value with the runner only under GITHUB_ACTIONS=true', () => {
  const written = [];
  const write = (text) => written.push(text);
  maskValue({ GITHUB_ACTIONS: 'true' }, 'launch-token-value', write);
  assert.deepEqual(written, ['::add-mask::launch-token-value\n']);
  written.length = 0;
  // Anything but the literal 'true' means no runner is listening, and the
  // command would print the secret it exists to hide onto a plain terminal.
  for (const env of [{}, { GITHUB_ACTIONS: 'false' }, { GITHUB_ACTIONS: '1' }, { GITHUB_ACTIONS: 'TRUE' }]) {
    maskValue(env, 'launch-token-value', write);
  }
  assert.deepEqual(written, [], 'outside Actions the command is noise carrying a secret');
  maskValue({ GITHUB_ACTIONS: 'true' }, '', write);
  assert.deepEqual(written, [], 'an empty value masks nothing and Actions rejects it anyway');
});

test('start masks the launch token the moment the handshake yields it, before the probe or any state write', async () => {
  const outputDir = makeTempDir();
  const child = fakeChild();
  const launchToken = 'x'.repeat(43);
  // One ledger for both the mask writes and the readiness probe, so ORDER is
  // asserted rather than mere occurrence: masking after the token had already
  // been used would satisfy a presence-only check while leaving the window
  // NODE_DEBUG=http leaks through wide open (Codex T4 #1).
  const ledger = [];
  const starting = startSubcommand({
    inputs: baseInputs(), outputDir, projectRoot: makeTempDir(),
    env: { GITHUB_ACTIONS: 'true' },
    spawnShim: () => child,
    probeReady: async () => { ledger.push('probe-ready'); return { project_hash: 'hash', ready: true }; },
    writeStdout: (text) => ledger.push(text),
    readyTimeoutMs: 5_000,
  });
  setImmediate(() => child.stdout.emit('data', `${JSON.stringify({
    status: 'started', port: 8787, pid: 4242, project_hash: 'hash', launch_token: launchToken,
  })}\n`));
  assert.equal(await starting, 0);
  assert.deepEqual(ledger, [`::add-mask::${launchToken}\n`, 'probe-ready']);
  assert.equal(readState(outputDir).launchToken, launchToken, 'masking does not disturb what start records');
});

test('run masks the session token the moment it is minted, before the hypothesis post and the wrapped command', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43), sessionName: 'ci-debug',
    hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo',
  });
  const sessionToken = 'z'.repeat(43);
  const ledger = [];
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: { GITHUB_ACTIONS: 'true' },
    probeToken: async () => true,
    request: async ({ path: requestPath }) => {
      ledger.push(`request ${requestPath}`);
      return requestPath === '/session'
        ? { status: 201, json: { session_id: 'ci-debug-abc', session_token: sessionToken } }
        : { status: 202, json: { status: 'recorded' } };
    },
    spawnCommand: () => { ledger.push('spawn'); return { status: 0 }; },
    writeStdout: (text) => ledger.push(text),
  });
  assert.equal(code, 0);
  assert.deepEqual(ledger, [
    'request /session',
    `::add-mask::${sessionToken}\n`,
    'request /hypothesis',
    'spawn',
  ]);
});

test('httpRequestJson always settles: a lying Content-Length, a trickling peer, and an over-cap body all reject', async () => {
  // 1. Headers promise 100 bytes, ten arrive, then the peer hangs up. The old
  // helper saw neither 'end' nor 'error' on this path, so the promise never
  // settled and run() waited out the entire job (Codex T4 #2, reproduced).
  const liar = await rawHttpPeer((socket) => {
    socket.write('HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"partial"');
    setTimeout(() => socket.destroy(), 20);
  });
  try {
    const startedAt = Date.now();
    await assert.rejects(
      () => httpRequestJson({ port: liar.port, method: 'POST', path: '/session', body: { name: 'ci-debug' } }),
      (error) => error instanceof Error,
    );
    // Asserting PROMPTNESS rather than a message: the point is that the
    // premature close settled it, not that some timeout eventually did. The
    // exact wording Node attaches to a mid-body reset varies by version.
    assert.ok(Date.now() - startedAt < 2_000, 'the premature close settled it, no timeout was needed');
  } finally {
    await liar.close();
  }

  // 2. One byte every 25ms resets the 5s inactivity timeout forever, so only a
  // wall-clock deadline can stop it. Shortened through the seam; the shipped
  // default is 10s.
  let trickle;
  const trickler = await rawHttpPeer((socket) => {
    socket.write('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n');
    trickle = setInterval(() => socket.write('x'), 25);
    socket.on('close', () => clearInterval(trickle));
  });
  try {
    const startedAt = Date.now();
    await assert.rejects(
      () => httpRequestJson({ port: trickler.port, method: 'GET', path: '/health', deadlineMs: 400 }),
      /exceeded 400ms/,
    );
    assert.ok(Date.now() - startedAt < 4_000, 'the deadline fired; the 5s inactivity timeout never could');
  } finally {
    clearInterval(trickle);
    await trickler.close();
  }

  // 3. Two megabytes is past the 1 MiB cap: rejected and the socket destroyed
  // rather than buffered into this process's heap.
  const flood = await rawHttpPeer((socket) => {
    socket.write('HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2097152\r\n\r\n');
    socket.write('x'.repeat(2 * 1024 * 1024));
  });
  try {
    await assert.rejects(
      () => httpRequestJson({ port: flood.port, method: 'GET', path: '/health' }),
      /exceeded 1048576 bytes/,
    );
  } finally {
    await flood.close();
  }
});

test('run authenticates the port occupant and never sends the launch token to one that fails', async () => {
  const outputDir = makeTempDir();
  const launchToken = 'x'.repeat(43);
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 4321, launchToken, sessionName: 'ci-debug' });
  const probes = [];
  let requested = 0;
  let commandRan = false;
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: {},
    probeToken: async (port, token) => { probes.push([port, token]); return false; },
    request: async () => { requested += 1; return { status: 201, json: {} }; },
    spawnCommand: () => { commandRan = true; return { status: 0 }; },
  });
  assert.equal(code, 3);
  assert.deepEqual(probes, [[4321, launchToken]], 'the recorded port and token are what get challenged');
  assert.equal(requested, 0, 'a process that cannot prove it holds the token never receives it');
  assert.equal(commandRan, false);
});

test('state writes serialize: the invocation that lost the output-dir refuses, and the winner survives intact', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43), sessionName: 'ci-debug' });
  const githubOutput = path.join(outputDir, 'github_output');
  writeFileSync(githubOutput, '');
  const lockPath = path.join(outputDir, 'action-state.lock');
  const usurper = { nonce: 'n2', pid: 2222, port: 9999, launchToken: 'y'.repeat(43), sessionName: 'other' };
  const order = [];
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: { GITHUB_OUTPUT: githubOutput },
    probeToken: async () => true,
    request: async () => ({ status: 201, json: { session_id: 'ci-debug-abc', session_token: 'z'.repeat(43) } }),
    // Invocation B claims the output-dir while A sits blocked in its wrapped
    // command. B goes through the SAME locked API A's commit will use, so the
    // two are ordered by the lock rather than by luck (Codex T4 r2).
    spawnCommand: () => withStateLock(outputDir, () => {
      // Mutual exclusion is real, not advisory: while B holds the lock, the
      // exact open() A's critical section performs fails EEXIST. Without this
      // the test would only re-prove the nonce compare, which is the
      // check-then-act this round exists to replace.
      assert.throws(
        () => closeSync(openSync(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600)),
        /EEXIST/,
        'a second holder must not be able to enter while B is inside',
      );
      writeState(outputDir, usurper);
      order.push('B committed');
      return { status: 0 };
    }),
  });
  assert.deepEqual(order, ['B committed'], 'B ran its whole critical section before A opened its own');
  assert.equal(code, 3, 'A re-read under the lock, saw a nonce it does not own, and stood down');
  assert.deepEqual(readState(outputDir), usurper, 'the newer invocation keeps its state, byte for byte');
  assert.equal(readFileSync(githubOutput, 'utf8'), '',
    'a session-id emitted from state we just declined to own would be a lie');
  assert.ok(!existsSync(lockPath), 'both critical sections released the lock behind them');
});

test('a fresh lock held by another invocation makes the commit fail bounded, never hang', async () => {
  const outputDir = makeTempDir();
  const recorded = { nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43), sessionName: 'ci-debug' };
  writeState(outputDir, recorded);
  const githubOutput = path.join(outputDir, 'github_output');
  writeFileSync(githubOutput, '');
  // Held and FRESH, so the stale sweep must not touch it: only the retry
  // budget can end this wait.
  const lockPath = path.join(outputDir, 'action-state.lock');
  writeFileSync(lockPath, '');
  const startedAt = Date.now();
  await assert.rejects(
    () => runSubcommand({
      inputs: baseInputs(),
      outputDir,
      env: { GITHUB_OUTPUT: githubOutput },
      probeToken: async () => true,
      request: async () => ({ status: 201, json: { session_id: 'ci-debug-abc', session_token: 'z'.repeat(43) } }),
      spawnCommand: () => ({ status: 0 }),
    }),
    /could not acquire the action state lock/,
  );
  const elapsed = Date.now() - startedAt;
  assert.ok(elapsed < 5_000,
    `the retry budget bounded the wait at ${elapsed}ms, nowhere near the 30s stale threshold`);
  assert.deepEqual(readState(outputDir), recorded, 'the holder\'s state is left exactly as it was');
  assert.equal(readFileSync(githubOutput, 'utf8'), '', 'a run that never committed emits no outputs');
  assert.ok(existsSync(lockPath), 'a lock this invocation never acquired must not be released by it');
});

test('a lock older than the stale threshold is reaped so a crashed invocation cannot wedge the output-dir forever', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43), sessionName: 'ci-debug' });
  const lockPath = path.join(outputDir, 'action-state.lock');
  writeFileSync(lockPath, '');
  // Backdated past the threshold: indistinguishable from a runner that was
  // cancelled or OOM-killed mid-write and never released.
  const longAgo = new Date(Date.now() - 120_000);
  utimesSync(lockPath, longAgo, longAgo);
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: {},
    probeToken: async () => true,
    request: async () => ({ status: 201, json: { session_id: 'ci-debug-abc', session_token: 'z'.repeat(43) } }),
    spawnCommand: () => ({ status: 0 }),
  });
  assert.equal(code, 0);
  assert.equal(readState(outputDir).sessionId, 'ci-debug-abc', 'the reaped lock did not block the commit');
  assert.ok(!existsSync(lockPath), 'the replacement lock is released too, not leaked');
});

test('a job-level DEBUG_HYPOTHESIS_ID is never inherited when this action opened no hypothesis', async () => {
  const { outputDir, inputs } = await startReal();
  try {
    const probe = 'node -e "process.exit(process.env.DEBUG_HYPOTHESIS_ID === undefined ? 0 : 91)"';
    const code = await runSubcommand({
      inputs: { ...inputs, runCommand: probe },
      outputDir,
      env: { DEBUG_HYPOTHESIS_ID: 'H-from-the-job' },
    });
    assert.equal(code, 0);
    assert.equal(readState(outputDir).commandExitCode, 0,
      'the wrapped command must not see a hypothesis id this action never posted');
  } finally {
    teardownSubcommand({ outputDir, env: {} });
  }
});

const sleepFor = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test('a reaper whose stale lock is replaced between observation and deletion leaves the successor standing', async () => {
  const outputDir = makeTempDir();
  const lockPath = path.join(outputDir, 'action-state.lock');
  // A crashed invocation's litter, old enough to be judged stale.
  const staleContent = '4242\nstale-holder-token\n';
  writeFileSync(lockPath, staleContent);
  const longAgo = new Date(Date.now() - 120_000);
  utimesSync(lockPath, longAgo, longAgo);
  const successor = '777\nsuccessor-token\n';
  let observedStale = null;
  const startedAt = Date.now();
  await assert.rejects(
    () => withStateLock(
      outputDir,
      () => { throw new Error('the critical section must never be entered here'); },
      {
        // The second reaper wins the race: between THIS one establishing
        // staleness and its unlink, the other removes the stale file and
        // takes the path with a fresh lock of its own. An owner-blind unlink
        // would delete that live lock and admit a third writer (Codex T4 r3).
        onStaleObserved: ({ observed }) => {
          observedStale = observed;
          unlinkSync(lockPath);
          writeFileSync(lockPath, successor);
        },
      },
    ),
    /could not acquire the action state lock/,
  );
  assert.equal(observedStale, staleContent, 'staleness was judged against the bytes that were actually there');
  assert.equal(readFileSync(lockPath, 'utf8'), successor,
    'the winner\'s fresh lock must survive the losing reaper');
  const elapsed = Date.now() - startedAt;
  assert.ok(elapsed < 5_000, `the loser failed bounded at ${elapsed}ms rather than spinning or deleting`);
  unlinkSync(lockPath);
});

test('a holder whose lock was reaped and replaced releases without evicting the successor', async () => {
  const outputDir = makeTempDir();
  const lockPath = path.join(outputDir, 'action-state.lock');
  const successor = '999\nsuccessor-token\n';
  let stamped = null;
  await withStateLock(outputDir, () => {
    stamped = readFileSync(lockPath, 'utf8');
    // A reaper judged this holder stale, deleted its lock, and a successor
    // took the path. This holder is now a ghost: its fd is still open, but
    // the lock on disk is someone else's.
    unlinkSync(lockPath);
    writeFileSync(lockPath, successor);
  });
  assert.match(stamped, new RegExp(`^${process.pid}\\n[0-9a-f-]{36}\\n$`),
    'the lock is stamped with its holder pid and a per-acquisition uuid');
  assert.equal(readFileSync(lockPath, 'utf8'), successor,
    'the release must not delete a lock this holder no longer owns');
  unlinkSync(lockPath);
});

test('withStateLock serializes concurrent holders: one inside at a time, nothing left behind', async () => {
  const outputDir = makeTempDir();
  const lockPath = path.join(outputDir, 'action-state.lock');
  let inside = 0;
  let maxConcurrent = 0;
  const order = [];
  // Six is chosen against the shipped budget: contenders retry every 50ms, so
  // the last one waits ~250ms of the ~450ms allowance.
  const holders = Array.from({ length: 6 }, (_, index) => withStateLock(outputDir, async () => {
    inside += 1;
    maxConcurrent = Math.max(maxConcurrent, inside);
    order.push(`enter-${index}`);
    await sleepFor(2); // yield inside the section, so an overlap could be observed
    order.push(`exit-${index}`);
    inside -= 1;
  }));
  await Promise.all(holders);
  assert.equal(maxConcurrent, 1, 'two holders inside at once is the entire failure this lock prevents');
  assert.equal(order.length, 12);
  // Every enter is immediately followed by its OWN exit: no interleaving.
  for (let i = 0; i < order.length; i += 2) {
    assert.equal(order[i].replace('enter-', ''), order[i + 1].replace('exit-', ''),
      `${order[i]} was interrupted before it left the critical section`);
  }
  assert.ok(!existsSync(lockPath), 'the last release left no lock behind');
});

test('a wrapped command killed by a signal records the 128 sentinel and the signal that did it', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43), sessionName: 'ci-debug' });
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: {},
    probeToken: async () => true,
    request: async () => ({ status: 201, json: { session_id: 'ci-debug-abc', session_token: 'z'.repeat(43) } }),
    // spawnSync reports a signal death as status null + signal name. `status
    // ?? 128` is the only branch that turns that into a number, and a plain
    // `||` there would have mapped a clean exit 0 to 128 as well — so the
    // sentinel needs its own pin, not just the ordinary exit-code path.
    spawnCommand: () => ({ status: null, signal: 'SIGKILL' }),
  });
  assert.equal(code, 0, 'run still succeeds; finish owns the verdict');
  const state = readState(outputDir);
  assert.equal(state.commandExitCode, 128, 'no exit code exists, so the 128+signal convention stands in');
  assert.equal(state.commandSignal, 'SIGKILL', 'the signal name is recorded, not merely the sentinel');
});

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

test('report captures the session from the collector, renders md+json, appends the summary, and emits outputs — token bytes never enter the evidence child', async () => {
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
    // Nothing tampered with this log, so the collector's answer and the file
    // it wrote are the same bytes — the untampered baseline the forgery tests
    // below are read against.
    assert.equal(copied, readFileSync(path.join(context.projectRoot, '.debug', `debug-${state.sessionId}.log`), 'utf8'),
      'an untouched session serves exactly what it stored');
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
    assert.equal(state.collectorAlive, true, 'the collector answered an authenticated challenge');
    assert.equal(state.evidenceCopied, true);
    assert.equal(state.evidenceAuthentic, true, 'the staged bytes came from the collector, not a pathname');
    assert.equal(state.reportRendered, true);
    // The capture flags are ADDED to whatever run recorded, never written
    // from report's own pre-capture snapshot: the CAS re-reads the file under
    // the lock and spreads THAT, so nothing run committed is rolled back
    // (Codex T4 #3/r2, applied to report).
    assert.ok(state.sessionId.startsWith('ci-debug-'), 'run\'s session id survives report\'s commit');
    assert.equal(state.commandExitCode, 1, 'and so does the exit code it recorded');
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: {} });
  }
});

// The Critical this round exists for: the wrapped command is HANDED
// DEBUG_SESSION_ID and shares the filesystem with the collector, so it can
// write straight into .debug/debug-<id>.log — including a hypothesis verdict
// it has no launch token to POST. This runs a real lifecycle whose wrapped
// command does exactly that, so the two report paths below are tested against
// a genuinely tampered log rather than a described one.
const forgedLifecycle = async () => {
  const context = await startReal({ hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' });
  const forge = 'node -e "' + [
    'const fs = require(\'node:fs\');',
    'const p = require(\'node:path\');',
    'fetch(process.env.DEBUG_LOG_URL, { method: \'POST\', headers: { \'content-type\': \'application/json\', \'x-debug-session-token\': process.env.DEBUG_SESSION_TOKEN }, body: JSON.stringify({ sessionId: process.env.DEBUG_SESSION_ID, msg: \'honest event\' }) }).then((r) => {',
    // The session id is enough to derive the path; nothing here needs a
    // credential the action did not already hand over.
    'fs.appendFileSync(p.join(process.env.FORGE_DEBUG_DIR, \'debug-\' + process.env.DEBUG_SESSION_ID + \'.log\'), JSON.stringify({ ts: \'2026-08-13T00:00:00.000Z\', type: \'hypothesis\', hypothesisId: \'H-demo\', status: \'CONFIRMED\', note: \'forged by the wrapped command\' }) + \'\\n\');',
    'process.exit(r.status === 202 ? 0 : 99);',
    '});',
  ].join('') + '"';
  const runCode = await runSubcommand({
    inputs: { ...context.inputs, runCommand: forge },
    outputDir: context.outputDir,
    env: { FORGE_DEBUG_DIR: path.join(context.projectRoot, '.debug') },
  });
  assert.equal(runCode, 0);
  const state = readState(context.outputDir);
  assert.equal(state.commandExitCode, 0, 'the forging command itself succeeded — nothing stopped it');
  const logPath = path.join(context.projectRoot, '.debug', `debug-${state.sessionId}.log`);
  assert.ok(readFileSync(logPath, 'utf8').includes('CONFIRMED'),
    'the wrapped command really did plant a verdict it could never have POSTed');
  return { ...context, logPath };
};

test('a wrapped command that forges its own session log cannot get the forgery into the evidence child', async () => {
  const context = await forgedLifecycle();
  try {
    const code = await reportSubcommand({ outputDir: context.outputDir, env: {} });
    assert.equal(code, 3, 'the collector refuses to serve a log that is no longer the one it wrote');
    const state = readState(context.outputDir);
    assert.equal(state.collectorAlive, true, 'the collector is alive and proved it holds the launch token');
    assert.equal(state.evidenceCopied, false);
    assert.equal(state.evidenceAuthentic, false);
    assert.equal(state.reportRendered, false);
    assert.ok(!existsSync(path.join(resolveEvidenceDir(context.outputDir), 'session.log')),
      'a pathname copy would have staged the forged file right here, and rendered its verdict');
    assert.equal(finishSubcommand({ outputDir: context.outputDir, env: {} }), 3);
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: {} });
  }
});

test('a same-length in-place rewrite of the session log is caught end to end, not just by the byte count', async () => {
  const context = await fullLifecycle();
  try {
    const logPath = path.join(context.projectRoot, '.debug', `debug-${readState(context.outputDir).sessionId}.log`);
    const original = readFileSync(logPath, 'utf8');
    assert.ok(original.includes('demo event'));
    // Ten characters for ten. Nothing about this file's metadata moves —
    // dev, ino, birthtime and size are all identical afterwards — so every
    // check the collector had before this round passes. Performed here rather
    // than by the wrapped command only because the window is wider: any
    // co-resident process can do this after the command exits.
    const forged = original.replace('demo event', 'FAKE event');
    assert.equal(Buffer.byteLength(forged, 'utf8'), Buffer.byteLength(original, 'utf8'));
    writeFileSync(logPath, forged);
    const code = await reportSubcommand({ outputDir: context.outputDir, env: {} });
    // Collector: content digest mismatch → 409 session_log_tampered.
    // readSessionLive: 409 → live_read_log_replaced. report: no fallback → 3.
    assert.equal(code, 3);
    const state = readState(context.outputDir);
    assert.equal(state.collectorAlive, true);
    assert.equal(state.evidenceCopied, false);
    assert.ok(!existsSync(path.join(resolveEvidenceDir(context.outputDir), 'session.log')));
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: {} });
  }
});

test('with nothing able to prove it owns the port, a forged log is staged as labeled partial evidence and still cannot go green', async () => {
  const context = await forgedLifecycle();
  try {
    const code = await reportSubcommand({
      outputDir: context.outputDir,
      env: {},
      // No authoritative source: the run's own collector is gone (or was
      // never the thing on that port), so the filesystem is all there is.
      probeToken: async () => false,
    });
    assert.equal(code, 0, 'unverifiable bytes are still worth uploading for a human to read');
    const state = readState(context.outputDir);
    assert.equal(state.collectorAlive, false);
    assert.equal(state.evidenceCopied, true);
    assert.equal(state.evidenceAuthentic, false, 'the artifact is labeled as coming off the filesystem');
    assert.equal(state.reportRendered, true);
    const staged = readFileSync(path.join(resolveEvidenceDir(context.outputDir), 'session.log'), 'utf8');
    assert.ok(staged.includes('CONFIRMED'),
      'this really is the forged file — labeling it, not hiding it, is what makes this safe');
    assert.equal(finishSubcommand({ outputDir: context.outputDir, env: {} }), 3,
      'forged bytes can be inspected but can never ride a green run');
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: {} });
  }
});

test('the wrapped command is handed no DEBUG_ACTION_* wiring — least of all the path to the launch token', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43), sessionName: 'ci-debug' });
  let handed = null;
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    // A production-shaped job env: this is exactly what action.yml puts in
    // front of the run step.
    env: {
      DEBUG_ACTION_OUTPUT_DIR: outputDir,
      DEBUG_ACTION_INVOCATION_NONCE: 'n1',
      DEBUG_ACTION_PORT: '8787',
      DEBUG_ACTION_RUN: 'npm test',
      UNRELATED_JOB_VAR: 'kept',
    },
    probeToken: async () => true,
    request: async () => ({ status: 201, json: { session_id: 'ci-debug-abc', session_token: 'z'.repeat(43) } }),
    spawnCommand: (command, { env: commandEnv }) => { handed = commandEnv; return { status: 0 }; },
  });
  assert.equal(code, 0);
  assert.deepEqual(Object.keys(handed).filter((key) => key.startsWith('DEBUG_ACTION_')), [],
    'DEBUG_ACTION_OUTPUT_DIR points at action-state.json, which carries the launch token');
  assert.equal(handed.UNRELATED_JOB_VAR, 'kept', 'only the action\'s own wiring is stripped');
  // The documented injected contract is untouched by the strip.
  assert.equal(handed.DEBUG_SESSION_ID, 'ci-debug-abc');
  assert.equal(handed.DEBUG_SESSION_TOKEN, 'z'.repeat(43));
  assert.equal(handed.DEBUG_LOG_URL, 'http://127.0.0.1:1/log');
});

test('a stolen launch token buys nothing: a verdict forged through the real endpoint is refused at capture', async () => {
  const context = await startReal({ hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' });
  try {
    // The wrapped command does what any process running as the same OS user
    // can do: find the state file (its default location is derivable — here
    // the guess is handed over directly, so the test measures the DEFENCE and
    // not the attacker's search), read the launch token out of it, and post a
    // CONFIRMED verdict through the collector's real /hypothesis endpoint.
    // The collector records it as faithfully as anything else — that is the
    // point. Nothing before this round would have noticed.
    const steal = 'node -e "' + [
      'const fs = require(\'node:fs\');',
      // First, prove the easy route is closed: production hands the run step
      // DEBUG_ACTION_OUTPUT_DIR, and the wrapped command must not see it.
      'if (process.env.DEBUG_ACTION_OUTPUT_DIR !== undefined) process.exit(92);',
      'const stolen = JSON.parse(fs.readFileSync(process.env.GUESSED_STATE_PATH, \'utf8\')).launchToken;',
      'fetch(process.env.DEBUG_LOG_URL.replace(\'/log\', \'/hypothesis\'), { method: \'POST\', headers: { \'content-type\': \'application/json\', Authorization: \'Bearer \' + stolen }, body: JSON.stringify({ sessionId: process.env.DEBUG_SESSION_ID, hypothesisId: \'H-demo\', status: \'CONFIRMED\', note: \'forged with the stolen launch token\' }) }).then((r) => process.exit(r.status === 202 ? 0 : 93));',
    ].join('') + '"';
    const runCode = await runSubcommand({
      inputs: { ...context.inputs, runCommand: steal },
      outputDir: context.outputDir,
      env: {
        DEBUG_ACTION_OUTPUT_DIR: context.outputDir,
        GUESSED_STATE_PATH: path.join(context.outputDir, 'action-state.json'),
      },
    });
    assert.equal(runCode, 0);
    const state = readState(context.outputDir);
    assert.equal(state.commandExitCode, 0,
      '92 would mean the env strip failed; 93 would mean the forgery never landed and this test proves nothing');
    const onDisk = readFileSync(path.join(context.projectRoot, '.debug', `debug-${state.sessionId}.log`), 'utf8');
    assert.ok(onDisk.includes('CONFIRMED'),
      'the theft succeeded at the collector: a forged verdict is now authentically recorded');
    // Authenticated capture alone would bless it — the collector's own log is
    // intact and its identity checks all pass. Only the hypothesis-set
    // contract can tell that the action never posted that line.
    const code = await reportSubcommand({ outputDir: context.outputDir, env: {} });
    assert.equal(code, 3);
    const after = readState(context.outputDir);
    assert.equal(after.collectorAlive, true, 'the collector is healthy; the EVIDENCE is not');
    assert.equal(after.evidenceCopied, false);
    assert.equal(after.evidenceAuthentic, false);
    assert.ok(!existsSync(path.join(resolveEvidenceDir(context.outputDir), 'session.log')),
      'a forged verdict never reaches the artifact');
    assert.equal(finishSubcommand({ outputDir: context.outputDir, env: {} }), 3);
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

test('report refuses a state carrying another invocation\'s nonce before it touches the collector', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43),
    sessionId: 'ci-debug-abc', projectRoot: makeTempDir(),
  });
  let probed = 0;
  const code = await reportSubcommand({
    outputDir,
    env: { DEBUG_ACTION_INVOCATION_NONCE: 'other' },
    probeToken: async () => { probed += 1; return true; },
    readLive: async () => { throw new Error('a refused report must never read a session'); },
    spawnReport: () => { throw new Error('a refused report must never reach the renderer'); },
  });
  assert.equal(code, 3);
  assert.equal(probed, 0, 'the refusal is settled from state alone, before any network contact');
});

// readSessionLive resolves [{ raw, parsed }] — parsed being JSON.parse(raw).
// Seams below build entries through this helper so a fixture can never drift
// into a shape the real collector would not produce.
const servedEntry = (line) => ({ raw: JSON.stringify(line), parsed: line });

// A hand-written session log: the CAS path below has to be driven
// deterministically, and a real collector's timing is not the thing under
// test here.
const writeSessionLog = (projectRoot, sessionId, lines) => {
  mkdirSync(path.join(projectRoot, '.debug'), { recursive: true });
  writeFileSync(
    path.join(projectRoot, '.debug', `debug-${sessionId}.log`),
    lines.map((line) => `${JSON.stringify(line)}\n`).join(''),
  );
};

test('report stages evidence outside the lock but refuses to commit over a newer invocation, and advertises nothing it disowned', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const recorded = {
    nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43),
    sessionId: 'ci-debug-abc', projectRoot, commandExitCode: 0,
  };
  writeState(outputDir, recorded);
  writeSessionLog(projectRoot, 'ci-debug-abc', [{ ts: '2026-08-13T00:00:00.000Z', msg: 'hand written event' }]);
  const githubOutput = path.join(outputDir, 'github_output');
  const stepSummary = path.join(outputDir, 'step_summary');
  writeFileSync(githubOutput, '');
  writeFileSync(stepSummary, '');
  const usurper = { nonce: 'n2', pid: 2222, port: 9999, launchToken: 'y'.repeat(43), sessionName: 'other' };
  let claimed = false;
  const code = await reportSubcommand({
    outputDir,
    env: { GITHUB_OUTPUT: githubOutput, GITHUB_STEP_SUMMARY: stepSummary },
    probeToken: async () => true,
    readLive: async () => [servedEntry({ ts: '2026-08-13T00:00:00.000Z', msg: 'served event' })],
    // Rendering happens OUTSIDE the critical section by design — a holder
    // that spawned two child processes could sit in the section for seconds,
    // and the stale threshold is 30s (recorded T4 r2 requirement). The seam
    // uses that window to let a second invocation claim the output-dir, which
    // is exactly the interleave the lock cannot prevent and the CAS must.
    spawnReport: (args) => {
      if (!claimed) {
        claimed = true;
        writeState(outputDir, usurper);
      }
      return defaultSpawnReport(args);
    },
  });
  assert.equal(code, 3, 'the nonce compare under the lock saw state it does not own');
  assert.deepEqual(readState(outputDir), usurper, 'the newer invocation keeps its state, byte for byte');
  const evidenceDir = resolveEvidenceDir(outputDir);
  assert.ok(existsSync(path.join(evidenceDir, 'report.md')),
    'the render already happened — it runs outside the lock, so ownership is decided after it');
  assert.equal(readFileSync(githubOutput, 'utf8'), '',
    'a report-path emitted from state we just declined to own would be a lie');
  assert.equal(readFileSync(stepSummary, 'utf8'), '',
    'and so would a step summary for a run this invocation no longer owns');
  assert.ok(!existsSync(path.join(outputDir, 'action-state.lock')), 'the critical section released behind it');
});

test('report records an unauthenticated collector without inventing evidence, and finish is what fails on it', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43),
    sessionId: 'ci-debug-abc', projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
  });
  writeSessionLog(projectRoot, 'ci-debug-abc', [{ ts: '2026-08-13T00:00:00.000Z', msg: 'last words' }]);
  const code = await reportSubcommand({
    outputDir,
    env: {},
    // Dead, or replaced by something that cannot answer the challenge — the
    // two are indistinguishable from here, and both mean the same thing: no
    // authoritative source for this session's bytes.
    probeToken: async () => false,
    readLive: async () => { throw new Error('an unauthenticated port must never be asked for a session'); },
  });
  assert.equal(code, 0, 'report only fails on ITS OWN mechanical failures; a dead collector is not one');
  const state = readState(outputDir);
  assert.equal(state.collectorAlive, false);
  assert.equal(state.evidenceCopied, true, 'whatever was readable is still staged');
  assert.equal(state.evidenceAuthentic, false, 'and it is labeled as unverified in the state file');
  assert.equal(state.reportRendered, true);
  assert.equal(finishSubcommand({ outputDir, env: {} }), 3,
    'the collector being unverifiable at capture time is finish\'s verdict to make');
});

test('report returns 3 when there is nothing to stage at all — evidence is the product, so its absence fails closed', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43),
    sessionId: 'ci-debug-missing', projectRoot,
  });
  const githubOutput = path.join(outputDir, 'github_output');
  writeFileSync(githubOutput, '');
  const code = await reportSubcommand({
    outputDir,
    env: { GITHUB_OUTPUT: githubOutput },
    probeToken: async () => false,
    spawnReport: () => { throw new Error('nothing was staged, so nothing can be rendered'); },
  });
  assert.equal(code, 3);
  const state = readState(outputDir);
  assert.equal(state.evidenceCopied, false);
  assert.equal(state.evidenceAuthentic, false);
  assert.equal(state.reportRendered, false);
  assert.equal(state.collectorAlive, false, 'the liveness fact is still recorded — it was observed');
  assert.equal(readFileSync(githubOutput, 'utf8'), '', 'no report-path is emitted for a report that does not exist');
});

test('the staged log is the collector\'s answer, not whatever is on disk under that name', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const launchToken = 'x'.repeat(43);
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 4321, launchToken, hypothesisId: 'H-demo',
    sessionId: 'ci-debug-abc', projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
  });
  // What a wrapped command left at the well-known path. A pathname copy would
  // stage this; the authenticated path never opens it.
  writeSessionLog(projectRoot, 'ci-debug-abc', [{ ts: '2026-08-13T00:00:00.000Z', msg: 'FORGED disk line' }]);
  const served = [
    servedEntry({ ts: '2026-08-13T00:00:01.000Z', msg: 'served by the collector' }),
    servedEntry({ ts: '2026-08-13T00:00:02.000Z', type: 'hypothesis', hypothesisId: 'H-demo', status: 'OPEN' }),
  ];
  const reads = [];
  const code = await reportSubcommand({
    outputDir,
    env: {},
    probeToken: async () => true,
    readLive: async (options) => { reads.push(options); return served; },
  });
  assert.equal(code, 0);
  const staged = readFileSync(path.join(resolveEvidenceDir(outputDir), 'session.log'), 'utf8');
  assert.equal(staged, `${served.map((entry) => entry.raw).join('\n')}\n`,
    'the collector\'s raw lines are staged verbatim and in order');
  assert.ok(!staged.includes('FORGED disk line'), 'the file at the well-known path was never opened');
  assert.equal(readState(outputDir).evidenceAuthentic, true);
  // Reading a session is a LAUNCH-token capability, so the read is addressed
  // with exactly what start recorded — a session token would 401.
  assert.deepEqual(reads, [{ port: 4321, token: launchToken, sessionId: 'ci-debug-abc', timeoutMs: 5000 }]);
});

test('a live read the collector refuses is an evidence-integrity failure, never a reason to fall back to the disk', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43),
    sessionId: 'ci-debug-abc', projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
  });
  // Readable, parsable, and a lie. The old pathname copy would have staged
  // and rendered it (Codex T5 #1).
  writeSessionLog(projectRoot, 'ci-debug-abc', [
    { ts: '2026-08-13T00:00:00.000Z', type: 'hypothesis', hypothesisId: 'H-demo', status: 'CONFIRMED' },
  ]);
  const code = await reportSubcommand({
    outputDir,
    env: {},
    probeToken: async () => true,
    // 409 session_log_replaced: the collector's own identity check found that
    // the file it wrote is not the file on disk.
    readLive: async () => { throw new Error('live_read_log_replaced'); },
    spawnReport: () => { throw new Error('nothing was staged, so nothing can be rendered'); },
  });
  assert.equal(code, 3);
  const state = readState(outputDir);
  assert.equal(state.collectorAlive, true, 'the collector is alive and authenticated — that is why its refusal counts');
  assert.equal(state.evidenceCopied, false);
  assert.equal(state.evidenceAuthentic, false);
  assert.ok(!existsSync(path.join(resolveEvidenceDir(outputDir), 'session.log')),
    'the readable file at the well-known path is not a fallback');
  assert.equal(finishSubcommand({ outputDir, env: {} }), 3);
});

test('every way a captured hypothesis set can deviate from the one this action posted is refused', async () => {
  const openLine = { ts: '2026-08-13T00:00:01.000Z', type: 'hypothesis', hypothesisId: 'H-demo', status: 'OPEN', title: 'seeded demo' };
  const event = { ts: '2026-08-13T00:00:00.000Z', msg: 'an ordinary event, always allowed' };
  const cases = [
    ['a verdict the action never records', { hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' },
      [event, { ...openLine, status: 'CONFIRMED' }]],
    ['a hypothesis id the action never opened', { hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' },
      [event, { ...openLine, hypothesisId: 'H-other' }]],
    ['a duplicate of the action\'s own line', { hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' },
      [event, openLine, openLine]],
    ['a title that is not the one posted', { hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' },
      [event, { ...openLine, title: 'a different claim entirely' }]],
    ['any hypothesis line at all when none was configured', {},
      [event, { ...openLine, hypothesisId: 'H-uninvited' }]],
  ];
  for (const [label, hypothesisState, served] of cases) {
    const outputDir = makeTempDir();
    const projectRoot = makeTempDir();
    writeState(outputDir, {
      nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
      projectRoot, commandExitCode: 0, failOnCommandFailure: 'true', ...hypothesisState,
    });
    const code = await reportSubcommand({
      outputDir,
      env: {},
      probeToken: async () => true,
      readLive: async () => served.map(servedEntry),
      spawnReport: () => { throw new Error('forged evidence must never reach the renderer'); },
    });
    assert.equal(code, 3, label);
    assert.equal(readState(outputDir).evidenceCopied, false, label);
    assert.ok(!existsSync(path.join(resolveEvidenceDir(outputDir), 'session.log')), `${label}: nothing is staged`);
    assert.equal(finishSubcommand({ outputDir, env: {} }), 3, label);
  }
  // And the shape the action DID post is accepted, events and all — a check
  // that refused everything would pass the cases above while breaking capture.
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
    projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
    hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo',
  });
  assert.equal(await reportSubcommand({
    outputDir,
    env: {},
    probeToken: async () => true,
    readLive: async () => [event, openLine].map(servedEntry),
  }), 0, 'the action\'s own set is exactly what capture accepts');
  assert.equal(readState(outputDir).evidenceAuthentic, true);
});

test('an entry the hypothesis check cannot inspect is refused rather than skipped', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
    projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
  });
  const code = await reportSubcommand({
    outputDir,
    env: {},
    probeToken: async () => true,
    // A line whose parsed form is missing or is not an object cannot be
    // classified. Skipping it would let a forged hypothesis through any
    // future path that produced this shape, so it fails closed instead.
    readLive: async () => [{ raw: '{"type":"hypothesis","status":"CONFIRMED"}' }],
    spawnReport: () => { throw new Error('an uninspectable capture must never reach the renderer'); },
  });
  assert.equal(code, 3);
  assert.equal(readState(outputDir).evidenceCopied, false);
});

test('staging is invocation-scoped: a reused output-dir never ships a previous run\'s evidence as this one\'s', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const evidenceDir = resolveEvidenceDir(outputDir);
  mkdirSync(evidenceDir, { recursive: true });
  // What a previous invocation left behind. The upload step enumerates these
  // three names, so leaving them is shipping last run's evidence under this
  // run's artifact.
  for (const [name, body] of [['session.log', '{"msg":"last run"}\n'], ['report.md', '## stale\n'], ['report.json', '{"schema":1}\n']]) {
    writeFileSync(path.join(evidenceDir, name), body);
  }
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
    projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
  });
  const code = await reportSubcommand({
    outputDir,
    env: {},
    // This invocation captures nothing at all.
    probeToken: async () => false,
    spawnReport: () => { throw new Error('nothing was staged, so nothing can be rendered'); },
  });
  assert.equal(code, 3);
  for (const name of ['session.log', 'report.md', 'report.json']) {
    assert.ok(!existsSync(path.join(evidenceDir, name)), `${name} from a previous invocation must not survive into this one`);
  }
});

test('a renderer that exits 0 without printing a schema-1 report publishes nothing', async () => {
  const cases = [
    ['truncated JSON', '{"schema":1,"session":{"events":'],
    ['a schema this action does not speak', JSON.stringify({ schema: 2, session: { events: 3 } })],
    ['a negative event count', JSON.stringify({ schema: 1, session: { events: -1 } })],
    ['no session block at all', JSON.stringify({ schema: 1 })],
  ];
  for (const [label, stdout] of cases) {
    const outputDir = makeTempDir();
    const projectRoot = makeTempDir();
    writeState(outputDir, {
      nonce: 'n1', pid: 1, port: 1, launchToken: 'x'.repeat(43),
      sessionId: 'ci-debug-abc', projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
    });
    const githubOutput = path.join(outputDir, 'github_output');
    const stepSummary = path.join(outputDir, 'step_summary');
    writeFileSync(githubOutput, '');
    writeFileSync(stepSummary, '');
    const code = await reportSubcommand({
      outputDir,
      env: { GITHUB_OUTPUT: githubOutput, GITHUB_STEP_SUMMARY: stepSummary },
      probeToken: async () => true,
      readLive: async () => [servedEntry({ ts: '2026-08-13T00:00:00.000Z', msg: 'served event' })],
      // Exit status 0 throughout: a healthy child that printed rubbish is the
      // whole point — status alone was never proof of a report (Codex T5 #2).
      spawnReport: (args) => (args.includes('--format=json')
        ? { status: 0, stdout }
        : { status: 0, stdout: '## Debug evidence report\n' }),
    });
    const evidenceDir = resolveEvidenceDir(outputDir);
    assert.equal(code, 3, label);
    assert.equal(readState(outputDir).reportRendered, false, label);
    assert.ok(!existsSync(path.join(evidenceDir, 'report.json')), `${label}: nothing is written before the shape is checked`);
    assert.ok(!existsSync(path.join(evidenceDir, 'report.md')), `${label}: the markdown is withheld with it`);
    assert.equal(readFileSync(githubOutput, 'utf8'), '', label);
    assert.equal(readFileSync(stepSummary, 'utf8'), '', label);
    // The capture itself succeeded, and stays staged for a human.
    assert.equal(readState(outputDir).evidenceCopied, true, label);
  }
});

test('finish taxonomy: missing state 3; missing exit code 3; dead collector 3; command failure mirrors or is waived by the toggle', async () => {
  const outputDir = makeTempDir();
  assert.equal(finishSubcommand({ outputDir, env: {} }), 3, 'no state');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true' });
  assert.equal(finishSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'other' } }), 3, 'nonce mismatch');
  assert.equal(finishSubcommand({ outputDir, env: {} }), 3, 'run never recorded an exit code');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 0, collectorAlive: false, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 3, 'collector died before capture');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 0, collectorAlive: true, evidenceCopied: false, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 3, 'nothing was captured');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 7, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 7, 'mirrors the command exit code');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'false', commandExitCode: 7, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 0, 'toggle waives the failure');
  // A toggle validateActionInputs could never have produced means the state
  // file is corrupt or forged, and the exit code sitting next to it is worth
  // no more than the toggle is — so it is a 3 on a failing run AND on a green
  // one, not a "treat anything but false as true" (Codex T5 #3).
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'maybe', commandExitCode: 7, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 3, 'an out-of-contract toggle is refused, not reinterpreted');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'maybe', commandExitCode: 0, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: {} }), 3, 'and refused on a green run too, where it would otherwise pass unread');
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
