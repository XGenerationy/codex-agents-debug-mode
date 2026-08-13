'use strict';

const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const {
  closeSync, constants, existsSync, openSync, readFileSync, readdirSync, utimesSync,
  writeFileSync, writeSync, mkdirSync, mkdtempSync, rmSync, symlinkSync,
} = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
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
