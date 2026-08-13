'use strict';

const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const {
  readFileSync, readdirSync, writeFileSync, writeSync, mkdirSync, mkdtempSync, rmSync, symlinkSync,
} = require('node:fs');
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
