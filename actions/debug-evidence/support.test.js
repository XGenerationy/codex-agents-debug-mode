'use strict';

const assert = require('node:assert');
const { createHash, createPublicKey, generateKeyPairSync, sign } = require('node:crypto');
const { EventEmitter } = require('node:events');
const {
  appendFileSync, closeSync, constants, existsSync, openSync, readFileSync, readdirSync,
  unlinkSync, utimesSync, writeFileSync, writeSync, mkdirSync, mkdtempSync, rmSync, symlinkSync,
} = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  canonicalResponderRecord,
} = require('../../scripts/debug_server');

const {
  defaultRenderReport,
  defaultSpawnCommand,
  defaultSpawnShim,
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

// The environment the runner hands every step AFTER `start`: `start` emits
// this invocation's nonce as the step output `invocation-nonce`, and
// action.yml maps it into run/report/teardown/finish. A test that calls one of
// those subcommands directly has to stand in for that hand-off — exactly as
// `runEnv` stands in for the verification-key one — because all four fail
// closed without it. Read from the state file rather than passed in, so the
// tests that let `start` mint its own random nonce work unchanged.
const invocationEnv = (outputDir, extra = {}) => ({
  DEBUG_ACTION_INVOCATION_NONCE: readState(outputDir)?.nonce,
  ...extra,
});

// The staged evidence child is INVOCATION-SCOPED (Codex T6 r1 #3), so naming
// it takes the same identity the production steps are handed. Resolved from
// the committed state so a test never has to hard-code the directory layout.
const evidenceDirOf = (outputDir) => resolveEvidenceDir(outputDir, readState(outputDir).nonce);

// "Nothing was staged", asserted so that it cannot pass for the wrong
// reason. A bare !existsSync against a path no run ever touched is true by
// accident, which is exactly how a mechanical env/path migration can defang
// a security test without changing a single assertion (Codex T6 r2 #2). Every
// run that gets past the identity gate creates its staging child as its first
// act, so requiring the DIRECTORY to exist proves the emptiness is this run's.
const assertNothingStaged = (evidenceDir, label) => {
  assert.ok(existsSync(evidenceDir), `${label}: the staging directory this run actually created`);
  for (const name of ['session.log', 'report.md', 'report.json']) {
    assert.ok(!existsSync(path.join(evidenceDir, name)), `${label}: ${name} is not staged`);
  }
};

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

// start owns the mint now, so every fake-shim test has to get past the port
// challenge and POST /session before it reaches the behaviour it is actually
// about. These are the two seams that do it.
const MINTED = { status: 201, json: { session_id: 'ci-debug-abc', session_token: 'z'.repeat(43) } };
const mintSeams = { probeToken: async () => true, request: async () => MINTED };

// What readSessionLive rejects with when nothing is listening on the port.
// Capture treats this class — and only this class — as "there is no
// authoritative source to ask", which is what licenses the labeled on-disk
// fallback; every other failure means the collector answered and refused.
const unreachableRead = async () => { throw new Error('live_read_connect_failed:ECONNREFUSED'); };

// The responder KEYPAIR the harness stands in for the runner to deliver. In
// production the boot shim generates it, hands back only the public half over
// the private pipe, start publishes that half as a step output, and the runner
// interpolates it into the RUN step's env — the step whose environment is
// resolved before the wrapped command exists (Codex T5 r6). It is never
// written to state, which is what stops a wrapped command that owns the state
// file from substituting a keypair of its own.
const RESPONDER_KEYS = generateKeyPairSync('ed25519');
const VERIFY_KEY_B64 = RESPONDER_KEYS.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
// The two values action.yml wires into the RUN step, both from `start`'s step
// outputs: the verification key and this invocation's identity. `run` needs
// the second before it can name its own staging directory, so a fixture state
// written with `nonce: 'n1'` and this env are one matched pair.
const RUN_ENV = { DEBUG_ACTION_COLLECTOR_VERIFY_KEY: VERIFY_KEY_B64, DEBUG_ACTION_INVOCATION_NONCE: 'n1' };

// A keypair the attacker generated for itself. Generating one is free, which
// is exactly why the verification key's INTEGRITY — not its secrecy — is what
// the runner-memory channel protects.
const IMPOSTOR_KEYS = generateKeyPairSync('ed25519');

// Sign exactly what the collector signs: the canonical record, imported from
// the collector itself so a drift between the two definitions is impossible to
// write by accident. `target` defaults to the unfiltered form capture asks for.
const proofFor = (privateKey, challenge, text, target = '/sessions/ci-debug-abc/logs') => sign(
  null,
  Buffer.from(canonicalResponderRecord({
    method: 'GET',
    target,
    challenge,
    bodyDigest: createHash('sha256').update(text, 'utf8').digest('hex'),
  }), 'utf8'),
  privateKey,
).toString('base64');

// A readLive seam that answers the way the real collector does: it signs the
// bytes it serves over the nonce REPORT chose, so a test never has to know the
// challenge in advance. Pass { privateKey } to sign with the wrong key,
// { target } to sign a different question, or { proof: null } for no proof.
const collectorAnswer = (lines, { privateKey = RESPONDER_KEYS.privateKey, target, proof } = {}) => async ({ challenge }) => {
  const text = lines.map((line) => `${JSON.stringify(line)}\n`).join('');
  return {
    entries: lines.map(servedEntry),
    text,
    proof: proof === undefined ? proofFor(privateKey, challenge, text, target) : proof,
  };
};

// readSessionLive resolves [{ raw, parsed }] — parsed being JSON.parse(raw).
// Seams build entries through this helper so a fixture can never drift into a
// shape the real collector would not produce.
const servedEntry = (line) => ({ raw: JSON.stringify(line), parsed: line });

// Capture happens inside `run` now: it is the only process whose environment
// was resolved before the wrapped command existed, so it is the only one whose
// view of the verification key that command cannot rewrite (Codex T5 r6).
// Every capture test therefore drives run, with a wrapped command that does
// nothing unless the test needs it to.
const captureViaRun = (options) => runSubcommand({
  inputs: baseInputs(),
  spawnCommand: () => ({ status: 0 }),
  ...options,
});

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

test('start boots a real collector, mints the session, and records state that carries no launch token', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const port = await getFreePort();
  const githubEnv = path.join(outputDir, 'github_env');
  const githubOutput = path.join(outputDir, 'github_output');
  writeFileSync(githubEnv, '');
  writeFileSync(githubOutput, '');
  const code = await startSubcommand({
    inputs: baseInputs({ port: String(port) }),
    outputDir,
    projectRoot,
    env: { GITHUB_ENV: githubEnv, GITHUB_OUTPUT: githubOutput },
  });
  assert.equal(code, 0);
  const state = readState(outputDir);
  try {
    assert.equal(state.port, port);
    assert.ok(Number.isInteger(state.pid) && state.pid > 0);
    // The architectural invariant, asserted on the field itself: after start
    // returns, the credential that can mint sessions and post hypothesis
    // lines exists nowhere on disk. Only the session token survives, and it
    // can do neither (Codex T5 r3).
    assert.equal('launchToken' in state, false, 'the launch token is never persisted');
    assert.ok(state.sessionId.startsWith('ci-debug-'), 'start mints the session while the launch token still exists');
    assert.ok(typeof state.sessionToken === 'string' && state.sessionToken.length >= 32);
    assert.equal(readFileSync(path.join(outputDir, 'action-state.json'), 'utf8').includes('launchToken'), false,
      'not under any other name either');
    // Positive form: the state file is AT the output-dir root, and the
    // staging child is a real directory somewhere below it. The old
    // `!dirname.includes(child)` form was true for any path at all.
    assert.equal(path.dirname(path.join(outputDir, 'action-state.json')), outputDir);
    assert.equal(path.dirname(evidenceDirOf(outputDir)), outputDir,
      'the evidence child is a child of the output dir, and the state file is its sibling');
    // GITHUB_ENV is a JOB-GLOBAL channel: whatever is written there persists
    // to every later step of the job, including the steps of a LATER
    // invocation of this action. Invocation identity therefore travels as a
    // step output (below), and this file is left completely untouched
    // (Codex T6 r1 #1).
    assert.equal(readFileSync(githubEnv, 'utf8'), '', 'start writes nothing job-global');
    const emitted = readFileSync(githubOutput, 'utf8');
    assert.match(emitted, /^invocation-nonce=[A-Za-z0-9_-]{8,64}$/m, 'the nonce travels as a step output');
    assert.equal(emitted.includes(`invocation-nonce=${state.nonce}`), true, 'and it is the nonce the state records');
    assert.ok(!emitted.includes(state.sessionToken), 'no credential enters a step output');
  } finally {
    teardownSubcommand({ outputDir, env: invocationEnv(outputDir) });
  }
});

// Ordering is the property, not merely presence. `start` validates its inputs
// and resolves output-dir containment before it can do anything useful, and an
// identity emitted after those checks would leave the later steps of a FAILED
// start with no identity of their own. On the job-global GITHUB_ENV channel
// those steps then inherit a PREVIOUS invocation's nonce (env-file values
// persist to every later step of the job and do appear in the expression `env`
// context — the runner source settles it), find that invocation's state in a
// shared output-dir, declare it owned, and let the always() upload publish its
// evidence under this run's artifact name (Codex T6 r1 #1). Emitting first, and
// only as a step output, closes both halves.
test('start emits the invocation nonce and the staging directory as its first action, before any check that can fail', async () => {
  const outputDir = makeTempDir();
  const githubOutput = path.join(outputDir, 'github_output');
  const githubEnv = path.join(outputDir, 'github_env');
  writeFileSync(githubOutput, '');
  writeFileSync(githubEnv, '');
  const refuse = (label) => () => { throw new Error(`a refused start must never ${label}`); };
  await assert.rejects(startSubcommand({
    inputs: baseInputs({ runCommand: '' }),
    outputDir,
    env: { GITHUB_OUTPUT: githubOutput, GITHUB_ENV: githubEnv },
    spawnShim: refuse('spawn a collector'),
  }), /invalid inputs/);
  const emitted = readFileSync(githubOutput, 'utf8');
  assert.match(emitted, /^invocation-nonce=[A-Za-z0-9_-]{8,64}$/m,
    'a start that goes on to fail has still published an identity for its own later steps');
  // The upload step's path set comes from HERE, not from anything written
  // after the wrapped command has run (Codex T6 r2 #1). Emitted in the same
  // first act as the nonce it is derived from, so the only way for it to be
  // empty is for this step never to have executed at all — which is exactly
  // when the upload gate must be closed.
  const emittedNonce = /^invocation-nonce=(.+)$/m.exec(emitted)[1];
  assert.match(emitted, /^evidence-dir=.+$/m, 'and the staging directory the upload step will read');
  assert.equal(
    /^evidence-dir=(.+)$/m.exec(emitted)[1],
    resolveEvidenceDir(outputDir, emittedNonce),
    'which is the invocation-scoped child derived from that same nonce',
  );
  assert.equal(readFileSync(githubEnv, 'utf8'), '',
    'and nothing is written to the job-global channel, on any path');
  // Distinct per invocation by construction, which is what makes a later
  // invocation unable to answer for an earlier one.
  const second = makeTempDir();
  const secondOutput = path.join(second, 'github_output');
  writeFileSync(secondOutput, '');
  await assert.rejects(startSubcommand({
    inputs: baseInputs({ runCommand: '' }),
    outputDir: second,
    env: { GITHUB_OUTPUT: secondOutput },
    spawnShim: refuse('spawn a collector'),
  }), /invalid inputs/);
  assert.notEqual(readFileSync(secondOutput, 'utf8'), emitted, 'a second invocation mints its own');
});

test('teardown is idempotent: dead pid is success, missing state is success, nonce mismatch is 3', async () => {
  const outputDir = makeTempDir();
  // An identity with no state behind it: `start` emitted its nonce and then
  // failed before writing anything, so there is nothing to tear down.
  assert.equal(teardownSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' } }), 0, 'missing state = start never ran = success');
  writeState(outputDir, { nonce: 'n1', pid: 999999999 });
  assert.equal(teardownSubcommand({ outputDir, env: invocationEnv(outputDir) }), 0, 'ESRCH on a dead pid is success');
  assert.equal(teardownSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'other' } }), 3, 'nonce mismatch refuses to trust state');
});

// A fresh job whose `start` fails early hands teardown NO nonce. Pointed at a
// REUSED custom output-dir, the lenient check let it read that directory's
// stale state and kill(state.pid) — a pid belonging to another invocation, or
// recycled by the OS to an unrelated process on a self-hosted runner. A
// missing identity must mean "do not read, do not act" (Codex T6 r1 #2).
// `finish` takes the same posture: it reads the same state file, and an exit
// code it cannot show belongs to this invocation is not this job's verdict.
test('teardown and finish refuse to touch recorded state when no invocation nonce reached the step', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 4242, port: 1, sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43),
    commandExitCode: 7, collectorAlive: true, evidenceCopied: true, evidenceAuthentic: true,
    reportRendered: true, failOnCommandFailure: 'true',
  });
  const killed = [];
  const { written } = await captureStderr(() => {
    assert.equal(teardownSubcommand({ outputDir, env: {}, kill: (pid) => killed.push(pid) }), 3);
    assert.deepEqual(killed, [], 'a pid out of unidentifiable state is never signalled');
    // 3 rather than the 7 the state records: a stranger's exit code is not
    // this job's verdict.
    assert.equal(finishSubcommand({ outputDir, env: {} }), 3);
  });
  assert.match(written, /teardown: this step received no usable invocation nonce/);
  assert.match(written, /finish: this step received no usable invocation nonce/);
  // And with the identity present, both act on exactly the same state.
  assert.equal(teardownSubcommand({
    outputDir,
    env: invocationEnv(outputDir),
    kill: (pid) => killed.push(pid),
  }), 0);
  assert.deepEqual(killed, [4242]);
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 7);
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
    ...mintSeams,
    kill: (pid) => { killed.push(pid); },
    readyTimeoutMs: 5_000,
  });
  setImmediate(() => child.stdout.emit('data', `${JSON.stringify({
    status: 'started', port: 8787, pid: 4242, project_hash: 'hash', launch_token: 'x'.repeat(43), verify_key: VERIFY_KEY_B64,
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
    ...mintSeams,
    kill: (pid) => { killed.push(pid); },
    readyTimeoutMs: 5_000,
  });
  setImmediate(() => child.stdout.emit('data', `${JSON.stringify({
    status: 'started', port: 8787, pid: 4242, project_hash: 'hash', launch_token: 'x'.repeat(43), verify_key: VERIFY_KEY_B64,
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
  const state = { nonce: 'n1', pid: 4242, port: 8787, sessionToken: 'x'.repeat(43) };
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
    // The session start already minted — there is no launch token left to
    // mint another with, which is the point of the whole restructure.
    const recorded = await fetch(`http://127.0.0.1:${port}/log`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-debug-session-token': state.sessionToken },
      body: JSON.stringify({
        sessionId: state.sessionId,
        msg: `leaked ${values.ALPHA_VALUE} then ${values.BRAVO_VALUE} then ${values.CHARLIE_VALUE}`,
      }),
    });
    assert.equal(recorded.status, 202);
    const line = readFileSync(path.join(projectRoot, '.debug', `debug-${state.sessionId}.log`), 'utf8');
    for (const [name, value] of Object.entries(values)) {
      assert.ok(!line.includes(value), `${name}: a comma-only split would have left this value in the log`);
    }
    assert.match(line, /\[REDACTED\]/);
  } finally {
    teardownSubcommand({ outputDir, env: invocationEnv(outputDir) });
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
  // The responder key reaches `run` exactly the way action.yml will route it:
  // start writes it to GITHUB_OUTPUT, the runner parses that file when the step
  // ends, and the value is interpolated into the RUN step's env. The harness
  // stands in for the runner — reading the step output here and handing it back
  // as `runEnv` — precisely so nothing in these tests can accidentally take a
  // shortcut through state or the filesystem.
  const startOutput = path.join(outputDir, 'start_output');
  writeFileSync(startOutput, '');
  const code = await startSubcommand({ inputs, outputDir, projectRoot, env: { GITHUB_OUTPUT: startOutput } });
  assert.equal(code, 0);
  const emitted = readFileSync(startOutput, 'utf8');
  const keyLine = emitted.split('\n').find((line) => line.startsWith('collector-verify-key='));
  assert.ok(keyLine, 'start must publish the verification key as a step output');
  const collectorVerifyKey = keyLine.slice('collector-verify-key='.length);
  assert.ok(collectorVerifyKey.length >= 32);
  // Both step outputs travel together, exactly as action.yml maps them: the
  // verification key and the invocation identity `run` needs to name its own
  // staging child. The nonce is read back out of the step-output file for the
  // same reason the key is — nothing in these tests may take a shortcut
  // through state or the filesystem.
  const nonceLine = emitted.split('\n').find((line) => line.startsWith('invocation-nonce='));
  assert.ok(nonceLine, 'start must publish the invocation nonce as a step output');
  const invocationNonce = nonceLine.slice('invocation-nonce='.length);
  // The value action.yml interpolates into the upload step's path entries,
  // taken from the same pre-command file the runner would parse.
  const evidenceDirLine = emitted.split('\n').find((line) => line.startsWith('evidence-dir='));
  assert.ok(evidenceDirLine, 'start must publish the staging directory as a step output');
  const advertisedEvidenceDir = evidenceDirLine.slice('evidence-dir='.length);
  return {
    outputDir,
    projectRoot,
    port,
    inputs,
    collectorVerifyKey,
    invocationNonce,
    advertisedEvidenceDir,
    runEnv: {
      DEBUG_ACTION_COLLECTOR_VERIFY_KEY: collectorVerifyKey,
      DEBUG_ACTION_INVOCATION_NONCE: invocationNonce,
    },
  };
};

test('run injects exactly the documented env from the session start minted, records the exit code, and never fails on command failure', async () => {
  const { outputDir, projectRoot, inputs, runEnv } = await startReal();
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
      env: { ...runEnv, GITHUB_OUTPUT: githubOutput },
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
    assert.ok(!outputs.includes(state.sessionToken), 'session token never enters GITHUB_OUTPUT');
  } finally {
    teardownSubcommand({ outputDir, env: invocationEnv(outputDir) });
  }
});

test('start posts one OPEN hypothesis line and run injects DEBUG_HYPOTHESIS_ID — and no other status can ever exist', async () => {
  const { outputDir, projectRoot, inputs, runEnv } = await startReal({ hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' });
  try {
    const state = readState(outputDir);
    // Posted by START, while the launch token still existed. By the time the
    // wrapped command runs, the credential that wrote this line is gone.
    const sessionLog = readFileSync(path.join(projectRoot, '.debug', `debug-${state.sessionId}.log`), 'utf8');
    const hypothesisLines = sessionLog.split('\n').filter((l) => l.includes('"type":"hypothesis"'));
    assert.equal(hypothesisLines.length, 1);
    const parsed = JSON.parse(hypothesisLines[0]);
    assert.equal(parsed.status, 'OPEN');
    assert.equal(parsed.hypothesisId, 'H-demo');
    assert.equal(parsed.title, 'seeded demo');
    const probe = 'node -e "process.exit(process.env.DEBUG_HYPOTHESIS_ID === \'H-demo\' ? 0 : 90)"';
    const code = await runSubcommand({ inputs: { ...inputs, runCommand: probe }, outputDir, env: runEnv });
    assert.equal(code, 0);
    assert.equal(readState(outputDir).commandExitCode, 0);
  } finally {
    teardownSubcommand({ outputDir, env: invocationEnv(outputDir) });
  }
});

test('run without state (start never completed) is a 3-class refusal; nonce mismatch likewise', async () => {
  const outputDir = makeTempDir();
  // A VALID identity throughout: without one, run refuses at the nonce gate
  // and neither branch this test is named for is ever reached (Codex T6 r2 #2
  // — the migration that added the gate defanged exactly this shape).
  assert.equal(await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' },
  }), 3, 'no state at all');
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43) });
  assert.equal(await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: { DEBUG_ACTION_INVOCATION_NONCE: 'other' },
  }), 3, 'state carrying another invocation\'s nonce');
});

test('run refuses a state that carries no session rather than running the command uninstrumented', async () => {
  const outputDir = makeTempDir();
  // start died between the handshake and the mint, or something wrote a
  // partial state. Running the command anyway would produce a job that looks
  // instrumented and records nothing.
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug' });
  let commandRan = false;
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    // The invocation's own identity, so the refusal under test is the missing
    // SESSION rather than the missing nonce (Codex T6 r2 #2).
    env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' },
    spawnCommand: () => { commandRan = true; return { status: 0 }; },
  });
  assert.equal(code, 3);
  assert.equal(commandRan, false);
});

test('a session-mint failure kills the collector in start, so nothing is left holding the port', async () => {
  const outputDir = makeTempDir();
  const child = fakeChild();
  const killed = [];
  let requests = 0;
  const starting = startSubcommand({
    inputs: baseInputs(), outputDir, projectRoot: makeTempDir(), env: {},
    spawnShim: () => child,
    probeReady: async () => ({ project_hash: 'hash', ready: true }),
    probeToken: async () => true,
    request: async () => { requests += 1; return { status: 401, json: { error: 'unauthorized' } }; },
    kill: (pid) => { killed.push(pid); },
    readyTimeoutMs: 5_000,
  });
  setImmediate(() => child.stdout.emit('data', `${JSON.stringify({
    status: 'started', port: 8787, pid: 4242, project_hash: 'hash', launch_token: 'x'.repeat(43), verify_key: VERIFY_KEY_B64,
  })}\n`));
  await assert.rejects(starting, /session mint failed \(HTTP 401\)/);
  assert.equal(requests, 1);
  assert.deepEqual(killed, [4242], 'the mint runs before any state is written, so the collector is unstoppable unless start kills it');
  assert.equal(readState(outputDir), null, 'and no state claims a session that was never minted');
});

test('start challenges the port occupant before the launch token is ever put on the wire', async () => {
  const outputDir = makeTempDir();
  const child = fakeChild();
  const launchToken = 'x'.repeat(43);
  const probes = [];
  const killed = [];
  let requests = 0;
  const starting = startSubcommand({
    inputs: baseInputs(), outputDir, projectRoot: makeTempDir(), env: {},
    spawnShim: () => child,
    probeReady: async () => ({ project_hash: 'hash', ready: true }),
    // The shim reported a pid and a token, but between that report and the
    // mint the collector could have died and any local process could have
    // taken the port (Codex T4 #4, relocated here with the mint).
    probeToken: async (port, token) => { probes.push([port, token]); return false; },
    request: async () => { requests += 1; return MINTED; },
    kill: (pid) => { killed.push(pid); },
    readyTimeoutMs: 5_000,
  });
  setImmediate(() => child.stdout.emit('data', `${JSON.stringify({
    status: 'started', port: 8787, pid: 4242, project_hash: 'hash', launch_token: launchToken, verify_key: VERIFY_KEY_B64,
  })}\n`));
  await assert.rejects(starting, /identity could not be verified/);
  assert.deepEqual(probes, [[8787, launchToken]]);
  assert.equal(requests, 0, 'a process that cannot prove it holds the token never receives it');
  assert.deepEqual(killed, [4242]);
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

test('start masks each token the moment it exists and in the order it is used, before any of them is spent', async () => {
  const outputDir = makeTempDir();
  const child = fakeChild();
  const launchToken = 'x'.repeat(43);
  const sessionToken = 'z'.repeat(43);
  // One ledger for the mask writes, the readiness probe, the occupant
  // challenge and every request, so ORDER is asserted rather than mere
  // occurrence: masking after a token had already been used would satisfy a
  // presence-only check while leaving the window NODE_DEBUG=http leaks
  // through wide open (Codex T4 #1).
  const ledger = [];
  const starting = startSubcommand({
    inputs: baseInputs({ hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' }),
    outputDir,
    projectRoot: makeTempDir(),
    env: { GITHUB_ACTIONS: 'true' },
    spawnShim: () => child,
    probeReady: async () => { ledger.push('probe-ready'); return { project_hash: 'hash', ready: true }; },
    probeToken: async () => { ledger.push('probe-token'); return true; },
    request: async ({ path: requestPath }) => {
      ledger.push(`request ${requestPath}`);
      return requestPath === '/session'
        ? { status: 201, json: { session_id: 'ci-debug-abc', session_token: sessionToken } }
        : { status: 202, json: { status: 'recorded' } };
    },
    writeStdout: (text) => ledger.push(text),
    readyTimeoutMs: 5_000,
  });
  setImmediate(() => child.stdout.emit('data', `${JSON.stringify({
    status: 'started', port: 8787, pid: 4242, project_hash: 'hash', launch_token: launchToken, verify_key: VERIFY_KEY_B64,
  })}\n`));
  assert.equal(await starting, 0);
  assert.deepEqual(ledger, [
    `::add-mask::${launchToken}\n`,
    // NO mask for the verification key: it is public by design, and masking a
    // harmless value only litters later logs with '***'. What protects it is
    // where it travels, not who can read it.
    'probe-ready',
    'probe-token',
    'request /session',
    `::add-mask::${sessionToken}\n`,
    'request /hypothesis',
  ]);
  const state = readState(outputDir);
  assert.equal(state.sessionToken, sessionToken, 'masking does not disturb what start records');
  assert.equal('launchToken' in state, false, 'and the launch token is spent, not stored');
  assert.equal(readFileSync(path.join(outputDir, 'action-state.json'), 'utf8').includes(VERIFY_KEY_B64), false,
    'the verification key travels through runner memory, never through state');
});

test('run re-registers the session token with the runner before handing it to a child process', async () => {
  const outputDir = makeTempDir();
  const sessionToken = 'z'.repeat(43);
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug',
    sessionId: 'ci-debug-abc', sessionToken,
    hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo',
  });
  const ledger = [];
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: { ...RUN_ENV, GITHUB_ACTIONS: 'true' },
    // This state opened a hypothesis, so a faithful capture carries the one
    // OPEN line start posted alongside the events.
    readLive: collectorAnswer([
      { ts: '2026-08-14T00:00:00.000Z', msg: 'captured in run' },
      { ts: '2026-08-14T00:00:01.000Z', type: 'hypothesis', hypothesisId: 'H-demo', status: 'OPEN', title: 'seeded demo' },
    ]),
    spawnCommand: () => { ledger.push('spawn'); return { status: 0 }; },
    writeStdout: (text) => ledger.push(text),
  });
  assert.equal(code, 0);
  // A no-op for a runner that already masked this value in start, and the
  // only protection if the mask registry somehow did not carry across steps.
  // Order matters: the mask is registered BEFORE the token is put into a child
  // process's environment, and the capture digest is printed after the command
  // has come and gone — which is the shape of the whole step.
  assert.equal(ledger[0], `::add-mask::${sessionToken}\n`);
  assert.equal(ledger[1], 'spawn');
  assert.match(ledger[2], /^evidence-sha256 session\.log=[0-9a-f]{64} /);
  assert.equal(ledger.length, 3);
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

test('state writes serialize: the invocation that lost the output-dir refuses, and the winner survives intact', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug',
    sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43),
  });
  const githubOutput = path.join(outputDir, 'github_output');
  writeFileSync(githubOutput, '');
  const lockPath = path.join(outputDir, 'action-state.lock');
  const usurper = { nonce: 'n2', pid: 2222, port: 9999, sessionToken: 'y'.repeat(43), sessionName: 'other' };
  const order = [];
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: { ...RUN_ENV, GITHUB_OUTPUT: githubOutput },
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
  const recorded = {
    nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug',
    sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43),
  };
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
      env: { ...RUN_ENV, GITHUB_OUTPUT: githubOutput },
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
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug',
    sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43),
  });
  const lockPath = path.join(outputDir, 'action-state.lock');
  writeFileSync(lockPath, '');
  // Backdated past the threshold: indistinguishable from a runner that was
  // cancelled or OOM-killed mid-write and never released.
  const longAgo = new Date(Date.now() - 120_000);
  utimesSync(lockPath, longAgo, longAgo);
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: RUN_ENV,
    readLive: collectorAnswer([{ ts: '2026-08-14T00:00:00.000Z', msg: 'captured in run' }]),
    spawnCommand: () => ({ status: 0 }),
  });
  assert.equal(code, 0);
  assert.equal(readState(outputDir).commandExitCode, 0, 'the reaped lock did not block the commit');
  assert.ok(!existsSync(lockPath), 'the replacement lock is released too, not leaked');
});

test('a job-level DEBUG_HYPOTHESIS_ID is never inherited when this action opened no hypothesis', async () => {
  const { outputDir, inputs, runEnv } = await startReal();
  try {
    const probe = 'node -e "process.exit(process.env.DEBUG_HYPOTHESIS_ID === undefined ? 0 : 91)"';
    const code = await runSubcommand({
      inputs: { ...inputs, runCommand: probe },
      outputDir,
      env: { ...runEnv, DEBUG_HYPOTHESIS_ID: 'H-from-the-job' },
    });
    assert.equal(code, 0);
    assert.equal(readState(outputDir).commandExitCode, 0,
      'the wrapped command must not see a hypothesis id this action never posted');
  } finally {
    teardownSubcommand({ outputDir, env: invocationEnv(outputDir) });
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
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug',
    sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43),
  });
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: RUN_ENV,
    readLive: collectorAnswer([{ ts: '2026-08-14T00:00:00.000Z', msg: 'captured in run' }]),
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

// A real collector, a real wrapped command, and the capture that follows it —
// all inside the ONE run step, which is the point of round 6. Callers assert
// on `runCode` themselves; overrides let a test bend any seam of that single
// invocation, because there is no longer a later step to bend.
const fullLifecycle = async ({ env: envOverride = {}, ...overrides } = {}) => {
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
    env: {
      ...context.runEnv,
      GITHUB_OUTPUT: githubOutput,
      // Handed to the wrapped command (and to any spawnCommand seam) so a test
      // can reach the session log the way a co-resident process would.
      FORGE_DEBUG_DIR: path.join(context.projectRoot, '.debug'),
      ...envOverride,
    },
    ...overrides,
  });
  return { ...context, githubOutput, stepSummary, runCode };
};

test('run captures the session from the collector, renders md+json, emits outputs and digests, and report publishes it — token bytes never enter the evidence child', async () => {
  const printed = [];
  const context = await fullLifecycle({ writeStdout: (text) => printed.push(text) });
  try {
    assert.equal(context.runCode, 0);
    // report's whole remaining job: publish what run already committed.
    assert.equal(reportSubcommand({
      outputDir: context.outputDir,
      env: invocationEnv(context.outputDir, { GITHUB_STEP_SUMMARY: context.stepSummary }),
    }), 0);
    const evidenceDir = evidenceDirOf(context.outputDir);
    // End to end, the property the upload step depends on: the directory
    // `start` advertised BEFORE the wrapped command existed is the directory
    // `run` staged into afterwards. Nothing written after the command runs is
    // consulted to find the evidence (Codex T6 r2 #1).
    assert.equal(context.advertisedEvidenceDir, evidenceDir);
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
    assert.equal(state.evidenceAuthentic, true, 'the collector proved the answer was its own');
    for (const file of ['session.log', 'report.md', 'report.json']) {
      const bytes = readFileSync(path.join(evidenceDir, file), 'utf8');
      assert.ok(!bytes.includes(state.sessionToken), `${file} must not contain the session token`);
      // The responder key is verification material, never evidence: it lives
      // in runner memory and this step's env, and must reach neither the
      // artifact nor the state file.
      assert.ok(!bytes.includes(context.collectorVerifyKey), `${file} must not contain the verification key`);
    }
    assert.equal(readFileSync(path.join(context.outputDir, 'action-state.json'), 'utf8')
      .includes(context.collectorVerifyKey), false, 'nor the state file');
    // Staging-window detectability: staging and upload are separate steps of
    // the same composite action, so a detached child CAN rewrite these files
    // in between. The step log cannot be revised once streamed, so a digest
    // printed here is the record an artifact is checked against (Codex T5 r3).
    const expected = `evidence-sha256 ${['session.log', 'report.md', 'report.json']
      .map((file) => `${file}=${createHash('sha256').update(readFileSync(path.join(evidenceDir, file))).digest('hex')}`)
      .join(' ')}`;
    assert.deepEqual(printed, [`${expected}\n`], 'exactly one digest line, over the bytes actually staged');
    assert.ok(outputs.includes(`evidence-digest=${expected}\n`),
      'and the same content on the machine surface, so either can be compared against the artifact');
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
    teardownSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) });
  }
});

// The wrapped command is HANDED DEBUG_SESSION_ID and shares the filesystem
// with the collector, so it can write straight into .debug/debug-<id>.log —
// including a hypothesis verdict it has no launch token to POST. This runs a
// real lifecycle whose wrapped command does exactly that, so the capture
// paths below are tested against a genuinely tampered log rather than a
// described one. The forgery lands BEFORE the capture that follows it in the
// same run step, which is precisely the ordering a real attack has.
const forgedLifecycle = async ({ ...overrides } = {}) => {
  const { env: _ignored, ...rest } = overrides;
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
    env: {
      ...context.runEnv,
      FORGE_DEBUG_DIR: path.join(context.projectRoot, '.debug'),
      ...(overrides.env ?? {}),
    },
    ...rest,
  });
  const state = readState(context.outputDir);
  assert.equal(state.commandExitCode, 0, 'the forging command itself succeeded — nothing stopped it');
  const logPath = path.join(context.projectRoot, '.debug', `debug-${state.sessionId}.log`);
  assert.ok(readFileSync(logPath, 'utf8').includes('CONFIRMED'),
    'the wrapped command really did plant a verdict it could never have POSTed');
  return { ...context, logPath, runCode };
};

test('a wrapped command that forges its own session log cannot get the forgery into the evidence child', async () => {
  const context = await forgedLifecycle();
  try {
    assert.equal(context.runCode, 3, 'the collector refuses to serve a log that is no longer the one it wrote');
    const state = readState(context.outputDir);
    // collectorAlive now MEANS 'an authenticated read of this session's log
    // succeeded'. A collector that answers and then refuses to vouch for its
    // own file has not given us one, so this is false — and finish fails on
    // it twice over, liveness and evidence alike.
    assert.equal(state.collectorAlive, false, 'no authoritative read completed');
    assert.equal(state.evidenceCopied, false);
    assert.equal(state.evidenceAuthentic, false);
    assert.equal(state.reportRendered, false);
    assertNothingStaged(evidenceDirOf(context.outputDir),
      'a pathname copy would have staged the forged file right here, and rendered its verdict');
    assert.equal(finishSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) }), 3);
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) });
  }
});

test('a same-length in-place rewrite of the session log is caught end to end, not just by the byte count', async () => {
  let rewritten = false;
  // The rewrite lands between the wrapped command and the capture, inside the
  // one run step — the window any co-resident process actually has. Ten
  // characters for ten: dev, ino, birthtime and size are all identical
  // afterwards, so every check the collector had before round 2 passes.
  const context = await fullLifecycle({
    spawnCommand: async (command, options) => {
      const result = await defaultSpawnCommand(command, options);
      const logPath = path.join(options.env.FORGE_DEBUG_DIR, `debug-${options.env.DEBUG_SESSION_ID}.log`);
      const original = readFileSync(logPath, 'utf8');
      const forged = original.replace('demo event', 'FAKE event');
      assert.equal(Buffer.byteLength(forged, 'utf8'), Buffer.byteLength(original, 'utf8'));
      writeFileSync(logPath, forged);
      rewritten = true;
      return result;
    },
  });
  try {
    assert.ok(rewritten, 'the rewrite really happened');
    // Collector: content digest mismatch → 409 session_log_tampered.
    // readSessionLive: 409 → live_read_log_replaced. run: no fallback → 3.
    assert.equal(context.runCode, 3);
    const state = readState(context.outputDir);
    assert.equal(state.collectorAlive, false, 'the read never completed, so nothing authoritative was served');
    assert.equal(state.evidenceCopied, false);
    assertNothingStaged(evidenceDirOf(context.outputDir), 'a same-length rewrite stages nothing');
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) });
  }
});

test('with nothing able to prove it owns the port, a forged log is staged as labeled partial evidence and still cannot go green', async () => {
  const context = await forgedLifecycle();
  try {
    const code = await captureViaRun({
      inputs: context.inputs,
      outputDir: context.outputDir,
      env: context.runEnv,
      // No authoritative source: the run's own collector is gone (or was
      // never the thing on that port), so the filesystem is all there is.
      readLive: unreachableRead,
    });
    assert.equal(code, 3, 'nothing could prove it owns the port, and that verdict is run\'s to make (Codex T5 r7)');
    const state = readState(context.outputDir);
    assert.equal(state.collectorAlive, false);
    assert.equal(state.evidenceCopied, true, 'unverifiable bytes are still worth uploading for a human to read');
    assert.equal(state.evidenceAuthentic, false, 'the artifact is labeled as coming off the filesystem');
    assert.equal(state.reportRendered, true);
    // Through the publish step: "still worth a human's eyes" is a claim about
    // what reaches the artifact, not about what run wrote (Codex T5 r8).
    assert.equal(reportSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) }), 0);
    const staged = readFileSync(path.join(evidenceDirOf(context.outputDir), 'session.log'), 'utf8');
    assert.ok(staged.includes('CONFIRMED'),
      'this really is the forged file — labeling it, not hiding it, is what makes this safe');
    assert.equal(finishSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) }), 3,
      'forged bytes can be inspected but can never ride a green run');
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) });
  }
});

// Poll rather than sleep: the detached child below races run's commit, and a
// fixed wait would either be flaky or slow.
const waitUntil = async (predicate, timeoutMs = 20000) => {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (predicate()) return true;
    if (Date.now() >= deadline) return false;
    await new Promise((resolve) => { setTimeout(resolve, 10); });
  }
};

// The only way to assert on a diagnostic that goes to the step log. Restored in
// a finally, so a failure inside cannot silence the rest of the suite.
const captureStderr = async (body) => {
  const written = [];
  const original = process.stderr.write.bind(process.stderr);
  process.stderr.write = (chunk) => { written.push(String(chunk)); return true; };
  try {
    const result = await body();
    return { result, written: written.join('') };
  } finally {
    process.stderr.write = original;
  }
};

// THE round-7 test, and the round-6 Critical in its other suit. Everything here
// is done by a process running as the same OS user: kill the collector, write a
// forged session log at the derivable path, and leave a detached child to
// rewrite the state record to all-green in the window between run's commit and
// any later step reading it. The only thing that survives that is a verdict
// already made — which is why the unreachable class fails IN run.
test('a wrapped command that kills the collector, forges the log and poisons the state afterwards still cannot go green', async () => {
  const context = await startReal({ hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' });
  try {
    const before = readState(context.outputDir);
    const statePath = path.join(context.outputDir, 'action-state.json');
    // The detached child. It waits for run's CAS commit — `collectorAlive`
    // appears in the state file at that moment and never before — and only then
    // rewrites the record, so it cannot be clobbered by the commit it is
    // hiding from. This is exactly the window a post-command verdict would be
    // decided in.
    const poisoner = path.join(context.outputDir, 'poisoner.js');
    writeFileSync(poisoner, [
      "const fs = require('node:fs');",
      "const target = process.env.POISON_STATE_PATH;",
      "const deadline = Date.now() + 20000;",
      "const tick = () => {",
      "  let state = null;",
      "  try { state = JSON.parse(fs.readFileSync(target, 'utf8')); } catch { state = null; }",
      "  if (state && Object.prototype.hasOwnProperty.call(state, 'collectorAlive')) {",
      "    fs.writeFileSync(target, JSON.stringify({",
      "      ...state, collectorAlive: true, evidenceAuthentic: true, evidenceCopied: true, reportRendered: true,",
      "    }));",
      "    return;",
      "  }",
      "  if (Date.now() < deadline) setTimeout(tick, 10);",
      "};",
      "tick();",
      '',
    ].join('\n'));
    // 90 names the one way this could pass without the attack running.
    const attack = 'node -e "' + [
      'const fs = require(\'node:fs\');',
      'const cp = require(\'node:child_process\');',
      'const p = require(\'node:path\');',
      'if (!process.env.COLLECTOR_PID) process.exit(90);',
      // Same OS user, so the collector is killable by pid. The pid is handed
      // over rather than searched for (it is discoverable from the port) so the
      // test measures the defence, not the attacker's reconnaissance.
      'process.kill(Number(process.env.COLLECTOR_PID));',
      // A CONVINCING session, so nothing below can be explained away as a parse
      // failure: well-formed NDJSON, plausible events, and the verdict this
      // action never posted.
      'const lines = [',
      '{ ts: \'2026-08-14T00:00:00.000Z\', msg: \'npm test: 128 passing, 0 failing\' },',
      '{ ts: \'2026-08-14T00:00:01.000Z\', msg: \'no regressions detected in the affected paths\' },',
      '{ ts: \'2026-08-14T00:00:02.000Z\', type: \'hypothesis\', hypothesisId: \'H-demo\', status: \'CONFIRMED\', note: \'resolved by the fix\' },',
      '];',
      'fs.writeFileSync(p.join(process.env.FORGE_DEBUG_DIR, \'debug-\' + process.env.DEBUG_SESSION_ID + \'.log\'), lines.map((line) => JSON.stringify(line)).join(\'\\n\') + \'\\n\');',
      'const child = cp.spawn(process.execPath, [process.env.POISONER], { detached: true, stdio: \'ignore\' });',
      'child.unref();',
      'process.exit(0);',
    ].join('') + '"';
    const runCode = await runSubcommand({
      inputs: { ...context.inputs, runCommand: attack },
      outputDir: context.outputDir,
      env: {
        ...context.runEnv,
        FORGE_DEBUG_DIR: path.join(context.projectRoot, '.debug'),
        COLLECTOR_PID: String(before.pid),
        POISONER: poisoner,
        POISON_STATE_PATH: statePath,
      },
    });
    assert.equal(runCode, 3,
      'no collector could be proved, and that verdict belongs to the one process the command cannot revise');
    assert.equal(readState(context.outputDir).commandExitCode, 0,
      '90 = the pid was never handed over, so the collector was never killed and the attack did not run');

    // The forged bytes ARE staged, labeled — that part is deliberate, and the
    // renderer had no trouble with them, so the 3 above is a verdict rather
    // than a parse accident.
    // Through the publish step. The detached child may already have flipped
    // `reportRendered`, but this class rendered fine, so the flag is true
    // either way and report preserves what run staged regardless.
    const evidenceDir = evidenceDirOf(context.outputDir);
    assert.equal(reportSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) }), 0);
    const staged = readFileSync(path.join(evidenceDir, 'session.log'), 'utf8');
    assert.ok(staged.includes('CONFIRMED'), 'the forgery is staged for a human to read, not hidden');
    const rendered = JSON.parse(readFileSync(path.join(evidenceDir, 'report.json'), 'utf8'));
    assert.equal(rendered.schema, 1);
    assert.equal(rendered.session.events, 2, 'a perfectly renderable session — the forgery is convincing');

    // And the poisoning worked completely. This is the whole argument: the
    // record a later step would read is attacker-authored, so no later step can
    // be trusted with the verdict.
    assert.ok(await waitUntil(() => readState(context.outputDir)?.collectorAlive === true),
      'the detached child rewrote the state after run committed');
    const poisoned = readState(context.outputDir);
    assert.equal(poisoned.evidenceAuthentic, true, 'the state now claims the forgery is authenticated');
    assert.equal(finishSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) }), 0,
      'finish, reading that record, is fooled completely — which is exactly why it is no longer the one deciding');
    // The job is red regardless, because run already failed and a failed
    // composite step cannot be un-failed.
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) });
  }
});

// The same class with nobody attacking: the collector simply died. The outcome
// is identical — that is the point of a where-not-what change. Only the process
// making the call moved.
test('a collector that merely died still stages the labeled partial log, still fails the step, and still says why', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
    projectRoot, failOnCommandFailure: 'true',
  });
  writeSessionLog(projectRoot, 'ci-debug-abc', [
    { ts: '2026-08-14T00:00:00.000Z', msg: 'the last thing the collector wrote down' },
  ]);
  const { result: code, written } = await captureStderr(() => captureViaRun({
    outputDir,
    env: RUN_ENV,
    readLive: unreachableRead,
  }));
  assert.equal(code, 3, 'the exit table always said a collector dying before capture fails the job');
  const state = readState(outputDir);
  assert.equal(state.collectorAlive, false);
  assert.equal(state.evidenceCopied, true, 'partial evidence a human can read is the point of the fallback');
  assert.equal(state.evidenceAuthentic, false, 'the label is a reader\'s aid, never a gate');
  assert.equal(state.reportRendered, true, 'and it stays truthful about what was actually produced');
  assert.equal(reportSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' } }), 0);
  assert.ok(readFileSync(path.join(evidenceDirOf(outputDir), 'session.log'), 'utf8')
    .includes('the last thing the collector wrote down'),
    'and it is still there after the publish step, for the upload step to take');
  assert.match(written, /no collector on port 1 would serve session ci-debug-abc/);
  assert.match(written, /UNAUTHENTICATED partial evidence and failing this step/,
    'the step log says both what was staged and what it cost');
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3, 'finish agrees; the job was already red');
});

test('the wrapped command is handed no DEBUG_ACTION_* wiring and none of the runner\'s command files', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug',
    sessionId: 'ci-debug-abc', sessionToken: 'z'.repeat(43),
  });
  const commandFiles = {
    GITHUB_ENV: path.join(outputDir, 'github_env'),
    GITHUB_PATH: path.join(outputDir, 'github_path'),
    GITHUB_OUTPUT: path.join(outputDir, 'github_output'),
    GITHUB_STATE: path.join(outputDir, 'github_state'),
    GITHUB_STEP_SUMMARY: path.join(outputDir, 'github_step_summary'),
  };
  for (const file of Object.values(commandFiles)) writeFileSync(file, '');
  let handed = null;
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    // A production-shaped job env: exactly what action.yml puts in front of
    // the run step, plus the five command files the runner exports into every
    // step.
    env: {
      ...RUN_ENV,
      ...commandFiles,
      DEBUG_ACTION_OUTPUT_DIR: outputDir,
      DEBUG_ACTION_INVOCATION_NONCE: 'n1',
      DEBUG_ACTION_PORT: '8787',
      DEBUG_ACTION_RUN: 'npm test',
      GITHUB_REPOSITORY: 'owner/repo',
      UNRELATED_JOB_VAR: 'kept',
    },
    spawnCommand: (command, { env: commandEnv }) => { handed = commandEnv; return { status: 0 }; },
    readLive: collectorAnswer([{ ts: '2026-08-13T00:00:00.000Z', msg: 'served event' }]),
  });
  assert.equal(code, 0);
  assert.deepEqual(Object.keys(handed).filter((key) => key.startsWith('DEBUG_ACTION_')), [],
    'DEBUG_ACTION_OUTPUT_DIR points at action-state.json, which carries this run\'s session token and nonce');
  // Defence in depth, and explicitly NOT the boundary: GITHUB_ENV is how a
  // wrapped command reaches the environment of every LATER step, and
  // GITHUB_OUTPUT/GITHUB_STATE/GITHUB_STEP_SUMMARY are how it forges this
  // action's own published facts. Capture no longer depends on any of that
  // being denied — it happens in this process, with a key read before the
  // command existed — but there is no reason to hand the channel over
  // (Codex T5 r6 #4).
  for (const name of Object.keys(commandFiles)) {
    assert.equal(Object.prototype.hasOwnProperty.call(handed, name), false,
      `${name} is the runner's own control plane, not the wrapped command's`);
  }
  assert.equal(handed.UNRELATED_JOB_VAR, 'kept', 'only the action\'s own wiring and the runner\'s control plane are stripped');
  assert.equal(handed.GITHUB_REPOSITORY, 'owner/repo', 'the informational GITHUB_* environment survives — it commands nothing');
  // The documented injected contract is untouched by the strip.
  assert.equal(handed.DEBUG_SESSION_ID, 'ci-debug-abc');
  assert.equal(handed.DEBUG_SESSION_TOKEN, 'z'.repeat(43));
  assert.equal(handed.DEBUG_LOG_URL, 'http://127.0.0.1:1/log');
});

test('there is no launch token left to steal: the wrapped command cannot forge a verdict even with the state file in hand', async () => {
  const context = await startReal({ hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo' });
  try {
    // Previous rounds DETECTED this attack at capture time. This one removes
    // it. The wrapped command does everything a process running as the same
    // OS user can do — reads the state file at its derivable path (handed
    // over here so the test measures the defence, not the attacker's search)
    // and tries the collector's real endpoints with every credential it can
    // reach — and there is simply nothing there that can write a verdict.
    //
    // Each non-zero exit names a specific defence that failed, so this can
    // never pass because the attack quietly did not run.
    const steal = 'node -e "' + [
      'const fs = require(\'node:fs\');',
      // 92: production hands the run step DEBUG_ACTION_OUTPUT_DIR; the wrapped
      // command must not see it.
      'if (process.env.DEBUG_ACTION_OUTPUT_DIR !== undefined) process.exit(92);',
      // 94: the state file is readable — and worthless. No launch token.
      'const state = JSON.parse(fs.readFileSync(process.env.GUESSED_STATE_PATH, \'utf8\'));',
      'if (state.launchToken !== undefined) process.exit(94);',
      'const base = process.env.DEBUG_LOG_URL.replace(\'/log\', \'\');',
      'const auth = { \'content-type\': \'application/json\', Authorization: \'Bearer \' + process.env.DEBUG_SESSION_TOKEN };',
      'Promise.all([',
      // 95: the only credential it holds must not be able to post a verdict...
      'fetch(base + \'/hypothesis\', { method: \'POST\', headers: auth, body: JSON.stringify({ sessionId: process.env.DEBUG_SESSION_ID, hypothesisId: \'H-demo\', status: \'CONFIRMED\', note: \'forged\' }) }),',
      // 96: ...nor mint a fresh session to escalate through.
      'fetch(base + \'/session\', { method: \'POST\', headers: auth, body: JSON.stringify({ name: \'ci-debug\' }) }),',
      ']).then(([h, s]) => process.exit(h.status !== 401 ? 95 : (s.status !== 401 ? 96 : 0)));',
    ].join('') + '"';
    const runCode = await runSubcommand({
      inputs: { ...context.inputs, runCommand: steal },
      outputDir: context.outputDir,
      env: {
        ...context.runEnv,
        DEBUG_ACTION_OUTPUT_DIR: context.outputDir,
        GUESSED_STATE_PATH: path.join(context.outputDir, 'action-state.json'),
      },
    });
    assert.equal(runCode, 0);
    const state = readState(context.outputDir);
    assert.equal(state.commandExitCode, 0,
      '92 = env strip failed; 94 = the launch token was persisted; 95 = a session token posted a verdict; 96 = it minted a session');
    const onDisk = readFileSync(path.join(context.projectRoot, '.debug', `debug-${state.sessionId}.log`), 'utf8');
    assert.equal(onDisk.includes('CONFIRMED'), false, 'no verdict was ever recorded, forged or otherwise');
    // And capture is clean: the run is honest, so it stays green. The
    // hypothesis-set contract has nothing left to catch, which is the point —
    // it is now a belt over a structural guarantee.
    const code = await captureViaRun({ outputDir: context.outputDir, env: context.runEnv, inputs: context.inputs });
    assert.equal(code, 0);
    const after = readState(context.outputDir);
    assert.equal(after.collectorAlive, true);
    assert.equal(after.evidenceAuthentic, true);
    const staged = readFileSync(path.join(evidenceDirOf(context.outputDir), 'session.log'), 'utf8');
    const hypothesisLines = staged.split('\n').filter((line) => line.includes('"type":"hypothesis"'));
    assert.equal(hypothesisLines.length, 1, 'exactly the one line start posted');
    assert.equal(JSON.parse(hypothesisLines[0]).status, 'OPEN');
    assert.equal(finishSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) }), 0);
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) });
  }
});

test('run refuses outright when there is no state and when the state carries no session', async () => {
  const outputDir = makeTempDir();
  // Capture lives here now, so both of these are run's refusals rather than
  // report's no-ops: nothing downstream is trusted to notice.
  assert.equal(await captureViaRun({ outputDir, env: RUN_ENV }), 3);
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43) });
  assert.equal(await captureViaRun({ outputDir, env: RUN_ENV }), 3, 'no sessionId — start never completed its mint');
  // And report, holding no key and making no decision, simply publishes
  // nothing.
  assert.equal(reportSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' } }), 0);
});

test('a state carrying another invocation\'s nonce is refused before anything touches the collector — in run, and again in report', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43),
    sessionId: 'ci-debug-abc', projectRoot: makeTempDir(),
  });
  let probed = 0;
  const code = await captureViaRun({
    outputDir,
    env: { ...RUN_ENV, DEBUG_ACTION_INVOCATION_NONCE: 'other' },
    spawnCommand: () => { throw new Error('a refused run must never reach the wrapped command'); },
    readLive: async () => { probed += 1; return { entries: [], text: '', proof: null }; },
    renderReport: () => { throw new Error('a refused run must never reach the renderer'); },
  });
  assert.equal(code, 3);
  assert.equal(probed, 0, 'the refusal is settled from state alone, before any network contact');
  assert.equal(reportSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'other' } }), 3,
    'and report refuses the same state rather than publishing an invocation it does not own');
});

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

test('run stages evidence outside the lock but refuses to commit over a newer invocation, and advertises nothing it disowned', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const recorded = {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43),
    sessionId: 'ci-debug-abc', projectRoot, commandExitCode: 0,
  };
  writeState(outputDir, recorded);
  writeSessionLog(projectRoot, 'ci-debug-abc', [{ ts: '2026-08-13T00:00:00.000Z', msg: 'hand written event' }]);
  const githubOutput = path.join(outputDir, 'github_output');
  const stepSummary = path.join(outputDir, 'step_summary');
  writeFileSync(githubOutput, '');
  writeFileSync(stepSummary, '');
  const usurper = { nonce: 'n2', pid: 2222, port: 9999, sessionToken: 'y'.repeat(43), sessionName: 'other' };
  let claimed = false;
  const code = await captureViaRun({
    outputDir,
    env: { ...RUN_ENV, GITHUB_OUTPUT: githubOutput, GITHUB_STEP_SUMMARY: stepSummary },
    readLive: collectorAnswer([{ ts: '2026-08-13T00:00:00.000Z', msg: 'served event' }]),
    // Rendering happens OUTSIDE the critical section by design — a holder
    // that spawned two child processes could sit in the section for seconds,
    // and the stale threshold is 30s (recorded T4 r2 requirement). The seam
    // uses that window to let a second invocation claim the output-dir, which
    // is exactly the interleave the lock cannot prevent and the CAS must.
    renderReport: (sessionText, sessionId) => {
      if (!claimed) {
        claimed = true;
        writeState(outputDir, usurper);
      }
      return defaultRenderReport(sessionText, sessionId);
    },
  });
  assert.equal(code, 3, 'the nonce compare under the lock saw state it does not own');
  assert.deepEqual(readState(outputDir), usurper, 'the newer invocation keeps its state, byte for byte');
  // Resolved from the nonce THIS invocation ran under: the usurper's state is
  // in place by now, and a staging child is named for the invocation that
  // staged into it, not for whoever owns the output-dir afterwards.
  const evidenceDir = resolveEvidenceDir(outputDir, 'n1');
  assert.ok(existsSync(path.join(evidenceDir, 'report.md')),
    'the render already happened — it runs outside the lock, so ownership is decided after it');
  assert.equal(readFileSync(githubOutput, 'utf8'), '',
    'a report-path emitted from state we just declined to own would be a lie');
  assert.equal(readFileSync(stepSummary, 'utf8'), '',
    'and so would a step summary for a run this invocation no longer owns');
  assert.ok(!existsSync(path.join(outputDir, 'action-state.lock')), 'the critical section released behind it');
});

test('run records an unauthenticated collector without inventing evidence, and fails the step itself', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43),
    sessionId: 'ci-debug-abc', projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
  });
  writeSessionLog(projectRoot, 'ci-debug-abc', [{ ts: '2026-08-13T00:00:00.000Z', msg: 'last words' }]);
  const code = await captureViaRun({
    outputDir,
    env: RUN_ENV,
    // Dead, or replaced by something that cannot answer at all — the two are
    // indistinguishable from here, and both mean the same thing: no
    // authoritative source for this session's bytes.
    readLive: unreachableRead,
  });
  // A collector that cannot be reached is not an INTEGRITY failure — the
  // labeled fallback is still staged — but it is still this step's failure,
  // because the alternative is handing the verdict to a later step whose view
  // of state a co-resident process can rewrite (Codex T5 r7).
  assert.equal(code, 3);
  const state = readState(outputDir);
  assert.equal(state.collectorAlive, false);
  assert.equal(state.evidenceCopied, true, 'whatever was readable is still staged');
  assert.equal(state.evidenceAuthentic, false, 'and it is labeled as unverified in the state file');
  assert.equal(state.reportRendered, true);
  assert.equal(reportSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' } }), 0);
  assert.ok(readFileSync(path.join(evidenceDirOf(outputDir), 'session.log'), 'utf8').includes('last words'),
    'and it survives the publish step, which is the only way the upload step can receive it');
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3,
    'finish agrees, as a belt over a job that is already red');
});

test('run returns 3 when there is nothing to stage at all — evidence is the product, so its absence fails closed', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43),
    sessionId: 'ci-debug-missing', projectRoot,
  });
  const githubOutput = path.join(outputDir, 'github_output');
  writeFileSync(githubOutput, '');
  const code = await captureViaRun({
    outputDir,
    env: { ...RUN_ENV, GITHUB_OUTPUT: githubOutput },
    readLive: unreachableRead,
    renderReport: () => { throw new Error('nothing was staged, so nothing can be rendered'); },
  });
  assert.equal(code, 3);
  const state = readState(outputDir);
  assert.equal(state.evidenceCopied, false);
  assert.equal(state.evidenceAuthentic, false);
  assert.equal(state.reportRendered, false);
  assert.equal(state.collectorAlive, false, 'the liveness fact is still recorded — it was observed');
  // The command's own exit code is still published — finish needs it, and it
  // is a fact this process observed. What is withheld is every output that
  // would ASSERT evidence: no path, no digest, no event count.
  const published = readFileSync(githubOutput, 'utf8');
  // Exactly two lines, and neither of them tells the upload step anything:
  // its gate and its paths come from `start`, before the wrapped command
  // existed (Codex T6 r2 #1).
  assert.equal(published, 'command-exit-code=0\nsession-id=ci-debug-missing\n');
  for (const name of ['report-path', 'evidence-digest', 'event-count']) {
    assert.equal(published.includes(name), false, `${name} is not emitted for a report that does not exist`);
  }
});

test('the staged log is the collector\'s answer, not whatever is on disk under that name', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const sessionToken = 'x'.repeat(43);
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 4321, sessionToken, hypothesisId: 'H-demo',
    sessionId: 'ci-debug-abc', projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
  });
  // What a wrapped command left at the well-known path. A pathname copy would
  // stage this; the authenticated path never opens it.
  writeSessionLog(projectRoot, 'ci-debug-abc', [{ ts: '2026-08-13T00:00:00.000Z', msg: 'FORGED disk line' }]);
  const served = [
    { ts: '2026-08-13T00:00:01.000Z', msg: 'served by the collector' },
    { ts: '2026-08-13T00:00:02.000Z', type: 'hypothesis', hypothesisId: 'H-demo', status: 'OPEN' },
  ];
  const answer = collectorAnswer(served);
  const reads = [];
  const code = await captureViaRun({
    outputDir,
    env: RUN_ENV,
    readLive: async (options) => { reads.push(options); return answer(options); },
  });
  assert.equal(code, 0);
  const staged = readFileSync(path.join(evidenceDirOf(outputDir), 'session.log'), 'utf8');
  assert.equal(staged, served.map((line) => `${JSON.stringify(line)}\n`).join(''),
    'the bytes the proof covers are the bytes staged, verbatim and in order');
  assert.ok(!staged.includes('FORGED disk line'), 'the file at the well-known path was never opened');
  assert.equal(readState(outputDir).evidenceAuthentic, true);
  // Addressed with exactly what start recorded, carrying a fresh challenge
  // and both bounds.
  assert.equal(reads.length, 1);
  assert.equal(reads[0].port, 4321);
  assert.equal(reads[0].token, sessionToken, 'the session token is the read credential');
  assert.equal(reads[0].sessionId, 'ci-debug-abc');
  assert.equal(reads[0].timeoutMs, 5000);
  assert.ok(reads[0].deadlineMs > 0, 'the read carries an absolute bound, not just an idle timeout');
  assert.match(reads[0].challenge, /^[0-9a-f]{64}$/, 'a fresh 256-bit nonce per capture');
});

test('a live read the collector refuses is an evidence-integrity failure, never a reason to fall back to the disk', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43),
    sessionId: 'ci-debug-abc', projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
  });
  // Readable, parsable, and a lie. The old pathname copy would have staged
  // and rendered it (Codex T5 #1).
  writeSessionLog(projectRoot, 'ci-debug-abc', [
    { ts: '2026-08-13T00:00:00.000Z', type: 'hypothesis', hypothesisId: 'H-demo', status: 'CONFIRMED' },
  ]);
  const code = await captureViaRun({
    outputDir,
    env: RUN_ENV,
    // 409 session_log_replaced: the collector's own identity check found that
    // the file it wrote is not the file on disk.
    readLive: async () => { throw new Error('live_read_log_replaced'); },
    spawnReport: () => { throw new Error('nothing was staged, so nothing can be rendered'); },
  });
  assert.equal(code, 3);
  const state = readState(outputDir);
  assert.equal(state.collectorAlive, false, 'a refused read is not an authenticated read');
  assert.equal(state.evidenceCopied, false);
  assert.equal(state.evidenceAuthentic, false);
  assertNothingStaged(evidenceDirOf(outputDir), 'the readable file at the well-known path is not a fallback');
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3);
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
      nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
      projectRoot, commandExitCode: 0, failOnCommandFailure: 'true', ...hypothesisState,
    });
    const code = await captureViaRun({
      outputDir,
      env: RUN_ENV,
      readLive: collectorAnswer(served),
      renderReport: () => { throw new Error('forged evidence must never reach the renderer'); },
    });
    assert.equal(code, 3, label);
    assert.equal(readState(outputDir).evidenceCopied, false, label);
    assertNothingStaged(evidenceDirOf(outputDir), `${label}: nothing is staged`);
    assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3, label);
  }
  // And the shape the action DID post is accepted, events and all — a check
  // that refused everything would pass the cases above while breaking capture.
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
    projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
    hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo',
  });
  assert.equal(await captureViaRun({
    outputDir,
    env: RUN_ENV,
    readLive: collectorAnswer([event, openLine]),
  }), 0, 'the action\'s own set is exactly what capture accepts');
  assert.equal(readState(outputDir).evidenceAuthentic, true);
});

test('an entry the hypothesis check cannot inspect is refused rather than skipped', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
    projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
  });
  // A line whose parsed form is missing or is not an object cannot be
  // classified. Skipping it would let a forged hypothesis through any future
  // path that produced this shape, so it fails closed instead — even though
  // the answer is otherwise perfectly signed.
  const uninspectable = '{"type":"hypothesis","status":"CONFIRMED"}';
  const text = `${uninspectable}\n`;
  const code = await captureViaRun({
    outputDir,
    env: RUN_ENV,
    readLive: async ({ challenge }) => ({
      entries: [{ raw: uninspectable }],
      text,
      proof: proofFor(RESPONDER_KEYS.privateKey, challenge, text),
    }),
    renderReport: () => { throw new Error('an uninspectable capture must never reach the renderer'); },
  });
  assert.equal(code, 3);
  assert.equal(readState(outputDir).evidenceCopied, false);
});

test('staging is invocation-scoped on EVERY entry path, including the ones that return before capture', async () => {
  // Files sitting in the staging slots this invocation is about to use. Those
  // slots are invocation-scoped now, so this is not a previous run's directory
  // any more — it is a plant in THIS run's, which is the harder case: the
  // upload step is told to take exactly this directory, so anything left in it
  // ships as this run's evidence.
  const plantStale = (outputDir, nonce) => {
    const evidenceDir = resolveEvidenceDir(outputDir, nonce);
    mkdirSync(evidenceDir, { recursive: true });
    for (const [name, body] of [['session.log', '{"msg":"last run"}\n'], ['report.md', '## stale\n'], ['report.json', '{"schema":1}\n']]) {
      writeFileSync(path.join(evidenceDir, name), body);
    }
    return evidenceDir;
  };
  const assertCleared = (evidenceDir, label) => {
    for (const name of ['session.log', 'report.md', 'report.json']) {
      assert.ok(!existsSync(path.join(evidenceDir, name)), `${label}: ${name} must not survive into this invocation`);
    }
  };

  // 1. run's own refusals, which now come before any capture could happen.
  // The clear sits above them for the same reason it used to sit above
  // report's (Codex T5 r3 #3): these are precisely the paths where a previous
  // invocation's report is still sitting in the staging slots.
  const runRefusals = [
    ['run: absent state', {}, null],
    ['run: foreign nonce', { DEBUG_ACTION_INVOCATION_NONCE: 'other' },
      { nonce: 'n1', pid: 1, port: 1, sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43) }],
    ['run: state carrying no session', {}, { nonce: 'n1', pid: 1, port: 1 }],
  ];
  for (const [label, env, state] of runRefusals) {
    const refused = makeTempDir();
    // The identity a refusal runs under names the slots it has to clear.
    const refusedEvidence = plantStale(refused, { ...RUN_ENV, ...env }.DEBUG_ACTION_INVOCATION_NONCE);
    if (state !== null) writeState(refused, state);
    assert.equal(await captureViaRun({
      outputDir: refused,
      env: { ...RUN_ENV, ...env },
      spawnCommand: () => { throw new Error('a refused run never reaches the wrapped command'); },
    }), 3, label);
    assertCleared(refusedEvidence, label);
  }

  // 2. And report's, which are the last chance before the upload step: no
  // state at all — start never completed — and state belonging to somebody
  // else. Refusing to trust it must not mean leaving its predecessor's files
  // behind either.
  const noState = makeTempDir();
  const noStateEvidence = plantStale(noState, 'n1');
  assert.equal(reportSubcommand({ outputDir: noState, env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' } }), 0);
  assertCleared(noStateEvidence, 'absent state');

  // The predecessor's state says its capture SUCCEEDED — evidenceCopied and
  // all — which is exactly the state that now buys a session log a reprieve
  // from the cleanup. That reprieve is scoped to the invocation that earned it:
  // preserving another run's log here would ship it under this run's artifact
  // name (Codex T5 r8, guarding r2 #3).
  const foreign = makeTempDir();
  const foreignEvidence = plantStale(foreign, 'other');
  writeState(foreign, {
    nonce: 'n1', pid: 1, port: 1, sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43),
    evidenceCopied: true, evidenceAuthentic: true, collectorAlive: true,
  });
  assert.equal(reportSubcommand({ outputDir: foreign, env: { DEBUG_ACTION_INVOCATION_NONCE: 'other' } }), 3);
  assertCleared(foreignEvidence, 'foreign nonce');

  // 3. A real attempt that captures nothing.
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const evidenceDir = plantStale(outputDir, 'n1');
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
    projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
  });
  const code = await captureViaRun({
    outputDir,
    env: RUN_ENV,
    readLive: unreachableRead,
    renderReport: () => { throw new Error('nothing was staged, so nothing can be rendered'); },
  });
  assert.equal(code, 3);
  assertCleared(evidenceDir, 'failed capture');
});

test('a foreign occupant answering 401 fails liveness and licenses only labeled partial evidence', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
    projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
  });
  writeSessionLog(projectRoot, 'ci-debug-abc', [{ ts: '2026-08-13T00:00:00.000Z', msg: 'whatever is on disk' }]);
  const code = await captureViaRun({
    outputDir,
    env: RUN_ENV,
    // Our collector died and something else took the port. It answers — but
    // not for our session, which is exactly what the session-token read scope
    // is there to distinguish (Codex T5 r3).
    readLive: async () => { throw new Error('live_read_unauthorized'); },
  });
  assert.equal(code, 3, 'a step that could not reach its own collector has not produced evidence');
  const state = readState(outputDir);
  assert.equal(state.collectorAlive, false, 'a stranger on the port is not our collector');
  assert.equal(state.evidenceAuthentic, false);
  assert.equal(state.evidenceCopied, true, 'the on-disk log is still worth a human\'s eyes');
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3, 'and it can never ride a green run');
});

test('a renderer that returns without producing a schema-1 report publishes nothing', async () => {
  const cases = [
    ['truncated JSON', '{"schema":1,"session":{"events":'],
    ['a schema this action does not speak', JSON.stringify({ schema: 2, session: { events: 3 } })],
    ['a negative event count', JSON.stringify({ schema: 1, session: { events: -1 } })],
    ['no session block at all', JSON.stringify({ schema: 1 })],
  ];
  for (const [label, rendered] of cases) {
    const outputDir = makeTempDir();
    const projectRoot = makeTempDir();
    writeState(outputDir, {
      nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43),
      sessionId: 'ci-debug-abc', projectRoot, commandExitCode: 0, failOnCommandFailure: 'true',
    });
    const githubOutput = path.join(outputDir, 'github_output');
    const stepSummary = path.join(outputDir, 'step_summary');
    writeFileSync(githubOutput, '');
    writeFileSync(stepSummary, '');
    const code = await captureViaRun({
      outputDir,
      env: { ...RUN_ENV, GITHUB_OUTPUT: githubOutput, GITHUB_STEP_SUMMARY: stepSummary },
      readLive: collectorAnswer([{ ts: '2026-08-13T00:00:00.000Z', msg: 'served event' }]),
      // A renderer that RETURNS rubbish rather than throwing is the whole
      // point: nothing but a shape check on what it produced can catch that
      // (Codex T5 #2).
      renderReport: () => ({ markdown: '## Debug evidence report\n', json: rendered }),
    });
    const evidenceDir = evidenceDirOf(outputDir);
    assert.equal(code, 3, label);
    assert.equal(readState(outputDir).reportRendered, false, label);
    assert.ok(!existsSync(path.join(evidenceDir, 'report.json')), `${label}: nothing is written before the shape is checked`);
    assert.ok(!existsSync(path.join(evidenceDir, 'report.md')), `${label}: the markdown is withheld with it`);
    const published = readFileSync(githubOutput, 'utf8');
    for (const name of ['report-path', 'evidence-digest', 'event-count']) {
      assert.equal(published.includes(name), false, `${label}: ${name} is withheld`);
    }
    assert.equal(readFileSync(stepSummary, 'utf8'), '', label);
    // The capture itself succeeded, and stays staged for a human — through the
    // publish step, which is where the upload step receives it from.
    assert.equal(readState(outputDir).evidenceCopied, true, label);
    const kept = readFileSync(path.join(evidenceDir, 'session.log'));
    assert.equal(reportSubcommand({
      outputDir,
      env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1', GITHUB_STEP_SUMMARY: stepSummary },
    }), 0, label);
    assert.deepEqual(readFileSync(path.join(evidenceDir, 'session.log')), kept, `${label}: the authenticated log survives`);
  }
});

// The publish step runs `if: always()`, so "staged" only means anything if it
// survives report. Round 6 staged the authenticated log on the renderer-failure
// classes deliberately — real evidence a human can read — and round 8 found
// that report's entry cleanup then deleted it before the upload step could
// receive it, because it read `reportRendered !== true` as "nothing was
// captured". This test runs the actual sequence rather than asserting on run's
// output and stopping there (Codex T5 r8).
test('a renderer failure costs the report surfaces and nothing else: the authenticated log survives report, byte for byte', async () => {
  for (const [label, renderReport] of [
    ['a renderer that throws', () => { throw new Error('renderer exploded'); }],
    ['a renderer that returns no schema-1 report', () => ({ markdown: '## Debug evidence report\n', json: '{}' })],
  ]) {
    const outputDir = makeTempDir();
    const projectRoot = makeTempDir();
    writeState(outputDir, {
      nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43),
      sessionId: 'ci-debug-abc', projectRoot, failOnCommandFailure: 'true',
    });
    const stepSummary = path.join(outputDir, 'step_summary');
    writeFileSync(stepSummary, '');
    const served = [
      { ts: '2026-08-14T00:00:00.000Z', msg: 'the events this session really recorded' },
      { ts: '2026-08-14T00:00:01.000Z', msg: 'and the reason a human wants them' },
    ];
    const runCode = await captureViaRun({
      outputDir,
      env: { ...RUN_ENV, DEBUG_ACTION_INVOCATION_NONCE: 'n1' },
      readLive: collectorAnswer(served),
      renderReport,
    });
    assert.equal(runCode, 3, `${label}: no report means no evidence product`);
    const evidenceDir = evidenceDirOf(outputDir);
    const captured = readFileSync(path.join(evidenceDir, 'session.log'));
    assert.equal(captured.toString('utf8'), served.map((line) => `${JSON.stringify(line)}\n`).join(''),
      `${label}: run staged the bytes the collector proved`);

    // The step that runs next in production, with this invocation's nonce —
    // exactly as action.yml wires it.
    assert.equal(reportSubcommand({
      outputDir,
      env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1', GITHUB_STEP_SUMMARY: stepSummary },
    }), 0, `${label}: publishing nothing is not report's failure`);
    assert.deepEqual(readFileSync(path.join(evidenceDir, 'session.log')), captured,
      `${label}: the authenticated log reaches the upload step unchanged`);
    for (const name of ['report.md', 'report.json']) {
      assert.ok(!existsSync(path.join(evidenceDir, name)),
        `${label}: the surfaces that do not exist are the ones cleared`);
    }
    assert.equal(readFileSync(stepSummary, 'utf8'), '',
      `${label}: there is no report to append, so the summary is left alone`);
    // And the job is red regardless, on run's verdict.
    assert.equal(finishSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' } }), 3, label);
  }
});

test('finish taxonomy: missing state 3; missing exit code 3; dead collector 3; command failure mirrors or is waived by the toggle', async () => {
  const outputDir = makeTempDir();
  // An identity with no state behind it, which is what a `start` that emitted
  // its nonce and then failed leaves behind.
  assert.equal(finishSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'n' } }), 3, 'no state');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true' });
  assert.equal(finishSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'other' } }), 3, 'nonce mismatch');
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3, 'run never recorded an exit code');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 0, collectorAlive: false, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3, 'collector died before capture');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 0, collectorAlive: true, evidenceCopied: false, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3, 'nothing was captured');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 7, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 7, 'mirrors the command exit code');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'false', commandExitCode: 7, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 0, 'toggle waives the failure');
  // A toggle validateActionInputs could never have produced means the state
  // file is corrupt or forged, and the exit code sitting next to it is worth
  // no more than the toggle is — so it is a 3 on a failing run AND on a green
  // one, not a "treat anything but false as true" (Codex T5 #3).
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'maybe', commandExitCode: 7, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3, 'an out-of-contract toggle is refused, not reinterpreted');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'maybe', commandExitCode: 0, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3, 'and refused on a green run too, where it would otherwise pass unread');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 300, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 1, 'out-of-range exit codes clamp to 1');
  writeState(outputDir, { nonce: 'n', failOnCommandFailure: 'true', commandExitCode: 0, collectorAlive: true, evidenceCopied: true, reportRendered: true });
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 0, 'green run');
});

test('the terminal main() catch redacts state tokens from stderr', async () => {
  const { spawnSync: spawnSyncChild } = require('node:child_process');
  const outputDir = makeTempDir();
  const token = ['fake-launch-', 'token-', 'abcdefghijklmnop'].join('');
  writeState(outputDir, { nonce: 'n1', pid: 1, port: 1, sessionToken: token });
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

// A listener that speaks the logs route's contract perfectly: 200, the right
// content type, well-formed NDJSON carrying exactly the hypothesis set the
// action posted. Everything capture checked before this round it satisfies —
// which is the point. `sign` decides what proof, if any, it returns.
const counterfeitCollector = async (sign) => {
  const served = [
    { ts: '2026-08-14T00:00:00.000Z', msg: 'looks just like a real event' },
    { ts: '2026-08-14T00:00:01.000Z', type: 'hypothesis', hypothesisId: 'H-demo', status: 'OPEN', title: 'seeded demo' },
  ];
  const body = served.map((line) => `${JSON.stringify(line)}\n`).join('');
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request.headers['x-debug-challenge']);
    const headers = { 'Content-Type': 'application/x-ndjson' };
    const proof = sign(request.headers['x-debug-challenge'], body, requests.length);
    if (proof !== null) headers['x-debug-proof'] = proof;
    response.writeHead(200, headers);
    response.end(body);
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port,
    body,
    requests,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
};

const counterfeitState = (outputDir, projectRoot, port) => writeState(outputDir, {
  nonce: 'n1', pid: 1, port, sessionName: 'ci-debug',
  sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43), projectRoot,
  hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo',
  commandExitCode: 0, failOnCommandFailure: 'true',
});

test('a counterfeit collector serving perfect NDJSON is refused: capture believes proof, not shape', async () => {
  for (const [label, sign] of [
    ['no proof at all', () => null],
    ['a signature from a keypair it generated itself', (challenge, body) => proofFor(IMPOSTOR_KEYS.privateKey, challenge, body)],
    ['a signature over different bytes', (challenge) => proofFor(RESPONDER_KEYS.privateKey, challenge, 'other bytes entirely')],
    ['a signature over a challenge it chose itself', (_challenge, body) => proofFor(RESPONDER_KEYS.privateKey, 'a-nonce-nobody-asked-for-000000', body)],
    ['a signature over a narrower request target', (challenge, body) => proofFor(RESPONDER_KEYS.privateKey, challenge, body, '/sessions/ci-debug-abc/logs?limit=1')],
  ]) {
    const outputDir = makeTempDir();
    const projectRoot = makeTempDir();
    // The wrapped command's own log, left where a pathname copy would find it.
    writeSessionLog(projectRoot, 'ci-debug-abc', [{ ts: '2026-08-14T00:00:00.000Z', msg: 'disk fallback bait' }]);
    const fake = await counterfeitCollector(sign);
    try {
      counterfeitState(outputDir, projectRoot, fake.port);
      // No readLive seam: the real reader, the real HTTP request, the real
      // verification. Only the listener is fake — which is exactly the attack,
      // a wrapped command rewriting `port` in a state file it can write and
      // standing up its own server there.
      const code = await captureViaRun({ outputDir, env: RUN_ENV });
      assert.equal(code, 3, label);
      const state = readState(outputDir);
      assert.equal(state.collectorAlive, false, `${label}: an unprovable answer is not a live collector`);
      assert.equal(state.evidenceCopied, false, label);
      assert.equal(state.evidenceAuthentic, false, label);
      assertNothingStaged(evidenceDirOf(outputDir), `${label}: an unproven answer is never staged`);
      // And it must not slide into the unreachable class either: a listener
      // that answers is not an absent collector, so the on-disk log is not a
      // licensed fallback here.
      assert.equal(
        readFileSync(path.join(projectRoot, '.debug', 'debug-ci-debug-abc.log'), 'utf8').includes('disk fallback bait'),
        true,
        `${label}: the bait is still on disk, and still unstaged`,
      );
      assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3, label);
      assert.equal(fake.requests.length, 1, `${label}: challenged exactly once`);
      assert.match(fake.requests[0], /^[0-9a-f]{64}$/, `${label}: with a fresh nonce`);
    } finally {
      await fake.close();
    }
  }
});

test('a recorded answer cannot be replayed: an old proof does not answer a fresh challenge', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  let recorded = null;
  // First request: sign honestly, as the real collector would. Every later
  // request: replay that exact (body, proof) pair — the strongest move
  // available to an attacker who once observed a valid answer.
  const listener = await counterfeitCollector((challenge, body, nth) => {
    if (nth === 1) recorded = proofFor(RESPONDER_KEYS.privateKey, challenge, body);
    return recorded;
  });
  try {
    counterfeitState(outputDir, projectRoot, listener.port);
    const first = await captureViaRun({ outputDir, env: RUN_ENV });
    assert.equal(first, 0, 'a correctly signed answer is accepted');
    assert.equal(readState(outputDir).evidenceAuthentic, true);

    const replayed = await captureViaRun({ outputDir, env: RUN_ENV });
    assert.equal(replayed, 3, 'the same proof against a fresh nonce is not a proof');
    const state = readState(outputDir);
    assert.equal(state.collectorAlive, false);
    assert.equal(state.evidenceCopied, false);
    assertNothingStaged(evidenceDirOf(outputDir),
      'and entry cleanup means the first capture is not left behind to pass as this one');
    assert.notEqual(listener.requests[0], listener.requests[1], 'each capture challenged with a different nonce');
  } finally {
    await listener.close();
  }
});

test('capture refuses when the responder key never reached this step, rather than trusting the port', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeSessionLog(projectRoot, 'ci-debug-abc', [{ ts: '2026-08-14T00:00:00.000Z', msg: 'on disk' }]);
  const listener = await counterfeitCollector((challenge, body) => proofFor(RESPONDER_KEYS.privateKey, challenge, body));
  try {
    counterfeitState(outputDir, projectRoot, listener.port);
    // Wiring broken: action.yml did not pass the step output through, so this
    // step cannot verify anything. That is an integrity failure, not a missing
    // collector — falling back to the on-disk log would hand back bytes with no
    // provenance at all and call them evidence.
    const code = await captureViaRun({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' } });
    assert.equal(code, 3);
    const state = readState(outputDir);
    assert.equal(state.collectorAlive, false);
    assert.equal(state.evidenceCopied, false);
    assertNothingStaged(evidenceDirOf(outputDir), 'no key, no staging');
    assert.equal(listener.requests.length, 0, 'nothing is even asked without a way to check the answer');
  } finally {
    await listener.close();
  }
});

test('render and digest never re-read the staged path: the payload is one immutable buffer', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const evidenceDir = resolveEvidenceDir(outputDir, 'n1');
  const lines = [
    { ts: '2026-08-14T00:00:00.000Z', msg: 'the bytes this run captured' },
    { ts: '2026-08-14T00:00:01.000Z', type: 'hypothesis', hypothesisId: 'H-demo', status: 'OPEN', title: 'seeded demo' },
  ];
  const captured = lines.map((line) => `${JSON.stringify(line)}\n`).join('');
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug',
    sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43), projectRoot,
    hypothesisId: 'H-demo', hypothesisTitle: 'seeded demo',
    commandExitCode: 0, failOnCommandFailure: 'true',
  });
  const printed = [];
  const githubOutput = path.join(outputDir, 'github_output');
  writeFileSync(githubOutput, '');
  const handed = [];
  const code = await captureViaRun({
    outputDir,
    env: { ...RUN_ENV, GITHUB_OUTPUT: githubOutput },
    readLive: collectorAnswer(lines),
    // The renderer is handed BYTES, never a path — assert that directly — and
    // it uses the moment it is called to plant a forgery at the staged path.
    // A render or a hash that re-read that path would pick the forgery up; the
    // final write overwrites it, and the digest describes the capture.
    renderReport: (sessionText, sessionId) => {
      handed.push([sessionText, sessionId]);
      mkdirSync(evidenceDir, { recursive: true });
      writeFileSync(path.join(evidenceDir, 'session.log'), '{"msg":"FORGED mid-flight"}\n');
      return defaultRenderReport(sessionText, sessionId);
    },
    writeStdout: (text) => printed.push(text),
  });
  assert.equal(code, 0);
  assert.deepEqual(handed, [[captured, 'ci-debug-abc']],
    'the renderer receives the captured bytes and the real session id, not a filename');
  const staged = readFileSync(path.join(evidenceDir, 'session.log'), 'utf8');
  assert.equal(staged, captured, 'the write is the last word; the mid-flight forgery is gone');
  const reportJson = JSON.parse(readFileSync(path.join(evidenceDir, 'report.json'), 'utf8'));
  assert.equal(reportJson.session.id, 'ci-debug-abc', 'rendered from memory, so the session id is the real one');
  assert.equal(reportJson.session.events, 1);
  assert.equal(reportJson.hypotheses[0].status, 'OPEN');
  assert.ok(!readFileSync(path.join(evidenceDir, 'report.md'), 'utf8').includes('FORGED mid-flight'));
  // Every digest describes the bytes this invocation decided to stage.
  const expected = `evidence-sha256 ${['session.log', 'report.md', 'report.json']
    .map((file) => `${file}=${createHash('sha256').update(readFileSync(path.join(evidenceDir, file))).digest('hex')}`)
    .join(' ')}`;
  assert.deepEqual(printed, [`${expected}\n`]);
  assert.ok(readFileSync(githubOutput, 'utf8').includes(`evidence-digest=${expected}\n`));
});

test('a swap after staging is DETECTABLE: the logged digests still describe what was captured', async () => {
  const context = await fullLifecycle();
  const printed = [];
  try {
    const code = await captureViaRun({
      inputs: context.inputs,
      outputDir: context.outputDir,
      env: { ...context.runEnv, GITHUB_OUTPUT: context.githubOutput },
      writeStdout: (text) => printed.push(text),
    });
    assert.equal(code, 0);
    const evidenceDir = evidenceDirOf(context.outputDir);
    const logged = printed[0].trim();
    // The window this cannot close: staging and upload are separate steps of
    // one composite action, same user, so a detached child can still rewrite
    // these files. What it CAN do is make that rewrite visible — the step log
    // is streamed and immutable, and the digests in it describe the capture,
    // not whatever is on disk at upload time.
    for (const name of ['session.log', 'report.md', 'report.json']) {
      writeFileSync(path.join(evidenceDir, name), 'swapped after the fact\n');
      const actual = createHash('sha256').update(readFileSync(path.join(evidenceDir, name))).digest('hex');
      assert.equal(logged.includes(`${name}=${actual}`), false,
        `${name}: the swapped bytes must not match the digest that was logged`);
    }
    // And the machine surface carries the same record, so a consumer can
    // compare without scraping the log.
    assert.ok(readFileSync(context.githubOutput, 'utf8').includes(`evidence-digest=${logged}\n`));
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) });
  }
});

test('the digests are computed from the payload, not from the sink: a lossy write is caught, not blessed', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const evidenceDir = resolveEvidenceDir(outputDir, 'n1');
  const lines = [{ ts: '2026-08-14T00:00:00.000Z', msg: 'the bytes this run captured' }];
  const captured = lines.map((line) => `${JSON.stringify(line)}\n`).join('');
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug',
    sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43), projectRoot,
    commandExitCode: 0, failOnCommandFailure: 'true',
  });
  const printed = [];
  const code = await captureViaRun({
    outputDir,
    env: RUN_ENV,
    readLive: collectorAnswer(lines),
    // The sink stands in for everything that can happen to a file after this
    // process decides what belongs in it — a detached child mid-write, a
    // filesystem that lies. Whatever lands here, the digest must still be the
    // one over the captured payload, or the step log would be endorsing the
    // swap instead of exposing it.
    stageFile: (filePath) => {
      mkdirSync(path.dirname(filePath), { recursive: true });
      writeFileSync(filePath, 'the sink wrote something else entirely\n');
    },
    writeStdout: (text) => printed.push(text),
  });
  assert.equal(code, 0);
  assert.equal(printed.length, 1);
  const logged = printed[0].trim();
  assert.ok(logged.includes(`session.log=${createHash('sha256').update(captured, 'utf8').digest('hex')}`),
    'the logged digest is the one over the captured bytes');
  for (const name of ['session.log', 'report.md', 'report.json']) {
    const onDisk = createHash('sha256').update(readFileSync(path.join(evidenceDir, name))).digest('hex');
    assert.equal(logged.includes(`${name}=${onDisk}`), false,
      `${name}: hashing the file back would have described the swap and called it evidence`);
  }
});

// The oracle attack. This counterfeit signs nothing itself — it cannot, and
// does not need to. It forwards capture's own fresh challenge to the REAL
// collector with a filter bolted onto the target, and hands back the answer
// the real collector genuinely signed. Every byte is authentic; every
// signature is valid; the evidence is a fraction of the truth.
const relayCollector = async (realPort, extraQuery) => {
  const targets = [];
  const server = http.createServer((request, response) => {
    targets.push(request.url);
    const upstream = http.request({
      hostname: '127.0.0.1',
      port: realPort,
      // The whole attack in one line: the caller asked for the session, we ask
      // for a slice of it, and the collector signs what it was asked for.
      path: `${request.url}${extraQuery}`,
      method: 'GET',
      // Everything the caller sent, including its Bearer token and its fresh
      // challenge — with Host rewritten, which any relay must do and which the
      // collector's own loopback-host check would otherwise reject.
      headers: { ...request.headers, host: `127.0.0.1:${realPort}` },
    }, (up) => {
      let body = '';
      up.setEncoding('utf8');
      up.on('data', (chunk) => { body += chunk; });
      up.on('end', () => {
        const headers = { 'Content-Type': 'application/x-ndjson' };
        if (up.headers['x-debug-proof']) headers['x-debug-proof'] = up.headers['x-debug-proof'];
        response.writeHead(up.statusCode, headers);
        response.end(body);
      });
    });
    upstream.on('error', () => { response.writeHead(502); response.end(); });
    upstream.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: server.address().port,
    targets,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
};

test('a relay that filters the real collector\'s answer is refused: the signature covers the request, not just the bytes', async () => {
  // No hypothesis-id, so the expected hypothesis set is empty and a subset of
  // plain events would sail through every content check. The only thing that
  // can catch this is the signature not covering the target that was asked.
  const context = await startReal();
  try {
    const probe = 'node -e "' + [
      'const post = (msg) => fetch(process.env.DEBUG_LOG_URL, { method: \'POST\', headers: { \'content-type\': \'application/json\', \'x-debug-session-token\': process.env.DEBUG_SESSION_TOKEN }, body: JSON.stringify({ sessionId: process.env.DEBUG_SESSION_ID, msg }) });',
      'Promise.all([\'first finding\', \'second finding\', \'the finding that matters\'].map(post)).then((rs) => process.exit(rs.every((r) => r.status === 202) ? 0 : 99));',
    ].join('') + '"';
    const runCode = await runSubcommand({
      inputs: { ...context.inputs, runCommand: probe },
      outputDir: context.outputDir,
      env: context.runEnv,
    });
    assert.equal(runCode, 0);
    assert.equal(readState(context.outputDir).commandExitCode, 0, 'all three events reached the collector');

    const relay = await relayCollector(context.port, '?type=event&limit=1');
    try {
      // The wrapped command's parting move: point the state file's port at the
      // relay. Everything else about the state is honest.
      const state = readState(context.outputDir);
      writeState(context.outputDir, { ...state, port: relay.port });
      const code = await captureViaRun({ outputDir: context.outputDir, env: context.runEnv, inputs: context.inputs });
      assert.equal(code, 3, 'a validly signed answer to a DIFFERENT question is not evidence');
      assert.equal(relay.targets.length, 1, 'the relay was asked exactly once');
      assert.equal(relay.targets[0].includes('?'), false, 'capture asked for the whole session, unfiltered');
      const after = readState(context.outputDir);
      assert.equal(after.collectorAlive, false);
      assert.equal(after.evidenceCopied, false);
      assert.equal(after.evidenceAuthentic, false);
      assertNothingStaged(evidenceDirOf(context.outputDir),
        'a truncated session is never staged, however genuine its signature');
      assert.equal(finishSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) }), 3);
    } finally {
      await relay.close();
    }
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) });
  }
});

test('a verification key planted in state is ignored: only runner memory can say who to trust', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  writeSessionLog(projectRoot, 'ci-debug-abc', [{ ts: '2026-08-14T00:00:00.000Z', msg: 'disk fallback bait' }]);
  // The wrapped command's best move once the key stopped being a secret:
  // generate its own keypair, sign its own answers with the private half, and
  // plant the public half wherever capture might look for it. State is the
  // one place it can write — so state must not be one of those places.
  const listener = await counterfeitCollector((challenge, body) => proofFor(IMPOSTOR_KEYS.privateKey, challenge, body));
  try {
    const impostorVerifyKey = IMPOSTOR_KEYS.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    writeState(outputDir, {
      nonce: 'n1', pid: 1, port: listener.port, sessionName: 'ci-debug',
      sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43), projectRoot,
      commandExitCode: 0, failOnCommandFailure: 'true',
      // Every plausible name a careless implementation might reach for.
      verifyKey: impostorVerifyKey,
      collectorVerifyKey: impostorVerifyKey,
      responderKey: impostorVerifyKey,
      DEBUG_ACTION_COLLECTOR_VERIFY_KEY: impostorVerifyKey,
    });
    // 1. The real key is in the environment: it wins, and the impostor's
    //    signature does not verify against it.
    const code = await captureViaRun({ outputDir, env: RUN_ENV });
    assert.equal(code, 3, 'the key in the environment is the only one that counts');
    const state = readState(outputDir);
    assert.equal(state.collectorAlive, false);
    assert.equal(state.evidenceCopied, false);
    assertNothingStaged(evidenceDirOf(outputDir), 'the impostor key in state bought nothing');
    assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 3);

    // 2. And with NO key in the environment at all, the planted ones are still
    //    not consulted — capture refuses rather than falling back to a key an
    //    attacker chose. This is the case that separates "env wins" from "state
    //    is never a source": an implementation that read state here would
    //    verify the impostor's signature perfectly and return 0.
    // A VALID identity, and ONLY the verification key omitted. With `env: {}`
    // this exits at the nonce gate before capture is reached at all, and a
    // regression to `env key || state key` would sail through it — the branch
    // this case exists to defend would never execute (Codex T6 r2 #2).
    const withoutEnvKey = await captureViaRun({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' } });
    assert.equal(withoutEnvKey, 3, 'a key from an attacker-writable file is not a key');
    assert.equal(readState(outputDir).evidenceCopied, false);
    assertNothingStaged(evidenceDirOf(outputDir), 'and neither did it with no env key at all');
    assert.equal(listener.requests.length, 1,
      'the second capture never even asked: with no trustworthy key there is no point');
  } finally {
    await listener.close();
  }
});

// The runner's env-file channel, modelled in the two stages the attack needs.
// Stage one is what GitHub itself does: every `KEY=value` line a step appends
// to $GITHUB_ENV becomes an environment variable in the steps that follow.
const applyRunnerEnvFile = (baseEnv, envFile) => {
  const applied = { ...baseEnv };
  for (const line of readFileSync(envFile, 'utf8').split('\n')) {
    const eq = line.indexOf('=');
    if (eq > 0) applied[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return applied;
};

// Stage two is why the poison beats a step-level `env:`, which the runner
// resolves after applying the env file and which would otherwise win: bash
// sources $BASH_ENV at the startup of every non-interactive shell, so an
// exported assignment in that script lands INSIDE the later step, after the
// runner has finished deciding what that step's environment should be. This is
// the exact channel Codex T5 r6 described.
const sourceBashEnv = (stepEnv) => {
  const applied = { ...stepEnv };
  if (!stepEnv.BASH_ENV || !existsSync(stepEnv.BASH_ENV)) return applied;
  for (const line of readFileSync(stepEnv.BASH_ENV, 'utf8').split('\n')) {
    const match = /^export ([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(line);
    if (match) applied[match[1]] = match[2];
  }
  return applied;
};

// The headline of round 6. The wrapped command does the worst thing it can
// do to a GitHub Actions job — it rewrites the environment of every step that
// follows it — and the answer is not that the channel is denied to it (it
// cannot be; the runner's command files live under RUNNER_TEMP and any child
// can enumerate them). The answer is that by the time the poison can take
// effect, every decision about this run's evidence has already been made, in
// the one process whose environment was resolved before the command existed.
test('a wrapped command that poisons every later step\'s environment changes nothing: capture already happened, in the one process it could not reach', async () => {
  const impostorVerifyKey = IMPOSTOR_KEYS.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  // The action's own collector, and the listener the attacker stood up to be
  // believed in its place. They are the same server with different keys —
  // which is the whole point: nothing but the signature tells them apart.
  const honest = await counterfeitCollector((challenge, body) => proofFor(RESPONDER_KEYS.privateKey, challenge, body));
  const counterfeit = await counterfeitCollector((challenge, body) => proofFor(IMPOSTOR_KEYS.privateKey, challenge, body));
  // Writes the attacker's BASH_ENV payload and the env-file lines that deliver
  // it. The env file's path is handed over rather than searched for: the strip
  // denies it, but that strip is explicitly NOT the boundary under test — what
  // is being measured is what a fully successful poisoning buys.
  const poison = (envFile, attackerScript) => () => {
    writeFileSync(attackerScript, `export DEBUG_ACTION_COLLECTOR_VERIFY_KEY=${impostorVerifyKey}\n`);
    appendFileSync(envFile, `BASH_ENV=${attackerScript}\n`);
    appendFileSync(envFile, `DEBUG_ACTION_COLLECTOR_VERIFY_KEY=${impostorVerifyKey}\n`);
    return { status: 0 };
  };
  const stage = (port) => {
    const outputDir = makeTempDir();
    counterfeitState(outputDir, makeTempDir(), port);
    const files = {
      envFile: path.join(outputDir, 'github_env'),
      attackerScript: path.join(outputDir, 'attacker.sh'),
      githubOutput: path.join(outputDir, 'github_output'),
      stepSummary: path.join(outputDir, 'step_summary'),
    };
    for (const file of [files.envFile, files.githubOutput, files.stepSummary]) writeFileSync(file, '');
    // The environment the runner resolved for the RUN step, before the wrapped
    // command existed. A child cannot rewrite its parent's memory, so this is
    // the one view of the key the command below cannot touch. The nonce is in
    // here because the runner injects it into every step after `start`, and
    // the poisoned later-step environment below is derived from this one.
    const runStepEnv = {
      ...RUN_ENV,
      DEBUG_ACTION_INVOCATION_NONCE: 'n1',
      GITHUB_ENV: files.envFile,
      GITHUB_OUTPUT: files.githubOutput,
    };
    return { outputDir, runStepEnv, ...files };
  };
  try {
    // 1. The honest collector is on the recorded port, and the poisoning
    //    succeeds completely. Capture is unaffected, because it happens here.
    const honestRun = stage(honest.port);
    const code = await runSubcommand({
      inputs: baseInputs(),
      outputDir: honestRun.outputDir,
      env: honestRun.runStepEnv,
      spawnCommand: poison(honestRun.envFile, honestRun.attackerScript),
    });
    assert.equal(code, 0, 'capture verified the real collector with the key this step held before the command ran');
    assert.equal(readState(honestRun.outputDir).evidenceAuthentic, true);
    assert.equal(counterfeit.requests.length, 0, 'the counterfeit was never asked — the recorded port is still the real one');
    // The poisoning genuinely worked: this is the environment every later step
    // now gets, applied the way the runner applies it (env file first) and
    // then the way bash applies it (BASH_ENV sourced at shell startup, which
    // is what lets it beat a step-level `env:` the runner resolved earlier).
    const laterStepEnv = sourceBashEnv(applyRunnerEnvFile(honestRun.runStepEnv, honestRun.envFile));
    assert.equal(laterStepEnv.BASH_ENV, honestRun.attackerScript);
    assert.equal(laterStepEnv.DEBUG_ACTION_COLLECTOR_VERIFY_KEY, impostorVerifyKey,
      'a step that verified with ITS OWN environment would have rejected the real collector and believed the attacker\'s');
    assert.notEqual(honestRun.runStepEnv.DEBUG_ACTION_COLLECTOR_VERIFY_KEY, impostorVerifyKey,
      'while the run step\'s environment was resolved before the command existed and cannot be revised');
    // report runs in exactly that poisoned environment — and there is nothing
    // in it left to poison. It holds no key, verifies nothing, and publishes
    // the bytes run already proved and staged.
    assert.equal(reportSubcommand({
      outputDir: honestRun.outputDir,
      env: { ...laterStepEnv, GITHUB_STEP_SUMMARY: honestRun.stepSummary },
    }), 0);
    assert.ok(readFileSync(honestRun.stepSummary, 'utf8').includes('## Debug evidence report'));
    assert.equal(readFileSync(path.join(evidenceDirOf(honestRun.outputDir), 'session.log'), 'utf8'), honest.body,
      'and the artifact is byte-for-byte the answer the proof covered');
    assert.equal(finishSubcommand({ outputDir: honestRun.outputDir, env: laterStepEnv }), 0,
      'an honest run stays green even from inside the poisoned environment');

    // 2. What the poisoning was FOR: the counterfeit where capture will look,
    //    serving an answer that verifies perfectly under the planted key. run
    //    refuses it — and a composite step that fails is one no later step,
    //    however thoroughly poisoned, can un-fail.
    const forgedRun = stage(counterfeit.port);
    const forgedCode = await runSubcommand({
      inputs: baseInputs(),
      outputDir: forgedRun.outputDir,
      env: forgedRun.runStepEnv,
      spawnCommand: poison(forgedRun.envFile, forgedRun.attackerScript),
    });
    assert.equal(forgedCode, 3, 'the planted key is not the key capture verifies with');
    assert.equal(counterfeit.requests.length, 1, 'asked exactly once, and refused on the proof');
    const forgedState = readState(forgedRun.outputDir);
    assert.equal(forgedState.collectorAlive, false);
    assert.equal(forgedState.evidenceAuthentic, false);
    assert.equal(forgedState.reportRendered, false);
    const evidenceDir = evidenceDirOf(forgedRun.outputDir);
    for (const name of ['session.log', 'report.md', 'report.json']) {
      assert.ok(!existsSync(path.join(evidenceDir, name)), `${name} is never staged`);
    }
    assert.equal(readFileSync(forgedRun.githubOutput, 'utf8').includes('report-path'), false,
      'and no output advertises evidence that does not exist');
    const forgedLaterEnv = sourceBashEnv(applyRunnerEnvFile(forgedRun.runStepEnv, forgedRun.envFile));
    assert.equal(reportSubcommand({
      outputDir: forgedRun.outputDir,
      env: { ...forgedLaterEnv, GITHUB_STEP_SUMMARY: forgedRun.stepSummary },
    }), 0);
    assert.equal(readFileSync(forgedRun.stepSummary, 'utf8'), '', 'nothing was captured, so nothing is published');
    assert.equal(finishSubcommand({ outputDir: forgedRun.outputDir, env: forgedLaterEnv }), 3);
  } finally {
    await honest.close();
    await counterfeit.close();
  }
});

test('run exit taxonomy: every evidence-integrity class is a 3 that publishes nothing, while the wrapped command\'s own failure is not', async () => {
  const served = [{ ts: '2026-08-14T00:00:00.000Z', msg: 'served event' }];
  const forgedVerdict = [{ ts: '2026-08-14T00:00:00.000Z', type: 'hypothesis', hypothesisId: 'H-demo', status: 'CONFIRMED' }];
  const healthy = () => collectorAnswer(served);
  const unreached = async () => { throw new Error('this class is settled before any read'); };
  const classes = [
    ['no recorded state', { state: null, readLive: unreached }],
    ['a state carrying no session', { state: { sessionId: undefined, sessionToken: undefined }, readLive: unreached }],
    ['another invocation\'s nonce', { env: { ...RUN_ENV, DEBUG_ACTION_INVOCATION_NONCE: 'other' }, reportCode: 3, readLive: unreached }],
    ['no verification key in this step\'s environment', { env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' }, readLive: unreached }],
    ['an answer signed by a key that is not the collector\'s', { readLive: collectorAnswer(served, { privateKey: IMPOSTOR_KEYS.privateKey }) }],
    ['a validly signed answer to a different question', { readLive: collectorAnswer(served, { target: '/sessions/ci-debug-abc/logs?type=event&limit=1' }) }],
    ['an answer with no proof at all', { readLive: collectorAnswer(served, { proof: null }) }],
    ['a collector that refuses to serve the session', { readLive: async () => { throw new Error('live_read_log_replaced'); } }],
    ['a captured verdict this action never posted', { readLive: collectorAnswer(forgedVerdict) }],
    // The two renderer classes captured authentic bytes before they failed.
    // Those bytes stay staged — they are real evidence a human can read — and
    // it is the REPORT, the thing this action publishes, that is withheld.
    ['a renderer that throws', { staged: ['session.log'], readLive: healthy(), renderReport: () => { throw new Error('renderer exploded'); } }],
    ['a renderer that returns no schema-1 report', { staged: ['session.log'], readLive: healthy(), renderReport: () => ({ markdown: '## Debug evidence report\n', json: '{}' }) }],
  ];
  // The default env is the one action.yml wires for the run step, plus the
  // nonce the runner injects into every step after `start` — the same
  // environment `report` is handed a moment later, which is why the same
  // object drives both calls below.
  const defaultEnv = { ...RUN_ENV, DEBUG_ACTION_INVOCATION_NONCE: 'n1' };
  for (const [label, { state = {}, env = defaultEnv, staged = [], reportCode = 0, ...seams }] of classes) {
    const outputDir = makeTempDir();
    const projectRoot = makeTempDir();
    if (state !== null) {
      writeState(outputDir, {
        nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43),
        sessionId: 'ci-debug-abc', projectRoot, failOnCommandFailure: 'true', ...state,
      });
    }
    const githubOutput = path.join(outputDir, 'github_output');
    writeFileSync(githubOutput, '');
    const code = await captureViaRun({ outputDir, env: { ...env, GITHUB_OUTPUT: githubOutput }, ...seams });
    // 3 and not 1: this is the action's machinery failing, which a consumer
    // must be able to tell apart from the wrapped command's own verdict.
    assert.equal(code, 3, label);
    // Named for the identity this class ran under, which for the foreign-nonce
    // class is deliberately not the one the state carries.
    const evidenceDir = resolveEvidenceDir(outputDir, env.DEBUG_ACTION_INVOCATION_NONCE);
    assert.deepEqual(
      ['session.log', 'report.md', 'report.json'].filter((name) => existsSync(path.join(evidenceDir, name))),
      staged,
      `${label}: exactly these files may be staged`,
    );
    const published = readFileSync(githubOutput, 'utf8');
    for (const name of ['report-path', 'evidence-digest', 'event-count']) {
      assert.equal(published.includes(name), false, `${label}: ${name} must not be published`);
    }
    // Through the publish step, because that is what runs before the upload
    // step in production and it is allowed to clear stale slots (Codex T5 r8).
    assert.equal(reportSubcommand({ outputDir, env }), reportCode, `${label}: report's own exit`);
    assert.deepEqual(
      ['session.log', 'report.md', 'report.json'].filter((name) => existsSync(path.join(evidenceDir, name))),
      staged,
      `${label}: and exactly these files are still there when the artifact is uploaded`,
    );
  }
  // The contrast that defines the taxonomy. A wrapped command that fails is
  // not an integrity failure at all: run captures its session, stages the
  // evidence, records the code and returns 0 — and finish, which owns the
  // verdict, is where the mirroring happens.
  const outputDir = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43),
    sessionId: 'ci-debug-abc', projectRoot: makeTempDir(), failOnCommandFailure: 'true',
  });
  const code = await runSubcommand({
    inputs: baseInputs(),
    outputDir,
    env: RUN_ENV,
    spawnCommand: () => ({ status: 7 }),
    readLive: healthy(),
  });
  assert.equal(code, 0, 'the evidence is complete, which is all this step promises');
  assert.equal(readState(outputDir).commandExitCode, 7);
  assert.equal(finishSubcommand({ outputDir, env: invocationEnv(outputDir) }), 7, 'the command\'s own code is mirrored, once, by finish');
});

test('report publishes only what run committed, and holds nothing worth poisoning', async () => {
  // 1. run recorded no capture. Whatever is sitting in the staging slots is an
  //    earlier invocation's, so it is cleared rather than published — and the
  //    step still succeeds, because run has already failed the action if this
  //    was an integrity failure. A composite step that failed cannot be
  //    un-failed here, and a second failure would only obscure the first.
  const outputDir = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionId: 'ci-debug-abc',
    sessionToken: 'x'.repeat(43), reportRendered: false,
  });
  const evidenceDir = evidenceDirOf(outputDir);
  mkdirSync(evidenceDir, { recursive: true });
  for (const name of ['session.log', 'report.md', 'report.json']) {
    writeFileSync(path.join(evidenceDir, name), 'left behind by an earlier invocation\n');
  }
  const stepSummary = path.join(outputDir, 'step_summary');
  writeFileSync(stepSummary, '');
  assert.equal(reportSubcommand({
    outputDir,
    env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1', GITHUB_STEP_SUMMARY: stepSummary },
  }), 0);
  for (const name of ['session.log', 'report.md', 'report.json']) {
    assert.ok(!existsSync(path.join(evidenceDir, name)),
      `${name} from an earlier invocation is never shipped as this run's evidence`);
  }
  assert.equal(readFileSync(stepSummary, 'utf8'), '', 'and the human surface says nothing either');

  // 2. run DID capture. The staged markdown reaches the summary — and it makes
  //    no difference what the environment carries, because report reads no key
  //    from it and verifies nothing with it.
  writeState(outputDir, { ...readState(outputDir), reportRendered: true });
  mkdirSync(evidenceDir, { recursive: true });
  writeFileSync(path.join(evidenceDir, 'report.md'), '## Debug evidence report\nstaged by run\n');
  const poisoned = {
    DEBUG_ACTION_INVOCATION_NONCE: 'n1',
    GITHUB_STEP_SUMMARY: stepSummary,
    BASH_ENV: '/tmp/attacker.sh',
    DEBUG_ACTION_COLLECTOR_VERIFY_KEY: IMPOSTOR_KEYS.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  };
  assert.equal(reportSubcommand({ outputDir, env: poisoned }), 0);
  assert.ok(readFileSync(stepSummary, 'utf8').includes('staged by run'));

  // 3. The one failure report has left is its own: the summary it was told to
  //    write, or the staged bytes it was told to publish, being unusable.
  unlinkSync(path.join(evidenceDir, 'report.md'));
  assert.equal(reportSubcommand({ outputDir, env: poisoned }), 3,
    'a recorded capture whose staged report has vanished is report\'s own mechanical failure');
});

test('the boot handshake and the state file carry no private key material', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const port = await getFreePort();
  // The real shim, spawned exactly as start spawns it, so the assertion is
  // about the line the collector actually prints rather than a fixture of it.
  const handshakes = [];
  const startOutput = path.join(outputDir, 'start_output');
  writeFileSync(startOutput, '');
  const code = await startSubcommand({
    inputs: baseInputs({ port: String(port) }),
    outputDir,
    projectRoot,
    env: { GITHUB_OUTPUT: startOutput },
    spawnShim: (args, options) => {
      const child = defaultSpawnShim(args, options);
      child.stdout.on('data', (chunk) => handshakes.push(String(chunk)));
      return child;
    },
  });
  try {
    assert.equal(code, 0);
    const handshake = JSON.parse(handshakes.join('').split('\n')[0]);
    // The public half travels; the private half has no representation here at
    // all. Ed25519 private keys serialize as PKCS#8 PEM/DER — no field of this
    // line may look like one, under any name.
    assert.equal(typeof handshake.verify_key, 'string');
    assert.ok(handshake.verify_key.length >= 32);
    const asText = JSON.stringify(handshake);
    for (const marker of ['PRIVATE KEY', 'privateKey', 'private_key', 'responder_key']) {
      assert.equal(asText.includes(marker), false, `handshake must not carry ${marker}`);
    }
    // Reconstructing a PUBLIC key from what travelled must succeed, and that
    // object must not be usable for signing.
    const rebuilt = createPublicKey({ key: Buffer.from(handshake.verify_key, 'base64'), format: 'der', type: 'spki' });
    assert.equal(rebuilt.type, 'public');
    const stateText = readFileSync(path.join(outputDir, 'action-state.json'), 'utf8');
    for (const marker of ['PRIVATE KEY', handshake.verify_key, 'verify_key', 'verifyKey']) {
      assert.equal(stateText.includes(marker), false, `state must not carry ${marker}`);
    }
    // And the key that DID travel reached the step output, unmasked and whole.
    assert.ok(readFileSync(startOutput, 'utf8').includes(`collector-verify-key=${handshake.verify_key}`));
  } finally {
    teardownSubcommand({ outputDir, env: invocationEnv(outputDir) });
  }
});

test('the renderer export surface capture depends on is pinned', () => {
  // support.js imports these three from debug_report.js and calls them
  // in-process, so a rename or a signature change there breaks CAPTURE — at
  // run time, in CI, with no evidence produced. This is the loud failure
  // instead (Codex T5 r5, ruling B; the coupling is documented in the action
  // README).
  const renderer = require('../../scripts/debug_report');
  for (const name of ['buildReport', 'renderMarkdown', 'renderJson']) {
    assert.equal(typeof renderer[name], 'function', `debug_report.js must export ${name}`);
  }
  // And the shapes support.js relies on: buildReport takes entries plus a
  // session id, and the two renderers turn its result into strings.
  const report = renderer.buildReport(
    [{ raw: '{"msg":"e"}', parsed: { ts: '2026-08-14T00:00:00.000Z', msg: 'e' } }],
    { sessionId: 'ci-debug-abc' },
  );
  assert.equal(report.schema, 1);
  assert.equal(report.session.id, 'ci-debug-abc');
  assert.equal(report.session.events, 1);
  assert.equal(typeof renderer.renderMarkdown(report), 'string');
  assert.equal(JSON.parse(renderer.renderJson(report)).schema, 1);
});

// Invocation-scoped staging (Codex T6 r1 #3). Two invocations can share an
// output-dir: the default is a fixed path under runner.temp, and a self-hosted
// runner can see the same custom directory again minutes later. With ONE fixed
// staging child, the second invocation's entry clear destroys the first's
// evidence, a concurrent restage lands in exactly the three filenames the
// upload step enumerates, and a stale entry that cannot be unlinked (a
// DIRECTORY where a session.log belongs) fails `report` while the always()
// upload still ships that directory's descendants — the pinned uploader
// expands directories with implicitDescendants. Scoping the child to the
// invocation removes the shared name, and therefore the whole class.
test('staging is invocation-scoped: a second invocation neither sees, clears, nor ships the first one\'s evidence', async () => {
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const stage = async (nonce, message) => {
    // Exactly what a second invocation does to a shared output-dir: it takes
    // ownership of the state file.
    writeState(outputDir, {
      nonce, pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
      projectRoot, failOnCommandFailure: 'true',
    });
    const githubOutput = path.join(outputDir, `github_output_${nonce}`);
    writeFileSync(githubOutput, '');
    const code = await captureViaRun({
      outputDir,
      env: { ...RUN_ENV, DEBUG_ACTION_INVOCATION_NONCE: nonce, GITHUB_OUTPUT: githubOutput },
      readLive: collectorAnswer([{ ts: '2026-08-14T00:00:00.000Z', msg: message }]),
    });
    assert.equal(code, 0, `invocation ${nonce} captured its own session`);
    return { dir: resolveEvidenceDir(outputDir, nonce), githubOutput };
  };
  const first = await stage('inv-first', 'the first invocation');
  const second = await stage('inv-second', 'the second invocation');
  assert.notEqual(first.dir, second.dir, 'the staging children are distinct paths');
  assert.ok(readFileSync(path.join(first.dir, 'session.log'), 'utf8').includes('the first invocation'),
    'the first invocation\'s evidence survived the second one entirely');
  assert.ok(readFileSync(path.join(second.dir, 'session.log'), 'utf8').includes('the second invocation'));
  // What the upload step is told to take is THIS invocation's directory —
  // published by `start` before the wrapped command existed, never by the
  // run step, which by then is writing into a file that command can append
  // to (Codex T6 r2 #1).
  for (const invocation of [first, second]) {
    const published = readFileSync(invocation.githubOutput, 'utf8');
    assert.equal(/^evidence-(dir|staged)=/m.test(published), false, 'run advertises no staging path');
  }
  // And the second invocation's publish step leaves the first's alone: it is
  // not this run's to ship, and not this run's to delete either.
  assert.equal(reportSubcommand({ outputDir, env: { DEBUG_ACTION_INVOCATION_NONCE: 'inv-second' } }), 0);
  assert.ok(existsSync(path.join(first.dir, 'session.log')), 'a stranger\'s staging is left untouched');
});

// The runner's own reading of a step-output file, including the multiline
// `key<<DELIMITER` form: every following line is body until a line equal to the
// delimiter closes it. Modelled here because the attack below turns exactly
// that feature against a post-command writer.
const parseStepOutputs = (text) => {
  const values = {};
  const lines = text.split('\n');
  for (let index = 0; index < lines.length; index += 1) {
    const heredoc = /^([^=<]+)<<(.*)$/.exec(lines[index]);
    if (heredoc) {
      const body = [];
      index += 1;
      while (index < lines.length && lines[index] !== heredoc[2]) {
        body.push(lines[index]);
        index += 1;
      }
      values[heredoc[1]] = body.join('\n');
      continue;
    }
    const pair = /^([^=]+)=(.*)$/.exec(lines[index]);
    if (pair) values[pair[1]] = pair[2];
  }
  return values;
};

// Codex T6 r2 #1, and it is deterministic rather than a race. `run` writes its
// step outputs AFTER the wrapped command has executed, and the runner does not
// read that file until the step handler returns — so the command has the whole
// intervening time to write into it. Stripping GITHUB_OUTPUT from the child's
// environment hides the VARIABLE, not the FILE: the runner's command files sit
// under RUNNER_TEMP/_runner_file_commands and any same-user process can
// enumerate them (support.js says as much where it does the stripping).
//
// So a post-command step output cannot be a security boundary. The upload
// step's paths and gate come from `start` instead, whose output file the runner
// parsed before the wrapped command existed — the same argument that protects
// the verification key.
test('a wrapped command that forges this step\'s output file cannot reach the upload path set', async () => {
  const served = [{ ts: '2026-08-14T00:00:00.000Z', msg: 'served event' }];
  const forge = async (payload) => {
    const outputDir = makeTempDir();
    const projectRoot = makeTempDir();
    writeState(outputDir, {
      nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
      projectRoot, failOnCommandFailure: 'true',
    });
    const githubOutput = path.join(outputDir, 'github_output');
    writeFileSync(githubOutput, '');
    const code = await captureViaRun({
      outputDir,
      env: { ...RUN_ENV, GITHUB_OUTPUT: githubOutput },
      readLive: collectorAnswer(served),
      // The child writes to the file directly. It is handed no path and no
      // variable; in production it enumerates the runner's command-file
      // directory, which this seam stands in for.
      spawnCommand: () => {
        appendFileSync(githubOutput, `${payload.join('\n')}\n`);
        return { status: 0 };
      },
    });
    assert.equal(code, 0, 'the capture itself succeeded — the forgery is not what run is verifying');
    return { outputDir, payload, published: readFileSync(githubOutput, 'utf8') };
  };

  // 1. The plain form. Nothing `run` writes afterwards contests these keys,
  //    because `run` no longer emits them at all.
  const plain = await forge(['evidence-staged=x', 'evidence-dir=C:/foreign']);
  const plainValues = parseStepOutputs(plain.published);
  assert.equal(plainValues['evidence-dir'], 'C:/foreign', 'the channel really is attacker-writable');
  assert.equal(plainValues['evidence-staged'], 'x');

  // 2. Codex's heredoc form, which is what made a post-command writer
  //    unfixable: the delimiter is the exact line the trusted process was
  //    going to write, so everything it appends is swallowed as body.
  const heredoc = await forge([
    'evidence-staged=x',
    'evidence-dir<<evidence-staged=session.log report.md report.json',
    'C:/foreign/**',
  ]);
  const heredocValues = parseStepOutputs(heredoc.published);
  assert.ok(heredocValues['evidence-dir'].includes('C:/foreign/**'),
    'an attacker-controlled MULTILINE path set, which is what a path: block consumes');
  assert.equal(heredocValues['command-exit-code'], undefined,
    'and every trusted line run wrote afterwards was swallowed into that body');

  // THE DEFENCE, asserted where it lives: nothing about the upload step reads
  // any of this. Its gate and its paths are `start` outputs, fixed before the
  // command ran, and `run` publishes no evidence-dir/evidence-staged for an
  // attacker to contest in the first place.
  for (const { published, payload } of [plain, heredoc]) {
    const runsOwnLines = published.split('\n').filter((line) => !payload.includes(line));
    assert.equal(runsOwnLines.some((line) => /^evidence-(dir|staged)/.test(line)), false,
      'run publishes no upload-controlling output for an attacker to contest');
  }
  const upload = actionStepsByName()['Upload evidence artifact'];
  assert.equal(upload.if, "${{ always() && steps.start.outputs.evidence-dir != '' }}");
  for (const entry of upload.with.path) {
    assert.equal(entry.startsWith('${{ steps.start.outputs.evidence-dir }}/'), true, entry);
  }
  // `evidence-digest` is a legitimate run output — a convenience, never a
  // trust anchor. What must never appear is a post-command output the
  // UPLOAD step depends on.
  assert.equal(/steps\.run\.outputs\.evidence-(dir|staged)/.test(ACTION_YML()), false,
    'no post-command staging output may be referenced anywhere in the wiring');
});

// The replacement for "run tells the upload step what it staged": it does not,
// and must not. What it still owes is the DIGEST — printed to its own step log,
// immutable once streamed — and the staged files themselves.
test('run publishes no upload-controlling output, while still staging exactly what each class earns', async () => {
  const served = [{ ts: '2026-08-14T00:00:00.000Z', msg: 'served event' }];
  const cases = [
    ['a complete capture', {}, ['session.log', 'report.md', 'report.json']],
    // A renderer failure still staged the authenticated log: real evidence a
    // human can read, and the upload step must still ship it.
    ['a renderer that throws', { renderReport: () => { throw new Error('renderer exploded'); } }, ['session.log']],
    // An integrity failure staged nothing. `if-no-files-found: ignore` is what
    // covers this now, rather than a gate run computes after the fact.
    ['no verification key in this step\'s environment', { env: { DEBUG_ACTION_INVOCATION_NONCE: 'n1' } }, []],
  ];
  for (const [label, overrides, expected] of cases) {
    const outputDir = makeTempDir();
    const projectRoot = makeTempDir();
    writeState(outputDir, {
      nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
      projectRoot, failOnCommandFailure: 'true',
    });
    const githubOutput = path.join(outputDir, 'github_output');
    writeFileSync(githubOutput, '');
    const printed = [];
    const { env = RUN_ENV, ...seams } = overrides;
    await captureViaRun({
      outputDir,
      env: { ...env, GITHUB_OUTPUT: githubOutput },
      readLive: collectorAnswer(served),
      writeStdout: (text) => printed.push(text),
      ...seams,
    });
    const published = readFileSync(githubOutput, 'utf8');
    assert.equal(/^evidence-dir=/m.test(published), false, `${label}: run advertises no staging directory`);
    assert.equal(/^evidence-staged=/m.test(published), false, `${label}: and no staging manifest`);
    assert.deepEqual(
      ['session.log', 'report.md', 'report.json'].filter((name) => existsSync(path.join(resolveEvidenceDir(outputDir, 'n1'), name))),
      expected,
      `${label}: exactly these files are staged`,
    );
    // The trust unit, unchanged: bytes are evidence only against a digest this
    // process printed to the step log before staging them.
    assert.equal(
      printed.some((text) => text.startsWith('evidence-sha256')),
      expected.length > 0,
      `${label}: a digest line exists exactly when payloads were staged`,
    );
  }
});

test('run refuses when no usable invocation nonce reached it: it cannot even name its own staging', async () => {
  const outputDir = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
    projectRoot: makeTempDir(), failOnCommandFailure: 'true',
  });
  const refuse = () => { throw new Error('a refused run must never reach the wrapped command'); };
  assert.equal(await captureViaRun({
    outputDir,
    env: { DEBUG_ACTION_COLLECTOR_VERIFY_KEY: VERIFY_KEY_B64 },
    spawnCommand: refuse,
  }), 3, 'no identity, no run');
  // A nonce is a directory-name segment now, so a traversal-shaped one is
  // refused rather than resolved. Entropy comes from randomUUID in start; this
  // is the path-safety half.
  assert.equal(await captureViaRun({
    outputDir,
    env: { ...RUN_ENV, DEBUG_ACTION_INVOCATION_NONCE: '../escape' },
    spawnCommand: refuse,
  }), 3, 'a traversal-shaped identity is refused');
  assert.equal(existsSync(path.join(outputDir, 'escape')), false, 'and nothing was created outside the staging child');
});

test('resolveEvidenceDir refuses any invocation nonce that is not a safe path segment', () => {
  const outputDir = makeTempDir();
  for (const bad of [undefined, null, '', '../escape', 'a/b', 'a\\b', '.', '..', 'x'.repeat(65)]) {
    assert.throws(() => resolveEvidenceDir(outputDir, bad), /not a safe path segment/, `refuses ${JSON.stringify(bad)}`);
  }
  // The shape start actually mints, and the shapes the tests use.
  for (const good of ['0e2b1c34-5d6e-4f70-8a9b-0c1d2e3f4a5b', 'n1', 'inv-second']) {
    assert.equal(resolveEvidenceDir(outputDir, good), path.join(outputDir, `debug-evidence-files-${good}`));
  }
});

// This step is handed the invocation nonce as `start`'s step output. Its
// ABSENCE means this invocation's `start` never ran far enough to emit one —
// and nothing in the output-dir can then be shown to belong to this run. "A
// state file exists" proves nothing on its own: an output-dir is reusable
// across steps and across jobs on a self-hosted runner, so a PREVIOUS
// invocation's state sits at exactly that path. Degrading to that check would
// publish a stranger's report into this job's summary.
//
// What it must NOT do is clean up: staging is invocation-scoped, so every
// directory it could clear belongs to some other invocation — possibly one
// still running. Their evidence is not this step's to publish and not this
// step's to destroy, and it cannot reach this job's artifact either way,
// because the upload step is gated on THIS invocation's run outputs
// (Codex T6 r1 #1/#3).
test('report fails closed when no invocation nonce reached this step, and destroys nobody else\'s evidence', async () => {
  const outputDir = makeTempDir();
  const strangerDir = resolveEvidenceDir(outputDir, 'inv-stranger');
  mkdirSync(strangerDir, { recursive: true });
  const stepSummary = path.join(outputDir, 'step_summary');
  writeFileSync(stepSummary, '');
  // The most favourable state that can exist: a complete, successful,
  // authenticated capture. None of it may buy a publish without the identity.
  writeState(outputDir, {
    nonce: 'inv-stranger', pid: 1, port: 1, sessionId: 'ci-debug-abc', sessionToken: 'x'.repeat(43),
    commandExitCode: 0, collectorAlive: true, evidenceAuthentic: true, evidenceCopied: true,
    reportRendered: true, failOnCommandFailure: 'true',
  });
  for (const name of ['session.log', 'report.md', 'report.json']) {
    writeFileSync(path.join(strangerDir, name), `staged ${name}\n`);
  }
  const { result, written } = await captureStderr(() => reportSubcommand({
    outputDir,
    env: { GITHUB_STEP_SUMMARY: stepSummary },
  }));
  assert.equal(result, 3, 'no identity is an infra failure, never a licence to publish');
  assert.equal(readFileSync(stepSummary, 'utf8'), '', 'nothing may reach the step summary');
  for (const name of ['session.log', 'report.md', 'report.json']) {
    assert.ok(existsSync(path.join(strangerDir, name)), `${name} belongs to another invocation and is left alone`);
  }
  assert.match(written, /report: this step received no usable invocation nonce/);
});

// ---------------------------------------------------------------------------
// action.yml — structural pins (Task 6, rebuilt for Codex T6 r1 #4).
//
// The first version of these pins matched SUBSTRINGS, and Codex demonstrated
// four mutations that survived them: all four exact step guards replaced by a
// bare `${{ always() }}` (the check was a prefix match); an extra
// `C:/foreign/**` added to the upload block (the check required the expected
// paths but never rejected extras); the verify-key mapping moved into an
// INLINE comment (the stripper removed only whole-line comments, so the
// "which step carries it" answer stayed the same while no mapping existed);
// and two output-dir sites diverging under a `>= 6` occurrence count. A
// substring pin can only say "this appears somewhere"; these properties need
// "this, exactly, and nothing else".
//
// So the raw text is parsed instead, by a small structure-aware reader for the
// subset of YAML this file uses — block mappings, one block scalar (`path: |`),
// no flow collections, no anchors, no multi-line quoted scalars — and every
// assertion below is an exact deepEqual over what it returns. The repo ships
// zero runtime dependencies and this adds no test dependency either. The
// SHA-pin assertion deliberately stays on the RAW text: the version comment is
// part of what it pins, and the reader strips comments.
const ACTION_YML = () => readFileSync(path.join(__dirname, 'action.yml'), 'utf8');
const OUTPUT_DIR_EXPR = "${{ inputs.output-dir || format('{0}/debug-evidence', runner.temp) }}";
const NONCE_EXPR = '${{ steps.start.outputs.invocation-nonce }}';
const START_GUARD = "${{ always() && steps.start.outcome != 'skipped' }}";

// A `#` opens a comment only at line start or after whitespace, and never
// inside a quoted scalar — the rule tools/workflow_checks.js documents for the
// same reason. Quote state is per line: this file has no multi-line quoted
// scalars, and introducing one would break the exact assertions below loudly
// rather than silently.
const stripYamlComment = (line) => {
  let quote = null;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (quote) {
      if (character === quote) quote = null;
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (character === '#' && (index === 0 || /\s/.test(line[index - 1]))) {
      return line.slice(0, index);
    }
  }
  return line;
};

// `key: value`, `key:`, or the `- key: value` that opens a sequence item.
const splitEntry = (body) => {
  const match = /^(?:- )?([A-Za-z0-9_.-]+):(?: (.*))?$/.exec(body);
  return match ? { key: match[1], value: match[2] ?? '' } : null;
};

// A scalar as written: `default: "true"` and `default: ""` are quoted in this
// file, and what the assertions care about is the value, not the quoting.
const unquoteScalar = (value) => (/^(".*"|'.*')$/.test(value) ? value.slice(1, -1) : value);

// Returns { inputs: { name: { default, required, … } }, outputs: { name: value },
// using, steps: [{ name, id, if, shell, uses, run, env: {}, with: { path: [] } }] }.
// Indentation is the structure, exactly as the file is written.
//
// `inputs` and `runs.using` are parsed rather than skipped because skipping is
// failing open: flipping `fail-on-command-failure`'s default to "false" or
// `using: composite` to `using: docker` left the old reader's output identical,
// so tests that claimed to pin this file's structure could not see either
// change (Codex T6 r2 #3). An unknown key directly under `runs:` now throws for
// the same reason.
const parseActionYml = () => {
  const lines = [];
  for (const raw of ACTION_YML().split(/\r?\n/)) {
    const text = stripYamlComment(raw).replace(/\s+$/, '');
    if (text.trim() === '') continue;
    lines.push({ indent: text.length - text.trimStart().length, body: text.trim() });
  }
  const inputs = {};
  const outputs = {};
  const steps = [];
  let using = null;
  let section = null;
  let inputName = null;
  let outputName = null;
  let step = null;
  let nested = null;
  let blockScalar = null;
  for (const line of lines) {
    if (line.indent === 0) {
      section = { 'inputs:': 'inputs', 'outputs:': 'outputs', 'runs:': 'runs' }[line.body] ?? null;
      step = null;
      continue;
    }
    // Indent 6 and deeper in these two sections is a folded `description:`
    // continuation, which carries nothing an assertion needs.
    if (section === 'inputs') {
      const entry = splitEntry(line.body);
      if (line.indent === 2 && entry && entry.value === '') {
        inputName = entry.key;
        inputs[inputName] = {};
      } else if (line.indent === 4 && entry) {
        inputs[inputName][entry.key] = unquoteScalar(entry.value);
      }
      continue;
    }
    if (section === 'outputs') {
      const entry = splitEntry(line.body);
      if (line.indent === 2 && entry && entry.value === '') outputName = entry.key;
      if (line.indent === 4 && entry && entry.key === 'value') outputs[outputName] = entry.value;
      continue;
    }
    if (section !== 'runs') continue;
    if (blockScalar && line.indent >= blockScalar.indent) {
      blockScalar.items.push(line.body);
      continue;
    }
    blockScalar = null;
    // The `runs:` mapping's own keys. `using` is captured, `steps` opens the
    // list, and anything else is a structure these tests have never seen and
    // must not silently accept.
    if (line.indent === 2) {
      const entry = splitEntry(line.body);
      if (!entry) throw new Error(`unparsed runs line: ${line.body}`);
      if (entry.key === 'using') using = unquoteScalar(entry.value);
      else if (entry.key !== 'steps') throw new Error(`unknown runs key: ${entry.key}`);
      continue;
    }
    if (line.indent === 4 && line.body.startsWith('- ')) {
      step = { env: {}, with: {} };
      steps.push(step);
    }
    if (line.indent === 4 || line.indent === 6) {
      const entry = splitEntry(line.body);
      if (!entry) throw new Error(`unparsed step line: ${line.body}`);
      nested = null;
      if (entry.key === 'env' || entry.key === 'with') nested = entry.key;
      else step[entry.key] = entry.value;
      continue;
    }
    if (line.indent === 8) {
      const entry = splitEntry(line.body);
      if (!entry || !nested) throw new Error(`unparsed nested line: ${line.body}`);
      if (entry.value === '|') {
        blockScalar = { items: [], indent: 10 };
        step[nested][entry.key] = blockScalar.items;
      } else {
        step[nested][entry.key] = entry.value;
      }
      continue;
    }
    throw new Error(`unexpected indentation ${line.indent}: ${line.body}`);
  }
  return { inputs, outputs, using, steps };
};

// The same stripper the reader uses, applied to the whole file: a rule about
// what must NOT appear has to be read against wiring, not against the prose
// that explains the rule. Inline comments included — a whole-line-only
// stripper is exactly what Codex's third mutation walked straight through.
const ACTION_YML_CODE = () => ACTION_YML().split(/\r?\n/).map(stripYamlComment).join('\n');

const actionStepsByName = () => Object.fromEntries(parseActionYml().steps.map((step) => [step.name, step]));

test('action.yml declares a composite action with exactly these inputs and defaults', () => {
  const { inputs, using } = parseActionYml();
  // `using` decides what the whole `steps:` list below even means: under
  // `docker` or a JavaScript `main:` none of it runs, and every other pin here
  // would still pass while the action did something else entirely.
  assert.equal(using, 'composite');
  // Every default, exactly. `fail-on-command-failure: "true"` is the
  // security-relevant one — flipped to "false", a job whose wrapped command
  // failed goes green — but a silent change to ANY of these (the port the
  // collector binds, the caps, the session name the evidence is filed under)
  // is a change to the contract, so the whole map is pinned rather than one
  // field of it (Codex T6 r2 #3).
  assert.deepEqual(
    Object.fromEntries(Object.entries(inputs).map(([name, spec]) => [name, spec.default ?? null])),
    {
      run: null,
      'working-directory': '.',
      'session-name': 'ci-debug',
      'fail-on-command-failure': 'true',
      'output-dir': '',
      'artifact-name': 'debug-evidence',
      'node-version': '24',
      port: '8787',
      'redact-names': '',
      'max-events': '',
      'max-bytes': '',
      'hypothesis-id': '',
      'hypothesis-title': '',
    },
  );
  // The one input with no default is the one the action cannot invent.
  assert.equal(inputs.run.required, 'true');
  assert.equal(inputs.run.default, undefined);
});

test('action.yml declares exactly the steps this action runs, in the order the architecture requires', () => {
  // run before report before upload: `report` decides what the upload step
  // finds staged (Codex T5 r8), and every evidence verdict is already made by
  // the time either of them runs.
  assert.deepEqual(parseActionYml().steps.map((step) => step.name), [
    'Set up Node.js',
    'Start collector',
    'Run wrapped command',
    'Render evidence report',
    'Upload evidence artifact',
    'Stop collector',
    'Apply verdict',
  ]);
});

test('action.yml is wiring-only: each subcommand exactly once, with its exact shell', () => {
  const steps = parseActionYml().steps;
  const wiring = steps.filter((step) => step.run !== undefined);
  assert.deepEqual(wiring.map((step) => step.run), [
    'node "${{ github.action_path }}/support.js" start',
    'node "${{ github.action_path }}/support.js" run',
    'node "${{ github.action_path }}/support.js" report',
    'node "${{ github.action_path }}/support.js" teardown',
    'node "${{ github.action_path }}/support.js" finish',
  ]);
  assert.deepEqual(wiring.map((step) => step.shell), ['bash', 'bash', 'bash', 'bash', 'bash']);
  // Everything that is not a support.js call is one of the two pinned
  // third-party actions — there is no third kind of step.
  assert.deepEqual(steps.filter((step) => step.run === undefined).map((step) => step.uses), [
    'actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38',
    'actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02',
  ]);
  assert.equal(ACTION_YML_CODE().includes('continue-on-error'), false, 'a failed run step must stay failed');
});

test('action.yml pins third-party actions to the closeout SHAs, version comments included', () => {
  // RAW text on purpose: the trailing `# vX.Y.Z` is part of the pin a human
  // reads, and the semantic reader strips comments by design.
  const text = ACTION_YML();
  assert.ok(text.includes('uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6.5.0'));
  assert.ok(text.includes('uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2'));
  assert.ok(!/uses:\s+[^.@\s]+\/[^@\s]+@(?![0-9a-f]{40})/.test(text), 'no unpinned remote uses');
});

test('every step env is exactly what its subcommand reads — no more, no less', () => {
  const byName = actionStepsByName();
  // Reconciled against support.js: main() builds `inputs` from these names,
  // and start is the only subcommand that reads any of them beyond the output
  // dir. `artifact-name` is deliberately absent — no subcommand reads it; the
  // upload step's `name:` is its only consumer.
  assert.deepEqual(byName['Start collector'].env, {
    DEBUG_ACTION_RUN: '${{ inputs.run }}',
    DEBUG_ACTION_SESSION_NAME: '${{ inputs.session-name }}',
    DEBUG_ACTION_WORKDIR: '${{ inputs.working-directory }}',
    DEBUG_ACTION_FAIL_ON_COMMAND_FAILURE: '${{ inputs.fail-on-command-failure }}',
    DEBUG_ACTION_OUTPUT_DIR: OUTPUT_DIR_EXPR,
    DEBUG_ACTION_PORT: '${{ inputs.port }}',
    DEBUG_ACTION_REDACT_NAMES: '${{ inputs.redact-names }}',
    DEBUG_ACTION_MAX_EVENTS_INPUT: '${{ inputs.max-events }}',
    DEBUG_ACTION_MAX_BYTES_INPUT: '${{ inputs.max-bytes }}',
    DEBUG_ACTION_HYPOTHESIS_ID: '${{ inputs.hypothesis-id }}',
    DEBUG_ACTION_HYPOTHESIS_TITLE: '${{ inputs.hypothesis-title }}',
  });
  // run reads the command and its working directory; everything else it needs
  // is in the state start committed.
  assert.deepEqual(byName['Run wrapped command'].env, {
    DEBUG_ACTION_RUN: '${{ inputs.run }}',
    DEBUG_ACTION_WORKDIR: '${{ inputs.working-directory }}',
    DEBUG_ACTION_OUTPUT_DIR: OUTPUT_DIR_EXPR,
    DEBUG_ACTION_COLLECTOR_VERIFY_KEY: '${{ steps.start.outputs.collector-verify-key }}',
    DEBUG_ACTION_INVOCATION_NONCE: NONCE_EXPR,
  });
  // The post-command steps get where to look and who they are. Nothing else:
  // their environments are the ones a hostile wrapped command can influence,
  // so there must be nothing in them worth influencing.
  for (const name of ['Render evidence report', 'Stop collector', 'Apply verdict']) {
    assert.deepEqual(byName[name].env, {
      DEBUG_ACTION_OUTPUT_DIR: OUTPUT_DIR_EXPR,
      DEBUG_ACTION_INVOCATION_NONCE: NONCE_EXPR,
    }, `${name} carries its output dir and its identity, and nothing else`);
  }
  assert.deepEqual(byName['Set up Node.js'].env, {});
  assert.deepEqual(byName['Upload evidence artifact'].env, {});
});

test('the collector verification key reaches the run step and no other step', () => {
  // The round-6 Critical as a property of the file. A later step's environment
  // is attacker-influenceable (spec invariant 10), so the trust anchor must be
  // consumed only in the process whose env was resolved before the wrapped
  // command existed.
  const steps = parseActionYml().steps;
  const carriers = steps.filter((step) => 'DEBUG_ACTION_COLLECTOR_VERIFY_KEY' in step.env);
  assert.deepEqual(carriers.map((step) => step.name), ['Run wrapped command']);
  assert.equal(
    carriers[0].env.DEBUG_ACTION_COLLECTOR_VERIFY_KEY,
    '${{ steps.start.outputs.collector-verify-key }}',
    'runner memory, never a file',
  );
});

test('invocation identity travels as start\'s step output, to every step that reads state', () => {
  // Codex T6 r1 #1, and it REPLACES the round-8 "never remap the nonce" pin:
  // that rule rested on the claim that GITHUB_ENV values are absent from the
  // expression env context, which the runner source disproves. They are
  // present — and job-global — which is precisely why identity cannot live
  // there: a later invocation whose own start failed would inherit an earlier
  // one's nonce and claim its evidence. A step output cannot be inherited.
  const steps = parseActionYml().steps;
  const carriers = steps.filter((step) => 'DEBUG_ACTION_INVOCATION_NONCE' in step.env);
  assert.deepEqual(carriers.map((step) => step.name), [
    'Run wrapped command',
    'Render evidence report',
    'Stop collector',
    'Apply verdict',
  ], 'every step that reads recorded state is told which invocation it belongs to');
  for (const step of carriers) {
    assert.equal(step.env.DEBUG_ACTION_INVOCATION_NONCE, NONCE_EXPR, `${step.name} reads this invocation's start`);
  }
  assert.equal(ACTION_YML_CODE().includes('${{ env.'), false,
    'nothing is sourced from the expression env context, which carries job-global GITHUB_ENV values');
});

test('the guards are exact: post-command steps on always(), upload on what run actually staged', () => {
  const byName = actionStepsByName();
  for (const name of ['Render evidence report', 'Stop collector', 'Apply verdict']) {
    // Exact, not prefix: a bare `${{ always() }}` would also run these on the
    // path where an earlier step failed and `start` never executed at all,
    // where they have neither identity nor state of their own.
    assert.equal(byName[name].if, START_GUARD, `${name} carries the exact guard`);
  }
  // The upload step asks the only process that can honestly answer. Not gated
  // on `report` succeeding: a Step Summary failure must never suppress
  // evidence run proved (Codex T6 r1 #3).
  assert.equal(byName['Upload evidence artifact'].if, "${{ always() && steps.start.outputs.evidence-dir != '' }}");
  // And the three steps that must be unconditional: a guard on any of them
  // would let the evidence verdict be skipped rather than made.
  for (const name of ['Set up Node.js', 'Start collector', 'Run wrapped command']) {
    assert.equal(byName[name].if, undefined, `${name} is unconditional`);
  }
});

test('upload takes exactly the paths run reports staging into, and nothing else', () => {
  const upload = actionStepsByName()['Upload evidence artifact'];
  assert.deepEqual(Object.keys(upload.with), ['name', 'path', 'if-no-files-found']);
  assert.equal(upload.with.name, '${{ inputs.artifact-name }}');
  assert.equal(upload.with['if-no-files-found'], 'ignore');
  // EXACT list: an extra entry is how a broad path (or a foreign directory)
  // gets into the artifact, and the pinned uploader expands directories with
  // implicitDescendants, so one extra line can ship a whole tree.
  assert.deepEqual([...upload.with.path].sort(), [
    '${{ steps.start.outputs.evidence-dir }}/report.json',
    '${{ steps.start.outputs.evidence-dir }}/report.md',
    '${{ steps.start.outputs.evidence-dir }}/session.log',
  ]);
  // The state file carries this run's session token and lives at the
  // output-dir ROOT, outside the invocation-scoped child, so no path here can
  // reach it. Asserted as well as arranged.
  for (const entry of upload.with.path) {
    assert.equal(entry.includes('action-state.json'), false);
    assert.notEqual(entry, OUTPUT_DIR_EXPR);
    assert.equal(entry.startsWith('${{ steps.start.outputs.evidence-dir }}/'), true);
  }
});

test('every action output is produced by the run step, and the set is exactly these five', () => {
  // Capture happens in run, so run is the only step whose account of the
  // session can be trusted; `report` publishes and produces nothing.
  // `evidence-dir`/`evidence-staged` are run's own STEP outputs, consumed by
  // the upload step's guard and paths — deliberately not part of the action's
  // public contract.
  assert.deepEqual(parseActionYml().outputs, {
    'command-exit-code': '${{ steps.run.outputs.command-exit-code }}',
    'session-id': '${{ steps.run.outputs.session-id }}',
    'event-count': '${{ steps.run.outputs.event-count }}',
    'report-path': '${{ steps.run.outputs.report-path }}',
    'evidence-digest': '${{ steps.run.outputs.evidence-digest }}',
  });
});

test('the output-dir default expression is byte-identical at every site, and there are exactly five', () => {
  const text = ACTION_YML();
  // Exact, not a floor: under a `>=` bound two sites could diverge — one
  // pointing somewhere else entirely — while the count still passed.
  assert.equal(text.split(OUTPUT_DIR_EXPR).length - 1, 5,
    'start/run/report/teardown/finish env, and nowhere else');
  assert.equal(text.includes("format('{0}/debug-evidence',runner.temp"), false, 'no whitespace variant');
});
