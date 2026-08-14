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
const { escapeMarkdownText } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_evidence.js'));
// THE RENDERER'S OWN CAP, imported rather than copied. A literal 500 here
// silently disagrees with debug_report.js the moment the cap moves, and if it
// SHRINKS the disagreement is permissive — the same direction that let a
// truncated caveat reach report.md in the first place.
const { EXCERPT_CHAR_CAP, buildReport, renderMarkdown } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_report.js'));

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
  actionInputsFromEnv,
  admissionBlockers,
  admissionCaveats,
  admissionField,
  admissionEstablished,
  evaluateAdmission,
  detectSudoBinary,
  readEffectiveUid,
  readOwnCapabilities,
  readPtraceScope,
  readState,
  redactKnownSecrets,
  reportSubcommand,
  resolveEvidenceDir,
  runSubcommand,
  RUNNER_COMMAND_FILE_VARS,
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
// view of the verification key that command cannot rewrite through any
// ordinary interface, on a host that refuses same-UID ptrace attachment
// (Codex T5 r6, scoped T6 r5).
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
  evidenceTrust: 'strict',
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
    probeAdmission: ADMITTED,
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
    probeAdmission: ADMITTED,
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
    probeAdmission: ADMITTED,
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
// THE PLATFORM PREREQUISITE (Codex T6 r5, rewritten after the r6 Critical).
// Every in-process guarantee this action rests on — the trusted run process,
// the verification key held only in its memory, the collector's private signing
// key — assumes the host forbids same-UID ptrace attachment. Only Yama mode 3
// does that unconditionally: modes 1 and 2 are bypassable with CAP_SYS_PTRACE,
// and standard VM-based GitHub-hosted Linux runners hand workflow commands
// PASSWORDLESS SUDO, so a hostile native command there can elevate, attach to
// the waiting run process or to the collector (whose pid is in state), and
// defeat authentication outright. Calling mode 1 "restricted" was therefore the
// action's core guarantee silently failing on its principal platform.
//
// So: mode 3 is NECESSARY. It is not sufficient (Codex T6 r8): it blocks
// ptrace, but a principal that can reach root rewrites another task's memory
// with a privileged BPF program or a kernel module without ever calling
// ptrace. Strict admission is therefore a CONJUNCTION — mode 3, a non-root
// euid, NO SUDO BINARY at a conventional absolute path or anywhere on the
// inherited PATH, no dangerous capability in this process's own set — and
// anything less is refused before the wrapped command exists unless the caller
// has consciously opted into best-effort evidence. (The sudo term read "no
// passwordless sudo" until round 15 caught it: that was the BEHAVIOURAL probe
// withdrawn in round 9, and this sentence states the condition as it is now,
// not as it once was.)
//
// Records are built by the REAL evaluator with its probes injected, never
// hand-written. A hand-written fixture would keep passing after the
// conjunction lost a term, which is exactly the drift this round closes. And
// injecting every probe is what keeps these tests off THIS host: a test that
// asked the machine for its policy would fail on precisely the hardened runner
// strict mode exists for (Codex T6 r8 #3).
const admissionOf = ({
  ptrace = 'unconditional', uid = 'non-root', sudo = 'absent', capabilities = 'clear',
} = {}) => evaluateAdmission({
  readPtrace: () => ptrace,
  readEuid: () => uid,
  detectSudo: () => sudo,
  readCapabilities: () => capabilities,
});
const ADMITTED = () => admissionOf();

// The detector's `present` reading for a given matched set, recomputed HERE
// from node:crypto rather than by calling the action's own helper: a test that
// shared the implementation's arithmetic would agree with a broken one. Sorted
// and NUL-joined, so the reading depends on the SET of matched candidates and
// not on the order PATH happened to list them (Codex T6 r13).
const sudoPresent = (...paths) => `present: ${paths.length} at sha256=${
  createHash('sha256').update([...paths].sort().join('\0')).digest('hex')}`;

// The qualification is a BLOCK of lines now, not one line: the non-establishment
// and the limits of the check that found it. Both belong beside the digest — a
// reader who sees the digest must not be able to miss either — so the pin is
// that the lines immediately preceding it are all qualification, and that both
// claims are among them.
// Exactly one digest line, and everything else run wrote to its own log is an
// admission-record line — so a stray write cannot hide among them.
const assertOneDigest = (printed, expected = null) => {
  const digests = printed.filter((text) => text.startsWith('evidence-sha256'));
  assert.equal(digests.length, 1, 'exactly one digest line');
  if (expected !== null) assert.deepEqual(digests, [`${expected}\n`], 'over the expected bytes');
  for (const text of printed) {
    assert.ok(text.startsWith('evidence-sha256') || text.startsWith('evidence-qualification'),
      `run wrote something that is neither a digest nor a qualification: ${text}`);
  }
  return digests[0];
};

const assertQualifiedDigest = (printed, digestIndex) => {
  const preceding = [];
  for (let index = digestIndex - 1; index >= 0 && printed[index].startsWith('evidence-qualification'); index -= 1) {
    preceding.unshift(printed[index]);
  }
  assert.ok(preceding.length > 0, 'the qualification sits immediately before the digest it qualifies');
  assert.ok(preceding.some((line) => /the in-process guarantees were NOT established/i.test(line)),
    'the non-establishment is stated');
  assert.ok(preceding.some((line) => /not a proof that no route exists/i.test(line)),
    'and so is the limit of the check that decided it');
  assert.ok(preceding.some((line) => line.includes('ADMISSION RECORD')),
    'and the admission record itself, which is what start\'s copy is compared against');
};

test('the ptrace policy is classified honestly: only mode 3 forbids attachment unconditionally', () => {
  const scope = (raw, platform = 'linux') => readPtraceScope({
    platform,
    readFile: () => {
      if (raw instanceof Error) throw raw;
      return raw;
    },
  });
  // The ONLY value that establishes the prerequisite.
  assert.equal(scope('3\n'), 'unconditional');
  // Bypassable with CAP_SYS_PTRACE — which a command holding passwordless sudo
  // can simply grant itself. Named for what it is, never "restricted".
  for (const mode of ['1', '2']) {
    assert.equal(scope(`${mode}\n`), 'privilege-bypassable', `mode ${mode} is not a boundary`);
  }
  // Classic same-UID attachment permitted outright.
  assert.equal(scope('0\n'), 'permissive');
  // Everything else is UNKNOWN, never read in the host's favour: values this
  // code does not understand (a future mode, a typo), values it cannot parse,
  // a file it could not read, and platforms with no Yama at all.
  const unreadable = Object.assign(new Error('ENOENT'), { code: 'ENOENT' });
  for (const junk of ['4', '999', '', '  ', 'yes', '-1', '1x', '03x', unreadable]) {
    assert.equal(scope(junk), 'unknown', `unrecognised input ${JSON.stringify(String(junk))}`);
  }
  assert.equal(scope('3\n', 'win32'), 'unknown');
  assert.equal(scope('3\n', 'darwin'), 'unknown');
  // The file's contents are host data, and a plain-object lookup resolves
  // INHERITED properties for these three strings — returning a function or an
  // object instead of falling through to 'unknown', which would then travel
  // into state and into diagnostics (Codex T6 r7 #2). The refusal predicate
  // would still refuse them, so this is a contract violation rather than a
  // boundary bypass, and it is fixed at the lookup rather than relied on.
  for (const inherited of ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty']) {
    assert.equal(scope(inherited), 'unknown', `inherited key ${inherited} must not resolve`);
  }
});

test('strict admission is a conjunction, and each condition alone denies it', () => {
  // The one admitting combination.
  assert.deepEqual(ADMITTED().blockers, []);
  assert.equal(admissionEstablished(ADMITTED()), true);
  // Every condition, failing ALONE. A conjunction that quietly lost a term
  // would still admit each of these — which is the whole point of testing them
  // one at a time rather than all-clear vs all-bad.
  for (const [probe, value] of [
    ['ptrace', 'privilege-bypassable'],
    ['ptrace', 'permissive'],
    ['ptrace', 'unknown'],
    ['uid', 'root'],
    ['uid', 'unknown'],
    ['sudo', sudoPresent('/usr/bin/sudo')],
    ['sudo', 'unknown'],
    ['capabilities', 'unknown'],
    ['capabilities', 'CAP_BPF'],
    ['capabilities', 'CAP_SYS_ADMIN+CAP_BPF'],
  ]) {
    const record = admissionOf({ [probe]: value });
    assert.equal(admissionEstablished(record), false, `${probe}=${value} must deny strict`);
    assert.equal(record.blockers.length, 1, `${probe}=${value} is the only blocker`);
    assert.ok(record.blockers[0].includes(value), `${probe}=${value}: the blocker names what it found`);
    assert.equal(record[probe], value, 'and the record keeps the raw reading for diagnostics');
  }
  // Mode 3 is NECESSARY, NEVER SUFFICIENT (the r8 Critical). Each of these has
  // the ptrace boundary and still denies, because the wrapped principal can
  // reach root and rewrite another task's memory without ptrace at all.
  for (const rootRoute of [{ uid: 'root' }, { sudo: sudoPresent('/usr/bin/sudo') }, { capabilities: 'CAP_BPF' }]) {
    const record = admissionOf(rootRoute);
    assert.equal(record.ptrace, 'unconditional', 'mode 3 is present');
    assert.equal(admissionEstablished(record), false, `${JSON.stringify(rootRoute)}: mode 3 does not rescue it`);
  }
  // A record that is missing, malformed, or forged-looking is not established.
  // The predicate is the ONLY thing that decides, and it reads a record it
  // cannot verify — so anything it does not positively recognise is a denial.
  for (const junk of [undefined, null, {}, { blockers: null }, { blockers: 'none' }, { blockers: 0 }, 'clear', []]) {
    assert.equal(admissionEstablished(junk), false, `${JSON.stringify(junk) ?? 'undefined'} is not an admission`);
  }
  // THE PERSISTED blockers ARRAY IS NOT AN INPUT (Codex T6 r9 #2). The record
  // makes a round trip through a same-user-writable state file, and the
  // round-8 predicate asked it one question — "is your blockers list empty?"
  // — which the record could simply answer. Every verdict is now DERIVED from
  // the four readings, and the four readings are validated against the values
  // this code actually produces.
  const forged = {
    ptrace: 'permissive', uid: 'root', sudo: sudoPresent('/usr/bin/sudo'), capabilities: 'CAP_BPF',
    blockers: [],
  };
  assert.equal(admissionEstablished(forged), false, 'an empty blockers list cannot launder four failing readings');
  assert.equal(admissionBlockers(forged).length, 4, 'and every one of them is still reported');
  assert.equal(admissionEstablished({ blockers: [] }), false, 'a bare blockers list establishes nothing');
  assert.deepEqual(
    admissionBlockers({ blockers: [] }).map((blocker) => blocker.split(':')[0]),
    ['same-UID ptrace policy', 'effective uid', 'sudo binary', 'privileged capabilities'],
    'a record with no readings at all fails every condition, by name',
  );
  // Derivation runs the other way too: a persisted list that CLAIMS blockers
  // over four clear readings does not deny, because the list is not consulted.
  assert.equal(admissionEstablished({ ...ADMITTED(), blockers: ['invented'] }), true);
  // Values outside the vocabularies this code produces are unreadable, not
  // clear — including the shapes a forger would reach for first.
  for (const bad of [
    { ptrace: 'unconditional ' }, { ptrace: 'UNCONDITIONAL' }, { ptrace: true },
    { uid: 0 }, { uid: 'nonroot' }, { sudo: 'unavailable' }, { sudo: 'absent ' },
    { sudo: 'unknown: some other reason' }, { sudo: 'unknown:' },
    { capabilities: '' }, { capabilities: 'clear!' }, { capabilities: ['clear'] },
    // THE ANCHORS THEMSELVES (Codex T6 r13). The producers are bounded, so a
    // widened vocabulary breaks nothing until something feeds it a value the
    // producer would never emit — which is exactly what a rewritten state file
    // is. Each case below passes the round-10 pattern this round replaced, and
    // must not pass the anchored one.
    { sudo: 'present: /usr/bin/sudo' }, // the round-10 form, unbounded and path-carrying
    { sudo: 'present: /tmp/evil\nFORGED-LINE/sudo' }, // and the newline it admitted
    { sudo: `present: 1 at sha256=${'a'.repeat(63)}` }, // digest too short
    { sudo: `present: 1 at sha256=${'a'.repeat(65)}` }, // too long
    { sudo: `present: 1 at sha256=${'A'.repeat(64)}` }, // not lower-case hex
    { sudo: `present: 1 at sha256=${'g'.repeat(64)}` }, // not hex at all
    { sudo: `present: 0 at sha256=${'a'.repeat(64)}` }, // present means at least one
    { sudo: `present: 1 at sha256=${'a'.repeat(64)}\nFORGED` }, // a second line
    { sudo: ` present: 1 at sha256=${'a'.repeat(64)}` }, // unanchored at the front
    { capabilities: 'CAP_MADE_UP' }, // a name this action does not check for
    { capabilities: 'CAP_SYS_ADMIN+CAP_MADE_UP' },
    { capabilities: 'CAP_BPF+CAP_SYS_ADMIN' }, // real names, an order the producer never emits
    { capabilities: `CAP_${'X'.repeat(400)}` }, // unbounded length
    { capabilities: 'CAP_SYS_ADMIN\nCAP_BPF' },
    { ptrace: 'unconditional\nFORGED' },
    { uid: 'non-root\nFORGED' },
  ]) {
    const record = { ...ADMITTED(), ...bad };
    assert.equal(admissionEstablished(record), false, `${JSON.stringify(bad)} is not a reading this code produced`);
    assert.ok(admissionBlockers(record).some((blocker) => /unreadable record/.test(blocker)),
      `${JSON.stringify(bad)} is reported as unreadable`);
    // ...and the reason is one of exactly two, never a bare "unreadable".
    assert.ok(admissionBlockers(record).some((blocker) => /unreadable record \((?:malformed reading|outside this action's vocabulary)/.test(blocker)),
      `${JSON.stringify(bad)} names why it was rejected`);
  }
  // The two fixed unknown readings ARE part of the vocabulary — reporting them
  // as "unreadable record" would lose the remediation hint they exist to give.
  for (const reading of ['unknown', 'unknown: empty-or-relative PATH entry']) {
    const record = { ...ADMITTED(), sudo: reading };
    assert.equal(admissionEstablished(record), false, `${reading} denies`);
    assert.deepEqual(admissionBlockers(record), [`sudo binary: ${reading}`], `${reading} is reported as itself`);
  }
  // Inherited properties are not readings either.
  assert.equal(admissionEstablished(Object.create({ ptrace: 'unconditional', uid: 'non-root', sudo: 'absent', capabilities: 'clear' })), false,
    'a prototype cannot supply the readings');
});

test('a probe that cannot be called produces a denying record, never a crash', () => {
  // evaluateAdmission invoked each selected seam immediately, so an explicit
  // `undefined` probe threw TypeError instead of producing the unknown,
  // denying reading the round-9 seam() fix promised everywhere else (Codex
  // T6 r10 #3). A gate that throws is not a gate that denies: the throw
  // escapes to main's catch and becomes exit 1, which reads as "the action
  // crashed" rather than "this host was refused".
  const probes = ['readPtrace', 'readEuid', 'detectSudo', 'readCapabilities'];
  const fields = { readPtrace: 'ptrace', readEuid: 'uid', detectSudo: 'sudo', readCapabilities: 'capabilities' };
  const clear = {
    readPtrace: () => 'unconditional',
    readEuid: () => 'non-root',
    detectSudo: () => 'absent',
    readCapabilities: () => 'clear',
  };
  for (const probe of probes) {
    for (const [label, broken] of [
      ['explicit undefined', undefined],
      ['null', null],
      ['not callable', 'unconditional'],
      ['a throwing probe', () => { throw new Error('probe exploded'); }],
      ['a probe returning nothing', () => undefined],
      ['a probe returning a non-string', () => ({ ptrace: 'unconditional' })],
    ]) {
      const record = evaluateAdmission({ ...clear, [probe]: broken });
      assert.equal(record[fields[probe]], 'unknown', `${probe}: ${label} reads as unknown`);
      assert.equal(admissionEstablished(record), false, `${probe}: ${label} denies`);
      // And only that one reading is affected — a broken probe must not
      // silently poison the others.
      assert.equal(record.blockers.length, 1, `${probe}: ${label} blocks on its own reading alone`);
    }
  }
  // All four broken at once still yields a record rather than a throw.
  const nothing = evaluateAdmission({ readPtrace: undefined, readEuid: undefined, detectSudo: undefined, readCapabilities: undefined });
  assert.equal(admissionEstablished(nothing), false);
  assert.equal(nothing.blockers.length, 4);
});

test('start streams a pre-command admission record on every regime', async () => {
  // AN ARTIFACT-ONLY STAMP IS NOT ENOUGH (Codex T6 r9 #3). A compromised
  // best-effort run can forge whatever stamp the artifact carries, so the
  // stamp is only worth something when there is an unforgeable copy to
  // compare it against. That copy is this one: written by `start`, into its
  // own step log, before the wrapped command exists. It is emitted on EVERY
  // regime — an admitted run needs it as much as a refused one, because
  // "which regime was in force" is exactly what a reader cannot otherwise
  // establish after the fact.
  const recordFrom = (written) => written.split('\n').filter((line) => line.includes('ADMISSION RECORD'));

  // (i) STRICT, ADMITTED — and streamed BEFORE the collector is spawned, so
  //     nothing the job goes on to do can be its cause.
  const outputDir = makeTempDir();
  const port = await getFreePort();
  let writtenAtSpawn = null;
  const strict = await captureStderr(async (soFar) => {
    assert.equal(await startSubcommand({
      inputs: baseInputs({ port: String(port) }),
      outputDir,
      projectRoot: makeTempDir(),
      env: {},
      probeAdmission: ADMITTED,
      spawnShim: (args, options) => {
        writtenAtSpawn = soFar();
        return defaultSpawnShim(args, options);
      },
    }), 0);
  });
  try {
    assert.equal(recordFrom(strict.written).length, 1, 'exactly one record, on the admitted path too');
    assert.match(strict.written, /evidence-trust=strict/);
    assert.match(strict.written, /boundary=ESTABLISHED/);
    assert.match(strict.written, /not a proof that no route exists/i, 'the limitation rides in every copy');
    assert.ok(writtenAtSpawn !== null && writtenAtSpawn.includes('ADMISSION RECORD'),
      'the record was already streamed when the collector was spawned');
  } finally {
    teardownSubcommand({ outputDir, env: invocationEnv(outputDir) });
  }

  // (ii) BEST-EFFORT — the record names the regime and every failing reading.
  const bestEffortDir = makeTempDir();
  const bestEffortPort = await getFreePort();
  const bestEffort = await captureStderr(async () => {
    assert.equal(await startSubcommand({
      inputs: baseInputs({ port: String(bestEffortPort), evidenceTrust: 'best-effort' }),
      outputDir: bestEffortDir,
      projectRoot: makeTempDir(),
      env: {},
      probeAdmission: () => admissionOf({ ptrace: 'privilege-bypassable', sudo: sudoPresent('/usr/bin/sudo') }),
    }), 0);
  });
  try {
    assert.equal(recordFrom(bestEffort.written).length, 1);
    assert.match(bestEffort.written, /evidence-trust=best-effort/);
    assert.match(bestEffort.written, /boundary=NOT established/);
    assert.match(bestEffort.written, /same-UID ptrace policy: privilege-bypassable/);
    // The finding, and NOT the path it was found at: the record carries a
    // count and a digest, so nothing the host supplied reaches the step log.
    assert.match(bestEffort.written, /sudo binary: present: 1 at sha256=[0-9a-f]{64}/);
    assert.equal(bestEffort.written.includes('/usr/bin/sudo'), false,
      'the matched candidate is never echoed into the record');
  } finally {
    teardownSubcommand({ outputDir: bestEffortDir, env: invocationEnv(bestEffortDir) });
  }

  // (iii) STRICT, REFUSED — the record precedes the refusal, so even a run
  //       that produced no evidence leaves an account of why.
  const refusedDir = makeTempDir();
  const refused = await captureStderr(() => startSubcommand({
    inputs: baseInputs({ evidenceTrust: 'strict' }),
    outputDir: refusedDir,
    projectRoot: makeTempDir(),
    env: {},
    probeAdmission: () => admissionOf({ uid: 'root' }),
    spawnShim: () => { throw new Error('a refused start must never spawn a collector'); },
  }));
  assert.equal(refused.result, 3);
  assert.equal(recordFrom(refused.written).length, 1, 'a refusal is a run too');
  assert.match(refused.written, /boundary=NOT established/);
  assert.ok(
    refused.written.indexOf('ADMISSION RECORD') < refused.written.indexOf('refusing to run the wrapped command'),
    'the record comes first',
  );

  // (iv) THE RECORD NAMES ITS INVOCATION AND ITS OWN LIMITS (Codex T6 r10 #4).
  //      The three pieces are compared by a human, and this action verifies
  //      none of that correspondence — so the record has to say so, and it has
  //      to carry the nonce, or a reader could pair a run's digest with a
  //      DIFFERENT invocation's start record and believe they matched.
  const nonceLine = strict.written.split('\n').find((line) => line.includes('ADMISSION RECORD'));
  const nonce = /invocation=([A-Za-z0-9_-]{8,64})/.exec(nonceLine);
  assert.ok(nonce, 'the record names the invocation it belongs to');
  assert.match(strict.written, /this action verifies none of that correspondence/i);
  assert.match(strict.written, /compare .{0,40}against the start record with the same invocation/i);
});

test('the authenticated wording requires a strict admission, not merely clear readings', async () => {
  // BEST-EFFORT WITH NOTHING WRONG (Codex T6 r10 #2). The readings can come
  // back clear on a host whose caller still chose best-effort — and the
  // round-9 builder derived ESTABLISHED and the authenticated trust-unit
  // sentence from the readings ALONE, so that run advertised itself as
  // authenticated while action.yml and the spec both promise that nothing
  // under best-effort is. The regime is half the answer; the readings are the
  // other half, and the claim needs both.
  const clear = ADMITTED();
  const strict = admissionCaveats(clear, 'strict', 'n1').join('\n');
  const bestEffort = admissionCaveats(clear, 'best-effort', 'n1').join('\n');
  // The readings are reported identically — the host is the host.
  assert.match(strict, /in-process boundary=ESTABLISHED/);
  assert.match(bestEffort, /in-process boundary=ESTABLISHED/);
  assert.match(bestEffort, /Findings: every checked route clear/);
  // The CLAIM is not.
  assert.match(strict, /the trust unit is this admission record/i, 'a strict admission is authenticated');
  assert.doesNotMatch(bestEffort, /the trust unit is this admission record/i,
    'best-effort never claims an authenticated trust unit, however clean the host');
  assert.match(bestEffort, /diagnostic claims only/i);
  assert.match(bestEffort, /not admitted under strict/i, 'and it says which half is missing');
  // Stated positively in the structured line too, so a machine reader sees it.
  assert.match(strict, /admission=STRICT \(authenticated\)/);
  assert.match(bestEffort, /admission=DIAGNOSTIC ONLY/);
  // FAIL CLOSED on anything that is not the literal 'strict': a state file is
  // same-user writable, and an unrecognised regime is not a strict one.
  for (const regime of [undefined, null, '', 'STRICT', 'strict ', 'loose', 0]) {
    const text = admissionCaveats(clear, regime, 'n1').join('\n');
    assert.doesNotMatch(text, /the trust unit is this admission record/i,
      `${JSON.stringify(regime) ?? 'undefined'} is not a strict admission`);
    assert.match(text, /admission=DIAGNOSTIC ONLY/);
  }
  // The nonce travels in the record, whatever the regime.
  assert.match(bestEffort, /invocation=n1/);
});

test('every probe denies strict when it cannot be evaluated', () => {
  // The rule for all four: only a POSITIVE, recognised reading clears a
  // condition. Missing files, absent APIs, throwing calls, timeouts and values
  // this code has never seen are all denials — never read in the host's
  // favour, because the cost of guessing wrong is a false authentication
  // claim (Codex T6 r8 #1).
  //
  // (ptrace has its own classification test above.)

  // EFFECTIVE UID.
  assert.equal(readEffectiveUid({ getuid: () => 1001 }), 'non-root');
  assert.equal(readEffectiveUid({ getuid: () => 0 }), 'root');
  // NULL, not undefined (Codex T6 r9 #4). `{ getuid: undefined }` ACTIVATES a
  // default parameter, so the round-8 version of this line asked the LIVE host
  // for its uid: green on Windows because geteuid is genuinely absent, and a
  // FAILURE on the Ubuntu matrix — on precisely the hardened Linux runner
  // strict mode exists for.
  assert.equal(readEffectiveUid({ getuid: null }), 'unknown', 'a platform with no geteuid at all');
  // And the hazard is closed at the seam rather than routed around: an
  // explicitly passed undefined now means "absent" too, because that is what
  // every reader assumes it means.
  assert.equal(readEffectiveUid({ getuid: undefined }), 'unknown', 'explicit undefined is absence, not "use the default"');
  // Omitting the key entirely still wires up the real API — asserted as a
  // contract, not as a claim about this machine's uid.
  assert.ok(['root', 'non-root', 'unknown'].includes(readEffectiveUid()), 'the production default is still wired');
  assert.ok(['root', 'non-root', 'unknown'].includes(readEffectiveUid({})), 'and an empty options object is not a seam');
  assert.equal(readEffectiveUid({ getuid: () => { throw new Error('EPERM'); } }), 'unknown');
  for (const junk of [null, undefined, '0', '1001', 1.5, NaN, Infinity, -0.5, {}]) {
    assert.equal(readEffectiveUid({ getuid: () => junk }), 'unknown', `${JSON.stringify(junk) ?? 'undefined'} is not a uid`);
  }

  // SUDO, BY EXISTENCE AND NEVER BY BEHAVIOUR (Codex T6 r9, Critical).
  //
  // The round-8 probe ran `sudo -n true` and read a denial as "no sudo here".
  // That was unsound twice over. Sudoers rules are COMMAND-SPECIFIC, so a
  // principal holding `NOPASSWD: /usr/bin/env` is denied `true` and cleared
  // admission while retaining a usable route to root. And a fake `sudo` earlier
  // on PATH could print "a password is required", exit 1, and GRANT strict
  // admission while the real /usr/bin/sudo stayed reachable — a probe whose
  // failure mode is granting is worse than no probe at all.
  //
  // So: a sudo binary EXISTING anywhere the inspection reaches denies, full
  // stop — the conventional absolute paths and every candidate on the inherited
  // PATH (round 10). No execution, no interpretation of output.
  const sudoAt = (present, { platform = 'linux', throws = null, ...pathOption } = {}) => detectSudoBinary({
    platform,
    // Absent by default, so a test that says nothing about PATH is testing the
    // conventional paths alone.
    ...(Object.hasOwn(pathOption, 'pathValue') ? { pathValue: pathOption.pathValue } : { pathValue: undefined }),
    statPath: (candidate) => {
      if (throws) throw throws;
      if (Object.hasOwn(present, candidate)) return present[candidate];
      return 'absent';
    },
  });
  // Each trusted path denies on its own.
  for (const candidate of ['/usr/bin/sudo', '/bin/sudo', '/usr/local/bin/sudo']) {
    assert.equal(sudoAt({ [candidate]: 'present' }), sudoPresent(candidate), `${candidate} denies`);
  }
  // All of them, named, so the diagnostic is not a guess.
  assert.equal(
    sudoAt({ '/usr/bin/sudo': 'present', '/bin/sudo': 'present' }),
    sudoPresent('/usr/bin/sudo', '/bin/sudo'),
  );
  // The only clearing reading: every trusted path positively absent.
  assert.equal(sudoAt({}), 'absent');
  // Anything unreadable is a reading this code does not have.
  assert.equal(sudoAt({ '/usr/bin/sudo': 'unreadable' }), 'unknown', 'an unstattable path denies');
  assert.equal(sudoAt({ '/bin/sudo': 'unreadable' }), 'unknown');
  assert.equal(sudoAt({}, { throws: new Error('EACCES') }), 'unknown', 'a throwing stat denies');
  assert.equal(sudoAt({ '/usr/bin/sudo': 'nonsense' }), 'unknown', 'a reading this code does not recognise denies');
  // A present binary still reports as present even when another path is
  // unreadable: the more specific finding is the more useful diagnostic, and
  // both deny anyway.
  assert.equal(
    sudoAt({ '/usr/bin/sudo': 'present', '/bin/sudo': 'unreadable' }),
    sudoPresent('/usr/bin/sudo'),
  );
  // Non-Linux has no such thing as these paths, and "not Linux" is not "no
  // route to root" — this action's boundary claim is Linux-only.
  assert.equal(sudoAt({}, { platform: 'win32' }), 'unknown');
  assert.equal(sudoAt({}, { platform: 'darwin' }), 'unknown');

  // AND THE CONVENTIONAL PATHS ARE NOT THE WHOLE SURFACE (Codex T6 r10,
  // Critical). A fixed three-path list reported `absent` on a NixOS-style
  // layout where sudo lives in the system path — so a wrapped command could
  // become root through a sudo this action had just certified as not there.
  // THE PIN, in the exact shape Codex demonstrated:
  assert.equal(
    sudoAt({ '/run/current-system/sw/bin/sudo': 'present' }, { pathValue: '/run/current-system/sw/bin:/usr/bin' }),
    sudoPresent('/run/current-system/sw/bin/sudo'),
    'a NixOS system-path sudo denies',
  );
  // The round-9 ruling forbade EXECUTING a PATH-resolved binary and trusting
  // what it printed. Reading PATH and lstat-ing what it names executes
  // nothing, and can only ever ADD candidates.
  assert.equal(
    sudoAt({ '/opt/vendor/bin/sudo': 'present' }, { pathValue: '/opt/vendor/bin' }),
    sudoPresent('/opt/vendor/bin/sudo'),
    'any PATH entry is a candidate',
  );
  // A HOSTILE PATH CANNOT SHRINK THE CHECK. Unset, or stripped down to one
  // harmless directory — the conventional paths are checked regardless.
  //
  // ONLY AN ABSENT PATH means "conventional locations only". An explicitly
  // EMPTY one does not (Codex T6 r11, Critical): POSIX and bash both read a
  // NULL COMPONENT as the current working directory, and '' is a single null
  // component — so PATH='' says "look in the cwd", a place a sudo can sit.
  // The round-10 version of this table pinned '' as `absent`, which meant the
  // suite was DEFENDING a false grant of strict admission.
  for (const [label, pathValue] of [
    ['unset', undefined],
    ['null', null],
    ['stripped', '/nowhere'],
    ['not a string', 42],
  ]) {
    assert.equal(sudoAt({ '/usr/bin/sudo': 'present' }, { pathValue }), sudoPresent('/usr/bin/sudo'),
      `${label} PATH still checks the conventional locations`);
    assert.equal(sudoAt({}, { pathValue }), 'absent',
      `${label} PATH with nothing installed is still a clean reading`);
  }
  // THE NULL-COMPONENT TABLE. All three spellings of "this PATH names the
  // working directory" answer identically, in one place, so a future edit
  // cannot fix one and leave the others behind.
  for (const [label, pathValue] of [
    ['a wholly empty PATH', ''],
    ['a lone separator', ':'],
    ['a trailing separator', '/usr/bin:'],
    ['a leading separator', ':/usr/bin'],
    ['a doubled separator', '/usr/bin::/bin'],
    ['a relative entry', 'relative/bin'],
    ['a bare dot', '.'],
  ]) {
    assert.equal(sudoAt({}, { pathValue }), 'unknown: empty-or-relative PATH entry',
      `${label} is an unchecked candidate, not a clean reading`);
  }
  // The reason is a FIXED LITERAL. The raw component is attacker-influenced
  // text and never reaches a diagnostic — it would travel into the step log,
  // the admission record and the artifact (ruling (b), Codex T6 r11).
  for (const hostile of ['\n::CRITICAL::injected', 'a'.repeat(5000), '${IFS}', '../../etc']) {
    const reading = sudoAt({}, { pathValue: hostile });
    assert.equal(reading, 'unknown: empty-or-relative PATH entry', `${JSON.stringify(hostile.slice(0, 20))}: fixed reason`);
    assert.equal(reading.includes(hostile), false, 'the raw component is never echoed');
  }
  // Both lists at once, each named once — a directory that repeats, or that is
  // also a conventional path, must not double-report.
  assert.equal(
    sudoAt({ '/usr/bin/sudo': 'present', '/opt/bin/sudo': 'present' }, { pathValue: '/usr/bin:/opt/bin:/usr/bin:/opt/bin/' }),
    sudoPresent('/usr/bin/sudo', '/opt/bin/sudo'),
  );
  // The reading is over the SET, so the same two candidates reached by a
  // differently ordered PATH are indistinguishable — which is what lets an
  // operator recompute the digest from their own listing.
  assert.equal(
    sudoAt({ '/usr/bin/sudo': 'present', '/opt/bin/sudo': 'present' }, { pathValue: '/opt/bin:/usr/bin' }),
    sudoAt({ '/usr/bin/sudo': 'present', '/opt/bin/sudo': 'present' }, { pathValue: '/usr/bin:/opt/bin' }),
  );
  // A trailing slash names the same directory.
  assert.equal(sudoAt({ '/opt/bin/sudo': 'present' }, { pathValue: '/opt/bin///' }), sudoPresent('/opt/bin/sudo'));
  assert.equal(sudoAt({ '/sudo': 'present' }, { pathValue: '/' }), sudoPresent('/sudo'));
  // (The unresolvable-entry cases live in the null-component table above, which
  // is the single place all of them are pinned — the round-10 version of this
  // loop asserted the bare 'unknown' and sat one table away from the '' case
  // that disagreed with it, which is how the two drifted apart.)
  assert.equal(sudoAt({}, { pathValue: '/usr/bin:relative/bin' }), 'unknown: empty-or-relative PATH entry',
    'a mixed PATH is judged by its worst entry');
  // And an unstattable PATH candidate denies exactly like an unstattable
  // conventional one.
  assert.equal(sudoAt({ '/opt/bin/sudo': 'unreadable' }, { pathValue: '/opt/bin' }), 'unknown');
  // A present binary still outranks an ambiguity, wherever each came from.
  assert.equal(
    sudoAt({ '/opt/bin/sudo': 'present' }, { pathValue: '/opt/bin:relative/bin' }),
    sudoPresent('/opt/bin/sudo'),
  );

  // OWN CAPABILITIES, from /proc/self/status. PERMITTED counts as much as
  // EFFECTIVE: a permitted-but-not-effective capability is one syscall away
  // from being effective.
  const caps = (text, platform = 'linux') => readOwnCapabilities({
    platform,
    readFile: () => { if (text instanceof Error) throw text; return text; },
  });
  const status = (prm, eff) => `Name:\tnode\nUid:\t1001\t1001\t1001\t1001\nCapPrm:\t${prm}\nCapEff:\t${eff}\nSeccomp:\t2\n`;
  assert.equal(caps(status('0000000000000000', '0000000000000000')), 'clear');
  assert.equal(caps(status('0000000000010000', '0000000000000000')), 'CAP_SYS_MODULE', 'bit 16, permitted only');
  assert.equal(caps(status('0000000000000000', '0000000000080000')), 'CAP_SYS_PTRACE', 'bit 19, effective only');
  assert.equal(caps(status('0000000000200000', '0000000000000000')), 'CAP_SYS_ADMIN', 'bit 21');
  assert.equal(caps(status('0000008000000000', '0000000000000000')), 'CAP_BPF', 'bit 39 — the r8 route, and the one a 32-bit mask silently drops');
  assert.equal(caps(status('000000ffffffffff', '000000ffffffffff')).split('+').length, 4, 'a full set names every one');
  // Capabilities this action does not consider dangerous do not deny.
  assert.equal(caps(status('0000000000000400', '0000000000000400')), 'clear', 'CAP_NET_BIND_SERVICE is not one of them');
  // Unevaluable in any way => unknown => denies.
  assert.equal(caps(status('0000000000000000', '0000000000000000').replace(/CapEff:[^\n]*\n/, '')), 'unknown', 'a missing field is not a clear one');
  assert.equal(caps(status('0000000000000000', '0000000000000000').replace(/CapPrm:[^\n]*\n/, '')), 'unknown');
  assert.equal(caps(status('zzzz', '0')), 'unknown', 'unparseable is not zero');
  assert.equal(caps(status('', '0')), 'unknown', 'empty is not zero');
  assert.equal(caps(new Error('ENOENT')), 'unknown', 'no /proc/self/status to read');
  assert.equal(caps(status('0', '0'), 'win32'), 'unknown', 'no /proc at all');
  assert.equal(caps(status('0', '0'), 'darwin'), 'unknown');
});

// Defaulting is BY ABSENCE, not by falsiness (Codex T6 r7 #3). `|| 'strict'`
// rounded an explicitly empty input up to the safe literal, which sounds
// harmless and is not: validateActionInputs promises that an unrecognised
// evidence-trust is an input ERROR, and silently accepting one shape of
// unrecognised value makes that promise untrue. Driven through the real entry
// point, because main() is where the normalisation lives.
test('evidence-trust defaults by absence and reports an explicitly empty value as the input error it is', () => {
  const { spawnSync: spawnSyncChild } = require('node:child_process');
  const start = (extra) => spawnSyncChild(process.execPath, [path.join(__dirname, 'support.js'), 'start'], {
    env: {
      DEBUG_ACTION_OUTPUT_DIR: makeTempDir(),
      DEBUG_ACTION_RUN: 'true',
      PATH: process.env.PATH,
      SystemRoot: process.env.SystemRoot,
      ...extra,
    },
    encoding: 'utf8',
    timeout: 20000,
  });
  // Explicit empty: the promised error, not a silent upgrade.
  const empty = start({ DEBUG_ACTION_EVIDENCE_TRUST: '' });
  assert.equal(empty.status, 1, 'an invalid input is an input failure');
  assert.match(empty.stderr, /invalid inputs:.*evidence-trust: must be 'strict' or 'best-effort'/);
  // Omitted: the default is read off the ENVIRONMENT-BUILDING SEAM, not off
  // this machine (Codex T6 r8 #3). The previous version asserted that an
  // omitted input produced a REFUSAL, which is only true on a host that fails
  // the prerequisite — so it would have failed on exactly the hardened runner
  // strict mode exists for, and a green run here meant "this box is not
  // hardened" as much as it meant "the default is strict".
  assert.equal(actionInputsFromEnv({}).evidenceTrust, 'strict', 'absent means strict');
  assert.equal(actionInputsFromEnv({ DEBUG_ACTION_EVIDENCE_TRUST: '' }).evidenceTrust, '',
    'and an explicit empty value is passed through to be rejected, not rounded up');
  assert.equal(actionInputsFromEnv({ DEBUG_ACTION_EVIDENCE_TRUST: 'best-effort' }).evidenceTrust, 'best-effort');
});

test('the default reaches the refusal on a host that establishes nothing', async () => {
  // The other half of the property above, with the host injected rather than
  // consulted: inputs built by the real env seam with evidence-trust ABSENT,
  // driven through the real start, against a denied admission.
  const outputDir = makeTempDir();
  const inputs = actionInputsFromEnv({ DEBUG_ACTION_RUN: 'true' });
  assert.equal(inputs.evidenceTrust, 'strict');
  const { result, written } = await captureStderr(() => startSubcommand({
    inputs,
    outputDir,
    projectRoot: makeTempDir(),
    env: {},
    probeAdmission: () => admissionOf({ sudo: sudoPresent('/usr/bin/sudo') }),
    spawnShim: () => { throw new Error('a refused start must never spawn a collector'); },
  }));
  assert.equal(result, 3, 'the default refused');
  assert.match(written, /refusing to run the wrapped command/);
  // And best-effort, built the same way, does not refuse — so the assertion
  // above is about the DEFAULT and not about the host.
  const permissive = await captureStderr(() => assert.rejects(startSubcommand({
    inputs: actionInputsFromEnv({ DEBUG_ACTION_RUN: 'true', DEBUG_ACTION_EVIDENCE_TRUST: 'best-effort' }),
    outputDir: makeTempDir(),
    projectRoot: makeTempDir(),
    env: {},
    probeAdmission: () => admissionOf({ sudo: sudoPresent('/usr/bin/sudo') }),
    // Reaching the collector is exactly how far this half needs to go: the
    // gate let it through, which is the property under test.
    spawnShim: () => { throw new Error('past the gate'); },
  }), /past the gate/));
  assert.match(permissive.written, /BEST-EFFORT/, 'the opt-in got past the gate');
});

test('evidence-trust accepts exactly two literals and fails closed on anything else', () => {
  assert.deepEqual(validateActionInputs(baseInputs({ evidenceTrust: 'strict' })), []);
  assert.deepEqual(validateActionInputs(baseInputs({ evidenceTrust: 'best-effort' })), []);
  for (const bad of ['', 'STRICT', 'Best-Effort', 'yes', 'best effort', 'loose']) {
    assert.ok(
      validateActionInputs(baseInputs({ evidenceTrust: bad })).some((error) => /evidence-trust/.test(error)),
      `refuses ${JSON.stringify(bad)}`,
    );
  }
});

test('strict refuses before the wrapped command exists, and nothing downstream can run it', async () => {
  for (const policy of ['privilege-bypassable', 'permissive', 'unknown']) {
    // (the non-ptrace conditions get the same treatment below)
    const outputDir = makeTempDir();
    const projectRoot = makeTempDir();
    const githubOutput = path.join(outputDir, 'github_output');
    writeFileSync(githubOutput, '');
    const { result, written } = await captureStderr(() => startSubcommand({
      inputs: baseInputs({ evidenceTrust: 'strict' }),
      outputDir,
      projectRoot,
      env: { GITHUB_OUTPUT: githubOutput },
      probeAdmission: () => admissionOf({ ptrace: policy }),
      // The refusal happens BEFORE the collector exists, so there is nothing
      // to tear down and nothing listening on the port.
      spawnShim: () => { throw new Error('a refused start must never spawn a collector'); },
    }));
    assert.equal(result, 3, `${policy}: 3 is the machinery-failure class`);
    // The diagnostic has to be actionable: what was found, why it is not a
    // boundary, and both ways forward.
    assert.match(written, new RegExp(`same-UID ptrace policy: ${policy}`), `${policy}: names what it found`);
    assert.match(written, /refusing to run the wrapped command/);
    assert.match(written, /NO sudo binary at a conventional absolute path or anywhere on the inherited PATH/,
      'the sudo policy is stated as existence over the whole inspection, not the old three-path rule');
    assert.match(written, /hosted execution stays best-effort/, 'the hosted-runner consequence is stated, not implied');
    assert.match(written, /bpf_probe_write_user/, 'and the non-ptrace route root opens (Codex T6 r8)');
    assert.match(written, /not a proof that no route exists/i, 'the check states its own limits');
    assert.match(written, /evidence-trust: best-effort/, 'the opt-out is named');
    assert.equal(readState(outputDir), null, `${policy}: no state, so no collector to strand`);
    // And the wrapped command cannot run afterwards either. In production the
    // run step is unconditional, so a failed start SKIPS it (pinned by the
    // guards test); here the same outcome is proved from the other side —
    // there is no state, so run refuses without ever reaching the command.
    const nonce = /^invocation-nonce=(.+)$/m.exec(readFileSync(githubOutput, 'utf8'))[1];
    const runCode = await runSubcommand({
      inputs: baseInputs(),
      outputDir,
      env: { ...RUN_ENV, DEBUG_ACTION_INVOCATION_NONCE: nonce },
      spawnCommand: () => { throw new Error('the wrapped command must never execute after a refusal'); },
    });
    assert.equal(runCode, 3, `${policy}: run refuses too`);
  }
  // Mode 3 present, a route to root open: refused just the same, and the
  // diagnostic names the condition that actually blocked (Codex T6 r8 #1).
  for (const [route, blocked] of [
    [{ uid: 'root' }, 'effective uid: root'],
    [{ sudo: sudoPresent('/usr/bin/sudo') }, `sudo binary: ${sudoPresent('/usr/bin/sudo')}`],
    [{ capabilities: 'CAP_BPF' }, 'privileged capabilities: CAP_BPF'],
    [{ ptrace: 'permissive', uid: 'root', sudo: sudoPresent('/bin/sudo'), capabilities: 'CAP_SYS_ADMIN' }, 'privileged capabilities: CAP_SYS_ADMIN'],
  ]) {
    const outputDir = makeTempDir();
    const { result, written } = await captureStderr(() => startSubcommand({
      inputs: baseInputs({ evidenceTrust: 'strict' }),
      outputDir,
      projectRoot: makeTempDir(),
      env: {},
      probeAdmission: () => admissionOf(route),
      spawnShim: () => { throw new Error('a refused start must never spawn a collector'); },
    }));
    assert.equal(result, 3, `${JSON.stringify(route)}: refused`);
    assert.ok(written.includes(blocked), `${JSON.stringify(route)}: names "${blocked}"`);
    assert.equal(readState(outputDir), null, 'no state, so no collector to strand');
  }
});

test('the policy is read AFTER the identity outputs are published, never as a default parameter', async () => {
  const outputDir = makeTempDir();
  const githubOutput = path.join(outputDir, 'github_output');
  writeFileSync(githubOutput, '');
  let publishedWhenRead = null;
  await captureStderr(() => startSubcommand({
    inputs: baseInputs({ evidenceTrust: 'strict' }),
    outputDir,
    projectRoot: makeTempDir(),
    env: { GITHUB_OUTPUT: githubOutput },
    probeAdmission: () => {
      publishedWhenRead = readFileSync(githubOutput, 'utf8');
      return admissionOf({ ptrace: 'permissive' });
    },
    spawnShim: () => { throw new Error('a refused start must never spawn a collector'); },
  }));
  // start's first act is publishing this invocation's identity and its staging
  // directory; a detector evaluated as a DEFAULT PARAMETER would run before the
  // function body and so before both (Codex T6 r6, ordering).
  assert.match(publishedWhenRead, /^invocation-nonce=/m, 'the nonce was already published');
  assert.match(publishedWhenRead, /^evidence-dir=/m, 'and so was the staging directory');
});

test('best-effort proceeds and qualifies the evidence in all three places', async () => {
  // (i) start's step log, BEFORE the wrapped command exists. This is the
  //     copy the command cannot reach — immutable once streamed, and no later
  //     process can retract it. It establishes that best-effort was chosen,
  //     never that what follows is tamper-resistant.
  const outputDir = makeTempDir();
  const projectRoot = makeTempDir();
  const port = await getFreePort();
  const { written } = await captureStderr(async () => {
    const code = await startSubcommand({
      inputs: baseInputs({ port: String(port), evidenceTrust: 'best-effort' }),
      outputDir,
      projectRoot,
      env: {},
      probeAdmission: () => admissionOf({ ptrace: 'privilege-bypassable' }),
    });
    assert.equal(code, 0, 'an opted-in caller proceeds');
  });
  try {
    assert.match(written, /BEST-EFFORT/);
    assert.match(written, /same-UID ptrace policy: privilege-bypassable/);
    assert.match(written, /not a proof that no route exists/i, 'and states what the check does not cover');
    const state = readState(outputDir);
    assert.equal(state.admission.ptrace, 'privilege-bypassable');
    assert.equal(admissionEstablished(state.admission), false, 'and the record says so as one predicate');
    assert.equal(state.evidenceTrust, 'best-effort');
  } finally {
    teardownSubcommand({ outputDir, env: invocationEnv(outputDir) });
  }

  // (ii) run's own log, immediately before the digest line — beside the
  //      record a reader treats as the trust unit ON THE STRICT PATH, rather
  //      than somewhere else in the job (Codex T6 r6 ruling (b)) — and
  //      (iii) the report caveat. Both are written after the command ran, so
  //      both are diagnostic here: they help on an honest run and can be
  //      suppressed on a dishonest one.
  const runDir = makeTempDir();
  writeState(runDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
    projectRoot: makeTempDir(), failOnCommandFailure: 'true',
    admission: admissionOf({ ptrace: 'privilege-bypassable' }), evidenceTrust: 'best-effort',
  });
  const printed = [];
  const code = await captureViaRun({
    outputDir: runDir,
    env: RUN_ENV,
    readLive: collectorAnswer([{ ts: '2026-08-14T00:00:00.000Z', msg: 'served event' }]),
    writeStdout: (text) => printed.push(text),
  });
  assert.equal(code, 0);
  const digestIndex = printed.findIndex((text) => text.startsWith('evidence-sha256'));
  assert.ok(digestIndex > 0, 'the digest line was printed');
  assertQualifiedDigest(printed, digestIndex);
  const report = JSON.parse(readFileSync(path.join(resolveEvidenceDir(runDir, 'n1'), 'report.json'), 'utf8'));
  assert.ok(report.caveats.some((caveat) => caveat.includes('privilege-bypassable')));
});

test('a renderer failure still gets the qualification: it belongs to the log, not to the report', async () => {
  // The class where only session.log is staged. The report caveat cannot exist
  // here, which is exactly why the log copy is the one that matters.
  const outputDir = makeTempDir();
  writeState(outputDir, {
    nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
    projectRoot: makeTempDir(), failOnCommandFailure: 'true',
    admission: admissionOf({ ptrace: 'permissive' }), evidenceTrust: 'best-effort',
  });
  const printed = [];
  const code = await captureViaRun({
    outputDir,
    env: RUN_ENV,
    readLive: collectorAnswer([{ ts: '2026-08-14T00:00:00.000Z', msg: 'served event' }]),
    renderReport: () => { throw new Error('renderer exploded'); },
    writeStdout: (text) => printed.push(text),
  });
  assert.equal(code, 3);
  assert.equal(existsSync(path.join(resolveEvidenceDir(outputDir, 'n1'), 'report.json')), false);
  const digestIndex = printed.findIndex((text) => text.startsWith('evidence-sha256'));
  assert.ok(digestIndex > 0, 'session.log still has a digest');
  assertQualifiedDigest(printed, digestIndex);
});

// A PATH entry long enough to be legitimate and still blow the render cap on
// its own, and one carrying a newline. Both are what the REAL detector can be
// handed; neither could be reached by the hand-written findings the round-11
// and round-12 guards were built from, which is precisely why those guards
// passed while report.md was being truncated in production (Codex T6 r13).
const LONG_DIRECTORY = `/opt/${'nested-vendor-directory/'.repeat(14)}bin`;
const NEWLINE_DIRECTORY = '/tmp/evil\nFORGED-LINE';

test('the sudo vocabulary spans the counts the producer can actually emit', () => {
  // THE CLOSURE WE CLAIMED WAS NOT CLOSED (Codex T6 r15 #1). The producer's
  // count is the number of matched candidates, which is bounded only by the
  // length of PATH — and a probe with 99,999 PATH entries plus the three
  // conventional paths produced `present: 100002 …`, which the vocabulary then
  // rejected as a value this action does not produce. Fail-closed, so not an
  // admission bypass, but it degrades a best-effort record to "unreadable" for
  // a reading that was perfectly correct, and it falsifies the closure the
  // anchored vocabulary exists to state.
  //
  // NO CLAMPING: a clamped count would invent a semantics ("100002 means at
  // least 99999"?) that we would then have to document and defend. The
  // vocabulary widens to the producer's real range instead.
  const digest = `at sha256=${'a'.repeat(64)}`;
  const accepted = (count) => admissionBlockers({ ...ADMITTED(), sudo: `present: ${count} ${digest}` });
  for (const [label, count] of [
    ['one digit', 1],
    ['two digits', 12],
    ['six digits', 100002],
    ['ten digits', 1234567890],
  ]) {
    assert.deepEqual(accepted(count), [`sudo binary: present: ${count} ${digest}`],
      `${label}: a count the producer can emit is a finding, not an unreadable record`);
  }
  // Eleven digits is past anything a PATH can produce and stays out.
  assert.deepEqual(accepted(12345678901), ["sudo binary: unreadable record (outside this action's vocabulary)"]);
  assert.deepEqual(accepted(0), ["sudo binary: unreadable record (outside this action's vocabulary)"],
    'present means at least one');

  // THE TRUE MAXIMUM. 'present: ' is 9, ' at sha256=' is 11, the digest is 64,
  // so a reading is 84 + digits: 85 at one digit and 94 at ten. The 85 quoted
  // in earlier rounds was the single-digit case mistaken for the maximum, and
  // an ordinary two-digit count already exceeds it.
  assert.equal(`present: 1 ${digest}`.length, 85);
  assert.equal(`present: 1234567890 ${digest}`.length, 94);
  assert.ok(94 <= 128, 'and the widest reading still sits well inside the structural bound');

  // Through the REAL producer, at the scale that was probed. Building the PATH
  // here rather than asserting the regex in isolation is the point: the claim
  // is about what detectSudoBinary can emit, not about what a pattern matches.
  const many = Array.from({ length: 99999 }, (_, index) => `/probe${index}`).join(':');
  const reading = detectSudoBinary({ platform: 'linux', pathValue: many, statPath: () => 'present' });
  assert.match(reading, /^present: 100002 at sha256=[0-9a-f]{64}$/, 'three conventional paths plus 99,999 candidates');
  assert.deepEqual(admissionBlockers({ ...ADMITTED(), sudo: reading }), [`sudo binary: ${reading}`],
    'and the vocabulary accepts what the producer just produced');
  assert.ok(reading.length <= 128, 'still inside the structural bound');
});

test('a reading is validated STRUCTURALLY before any vocabulary is consulted', () => {
  // THE ENUMERATED DEFENCE BECOMES A STRUCTURAL ONE (round-13 residual).
  // Three of the four readings were bounded by luck of construction, and the
  // anchored vocabularies added in round 13 only describe the readings that
  // exist TODAY. A fifth reading added tomorrow with an unbounded value AND a
  // matching unbounded vocabulary would reintroduce the class, and the field
  // sweep would only notice if someone remembered to extend it. This test
  // drives exactly that: a SYNTHETIC field whose vocabulary accepts
  // everything, which is the worst case a future edit can produce.
  const consulted = [];
  const permissive = admissionField('synthetic', 'synthetic reading', 'clear', (value) => {
    consulted.push(value);
    return true;
  });
  // The clean case still works, and the vocabulary IS consulted for it —
  // otherwise this test would pass for the wrong reason.
  assert.equal(permissive.read('clear'), 'clear');
  assert.equal(permissive.read('something'), 'blocked');
  assert.deepEqual(consulted, ['clear', 'something']);

  // And the four rejections. Each must deny, and none may reach the
  // vocabulary — which is the property that makes this a GATE rather than a
  // lint running alongside one.
  consulted.length = 0;
  for (const [label, value] of [
    ['9000 producer bytes', 'x'.repeat(9000)],
    ['an embedded newline', 'clear\nFORGED-LINE'],
    ['a NUL', 'clear\u0000injected'],
    ['a non-string', { toString: () => 'clear' }],
    ['a carriage return', 'clear\rFORGED'],
    ['an escape sequence', 'clear\u001b[31m'],
    ['a DEL', 'clear\u007f'],
    ['a tab', 'clear\tsplit'],
    // BEYOND C0 AND DEL (Codex T6 r15 #2). Round 14's gate excluded C0
    // (U+0000-U+001F) plus DEL and nothing else, so it advertised "no control
    // characters at all" and "single-line" while these all passed — U+0085 NEL
    // among them, which is a C1 control the gate never covered. (Corrected in
    // round 16: this note said "C0/C1", which would have caught NEL.) Today's
    // vocabularies reject them, so this was never an admission bypass — but it
    // defeats exactly the future-proofing the structural gate exists to
    // provide, which is the whole reason that gate is not a lint. Readings are
    // printable ASCII now.
    ['NEL, U+0085', 'clear\u0085FORGED'],
    ['LINE SEPARATOR, U+2028', 'clear\u2028FORGED'],
    ['PARAGRAPH SEPARATOR, U+2029', 'clear\u2029FORGED'],
    ['RIGHT-TO-LEFT OVERRIDE, U+202E', 'clear\u202EFORGED'],
    ['a zero-width space, U+200B', 'clear\u200BFORGED'],
    ['a non-ASCII letter, U+00E9', 'cl\u00e9ar'],
    ['an astral character', 'clear\u{1F600}'],
    ['one character over the bound', 'x'.repeat(129)],
    ['undefined', undefined],
    ['null', null],
    ['a number', 0],
  ]) {
    assert.equal(permissive.read(value), 'malformed', `${label}: must be rejected structurally`);
    assert.deepEqual(consulted, [], `${label}: the vocabulary must never see it`);
  }
  // The bound itself: 128 is generous headroom over today's widest reading
  // (sudo, at 94 — 84 fixed characters plus up to ten count digits) and still
  // far too small for an interpolated path.
  assert.equal(permissive.read('x'.repeat(128)), 'blocked', 'the bound is inclusive');

  // A malformed reading DENIES, and says whose fault it is. "This host failed
  // the check" and "our own probe returned something malformed" are different
  // problems with different fixes, so they are different blockers.
  const malformed = { ...ADMITTED(), capabilities: 'CAP_SYS_ADMIN\nFORGED-LINE' };
  assert.equal(admissionEstablished(malformed), false, 'a malformed reading denies');
  assert.deepEqual(admissionBlockers(malformed), [
    'privileged capabilities: unreadable record (malformed reading — not a bounded printable-ASCII string)',
  ]);
  // Distinct from a well-formed value that is simply not in the vocabulary.
  assert.deepEqual(admissionBlockers({ ...ADMITTED(), capabilities: 'CAP_MADE_UP' }), [
    'privileged capabilities: unreadable record (outside this action\'s vocabulary)',
  ]);
  // Never throws, whatever it is handed.
  for (const value of [Symbol('x'), 9007199254740993n, () => 'clear', new Error('x')]) {
    assert.equal(admissionEstablished({ ...ADMITTED(), uid: value }), false);
  }
});

test('no reading can carry producer bytes: every field is bounded and single-line', () => {
  // THE FIELD-LEVEL SWEEP (Codex T6 r13). "Bounded" was assumed for three
  // readings and false for the fourth, so each is now driven with hostile
  // PRODUCER input — the bytes the host actually supplies — and checked
  // against the vocabulary the record validates, not against a hand-written
  // sample of what the producer usually says.
  const boundedReading = (label, value, cap) => {
    assert.equal(typeof value, 'string', `${label}: a reading is a string`);
    assert.equal(/[\r\n]/.test(value), false, `${label}: single line, got ${JSON.stringify(value)}`);
    assert.ok(value.length <= cap, `${label}: ${value.length} chars exceeds the ${cap}-character bound`);
    // And it must be a value the record accepts — an unbounded reading that
    // merely happens to be short is still a hole.
    assert.deepEqual(
      admissionBlockers({ ...ADMITTED(), [label]: value }).filter((blocker) => /unreadable record/.test(blocker)),
      [],
      `${label}: ${JSON.stringify(value)} is outside the vocabulary`,
    );
  };

  // 1. PTRACE. The producer is the contents of a /proc file, and the lookup is
  //    a Map miss away from 'unknown' — no file byte is ever interpolated.
  for (const raw of ['3\n', '1', 'a'.repeat(9000), 'evil\nFORGED', '\u0000', '3; rm -rf /', '']) {
    boundedReading('ptrace', readPtraceScope({ platform: 'linux', readFile: () => raw }), 21);
  }

  // 2. UID. The producer returns a number; the reading is one of three labels.
  for (const uid of [0, 1001, 4294967295, -1, 1.5, Number.NaN]) {
    boundedReading('uid', readEffectiveUid({ getuid: () => uid }), 8);
  }

  // 3. SUDO. The producer supplies PATHS, and this is the reading that carried
  //    them verbatim. A 362-character candidate produced a 579-character
  //    caveat; a candidate with a newline split the record in two.
  for (const pathValue of [LONG_DIRECTORY, NEWLINE_DIRECTORY, `${LONG_DIRECTORY}:${NEWLINE_DIRECTORY}`, '/usr/bin']) {
    boundedReading('sudo', detectSudoBinary({
      platform: 'linux',
      pathValue,
      statPath: () => 'present',
    }), 94);
  }

  // 4. CAPABILITIES. The producer is a hex mask; the reading is a join over a
  //    FIXED four-name set, so the widest possible value is all four.
  for (const mask of ['000000ffffffffff', 'ffffffffffffffff', '0000000000000000', '0000008000000000']) {
    boundedReading('capabilities', readOwnCapabilities({
      platform: 'linux',
      readFile: () => `CapPrm:\t${mask}\nCapEff:\t${mask}\n`,
    }), 60);
  }

  // The matched paths are NOT in the reading at all — not raw, not sanitised.
  // The actionable fact is "sudo exists here"; a list would rebuild the
  // injection surface for no decision the operator cannot already make.
  const present = detectSudoBinary({ platform: 'linux', pathValue: NEWLINE_DIRECTORY, statPath: () => 'present' });
  assert.match(present, /^present: [0-9]+ at sha256=[0-9a-f]{64}$/);
  assert.equal(present.includes('FORGED-LINE'), false, 'no raw candidate bytes in the reading');
  assert.equal(present.includes('/tmp'), false, 'not even a fragment of one');
  // The digest is over the SORTED, NUL-JOINED matched set, so an operator can
  // recompute it from their own listing without this action disclosing one.
  assert.equal(
    detectSudoBinary({ platform: 'linux', pathValue: undefined, statPath: () => 'present' }),
    sudoPresent('/usr/bin/sudo', '/bin/sudo', '/usr/local/bin/sudo'),
  );
});

test('the whole producer chain stays inside the record contract, not just hand-written findings', async () => {
  // THE GAP THAT HID THE DEFECT. Every earlier guard started from a fixture a
  // human typed. This one starts where the bytes do — detectSudoBinary reading
  // a hostile PATH — and follows them through evaluateAdmission, into
  // admissionCaveats, and out through the renderer a consumer actually reads.
  for (const [label, pathValue] of [
    ['a long legitimate candidate', LONG_DIRECTORY],
    ['a candidate carrying a newline', NEWLINE_DIRECTORY],
    ['both at once', `${LONG_DIRECTORY}:${NEWLINE_DIRECTORY}`],
  ]) {
    const admission = evaluateAdmission({
      readPtrace: () => 'unconditional',
      readEuid: () => 'non-root',
      detectSudo: () => detectSudoBinary({ platform: 'linux', pathValue, statPath: () => 'present' }),
      readCapabilities: () => 'clear',
    });
    assert.equal(admissionEstablished(admission), false, `${label}: a present sudo denies`);
    // The record, and then the report a human is shown.
    const caveats = admissionCaveats(admission, 'best-effort', 'n1');
    const markdown = renderMarkdown(buildReport(
      [{ raw: '{"msg":"e"}', parsed: { ts: '2026-08-14T00:00:00.000Z', msg: 'e' } }],
      { sessionId: 'ci-debug-abc', caveats },
    ));
    for (const caveat of caveats) {
      assert.equal(/[\r\n]/.test(caveat), false, `${label}: the record stays single-line`);
      assert.ok(escapeMarkdownText(caveat).length <= EXCERPT_CHAR_CAP - 100,
        `${label}: ${escapeMarkdownText(caveat).length} escaped characters is outside the authoring margin`);
    }
    // Nothing the host supplied reaches the artifact, and nothing was cut off
    // on the way there.
    assert.equal(markdown.includes('FORGED-LINE'), false, `${label}: no injected bytes in the rendered report`);
    assert.equal(markdown.includes('nested-vendor-directory'), false, `${label}: no raw path fragments either`);
    for (const line of markdown.split('\n').filter((entry) => entry.startsWith('> **Caveat:**'))) {
      assert.equal(line.includes('…'), false, `${label}: a caveat was truncated: ${line.slice(-60)}`);
    }
    // A forged line cannot appear as its own blockquote, which is what the
    // newline case produced before the reading was bounded.
    assert.equal(markdown.includes('\nFORGED-LINE'), false, `${label}: the record was not split`);
  }
});

test('generated caveats keep an authoring margin under the render cap', () => {
  // AUTHORING-TIME FEEDBACK, not a second correctness check. The truncation
  // assertion below is the correctness one: it renders the report and proves
  // nothing a human is shown was cut short. This one fires EARLIER and for a
  // different reason — it tells whoever is editing this prose that they are
  // running out of room, before the sentence they add crosses the cap and
  // turns into a truncation hunt. Delete either and the other does not cover
  // it: this one never renders anything, and that one cannot warn in advance.
  //
  // 400 is EXCERPT_CHAR_CAP minus a deliberate 100-character margin. The
  // record has grown in most rounds of this review, and a caveat sitting at
  // 490 is one clause away from being silently cut.
  const MARGIN = 100;
  const authoringCap = EXCERPT_CHAR_CAP - MARGIN;
  for (const [label, admission, evidenceTrust] of [
    ['admitted', ADMITTED(), 'strict'],
    ['clear but best-effort', ADMITTED(), 'best-effort'],
    ['every route blocked', admissionOf({
      ptrace: 'permissive', uid: 'root', sudo: sudoPresent('/usr/bin/sudo'), capabilities: 'CAP_SYS_MODULE+CAP_SYS_PTRACE+CAP_SYS_ADMIN+CAP_BPF',
    }), 'best-effort'],
    ['an unresolvable PATH', admissionOf({ sudo: 'unknown: empty-or-relative PATH entry' }), 'best-effort'],
    ['no usable record', undefined, 'strict'],
  ]) {
    for (const caveat of admissionCaveats(admission, evidenceTrust, 'n1')) {
      const rendered = escapeMarkdownText(caveat).length;
      assert.ok(
        rendered <= authoringCap,
        `${label}: this caveat is ${rendered} escaped characters, ${rendered - authoringCap} over the ${authoringCap} authoring cap`
        + ` (EXCERPT_CHAR_CAP ${EXCERPT_CHAR_CAP} minus a ${MARGIN} margin) — split it into shorter statements rather than raising the cap: "${caveat.slice(0, 60)}…"`,
      );
    }
  }
});

test('every security statement in the admission record survives Markdown rendering intact', async () => {
  // ASSERTED ON THE RENDERED OUTPUT, NEVER ON THE INPUT (Codex T6 r11 #2).
  // The record was correct in every copy the action produced and still reached
  // report.md truncated: debug_report.js caps each rendered caveat at
  // EXCERPT_CHAR_CAP characters, and one generated caveat was 676 — so the
  // human artifact ended
  // "These are the escala…", silently deleting "not a proof that no route
  // exists" and the examples of routes this action cannot see. report.md read
  // STRONGER than report.json and the step logs, which is the exact inversion
  // the caveat exists to prevent.
  //
  // Neither component was wrong on its own. A Task 2 render cap ate Task 6
  // security text, and only a test that reads what a human is actually shown
  // could see it — which is why every assertion below is against rendered
  // Markdown, and why asserting the caveat strings themselves is what let this
  // through in the first place.
  const required = [
    'not a proof that no route exists',
    'a setuid binary, a mounted container socket, or a writable privileged service grants the same power unobserved',
    'every sudo candidate on the inherited PATH, lstat-ed and never executed',
    'This action verifies none of that correspondence',
    'Compare the copies by hand',
  ];
  // Both regimes, and both the longest and the shortest admission records: the
  // denied record names four findings and is the one closest to any cap.
  for (const [label, admission, evidenceTrust] of [
    ['admitted', ADMITTED(), 'strict'],
    ['clear but best-effort', ADMITTED(), 'best-effort'],
    ['every route blocked', admissionOf({
      ptrace: 'permissive', uid: 'root', sudo: sudoPresent('/usr/bin/sudo'), capabilities: 'CAP_SYS_MODULE+CAP_SYS_PTRACE+CAP_SYS_ADMIN+CAP_BPF',
    }), 'best-effort'],
    ['an unresolvable PATH', admissionOf({ sudo: 'unknown: empty-or-relative PATH entry' }), 'best-effort'],
  ]) {
    const outputDir = makeTempDir();
    writeState(outputDir, {
      nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
      projectRoot: makeTempDir(), failOnCommandFailure: 'true', admission, evidenceTrust,
    });
    const code = await captureViaRun({
      outputDir,
      env: RUN_ENV,
      readLive: collectorAnswer([{ ts: '2026-08-14T00:00:00.000Z', msg: 'served event' }]),
    });
    assert.equal(code, 0, label);
    const evidenceDir = resolveEvidenceDir(outputDir, 'n1');
    const markdown = readFileSync(path.join(evidenceDir, 'report.md'), 'utf8');
    // NOTHING the renderer showed a human was cut short. The cap appends an
    // ellipsis, so its presence on a caveat line is the truncation itself.
    const caveatLines = markdown.split('\n').filter((line) => line.startsWith('> **Caveat:**'));
    assert.ok(caveatLines.length > 0, `${label}: the record reached the report`);
    for (const line of caveatLines) {
      assert.equal(line.includes('…'), false, `${label}: a caveat was truncated: ${line.slice(-60)}`);
    }
    // And every statement that carries the limitation is present in full,
    // compared through the renderer's own escaper so this is a test about
    // SURVIVAL rather than about escaping.
    for (const statement of required) {
      assert.ok(markdown.includes(escapeMarkdownText(statement)),
        `${label}: report.md must carry "${statement.slice(0, 40)}…"`);
    }
    // The plain-text surface is capped by the same helper, so it gets the same
    // guarantee — a consumer reading the step log must not see less than one
    // reading report.md.
    const json = JSON.parse(readFileSync(path.join(evidenceDir, 'report.json'), 'utf8'));
    for (const caveat of json.caveats) {
      assert.ok(escapeMarkdownText(caveat).length <= EXCERPT_CHAR_CAP,
        `${label}: a caveat is too long to render whole: ${caveat.length} chars`);
    }
  }
});

test('run stamps the rendered evidence with the platform caveat, and omits it only when the prerequisite is established', async () => {
  const served = [{ ts: '2026-08-14T00:00:00.000Z', msg: 'served event' }];
  for (const [label, record, expectStamp] of [
    ['admitted', ADMITTED(), false],
    ['ptrace bypassable', admissionOf({ ptrace: 'privilege-bypassable' }), true],
    ['ptrace permissive', admissionOf({ ptrace: 'permissive' }), true],
    ['ptrace unknown', admissionOf({ ptrace: 'unknown' }), true],
    ['root', admissionOf({ uid: 'root' }), true],
    ['a sudo binary', admissionOf({ sudo: sudoPresent('/usr/bin/sudo') }), true],
    ['CAP_BPF', admissionOf({ capabilities: 'CAP_BPF' }), true],
    ['no record at all', undefined, true],
  ]) {
    const policy = label;
    const outputDir = makeTempDir();
    writeState(outputDir, {
      nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
      projectRoot: makeTempDir(), failOnCommandFailure: 'true', admission: record,
      // start always records the regime it ran under; a fixture that omitted it
      // was modelling a state this action never writes.
      evidenceTrust: 'strict',
    });
    const code = await captureViaRun({ outputDir, env: RUN_ENV, readLive: collectorAnswer(served) });
    assert.equal(code, 0, `${policy}: labeling is not refusing — the refusal already happened in start`);
    const evidenceDir = resolveEvidenceDir(outputDir, 'n1');
    const markdown = readFileSync(path.join(evidenceDir, 'report.md'), 'utf8');
    const json = JSON.parse(readFileSync(path.join(evidenceDir, 'report.json'), 'utf8'));
    assert.equal(/> \*\*Caveat:\*\*[^\n]*in-process guarantees were NOT established/.test(markdown), expectStamp,
      `${policy}: markdown stamp`);
    assert.equal(
      json.caveats.some((caveat) => caveat.includes('in-process guarantees were NOT established')),
      expectStamp,
      `${policy}: json stamp`,
    );
    // The caveat names the condition that actually blocked, so a reader can
    // tell "this host permits ptrace" from "this host handed the job root".
    if (expectStamp) {
      for (const blocker of admissionBlockers(record)) {
        assert.ok(json.caveats.some((caveat) => caveat.includes(blocker)), `${label}: the record names ${blocker}`);
      }
    }
    // The ADMISSION RECORD and the limits of the check are mirrored on EVERY
    // run, admitted ones included (Codex T6 r9 #3). The artifact's copy is
    // only meaningful because start streamed an identical one before the
    // command existed; a reader compares the two, and cannot compare what the
    // artifact does not carry.
    assert.ok(json.caveats.some((caveat) => caveat.includes('ADMISSION RECORD')),
      `${label}: the record is mirrored into the report`);
    assert.ok(json.caveats.some((caveat) => /not a proof that no route exists/i.test(caveat)),
      `${label}: json states what the check does not prove`);
    assert.match(markdown, /> \*\*Caveat:\*\*[^\n]*ADMISSION RECORD/,
      `${label}: and the markdown carries it too`);
  }
});

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
      probeAdmission: ADMITTED,
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
    probeAdmission: ADMITTED,
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
    probeAdmission: ADMITTED,
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
    probeAdmission: ADMITTED,
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
    probeAdmission: ADMITTED,
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
      probeAdmission: ADMITTED,
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
      probeAdmission: ADMITTED,
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
    probeAdmission: ADMITTED,
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
  // `__env` is NOT an action input: it is extra environment for the START
  // step, and it exists because the collector's redaction snapshot IS start's
  // environment (spec Security invariant 3 — the collector inherits the job
  // env by design, which is what lets it scrub a job secret out of an event
  // the wrapped command logged). A test that wants to prove redaction has to
  // put the value where the collector will see it, and that is here. Filtered
  // out of `inputs` so it can never be mistaken for one; absent by default, so
  // every existing caller's start environment is byte-for-byte what it was.
  const { __env: startEnv = {}, ...inputOverrides } = overrides;
  const inputs = baseInputs({ port: String(port), ...inputOverrides });
  // The responder key reaches `run` exactly the way action.yml will route it:
  // start writes it to GITHUB_OUTPUT, the runner parses that file when the step
  // ends, and the value is interpolated into the RUN step's env. The harness
  // stands in for the runner — reading the step output here and handing it back
  // as `runEnv` — precisely so nothing in these tests can accidentally take a
  // shortcut through state or the filesystem.
  const startOutput = path.join(outputDir, 'start_output');
  writeFileSync(startOutput, '');
  const code = await startSubcommand({ probeAdmission: ADMITTED, inputs, outputDir, projectRoot, env: { GITHUB_OUTPUT: startOutput, ...startEnv } });
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
    probeAdmission: ADMITTED,
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
    probeAdmission: ADMITTED,
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
    probeAdmission: ADMITTED,
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
    nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug', admission: ADMITTED(),
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
  const digestEntry = ledger.findIndex((entry) => entry.startsWith('evidence-sha256'));
  assert.ok(digestEntry > 1, 'the digest comes after the spawn, not before it');
  assert.match(ledger[digestEntry], /^evidence-sha256 session\.log=[0-9a-f]{64} /);
  // The only thing between them is the admission record run mirrors beside the
  // digest, and nothing follows it.
  for (const entry of ledger.slice(2, digestEntry)) {
    assert.ok(entry.startsWith('evidence-qualification'), `unexpected ledger entry: ${entry}`);
  }
  assert.equal(ledger.length, digestEntry + 1);
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
    assertOneDigest(printed, expected, 'over the bytes actually staged');
    assert.ok(outputs.includes(`evidence-digest=${expected}\n`),
      'and the same content on the machine surface, so either can be compared against the artifact');
    assert.equal(state.collectorAlive, true, 'the collector answered an authenticated challenge');
    assert.equal(state.evidenceCopied, true);
    assert.equal(state.evidenceAuthentic, true, 'the staged bytes came from the collector, not a pathname');
    assert.equal(state.reportRendered, true);
    // The capture flags are ADDED to whatever start recorded, never written
    // from run's own pre-command snapshot: the CAS re-reads the file under the
    // lock and spreads THAT, so nothing start committed is rolled back
    // (Codex T4 #3/r2, applied to run's commit).
    assert.ok(state.sessionId.startsWith('ci-debug-'), 'the session id start minted survives run\'s commit');
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
    const result = await body(() => written.join(''));
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
    nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug', admission: ADMITTED(),
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
  assertOneDigest(printed, expected);
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
    const logged = assertOneDigest(printed).trim();
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
    nonce: 'n1', pid: 1, port: 1, sessionName: 'ci-debug', admission: ADMITTED(),
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
  const logged = assertOneDigest(printed).trim();
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
    // command existed. An ordinary child has no interface for writing into
    // its parent's address space, so this is the one view of the key the
    // command below cannot touch — on a host that refuses same-UID ptrace
    // attachment, which is the prerequisite start detects and labels. The
    // nonce is in
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
      'while the run step\'s environment was resolved before the command existed, so the command it runs cannot revise it');
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
    probeAdmission: ADMITTED,
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
  // And EXCERPT_CHAR_CAP, which the action's tests measure generated caveats
  // against (round 12). Dropping the export leaves that measurement comparing
  // against `undefined`, and the arithmetic degrades to NaN — so the margin
  // guard does NOT pass silently, it fails with `NaN over the NaN authoring
  // cap`, which is true and useless. (Corrected in round 13: this comment
  // originally claimed every length would silently pass, which the round-12
  // mutation had already disproved. `length <= NaN` is false.) The point of
  // pinning the name HERE is to turn that incoherent failure into a sentence
  // naming the actual cause.
  assert.equal(typeof renderer.EXCERPT_CHAR_CAP, 'number', 'debug_report.js must export EXCERPT_CHAR_CAP');
  assert.ok(renderer.EXCERPT_CHAR_CAP > 0, 'a cap of zero or less would truncate everything');
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
//
// An UNTERMINATED heredoc throws, because that is what the runner does — it
// raises "Matching delimiter not found" and fails the step (Codex T6 r3 #2).
// A model that swallowed to EOF instead would let a test assert a parse GitHub
// would never perform, and the attack it demonstrated would in reality only
// have failed the run step rather than redirecting anything.
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
      if (index >= lines.length) throw new Error(`unterminated heredoc for ${heredoc[1]}`);
      values[heredoc[1]] = body.join('\n');
      continue;
    }
    const pair = /^([^=]+)=(.*)$/.exec(lines[index]);
    if (pair) values[pair[1]] = pair[2];
  }
  return values;
};

test('the step-output model matches the runner: an unterminated heredoc is an error, not a swallow', () => {
  assert.deepEqual(parseStepOutputs('a=1\nb<<EOF\nline one\nline two\nEOF\nc=3\n'), {
    a: '1',
    b: 'line one\nline two',
    c: '3',
  });
  assert.throws(() => parseStepOutputs('a=1\nb<<NEVER-CLOSED\nline one\n'), /unterminated heredoc for b/);
});

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
  // `payloadFor` receives the environment the wrapped command is given, which
  // is how the child below learns the one thing it needs to close its heredoc.
  const forge = async (payloadFor) => {
    const outputDir = makeTempDir();
    const projectRoot = makeTempDir();
    writeState(outputDir, {
      nonce: 'n1', pid: 1, port: 1, sessionToken: 'x'.repeat(43), sessionId: 'ci-debug-abc',
      projectRoot, failOnCommandFailure: 'true',
    });
    const githubOutput = path.join(outputDir, 'github_output');
    writeFileSync(githubOutput, '');
    let payload = null;
    const code = await captureViaRun({
      outputDir,
      env: { ...RUN_ENV, GITHUB_OUTPUT: githubOutput },
      readLive: collectorAnswer(served),
      // The child writes to the file directly. It is handed no path and no
      // variable; in production it enumerates the runner's command-file
      // directory, which this seam stands in for.
      spawnCommand: (command, { env }) => {
        payload = payloadFor(env);
        appendFileSync(githubOutput, `${payload.join('\n')}\n`);
        return { status: 0 };
      },
    });
    assert.equal(code, 0, 'the capture itself succeeded — the forgery is not what run is verifying');
    return { outputDir, payload, published: readFileSync(githubOutput, 'utf8') };
  };

  // 1. The plain form. Nothing `run` writes afterwards contests these keys,
  //    because `run` no longer emits them at all.
  const plain = await forge(() => ['evidence-staged=x', 'evidence-dir=C:/foreign']);
  const plainValues = parseStepOutputs(plain.published);
  assert.equal(plainValues['evidence-dir'], 'C:/foreign', 'the channel really is attacker-writable');
  assert.equal(plainValues['evidence-staged'], 'x');

  // 2. The heredoc form, which is what makes a post-command writer unfixable
  //    even for a key it DOES write: the delimiter is the exact line the
  //    trusted process is about to append, so everything up to it becomes
  //    body. The delimiter has to be one the child can spell in advance, and
  //    it can: `session-id=<id>` is a line run always writes, and the id is
  //    sitting in the child's own environment as DEBUG_SESSION_ID (Codex T6 r3
  //    #2 — the earlier version of this test used a delimiter run no longer
  //    emits, which the corrected model rejects as unterminated, exactly as
  //    the runner would).
  const heredoc = await forge((env) => [
    'evidence-staged=x',
    `evidence-dir<<session-id=${env.DEBUG_SESSION_ID}`,
    'C:/foreign/**',
  ]);
  // It parses: this is a file GitHub would accept, not one it would reject.
  const heredocValues = parseStepOutputs(heredoc.published);
  assert.ok(heredocValues['evidence-dir'].includes('C:/foreign/**'),
    'an attacker-controlled MULTILINE path set, which is what a path: block consumes');
  assert.equal(heredocValues['command-exit-code'], undefined,
    'and the trusted line run wrote before the delimiter was swallowed into that body');
  assert.equal(heredocValues['session-id'], undefined,
    'the delimiter line itself is consumed as the terminator, so even that output is lost');

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
// because the upload step's guard and paths come from THIS invocation's start
// outputs, fixed before the wrapped command existed (Codex T6 r1 #1, r2 #1).
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

// The input/output `description:` text, flowed — the copy GitHub renders in the
// marketplace and in a consumer's editor, which is where most callers meet this
// action's claims and where `parseActionYml` deliberately drops the folded
// continuations. Comments cannot appear inside a block scalar, so the lines are
// taken as written.
const actionDescriptionText = () => {
  const collected = [];
  let section = null;
  let capturing = false;
  for (const raw of ACTION_YML().split(/\r?\n/)) {
    const text = raw.replace(/\s+$/, '');
    if (text.trim() === '') continue;
    const indent = text.length - text.trimStart().length;
    if (indent === 0) {
      section = { 'inputs:': 'inputs', 'outputs:': 'outputs' }[text.trim()] ?? null;
      capturing = false;
      continue;
    }
    if (section === null) continue;
    if (indent <= 4) capturing = false;
    if (indent === 4 && /^description:/.test(text.trim())) {
      capturing = true;
      collected.push(text.trim().replace(/^description:\s*/, '').replace(/^["'>|-]+\s*/, ''));
      continue;
    }
    if (capturing && indent >= 6) collected.push(text.trim());
  }
  return collected.join(' ');
};

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
      // The default that REFUSES on a standard hosted runner. Pinned here
      // because a silent flip to 'best-effort' would turn every unverifiable
      // host back into a green run (Codex T6 r6).
      'evidence-trust': 'strict',
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
    DEBUG_ACTION_EVIDENCE_TRUST: '${{ inputs.evidence-trust }}',
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

test('upload takes exactly the paths start advertises before the command runs, and nothing else', () => {
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
  // session can be trusted — authenticated after a strict admission,
  // diagnostic under best-effort; `report` publishes and produces nothing.
  // The upload step reads none of these: its guard and paths come from
  // `start`, before the wrapped command existed. Every output here is
  // availability-only — a wrapped command can suppress or garble them by
  // writing to the same step-output file (Codex T6 r2 #1/r3 (a)).
  assert.deepEqual(parseActionYml().outputs, {
    'command-exit-code': '${{ steps.run.outputs.command-exit-code }}',
    'session-id': '${{ steps.run.outputs.session-id }}',
    'event-count': '${{ steps.run.outputs.event-count }}',
    'report-path': '${{ steps.run.outputs.report-path }}',
    'evidence-digest': '${{ steps.run.outputs.evidence-digest }}',
  });
});

// The comments are part of the deliverable here, because the thing being
// reviewed is a security CLAIM. "Pre-command outputs are out of the wrapped
// command's reach" is true of THIS invocation's command and false of one an
// earlier invocation in the same job already ran: that command's GITHUB_ENV
// file can set BASH_ENV, and every `shell: bash` step afterwards — a later
// invocation's `start` included — sources it before running, so it can append
// a last-wins `evidence-dir=` to that start's own output file. Same-job reuse
// after an instrumented command is outside the guarantee, and the file must
// say so rather than let a reader generalise (Codex T6 r3 #1).
test('action.yml states the scope of its integrity guarantee rather than overclaiming', () => {
  // Flowed into one string: these notes wrap across lines, so a phrase can sit
  // either side of a line break and its `# ` prefix.
  const commentary = ACTION_YML().split(/\r?\n/)
    .filter((line) => line.trim().startsWith('#'))
    .map((line) => line.trim().replace(/^#\s?/, ''))
    .join(' ');
  // Case-insensitive: the emphasis in the file is a writer's choice, the
  // presence of the scope is not.
  for (const phrase of [
    'first (or only) invocation',
    'separate job',
    'bash_env',
  ]) {
    assert.ok(commentary.toLowerCase().includes(phrase), `the scope note must name: ${phrase}`);
  }
  // And the claim it qualifies is stated as scoped, not absolute.
  assert.match(commentary, /out of (?:the reach of|reach of)?\s*THIS invocation'?s? (?:wrapped )?command|unreachable by THIS invocation/i);
  // POLARITY, not vocabulary (Codex T6 r4 #1). The checks above pass on
  // keywords, so flipping "does NOT survive" to "DOES survive" left every one
  // of them green while the comment asserted the opposite of the truth — a pin
  // that stays green through a reversal is worse than no pin. Each claim below
  // is therefore pinned twice: the form it MUST take, and the absence of its
  // inverse.
  const claims = [
    {
      what: 'the same-job limitation',
      required: /it does not survive an earlier instrumented command in the same job/i,
      forbidden: /it does survive an earlier instrumented command|survives an earlier instrumented command/i,
    },
    {
      what: 'the separate-job requirement',
      required: /belongs in a separate job/i,
      forbidden: /same-job reuse is (?:safe|fine|supported|guaranteed)|can be reused safely in the same job/i,
    },
    {
      what: 'the refusal to guarantee same-job reuse',
      required: /same-job reuse is not something this runner channel can be made to guarantee/i,
      forbidden: /same-job reuse is something this runner channel can be made to guarantee/i,
    },
    {
      what: 'the invocation the guarantee is scoped to',
      required: /it holds for the first \(or only\) invocation of this action in a job/i,
      forbidden: /it holds for (?:every|any|each|all) invocations?/i,
    },
  ];
  for (const claim of claims) {
    assert.match(commentary, claim.required, `the scope note must state ${claim.what}`);
    assert.doesNotMatch(commentary, claim.forbidden, `the scope note must not reverse ${claim.what}`);
  }
  // The README reference is an OBLIGATION on Task 8, not a claim that a
  // tracked README already carries the warning — there is none (Codex T6 r4 #3).
  assert.match(commentary, /task 8'?s? readme must say so/i);
  assert.doesNotMatch(commentary, /the readme (?:says|already says) so/i);
  // The platform prerequisite, pinned the same way (Codex T6 r5). Three rounds
  // running, the same shape has surfaced: a conditional guarantee written as an
  // absolute one. So the condition is pinned by polarity too — its presence,
  // and the absence of the unconditional forms it replaced.
  const platformClaims = [
    {
      what: 'the ptrace prerequisite',
      required: /it holds only where the host\s+refuses classic same-uid ptrace attachment/i,
      forbidden: /(?:regardless of|whatever) the host'?s? ptrace|on any host/i,
    },
    {
      what: 'that only mode 3 establishes it',
      required: /only linux yama\s+ptrace_scope 3 does that unconditionally/i,
      // The exact overclaim the r6 Critical was: modes 1 and 2 counted as a
      // boundary, which is the hosted-runner default.
      forbidden: /ptrace_scope >= 1|modes? 1 and 2 (?:are|is) (?:enough|sufficient|a boundary)/i,
    },
    {
      what: 'why modes 1 and 2 are not a boundary here',
      required: /bypassable with cap_sys_ptrace, and standard\s+github-hosted runners ship mode 1 with passwordless sudo/i,
      forbidden: /cap_sys_ptrace (?:is|remains) (?:theoretical|unreachable)/i,
    },
    {
      what: 'that the action refuses rather than merely labels',
      required: /refuses to run the wrapped command at all unless the\s+prerequisite is positively established/i,
      forbidden: /proceeds anyway and labels the evidence(?! instead)/i,
    },
    {
      what: 'why labeling alone cannot be the control',
      required: /such a command can strip\s+the caveat that warns about it/i,
      forbidden: /the caveat (?:is|remains) sufficient|labeling alone is enough/i,
    },
    // The trust contract is CONDITIONAL on the admission mode (Codex T6 r7).
    // Adding a second regime left every claim written as if only strict
    // existed; under best-effort the accepted threat is a command able to
    // rewrite run itself, so run's account, its digest and the report
    // authenticate nothing. Pinned by polarity because the unconditional form
    // is the one that reads naturally and would drift back.
    {
      what: 'what a strict admission buys',
      required: /after a\s+successful strict admission, run'?s account is authenticated/i,
      forbidden: /the (?:trusted )?run digest is the (?:unit of trust|trust anchor)(?![^.]*strict)/i,
    },
    // THE TRUST UNIT HAS THREE PARTS (Codex T6 r9 #3). An artifact plus a
    // digest is forgeable end to end by a command that can rewrite the process
    // producing both; what makes the pair mean anything is the pre-command
    // admission record streamed by `start`, which no later process can retract.
    // The two-part wording is the exact form rounds 7 and 8 shipped, so it is
    // the forbidden half.
    {
      what: 'that the trust unit has three parts',
      where: ['action.yml comments', 'action.yml input/output descriptions', 'support.js comments'],
      required: /admission record[^.]{0,80}digest[^.]{0,80}artifact/i,
      forbidden: /the artifact plus the matching digest from its step log is the trust unit|the artifact plus the matching digest is the (?:trust unit|unit of trust)/i,
    },
    // SUDO IS DETECTED BY EXISTENCE, NEVER BY BEHAVIOUR (the r9 Critical).
    // Probing one command cannot establish absence — sudoers rules are
    // command-specific — and a PATH-planted fake can fabricate a denial that
    // GRANTS admission. The forbidden half names the round-8 design.
    {
      what: 'that sudo is detected by existence, not behaviour',
      where: ['action.yml comments', 'action.yml input/output descriptions', 'support.js comments'],
      required: /any sudo binary at a conventional absolute path or anywhere on the inherited path denies/i,
      forbidden: /(?:probing|running|executing) [`']?sudo[`']?[^.]{0,40}(?:establishes|proves|shows|confirms|is enough|is sufficient)|no passwordless sudo(?![^.]*(?:cannot|does not|is not))/i,
    },
    {
      what: 'what best-effort does NOT buy',
      required: /under\s+`?evidence-trust: best-effort`? it is a diagnostic claim only/i,
      forbidden: /best-effort (?:evidence )?(?:is|remains) (?:authenticated|tamper-resistant|trustworthy)/i,
    },
    {
      what: 'that the digest authenticates only on the strict path',
      where: ['action.yml input/output descriptions'],
      required: /that log line is the authenticated copy only after a\s+successful strict admission/i,
      forbidden: /the authoritative copy is that log line/i,
    },
    {
      what: 'what an unestablished host costs',
      required: /attach to this process, or to the\s+collector whose pid is in the state file, and read or inject memory,\s+which defeats authenticated evidence/i,
      forbidden: /(?:ptrace|attachment) (?:is|remains) (?:irrelevant|not a concern|out of scope entirely)/i,
    },
    {
      what: 'the labeling behaviour, not a claim to have created the boundary',
      required: /the action labels that platform; it cannot\s+create the boundary on it/i,
      forbidden: /the action (?:creates|establishes|enforces) (?:that|the) boundary/i,
    },
    {
      what: 'the scope of the in-process claim',
      required: /that claim is about those values and nothing else/i,
      forbidden: /view of the world the command (?:it runs )?cannot influence/i,
    },
    // Mode 3 is NECESSARY, NOT SUFFICIENT (the r8 Critical). It blocks ptrace;
    // it does not block a principal that can reach root from rewriting another
    // task's memory with a privileged BPF program or a kernel module. Two
    // rounds of text were written as if mode 3 settled the question, so the
    // correction is pinned on both sides.
    {
      what: 'that Yama mode 3 is necessary and not sufficient',
      where: ['action.yml comments', 'support.js comments'],
      required: /mode 3 is necessary,? (?:but )?not sufficient/i,
      forbidden: /mode 3 (?:alone )?is (?:enough|sufficient)|ptrace_scope 3 is all (?:that is |it )?(?:required|needed)/i,
    },
    {
      what: 'the non-ptrace route root opens',
      where: ['action.yml comments', 'support.js comments'],
      required: /bpf_probe_write_user/i,
      forbidden: /ptrace is the only (?:way|route|mechanism)/i,
    },
    // The routes CHECKED, never a proof that none exists (r8 #2). This is the
    // same overclaim shape as rounds 4-7 — a partial control described as a
    // total one — and it is stated on every surface a consumer reads.
    {
      what: 'that the check names its own limits',
      where: ['action.yml comments', 'action.yml input/output descriptions', 'support.js comments'],
      required: /(?:these are )?the escalation routes (?:this action|it) checks, not a proof that no route exists/i,
      forbidden: /(?:proves|proved|establishes|confirms|guarantees|verifies) (?:that )?(?:no|there is no) (?:escalation |privilege )?(?:route|path)/i,
    },
    // THE INSPECTION IS NOT A FIXED PATH LIST (Codex T6 r10, Critical). Three
    // conventional paths reported `absent` on a NixOS-style layout and would
    // have GRANTED strict on a host where the wrapped command can become root.
    // The forbidden half is the shape of that mistake — and of the coordinator's
    // over-broad "never consults PATH" instruction that caused it.
    {
      what: 'that every PATH candidate is inspected',
      where: ['action.yml comments', 'action.yml input/output descriptions', 'support.js comments'],
      required: /every sudo candidate on the inherited path, lstat-ed and never executed/i,
      forbidden: /(?:checks|inspects|covers) (?:only|just) the (?:three )?conventional|path is (?:deliberately )?never (?:consulted|inspected)|the conventional paths are the whole surface/i,
    },
    // THE THREE PIECES ARE COMPARED BY A HUMAN (Codex T6 r10 #4). Nothing in
    // this action checks that run's digest belongs with start's record, so the
    // record says so itself — and carries the nonce, so the comparison cannot
    // accidentally be made across invocations.
    {
      what: 'that the correspondence is verified by a human, not by the action',
      where: ['action.yml comments', 'action.yml input/output descriptions', 'support.js comments'],
      required: /verifies none of that correspondence/i,
      forbidden: /the action (?:verifies|checks|confirms|proves) (?:that )?(?:the )?(?:copies|records|three pieces) match|correspondence is verified automatically/i,
    },
    {
      what: 'that the nonce lets a reader detect a mismatch rather than preventing one',
      where: ['action.yml comments', 'action.yml input/output descriptions', 'support.js comments'],
      required: /lets a reader detect (?:a|any) mismatch/i,
      forbidden: /cannot accidentally be paired|cannot be paired with|prevents (?:a |any )?(?:cross-invocation|mismatched) pairing|makes (?:a |any )?mismatch impossible/i,
    },
    // Hosted execution stays best-effort, and the round-7 sysctl route is
    // withdrawn: the same passwordless sudo that sets mode 3 opens the BPF
    // route, so hardening that way would have demonstrated a FALSE guarantee.
    // The forbidden half is the exact sentence round 7 asked for.
    {
      what: 'that hosted execution stays best-effort',
      where: ['action.yml comments', 'action.yml input/output descriptions'],
      required: /hosted execution (?:therefore )?(?:stays|remains) best-effort/i,
      forbidden: /strict is still reachable|harden the runner first|sysctl -w kernel\.yama\.ptrace_scope=3[^.]*(?:strict|reachable)/i,
    },
  ];
  // SURFACES, asserted separately (Codex T6 r8 #4). The round-7 version flowed
  // the whole action file into ONE haystack and never looked at support.js at
  // all — so a claim could vanish from the `description:` a consumer reads
  // while a duplicate comment elsewhere in the file kept the assertion green,
  // and the report that said it protected both files was simply wrong.
  //
  // Three surfaces, because they have three different audiences: the comments
  // are read by whoever edits the wiring, the descriptions are the copy GitHub
  // renders to a consumer who never opens the file, and support.js is where
  // the behaviour actually lives.
  const flow = (text, prefix) => text.split(/\r?\n/)
    .filter((line) => line.trim().startsWith(prefix))
    .map((line) => line.trim().slice(prefix.length).trim())
    .join(' ');
  const surfaces = {
    'action.yml comments': flow(ACTION_YML(), '#'),
    'action.yml input/output descriptions': actionDescriptionText(),
    'support.js comments': flow(readFileSync(path.join(__dirname, 'support.js'), 'utf8'), '//'),
  };
  for (const [name, text] of Object.entries(surfaces)) {
    assert.ok(text.length > 400, `${name}: the surface extractor found nothing to check`);
  }
  for (const claim of platformClaims) {
    // A claim states which surfaces MUST carry it — and must carry it in each
    // of them independently.
    for (const where of claim.where ?? ['action.yml comments']) {
      assert.match(surfaces[where], claim.required, `${where} must state ${claim.what}`);
    }
    // Its reversal is forbidden EVERYWHERE. A claim that is only required of
    // one surface can still be contradicted on another, and a contradiction
    // anywhere in the shipped text is the failure this pins.
    for (const [name, text] of Object.entries(surfaces)) {
      assert.doesNotMatch(text, claim.forbidden, `${name} must not reverse ${claim.what}`);
    }
  }
});

test('the output-dir default expression is byte-identical at every site, and there are exactly five', () => {
  const text = ACTION_YML();
  // Exact, not a floor: under a `>=` bound two sites could diverge — one
  // pointing somewhere else entirely — while the count still passed.
  assert.equal(text.split(OUTPUT_DIR_EXPR).length - 1, 5,
    'start/run/report/teardown/finish env, and nowhere else');
  assert.equal(text.includes("format('{0}/debug-evidence',runner.temp"), false, 'no whitespace variant');
});

// --- Task 7: the demo repro, the dogfood workflow, the gate forwarder ------

const REPO_ROOT = path.join(__dirname, '..', '..');
const REPRO_PATH = path.join(__dirname, 'demo', 'repro.js');
// The workflow wraps `node <repo-relative path>`; a test that runs the file
// must run THAT file, so the path is built once and the workflow assertion
// below resolves its own literal against this constant rather than repeating
// it. A demo that drifted into two different repros would otherwise pass both.
const REPRO_COMMAND = `node "${REPRO_PATH}"`;

// A structural reader for a workflow file, on exactly the doctrine
// parseActionYml is built on: indentation IS the structure, and a construct
// this reader does not understand THROWS rather than being skipped, because
// skipping is failing open — a job that silently stopped passing
// `evidence-trust: best-effort` would otherwise still satisfy every assertion
// below. The subset is the one this repo's workflows are written in: nested
// block mappings, sequences of mappings (`- name: …`), plain scalars and
// `run: |` block scalars. No anchors, no flow mappings, no multi-document
// files, no scalar sequences.
//
// Block-scalar bodies are joined with '\n' after their own indentation is
// trimmed: what the assertions below read out of a `run:` script is which
// lines it contains, never how deeply they were indented.
const parseWorkflowMapping = (lines, cursor, indent) => {
  const map = {};
  while (cursor.i < lines.length) {
    const line = lines[cursor.i];
    if (line.indent < indent) break;
    if (line.indent > indent) throw new Error(`unexpected indentation ${line.indent}: ${line.body}`);
    if (line.item) break; // the next sequence element starts here
    // ALL of the separation after the colon, not one character of it (Codex T7
    // r5 #2). YAML treats the whitespace between a `:` and its value as
    // separation rather than content, and a pattern that ate exactly one space
    // stored ` *missing` for `runs-on:  *missing` — which is a non-empty string
    // that begins with a space, so the anchor refusal below examined the space
    // and waved the alias through. `[ \t]+` rather than `\s+` because a line
    // break is not separation here: `key:` with nothing after it is the
    // null/nested form the block below reads, and must keep reaching it.
    const entry = /^([A-Za-z0-9_.-]+):(?:[ \t]+(.*))?$/.exec(line.body);
    if (!entry) throw new Error(`unparsed workflow line: ${line.body}`);
    const [, key, rawValue] = entry;
    // NOT LAST-WINS. A second `runs-on:`, or a second `with:` block, silently
    // overwrote the first and left this reader answering for a document nobody
    // wrote (Codex T7 r2 #4). `__proto__` is refused outright rather than
    // counted: assigning it sets the prototype instead of creating an own
    // property, so neither the duplicate check nor any assertion below could
    // ever observe it, and it is not a workflow key in any case.
    if (key === '__proto__') throw new Error("workflow reader: '__proto__' is not a workflow key");
    if (Object.hasOwn(map, key)) throw new Error(`workflow reader: duplicate key '${key}'`);
    cursor.i += 1;
    // BLOCK SCALARS, LITERAL AND FOLDED. `|` keeps the line breaks and `>`
    // folds them to spaces; the `-` chomping indicator strips a trailing
    // newline this reader never produced in the first place, so it is accepted
    // and changes nothing. `>` was added in round 5 (Codex T7 r5 #3): the
    // closeout gate writes one long `description:` that way and the reader
    // could not read the gate AT ALL until it did — the body threw
    // `unexpected indentation`, which is fail-closed and therefore invisible
    // until something actually asked the reader to read that file.
    //
    // Blank lines are dropped before this point, so a folded body reads as one
    // line and a literal body loses its paragraph breaks. That is a real limit
    // of the reader, and it is why `run:` bodies are asserted over for WHICH
    // LINES they contain rather than for their exact text.
    const blockScalar = rawValue === undefined ? null : /^([|>])(-?)$/.exec(rawValue);
    if (blockScalar) {
      const body = [];
      while (cursor.i < lines.length && lines[cursor.i].indent > indent) {
        body.push(lines[cursor.i].body);
        cursor.i += 1;
      }
      map[key] = body.join(blockScalar[1] === '|' ? '\n' : ' ');
      continue;
    }
    // EVERY OTHER BLOCK-SCALAR HEADER IS REFUSED, NOT STORED. `|+`, `>+` and
    // the explicit-indentation forms (`|2`) are constructs this reader does not
    // implement, and no plain scalar in YAML may begin with `|` or `>` — those
    // are indicators, so a quoted `"> file"` reaches this line as `"…` and is
    // unaffected. A header whose body is EMPTY would otherwise be stored as the
    // literal string `|+`: a plausible non-empty scalar satisfying every rule
    // below, which is the anchor defect in a new costume.
    if (rawValue !== undefined && /^[|>]/.test(rawValue)) {
      throw new Error(`workflow reader: '${key}' uses a block scalar header this reader does not implement: ${rawValue}`);
    }
    if (rawValue === undefined || rawValue === '') {
      const next = lines[cursor.i];
      // `pull_request:` with nothing under it is a real, meaningful trigger —
      // null, not an empty mapping, so an assertion can tell the two apart.
      map[key] = next && next.indent > indent
        ? parseWorkflowBlock(lines, cursor, next.indent)
        : null;
      continue;
    }
    // ANCHORS AND ALIASES ARE REFUSED, NOT RESOLVED (Codex T7 r4 #5). `&name`
    // and `*name` are node PROPERTIES rather than text, so `runs-on: *missing`
    // was absorbed as the literal `*missing` — a plausible, non-empty runner
    // name that satisfied every check below while GitHub's loader could not
    // resolve it at all. Round 3 recorded this as a tolerable limit on the
    // grounds that assertions over such a value fail closed; they do not,
    // because no assertion in this file reads `runs-on`.
    //
    // Resolution is deliberately NOT implemented. This repository's workflows
    // use neither construct, so a flat refusal is fail-closed, needs no
    // second pass, and avoids the quote-aware resolution whose own
    // false-rejection edge was the reason for leaving this open.
    //
    // The test is the first NON-SEPARATION character of the UNQUOTED value,
    // which is the only position YAML reads a node property in — `rawValue[0]`
    // is that character because the entry pattern above now consumes every
    // separator, which it did not in round 4 (Codex T7 r5 #2). Anywhere else
    // `*` and `&` are ordinary text and must stay so, or this fix would
    // introduce exactly the kind of false rejection round 4 exists to remove:
    // `run: rm -rf build/*`, `run: "*.js"`, and every glob and `>&2` redirect
    // inside a `run: |` body (which never reaches this line at all) are
    // accepted unchanged.
    //
    // NOT INSIDE A FLOW COLLECTION, and the claim below says so. `[*missing]`
    // is stored as an opaque literal string because flow collections are not
    // parsed at all, so no element of one is ever a scalar this line sees.
    if (rawValue[0] === '&' || rawValue[0] === '*') {
      throw new Error(`workflow reader: '${key}' carries a YAML anchor or alias, which this reader refuses rather than resolves`);
    }
    map[key] = unquoteScalar(rawValue);
  }
  return map;
};

function parseWorkflowBlock(lines, cursor, indent) {
  if (!lines[cursor.i].item) return parseWorkflowMapping(lines, cursor, indent);
  const items = [];
  while (cursor.i < lines.length && lines[cursor.i].indent === indent && lines[cursor.i].item) {
    // Consume the marker, then read the item as an ordinary mapping: its first
    // key sits on the dash line and the rest follow at the same indent.
    lines[cursor.i].item = false;
    items.push(parseWorkflowMapping(lines, cursor, indent));
  }
  return items;
}

const workflowPath = (name) => path.join(REPO_ROOT, '.github', 'workflows', name);
const workflowText = (name) => readFileSync(workflowPath(name), 'utf8');
// The same stripper the reader uses, applied to the whole file: a rule about
// what must NOT appear in the WIRING has to be read against wiring, or the
// prose explaining the rule trips it. (It did: a comment saying this workflow
// deliberately references no `secrets.` value failed a raw-text scan for
// exactly that string.)
const workflowCode = (name) => workflowText(name).split(/\r?\n/).map(stripYamlComment).join('\n');

// GitHub's OWN key sets, at the three levels this reader produces. Allowlists
// rather than denylists, for the same reason the reader throws on a shape it
// does not understand: a key nobody recognises is a key nobody reads, and the
// runner ignores it in silence — `run-on:` is not a slightly-wrong runner
// declaration, it is a job with no runner declaration at all.
const WORKFLOW_KEYS = ['name', 'run-name', 'on', 'permissions', 'env', 'defaults', 'concurrency', 'jobs'];
const JOB_KEYS = ['name', 'permissions', 'needs', 'if', 'runs-on', 'environment', 'concurrency',
  'outputs', 'env', 'defaults', 'steps', 'timeout-minutes', 'strategy', 'continue-on-error',
  'container', 'services', 'uses', 'with', 'secrets'];
const STEP_KEYS = ['id', 'if', 'name', 'uses', 'run', 'working-directory', 'shell', 'with', 'env',
  'continue-on-error', 'timeout-minutes'];

const isMapping = (value) => typeof value === 'object' && value !== null && !Array.isArray(value);

// GitHub's OWN identifier rule, which job ids and step ids share: it must start
// with a letter or `_` and hold only letters, digits, `-` and `_`. The reader's
// line pattern is looser BY DESIGN — the same pattern also has to read
// `runs-on` and `timeout-minutes` — so nothing rejected `9.bad:` as a job id,
// and every Task 7 assertion below then answered for a file GitHub refuses
// outright (Codex T7 r3).
const GITHUB_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_-]*$/;

// The keys GitHub types as a mapping wherever they appear. A scalar here is not
// a slightly-wrong table, it is no table at all — `run-on:` one level down.
// Keys that legitimately take EITHER form (`permissions: read-all`,
// `concurrency: group`, `container: image`, `secrets: inherit`, `needs: job`)
// are deliberately absent.
const MAPPING_VALUED = ['env', 'with', 'defaults', 'outputs', 'strategy', 'services'];

const assertWorkflowKeys = (where, mapping, allowed, required) => {
  for (const [key, value] of Object.entries(mapping)) {
    if (!allowed.includes(key)) throw new Error(`${where}: '${key}' is not a key GitHub reads here`);
    // AN EMPTY BLOCK IS NOT AN EMPTY SETTING, IT IS A MISSING ONE. `on:` with
    // no events under it never triggers and `run:` with no command is not a
    // step, yet both parse to null and both satisfied a schema that asked only
    // whether the PROPERTY existed (Codex T7 r3). Null IS meaningful inside an
    // `on:` block — `pull_request:` alone is a real trigger — and this function
    // is never applied there; it runs at the workflow, job and step levels,
    // where no key of GitHub's means anything without a value.
    if (value === null) throw new Error(`${where}: '${key}' has no value`);
    if (MAPPING_VALUED.includes(key) && !isMapping(value)) {
      throw new Error(`${where}: '${key}' must be a mapping`);
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(mapping, key)) throw new Error(`${where}: missing required key '${key}'`);
  }
};

// THE SCHEMA, applied to everything this reader returns. Without it the reader
// accepted any key matching its lexical pattern, so a job whose `runs-on` had
// been renamed to `run-on` satisfied every Task 7 assertion while GitHub had no
// runner definition to act on. Structure is the only thing that can catch that:
// no assertion about `uses` pinning, port allocation or input validity reads
// the key that went missing.
const assertWorkflowSchema = (document) => {
  assertWorkflowKeys('workflow', document, WORKFLOW_KEYS, ['on', 'jobs']);
  if (!isMapping(document.jobs)) throw new Error('workflow: jobs must be a mapping of job ids');
  for (const [jobName, job] of Object.entries(document.jobs)) {
    if (!GITHUB_IDENTIFIER.test(jobName)) throw new Error(`job ${jobName}: not a job id GitHub accepts`);
    if (!isMapping(job)) throw new Error(`job ${jobName}: not a mapping`);
    // `runs-on` and `steps` are required because every job in this repository's
    // workflows runs steps on a runner; a reusable-workflow call (job-level
    // `uses:`) would need its own branch here, and adding one without adding
    // its assertions would be the same fail-open in a new place.
    assertWorkflowKeys(`job ${jobName}`, job, JOB_KEYS, ['runs-on', 'steps']);
    if (typeof job['runs-on'] !== 'string' || job['runs-on'] === '') {
      throw new Error(`job ${jobName}: runs-on must be a non-empty scalar`);
    }
    if (!Array.isArray(job.steps) || job.steps.length === 0) {
      throw new Error(`job ${jobName}: steps must be a non-empty sequence`);
    }
    const stepIds = new Set();
    job.steps.forEach((step, index) => {
      const where = `job ${jobName} step ${index}`;
      if (!isMapping(step)) throw new Error(`${where}: not a mapping`);
      assertWorkflowKeys(where, step, STEP_KEYS, []);
      // A step id obeys the job-id rule and must additionally be unique within
      // the job, because `steps.<id>.` is how every later expression names a
      // step: two steps answering to one id resolve to whichever GitHub picked,
      // which is why it refuses the file rather than choosing.
      //
      // UNIQUE CASE-INSENSITIVELY (Codex T7 r4 #3). The runner's reference
      // builder holds step ids in an ORDINAL CASE-INSENSITIVE set, so `first`
      // and `FIRST` are one id there while a plain `Set` treats them as two —
      // a file that passes here and fails on the runner. `toLowerCase()` is
      // exactly an ordinal fold here because `GITHUB_IDENTIFIER` has already
      // confined the id to ASCII letters, digits, `-` and `_`, on which
      // Unicode's default case conversion and .NET's ordinal one agree.
      if (Object.hasOwn(step, 'id')) {
        if (!GITHUB_IDENTIFIER.test(step.id)) throw new Error(`${where}: '${step.id}' is not a step id GitHub accepts`);
        const folded = step.id.toLowerCase();
        if (stepIds.has(folded)) throw new Error(`${where}: duplicate step id '${step.id}'`);
        stepIds.add(folded);
      }
      // PRESENCE IS NOT A COMMAND. The XOR below used to read `Object.hasOwn`
      // on both keys, so `run:` with an empty value — null once parsed — was
      // counted as a step carrying a command (Codex T7 r3). What GitHub
      // executes is the STRING, so the string is what has to be there.
      const command = ['uses', 'run'].filter((key) => Object.hasOwn(step, key));
      if (command.length !== 1) {
        throw new Error(`${where}: a step needs exactly one of 'uses' and 'run'`);
      }
      if (typeof step[command[0]] !== 'string') {
        throw new Error(`${where}: '${command[0]}' must be a string`);
      }
      // AND `uses` — ONLY `uses` — MUST ALSO BE NON-EMPTY (Codex T7 r4 #4).
      // Round 3 applied one non-empty rule to both keys and so asserted more
      // than GitHub does: GitHub's schema gives `uses` a minimum length,
      // because an empty one names no action to resolve, and gives `run` only
      // the type `string`. `run: ""` is a step that runs an empty script —
      // pointless, not invalid — so rejecting it was a FALSE REJECTION of a
      // legal document, which is a worse defect than the hole it was chasing.
      if (command[0] === 'uses' && step.uses === '') {
        throw new Error(`${where}: 'uses' must be a non-empty string`);
      }
      if (Object.hasOwn(step, 'with') && !Object.hasOwn(step, 'uses')) {
        throw new Error(`${where}: 'with' belongs to a 'uses' step; the runner ignores it here`);
      }
    });
  }
  return document;
};

// Text in, document out, so a CONSTRUCTED workflow — one deliberately broken
// in a way GitHub would reject — can be pushed through the very same reader the
// assertions below rely on. Reading only from disk left the reader's own
// tolerances untestable.
const parseWorkflowText = (text) => {
  const lines = [];
  for (const raw of text.split(/\r?\n/)) {
    const text = stripYamlComment(raw).replace(/\s+$/, '');
    if (text.trim() === '') continue;
    const indent = text.length - text.trimStart().length;
    const body = text.trim();
    // A sequence element is re-indented to where its keys actually sit, which
    // is what makes an item's mapping parse like any other mapping.
    lines.push(body.startsWith('- ')
      ? { indent: indent + 2, body: body.slice(2), item: true }
      : { indent, body, item: false });
  }
  const cursor = { i: 0 };
  const document = parseWorkflowMapping(lines, cursor, 0);
  if (cursor.i !== lines.length) throw new Error(`workflow reader stopped at line ${cursor.i}: ${lines[cursor.i].body}`);
  return assertWorkflowSchema(document);
};

const parseWorkflow = (name) => parseWorkflowText(workflowText(name));

const DEMO_WORKFLOW = 'debug-evidence-demo.yml';
// The repository's OTHER workflow, named here because the claim below is about
// both of them (Codex T7 r5 #3). It used to be read as raw text only, so the
// "protects this repository's own two workflows" claim was true of one file.
const GATE_WORKFLOW = 'closeout-gate.yml';
const DEMO_ACTION_REF = './actions/debug-evidence';
const actionInvocations = (job) => job.steps.filter((step) => step.uses === DEMO_ACTION_REF);

// The smallest workflow GitHub would actually run, used as the base for the
// step-level mutations below: surgery on the real file cannot express "a step
// with neither uses nor run" without also disturbing its indentation.
const MINIMAL_WORKFLOW = [
  'name: Minimal',
  'on:',
  '  workflow_dispatch:',
  'jobs:',
  '  only:',
  '    runs-on: ubuntu-latest',
  '    steps:',
  '      - name: Do something',
  '        run: echo hello',
  '',
].join('\n');

// THE READER'S OWN TOLERANCES, which nothing tested (Codex T7 r2 #4). It
// accepted any key matching a lexical pattern and assigned it with no schema
// and no duplicate check, so RENAMING a job's `runs-on` to `run-on` left every
// Task 7 assertion below satisfied — the reader stored the typo'd key, no
// assertion read it, and the workflow GitHub would have run had no runner
// definition at all. A reader whose stated doctrine is that an unrecognised
// construct THROWS rather than being skipped has to apply that doctrine to
// keys, not only to shapes.
// SCOPE OF THIS CLAIM, restated in round 4 and deliberately SMALLER than
// either version before it. THE READER VALIDATES SELECTED WORKFLOW, JOB AND
// STEP STRUCTURAL CHECKS, SUFFICIENT TO CATCH A MIS-SPELLED OR MIS-SHAPED KEY
// IN THIS REPOSITORY'S OWN TWO WORKFLOWS. IT DOES NOT IMPLEMENT GITHUB'S
// SCHEMA AND NO LONGER CLAIMS TO.
//
// BOTH OF THOSE TWO FILES GO THROUGH IT, as of round 5 (Codex T7 r5 #3). Until
// then only `debug-evidence-demo.yml` did; `closeout-gate.yml` was read as raw
// text, so a claim about two workflows was structurally true of one — and the
// gate is the file that gates every merge. Reading it needed one construct the
// reader did not have: the FOLDED BLOCK SCALAR (`description: >-`), which threw
// `unexpected indentation` on its own body. That was fail-closed and therefore
// silent, which is exactly how a reader nobody points at a file stays green.
//
// Three consecutive rounds tightened this pass toward "rejects whatever GitHub
// would reject", and each one produced fresh divergence from a schema this
// repository does not implement — round 3's tightening produced an outright
// FALSE REJECTION of `run: ""`, which GitHub accepts. The ambition was the
// defect, not its implementation: a test's advertised scope must be no larger
// than the thing it protects, and the thing this protects is two files.
//
// WHAT IT DECIDES — every rule named here is pinned by at least one case
// below, and the list was audited against the code by DISABLING EACH RULE IN
// TURN rather than written from memory: that indentation is the structure, so
// a key written past its siblings' column belongs to no mapping; which keys
// may appear at the workflow, job and step levels and whether they are spelled
// as GitHub spells them; that no key is repeated in one mapping; that `on:`
// and `jobs:` are present and that no key at these three levels is null; that
// `jobs` is a mapping and each job a mapping; that job ids and step ids match
// GitHub's identifier pattern, and that step ids are unique within a job under
// the case-insensitive comparison the runner uses; that `runs-on` is PRESENT
// and a NON-EMPTY SCALAR and that `steps` is present and a non-empty sequence;
// that a step carries exactly one of `uses` and `run`, that it is a string,
// that `uses` is additionally non-empty, and that `with` accompanies a `uses`;
// that the six keys GitHub always types as tables hold tables; that a block
// scalar is read as `|` or `>` says and any other header is refused rather
// than stored; and that YAML anchors and aliases are refused rather than
// absorbed, wherever this reader reads a scalar.
//
// THE `runs-on` NON-EMPTY RULE IS NOW PINNED, and how it came to be unpinned
// is the most useful thing in this comment (Codex T7 r5 #1). Round 4 declined
// to pin it and wrote the reasoning down: nothing unambiguously invalid
// reaches it, because null is caught earlier by the empty-key rule, `*alias`
// by the anchor rule, and the two remaining shapes are LEGAL GitHub this
// reader refuses anyway —
//
//     runs-on:            # the `group`/`labels` mapping form: legal, refused
//       group: ours
//
//     runs-on:            # the block-sequence array form: legal, refused
//       - self-hosted     # (as an "unparsed workflow line")
//
// — so a case over either would pin a FALSE REJECTION. Every step of that is
// still true, and the two forms above are still deliberately NOT pinned. The
// enumeration simply missed `runs-on: ""`. GitHub's schema admits a non-empty
// string, a sequence or a mapping and never an empty scalar; it reaches the
// rule; deleting the rule accepts it. "THERE IS NOTHING TO PIN HERE" IS ITSELF
// A CLAIM AND NEEDS THE SAME EXHAUSTIVE ENUMERATION AS ANY OTHER — a round
// that reasons its way out of writing a test must show its enumeration so
// somebody can find the missing row, which is what happened here.
//
// TWO RULES REMAIN ENFORCED AND UNPINNED, and the enumeration for each is
// written out so it can be checked rather than taken on trust. Both are
// backstops that no input can reach while the rules in front of them hold:
//
//   - `workflow reader stopped at line N` (the top-level cursor did not reach
//     the end). To leave the cursor short, the top-level mapping loop must
//     break early, and it has exactly two early exits: a line indented LESS
//     than 0, which cannot exist, and a sequence-item line. Item lines are
//     re-indented to `indent + 2` when they are read, so every one of them has
//     an indent of at least 2 and trips the indentation rule before the item
//     break is reached. A `---` document marker, a top-level sequence, a stray
//     item after a complete mapping and a dedent to an unaligned column were
//     all tried: each is refused earlier, by the indentation rule or by
//     `unparsed workflow line`. It stays because it is the assertion that
//     would catch a future relaxation of the indentation rule.
//   - `step: not a mapping`. `job.steps` is only ever what the block reader
//     built, which is a mapping (refused by `!Array.isArray`), a scalar
//     (refused likewise), null (refused as `'steps' has no value`), or an
//     array whose every element is a mapping BY CONSTRUCTION — the array is
//     filled from `parseWorkflowMapping`, which returns a plain object and
//     nothing else. A scalar sequence element (`- plain`), a nested sequence
//     and an empty item are all refused earlier as unparsed lines. It mirrors
//     the job-level check one scope down and costs one line.
//
// WHAT IT DOES NOT DECIDE — listed at the point of the claim rather than left
// to be rediscovered a fourth time. Each of these is ACCEPTED by this reader:
//
//   - VALUE TYPES, beyond the specific ones named above. The round-3 wording
//     claimed value types generally and then excluded `timeout-minutes: abc`
//     and `continue-on-error: maybe`, which ARE a number and a boolean type
//     error — it contradicted itself (Codex T7 r4 #1). Every scalar this
//     reader is not told about is stored exactly as written.
//   - SCALAR CONTENT AND CROSS-REFERENCES: a malformed `if:` expression,
//     `uses: hello world`, `uses:` with no `@ref`, `shell: nosuchshell`,
//     `needs:` naming a job that does not exist, an unknown event under `on:`,
//     a broken cron, an unknown `permissions` scope. Deciding those means
//     implementing GitHub's expression language, ref grammar, event and
//     permission vocabularies and a cron parser — none of which is reachable
//     while this repository ships zero dependencies, and a half-implemented
//     one would be worse than an honest boundary.
//   - `defaults:` IS NOT RECURSIVELY CONSTRAINED. It must be a mapping, and
//     that is all; a typo'd child inside it is admitted, where GitHub
//     constrains the whole subtree.
//   - RUN-STEP AND USES-STEP KEYS ARE NOT SEPARATED. `STEP_KEYS` is one flat
//     allowlist, so a `uses` step carrying `shell:` or `working-directory:` is
//     admitted; GitHub reads those two key sets apart.
//   - `on:` IS ONLY CAUGHT EMPTY IN ITS NULL FORM. `on: ""`, `on: []` and
//     `on: {}` all pass, so the round-3 null rule still admits three
//     representations of a workflow that cannot trigger (Codex T7 r4 #2).
//   - FLOW COLLECTIONS ARE NOT PARSED, so nothing INSIDE one is judged — and
//     that includes anchors and aliases, which is why the rule above is worded
//     "wherever this reader reads a scalar" (Codex T7 r5 #2). `runs-on:
//     [*missing]` is stored as the opaque literal string `[*missing]` and
//     accepted, exactly as `runs-on: [self-hosted, linux]` is accepted for the
//     wrong reason. This is ONE limit with two faces, not two limits: an
//     element of a flow collection is never a scalar this reader reads, so the
//     anchor rule cannot see it without the collection being parsed first.
//     REACHING INSIDE WITHOUT PARSING WAS CONSIDERED AND REJECTED, and here is
//     the enumeration. A scan for `&`/`*` ANYWHERE in the literal refuses
//     `paths: ['**/*.js']`, which is one of the commonest lines in any
//     workflow. A scan of ELEMENT STARTS ONLY — after `[`, `{` or `,` — gets
//     that case right but must decide what a comma is, and a comma inside a
//     quoted element (`["a,*b"]`) makes it wrong again; getting THAT right
//     means tracking quote state across the collection, which is a flow parser
//     by another name and the one thing this round was told not to build. The
//     gate raises the stakes rather than the difficulty: it carries five flow
//     collections (`types:` three times, `workflows:` once, and `push: {}`)
//     and this suite is now required to ACCEPT it, so a new rule reaching
//     inside collections has a real merge-gating file to be wrong about — the
//     `{}` among them being a flow MAPPING, which the same rule would have to
//     handle too. Round 4's standing lesson
//     decides it: generality bought at the price of a false rejection is a net
//     loss. Neither workflow here uses an anchor anywhere, in a flow
//     collection or out of one.
//
// None of the excluded cases is pinned as ACCEPTED, deliberately: an
// `assert.doesNotThrow` over them would make today's gap tomorrow's
// requirement and stand in the way of closing it. Several of them ARE pinned
// for the two workflows this suite actually asserts over (the `uses:` pin
// check requires a 40-hex SHA); they are unconstrained only for arbitrary
// documents, which this reader is not in the business of judging.
test("the workflow reader refuses the mis-spelled and mis-shaped keys this repository's own workflows could acquire, rather than storing them", () => {
  // The positive control first: the base each mutation below starts from is
  // one this reader accepts, so every red below is caused by the mutation.
  assert.doesNotThrow(() => parseWorkflowText(MINIMAL_WORKFLOW));
  assert.doesNotThrow(() => parseWorkflowText(workflowText(DEMO_WORKFLOW)));
  // BOTH WORKFLOWS, because the claim above says both (Codex T7 r5 #3). The
  // gate was previously read as raw text only, so every structural rule in this
  // file protected exactly one of the two files it claimed to protect — and the
  // gate is the more consequential one. Passing it through here is also the
  // legal-document control for every strictness rule in the reader: it is the
  // largest real workflow this repository owns, and a rule that rejects a legal
  // construct is far likelier to meet one here than in MINIMAL_WORKFLOW.
  assert.doesNotThrow(() => parseWorkflowText(workflowText(GATE_WORKFLOW)));
  const real = workflowText(DEMO_WORKFLOW);
  assert.ok(real.includes('    runs-on: ubuntu-latest\n'), 'the mutation target exists as written');
  // CODEX'S EXACT CASE, on the real file: one job loses its runner definition
  // and keeps a plausible-looking neighbour in its place.
  assert.throws(
    () => parseWorkflowText(real.replace('    runs-on: ubuntu-latest\n', '    run-on: ubuntu-latest\n')),
    /run-on/,
    'a job key GitHub does not know is an error, not a stored property',
  );
  // …and the same file with the key simply GONE, because an allowlist that
  // only rejected the typo would pass a job that dropped the line entirely.
  assert.throws(
    () => parseWorkflowText(real.replace('    runs-on: ubuntu-latest\n', '')),
    /runs-on/,
    'a job with no runner definition is not a job',
  );
  // DUPLICATES. YAML last-wins silently, so a second `runs-on:` (or a second
  // `with:` block) meant the reader answered for a document nobody wrote.
  assert.throws(
    () => parseWorkflowText(real.replace('    runs-on: ubuntu-latest\n', '    runs-on: ubuntu-latest\n    runs-on: windows-latest\n')),
    /duplicate key/,
    'the last one does not silently win',
  );
  // …AND THE SAME SURGERY ON THE GATE, because "accepts it" is not "protects
  // it": a reader that parsed the gate and rejected nothing in it would satisfy
  // the positive control above while catching none of the typos the claim says
  // it catches. The gate declares three jobs and gates every merge, so a job of
  // its own that lost its runner definition is the more expensive version of
  // exactly the defect this reader was built for.
  const gate = workflowText(GATE_WORKFLOW);
  assert.ok(gate.includes('    runs-on: ubuntu-latest\n'), 'the gate mutation target exists as written');
  assert.throws(
    () => parseWorkflowText(gate.replace('    runs-on: ubuntu-latest\n', '    run-on: ubuntu-latest\n')),
    /run-on/,
    'a typo in the gate is a typo the reader reports',
  );
  assert.throws(
    () => parseWorkflowText(gate.replace('  retry-forwarder:\n', '  retry.forwarder:\n')),
    /not a job id/,
    'and the gate obeys the identifier rule like any other file',
  );
  // `runs-on` MUST BE A NON-EMPTY SCALAR, and round 4 concluded — wrongly, and
  // with the coordinator's endorsement — that there was no case here to pin
  // (Codex T7 r5 #1). Its enumeration ran: null, caught upstream by the
  // empty-key rule; `*alias`, caught by the anchor rule; the `group`/`labels`
  // mapping and the block-sequence array, both LEGAL GitHub this reader refuses
  // anyway, so a case over them would pin a FALSE REJECTION. Every step of that
  // was true. It simply MISSED THE EMPTY STRING. GitHub's schema admits a
  // non-empty string, a sequence or a mapping and never an empty scalar;
  // `runs-on: ""` reaches this rule, and deleting the rule makes it accepted.
  //
  // The transferable half: "there is nothing to pin here" is itself a claim,
  // and needs the same exhaustive enumeration as any other. A round that
  // reasons its way out of a test has to show its enumeration.
  for (const empty of ['""', "''"]) {
    assert.throws(
      () => parseWorkflowText(MINIMAL_WORKFLOW.replace('    runs-on: ubuntu-latest\n', `    runs-on: ${empty}\n`)),
      /runs-on must be a non-empty scalar/,
      `runs-on: ${empty} names no runner GitHub could schedule on`,
    );
  }
  // …and it must NOT be strict about what a runner NAME looks like, which is
  // the false rejection lurking one step past this rule and the reason round 4
  // was right to be careful. An expression is the ordinary way to write a
  // matrix job's runner, and this is a legal document end to end.
  assert.doesNotThrow(() => parseWorkflowText(MINIMAL_WORKFLOW.replace(
    '    runs-on: ubuntu-latest\n',
    '    strategy:\n      matrix:\n        os: [ubuntu-latest, windows-latest]\n    runs-on: ${{ matrix.os }}\n',
  )), 'a matrix expression is a runner declaration, not a missing one');
  // ANCHORS AND ALIASES ARE REFUSED, NOT ABSORBED (Codex T7 r4 #5). Round 3
  // recorded `&`/`*` as a known limit on the argument that "every assertion
  // over such a value fails closed" — which was wrong, because NO assertion in
  // this suite reads `runs-on` at all, so `runs-on: *missing` stored a
  // plausible non-empty string and sailed through a schema whose whole job is
  // to notice that a runner definition went missing. Refusal is the fix rather
  // than resolution: this repository's workflows use neither construct, so a
  // flat refusal is fail-closed and cannot mis-resolve anything.
  //
  // SCOPED TO WHERE THIS READER READS A SCALAR, and the claim above says so
  // (Codex T7 r5 #2). `runs-on: [*missing]` is NOT refused: flow collections
  // are stored as opaque literals, so no element of one is ever a scalar this
  // rule sees. That exclusion is recorded rather than closed — see the claim
  // for why reaching inside a collection this reader does not parse costs more
  // than it buys — and it is deliberately not pinned as accepted.
  assert.throws(
    () => parseWorkflowText(real.replace('    runs-on: ubuntu-latest\n', '    runs-on: *missing\n')),
    /anchor or alias/,
    'an alias GitHub could not resolve is not a runner name',
  );
  assert.throws(
    () => parseWorkflowText(real.replace('    runs-on: ubuntu-latest\n', '    runs-on: &runner ubuntu-latest\n')),
    /anchor or alias/,
    'an anchor definition is a node property, not part of the scalar',
  );
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        uses: a/b@v1\n        with: *inputs\n')),
    /anchor or alias/,
  );
  // …including where the SCHEMA pass never runs. `on:`'s contents are stored
  // as written and never key-checked, so a refusal that lived in the schema
  // instead of the reader would leave an unresolvable alias inside a trigger
  // block untouched.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('  workflow_dispatch:\n', '  push: &trigger\n')),
    /anchor or alias/,
  );
  // …AND THE SEPARATOR IS NOT ONE CHARACTER WIDE (Codex T7 r5 #2). The entry
  // pattern consumed EXACTLY ONE space after the colon, so `runs-on:  *missing`
  // — two spaces — left the value beginning with a space. The character the
  // refusal examined was therefore that space rather than the alias indicator,
  // the value was stored as the non-empty literal ` *missing`, and the document
  // took the very path this refusal exists to close. The bypass is one keypress
  // wide and survives every case above it.
  assert.throws(
    () => parseWorkflowText(real.replace('    runs-on: ubuntu-latest\n', '    runs-on:  *missing\n')),
    /anchor or alias/,
    'two spaces after the colon does not turn an alias into a runner name',
  );
  assert.throws(
    () => parseWorkflowText(real.replace('    runs-on: ubuntu-latest\n', '    runs-on: \t&runner ubuntu-latest\n')),
    /anchor or alias/,
    'a tab is separation as much as a space is',
  );
  // The root of that bypass, pinned at the root: YAML says the separation
  // between a `:` and its value is NOT part of the value, so what the reader
  // stores is the value — not the value with a space glued to its front. A
  // `uses:` written with two spaces used to be stored as ` ./actions/…`, which
  // no exact comparison in this file matches, so the invocation it names simply
  // stopped being counted. That is the reader answering for a document nobody
  // wrote, one character wide.
  const separated = parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        run:  echo hello\n'));
  assert.equal(separated.jobs.only.steps[0].run, 'echo hello', 'separation after the colon is separation, not the first character of the value');
  // …and widening the separator does not mean allowing NONE of it: `run:echo`
  // is a plain scalar in YAML, not a key with a value, so a step written that
  // way has no command at all and the reader must not invent one.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        run:echo hello\n')),
    /unparsed workflow line/,
    'a colon with no separation after it is not a key indicator',
  );
  // AND THE LEGAL CASES STAY LEGAL, which is the whole difficulty: `*` and `&`
  // are node properties only as the first character of an unquoted scalar, and
  // are ordinary text everywhere else. Rejecting a shell glob or a `>&2`
  // redirect would be a new false rejection of exactly the kind fix (4) above
  // exists to remove. (The real demo workflow, asserted at the top of this
  // test, carries both inside its `run:` blocks and is the live control.)
  for (const legal of [
    '        run: rm -rf build/*\n',
    '        run: "*.js && echo done"\n',
    "        run: '&notananchor'\n",
    '        run: echo a * b & c\n',
    '        run: |\n          for f in *.js; do echo "$f" >&2; done\n',
  ]) {
    assert.doesNotThrow(
      () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', legal)),
      `a '*' or '&' that is not a node property is ordinary text: ${legal.trim()}`,
    );
  }
  // BLOCK SCALARS, BOTH KINDS (Codex T7 r5 #3). Until round 5 the reader knew
  // only `|`, so the gate's folded `description: >-` threw on its own body and
  // the gate could not be read at all. `>` folds its lines to spaces and `|`
  // keeps the breaks, and both are pinned because a fold implemented as a join
  // with '\n' — or the reverse — passes every other case in this file.
  const folded = parseWorkflowText(MINIMAL_WORKFLOW.replace(
    '        run: echo hello\n',
    '        run: >-\n          echo one\n          echo two\n',
  ));
  assert.equal(folded.jobs.only.steps[0].run, 'echo one echo two', '`>` folds its line breaks to spaces');
  const literal = parseWorkflowText(MINIMAL_WORKFLOW.replace(
    '        run: echo hello\n',
    '        run: |\n          echo one\n          echo two\n',
  ));
  assert.equal(literal.jobs.only.steps[0].run, 'echo one\necho two', '`|` keeps them');
  // The chomping indicator this reader accepts changes only a trailing newline
  // it never emits, so `|-` must read exactly as `|` does rather than as a
  // header it refuses.
  const chomped = parseWorkflowText(MINIMAL_WORKFLOW.replace(
    '        run: echo hello\n',
    '        run: |-\n          echo one\n          echo two\n',
  ));
  assert.equal(chomped.jobs.only.steps[0].run, 'echo one\necho two');
  // …and the headers it does NOT implement are refused rather than stored as
  // scalars. `|+` keeps trailing blank lines, which this reader drops before it
  // ever sees them, and `|2` sets an explicit indentation this reader does not
  // read — storing either as the literal text `|+` would hand every rule below
  // a plausible non-empty string.
  for (const header of ['|+', '>+', '|2']) {
    assert.throws(
      () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', `        run: ${header}\n          echo one\n`)),
      /block scalar header this reader does not implement/,
      `${header} is not a header this reader can honour`,
    );
  }
  // AND A QUOTED SCALAR THAT MERELY STARTS WITH ONE IS ORDINARY TEXT, which is
  // the same false-rejection edge the anchor rule has: `|` and `>` are
  // indicators only where a value begins unquoted, and a redirect is neither.
  for (const legal of ['        run: "> out.txt"\n', "        run: '|'\n", '        run: echo hi > out.txt\n']) {
    assert.doesNotThrow(
      () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', legal)),
      `a '|' or '>' that is not a block header is ordinary text: ${legal.trim()}`,
    );
  }
  // INDENTATION IS THE STRUCTURE, and a key written past its siblings' column
  // belongs to no mapping — YAML refuses the file rather than guessing which
  // level was meant. Nothing pinned this until round 5's disable-each-rule
  // sweep: with the check inert, a `timeout-minutes` one column too deep is
  // silently absorbed into the job above it, so the reader answers for a job
  // the file does not declare. That is the duplicate-key defect again, one
  // column wide, and it is the rule the whole reader is built on.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('    steps:\n', '     timeout-minutes: 5\n    steps:\n')),
    /unexpected indentation 5/,
    'a key indented past its siblings is a key of no mapping',
  );
  // …and the same key at the right column is an ordinary job key, or this
  // would be a reader that refuses nesting rather than one that reads it.
  assert.doesNotThrow(() => parseWorkflowText(MINIMAL_WORKFLOW.replace('    steps:\n', '    timeout-minutes: 5\n    steps:\n')));
  // JOB IDS, which nothing validated at all (Codex T7 r3). GitHub's rule is
  // explicit — a job id starts with a letter or `_` and holds only letters,
  // digits, `-` and `_` — and the reader's line pattern is looser than that BY
  // DESIGN, because the same pattern also has to read `runs-on` and
  // `timeout-minutes`. So each of these parsed into a job that this file then
  // made its Task 7 assertions about, on a file GitHub refuses outright.
  for (const badId of ['9.bad', '9bad', 'bad.id', '-lead']) {
    assert.throws(
      () => parseWorkflowText(MINIMAL_WORKFLOW.replace('  only:\n', `  ${badId}:\n`)),
      /not a job id/,
      `'${badId}' is not a job id GitHub would run`,
    );
  }
  // …and the rule is NOT "reject anything unusual": an id exercising every
  // character class GitHub allows still parses, or this check would be
  // rejecting valid workflows rather than invalid ones.
  assert.doesNotThrow(() => parseWorkflowText(MINIMAL_WORKFLOW.replace('  only:\n', '  _ok-9:\n')));
  // STEP IDS obey the same rule and must additionally be unique within the job:
  // `steps.<id>.` is how every later expression names a step, so two steps
  // answering to one id resolve to whichever GitHub picked — which is why it
  // refuses the file instead.
  assert.ok(real.includes('        id: first\n') && real.includes('        id: second\n'),
    'the step-id mutation targets exist as written');
  assert.throws(
    () => parseWorkflowText(real.replace('        id: second\n', '        id: first\n')),
    /duplicate step id/,
  );
  assert.throws(
    () => parseWorkflowText(real.replace('        id: first\n', '        id: 1st\n')),
    /not a step id/,
  );
  // …AND UNIQUENESS IS CASE-INSENSITIVE, because GitHub's is (Codex T7 r4 #3).
  // The runner builds its step references through an ORDINAL CASE-INSENSITIVE
  // set, so `first` and `FIRST` in one job collide there while a plain `Set`
  // waves them through here — a file that passes locally and fails on the
  // runner, which is the worst direction for this check to be wrong in.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace(
      '      - name: Do something\n        run: echo hello\n',
      '      - name: Do something\n        id: first\n        run: echo hello\n'
        + '      - name: Do something else\n        id: FIRST\n        run: echo hi\n',
    )),
    /duplicate step id/,
    "`first` and `FIRST` are one id to the runner's reference builder",
  );
  // …and the fold is CASE, nothing more. `a_b`, `ab` and `a-b` are three
  // distinct step ids to GitHub; a fold that also flattened `-` and `_` would
  // reject a legal file, which is the same over-strictness as the `run: ""`
  // rejection this round removes.
  assert.doesNotThrow(() => parseWorkflowText(MINIMAL_WORKFLOW.replace(
    '      - name: Do something\n        run: echo hello\n',
    '      - name: Do something\n        id: a_b\n        run: echo hello\n'
      + '      - name: Two\n        id: ab\n        run: echo hi\n'
      + '      - name: Three\n        id: a-b\n        run: echo ho\n',
  )));
  // Unique per JOB, not per workflow: `steps.setup` only ever resolves inside
  // its own job, so two jobs may each name a step `setup`. Without this the
  // uniqueness check could be hoisted a scope too far and reject a legal file
  // with nothing here to notice.
  assert.doesNotThrow(() => parseWorkflowText(MINIMAL_WORKFLOW.replace(
    '      - name: Do something\n        run: echo hello\n',
    '      - name: Do something\n        id: setup\n        run: echo hello\n'
      + '  other:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Do something else\n        id: setup\n        run: echo hi\n',
  )));
  // …and the CASE-FOLDED set must not be hoisted a scope too far either: the
  // pair above cannot catch that, since a workflow-wide PLAIN set collides on
  // it while a workflow-wide FOLDED set is only visible against ids that
  // differ by case alone.
  assert.doesNotThrow(() => parseWorkflowText(MINIMAL_WORKFLOW.replace(
    '      - name: Do something\n        run: echo hello\n',
    '      - name: Do something\n        id: setup\n        run: echo hello\n'
      + '  other:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Do something else\n        id: SETUP\n        run: echo hi\n',
  )));
  // Prototype keys are not workflow keys, and `map.__proto__ = value` would not
  // even become an own property — so neither the duplicate check nor any later
  // assertion could see it.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        run: echo hello\n        __proto__: x\n')),
    /__proto__/,
  );
  // STEP SHAPE. GitHub runs a step through exactly one of `uses` or `run`;
  // both is an error and neither is a no-op the reader used to accept.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        uses: actions/checkout@v4\n        run: echo hello\n')),
    /exactly one of/,
  );
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '')),
    /exactly one of/,
  );
  // PRESENCE IS NOT A COMMAND (Codex T7 r3). An empty `run:` parses to null,
  // and a XOR asking only whether the PROPERTY was there counted that as a step
  // with a command, so a step carrying nothing to run was admitted. What GitHub
  // executes is the STRING, so the string is what has to be there.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        run:\n')),
    /'run' has no value/,
  );
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        run:\n          echo: hello\n')),
    /'run' must be a string/,
  );
  // …BUT `run: ""` IS LEGAL AND MUST BE ACCEPTED (Codex T7 r4 #4). Round 3
  // extended the non-empty rule from `uses` to `run` and thereby asserted MORE
  // than GitHub does: GitHub's schema gives `uses` a minimum length and gives
  // `run` only the type `string`, so an empty command is a pointless step, not
  // an invalid one. The round-3 mutations missed it because every one of them
  // was aimed at THIS repository's workflows rather than at a legal document;
  // this is the positive control that would have caught it.
  assert.doesNotThrow(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        run: ""\n')),
  );
  // `uses`, by contrast, IS required to be non-empty, and its empty form named
  // no action while satisfying the very same XOR.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        uses:\n')),
    /'uses' has no value/,
  );
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        uses: ""\n')),
    /'uses' must be a non-empty string/,
  );
  // A TABLE-VALUED KEY HOLDING A SCALAR is `run-on:` one level down: a step
  // whose `env` is a scalar gets no variables and a `with:` with nothing under
  // it gives the action no inputs. Both parsed clean.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        run: echo hello\n        env: nope\n')),
    /'env' must be a mapping/,
  );
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        uses: a/b@v1\n        with: nope\n')),
    /'with' must be a mapping/,
  );
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        uses: a/b@v1\n        with:\n')),
    /'with' has no value/,
  );
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('    steps:\n', '    step:\n')),
    /step/,
    'a mistyped `steps` leaves the job with nothing to run',
  );
  // THE ALLOWLIST AT STEP LEVEL, which nothing exercised: the pins above cover
  // the workflow and job levels, so the step-level call could have been passed
  // a superset — or dropped — with everything here still green.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        run: echo hello\n        runs-on: x\n')),
    /'runs-on' is not a key GitHub reads here/,
    'a job key written at step level is a key the runner never reads',
  );
  // THE COLLECTION SHAPES, likewise enforced but unpinned. Each is a scalar
  // where GitHub requires a collection, and each was decided by a line no case
  // below would have missed if it were deleted.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace(/jobs:\n[\s\S]*$/, 'jobs: nope\n')),
    /jobs must be a mapping/,
  );
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace(
      '  only:\n    runs-on: ubuntu-latest\n    steps:\n      - name: Do something\n        run: echo hello\n',
      '  only: nope\n',
    )),
    /job only: not a mapping/,
  );
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace(
      '    steps:\n      - name: Do something\n        run: echo hello\n',
      '    steps: nope\n',
    )),
    /steps must be a non-empty sequence/,
  );
  // A `with:` on a `run:` step is silently ignored by the runner — the same
  // class of defect as the typo'd key, one level down.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('        run: echo hello\n', '        run: echo hello\n        with:\n          k: v\n')),
    /with/,
  );
  // Top level: a workflow with no trigger never runs, and one with no jobs
  // does nothing. Both parsed fine before.
  assert.throws(() => parseWorkflowText(MINIMAL_WORKFLOW.replace('on:\n  workflow_dispatch:\n', '')), /on/);
  // A REQUIRED KEY PRESENT BUT EMPTY — the third hole of the same class as the
  // two Codex named, found here rather than reported. `on:` with its events
  // deleted still satisfied a required-key check written as `Object.hasOwn`, so
  // a workflow that can never trigger parsed clean: the empty `run:` defect, at
  // the top level. Null is meaningful INSIDE an `on:` block — `pull_request:`
  // alone is a real trigger, which is why the reader stores it as null — but it
  // is never meaningful AS the block.
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace('on:\n  workflow_dispatch:\n', 'on:\n')),
    /'on' has no value/,
  );
  // The scalar trigger form is legal GitHub and stays accepted.
  assert.doesNotThrow(() => parseWorkflowText(MINIMAL_WORKFLOW.replace('on:\n  workflow_dispatch:\n', 'on: push\n')));
  assert.throws(
    () => parseWorkflowText(MINIMAL_WORKFLOW.replace(/jobs:\n[\s\S]*$/, 'jobs:\n  only:\n    runs-on: ubuntu-latest\n    steps:\n      - name: n\n        run: r\n').replace('jobs:', 'job:')),
    /job/,
  );
});

test('demo/repro.js reads exactly the injected session contract and nothing the run step strips', () => {
  const source = readFileSync(REPRO_PATH, 'utf8');
  // Every environment variable this file names, in source order. The wrapped
  // command's contract is four names (three always, DEBUG_HYPOTHESIS_ID when a
  // hypothesis-id was configured) plus the demo's own redaction fixture — and
  // the run step DELETES the runner's command-file variables from the child
  // env (adaptation note 3), so a demo that reached for GITHUB_OUTPUT or
  // GITHUB_ENV would work in no CI at all.
  const named = [...source.matchAll(/process\.env\.([A-Za-z_][A-Za-z0-9_]*)/g)].map((match) => match[1]);
  assert.deepEqual([...new Set(named)].sort(), [
    'DEBUG_HYPOTHESIS_ID',
    'DEBUG_LOG_URL',
    'DEBUG_SESSION_ID',
    'DEBUG_SESSION_TOKEN',
    'DEMO_FAKE_SECRET',
  ]);
  // The computed forms are the way PAST the scan above, so they are pinned
  // rather than banned: the demo checks that the stripped variables are
  // ABSENT, which needs a dynamic read and consumes no value through one. A
  // computed read that fed a value into an event would be a dependency the
  // enumeration could not see.
  const computed = [...source.matchAll(/process\.env\[[^\]]*\][^\n]*/g)].map((match) => match[0]);
  assert.equal(computed.length, 1, 'exactly one computed read');
  assert.match(computed[0], /^process\.env\[name\] !== undefined\)/, 'a presence test, not a value');
  const enumerated = [...source.matchAll(/Object\.keys\(process\.env\)[^\n]*/g)].map((match) => match[0]);
  assert.equal(enumerated.length, 1, 'exactly one enumeration of the environment');
  assert.match(enumerated[0], /startsWith\('DEBUG_ACTION_'\)/, 'and it looks for what must not be there');
});

test('demo/repro.js refuses to run without its redaction fixture instead of logging "undefined"', () => {
  // The redaction proof is the demo's whole point, and its failure mode is
  // SILENT: with DEMO_FAKE_SECRET unset the third event reads
  // "token=undefined", the artifact contains no [REDACTED] marker, and a human
  // skimming a green job learns nothing. The exit code below is what turns
  // that into a red demo job.
  const { spawnSync: spawnSyncChild } = require('node:child_process');
  const result = spawnSyncChild(process.execPath, [REPRO_PATH], {
    env: { ...process.env, DEMO_FAKE_SECRET: '' },
    encoding: 'utf8',
  });
  assert.equal(result.status, 99, 'the infrastructure code, reached before any event is posted');
  assert.match(result.stderr, /DEMO_FAKE_SECRET/);
});

test('demo repro drives the full lifecycle: seeded exit 1, redacted secret, deterministic report content', async () => {
  // Assembled from parts so this file never contains a contiguous
  // secret-shaped literal, and so the value is visibly a fixture.
  const secret = ['demo-fake-', 'secret-value-', '0123456789'].join('');
  const context = await startReal({
    hypothesisId: 'DEMO-H1',
    hypothesisTitle: 'seeded demo failure',
    redactNames: 'DEMO_FAKE_SECRET',
    // The regime the dogfood workflow actually runs under: a hosted runner
    // ships sudo, so strict REFUSES there and the workflow opts in. The
    // caveat assertions below are the two facts that hold whatever the host
    // readings say.
    evidenceTrust: 'best-effort',
    __env: { DEMO_FAKE_SECRET: secret },
  });
  const stdout = [];
  try {
    const githubOutput = path.join(context.outputDir, 'github_output');
    const stepSummary = path.join(context.outputDir, 'step_summary');
    for (const file of [githubOutput, stepSummary]) writeFileSync(file, '');
    const runCode = await runSubcommand({
      inputs: { ...context.inputs, runCommand: REPRO_COMMAND },
      outputDir: context.outputDir,
      env: {
        ...context.runEnv,
        DEMO_FAKE_SECRET: secret,
        GITHUB_OUTPUT: githubOutput,
        // THE RUNNER CONTROL PLANE, present in RUN's own environment and
        // stripped from the child's (adaptation note 3). Passing them here is
        // the point: the demo must produce the same evidence with them present
        // as without, or it is depending on something CI takes away.
        GITHUB_ENV: path.join(context.outputDir, 'github_env'),
        GITHUB_PATH: path.join(context.outputDir, 'github_path'),
        GITHUB_STATE: path.join(context.outputDir, 'github_state'),
        GITHUB_STEP_SUMMARY: stepSummary,
      },
      writeStdout: (text) => stdout.push(text),
    });
    assert.equal(runCode, 0, 'authenticated capture and a rendered report');
    const state = readState(context.outputDir);
    assert.equal(state.commandExitCode, 1, 'the seeded failure, not the 98/99 demo-infrastructure codes');
    assert.equal(state.evidenceAuthentic, true);
    const reportCode = reportSubcommand({
      outputDir: context.outputDir,
      env: invocationEnv(context.outputDir, { GITHUB_STEP_SUMMARY: stepSummary }),
    });
    assert.equal(reportCode, 0);
    const evidenceDir = evidenceDirOf(context.outputDir);
    const sessionLog = readFileSync(path.join(evidenceDir, 'session.log'), 'utf8');
    assert.ok(sessionLog.includes('[REDACTED]'), 'redaction marker present');
    assert.ok(sessionLog.includes('DEMO render: userId=null on first render'), 'the seeded bug is in the evidence');
    // ALL THREE staged payloads, plus the Step Summary the human reads: the
    // demo's claim is about what leaves the runner, not about one file of it.
    for (const name of ['session.log', 'report.md', 'report.json']) {
      assert.equal(readFileSync(path.join(evidenceDir, name), 'utf8').includes(secret), false,
        `${name} carries no copy of the fixture value`);
    }
    const summary = readFileSync(stepSummary, 'utf8');
    assert.equal(summary.includes(secret), false, 'the Step Summary carries no copy either');
    assert.ok(summary.includes('DEMO-H1'), 'the report reached the Step Summary');
    const reportJson = JSON.parse(readFileSync(path.join(evidenceDir, 'report.json'), 'utf8'));
    assert.equal(reportJson.hypotheses.length, 1);
    assert.equal(reportJson.hypotheses[0].id, 'DEMO-H1');
    assert.equal(reportJson.hypotheses[0].status, 'OPEN');
    assert.equal(reportJson.hypotheses[0].events, 3);
    assert.equal(reportJson.untaggedEvents, 1);
    assert.equal(reportJson.session.events, 4, 'the count the workflow asserts on the live runner');
    // The regime travels WITH the evidence, and says what it is worth. Both
    // strings are branch-independent: `admission=DIAGNOSTIC ONLY` is what
    // best-effort produces on a clean host and on a hosted one alike.
    const caveats = reportJson.caveats.join(' ');
    assert.ok(caveats.includes('evidence-trust=best-effort'), 'the artifact states the regime');
    assert.ok(caveats.includes('admission=DIAGNOSTIC ONLY'), 'and what that regime is worth');
    assert.ok(caveats.includes(`invocation=${context.invocationNonce}`), 'and which invocation it belongs to');
    // The qualification is printed BESIDE the digest in run's own step log —
    // the copy a reader compares against start's pre-command record.
    const printed = stdout.join('');
    assert.ok(printed.includes('evidence-qualification ADMISSION RECORD'), 'run repeats the record beside its digest');
    // Recomputed from the STAGED BYTES, so the demo's artifact and the line a
    // reader compares it against are checked as one chain rather than by
    // shape. The action hashes in memory before writing; equality here says
    // the two agree for this session.
    const digestLine = `evidence-sha256 ${['session.log', 'report.md', 'report.json']
      .map((name) => `${name}=${createHash('sha256').update(readFileSync(path.join(evidenceDir, name))).digest('hex')}`)
      .join(' ')}`;
    assert.ok(printed.includes(`${digestLine}\n`), 'the printed digest describes the bytes this run staged');
    const outputs = readFileSync(githubOutput, 'utf8');
    assert.match(outputs, /command-exit-code=1/);
    assert.match(outputs, /event-count=4/);
    assert.ok(outputs.includes(`evidence-digest=${digestLine}`), 'the convenience output is byte-identical to the log line');
    assert.equal(finishSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) }), 1,
      'the default mirrors the seeded failure');
    writeState(context.outputDir, { ...readState(context.outputDir), failOnCommandFailure: 'false' });
    assert.equal(finishSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) }), 0,
      'the dogfood toggle waives it');
    // AND THE WORKFLOW'S OWN ASSERTION STEP, run against the bytes this real
    // lifecycle staged. The executor tests further down drive that same script
    // with CONSTRUCTED payloads to prove it rejects a partial mask and an
    // unreadable file; this is the one place that proves their honest fixture
    // is the shape the action really produces, so a session.log format change
    // cannot leave those tests passing against a model of a format that is gone.
    // Guarded rather than skipped because none of the assertions above need a
    // shell and only this one does.
    if (SHELL_AVAILABLE) {
      const accepted = runDemoAssertionsOn(path.join(evidenceDir, 'report.md'), { secret });
      assert.equal(accepted.status, 0,
        `the shipped demo assertions must accept a real capture: ${accepted.stdout}${accepted.stderr}`);
    }
  } finally {
    teardownSubcommand({ outputDir: context.outputDir, env: invocationEnv(context.outputDir) });
  }
});

test('the demo workflow is a dogfood, not a gate: read-only, pinned, and no step allowed to fail', () => {
  const workflow = parseWorkflow(DEMO_WORKFLOW);
  // The display name the gate's forwarder list has to match, byte for byte.
  assert.equal(workflow.name, 'Debug evidence demo');
  assert.deepEqual(workflow.permissions, { contents: 'read' });
  assert.deepEqual(workflow.on, { pull_request: null, workflow_dispatch: null });
  // Cancellation is safe here and NOT on the enforcing gate: a cancelled
  // advisory demo costs a demo, a cancelled gate costs a verdict.
  assert.equal(workflow.concurrency['cancel-in-progress'], 'true');
  assert.deepEqual(Object.keys(workflow.jobs), ['demo', 'strict-refusal', 'namespacing']);
  // Nothing in this workflow may reference a secret: it executes PR-controlled
  // code (the action and the repro come out of the checkout under test), and
  // the only thing keeping that ordinary is that there is nothing to steal.
  assert.equal(/secrets\./.test(workflowCode(DEMO_WORKFLOW)), false, 'no secret is referenced');
  // NO STEP HERE IS ALLOWED TO FAIL, and that is a design constraint rather
  // than an accident. `continue-on-error` is how a workflow demonstrates an
  // expected failure, and this repo's own suppression scan classifies it as
  // gate weakening in any touched workflow (CONFIG_SILENCING in
  // scripts/pr_closeout_core.js) — correctly, because nothing in the YAML says
  // whether the failure is re-asserted afterwards. The refusal paths are
  // `support.js` probes that capture and assert an exit status instead.
  // Read against the WIRING, not the prose that explains the rule — the same
  // stripper the `secrets.` check above uses, and for the same reason.
  assert.equal(/continue-on-error/.test(workflowCode(DEMO_WORKFLOW)), false,
    'expected failures are probed and asserted, never tolerated');
  // The scanner's own trigger shape is absent even from the prose: the
  // suppression scan reads raw text, so a comment spelling the construct out
  // in full would fail this repo's CI on this very file.
  assert.equal(/continue-on-error["']?\s*[:=]\s*true/i.test(workflowText(DEMO_WORKFLOW)), false,
    'not even in a comment');
  // FROM THE PARSED STRUCTURE, never from raw text (Codex T7 r1 #3). A
  // raw-text scan reads COMMENTED-OUT lines too, so commenting a checkout step
  // out left its pinned `uses:` plainly visible to this assertion while the
  // workflow the runner would actually execute had no checkout at all and
  // would fail resolving the local action. What is asserted has to be what the
  // runner would run — actionlint would also catch it, and is deliberately not
  // adopted: this repo ships "dependencies": 0 and that posture is load-bearing.
  const uses = Object.values(workflow.jobs)
    .flatMap((job) => job.steps)
    .filter((step) => step.uses !== undefined)
    .map((step) => step.uses);
  // LOCAL AND REMOTE ARE DIFFERENT CLAIMS, so they are separated rather than
  // one being `continue`d past. A path reference cannot be pinned at all —
  // that is precisely why it is called out — and the only one permitted here
  // is the action under test.
  const local = uses.filter((reference) => reference.startsWith('./'));
  const remote = uses.filter((reference) => !reference.startsWith('./'));
  assert.deepEqual([...new Set(local)], [DEMO_ACTION_REF], 'the only local reference is the action under test');
  assert.equal(local.length, 3, 'and it is invoked three times');
  for (const reference of remote) {
    assert.match(reference, /^[^@\s]+@[0-9a-f]{40}$/, `${reference} must be SHA-pinned`);
  }
  // EVERY job checks out, as its first step. This is the assertion the raw-text
  // form could not make: a job whose checkout is commented out still carried
  // the pinned string in the file, and only the parsed structure knows the
  // step is gone.
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    assert.equal(job.steps[0].uses, 'actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10',
      `${jobName}: the repo-wide checkout pin, first, as the runner would resolve it`);
  }
  // The version COMMENT is a claim about the raw text by construction, so it
  // is the one thing here still read that way.
  for (const pin of [
    'uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3',
    'uses: actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6.5.0',
  ]) {
    assert.ok(workflowText(DEMO_WORKFLOW).includes(pin), `version comment included: ${pin}`);
  }
  // ARTIFACT NAMES ARE A NAMESPACE, and upload-artifact v4 REFUSES a duplicate
  // name inside one workflow run — a collision would fail whichever job
  // uploaded second, and the two-invocation job below exists precisely to show
  // the naming working.
  const artifactNames = Object.values(workflow.jobs)
    .flatMap((job) => actionInvocations(job).map((step) => step.with['artifact-name']));
  assert.equal(artifactNames.length, 3, 'three action invocations across the workflow');
  assert.equal(artifactNames.every((name) => typeof name === 'string' && name !== ''), true, 'every invocation names its artifact');
  assert.equal(new Set(artifactNames).size, artifactNames.length, 'and no two invocations share a name');
  // PER JOB, because that is the scope that matters: each job gets its own
  // runner, so two jobs may both take the default port, while two invocations
  // in ONE job must not contend for it — teardown signals its collector and
  // returns without waiting for it to exit, so a shared port is a race the
  // second start would lose (port_in_use, and a red demo).
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    const ports = actionInvocations(job).map((step) => step.with.port ?? parseActionYml().inputs.port.default);
    assert.equal(new Set(ports).size, ports.length, `${jobName}: no two invocations bind the same port`);
  }
});

test('every demo-workflow invocation passes the action\'s own input validator', () => {
  const declared = parseActionYml().inputs;
  const workflow = parseWorkflow(DEMO_WORKFLOW);
  // The `with:` key -> validateActionInputs field map. Anything absent from a
  // `with:` block is filled from action.yml's OWN default, so this test also
  // pins that the workflow depends only on defaults the action really declares.
  const fields = {
    run: 'runCommand',
    'session-name': 'sessionName',
    'working-directory': 'workingDirectory',
    'fail-on-command-failure': 'failOnCommandFailure',
    port: 'port',
    'redact-names': 'redactNames',
    'max-events': 'maxEvents',
    'max-bytes': 'maxBytes',
    'hypothesis-id': 'hypothesisId',
    'hypothesis-title': 'hypothesisTitle',
    'evidence-trust': 'evidenceTrust',
  };
  const inputsOf = (step) => {
    const resolved = {};
    for (const [key, field] of Object.entries(fields)) {
      resolved[field] = Object.hasOwn(step.with, key) ? step.with[key] : declared[key].default;
    }
    // The runner resolves the expression; validateActionInputs only ever sees
    // a path, so the literal text stands in for one. `output-dir: ""` means
    // the action's runner.temp default, which is outside the workspace by
    // construction — the empty `workspace` below says "not asserting
    // containment here", which is action.yml's own job.
    return { ...resolved, outputDir: step.with['output-dir'] ?? '', workspace: '' };
  };
  let invocations = 0;
  for (const [jobName, job] of Object.entries(workflow.jobs)) {
    for (const step of actionInvocations(job)) {
      invocations += 1;
      // A `with:` key the action never declared is silently IGNORED by the
      // runner — a typo'd `artifact_name` would leave the artifact under the
      // default name and no error anywhere.
      for (const key of Object.keys(step.with)) {
        assert.ok(Object.hasOwn(declared, key), `${jobName}/${step.name}: '${key}' is not an input of this action`);
      }
      assert.deepEqual(validateActionInputs(inputsOf(step)), [],
        `${jobName}/${step.name}: the action would reject these inputs`);
    }
  }
  assert.equal(invocations, 3);
});

test('the demo job wraps the seeded repro under best-effort and waives its exit code', () => {
  const job = parseWorkflow(DEMO_WORKFLOW).jobs.demo;
  assert.equal(actionInvocations(job).length, 1);
  const [invocation] = actionInvocations(job);
  // The command, resolved against this checkout: the workflow wraps the same
  // file the lifecycle test above runs, not a second demo that drifted.
  assert.match(invocation.with.run, /^node \S+$/);
  assert.equal(path.resolve(REPO_ROOT, invocation.with.run.slice('node '.length)), REPRO_PATH);
  // ADAPTATION NOTE 1: strict REFUSES on a hosted runner (it ships sudo), and
  // the sysctl-hardening route is withdrawn — mode 3 does not survive
  // passwordless sudo, so hardening that way would advertise a guarantee the
  // host does not provide.
  assert.equal(invocation.with['evidence-trust'], 'best-effort');
  // ADAPTATION NOTE 4: the seeded exit 1 leaves the job green ONLY through
  // this toggle. Its default is 'true' (pinned in the action.yml test above),
  // so a dropped line here turns the dogfood red for the wrong reason.
  assert.equal(invocation.with['fail-on-command-failure'], 'false');
  assert.equal(invocation.with['redact-names'], 'DEMO_FAKE_SECRET');
  assert.equal(invocation.with['hypothesis-id'], 'DEMO-H1');
  // The fixture value the redaction proof depends on has to be in the env of
  // the step that starts the collector, because the collector's redaction
  // snapshot is that environment.
  const workflow = parseWorkflow(DEMO_WORKFLOW);
  assert.equal(typeof workflow.env.DEMO_FAKE_SECRET, 'string');
  assert.ok(workflow.env.DEMO_FAKE_SECRET.length >= 8, 'long enough to be a needle, fixed so the demo is deterministic');
  // The live assertions, which are what makes this a check rather than a
  // demonstration: the action's own outputs, compared to the seeded values.
  const assertion = job.steps[job.steps.length - 1];
  assert.equal(assertion.env.EXIT_CODE, '${{ steps.demo.outputs.command-exit-code }}');
  assert.equal(assertion.env.EVENT_COUNT, '${{ steps.demo.outputs.event-count }}');
  assert.ok(assertion.run.includes('test "$EXIT_CODE" = "1"'), 'the seeded failure is asserted, not just reported');
  assert.ok(assertion.run.includes('test "$EVENT_COUNT" = "4"'), 'four events, exactly as the lifecycle test counts them');
  // AND THE ADVERTISED CLAIM ITSELF (Codex T7 r1 #1). Every check above is
  // satisfied by a collector that wrote the fixture value verbatim into all
  // three payloads: the exit code, the event count, a session id and a digest
  // are all produced either way, so the job stayed green while this file's
  // header promised that "the artifact's session.log must then read [REDACTED]
  // where repro.js logged it". The unit test above checks redaction; the LIVE
  // job — the only surface that runs on a real runner — did not, and a demo
  // that certifies a claim it never checked is worse than no demo.
  assert.equal(assertion.env.REPORT_PATH, '${{ steps.demo.outputs.report-path }}');
  // The needle arrives by ENV INHERITANCE from the workflow-level `env:`, and
  // is deliberately NOT re-bound here: this file's standing rule is that no
  // `${{ }}` expression is substituted into a script body, and the cheapest
  // way to keep the rule auditable is for the body to contain none at all.
  assert.equal(Object.hasOwn(assertion.env, 'DEMO_FAKE_SECRET'), false, 'inherited, never re-bound');
  assert.doesNotMatch(assertion.run, /\$\{\{/, 'no expression is interpolated into the script body');
  for (const line of [
    // A needle that went missing would make grep -F match every line, so this
    // is a diagnostic rather than a load-bearing guard — but the polarity is
    // still stated instead of assumed.
    'test -n "$DEMO_FAKE_SECRET"',
    'test -f "$REPORT_PATH"',
    'evidence_dir=$(dirname "$REPORT_PATH")',
    // PRESENCE, ON THE WHOLE FIELD (Codex T7 r2 #1). The superseded form asked
    // only that `[REDACTED]` occur SOMEWHERE in session.log, which
    // `token=[REDACTED]secret-value-0123456789` satisfies while leaking most of
    // the fixture — and the absence sweep below could not see it either,
    // because the COMPLETE value never appears. The log is parsed and the msg
    // field compared for equality instead, with the token-bearing events
    // counted so a correct event cannot cover for a leaking neighbour.
    'const expected = "DEMO config dump: token=[REDACTED]";',
    'const mentions = events.filter((event) => typeof event.msg === "string" && event.msg.includes("token="));',
    'const exact = mentions.filter((event) => event.msg === expected);',
    'if (mentions.length !== 1 || exact.length !== 1) {',
    // ABSENCE is the success case, so it is written out rather than left to a
    // bare `!`: each payload is proven to EXIST first, and the sweep's status is
    // CAPTURED rather than consumed as an `if` condition — as a condition,
    // grep's 1 (absent) and its 2 (unreadable) take the same branch and `set -e`
    // does not rescue it, so the step reported success on a file it never read.
    'test -f "$evidence_dir/$payload"',
    'status=0',
    'grep -qF -- "$DEMO_FAKE_SECRET" "$evidence_dir/$payload" || status=$?',
    'if test "$status" = "0"; then',
    'echo "FAIL: the fixture value reached $payload unredacted" >&2',
    'if test "$status" != "1"; then',
    'exit 1',
  ]) {
    assert.ok(assertion.run.includes(line), `the demo assertion must check: ${line}`);
  }
  // THE SUPERSEDED FORMS ARE GONE, both of them: a bare presence grep would
  // still read as the proof to a reviewer skimming the file, and the `if grep`
  // condition is the fail-open itself.
  for (const superseded of [
    'grep -qF "[REDACTED]" "$evidence_dir/session.log"',
    'if grep -qF "$DEMO_FAKE_SECRET" "$evidence_dir/$payload"; then',
  ]) {
    assert.equal(assertion.run.includes(superseded), false, `superseded: ${superseded}`);
  }
  // The parser reaches the fixture and the staged log through env, exactly as
  // the rest of the step does — no expression, and no value spliced into the
  // script text.
  assert.match(assertion.run, /^SESSION_LOG="\$evidence_dir\/session\.log" node -e '$/m);
  // BOTH loops cover all three staged payloads. session.log alone would leave
  // report.md and report.json free to carry the value the artifact ships.
  assert.equal((assertion.run.match(/^for payload in session\.log report\.md report\.json; do$/gm) ?? []).length, 2,
    'existence and absence are each checked over all three staged payloads');
});

// The two refusal probes, read as what they are: `support.js start` invoked
// with the same DEBUG_ACTION_* environment action.yml's own Start collector
// step sets. Each is checked against the action's REAL env->inputs mapping
// (actionInputsFromEnv) and its REAL validator, so "this probe reaches the
// admission refusal" and "this probe is rejected at input validation" are
// facts about the shipped code rather than about this test's expectations.
const probeStep = (job, name) => {
  const step = job.steps.find((candidate) => candidate.name === name);
  assert.ok(step, `no step named ${name}`);
  return step;
};

test('the strict-refusal probe reaches the admission refusal, not an input error', () => {
  const job = parseWorkflow(DEMO_WORKFLOW).jobs['strict-refusal'];
  assert.equal(actionInvocations(job).length, 0, 'a probe job, deliberately not an action invocation');
  // The probe must run the runtime the ACTION would have chosen; a drifting
  // node-version would make this a probe of something else.
  const setup = job.steps.find((step) => String(step.uses).startsWith('actions/setup-node@'));
  assert.ok(setup, 'the probe job sets up node itself — no action invocation does it here');
  assert.equal(setup.with['node-version'], parseActionYml().inputs['node-version'].default);
  const probe = probeStep(job, 'Probe the start subcommand at the default evidence-trust');
  const inputs = actionInputsFromEnv(probe.env);
  // THE DEFAULT BY ABSENCE. An explicitly empty DEBUG_ACTION_EVIDENCE_TRUST is
  // a value the contract does not recognise and would fail validation instead
  // — a distinction support.js pins deliberately, and one this probe would
  // silently lose if the variable were spelled out as ''.
  assert.equal(Object.hasOwn(probe.env, 'DEBUG_ACTION_EVIDENCE_TRUST'), false);
  assert.equal(inputs.evidenceTrust, 'strict');
  assert.deepEqual(
    validateActionInputs({ ...inputs, outputDir: probe.env.DEBUG_ACTION_OUTPUT_DIR, workspace: '' }),
    [],
    'the inputs are valid, so exit 3 can only be the admission refusal',
  );
  // Redirected so the probe's emissions never become this step's real outputs.
  assert.match(probe.env.GITHUB_OUTPUT, /^\$\{\{ runner\.temp \}\}\//);
  for (const line of [
    'test "$status" = "3"',
    // Identity FIRST, before validation and before any filesystem work — and
    // the nonce is read back through the SAME anchored vocabulary that counts
    // it, so what is spliced into the record pattern below can only ever be
    // one bounded [A-Za-z0-9_-] segment.
    'test "$(grep -cE \'^invocation-nonce=[A-Za-z0-9_-]+$\' "$GITHUB_OUTPUT")" = "1"',
    'nonce=$(grep -oE \'^invocation-nonce=[A-Za-z0-9_-]+$\' "$GITHUB_OUTPUT" | cut -d= -f2-)',
    // EXACTLY ONE admission record (Codex T7 r1 ruling). Five separate greps
    // established five facts and nothing about whether they belonged to the
    // SAME record; a second record in this log would mean the run emitted two,
    // and a reader comparing copies could not tell which one to compare.
    'test "$(grep -c \'ADMISSION RECORD\' "$log")" = "1"',
    // …and exactly one of them is the anchored record this invocation is
    // entitled to: counting the headline SUBSTRING and matching the anchored
    // line were two different facts, and only the second one is a claim.
    'test "$(grep -cE "$record_pattern" "$log")" = "1"',
    // EXACTLY ONE FINDINGS LINE, AND IT IS THE ONE THAT FOLLOWS THAT HEADLINE
    // (Codex T7 r2 #2). The old probe counted headlines with one grep and then
    // searched EVERY findings line with another, so a log whose own record said
    // `sudo binary: absent` still passed on an unrelated second findings line
    // carrying the sudo-present reading — establishing the exact opposite of
    // this job's unique live claim. The two lines are read as one block:
    // position, not coincidence, is what binds the finding to the record.
    'test "$(grep -c \'^debug-evidence-action: start: Findings: \' "$log")" = "1"',
    'record_line=$(grep -nE "$record_pattern" "$log" | cut -d: -f1)',
    'findings_line=$(sed -n "$((record_line + 1))p" "$log")',
    // bash's own ERE, deliberately not a `printf | grep -q` pipeline: with
    // `pipefail` set, grep -q closing the pipe early can leave the WRITER dying
    // of SIGPIPE and the whole pipeline reading as a failure on the good path.
    '[[ $findings_line =~ $findings_pattern ]]',
    // …and nothing created: the refusal precedes the staging directory and
    // the state file, so neither exists.
    'test ! -e "$evidence_dir"',
    'test ! -e "$RUNNER_TEMP/strict-probe/action-state.json"',
    'test ! -e "$RUNNER_TEMP/strict-probe"',
  ]) {
    assert.ok(probe.run.includes(line), `the strict probe must check: ${line}`);
  }
  // THE SCATTERED SUBSTRINGS ARE GONE. Each one could match any line of the
  // log, so together they proved four facts and no coherence between them.
  for (const scattered of [
    'grep -q "ADMISSION RECORD" "$log"',
    'grep -q "evidence-trust=strict" "$log"',
    'grep -q "in-process boundary=NOT established" "$log"',
    'grep -q "sudo binary: present" "$log"',
  ]) {
    assert.equal(probe.run.includes(scattered), false, `superseded by an anchored match: ${scattered}`);
  }
  // AND THE FINDINGS PATTERN IS NEVER HANDED TO A WHOLE-FILE SEARCH AGAIN. That
  // was the round-2 defect exactly: an anchored, well-formed pattern, applied
  // to every line in the log instead of to the one line that belongs to the
  // record this probe matched.
  assert.doesNotMatch(probe.run, /grep -q[A-Za-z]* '\^debug-evidence-action: start: Findings:[^']*' "\$log"/,
    'the sudo finding is read out of its record, never searched for across the log');
  // THE PATTERNS ARE CHECKED AGAINST THE SHIPPED BUILDER, not against this
  // test's memory of it. admissionCaveats is the single source of the record's
  // text, so a pattern that had drifted from it would match nothing on the
  // runner — a red job for a reason nobody could act on. The host readings are
  // the ones a GitHub-hosted runner actually produces: sudo present, and a
  // ptrace mode that is not 3.
  const sampleNonce = 'abcdef01-2345-6789-abcd-ef0123456789';
  const hosted = {
    ptrace: 'privilege-bypassable',
    uid: 'non-root',
    sudo: `present: 1 at sha256=${'a'.repeat(64)}`,
    capabilities: 'clear',
  };
  const emitted = (admission, trust, index) => `debug-evidence-action: start: ${admissionCaveats(admission, trust, sampleNonce)[index]}`;
  // Both patterns are read out of the SHELL VARIABLES the probe now assigns
  // them to, which is also what lets one pattern serve the count, the position
  // lookup and the block match without being written three times.
  const recordSource = /^record_pattern="(\^debug-evidence-action: start: ADMISSION RECORD[^"]*)"$/m.exec(probe.run);
  assert.ok(recordSource, 'the probe matches ONE anchored admission-record line');
  const recordPattern = new RegExp(recordSource[1].replace('$nonce', sampleNonce));
  assert.match(emitted(hosted, 'strict', 0), recordPattern, 'the anchored pattern matches what start emits');
  // POLARITY, because an anchored pattern that matched anything would be the
  // same defect in a longer form: the regime and the boundary verdict are part
  // of the claim, so a record carrying different ones must NOT satisfy it.
  assert.doesNotMatch(emitted(hosted, 'best-effort', 0), recordPattern, 'a best-effort record is a different claim');
  assert.doesNotMatch(emitted({ ...hosted, ptrace: 'unconditional', sudo: 'absent' }, 'strict', 0), recordPattern,
    'a record whose boundary IS established is a different claim');
  // The live half no stubbed unit test can establish — a hosted runner ships
  // sudo — anchored to the FINDINGS line of the same record rather than
  // floating free anywhere in the log.
  const findingsSource = /^findings_pattern='(\^debug-evidence-action: start: Findings:[^']*)'$/m.exec(probe.run);
  assert.ok(findingsSource, 'the probe matches ONE anchored findings line');
  const findingsPattern = new RegExp(findingsSource[1]);
  assert.match(emitted(hosted, 'strict', 1), findingsPattern, 'sudo present, in the findings of this record');
  assert.doesNotMatch(emitted({ ...hosted, sudo: 'absent' }, 'strict', 1), findingsPattern,
    'a runner without sudo does not satisfy it — that is the point of the job');
  // ORDERING IS NOT A PROBE CLAIM (Codex T7 r1 ruling). Reading the output
  // afterwards can establish CONTENT and never SEQUENCE: that the nonce was
  // published before admission was decided is a fact about the source, pinned
  // by the unit test named below, and the workflow must say so rather than
  // implying its greps established it.
  const jobCommentary = workflowText(DEMO_WORKFLOW).split(/\r?\n/)
    .filter((line) => line.trim().startsWith('#'))
    .map((line) => line.trim().replace(/^#\s?/, ''))
    .join(' ');
  assert.match(jobCommentary, /cannot establish ORDER/);
  assert.match(jobCommentary, /remains a source claim, pinned by the unit test/);
});

// --- The shipped shell, RUN, against inputs constructed to be broken --------
//
// Every assertion above reads the workflow as TEXT, which can establish that a
// check is written and never that it holds. Both round-2 Importants were
// checks that WERE written: they simply had the wrong subject, and stayed green
// on a log and on a set of staged bytes that were genuinely broken. The only
// thing that settles that is executing the shipped script against the broken
// input and watching it refuse.
const { spawnSync: spawnShell } = require('node:child_process');
// MSYS/Git Bash reads C:/x happily and C:\x not at all, and the assertions
// below interpolate these paths into shell words.
const bashPath = (value) => value.replace(/\\/g, '/');
const SHELL_TOOLS = 'command -v grep >/dev/null && command -v sed >/dev/null && command -v cut >/dev/null && command -v node >/dev/null';
const SHELL_AVAILABLE = (() => {
  try {
    return spawnShell('bash', ['-c', SHELL_TOOLS], { encoding: 'utf8' }).status === 0;
  } catch {
    return false;
  }
})();
const NO_SHELL = 'no bash with grep/sed/cut/node here; the shipped scripts cannot be executed';

const STRICT_NONCE = 'abcdef01-2345-6789-abcd-ef0123456789';
// What a GitHub-hosted runner actually reports: sudo present, and a ptrace mode
// that is not 3. The same readings the pattern assertions above use.
const HOSTED_ADMISSION = {
  ptrace: 'privilege-bypassable',
  uid: 'non-root',
  sudo: `present: 1 at sha256=${'a'.repeat(64)}`,
  capabilities: 'clear',
};
const startLine = (text) => `debug-evidence-action: start: ${text}`;
const REFUSAL_LINE = startLine('refusing to run the wrapped command: this host does not establish the'
  + ' in-process boundary this action\'s evidence depends on (same-UID ptrace policy: privilege-bypassable).');

// Everything ABOVE `test "$status" = "3"` is the invocation itself — a
// `support.js start` that only a Linux host shipping sudo can drive to the
// refusal — so the harness supplies that invocation's three results (its exit
// status, its captured log, its redirected output file) and then runs the
// SHIPPED BYTES from that line down. None of the assertions are reproduced
// here; only their inputs are constructed.
const STRICT_PROBE_SPLIT = 'test "$status" = "3"';
const runStrictProbeAssertions = (logLines) => {
  const script = probeStep(parseWorkflow(DEMO_WORKFLOW).jobs['strict-refusal'],
    'Probe the start subcommand at the default evidence-trust').run;
  const at = script.indexOf(STRICT_PROBE_SPLIT);
  assert.ok(at > 0, 'the probe still separates its invocation from its assertions');
  const dir = makeTempDir();
  const logFile = path.join(dir, 'strict-probe.log');
  const outputFile = path.join(dir, 'strict-probe-output');
  const runnerTemp = path.join(dir, 'runner-temp');
  mkdirSync(runnerTemp);
  writeFileSync(logFile, `${logLines.join('\n')}\n`);
  // The identity half the probe reads back, and an evidence-dir that was never
  // created — which is what a refusal before staging leaves behind.
  writeFileSync(outputFile, `invocation-nonce=${STRICT_NONCE}\nevidence-dir=${bashPath(path.join(dir, 'never-created'))}\n`);
  return spawnShell('bash', ['-c', `set -euo pipefail\nstatus=3\nlog="${bashPath(logFile)}"\n${script.slice(at)}`], {
    encoding: 'utf8',
    env: { ...process.env, GITHUB_OUTPUT: bashPath(outputFile), RUNNER_TEMP: bashPath(runnerTemp) },
  });
};

test('the strict-refusal probe binds the sudo finding to the admission record, and rejects a log where it floats free', {
  skip: !SHELL_AVAILABLE && NO_SHELL,
}, () => {
  // THE HONEST LOG, assembled from the SHIPPED BUILDER rather than from this
  // test's memory of it: exactly what `start` streams on a hosted runner that
  // refuses under strict, plus the refusal line itself.
  const honest = [
    ...admissionCaveats(HOSTED_ADMISSION, 'strict', STRICT_NONCE).map(startLine),
    REFUSAL_LINE,
  ];
  const accepted = runStrictProbeAssertions(honest);
  assert.equal(accepted.status, 0, `the real record must satisfy the probe: ${accepted.stderr}`);
  // CODEX'S EXACT COUNTER-EXAMPLE (T7 r2 #2). One admission headline, whose own
  // findings say sudo is ABSENT, and a SECOND findings line — belonging to
  // nothing — that carries the sudo-present reading. The old probe counted
  // headlines with one grep and searched every findings line with another, so
  // all four of its greps matched and the job went green while asserting the
  // opposite of this runner's own record. This is the job's UNIQUE LIVE CLAIM;
  // a log that contradicts it must never satisfy it.
  const forged = [
    startLine(admissionCaveats(HOSTED_ADMISSION, 'strict', STRICT_NONCE)[0]),
    startLine('Findings: same-UID ptrace policy: privilege-bypassable; sudo binary: absent.'),
    startLine(`Findings: unrelated sweep; same-UID ptrace policy: privilege-bypassable; sudo binary: present: 1 at sha256=${'a'.repeat(64)}.`),
    REFUSAL_LINE,
  ];
  const rejected = runStrictProbeAssertions(forged);
  assert.notEqual(rejected.status, 0, 'a sudo finding that belongs to no admission record proves nothing');
  // AND THE NARROWER HALF, so the rejection above cannot be credited to the
  // second findings line alone: ONE headline, ONE findings line, and it is the
  // wrong one. Position is what settles this, not counting.
  const displaced = [
    startLine(admissionCaveats(HOSTED_ADMISSION, 'strict', STRICT_NONCE)[0]),
    startLine('Checked: Yama ptrace mode, effective uid, sudo binary presence, and this process\'s own permitted/effective capabilities.'),
    startLine(admissionCaveats(HOSTED_ADMISSION, 'strict', STRICT_NONCE)[1]),
    REFUSAL_LINE,
  ];
  assert.notEqual(runStrictProbeAssertions(displaced).status, 0,
    'the findings line must be the one that follows the matched headline');
  // …and the mirror image, which POSITION alone cannot see: the record and its
  // own findings line are correct and in order, and a second findings line
  // appears further down. One record's findings are the whole claim, so a log
  // carrying two of them is not the log this probe is entitled to read.
  const doubled = [
    ...admissionCaveats(HOSTED_ADMISSION, 'strict', STRICT_NONCE).map(startLine),
    REFUSAL_LINE,
    startLine('Findings: stray sweep; same-UID ptrace policy: privilege-bypassable.'),
  ];
  assert.notEqual(runStrictProbeAssertions(doubled).status, 0,
    'exactly one findings line, not merely a correct first one');
  // …and the polarity in the other direction: the honest log with its findings
  // line saying sudo is absent is the case this whole job exists to detect.
  const noSudo = [
    ...admissionCaveats({ ...HOSTED_ADMISSION, sudo: 'absent' }, 'strict', STRICT_NONCE).map(startLine),
    REFUSAL_LINE,
  ];
  assert.notEqual(runStrictProbeAssertions(noSudo).status, 0,
    'if GitHub ever shipped a runner without sudo this job goes red, which is the point of it');
});

// session.log's ON-DISK FORMAT, measured rather than assumed: one
// JSON.stringify'd event per LF-terminated line (debug_server.js's append path),
// staged byte-for-byte as the collector served it. The demo posts four events
// and opens one hypothesis, so a real capture is five lines.
const DEMO_SECRET = ['demo-fake-', 'secret-value-', '0123456789'].join('');
const REDACTED_CONFIG_MSG = 'DEMO config dump: token=[REDACTED]';
const demoSessionLog = (configMessages) => [
  { type: 'hypothesis', hypothesisId: 'DEMO-H1', status: 'OPEN', title: 'seeded demo failure' },
  { msg: 'DEMO fetch: userId=42 loaded from fixture', hypothesisId: 'DEMO-H1' },
  { msg: 'DEMO render: userId=null on first render', data: { userId: null }, hypothesisId: 'DEMO-H1' },
  ...configMessages.map((msg) => ({ msg, hypothesisId: 'DEMO-H1' })),
  { msg: 'DEMO unrelated background noise' },
].map((event, index) => `${JSON.stringify({ ts: `2026-08-13T00:00:0${index}.000Z`, ...event })}\n`).join('');

const DEMO_ASSERTION_STEP = 'Assert the action reported the seeded failure without failing the job';
// The demo job's assertion step, SHIPPED BYTES, pointed at a report.md whose
// directory holds the three staged payloads — which is exactly how the step
// finds them on the runner. The action's four outputs arrive through env, as
// they do live; only the staged bytes differ between the cases below.
const runDemoAssertionsOn = (reportPath, { preamble = '', secret = DEMO_SECRET } = {}) => {
  const script = probeStep(parseWorkflow(DEMO_WORKFLOW).jobs.demo, DEMO_ASSERTION_STEP).run;
  return spawnShell('bash', ['-c', `${preamble}${script}`], {
    encoding: 'utf8',
    env: {
      ...process.env,
      EXIT_CODE: '1',
      EVENT_COUNT: '4',
      SESSION_ID: 'demo-0f3efe83b2633f14d915568e',
      DIGEST: `evidence-sha256 session.log=${'0'.repeat(64)}`,
      REPORT_PATH: bashPath(reportPath),
      DEMO_FAKE_SECRET: secret,
    },
  });
};

const stageDemoPayloads = ({ sessionLog, reportMd = '## Debug evidence report\n', reportJson = '{"schema":1}\n' }) => {
  const evidenceDir = path.join(makeTempDir(), 'debug-evidence-files-n1');
  mkdirSync(evidenceDir);
  writeFileSync(path.join(evidenceDir, 'session.log'), sessionLog);
  writeFileSync(path.join(evidenceDir, 'report.md'), reportMd);
  writeFileSync(path.join(evidenceDir, 'report.json'), reportJson);
  return path.join(evidenceDir, 'report.md');
};

// The read error Codex REPRODUCED, injected as the exit status it produces
// rather than as a permission bit: `chmod 000` denies nothing on Windows and
// nothing to root, so a filesystem-based reproduction would silently stop
// testing anything on two of the hosts this suite runs on. A shell function
// shadows the external command for the sweep and returns 2 with no match,
// which is precisely what an unreadable payload looks like to the script.
const grepFailsOn = (payload) => [
  'grep() {',
  '  for arg in "$@"; do',
  `    case "$arg" in */${payload})`,
  `      printf 'grep: %s: Permission denied\\n' "$arg" >&2`,
  '      return 2 ;;',
  '    esac',
  '  done',
  '  command grep "$@"',
  '}',
  '',
].join('\n');

test('the demo job\'s redaction proof rejects a partial mask and a payload it could not read', {
  skip: !SHELL_AVAILABLE && NO_SHELL,
}, () => {
  const honest = stageDemoPayloads({ sessionLog: demoSessionLog([REDACTED_CONFIG_MSG]) });
  const accepted = runDemoAssertionsOn(honest);
  assert.equal(accepted.status, 0, `a correctly redacted capture must pass: ${accepted.stderr}`);
  // PARTIAL MASKING (Codex T7 r2 #1). The marker is present, the COMPLETE
  // fixture value is absent from all three payloads, and most of the secret
  // leaked anyway. A presence grep for `[REDACTED]` plus an absence grep for
  // the whole value both pass on this; only equality on the whole field does
  // not.
  const partial = stageDemoPayloads({ sessionLog: demoSessionLog([`DEMO config dump: token=[REDACTED]${DEMO_SECRET.slice('demo-fake-'.length)}`]) });
  assert.notEqual(runDemoAssertionsOn(partial).status, 0, 'a partially masked secret is a leak');
  // …and the case an "exactly one event equals the expected string" check ALONE
  // still passes: the correct event IS present, exactly once, and a second
  // event carries the partial leak beside it.
  const alongside = stageDemoPayloads({
    sessionLog: demoSessionLog([REDACTED_CONFIG_MSG, `DEMO config dump: token=[REDACTED]${DEMO_SECRET.slice('demo-fake-'.length)}`]),
  });
  assert.notEqual(runDemoAssertionsOn(alongside).status, 0,
    'one correct event does not excuse a leaking one beside it');
  // A GREP READ ERROR IS NOT AN ABSENCE. As the condition of an `if`, statuses
  // 1 (absent - the success case) and 2 (could not read the file) take the same
  // branch and `set -e` does not rescue a condition, so the sweep reported
  // success on a payload it never examined. `test -f` immediately above it
  // neither guarantees continued readability nor closes the check/use gap.
  for (const payload of ['session.log', 'report.md', 'report.json']) {
    const unreadable = runDemoAssertionsOn(honest, { preamble: grepFailsOn(payload) });
    assert.notEqual(unreadable.status, 0, `an unreadable ${payload} must fail the step, not pass it`);
  }
  // THE STATUS THAT MEANS WHAT IT SAYS still has to work, in both directions:
  // a complete leak is a failure, and the leak may be in any of the three.
  for (const [payload, extra] of [['report.md', { reportMd: `## Debug evidence report\n${DEMO_SECRET}\n` }],
    ['report.json', { reportJson: `{"schema":1,"leak":"${DEMO_SECRET}"}\n` }]]) {
    const leaked = stageDemoPayloads({ sessionLog: demoSessionLog([REDACTED_CONFIG_MSG]), ...extra });
    assert.notEqual(runDemoAssertionsOn(leaked).status, 0, `the fixture value reached ${payload}`);
  }
  // And the vacuous capture: no config-dump event at all is not a redaction
  // proof, it is the absence of one.
  const missing = stageDemoPayloads({ sessionLog: demoSessionLog([]) });
  assert.notEqual(runDemoAssertionsOn(missing).status, 0, 'no redacted event is not proof of redaction');
});

test('the failing-start probe is rejected at input validation and takes nothing from its neighbours', () => {
  const job = parseWorkflow(DEMO_WORKFLOW).jobs.namespacing;
  const probe = probeStep(job, 'A third start that fails, against the same shared output dir');
  const inputs = actionInputsFromEnv(probe.env);
  // DELIBERATELY INVALID, proven deliberate by the action's own validator
  // rather than by this test's belief about it.
  assert.deepEqual(
    validateActionInputs({ ...inputs, outputDir: probe.env.DEBUG_ACTION_OUTPUT_DIR, workspace: '' }),
    ['session-name: must match [A-Za-z0-9_-]+'],
  );
  // The SHARED directory: this probe's whole point is that it fails against
  // the output-dir two live invocations just used.
  const [first, second] = actionInvocations(job);
  assert.equal(probe.env.DEBUG_ACTION_OUTPUT_DIR, first.with['output-dir']);
  assert.equal(probe.env.DEBUG_ACTION_OUTPUT_DIR, second.with['output-dir']);
  for (const line of [
    // 1, not 3: the exit taxonomy separates "this host was refused" from
    // "these inputs are not usable".
    'test "$status" = "1"',
    'grep -q "invalid inputs: session-name" "$log"',
    // Its own staging child, named from its own pre-validation identity, and
    // NOT PRESENT AT ALL — never the neighbours' evidence (Codex T7 r1 #4).
    // Naming two files checked two files: a directory holding report.json, a
    // lock, or any other residue satisfied both while flatly contradicting
    // "stays empty". The claim is about the directory, so the check is too —
    // and it is the stronger claim the refusal actually earns, since `start`
    // rejects these inputs before it creates anything at all.
    'test ! -e "$evidence_dir"',
    // A DIFFERENT directory from the neighbour's, whose staged report is
    // still there afterwards: neither adopted nor destroyed.
    'test "$evidence_dir" != "$(dirname "$SECOND_REPORT")"',
    'test -f "$SECOND_REPORT"',
    // And the shared state file still belongs to whoever owned it before.
    'test "$before" = "$after"',
  ]) {
    assert.ok(probe.run.includes(line), `the failing-start probe must check: ${line}`);
  }
});

test('the two-invocation job demonstrates NAMESPACING ONLY, and says so in the file', () => {
  const workflow = parseWorkflow(DEMO_WORKFLOW);
  const job = workflow.jobs.namespacing;
  const [first, second] = actionInvocations(job);
  assert.equal(actionInvocations(job).length, 2, 'two invocations, one job');
  // ONE output-dir, shared, which is the whole point: the staging children and
  // the step outputs are what keep them apart, not the directory.
  assert.equal(first.with['output-dir'], second.with['output-dir']);
  assert.match(first.with['output-dir'], /^\$\{\{ runner\.temp \}\}\//, 'outside the workspace by construction');
  assert.notEqual(first.with['artifact-name'], second.with['artifact-name']);
  assert.notEqual(first.with.port ?? parseActionYml().inputs.port.default, second.with.port);
  assert.equal(first.id, 'first');
  assert.equal(second.id, 'second');
  const assertion = probeStep(job, 'Assert each invocation answered for itself');
  // Each invocation answers for ITSELF: its own session, its own staged
  // report — and the second one's arrival neither renamed nor cleared the
  // first one's evidence, which is still on disk when this step runs.
  for (const line of [
    'test "$FIRST_SESSION" != "$SECOND_SESSION"',
    'test "$FIRST_EXIT" = "1"',
    'test "$SECOND_EXIT" = "1"',
    'test "$FIRST_REPORT" != "$SECOND_REPORT"',
    'test -f "$FIRST_REPORT"',
    'test -f "$SECOND_REPORT"',
  ]) {
    assert.ok(assertion.run.includes(line), `the assertion step must check: ${line}`);
  }
  // THE LABEL, pinned by polarity because the claim it makes is a security
  // claim and the flattering reading of this job is the wrong one (Codex T6
  // r2 ruling, carried into Task 7's adaptation note 2). Two invocations in
  // one job show expression SCOPING; they show nothing about isolation,
  // because an earlier instrumented command reaches a later invocation's
  // start through BASH_ENV.
  const commentary = workflowText(DEMO_WORKFLOW).split(/\r?\n/)
    .filter((line) => line.trim().startsWith('#'))
    .map((line) => line.trim().replace(/^#\s?/, ''))
    .join(' ');
  assert.match(commentary, /namespacing only/i);
  assert.match(commentary, /not adversarial isolation/i);
  assert.match(commentary, /separate job/i);
  assert.doesNotMatch(commentary, /(?:demonstrates|proves|shows) (?:adversarial )?isolation|isolated from each other|safe to reuse in the same job/i);
  // AND THE SECOND LABEL THIS JOB NEEDS (Codex T7 r1 ruling on teardown).
  // Distinct ports are operationally right — they dodge the signal-to-port-
  // release race — but dodging the race also dodges the evidence: a first
  // collector that IGNORED termination outright would still be listening on
  // 8787 while this second invocation succeeded on 8788. So the only teardown
  // fact this job establishes is that the call RETURNED, and the comment has
  // to say that rather than leaving a reader to infer more.
  assert.match(commentary, /the only teardown fact established here is that teardown RETURNED/);
  assert.match(commentary, /proves NOTHING about whether the first collector actually died/);
  assert.match(commentary, /bounded process-exit polling or a teardown that waits/);
});

test('the closeout gate forwards a retry for the demo workflow, and still excludes itself', () => {
  const text = workflowText(GATE_WORKFLOW);
  // The trigger list, exactly: a fourth entry (or a reordering) is a change to
  // which siblings can unblock a gate that BLOCKED on a pending check.
  assert.match(text, /^ {4}workflows: \["Validate", "Closeout preview", "Debug evidence demo"\]$/m);
  // …and the same list read STRUCTURALLY, which the regex above cannot do
  // (Codex T7 r5 #3). A `workflows:` list is only a trigger where it sits under
  // `on.workflow_run`; the pattern above matches it at any four-space indent
  // anywhere in the file, so the list could be moved under a neighbouring
  // trigger — or the trigger renamed — with the regex still green and the gate
  // no longer listening. The value is compared as the literal text the reader
  // stores, because flow sequences are not parsed (see the reader's claim).
  const gateDocument = parseWorkflow(GATE_WORKFLOW);
  assert.equal(gateDocument.on.workflow_run.workflows, '["Validate", "Closeout preview", "Debug evidence demo"]');
  assert.deepEqual(Object.keys(gateDocument.jobs), ['gate', 'retry-forwarder', 'base-drift-forwarder']);
  // The invariant the list exists to preserve: the gate must never watch for
  // its OWN completion, or every run re-triggers another.
  assert.doesNotMatch(text, /workflows: \[[^\]]*"Closeout gate"/);
  const commentary = text.split(/\r?\n/)
    .filter((line) => line.trim().startsWith('#'))
    .map((line) => line.trim().replace(/^#\s?/, ''))
    .join(' ');
  // The comment names what it scopes to, and still explains the exclusion.
  assert.match(commentary, /"Validate", "Closeout preview", "Debug evidence demo"/);
  assert.doesNotMatch(commentary, /ONLY these two sibling/i);
  assert.match(commentary, /NOT "Closeout gate" itself/);
  assert.match(commentary, /no retrigger loop/i);
  // THE BOOTSTRAP COST, documented rather than fixed (Codex T7 r1 #2). A
  // workflow_run listener runs the YAML as committed on the DEFAULT branch, so
  // a sibling newly added to the list above does not exist for this trigger
  // until the PR adding it has merged — which means that PR's own gate run
  // cannot be unblocked by that sibling's completion. This is a real one-time
  // operational cost and the comment must not read as though it were closed.
  assert.match(commentary, /BOOTSTRAP/);
  assert.match(commentary, /a one-time operational cost, NOT something this file fixes/);
  assert.match(commentary, /does not\s+exist for this trigger until the PR that adds it has MERGED/);
  assert.match(commentary, /re-runs the gate by hand, once/);
  assert.match(commentary, /it is paid once per newly-listed sibling, at merge time/);
  // The parenthetical that enumerates the siblings drifted when the third one
  // was added: a list that names two of three is a claim about the repository
  // that is simply false.
  assert.doesNotMatch(commentary, /sibling workflow \(Validate \/ Closeout preview\) completes/);
  assert.match(commentary, /sibling workflow \(Validate \/ Closeout preview \/ Debug evidence demo\)\s+completes/);
  // AND the structural fact the gate's own blast-radius note asserts about its
  // siblings, which the demo workflow CHANGES: it uploads an evidence
  // artifact, so the old "neither uploads an artifact" sentence became false
  // the moment this task shipped. Pinned by polarity: a comment that is wrong
  // about the repository is worse than one that says nothing.
  assert.doesNotMatch(commentary, /neither uploads an artifact/i);
  assert.match(commentary, /"Debug evidence demo" (?:does )?upload/i);
  // And the COUNT it states is the count the demo workflow actually produces.
  // A number in a comment is a claim about the repository like any other, and
  // this one drifts the moment a job is added or removed.
  const claimed = /upload evidence\s+artifacts \((\d+) per run/.exec(commentary);
  assert.ok(claimed, 'the note states how many artifacts the demo produces');
  const invocations = Object.values(parseWorkflow(DEMO_WORKFLOW).jobs)
    .flatMap((job) => actionInvocations(job));
  assert.equal(Number(claimed[1]), invocations.length);
  // AND THE BOUND ON THOSE ARTIFACTS IS SNAPSHOT-SCOPED, not structural
  // (Codex T7 r1 #5). The note models a hostile PR-controlled checkout and
  // then describes the artifact contents as three deterministic demo files —
  // but the same PR controls the action, the repro AND the upload
  // configuration, so "three files from a deterministic repro" describes the
  // reviewed snapshot and nothing a PR is prevented from changing.
  assert.match(commentary, /bounded only for the SNAPSHOT\s+REVIEWED/);
  assert.match(commentary, /the same PR controls the\s+action, the repro and the upload configuration/);
  // The neighbouring half genuinely IS structural and must not be dragged down
  // with it: no write scope is requested, and no sibling exposes a repository
  // secret this token could reach. Qualifying that would be the opposite error.
  assert.match(commentary, /The permissions: block above is entirely READ-only/);
  assert.doesNotMatch(commentary, /read-only[^.]{0,60}(?:snapshot|only for the snapshot)/i);
  // The blast-radius summary further down said "neither sibling workflow
  // exposes a secret or artifact this token could reach" — a two-of-three
  // count AND, since this task shipped, a false claim about artifacts.
  assert.doesNotMatch(commentary, /neither sibling workflow exposes a secret or artifact/);
  assert.match(commentary, /no\s+sibling workflow exposes a repository secret this token could reach/);
});

// THE CROSS-MODULE BYTE CONTRACT the demo's exit-98 guard silently depends on.
// repro.js enumerates the variables `run` promises to delete from the wrapped
// command's environment, support.js enumerates the ones it actually deletes,
// and the two lists were byte-identical with NOTHING pinning them: a grep of
// this suite returned zero hits for either name, and the repro's own comment
// invited a reader to compare them "by eye". Add a sixth command-file variable
// to support.js and the demo's guard quietly stops checking it while staying
// green — a guard that certifies a contract it no longer covers.
test('the demo repro checks exactly the control-plane variables the run step deletes', () => {
  const { STRIPPED_CONTROL_PLANE } = require(REPRO_PATH);
  // BOTH SIDES ARE PROVEN TO EXIST FIRST. deepEqual(undefined, undefined)
  // passes, so an export that silently disappeared from either module would
  // turn this pin into a vacuous green — the exact failure mode the pin exists
  // to remove, reintroduced one level up.
  for (const [label, list] of [['repro.js STRIPPED_CONTROL_PLANE', STRIPPED_CONTROL_PLANE], ['support.js RUNNER_COMMAND_FILE_VARS', RUNNER_COMMAND_FILE_VARS]]) {
    assert.ok(Array.isArray(list) && list.length >= 5, `${label} must be exported, and be the five runner command files at least`);
    assert.equal(list.every((name) => typeof name === 'string' && name.startsWith('GITHUB_')), true, `${label}: every entry is a GITHUB_ variable`);
  }
  // Order included, deliberately: deepEqual on arrays is order-sensitive, and
  // the point of the pin is that these are the same list rather than the same
  // set assembled twice.
  assert.deepEqual(STRIPPED_CONTROL_PLANE, RUNNER_COMMAND_FILE_VARS);
  // And the repro no longer advertises an eyeball contract it does not need.
  assert.doesNotMatch(readFileSync(REPRO_PATH, 'utf8'), /by eye/i);
});
