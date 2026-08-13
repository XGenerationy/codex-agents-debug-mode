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
