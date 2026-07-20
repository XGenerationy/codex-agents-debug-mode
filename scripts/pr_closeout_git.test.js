const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { access, mkdtemp, mkdir, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  classifyGateIntegrity,
  digestValidationConfig,
  failureSignature,
  fingerprintEntries,
  isGateFile,
  verifyBaseline,
  verifyGeneratorReproducibility,
  withDisposableWorktree,
} = require('./pr_closeout_git');

const git = (repo, ...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();

const liveAttestation = (extra = {}) => ({
  provider: 'github-pull-request-review',
  status: 'PASS',
  baseSha: 'base123',
  headSha: 'abc123',
  configDigest: 'cfg123',
  decision: 'not-weakened',
  reviewer: 'Ada',
  evidence: 'https://github.example/review/7',
  ...extra,
});

test('recognizes files that define validation strength', () => {
  for (const file of [
    'package.json',
    'pnpm-lock.yaml',
    'Makefile',
    '.github/workflows/pr.yml',
    'biome.json',
    'tsconfig.build.json',
    'vitest.config.ts',
    'playwright.config.ts',
    '.pr-closeout.json',
    'pr-closeout.config.json',
    '.eslintrc.json',
    // Monorepo package manifests live under packages/*/package.json and must
    // also be treated as validation-defining gate files.
    'packages/web/package.json',
    'packages/server/package.json',
    // GNU make's default filenames: changes to whichever one readProjectMetadata
    // actually discovers must be treated as gate changes.
    'GNUmakefile',
    'makefile',
  ]) {
    assert.equal(isGateFile(file), true, file);
  }
  assert.equal(isGateFile('src/worker.ts'), false);
});

test('blocks unreviewed gate changes and fails obvious weakening', () => {
  const base = { changedFiles: ['package.json'], baseSha: 'base123', headSha: 'abc123', configDigest: 'cfg123' };
  assert.equal(classifyGateIntegrity({ ...base, addedLines: ['+  "test": "vitest"'] }).status, 'BLOCKED');
  assert.equal(
    classifyGateIntegrity({ ...base, addedLines: ['+  "passWithNoTests": true'] }).status,
    'FAIL',
  );
  assert.equal(
    classifyGateIntegrity({
      ...base,
      addedLines: ['+  "test": "vitest"'],
      attestation: liveAttestation(),
    }).status,
    'PASS',
  );
  // A gate file that could not be fully decoded (tracked-diff maxBuffer
  // overflow, oversized/missing/symlinked untracked gate file) leaves the gate
  // change set unscannable. Even with a valid attestation the closeout gate
  // must refuse to PASS, because it cannot prove no weakening was introduced.
  assert.equal(
    classifyGateIntegrity({
      ...base,
      addedLines: ['+__decode_error__:package.json:diff_buffer_exceeded:Error: maxBuffer exceeded'],
      attestation: liveAttestation(),
    }).status,
    'FAIL',
    'an unscannable gate diff must fail closed even with a valid attestation',
  );
  assert.equal(
    classifyGateIntegrity({
      ...base,
      addedLines: ['+  "test": "vitest"'],
      attestation: liveAttestation({ headSha: 'old' }),
    }).status,
    'BLOCKED',
  );
});

test('requires exact-head review for configured validation commands', () => {
  const configured = {
    changedFiles: [],
    addedLines: [],
    configuredCommands: ['typecheck'],
    baseSha: 'base123',
    headSha: 'abc123',
    configDigest: 'cfg123',
  };
  assert.equal(classifyGateIntegrity(configured).status, 'BLOCKED');
  assert.equal(classifyGateIntegrity({
    ...configured,
    attestation: liveAttestation(),
  }).status, 'PASS');
  assert.equal(classifyGateIntegrity({
    ...configured,
    attestation: liveAttestation({ configDigest: 'wrong' }),
  }).status, 'BLOCKED');
});

test('requires an exact review tuple even when the tree and command mapping are clean', () => {
  const clean = {
    changedFiles: [],
    addedLines: [],
    configuredCommands: [],
    baseSha: 'base123',
    headSha: 'head123',
    configDigest: 'cfg123',
  };
  assert.equal(classifyGateIntegrity(clean).status, 'BLOCKED');
  assert.equal(classifyGateIntegrity({
    ...clean,
    attestation: liveAttestation({ headSha: 'head123' }),
  }).status, 'PASS');
  assert.equal(classifyGateIntegrity({
    ...clean,
    review: {
      baseSha: 'base123',
      headSha: 'head123',
      configDigest: 'cfg123',
      reviewer: 'self-asserted',
      evidence: 'local config',
      decision: 'not-weakened',
    },
  }).status, 'BLOCKED');
});

test('detects multiline gate weakening and produces stable config digests', () => {
  const gate = classifyGateIntegrity({
    changedFiles: ['.eslintrc.json'],
    addedLines: ['+{', '+  "rules": {', '+    "security/no-danger": "off"', '+  }', '+}'],
    baseSha: 'base',
    headSha: 'head',
    configDigest: 'cfg',
  });
  assert.equal(gate.status, 'FAIL');
  assert.equal(digestValidationConfig({ b: 2, a: 1 }), digestValidationConfig({ a: 1, b: 2 }));
  assert.notEqual(digestValidationConfig({ a: 1 }), digestValidationConfig({ a: 2 }));
});

test('does not flag positive coverage thresholds as weakening', () => {
  const base = { changedFiles: ['package.json'], baseSha: 'base123', headSha: 'abc123', configDigest: 'cfg123' };
  for (const line of [
    '+  "coverage": 80',
    '+  "threshold": 100',
    '+  "coverage": 0.5',
    '+  "coverage": 0.50',
    '+  "coverage":"0.5"',
  ]) {
    assert.notEqual(
      classifyGateIntegrity({ ...base, addedLines: [line] }).status,
      'FAIL',
      line,
    );
  }
  for (const line of [
    '+  "coverage": 0',
    '+  "coverage": false',
    '+  "threshold": null',
    '+  "coverage": 0.0',
    '+coverage=0',
  ]) {
    assert.equal(
      classifyGateIntegrity({ ...base, addedLines: [line] }).status,
      'FAIL',
      line,
    );
  }
});

test('failure signatures use the full captured-output digest', () => {
  const base = { status: 'FAIL', exitCode: 1, stdout: 'same capped output', stderr: '', cwd: 'C:/repo' };
  const first = failureSignature({ ...base, outputDigest: { stdout: 'aaa', stderr: 'empty' } });
  const second = failureSignature({ ...base, outputDigest: { stdout: 'bbb', stderr: 'empty' } });
  assert.notEqual(first, second);
});

test('failure signatures differ when postcondition proof results differ', () => {
  const base = { status: 'FAIL', exitCode: 1, stdout: 'same', stderr: '', cwd: 'C:/repo' };
  const outputDigest = { stdout: 'aaa', stderr: 'empty' };
  const passed = failureSignature({ ...base, outputDigest, proofResult: { status: 'PASS', matched: true } });
  const failed = failureSignature({ ...base, outputDigest, proofResult: { status: 'FAIL', matched: false } });
  const missing = failureSignature({ ...base, outputDigest });
  assert.notEqual(passed, failed);
  assert.notEqual(passed, missing);
  assert.notEqual(failed, missing);
});

test('fingerprints are stable across order and change with content', () => {
  const first = fingerprintEntries([
    { path: 'b.txt', hash: '2' },
    { path: 'a.txt', hash: '1' },
  ]);
  const reordered = fingerprintEntries([
    { path: 'a.txt', hash: '1' },
    { path: 'b.txt', hash: '2' },
  ]);
  const changed = fingerprintEntries([{ path: 'a.txt', hash: 'different' }]);
  assert.equal(first, reordered);
  assert.notEqual(first, changed);
});

test('runs a generator twice and rejects second-run drift', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'closeout-generator-'));
  await mkdir(path.join(root, 'generated'));
  const target = path.join(root, 'generated', 'client.txt');
  let runs = 0;
  const executeGenerator = async () => {
    runs += 1;
    await writeFile(target, String(runs));
    return { status: 'PASS', exitCode: 0 };
  };
  const fingerprint = async () => String(runs);

  const result = await verifyGeneratorReproducibility({ executeGenerator, fingerprint });
  assert.equal(runs, 2);
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /changed the tree/i);
});

test('accepts an idempotent second generator run', async () => {
  let runs = 0;
  const result = await verifyGeneratorReproducibility({
    executeGenerator: async () => {
      runs += 1;
      return { status: 'PASS', exitCode: 0 };
    },
    fingerprint: async () => 'stable',
  });
  assert.equal(runs, 2);
  assert.equal(result.status, 'PASS');
});

test('classifies a matching disposable-worktree failure as a blocking baseline', async () => {
  const calls = [];
  const result = await verifyBaseline({
    repo: 'C:/repo',
    baseSha: 'base123',
    check: { id: 'typecheck', command: 'pnpm typecheck', baselineSafe: true },
    headResult: { status: 'FAIL', exitCode: 1, stdout: '', stderr: 'Type error at src/a.ts:4' },
    withWorktree: async ({ baseSha }, callback) => {
      calls.push(`worktree:${baseSha}`);
      return callback('C:/temp/baseline');
    },
    execute: async (check, cwd) => {
      calls.push(`${cwd}:${check.command}`);
      return { status: 'FAIL', exitCode: 1, stdout: '', stderr: 'Type error at src/a.ts:4' };
    },
  });
  assert.equal(result.status, 'BASELINE');
  assert.equal(result.blocking, true);
  assert.deepEqual(calls, ['worktree:base123', 'C:/temp/baseline:pnpm typecheck']);
});

test('creates and removes a real detached baseline worktree', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-baseline-repo-'));
  let worktree;
  try {
    git(repo, 'init', '--quiet');
    git(repo, 'config', 'user.name', 'Closeout Test');
    git(repo, 'config', 'user.email', 'closeout@example.invalid');
    git(repo, 'config', 'commit.gpgsign', 'false');
    await writeFile(path.join(repo, 'tracked.txt'), 'base\n');
    git(repo, 'add', 'tracked.txt');
    git(repo, 'commit', '--quiet', '-m', 'base');
    const baseSha = git(repo, 'rev-parse', 'HEAD');
    const value = await withDisposableWorktree({ repo, baseSha }, async (created) => {
      worktree = created;
      assert.equal(git(created, 'rev-parse', 'HEAD'), baseSha);
      assert.equal(git(created, 'rev-parse', '--abbrev-ref', 'HEAD'), 'HEAD');
      return 'verified';
    });
    assert.equal(value, 'verified');
    await assert.rejects(access(worktree), { code: 'ENOENT' });
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('does not claim a baseline for an unsafe or non-matching failure', async () => {
  const unsafe = await verifyBaseline({
    repo: 'C:/repo',
    baseSha: 'base123',
    check: { id: 'hunter-build', command: 'docker compose up -d --build hunter', baselineSafe: false },
    headResult: { status: 'FAIL', exitCode: 1, stderr: 'failed' },
  });
  assert.equal(unsafe.status, 'FAIL');
  assert.match(unsafe.evidence, /not baseline-safe/i);

  const different = await verifyBaseline({
    repo: 'C:/repo',
    baseSha: 'base123',
    check: { id: 'typecheck', command: 'pnpm typecheck', baselineSafe: true },
    headResult: { status: 'FAIL', exitCode: 1, stderr: 'head-only error' },
    withWorktree: async (_options, callback) => callback('C:/temp/baseline'),
    execute: async () => ({ status: 'FAIL', exitCode: 1, stdout: '', stderr: 'different error' }),
  });
  assert.equal(different.status, 'FAIL');
  assert.match(different.evidence, /did not reproduce exactly/i);
});

test('refuses a baseline label when tool versions differ', async () => {
  const result = await verifyBaseline({
    repo: 'C:/repo',
    baseSha: 'base123',
    check: { id: 'typecheck', command: 'pnpm typecheck', baselineSafe: true },
    headResult: { status: 'FAIL', exitCode: 1, stdout: '', stderr: 'same error' },
    toolVersions: { node: 'v24', pnpm: '10' },
    captureVersions: async () => ({ node: 'v24', pnpm: '9' }),
    withWorktree: async (_options, callback) => callback('C:/temp/baseline'),
    execute: async () => ({ status: 'FAIL', exitCode: 1, stdout: '', stderr: 'same error' }),
  });
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /tool versions differ/i);
});

test('blocks baseline classification when deterministic dependency setup fails', async () => {
  const result = await verifyBaseline({
    repo: 'C:/repo',
    baseSha: 'base123',
    check: { id: 'typecheck', command: 'pnpm typecheck', baselineSafe: true },
    headResult: { status: 'FAIL', exitCode: 1, stderr: 'same error' },
    withWorktree: async (_options, callback) => callback('C:/temp/baseline'),
    setup: async () => ({ status: 'FAIL', exitCode: 1, evidence: 'lockfile install failed' }),
    execute: async () => ({ status: 'FAIL', exitCode: 1, stderr: 'same error' }),
  });
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /dependency setup was not clean/i);
});
