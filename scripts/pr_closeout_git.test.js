const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { access, chmod, mkdtemp, mkdir, rename, rm, writeFile } = require('node:fs/promises');
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
    // Local composite actions hold the same validation surfaces as workflows
    // when a workflow does `uses: ./.github/actions/test`.
    '.github/actions/test/action.yml',
    '.github/actions/pr-check/action.yaml',
    '.github/actions/nested/setup/action.yml',
  ]) {
    assert.equal(isGateFile(file), true, file);
  }
  assert.equal(isGateFile('src/worker.ts'), false);
  assert.equal(isGateFile('.github/CODEOWNERS'), false);
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
  // In-place removal of a validation step must FAIL even with attestation.
  assert.equal(
    classifyGateIntegrity({
      ...clean,
      removedLines: ['-      - run: npm test'],
      attestation: liveAttestation({ headSha: 'head123' }),
    }).status,
    'FAIL',
  );
  assert.equal(
    classifyGateIntegrity({
      ...clean,
      removedLines: ['-      - uses: github/codeql-action/analyze@v3'],
      attestation: liveAttestation({ headSha: 'head123' }),
    }).status,
    'FAIL',
  );
  // Non-validation workflow edits must not be treated as deletion-only
  // validation weakening (CodeRabbit review #4780120134): checkout / setup /
  // deploy / notify / echo cleanup removals stay attestation-gated (BLOCKED
  // without attestation, PASS with a valid not-weakened review) rather than
  // unconditional FAIL.
  for (const line of [
    '-      - uses: actions/checkout@v4',
    '-      - uses: actions/setup-node@v4',
    '-      - run: echo deploy',
    '-      - run: |',
    // Bare `npm run` / `pnpm run` must not treat deploy/release as validation.
    '-      - run: npm run deploy',
    '-      - run: pnpm run release',
    '-        npm run changelog',
  ]) {
    assert.equal(
      classifyGateIntegrity({
        ...clean,
        removedLines: [line],
        attestation: liveAttestation({ headSha: 'head123' }),
      }).status,
      'PASS',
      `non-validation removal must not FAIL: ${line}`,
    );
  }
  // Explicit validation script names still FAIL.
  assert.equal(
    classifyGateIntegrity({
      ...clean,
      removedLines: ['-      - run: npm run typecheck'],
      attestation: liveAttestation({ headSha: 'head123' }),
    }).status,
    'FAIL',
  );
});

test('install.sh removal requires an executable invocation prefix', () => {
  // CodeRabbit discussion_r3652923138: bare `install.sh` matched prose such
  // as `# see install.sh for setup`, FAILing unconditionally like the bare
  // `npm run` false positive. Only executable invocations count as removals.
  const clean = {
    changedFiles: ['.github/workflows/validate.yml'],
    addedLines: [],
    removedLines: [],
    deletedFiles: [],
    baseSha: 'base123',
    headSha: 'head123',
    configDigest: 'cfg123',
  };
  assert.equal(
    classifyGateIntegrity({
      ...clean,
      removedLines: ['-      # see install.sh for setup'],
      attestation: liveAttestation({ headSha: 'head123' }),
    }).status,
    'PASS',
    'prose mention of install.sh must not FAIL',
  );
  // CodeRabbit #UC4NI / #UC4NN: a commented-out invocation is prose, not an
  // executable removal — even when it is path-qualified.
  assert.equal(
    classifyGateIntegrity({
      ...clean,
      removedLines: ['-      # run scripts/install.sh manually'],
      attestation: liveAttestation({ headSha: 'head123' }),
    }).status,
    'PASS',
    'commented-out install.sh invocation must not FAIL',
  );
  for (const line of [
    '-      - run: ./install.sh',
    '-      - run: bash install.sh',
    '-      - run: sh install.sh',
    '-      - run: source install.sh',
    // CodeRabbit #UC4NI / #UC4NN: path-qualified, rooted, dot-sourced, and
    // exec'd invocations are executable removals too.
    '-      - run: scripts/install.sh',
    '-      - run: /opt/ci/install.sh',
    '-      - run: . install.sh',
    '-      - run: exec install.sh',
  ]) {
    assert.equal(
      classifyGateIntegrity({
        ...clean,
        removedLines: [line],
        attestation: liveAttestation({ headSha: 'head123' }),
      }).status,
      'FAIL',
      `executable install.sh removal must FAIL: ${line}`,
    );
  }
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

test('does not treat GitHub Actions fail-fast false as gate weakening', () => {
  // strategy.fail-fast: false keeps the full Node/OS matrix visible after one
  // leg fails; that is required visibility, not a weakened gate.
  const result = classifyGateIntegrity({
    changedFiles: ['.github/workflows/validate.yml'],
    addedLines: ['+    fail-fast: false', '+    failFast: false'],
    baseSha: 'base123',
    headSha: 'abc123',
    configDigest: 'cfg123',
    attestation: liveAttestation(),
  });
  assert.equal(result.status, 'PASS', result.evidence);
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

test('creates and removes a real detached isolated baseline clone', async () => {
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

test('disables fsmonitor and global attributes for the isolated baseline clone', async () => {
  // A validation command can set core.fsmonitor or a global attribute smudge
  // filter that would execute during `git worktree add`. The internal worktree
  // wrapper overrides core.fsmonitor / core.useBuiltinFSMonitor /
  // core.attributesFile so no attacker-configured git mechanism runs during the
  // baseline checkout. Regression guard: with hostile config present the
  // worktree must still be created and the checked-out blob must be uncorrupted.
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-baseline-safety-'));
  let worktree;
  try {
    git(repo, 'init', '--quiet');
    git(repo, 'config', 'user.name', 'Closeout Test');
    git(repo, 'config', 'user.email', 'closeout@example.invalid');
    git(repo, 'config', 'commit.gpgsign', 'false');
    // Hostile config that would otherwise be inherited by `git worktree add`.
    git(repo, 'config', 'core.fsmonitor', '/nonexistent/fsmonitor-helper');
    await writeFile(path.join(repo, 'tracked.txt'), 'base\n');
    git(repo, 'add', 'tracked.txt');
    git(repo, 'commit', '--quiet', '-m', 'base');
    const baseSha = git(repo, 'rev-parse', 'HEAD');
    const value = await withDisposableWorktree({ repo, baseSha }, async (created) => {
      worktree = created;
      // The checked-out file must be the plain blob, uncorrupted by any filter.
      // Normalize CRLF so the assertion holds on Windows (autocrlf checkout)
      // while still detecting any smudge-driven content change.
      const content = require('node:fs').readFileSync(path.join(created, 'tracked.txt'), 'utf8').replace(/\r\n/g, '\n');
      assert.equal(content, 'base\n');
      return 'verified';
    });
    assert.equal(value, 'verified');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});


test('does not inherit repository filter drivers or .git/info/attributes into the baseline clone', async () => {
  // A failed validation command can write .git/info/attributes + filter.*.smudge
  // so that a linked worktree checkout runs an external smudge outside
  // spawnCaptured containment. The source file must remain untouched while
  // the isolated clone's fresh Git directory excludes its attributes.
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-baseline-filter-'));
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
    const infoDir = path.join(repo, '.git', 'info');
    await mkdir(infoDir, { recursive: true });
    await writeFile(path.join(infoDir, 'attributes'), 'tracked.txt filter=evil\n');
    git(repo, 'config', 'filter.evil.smudge', 'sed "s/base/HACKED/"');
    git(repo, 'config', 'filter.evil.clean', 'cat');
    const value = await withDisposableWorktree({ repo, baseSha }, async (created) => {
      worktree = created;
      const content = require('node:fs').readFileSync(path.join(created, 'tracked.txt'), 'utf8').replace(/\r\n/g, '\n');
      assert.equal(content, 'base\n', 'smudge filter must not rewrite the baseline checkout');
      assert.equal(
        require('node:fs').readFileSync(path.join(infoDir, 'attributes'), 'utf8'),
        'tracked.txt filter=evil\n',
        'baseline checkout must not park or mutate source-repository attributes',
      );
      return 'verified';
    });
    assert.equal(value, 'verified');
    // The source repo was never touched.
    const restoredAfter = require('node:fs').readFileSync(path.join(infoDir, 'attributes'), 'utf8');
    assert.match(restoredAfter, /filter=evil/);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});


test('neutralizes filter.<driver>.process and required during baseline worktree checkout', async () => {
  // Git prefers filter.<driver>.process over smudge/clean when present. A
  // hostile validation command can set only process+required (no smudge) and
  // assign the driver via in-tree .gitattributes; parking .git/info/attributes
  // alone does not cover that path, and clearing only smudge/clean leaves
  // process executable during `git worktree add`.
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-baseline-filter-process-'));
  const marker = path.join(repo, 'evil-process-ran');
  try {
    git(repo, 'init', '--quiet');
    git(repo, 'config', 'user.name', 'Closeout Test');
    git(repo, 'config', 'user.email', 'closeout@example.invalid');
    git(repo, 'config', 'commit.gpgsign', 'false');
    await writeFile(path.join(repo, 'tracked.txt'), 'base\n');
    // In-tree attributes (not .git/info/attributes) so info-park alone is
    // insufficient defense.
    await writeFile(path.join(repo, '.gitattributes'), 'tracked.txt filter=evil\n');
    git(repo, 'add', 'tracked.txt', '.gitattributes');
    git(repo, 'commit', '--quiet', '-m', 'base');
    const baseSha = git(repo, 'rev-parse', 'HEAD');

    const evilScript = path.join(repo, 'evil-process.sh');
    // Side-effect marker + hard fail: if process is invoked, the checkout is
    // not a clean unfiltered blob (required=true makes the failure fatal).
    await writeFile(
      evilScript,
      `#!/bin/sh\nprintf 'ran\\n' >> '${marker.replace(/'/g, "'\\''")}'\nexit 1\n`,
    );
    await chmod(evilScript, 0o755);
    git(repo, 'config', 'filter.evil.process', evilScript);
    git(repo, 'config', 'filter.evil.required', 'true');
    // Deliberately do NOT set smudge/clean — the incomplete fix only cleared
    // those keys and would leave process live.

    const value = await withDisposableWorktree({ repo, baseSha }, async (created) => {
      const content = require('node:fs').readFileSync(path.join(created, 'tracked.txt'), 'utf8').replace(/\r\n/g, '\n');
      assert.equal(content, 'base\n', 'process filter must not rewrite or block the baseline checkout');
      return 'verified';
    });
    assert.equal(value, 'verified');
    assert.equal(
      require('node:fs').existsSync(marker),
      false,
      'filter.evil.process must never have been invoked during the baseline checkout',
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});



test('neutralizes dotted filter driver names (filter.a.b.process)', async () => {
  // Git allows dotted filter subsection names. Parsing only parts[1] would
  // neutralize filter.a.* while leaving filter.a.b.process intact.
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-baseline-dotted-filter-'));
  const marker = path.join(repo, 'dotted-process-ran');
  try {
    git(repo, 'init', '--quiet');
    git(repo, 'config', 'user.name', 'Closeout Test');
    git(repo, 'config', 'user.email', 'closeout@example.invalid');
    git(repo, 'config', 'commit.gpgsign', 'false');
    await writeFile(path.join(repo, 'tracked.txt'), 'base\n');
    await writeFile(path.join(repo, '.gitattributes'), 'tracked.txt filter=a.b\n');
    git(repo, 'add', 'tracked.txt', '.gitattributes');
    git(repo, 'commit', '--quiet', '-m', 'base');
    const baseSha = git(repo, 'rev-parse', 'HEAD');
    const evilScript = path.join(repo, 'evil-dotted.sh');
    await writeFile(evilScript, `#!/bin/sh\nprintf 'ran\\n' >> '${marker.replace(/'/g, "'\\''")}'\nexit 1\n`);
    await chmod(evilScript, 0o755);
    git(repo, 'config', 'filter.a.b.process', evilScript);
    git(repo, 'config', 'filter.a.b.required', 'true');
    const value = await withDisposableWorktree({ repo, baseSha }, async (created) => {
      const content = require('node:fs').readFileSync(path.join(created, 'tracked.txt'), 'utf8').replace(/\r\n/g, '\n');
      assert.equal(content, 'base\n');
      return 'ok';
    });
    assert.equal(value, 'ok');
    assert.equal(require('node:fs').existsSync(marker), false);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('fails closed when local filter.* enumeration is not a clean empty match', async () => {
  // Swallowing every get-regexp error would skip filterOverrides and leave
  // process/required active during worktree add. Only exit code 1 (no matches)
  // is safe; other failures must abort baseline checkout.
  //
  // Force a non-1 git-config failure portably: replace `.git/config` with a
  // directory. chmod(0o000) is not reliable on Windows (CI windows-latest),
  // where file modes often still allow reads.
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-baseline-filter-scan-'));
  try {
    git(repo, 'init', '--quiet');
    git(repo, 'config', 'user.name', 'Closeout Test');
    git(repo, 'config', 'user.email', 'closeout@example.invalid');
    git(repo, 'config', 'commit.gpgsign', 'false');
    await writeFile(path.join(repo, 'tracked.txt'), 'base\n');
    git(repo, 'add', 'tracked.txt');
    git(repo, 'commit', '--quiet', '-m', 'base');
    const baseSha = git(repo, 'rev-parse', 'HEAD');
    const configPath = path.join(repo, '.git', 'config');
    const configBackup = path.join(repo, '.git', 'config.bak-closeout');
    await rename(configPath, configBackup);
    await mkdir(configPath);
    try {
      await assert.rejects(
        () => withDisposableWorktree({ repo, baseSha }, async () => 'should-not-run'),
        /enumerate filter/i,
      );
    } finally {
      await rm(configPath, { recursive: true, force: true });
      await rename(configBackup, configPath);
    }
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

test('preserves head FAIL when deterministic dependency setup fails', async () => {
  // A proven head FAIL must not be downgraded to BLOCKED solely because the
  // disposable baseline worktree could not install dependencies.
  const result = await verifyBaseline({
    repo: 'C:/repo',
    baseSha: 'base123',
    check: { id: 'typecheck', command: 'pnpm typecheck', baselineSafe: true },
    headResult: { status: 'FAIL', exitCode: 1, stderr: 'same error' },
    withWorktree: async (_options, callback) => callback('C:/temp/baseline'),
    setup: async () => ({ status: 'FAIL', exitCode: 1, evidence: 'lockfile install failed' }),
    execute: async () => ({ status: 'FAIL', exitCode: 1, stderr: 'same error' }),
  });
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /dependency setup was not clean/i);
  assert.match(result.evidence, /no baseline attribution/i);
});

test('blocks when head is non-FAIL and baseline dependency setup fails', async () => {
  const result = await verifyBaseline({
    repo: 'C:/repo',
    baseSha: 'base123',
    check: { id: 'typecheck', command: 'pnpm typecheck', baselineSafe: true },
    headResult: { status: 'PASS', exitCode: 0, stderr: '' },
    withWorktree: async (_options, callback) => callback('C:/temp/baseline'),
    setup: async () => ({ status: 'FAIL', exitCode: 1, evidence: 'lockfile install failed' }),
    execute: async () => ({ status: 'PASS', exitCode: 0, stderr: '' }),
  });
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /dependency setup was not clean/i);
});

test('treats npm lockfiles as validation-defining gate files', () => {
  // This repository validates with `npm ci`/`npm audit`, so the npm lockfiles
  // define validation strength the same way pnpm-lock.yaml does.
  for (const file of ['package-lock.json', 'npm-shrinkwrap.json', 'packages/web/package-lock.json']) {
    assert.equal(isGateFile(file), true, file);
  }
});

test('treats workspace manifests as validation-defining gate files', () => {
  // Removing a package from pnpm-workspace.yaml (or lerna/nx/turbo workspace
  // roots) can drop validation surfaces without touching package.json scripts.
  for (const file of [
    'pnpm-workspace.yaml',
    'packages/pnpm-workspace.yaml',
    'lerna.json',
    'nx.json',
    'turbo.json',
  ]) {
    assert.equal(isGateFile(file), true, file);
  }
});

test('detects coverage threshold reductions split across added lines', () => {
  const base = { changedFiles: ['vitest.config.ts'], baseSha: 'base123', headSha: 'abc123', configDigest: 'cfg123' };
  const addedLines = ['+  coverageThreshold: {', '+    statements: 0,', '+  },'];
  assert.equal(classifyGateIntegrity({ ...base, addedLines }).status, 'FAIL');
  assert.equal(
    classifyGateIntegrity({ ...base, addedLines, attestation: liveAttestation() }).status,
    'FAIL',
    'a multiline coverage reduction must fail closed even with a valid attestation',
  );
  // Positive thresholds in the same nested form are not weakening.
  assert.equal(
    classifyGateIntegrity({
      ...base,
      addedLines: ['+  coverageThreshold: {', '+    statements: 80,', '+  },'],
      attestation: liveAttestation(),
    }).status,
    'PASS',
  );
});

test('fails closed when a gate file is deleted', () => {
  const base = {
    changedFiles: ['.github/workflows/validate.yml'],
    addedLines: [],
    baseSha: 'base123',
    headSha: 'abc123',
    configDigest: 'cfg123',
  };
  // A deleted gate file yields no added lines to scan; the removal of an
  // entire validation surface must not PASS on attestation alone.
  const deleted = classifyGateIntegrity({
    ...base,
    deletedFiles: ['.github/workflows/validate.yml'],
    attestation: liveAttestation(),
  });
  assert.equal(deleted.status, 'FAIL');
  assert.match(deleted.evidence, /deleted/i);
  // Deleting a non-gate file does not affect gate integrity.
  assert.equal(
    classifyGateIntegrity({
      ...base,
      changedFiles: [],
      deletedFiles: ['src/worker.ts'],
      attestation: liveAttestation(),
    }).status,
    'PASS',
  );
});

test('failure signatures ignore volatile proof result fields', () => {
  // The same logical artifact proof recorded in the head repo and in the
  // disposable baseline worktree differs only in volatile fields (absolute
  // paths, log paths, timestamps, durations); the signatures must match.
  const base = { status: 'FAIL', exitCode: 1, stdout: 'same', stderr: '', cwd: 'C:/repo' };
  const outputDigest = { stdout: 'aaa', stderr: 'empty' };
  const head = failureSignature({
    ...base,
    outputDigest,
    proofResult: {
      status: 'PASS', exists: true, digest: 'abc', path: 'C:/repo/out/artifact.json',
      realPath: 'C:/repo/out/artifact.json', realRoot: 'C:/repo', size: 10, mtimeMs: 1, ctimeMs: 2,
      logPath: 'C:/repo/logs/proof.log', durationMs: 42,
    },
  });
  const baseline = failureSignature({
    ...base,
    outputDigest,
    proofResult: {
      status: 'PASS', exists: true, digest: 'abc', path: 'C:/temp/baseline/out/artifact.json',
      realPath: 'C:/temp/baseline/out/artifact.json', realRoot: 'C:/temp/baseline', size: 10, mtimeMs: 99, ctimeMs: 100,
      logPath: 'C:/temp/baseline/logs/proof.log', durationMs: 7,
    },
  });
  assert.equal(head, baseline);
});
