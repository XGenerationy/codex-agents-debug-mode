const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { mkdir, mkdtemp, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  collectContentRemovals,
  getComparisonStyle,
  resolveBaseSha,
} = require('./scan_touched_suppressions');

const git = (repo, ...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();

// resolveBaseSha reads process.env directly; save/restore the keys it consults
// so the tests stay hermetic regardless of the ambient CI environment.
const ENV_KEYS = ['CLOSEOUT_BASE_SHA', 'GITHUB_BASE_SHA', 'GITHUB_EVENT_BEFORE', 'GITHUB_BASE_REF'];

const setScanEnv = (eventBefore) => {
  const saved = {};
  for (const key of ENV_KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  process.env.GITHUB_EVENT_BEFORE = eventBefore;
  return () => {
    for (const key of ENV_KEYS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  };
};

const fixtureRepo = async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'scan-touched-suppressions-'));
  git(repo, 'init', '--quiet');
  git(repo, 'config', 'user.name', 'Scan Test');
  git(repo, 'config', 'user.email', 'scan@example.invalid');
  git(repo, 'config', 'commit.gpgsign', 'false');
  await writeFile(path.join(repo, 'tracked.txt'), 'base\n');
  git(repo, 'add', '.');
  git(repo, 'commit', '--quiet', '-m', 'base');
  await writeFile(path.join(repo, 'tracked.txt'), 'changed\n');
  git(repo, 'add', '.');
  git(repo, 'commit', '--quiet', '-m', 'second');
  return repo;
};

test('GITHUB_EVENT_BEFORE naming an unfetched commit falls through to another base', async () => {
  // actions/checkout defaults to fetch-depth: 1, so a format-valid push
  // preimage can name a commit that was never fetched. resolveBaseSha must not
  // select it as a two-dot base (the diff would die on an unknown revision
  // before the gate evaluates) and must fall through to the remaining
  // resolution chain instead (CodeRabbit discussion_r3652923145).
  const repo = await fixtureRepo();
  const restoreEnv = setScanEnv('0123456789abcdef0123456789abcdef01234567');
  try {
    const unfetched = process.env.GITHUB_EVENT_BEFORE;
    const base = resolveBaseSha(repo);
    assert.notEqual(base, unfetched);
    assert.notEqual(getComparisonStyle(), 'two-dot');
    // Fall-through still resolves a usable base (fail-closed chain intact).
    assert.match(base, /^[0-9a-f]{40}$/i);
  } finally {
    restoreEnv();
    await rm(repo, { recursive: true, force: true });
  }
});

test('GITHUB_EVENT_BEFORE naming a fetched commit selects the two-dot preimage base', async () => {
  const repo = await fixtureRepo();
  const firstSha = git(repo, 'rev-list', '--max-parents=0', 'HEAD');
  const restoreEnv = setScanEnv(firstSha);
  try {
    const base = resolveBaseSha(repo);
    assert.equal(base, firstSha);
    assert.equal(getComparisonStyle(), 'two-dot');
  } finally {
    restoreEnv();
    await rm(repo, { recursive: true, force: true });
  }
});

test('isMechanicalLockfile recognizes generated dependency lockfiles', () => {
  const { isMechanicalLockfile } = require('./scan_touched_suppressions');
  for (const file of [
    'package-lock.json', 'dir/package-lock.json', 'pnpm-lock.yaml',
    'yarn.lock', 'Cargo.lock', 'poetry.lock', 'go.sum', 'composer.lock',
    'Gemfile.lock', 'gradle.lockfile', 'bun.lockb', 'Pipfile.lock',
  ]) {
    assert.equal(isMechanicalLockfile(file), true, `${file} should be a lockfile`);
  }
  // Non-lockfile gate/config files must NOT be excluded — they can hold real
  // validation steps/scripts and must remain in the fail-closed scan.
  for (const file of ['package.json', 'tsconfig.json', '.eslintrc.json', 'Makefile']) {
    assert.equal(isMechanicalLockfile(file), false, `${file} must not be treated as a lockfile`);
  }
});

// Build a real `git diff --unified=0` (the exact form diffUnified feeds the
// content-removal scanner) for one file edited between two commits, so the
// pairing/allowance logic is exercised against genuine git output rather than a
// hand-built diff string.
const singleFileDiff = async (relPath, before, after) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'scan-content-removal-'));
  try {
    git(repo, 'init', '--quiet');
    git(repo, 'config', 'user.name', 'Scan Test');
    git(repo, 'config', 'user.email', 'scan@example.invalid');
    git(repo, 'config', 'commit.gpgsign', 'false');
    const abs = path.join(repo, relPath);
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, before);
    git(repo, 'add', '.');
    git(repo, 'commit', '--quiet', '-m', 'base');
    await writeFile(abs, after);
    git(repo, 'add', '.');
    git(repo, 'commit', '--quiet', '-m', 'head');
    return execFileSync(
      'git',
      ['diff', '--unified=0', '--no-ext-diff', '--no-textconv', 'HEAD~1', 'HEAD', '--', relPath],
      { cwd: repo, encoding: 'utf8' },
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
};

const pkg = (fields) => `${JSON.stringify({ name: 'x', ...fields }, null, 2)}\n`;

test('collectContentRemovals exempts a lone package.json version bump (single-line hunk)', async () => {
  // The exact reported false-positive: a benign version bump (removal +
  // same-field replacement) must no longer be a content removal / CI failure.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.2.3', scripts: { test: 'node --test' } }),
    pkg({ version: '1.2.4', scripts: { test: 'node --test' } }),
  );
  assert.deepEqual(collectContentRemovals(diff), []);
});

test('collectContentRemovals exempts a package.json version + description bump (multi-line hunk)', async () => {
  // Two adjacent same-field value edits share one hunk; index pairing must
  // align each removed line with its own replacement, not mispair them.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.2.3', description: 'old summary' }),
    pkg({ version: '1.2.4', description: 'new summary' }),
  );
  assert.deepEqual(collectContentRemovals(diff), []);
});

test('collectContentRemovals STILL flags a weakened test script replacement', async () => {
  // Preserve detection: `"test": "jest --coverage"` -> `"echo skip"`. The key
  // `test` is not an allowlisted descriptive field, so the removal is not a
  // safe replacement and must still fail closed.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.0.0', scripts: { test: 'jest --coverage' } }),
    pkg({ version: '1.0.0', scripts: { test: 'echo skip' } }),
  );
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /jest --coverage/.test(line)),
    `expected the removed jest command to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals STILL flags a lowered coverage threshold replacement', async () => {
  // Preserve detection: lowering a coverage threshold (`lines: 80` -> `50`) is
  // a same-key numeric edit, but `lines` is not an allowlisted descriptive
  // field, so it must still be reported (never exempted as a metadata bump).
  const before = 'module.exports = {\n  coverageThreshold: {\n    global: {\n      lines: 80,\n    },\n  },\n};\n';
  const after = 'module.exports = {\n  coverageThreshold: {\n    global: {\n      lines: 50,\n    },\n  },\n};\n';
  const diff = await singleFileDiff('jest.config.js', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /lines:\s*80/.test(line)),
    `expected the lowered coverage threshold to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals STILL flags a pure deletion of a workflow step (no replacement)', async () => {
  // Preserve detection: a step removed with no positional replacement is a pure
  // deletion and always fails closed, even when it matches no named validation
  // pattern (`./scripts/verify-artifacts.sh`).
  const before = 'name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo build\n      - run: ./scripts/verify-artifacts.sh\n';
  const after = 'name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo build\n';
  const diff = await singleFileDiff('.github/workflows/ci.yml', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /verify-artifacts\.sh/.test(line)),
    `expected the deleted step to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals STILL flags a non-named validation step replaced with echo (Codex #4781495663)', async () => {
  // The critical negative case: a real validation step that evades
  // VALIDATION_REMOVAL_PATTERNS, replaced with `echo passed`. `run` is not an
  // allowlisted descriptive field, so the modification is NOT exempted — the
  // fail-closed catch-all this scanner exists for must still fire.
  const before = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - run: ./scripts/verify-artifacts.sh\n';
  const after = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - run: echo passed\n';
  const diff = await singleFileDiff('.github/workflows/ci.yml', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /verify-artifacts\.sh/.test(line)),
    `expected the replaced validation step to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals does NOT exempt a metadata field that smuggles a validation command', async () => {
  // Defense in depth: even an allowlisted key (`description`) is not blindly
  // exempted when its removed value reads as a validation command — the
  // VALIDATION_REMOVAL_PATTERNS guard keeps it failing closed.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.0.0', description: 'run npm test before shipping' }),
    pkg({ version: '1.0.0', description: 'a safe rewording' }),
  );
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /npm test/.test(line)),
    `expected the command-bearing description removal to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals handles a mixed diff: exempt metadata, flag weakenings together', async () => {
  // One realistic diff mixing a benign version+description bump with a lowered
  // `coverage` value and a weakened `test` script. Only the two weakenings are
  // reported; the metadata edits are exempt.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.2.3', description: 'old', coverage: 90, scripts: { test: 'jest --coverage' } }),
    pkg({ version: '1.2.4', description: 'new', coverage: 50, scripts: { test: 'echo skip' } }),
  );
  const removals = collectContentRemovals(diff);
  assert.ok(removals.some((line) => /"coverage":\s*90/.test(line)), `coverage lowering must be flagged; got ${JSON.stringify(removals)}`);
  assert.ok(removals.some((line) => /jest --coverage/.test(line)), `test weakening must be flagged; got ${JSON.stringify(removals)}`);
  assert.ok(!removals.some((line) => /"version"/.test(line)), `version bump must be exempt; got ${JSON.stringify(removals)}`);
  assert.ok(!removals.some((line) => /"description"/.test(line)), `description bump must be exempt; got ${JSON.stringify(removals)}`);
});
