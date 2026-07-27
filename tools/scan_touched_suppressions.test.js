const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { mkdtemp, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { getComparisonStyle, resolveBaseSha } = require('./scan_touched_suppressions');

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
    'Gemfile.lock', 'gradle.lockfile', 'bun.lockb',
  ]) {
    assert.equal(isMechanicalLockfile(file), true, `${file} should be a lockfile`);
  }
  // Non-lockfile gate/config files must NOT be excluded — they can hold real
  // validation steps/scripts and must remain in the fail-closed scan.
  for (const file of ['package.json', 'tsconfig.json', '.eslintrc.json', 'Makefile']) {
    assert.equal(isMechanicalLockfile(file), false, `${file} must not be treated as a lockfile`);
  }
});
