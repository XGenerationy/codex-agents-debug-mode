const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const {
  closeSync, constants, readFileSync, readSync, writeSync,
} = require('node:fs');
const { mkdtemp, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { symlink } = require('node:fs/promises');

const {
  assertNotSymlink,
  isSameLockIdentity,
  openNoFollow,
  openNoFollowFlagAttempts,
  openNoFollowSync,
} = require('./pr_closeout_fs');

test('openNoFollow defaults to O_RDONLY when flags are omitted', async () => {
  // Suppression/gate scanners call openNoFollow(path) with no flags. After the
  // shared helper was extracted, rejecting missing flags would crash closeout
  // reads; default to O_RDONLY so one-argument callers stay valid while string
  // flags still throw.
  const dir = await mkdtemp(path.join(tmpdir(), 'closeout-fs-'));
  const file = path.join(dir, 'sample.txt');
  try {
    await writeFile(file, 'hello-open-nofollow\n', 'utf8');
    const handle = await openNoFollow(file);
    try {
      const buf = Buffer.alloc(32);
      const { bytesRead } = await handle.read(buf, 0, buf.length, 0);
      assert.equal(buf.subarray(0, bytesRead).toString('utf8'), 'hello-open-nofollow\n');
    } finally {
      await handle.close();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('openNoFollow rejects non-integer flags', async () => {
  await assert.rejects(
    () => openNoFollow('/tmp/unused', 'r'),
    /numeric fs\.constants flags/i,
  );
  await assert.rejects(
    () => openNoFollow('/tmp/unused', 'a'),
    TypeError,
  );
});

test('openNoFollow accepts explicit numeric write flags', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'closeout-fs-w-'));
  const file = path.join(dir, 'out.txt');
  try {
    const handle = await openNoFollow(
      file,
      constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC,
      0o666,
    );
    try {
      await handle.writeFile('written\n', 'utf8');
    } finally {
      await handle.close();
    }
    const again = await openNoFollow(file);
    try {
      const buf = Buffer.alloc(16);
      const { bytesRead } = await again.read(buf, 0, buf.length, 0);
      assert.equal(buf.subarray(0, bytesRead).toString('utf8'), 'written\n');
    } finally {
      await again.close();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('assertNotSymlink tolerates ENOENT', async () => {
  await assertNotSymlink(path.join(tmpdir(), 'no-such-closeout-fs-path'), 'should not throw');
});

test('openNoFollow does not hang when the path is a FIFO', { timeout: 10000 }, async () => {
  // Suppression/gate scanners open after lstat. A TOCTOU swap to a FIFO would
  // block forever on a blocking O_RDONLY open waiting for a writer. O_NONBLOCK
  // keeps the open non-hanging so callers can fstat and reject non-regular
  // descriptors. POSIX-only: Windows Node cannot see POSIX FIFOs.
  if (process.platform === 'win32') return;
  if (!(constants.O_NONBLOCK > 0)) return;
  const dir = await mkdtemp(path.join(tmpdir(), 'closeout-fs-fifo-'));
  const fifo = path.join(dir, 'raced.fifo');
  try {
    execFileSync('mkfifo', [fifo]);
    const handle = await openNoFollow(fifo);
    try {
      const info = await handle.stat();
      assert.equal(info.isFile(), false, 'FIFO must not report as a regular file');
    } finally {
      await handle.close();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('openNoFollowSync defaults to O_RDONLY when flags are omitted', async () => {
  // Sync mirror of the openNoFollow default-flags test above -- support.js's
  // writeEvidenceFile consumes this synchronously, so it needs the same
  // one-argument-stays-valid contract as its async counterpart.
  const dir = await mkdtemp(path.join(tmpdir(), 'closeout-fs-sync-'));
  const file = path.join(dir, 'sample.txt');
  try {
    await writeFile(file, 'hello-open-nofollow-sync\n', 'utf8');
    const fd = openNoFollowSync(file);
    try {
      const buf = Buffer.alloc(32);
      const bytesRead = readSync(fd, buf, 0, buf.length, 0);
      assert.equal(buf.subarray(0, bytesRead).toString('utf8'), 'hello-open-nofollow-sync\n');
    } finally {
      closeSync(fd);
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('openNoFollowSync rejects non-integer flags', () => {
  assert.throws(
    () => openNoFollowSync('/tmp/unused', 'r'),
    /numeric fs\.constants flags/i,
  );
  assert.throws(
    () => openNoFollowSync('/tmp/unused', 'a'),
    TypeError,
  );
});

test('openNoFollowSync accepts explicit numeric write flags and round-trips content', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'closeout-fs-sync-w-'));
  const file = path.join(dir, 'out.txt');
  try {
    const fd = openNoFollowSync(
      file,
      constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC,
      0o600,
    );
    try {
      writeSync(fd, 'written-sync\n', null, 'utf8');
    } finally {
      closeSync(fd);
    }
    assert.equal(readFileSync(file, 'utf8'), 'written-sync\n');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('openNoFollowSync refuses to follow a symlink swapped in for the target', { skip: (process.platform === 'win32' || !(constants.O_NOFOLLOW > 0)) && 'requires O_NOFOLLOW support' }, async () => {
  // This is the exact TOCTOU this function exists to close (chatgpt-codex-
  // connector PR7 #6Yawd4): writeEvidenceFile's lstatSync guard runs, then
  // (in a real attack) a symlink gets replanted before the open. Proving the
  // open itself refuses to follow a symlink -- not just that a caller-side
  // lstat happened to catch it earlier -- is what distinguishes this from the
  // pre-fix openSync(target, 'w') call.
  const dir = await mkdtemp(path.join(tmpdir(), 'closeout-fs-sync-symlink-'));
  const secret = path.join(dir, 'secret.txt');
  const link = path.join(dir, 'evidence.json');
  try {
    await writeFile(secret, 'do-not-overwrite\n', 'utf8');
    await symlink(secret, link);
    assert.throws(
      () => openNoFollowSync(link, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC, 0o600),
      /ELOOP/,
    );
    assert.equal(readFileSync(secret, 'utf8'), 'do-not-overwrite\n', 'the symlink target must be left untouched');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('isSameLockIdentity rejects a same-ctime inode reuse when birthtime differs', () => {
  // Codex UkAeu: ctimeMs has only millisecond resolution, so an unlink+recreate
  // that reuses the freed inode AND lands in the same millisecond can collide
  // on dev/ino/nlink/ctimeMs all at once. A ctime-only predicate would then
  // call two genuinely different files the same lock and let a reclaim
  // quarantine a peer's live successor. These lock/claim records have their
  // ctime bumped after creation (ACL protection, content writes) while
  // birthtime stays pinned to creation, so the stale record's birthtime stays
  // older than a same-millisecond successor's -- an independent second time
  // dimension the collision must also clear.
  const stale = { ino: 77, dev: 3, nlink: 1, ctimeMs: 5000, birthtimeMs: 1000 };
  // Reused inode, ctimeMs collides inside the same ms, but the successor was
  // actually born later -> birthtimeMs differs -> not the same file. This
  // assertion fails on the ctime-only predicate (which returns true here).
  const collidingSuccessor = { ino: 77, dev: 3, nlink: 1, ctimeMs: 5000, birthtimeMs: 5000 };
  assert.equal(isSameLockIdentity(stale, collidingSuccessor), false);

  // Genuine same file: every dimension including the immutable birthtime
  // matches, so a real stale record stays reclaimable (no false rejection).
  const untouchedSameFile = { ino: 77, dev: 3, nlink: 1, ctimeMs: 5000, birthtimeMs: 1000 };
  assert.equal(isSameLockIdentity(stale, untouchedSameFile), true);

  // The common unlink+recreate case (fresh change time) is still rejected on
  // ctimeMs alone -- the new birthtime term does not weaken the existing guard.
  const freshCtimeSuccessor = { ino: 77, dev: 3, nlink: 1, ctimeMs: 6000, birthtimeMs: 6000 };
  assert.equal(isSameLockIdentity(stale, freshCtimeSuccessor), false);
});

test('openNoFollowFlagAttempts keeps NOFOLLOW when NONBLOCK is unsupported', () => {
  // Regression for Qodo review #4780104996: a broken fallback retried
  // flags|NONBLOCK twice and never tried flags|NOFOLLOW, so platforms that
  // reject NONBLOCK (or the combo) fell through to a plain following open
  // even when NOFOLLOW alone would have worked.
  const flags = 0;
  const noFollow = 0x100;
  const nonBlock = 0x800;
  assert.deepEqual(openNoFollowFlagAttempts(flags, noFollow, nonBlock), [
    flags | noFollow | nonBlock,
    flags | nonBlock,
    flags | noFollow,
    flags,
  ]);
  // Single-extra platforms: preferred then plain only (no duplicate retries).
  assert.deepEqual(openNoFollowFlagAttempts(flags, noFollow, 0), [
    flags | noFollow,
    flags,
  ]);
  assert.deepEqual(openNoFollowFlagAttempts(flags, 0, nonBlock), [
    flags | nonBlock,
    flags,
  ]);
  assert.deepEqual(openNoFollowFlagAttempts(flags, 0, 0), [flags]);
});

test('openNoFollowFlagAttempts with requireNoFollow drops every attempt that lacks NOFOLLOW (CodeRabbit PR7 #6Yb1dD)', () => {
  // A destructive, truncating write cannot safely fall back to a
  // link-following open the way a read can (a read's result can simply be
  // discarded; a truncating write destroys its target the instant open
  // succeeds). requireNoFollow removes the NONBLOCK-only and fully-bare
  // fallback attempts, so the retry loop can never land on a combo that
  // omits real NOFOLLOW protection when the platform actually has it.
  const flags = 0;
  const noFollow = 0x100;
  const nonBlock = 0x800;
  assert.deepEqual(openNoFollowFlagAttempts(flags, noFollow, nonBlock, true), [
    flags | noFollow | nonBlock,
    flags | noFollow,
  ], 'both remaining attempts must carry NOFOLLOW; NONBLOCK-only and bare flags are both dropped');
  // On a platform where O_NOFOLLOW is entirely unavailable (noFollow === 0,
  // e.g. Windows), OR'ing it into every attempt is already a no-op -- there
  // is no attempt that COULD carry real protection either way, so this must
  // NOT throw or produce an empty list; it degrades to whatever nonBlock
  // alone provides, identical to what already happens today on those
  // platforms (their real protection is the caller's own lstat guard, not
  // this function).
  assert.deepEqual(openNoFollowFlagAttempts(flags, 0, nonBlock, true), [flags | nonBlock],
    'a platform with no O_NOFOLLOW constant must still get a usable attempt list, not an empty one');
  assert.deepEqual(openNoFollowFlagAttempts(flags, 0, 0, true), [flags],
    'a platform with neither extra flag must still get the plain attempt');
});
