const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { constants } = require('node:fs');
const { mkdtemp, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  assertNotSymlink,
  isSameLockIdentity,
  openNoFollow,
  openNoFollowFlagAttempts,
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
