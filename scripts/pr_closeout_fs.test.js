const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const {
  closeSync, constants, lstatSync, readFileSync, readSync, writeSync,
} = require('node:fs');
const { mkdtemp, rm, writeFile } = require('node:fs/promises');
const { EventEmitter } = require('node:events');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { symlink } = require('node:fs/promises');

const {
  assertNotSymlink,
  fileIdentity,
  isSameFileIdentity,
  isSameLockIdentity,
  isSameProtectedFileIdentity,
  openNoFollow,
  openNoFollowFlagAttempts,
  openNoFollowSync,
  PROTECT_WINDOWS_PRIVATE_FILE_EXEC_OPTIONS,
  PROTECT_WINDOWS_PRIVATE_FILE_TIMEOUT_MS,
  protectWindowsPrivateFile,
  protectWindowsPrivateFileAsync,
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

// Shared fixture builder: every predicate below consumes the normalized record
// fileIdentity produces, so the tests are written in that shape rather than in
// raw Stats. dev/ino are decimal STRINGS (exact at any width) and the time
// terms the lock predicate compares are nanosecond strings.
const idRecord = (over = {}) => ({
  dev: '1', ino: '42', nlink: 1,
  ctimeMs: 5000, ctimeNs: '5000000000',
  birthtimeMs: 1000, birthtimeNs: '1000000000',
  mtimeMs: 5000, size: 10, isFile: true, isSymbolicLink: false,
  ...over,
});

// Two DISTINCT NTFS file references one apart, both above 2**53. An NTFS file
// reference is (16-bit sequence << 48) | 48-bit MFT record, so it crosses 2**53
// once the sequence number reaches 32 -- routine on a volume whose MFT records
// have been recycled. At this magnitude the float64 ULP is 16, so these two
// references round to the SAME double.
const NTFS_REF_A = '81909218225795111';
const NTFS_REF_B = '81909218225795112';

test('isSameFileIdentity separates two distinct files whose inodes collide as float64', () => {
  // THE REGRESSION THIS FIXTURE EXISTS FOR. Before the identity record, every
  // caller captured ino from a default lstat -- a Number -- and compared it
  // with ===. Measured on Windows 10 19045 / NTFS: one fresh file whose true
  // reference was 81909218225795110 read back as 81909218225795100, and 800
  // files created in a single directory reported 797 distinct Number inos
  // against 800 distinct BigInt inos, with isSameFileIdentity returning TRUE
  // for two different files whose references were 17 apart. That is a
  // fail-open in every caller: an evidence file, a session log, a collector
  // token, or a port file could be certified as "still the same file" after
  // being swapped for a different one.
  //
  // The precondition is asserted rather than assumed -- if a future Node or
  // platform made these two values distinct as Numbers, this test would still
  // pass while silently no longer covering the regime it was written for.
  assert.equal(
    Number(NTFS_REF_A) === Number(NTFS_REF_B),
    true,
    'fixture precondition: the two references must collapse onto one double',
  );
  assert.notEqual(NTFS_REF_A, NTFS_REF_B, 'fixture precondition: the references are distinct');

  const pre = idRecord({ ino: NTFS_REF_A });
  const post = idRecord({ ino: NTFS_REF_B });
  assert.equal(isSameFileIdentity(pre, post), false);
  // The two stricter predicates compose the lax one, so neither may inherit
  // the false match. The birth/ctime terms are held equal here deliberately:
  // the ino term alone has to do the rejecting.
  assert.equal(isSameProtectedFileIdentity(pre, post), false);
  assert.equal(isSameLockIdentity(pre, post), false);
  // A genuine same-file comparison at the same magnitude still passes, so the
  // fix rejects the collision rather than everything above 2**53.
  assert.equal(isSameFileIdentity(pre, idRecord({ ino: NTFS_REF_A })), true);
});

test('the predicates fail closed on a Number ino instead of silently comparing float64', () => {
  // The migration is enforced by the predicate, not by review. A caller that
  // still passed a default Stats would otherwise clear the `ino !== '0'` guard
  // vacuously (a Number is never strictly equal to a string) and fall straight
  // back into the float64 comparison the record exists to remove -- the same
  // check, reading as hardened, silently unhardened.
  const numeric = { dev: 1, ino: 42, nlink: 1, ctimeMs: 5000, birthtimeMs: 1000 };
  assert.equal(isSameFileIdentity(numeric, { ...numeric }), false, 'a Number-ino pair must not certify identity');
  assert.equal(isSameFileIdentity(numeric, idRecord()), false);
  assert.equal(isSameFileIdentity(idRecord(), numeric), false);
  assert.equal(isSameProtectedFileIdentity(numeric, { ...numeric }), false);
  assert.equal(isSameLockIdentity(numeric, { ...numeric }), false);
  // And the collision itself, in the shape a pre-fix caller would have used:
  // this exact pair returned TRUE before the fix.
  assert.equal(
    isSameFileIdentity(
      { dev: 1, ino: Number(NTFS_REF_A), nlink: 1 },
      { dev: 1, ino: Number(NTFS_REF_B), nlink: 1 },
    ),
    false,
  );
});

test('fileIdentity refuses a default Stats and normalizes a bigint one exactly', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'closeout-fs-identity-'));
  try {
    const file = path.join(dir, 'probe.txt');
    await writeFile(file, 'probe\n', 'utf8');
    // The wrong input fails loudly at the capture site. Stringifying an
    // already-rounded Number would read as exact while carrying the defect.
    assert.throws(() => fileIdentity(lstatSync(file)), /bigint/i);
    assert.throws(() => fileIdentity(undefined), /bigint/i);

    const big = lstatSync(file, { bigint: true });
    const identity = fileIdentity(big);
    assert.equal(identity.dev, String(big.dev));
    assert.equal(identity.ino, String(big.ino));
    assert.equal(identity.ctimeNs, String(big.ctimeNs));
    assert.equal(typeof identity.dev, 'string');
    assert.equal(typeof identity.ino, 'string');
    // The scalars callers compare against Numbers must NOT stay BigInt: with a
    // raw bigint Stats `info.size !== identity.bytesWritten` and
    // `info.nlink !== 1` become permanently true while relational forms keep
    // working -- an inconsistent, partly silent failure.
    assert.equal(typeof identity.nlink, 'number');
    assert.equal(typeof identity.size, 'number');
    assert.equal(typeof identity.mtimeMs, 'number');
    assert.equal(identity.isFile, true);
    assert.equal(identity.isSymbolicLink, false);
    // The record must survive the /session mint's JSON response; a BigInt
    // field would throw here and turn that mint into a 500.
    assert.equal(JSON.parse(JSON.stringify(identity)).ino, String(big.ino));
    // A real file compares equal to itself across two independent captures.
    assert.equal(isSameFileIdentity(identity, fileIdentity(lstatSync(file, { bigint: true }))), true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('isSameLockIdentity fails closed on records that omit the nanosecond terms', () => {
  // Codex review, P3: hasExactIdentity only vouches for dev/ino, so two records
  // that simply OMIT both ns fields compared `undefined === undefined` and this
  // predicate returned TRUE for them. That is the same vacuous pass the string
  // ino was introduced to remove, arriving through the SHAPE of the input
  // rather than the width of a Number -- a caller holding a half-built record
  // (or a stale wire object) would have been told two files are the same lock
  // on the strength of two missing fields.
  //
  // The lax and protected predicates deliberately do NOT require these: their
  // preInfo is legitimately partial (the /session mint ships dev, ino and
  // birthtimeMs and nothing else), so demanding ns there would abort every
  // deferred start. isSameLockIdentity's callers always hold a full record.
  const partial = { dev: '1', ino: '2', nlink: 1 };
  assert.equal(isSameLockIdentity(partial, { ...partial }), false, 'omitted ns terms must never compare equal');
  assert.equal(isSameLockIdentity({ ...partial, ctimeNs: '5000000000' }, { ...partial, ctimeNs: '5000000000' }), false, 'a missing birthtimeNs is still a missing term');
  assert.equal(isSameLockIdentity({ ...partial, birthtimeNs: '1000000000' }, { ...partial, birthtimeNs: '1000000000' }), false, 'a missing ctimeNs is still a missing term');
  // A non-string ns (the pre-normalization Number shape) is refused for the
  // same reason the ino terms refuse one.
  assert.equal(isSameLockIdentity(
    { ...partial, ctimeNs: 5000000000, birthtimeNs: 1000000000 },
    { ...partial, ctimeNs: 5000000000, birthtimeNs: 1000000000 },
  ), false, 'a Number ns must not certify a lock identity');
  // The complete record still compares equal, so this fails closed on the
  // missing shape rather than on everything.
  assert.equal(isSameLockIdentity(idRecord(), idRecord()), true, 'a full record is not rejected');
  // And the lax/protected predicates are NOT tightened by this: the partial
  // wire shape they are contracted to accept still passes.
  assert.equal(isSameFileIdentity(partial, { ...partial }), true, 'the lax predicate still accepts a partial record');
  assert.equal(isSameProtectedFileIdentity({ dev: '1', ino: '42' }, idRecord()), true, 'the mint wire shape still passes the protected predicate');
});

test('isSameLockIdentity compares nanoseconds, not truncated milliseconds', () => {
  // The bigint Stats truncates ctimeMs to whole milliseconds while a default
  // Stats carries a sub-millisecond fraction (measured on this host:
  // 1787517135767.5864 against 1787517135767). Normalizing to the truncated
  // millisecond would have QUIETLY COARSENED this predicate from ~100 ns to
  // 1 ms -- a fix that weakened the guard it shipped to strengthen. These two
  // records are indistinguishable in whole milliseconds and must still be
  // rejected.
  const stale = idRecord({ ino: '77', dev: '3', ctimeMs: 5000, ctimeNs: '5000000000' });
  const subMsSuccessor = idRecord({ ino: '77', dev: '3', ctimeMs: 5000, ctimeNs: '5000123400' });
  assert.equal(stale.ctimeMs, subMsSuccessor.ctimeMs, 'fixture precondition: identical in whole milliseconds');
  assert.equal(isSameLockIdentity(stale, subMsSuccessor), false);
  assert.equal(isSameLockIdentity(stale, { ...stale }), true, 'a genuine same file is not rejected');
});

test('isSameLockIdentity rejects a same-ctime inode reuse when birthtime differs', () => {
  // Codex UkAeu: an unlink+recreate that reuses the freed inode AND lands in
  // the same instant can collide on dev/ino/nlink/ctime all at once. A
  // ctime-only predicate would then call two genuinely different files the
  // same lock and let a reclaim quarantine a peer's live successor. These
  // lock/claim records have their ctime bumped after creation (ACL protection,
  // content writes) while birthtime stays pinned to creation, so the stale
  // record's birthtime stays older than a same-instant successor's -- an
  // independent second time dimension the collision must also clear.
  const stale = idRecord({ ino: '77', dev: '3', ctimeNs: '5000000000', birthtimeNs: '1000000000' });
  const collidingSuccessor = idRecord({ ino: '77', dev: '3', ctimeNs: '5000000000', birthtimeNs: '5000000000' });
  assert.equal(isSameLockIdentity(stale, collidingSuccessor), false);

  // Genuine same file: every dimension including the birth time matches, so a
  // real stale record stays reclaimable (no false rejection). "Unchanged for
  // this record", not "immutable" -- on NTFS a same-name recreate inherits the
  // original's creation time through file tunneling, and the owner can set it
  // outright, which is why the predicate's doc refuses to call the term
  // independent on win32.
  const untouchedSameFile = idRecord({ ino: '77', dev: '3', ctimeNs: '5000000000', birthtimeNs: '1000000000' });
  assert.equal(isSameLockIdentity(stale, untouchedSameFile), true);

  // The common unlink+recreate case (fresh change time) is still rejected on
  // the ctime term alone -- the birthtime term does not weaken the existing
  // guard.
  const freshCtimeSuccessor = idRecord({ ino: '77', dev: '3', ctimeNs: '6000000000', birthtimeNs: '6000000000' });
  assert.equal(isSameLockIdentity(stale, freshCtimeSuccessor), false);
});

test('isSameProtectedFileIdentity rejects an inode reuse the lax predicate accepts', () => {
  // POSIX inode reuse (tmpfs hands a freed ino to the next file created in the
  // directory): dev/ino/nlink cannot see it, the creation time can. This is
  // the whole reason the post-ACL callers use this predicate instead of the
  // lax one -- and the difference is asserted rather than assumed, so a future
  // edit that collapses the two is caught here.
  const preInfo = idRecord({ birthtimeMs: 1000 });
  const reusedIno = idRecord({ birthtimeMs: 5000 });
  assert.equal(isSameFileIdentity(preInfo, reusedIno), true, 'the lax predicate is blind to this swap');
  assert.equal(isSameProtectedFileIdentity(preInfo, reusedIno), false);
  assert.equal(isSameProtectedFileIdentity(preInfo, { ...preInfo }), true, 'a genuine same file is not rejected');
});

test('isSameProtectedFileIdentity skips the birth term when either side reports none', () => {
  // The deferred caller's preInfo is a JSON wire object, and mounts that do
  // not record a birth time report 0. Neither may turn a healthy check red: a
  // bare `===` would abort every deferred start on the first shape, and on the
  // second it would silently become a ctimeMs comparison (Node falls
  // birthtimeMs back to ctimeMs where statx is unavailable) -- precisely what
  // isSameFileIdentity's contract forbids for ACL-protect callers, whose
  // intervening operation legitimately moves ctimeMs.
  const real = idRecord({ birthtimeMs: 1000 });
  // The wire shape: dev/ino strings and a birth time, nothing else.
  assert.equal(isSameProtectedFileIdentity({ dev: '1', ino: '42' }, real), true);
  assert.equal(isSameProtectedFileIdentity({ ...real, birthtimeMs: 0 }, real), true);
  assert.equal(isSameProtectedFileIdentity(real, { ...real, birthtimeMs: 0 }), true);
});

test('isSameProtectedFileIdentity still rejects every shape isSameFileIdentity rejects', () => {
  // Composition, not re-implementation: the lax terms are inherited from one
  // predicate rather than re-listed here, so a hardening that lands in
  // isSameFileIdentity cannot leave the protected variant behind (the
  // one-contract-one-implementation rule this repo already paid for twice --
  // the V8a redaction parser and the V7a scalar-header regex).
  const pre = idRecord({ birthtimeMs: 1000 });
  const born = (over) => idRecord({ birthtimeMs: 1000, ...over });
  assert.equal(isSameProtectedFileIdentity({ ...pre, dev: '0', ino: '0' }, born({ dev: '0', ino: '0' })), false);
  assert.equal(isSameProtectedFileIdentity(pre, born({ ino: '43' })), false);
  assert.equal(isSameProtectedFileIdentity(pre, born({ dev: '2' })), false);
  assert.equal(isSameProtectedFileIdentity(pre, born({ nlink: 2 })), false);
  // The zero-ino rejection specifically: the literal is the STRING '0' now, and
  // a stale `!== 0` would compare a string against a number, never match, and
  // silently retire the guard its comment exists to enforce.
  assert.equal(isSameFileIdentity(idRecord({ ino: '0' }), idRecord({ ino: '0' })), false);
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

test('Windows ACL sync and async entry points share one frozen stdio-ignore options object', async () => {
  // stdio:'ignore' is load-bearing for BOTH paths now. execFileSync honors it,
  // so the session-mint PowerShell never leaves a pipe for the parent to
  // service. The async variant is built on spawn — which also honors it —
  // precisely because promisified execFile silently DROPPED `stdio` (it
  // always buffers through pipes and settles only when they close), and a
  // PowerShell descendant holding those inherited pipes open past exit hung
  // the call until the 15s timeout on hosted windows-latest (the hang that
  // forced the sync workaround in 31c1f48). Drive both entry points through
  // their exec seams so the assertions cover the actual invocation — the
  // object reference, timeout, and windowsHide — not source text.
  assert.equal(PROTECT_WINDOWS_PRIVATE_FILE_EXEC_OPTIONS.stdio, 'ignore');
  assert.equal(PROTECT_WINDOWS_PRIVATE_FILE_EXEC_OPTIONS.timeout, PROTECT_WINDOWS_PRIVATE_FILE_TIMEOUT_MS);
  assert.equal(PROTECT_WINDOWS_PRIVATE_FILE_EXEC_OPTIONS.windowsHide, true);
  assert.ok(
    Object.isFrozen(PROTECT_WINDOWS_PRIVATE_FILE_EXEC_OPTIONS),
    'shared options must stay frozen',
  );
  const calls = [];
  // A ChildProcess stand-in: an EventEmitter that reports the given exit. The
  // helper must settle on 'exit'/'error' alone — it has no pipes to wait for.
  const fakeChild = ({ code = 0, signal = null, error = null } = {}) => {
    const child = new EventEmitter();
    queueMicrotask(() => {
      if (error) child.emit('error', error);
      else child.emit('exit', code, signal);
    });
    return child;
  };
  protectWindowsPrivateFile('C:\\p\\.debug\\project_salt', {
    platform: 'win32',
    execFileSyncFn: (file, args, options) => calls.push({ entry: 'sync', file, args, options }),
  });
  await protectWindowsPrivateFileAsync('C:\\p\\.debug\\session.log', {
    platform: 'win32',
    spawnFn: (file, args, options) => {
      calls.push({ entry: 'async', file, args, options });
      return fakeChild();
    },
  });
  assert.equal(calls.length, 2);
  for (const call of calls) {
    assert.equal(
      call.options,
      PROTECT_WINDOWS_PRIVATE_FILE_EXEC_OPTIONS,
      `${call.entry} exec must receive the one shared frozen options object by reference`,
    );
    assert.match(call.file, /\\powershell\.exe$/iu);
    assert.ok(call.args.includes('-EncodedCommand'), `${call.entry} must run the fixed encoded program`);
  }
  // Off Windows both entry points are no-ops that never reach exec.
  const never = () => { throw new Error('never reached off-Windows'); };
  protectWindowsPrivateFile('/p/.debug/project_salt', { platform: 'linux', execFileSyncFn: never });
  await protectWindowsPrivateFileAsync('/p/.debug/session.log', { platform: 'darwin', spawnFn: never });
  // Fail closed: the sync variant throws; the async variant rejects on a
  // spawn 'error' event, a synchronous spawn throw, a non-zero exit, and
  // signal death (which is also how the shared timeout's kill surfaces).
  assert.throws(
    () => protectWindowsPrivateFile('C:\\p\\.debug\\project_salt', {
      platform: 'win32', execFileSyncFn: () => { throw new Error('acl_denied'); },
    }),
    /acl_denied/,
  );
  await assert.rejects(
    protectWindowsPrivateFileAsync('C:\\p\\.debug\\session.log', {
      platform: 'win32', spawnFn: () => fakeChild({ error: new Error('acl_denied') }),
    }),
    /acl_denied/,
  );
  await assert.rejects(
    protectWindowsPrivateFileAsync('C:\\p\\.debug\\session.log', {
      platform: 'win32', spawnFn: () => { throw new Error('spawn_refused'); },
    }),
    /spawn_refused/,
  );
  await assert.rejects(
    protectWindowsPrivateFileAsync('C:\\p\\.debug\\session.log', {
      platform: 'win32', spawnFn: () => fakeChild({ code: 5 }),
    }),
    /windows_private_file_acl_failed: 5/,
  );
  await assert.rejects(
    protectWindowsPrivateFileAsync('C:\\p\\.debug\\session.log', {
      platform: 'win32', spawnFn: () => fakeChild({ code: null, signal: 'SIGTERM' }),
    }),
    /windows_private_file_acl_failed: SIGTERM/,
  );
  // BACKSTOP DEADLINE (review V2c hardening): spawn's shared timeout issues
  // TerminateProcess, but 'exit' fires only once the kernel finishes tearing
  // every thread down — a thread wedged in a non-alertable kernel wait can
  // defer that indefinitely, and a promise settling only on 'error'/'exit'
  // would hold its awaiting mint open forever. The reject is the load-bearing
  // half; the extra kill is best-effort.
  const wedged = new EventEmitter();
  let kills = 0;
  wedged.kill = () => { kills += 1; };
  // The deadline timer is unref'd BY DESIGN (production callers hold a live
  // server handle, and a settled call must never hold the process open), so
  // in this bare test process it must not be the loop's ONLY handle: with
  // nothing else referenced, Node 20/22 drain the event loop before the
  // 20ms deadline fires and the runner cancels the still-pending test
  // (cancelledByParent — Validate run 32642837205). A REFERENCED WATCHDOG
  // rather than a bare keep-alive (Codex): it holds the loop open to the
  // deadline AND, should the backstop ever stop settling the promise, loses
  // the race with a non-matching error so the test fails fast and directly
  // instead of parking until the runner cancels it again.
  let watchdog;
  const watchdogFired = new Promise((unusedResolve, rejectWatch) => {
    watchdog = setTimeout(
      () => rejectWatch(new Error('deadline backstop never settled the wedged promise within 500ms')),
      500,
    );
  });
  try {
    await assert.rejects(
      Promise.race([
        protectWindowsPrivateFileAsync('C:\\p\\.debug\\session.log', {
          platform: 'win32', spawnFn: () => wedged, deadlineMs: 20,
        }),
        watchdogFired,
      ]),
      /windows_private_file_acl_failed: deadline/,
    );
  } finally {
    clearTimeout(watchdog);
  }
  assert.equal(kills, 1, 'the deadline still attempts to kill the wedged child');
  // A late 'exit' after settlement lands on an already-settled promise: a
  // no-op, never a second settlement or an unhandled rejection.
  wedged.emit('exit', 0, null);
});
