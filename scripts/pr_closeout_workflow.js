const { randomBytes } = require('node:crypto');
const {
  closeSync,
  constants: fsConstants,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
} = require('node:fs');
const { tmpdir } = require('node:os');
const {
  link, lstat, mkdir, mkdtemp, open: openFile, realpath, rename, rm, stat, unlink,
} = require('node:fs/promises');
const path = require('node:path');

const { buildCheckPlan } = require('./pr_closeout_core');
const { fileIdentity, isSameLockIdentity, openNoFollow } = require('./pr_closeout_fs');
const {
  classifyGateIntegrity,
  digestValidationConfig,
  verifyBaseline,
  verifyGeneratorReproducibility,
} = require('./pr_closeout_git');
const {
  gateAttestationMarker, readLiveGateAttestation, readLivePrState, revokeDelegatedGhToken,
} = require('./pr_closeout_github');
const { createCommandExecutor, redactStructure, runPreflight, TOOL_PROBES } = require('./pr_closeout_process');
const { writeEvidenceReport } = require('./pr_closeout_report');
const {
  cleanTreeStatus,
  readGateChanges,
  readProjectMetadata,
  resolveRepositoryState,
  scanTouchedSuppressions,
  workingTreeFingerprint,
} = require('./pr_closeout_repo');
const { blockedConfirmationRows, runValidationPhases } = require('./pr_closeout_runner');

const DEFAULTS = {
  cleanTreeStatus,
  createCommandExecutor,
  digestValidationConfig,
  readGateChanges,
  readLiveGateAttestation,
  readLivePrState,
  readProjectMetadata,
  resolveRepositoryState,
  runPreflight,
  scanTouchedSuppressions,
  verifyBaseline,
  workingTreeFingerprint,
  writeEvidenceReport,
};

/**
 * Reduces every sub-check's status to one final verdict. Any suppression
 * marker found in touched files is an automatic FAIL regardless of what else
 * passed — the Zero-Suppression policy overrides everything. Otherwise: any
 * component FAIL wins; a BASELINE result (head failure reproduced exactly at
 * base — pre-existing, not introduced by this PR) is treated the same as
 * BLOCKED rather than silently passed; and PASS requires every tracked
 * status to be exactly 'PASS', with any other combination falling back to
 * BLOCKED rather than defaulting optimistically to PASS.
 * @returns {'PASS'|'FAIL'|'BLOCKED'}
 */
const evaluateOverallStatus = ({
  planStatus,
  preflight,
  gateIntegrity,
  phases,
  reproducibility,
  preGithubCleanTree,
  cleanTree,
  headConsistency,
  repositorySeal,
  livePrState,
  suppressionFindings = [],
}) => {
  if (suppressionFindings.length) return 'FAIL';
  const statuses = [
    planStatus,
    preflight?.status,
    gateIntegrity?.status,
    phases?.status,
    reproducibility?.status,
    // Pre-GitHub dirty-tree probes are first-class status inputs so a
    // transient dirt that later cleans up cannot be ignored even if the
    // fold-into-cleanTree path is skipped or mis-wired.
    preGithubCleanTree?.status,
    cleanTree?.status,
    headConsistency?.status,
    repositorySeal?.status,
    livePrState?.status,
  ];
  if (statuses.includes('FAIL')) return 'FAIL';
  if (statuses.some((status) => ['BLOCKED', 'BASELINE'].includes(status))) return 'BLOCKED';
  return statuses.every((status) => status === 'PASS') ? 'PASS' : 'BLOCKED';
};

/**
 * A check plan is only PASS if every configured check both resolved to a
 * runnable `command` and isn't itself already BLOCKED (e.g. an unresolved
 * dependency); a plan-building error is a hard FAIL, and any other gap
 * (missing command, pre-blocked check) falls back to BLOCKED rather than
 * silently passing.
 * @param {{errors: unknown[], checks: {command?: string, status?: string}[]}} plan
 * @returns {'PASS'|'FAIL'|'BLOCKED'}
 */
const planStatusFor = (plan) => {
  if (plan.errors.length) return 'FAIL';
  return plan.checks.every(({ command, status }) => command && status !== 'BLOCKED') ? 'PASS' : 'BLOCKED';
};

/**
 * Default evidence output directory when the caller doesn't supply one:
 * under the OS tmpdir, namespaced by a filesystem-safe repo basename, the
 * short head SHA, a filesystem-safe timestamp, and a process-unique suffix
 * (pid + random), so concurrent runs against the same repo/head never share
 * an evidence directory even when they start in the same millisecond
 * (Codex #4780351874). Without the unique suffix, independently numbered
 * attempt logs and final reports can truncate/interleave and one run may
 * return PASS while its on-disk evidence belongs partly to the other.
 * @param {string} repo
 * @param {string} headSha
 * @returns {string}
 */
const defaultOutputDir = (repo, headSha) => {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const name = path.basename(repo).replace(/[^a-z0-9_-]/gi, '-');
  const unique = `${process.pid}-${randomBytes(4).toString('hex')}`;
  return path.join(tmpdir(), 'codex-pr-closeout', `${name}-${headSha.slice(0, 12)}-${stamp}-${unique}`);
};

/**
 * Throws unless `outputDir` resolves outside `repo`. Evidence must never be
 * written inside the repository it is validating: it would then be
 * (un)tracked content the working-tree/suppression scans have to reason
 * about, and a later run could pick up a previous run's evidence as part of
 * the very tree it is fingerprinting. Called against both logical and
 * realpath'd (symlink-resolved) path pairs by `prepareOutputDirectory`.
 * @param {string} repo
 * @param {string} outputDir
 */
const assertOutputOutsideRepository = (repo, outputDir) => {
  const relative = path.relative(path.resolve(repo), path.resolve(outputDir));
  const inside = relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
  if (inside) throw new Error(`Evidence output must be outside the repository: ${outputDir}`);
};

/**
 * Resolves the realpath `target` would have once created, even though it
 * (and possibly several trailing segments) doesn't exist yet: `realpath`
 * throws ENOENT on a nonexistent path, so this walks up to the nearest
 * ancestor that does exist, resolves that ancestor through symlinks, and
 * rejoins the missing trailing segments on top. Falls back to the original
 * `target` if no ancestor exists at all (e.g. root). Lets
 * `prepareOutputDirectory` check the *physical* output location against the
 * repository before `mkdir` ever runs, so a symlinked ancestor can't make an
 * outside-looking path actually land inside the repo.
 * @param {string} target
 * @param {(path: string) => Promise<string>} realpathPath
 * @returns {Promise<string>}
 */
const resolvePhysicalTarget = async (target, realpathPath) => {
  const missing = [];
  let current = target;
  while (true) {
    try {
      const resolved = await realpathPath(current);
      return missing.length ? path.join(resolved, ...missing.reverse()) : resolved;
    } catch (error) {
      if (error && error.code !== 'ENOENT') throw error;
      const parent = path.dirname(current);
      if (parent === current) return target;
      missing.push(path.basename(current));
      current = parent;
    }
  }
};

/**
 * Creates the evidence output directory, defending against symlink TOCTOU:
 * checks `outputDir` against `repo` three times — the plain resolved paths,
 * the physical (symlink-resolved) paths before `mkdir` runs (via
 * `resolvePhysicalTarget`, since the directory doesn't exist yet), and the
 * physical paths again after `mkdir` actually creates it. A symlink planted
 * as the repo root or anywhere along the output path — even one that only
 * becomes resolvable once the directory exists — cannot smuggle the evidence
 * write inside the repository it describes. `mkdirPath`/`realpathPath` are
 * injectable for tests; callers use the real `fs/promises` implementations.
 * Invoked again later in the workflow immediately before each evidence
 * write, not just once at startup.
 * @returns {Promise<string>} the resolved output directory path.
 */
/**
 * Acquire an exclusive run lock under an explicit --output-dir so two closeout
 * processes cannot share report.json / command logs (Codex #4781560042).
 * Default (process-unique) dirs do not need this; stale locks from dead PIDs
 * are reclaimed. The stale-holder recovery read goes through `readLockFile`
 * (see readOutputDirLockFile) so a special lock file — FIFO, symlink, device —
 * can neither block the read nor redirect it outside the evidence directory
 * (Codex #UDDQC). `readLockFile` is injectable for tests, matching the
 * mkdirPath/realpathPath seam of prepareOutputDirectory.
 * @param {string} outputDir
 * @param {{readLockFile?: (lockPath: string) => Promise<string>}} [deps]
 * @returns {Promise<import('node:fs/promises').FileHandle>}
 */
/**
 * @typedef {{ handle: import('node:fs/promises').FileHandle, path: string, nonce: string, dirIdentity: {dev: string, ino: string}, release: () => Promise<void> }} OutputDirLock
 */

// Upper bound for a .closeout.lock payload (`pid\nnonce\niso\n` — well under
// 1 KiB). Anything larger is foreign/corrupt, not a live holder record.
const OUTPUT_DIR_LOCK_MAX_BYTES = 4096;
// `open(O_CREAT|O_EXCL)` makes the name visible before the initial payload
// write completes. Never reclaim an empty/incomplete lock from that short
// creation window, or a second closeout can unlink an active holder.
const OUTPUT_DIR_LOCK_INITIALIZING_GRACE_MS = 5_000;

/**
 * Extract the holder identity from a complete lock payload. The timestamp is
 * intentionally not part of identity: pid + nonce is the ownership tuple
 * that release and stale recovery must agree on.
 * @param {string} text
 * @returns {{pid: number, nonce: string}|null}
 */
const outputDirLockHolder = (text) => {
  const lines = String(text).split(/\r?\n/);
  const pid = Number(String(lines[0] || '').trim());
  const nonce = String(lines[1] || '').trim();
  return Number.isInteger(pid) && pid > 0 && nonce ? { pid, nonce } : null;
};

/**
 * Synchronous counterpart to readOutputDirLockFile for the process `exit`
 * handler. Exit hooks cannot await, but they must retain the same no-follow,
 * regular-file, bounded-read, and descriptor-identity checks before they
 * consider unlinking a lock. If any guard cannot be established, the handler
 * fails closed and stale recovery cleans up later.
 * @param {string} lockPath
 * @returns {string}
 */
const readOutputDirLockFileSync = (lockPath) => {
  const before = lstatSync(lockPath);
  if (!before.isFile() || before.size > OUTPUT_DIR_LOCK_MAX_BYTES) {
    throw new Error(`Evidence lock is not a size-bounded regular file: ${lockPath}`);
  }
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW || 0) | (fsConstants.O_NONBLOCK || 0);
  const descriptor = openSync(lockPath, flags);
  try {
    const info = fstatSync(descriptor);
    if (
      !info.isFile()
      || info.size > OUTPUT_DIR_LOCK_MAX_BYTES
      || info.dev !== before.dev
      || info.ino !== before.ino
    ) {
      throw new Error(`Evidence lock changed while opening: ${lockPath}`);
    }
    const buffer = Buffer.alloc(info.size);
    let offset = 0;
    while (offset < info.size) {
      const bytesRead = readSync(descriptor, buffer, offset, info.size - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    return buffer.subarray(0, offset).toString('utf8');
  } finally {
    closeSync(descriptor);
  }
};

/**
 * Read an existing .closeout.lock for stale-holder recovery without ever
 * blocking or following a link: open through openNoFollow (the shared
 * no-follow/nonblocking attempt ladder from pr_closeout_fs.js) and re-verify
 * via the descriptor that the lock is still a regular file within
 * OUTPUT_DIR_LOCK_MAX_BYTES before reading — the same guarded bounded-read
 * pattern hashFile and the debug collector's readSmallRegularFile use. A FIFO
 * would otherwise park readFile waiting for a writer and a symlink could
 * redirect the read to an unbounded file (Codex #UDDQC). Any guard failure
 * throws so the caller's catch treats the lock exactly like a corrupt/foreign
 * one (dead-holder reclaim), preserving today's recovery semantics.
 * @param {string} lockPath
 * @returns {Promise<string>} raw lock payload.
 */
const readOutputDirLockFile = async (lockPath) => {
  const before = await lstat(lockPath);
  if (!before.isFile() || before.size > OUTPUT_DIR_LOCK_MAX_BYTES) {
    throw new Error(`Evidence lock is not a size-bounded regular file: ${lockPath}`);
  }
  const handle = await openNoFollow(lockPath, fsConstants.O_RDONLY);
  try {
    const info = await handle.stat();
    if (
      !info.isFile()
      || info.size > OUTPUT_DIR_LOCK_MAX_BYTES
      || info.dev !== before.dev
      || info.ino !== before.ino
    ) {
      throw new Error(`Evidence lock changed while opening: ${lockPath}`);
    }
    const buffer = Buffer.alloc(info.size);
    let offset = 0;
    while (offset < info.size) {
      const { bytesRead } = await handle.read(buffer, offset, info.size - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    return buffer.subarray(0, offset).toString('utf8');
  } finally {
    await handle.close().catch(() => {});
  }
};

const acquireOutputDirLock = async (outputDir, { readLockFile = readOutputDirLockFile, statPath = stat } = {}) => {
  const lockPath = path.join(outputDir, '.closeout.lock');
  const nonce = `${process.pid}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  const payload = `${process.pid}\n${nonce}\n${new Date().toISOString()}\n`;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const handle = await openFile(
        lockPath,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
        0o600,
      );
      try {
        await handle.writeFile(payload, 'utf8');
      } catch (error) {
        await handle.close().catch(() => {});
        throw error;
      }
      // Recorded so later prepareOutputDirectory calls in this same run can
      // confirm outputDir still names the directory this lock was acquired
      // against, rather than a same-user swap-in-place replacement (Codex
      // finding: "Bind the evidence lock to the output directory inode").
      let dirIdentity;
      try {
        // Normalized to exact decimal strings, like every other identity
        // binding in this repo: a default stat reports ino as a Number, and an
        // NTFS file reference above 2**53 is rounded to float64, so two
        // DIFFERENT directories can compare equal here (see fileIdentity in
        // pr_closeout_fs.js for the measurements). A swap-detection check that
        // can be defeated by rounding is not swap detection.
        dirIdentity = fileIdentity(await statPath(outputDir, { bigint: true }));
        // Some filesystems (notably Windows FAT/network mounts) report
        // dev/ino as 0 for every path, which would make the swap-detection
        // comparisons below and in assertOutputDirLockIdentity pass
        // vacuously for a same-path replacement. Fail closed rather than
        // record an identity that provides no actual guarantee. The literal is
        // the STRING '0' -- a `=== 0` here would never match a normalized ino
        // and would silently retire this rejection.
        if (dirIdentity.ino === '0') {
          throw new Error(
            `Filesystem does not report a usable directory identity for ${outputDir}; refusing to rely on dev/ino swap detection.`,
          );
        }
      } catch (error) {
        // A rejecting statPath (EACCES/ENOENT/EIO) must get the same cleanup
        // as the ino===0 case above: the lock file is already on disk with
        // this process's live PID recorded inside it, and no exit listener
        // is registered yet, so leaving it behind here would permanently
        // block the output directory for every subsequent run (CodeRabbit
        // review).
        await handle.close().catch(() => {});
        await unlink(lockPath).catch(() => {});
        throw error;
      }
      let released = false;
      const release = async () => {
        if (released) return;
        await handle.close().catch(() => {});
        // Only mark released and drop the abrupt-exit safety net once the
        // on-disk lock is confirmed gone or confirmed to belong to someone
        // else. A read/unlink failure that leaves this unconfirmed (e.g. a
        // transient EACCES/EIO, or a guarded reader rejecting a swapped-in
        // special file) must not be treated the same as a verified removal:
        // the file may still be on disk naming this process's own live PID,
        // and marking it released here would both drop the exit-time safety
        // net and stop a later retry of release() from trying again,
        // permanently wedging the output directory for the rest of this
        // long-lived process's life (CodeRabbit review).
        let cleared = false;
        try {
          // Only unlink if we still own the nonce (another process must not
          // have reclaimed and rewritten the lock after a crash).
          const holder = outputDirLockHolder(await readLockFile(lockPath));
          if (holder?.nonce === nonce) {
            await unlink(lockPath);
          }
          cleared = true;
        } catch (error) {
          if (error?.code === 'ENOENT') cleared = true;
        }
        if (cleared) {
          released = true;
          // Unregister the abrupt-exit safety net so long-lived processes
          // that run closeout repeatedly do not accumulate exit listeners
          // (CodeRabbit discussion_r3652923142 / Codex discussion_r3652957330).
          process.removeListener('exit', onExit);
        }
      };
      // Safety net for abrupt exits (CodeRabbit #4781622077).
      const onExit = () => {
        try {
          const { unlinkSync } = require('node:fs');
          const holder = outputDirLockHolder(readOutputDirLockFileSync(lockPath));
          if (holder?.nonce === nonce) unlinkSync(lockPath);
        } catch {
          // ignore
        }
      };
      process.once('exit', onExit);
      return { handle, path: lockPath, nonce, dirIdentity: { dev: dirIdentity.dev, ino: dirIdentity.ino }, release };
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      let holder = null;
      let staleSnapshot = null;
      // Captured independently of readLockFile's own internal lstat so a
      // guard failure (FIFO/symlink/oversized) still leaves an identity to
      // re-verify against before reclaim. Without this, two concurrent
      // reclaimers could both see the same unreadable lock, both treat the
      // guard failure as "no trustworthy payload to compare" (the prior
      // staleSnapshot-only check below), and the second would then rename
      // away a legitimate successor lock the first already created after
      // quarantining the original (Codex Uert4).
      let staleIdentity = null;
      try {
        // Normalized record: isSameLockIdentity compares the exact 64-bit
        // reference and the nanosecond timestamps, neither of which survives a
        // default stat (see fileIdentity in pr_closeout_fs.js).
        staleIdentity = fileIdentity(await lstat(lockPath, { bigint: true }));
      } catch {
        staleIdentity = null;
      }
      try {
        // Guarded bounded read (Codex #UDDQC): a FIFO/symlinked/oversized
        // lock throws here and is treated exactly like a corrupt lock below.
        const text = await readLockFile(lockPath);
        staleSnapshot = String(text);
        holder = outputDirLockHolder(text);
        if (!holder) {
          // A fresh empty/partial record is an active contender between its
          // exclusive create and awaited payload write (M6UIcIK). Treat it as
          // held during a short bounded window; after that, stale/corrupt
          // records retain the existing reclaim behavior.
          const info = await stat(lockPath);
          if (Date.now() - info.mtimeMs < OUTPUT_DIR_LOCK_INITIALIZING_GRACE_MS) {
            const initializingError = new Error(
              `Evidence output directory lock is still initializing and may be held by a live closeout process: ${outputDir}`,
            );
            initializingError.code = 'ECLOSEOUTLOCKINIT';
            throw initializingError;
          }
        }
      } catch (readError) {
        // A permission/transient-I/O error (EACCES/EPERM/EIO) means a live
        // holder wrote a 0o600 lock this process cannot inspect; reclaiming it
        // would silently break exclusivity for explicit --output-dir runs
        // (qodo M6UGbRZ). Only genuinely corrupt/stale/empty locks (ENOENT,
        // parse failure, or the FIFO/symlink/oversized guard above) fall
        // through to the reclaim path; permission errors fail closed instead.
        if (readError?.code === 'EACCES' || readError?.code === 'EPERM' || readError?.code === 'EIO') {
          throw new Error(
            `Evidence output directory lock is unreadable (${readError.code}) and may be held by a live closeout process: ${outputDir}`,
          );
        }
        if (readError?.code === 'ECLOSEOUTLOCKINIT') {
          throw readError;
        }
        holder = null;
      }
      // Same-process re-entry: the lock file still names us while we hold the
      // FD. Unlink+recreate would not provide exclusion (Unix allows O_EXCL on
      // a new inode after unlink of an open file).
      if (holder?.pid === process.pid) {
        throw new Error(
          `Evidence output directory is already locked by this closeout process: ${outputDir}`,
        );
      }
      let holderAlive = false;
      if (holder) {
        try {
          process.kill(holder.pid, 0);
          holderAlive = true;
        } catch (probeError) {
          holderAlive = probeError?.code !== 'ESRCH';
        }
      }
      // PID reuse: a live PID with no matching nonce lineage still blocks;
      // only dead PIDs are reclaimed. Nonce is recorded so release cannot
      // unlink a successor's lock.
      if (holderAlive) {
        throw new Error(
          `Evidence output directory is already locked by closeout pid ${holder.pid}: ${outputDir}`,
        );
      }
      try {
        // Re-read immediately before atomically moving the stale entry out
        // of the lock name. A stale snapshot must never authorize deletion of
        // a record a concurrent contender created after our first read. The
        // rename means concurrent reclaimers cannot both unlink/recreate the
        // same pathname: the winner quarantines the old entry, while losers
        // restart at O_EXCL acquisition and observe any successor normally.
        // Parsed and incomplete records must match byte-for-byte before this
        // contender may remove them. A read guard failure has no trustworthy
        // payload to compare byte-for-byte, but it still leaves the
        // independently-captured staleIdentity (dev/ino/nlink) to re-verify:
        // falling through to an unconditional rename here would let this
        // contender quarantine whatever now occupies the path, including a
        // legitimate successor lock a peer created after reclaiming the same
        // guard failure first (Codex Uert4).
        if (staleSnapshot !== null) {
          if (String(await readLockFile(lockPath)) !== staleSnapshot) continue;
        } else if (staleIdentity) {
          let currentIdentity;
          try {
            currentIdentity = fileIdentity(await lstat(lockPath, { bigint: true }));
          } catch (identityError) {
            if (identityError?.code === 'ENOENT') continue;
            throw identityError;
          }
          if (!isSameLockIdentity(staleIdentity, currentIdentity)) continue;
        } else {
          // Neither a content snapshot nor an identity was ever captured
          // (the very first lstat above also failed) -- nothing here to
          // distinguish the current occupant from a fresh successor, so do
          // not delete blindly.
          continue;
        }
        // dev/ino/ctimeMs identity has only filesystem/clock resolution, not
        // byte-for-byte certainty: on a filesystem with rapid inode reuse, a
        // peer racing the same guard failure can unlink+recreate the lock
        // and land on the same inode with a ctimeMs collision inside the
        // same millisecond, so the identity match above cannot fully rule
        // out that lockPath now names a live successor lock rather than the
        // original stale entry (Codex UgisL/UguCX/Uert4/UikNw). Track
        // whether this reclaim ever had trustworthy content to compare, so
        // that case gets one more verification after quarantining below.
        const identityOnlyReclaim = staleSnapshot === null;
        const quarantinePath = `${lockPath}.reclaim-${process.pid}-${randomBytes(8).toString('hex')}`;
        try {
          await rename(lockPath, quarantinePath);
        } catch (renameError) {
          if (renameError?.code === 'ENOENT') continue;
          throw new Error(`Failed to quarantine stale evidence lock in ${outputDir}: ${renameError.message}`);
        }
        // Now that the entry is isolated under a private quarantine name,
        // re-verify that what actually landed there is still the stale
        // entry this contender was authorized to remove, not a live
        // successor that a peer created between this contender's check
        // above and the rename. Restore a misidentified successor with a
        // no-clobber link (not rename, which would silently overwrite a
        // third contender's new lock at lockPath) and retry rather than
        // deleting a peer's live lock.
        let requarantinedHolder = null;
        // Any quarantined content that is not byte-identical to the stale
        // snapshot this contender was authorized to remove must be restored
        // rather than deleted -- including an unreadable or a still-writing
        // successor payload that does not (yet) parse. Parseability is not the
        // test; byte-difference from the authorized snapshot is (CodeRabbit
        // UnT4B / qodo UnB_K).
        let notStale = false;
        if (identityOnlyReclaim) {
          // A genuinely corrupt/oversized/FIFO/symlinked lock fails the
          // same guarded read again, but a live successor's real lock now
          // parses cleanly -- proof this was never the stale entry the
          // identity check matched.
          try {
            requarantinedHolder = outputDirLockHolder(await readLockFile(quarantinePath));
          } catch {
            requarantinedHolder = null;
          }
        } else {
          // The byte-for-byte match above only proves lockPath held
          // staleSnapshot at the moment of that read; it is not atomic
          // with the rename, so a concurrent reclaimer that read the same
          // stale content can create its own new lock at lockPath in the
          // gap between that read and this rename -- and this rename would
          // then quarantine that live successor instead of the stale entry
          // (Codex Ukpki). A 500-iteration concurrent-acquisition stress
          // test reproduced two simultaneous successful acquisitions under
          // the prior unconditional-delete behavior. That successor can also
          // still be mid-write at the instant of quarantine: created via
          // O_EXCL, its payload not yet awaited (the window
          // OUTPUT_DIR_LOCK_INITIALIZING_GRACE_MS guards), so its bytes are
          // neither identical to staleSnapshot nor yet parseable -- and an
          // unreadable quarantine re-read throws (null). Restore on any byte
          // difference from staleSnapshot, never on parseability, so that
          // initializing successor is preserved rather than destroyed
          // (CodeRabbit UnT4B / qodo UnB_K).
          let requarantinedSnapshot;
          try {
            requarantinedSnapshot = String(await readLockFile(quarantinePath));
          } catch {
            requarantinedSnapshot = null;
          }
          notStale = requarantinedSnapshot !== staleSnapshot;
        }
        if (requarantinedHolder || notStale) {
          try {
            await link(quarantinePath, lockPath);
            await unlink(quarantinePath);
          } catch (restoreError) {
            if (restoreError?.code === 'EEXIST') {
              // Another contender already created a new lock at lockPath
              // while this was being verified; the quarantined successor
              // lock is no longer needed under this pathname.
              await unlink(quarantinePath).catch(() => {});
              continue;
            }
            throw new Error(
              `Failed to restore a live successor lock misidentified as stale in ${outputDir}: ${restoreError.message}`,
            );
          }
          continue;
        }
        try {
          await unlink(quarantinePath);
        } catch (unlinkError) {
          throw new Error(`Failed to remove quarantined evidence lock in ${outputDir}: ${unlinkError.message}`);
        }
      } catch (reclaimError) {
        if (reclaimError?.code !== 'ENOENT') throw reclaimError;
      }
    }
  }
  throw new Error(`Failed to acquire exclusive evidence lock in ${outputDir}`);
};

/**
 * Confirm outputDir still identifies the same filesystem object an
 * already-held exclusive lock was acquired against. Without this, a
 * same-user swap of the output directory (e.g. removed and recreated, or
 * replaced with a different mount/junction) between two
 * prepareOutputDirectory calls in one closeout run would go unnoticed — the
 * lock file's own name-based checks have nothing to say about the
 * directory's identity, only the lock file's. A no-op when `lock` is falsy
 * (the pre-acquisition call, or a non-exclusive run that never took a lock).
 * @param {OutputDirLock|null|undefined} lock
 * @param {string} outputDir
 * @param {{statPath?: (path: string, options?: object) => Promise<import('node:fs').BigIntStats>}} [deps]
 * @returns {Promise<void>}
 */
const assertOutputDirLockIdentity = async (lock, outputDir, { statPath = stat } = {}) => {
  if (!lock) return;
  const info = fileIdentity(await statPath(outputDir, { bigint: true }));
  // A zero ino (no usable filesystem identity) must never compare equal to
  // itself here: acquireOutputDirLock already refuses to record such an
  // identity, but failing closed independently means this check stays safe
  // even if a lock object ever reached this function some other way.
  if (
    lock.dirIdentity.ino === '0'
    || info.ino === '0'
    || info.dev !== lock.dirIdentity.dev
    || info.ino !== lock.dirIdentity.ino
  ) {
    throw new Error(`Evidence output directory changed identity after the exclusive lock was acquired: ${outputDir}`);
  }
};

const prepareOutputDirectory = async ({
  repo,
  outputDir,
  mkdirPath = mkdir,
  realpathPath = realpath,
  exclusive = false,
  // Optional box `{ lock: null }` filled when exclusive so callers can release
  // only their own lock without a process-global drain (Codex #4782132804).
  lockOut = null,
  // The lock (if any) already held for this invocation's output directory;
  // re-verified below before every write-preparation call re-uses it.
  verifyLock = null,
}) => {
  const resolvedRepo = path.resolve(repo);
  const resolvedOutput = path.resolve(outputDir);
  assertOutputOutsideRepository(resolvedRepo, resolvedOutput);
  const [physicalRepo, physicalAncestor] = await Promise.all([
    realpathPath(repo),
    resolvePhysicalTarget(outputDir, realpathPath),
  ]);
  assertOutputOutsideRepository(physicalRepo, physicalAncestor);
  await mkdirPath(resolvedOutput, { recursive: true });
  const physicalOutput = await realpathPath(outputDir);
  assertOutputOutsideRepository(physicalRepo, physicalOutput);
  await assertOutputDirLockIdentity(verifyLock, resolvedOutput);
  if (exclusive) {
    // Hold the lock for the run; release() unlinks on completion so later
    // runs do not always burn the stale-PID reclaim path (CodeRabbit
    // #4781622077). process exit is a safety net only.
    const lock = await acquireOutputDirLock(resolvedOutput);
    if (lockOut && typeof lockOut === 'object') {
      lockOut.lock = lock;
    }
  }
  return resolvedOutput;
};

/**
 * Release a specific exclusive output-dir lock acquired for one workflow run.
 * @param {OutputDirLock|null|undefined} lock
 * @returns {Promise<void>}
 */
const releaseOutputDirLock = async (lock) => {
  if (!lock || typeof lock.release !== 'function') return;
  await lock.release().catch(() => {});
};

DEFAULTS.prepareOutputDirectory = prepareOutputDirectory;

const ESSENTIAL_ENV = new Set([
  'PATH',
  'PATHEXT',
  'SYSTEMROOT',
  'COMSPEC',
  'TEMP',
  'TMP',
  'TMPDIR',
  'HOME',
  'USERPROFILE',
  'LOCALAPPDATA',
  'APPDATA',
  'PROGRAMFILES',
  'PROGRAMFILES(X86)',
  'PROGRAMDATA',
  'WINDIR',
  'CI',
  'NO_COLOR',
  'TERM',
  // Shell overrides honored by resolveCommandShell: Windows Git Bash and the
  // Unix OMO_CODEX_SHELL_PATH override must survive environment filtering or
  // preflight probes and executors fall back to a shell that is not on PATH.
  'OMO_CODEX_GIT_BASH_PATH',
  'OMO_CODEX_SHELL_PATH',
]);

/**
 * Builds the environment handed to every executed check: an allowlist, not a
 * denylist — only names in `ESSENTIAL_ENV` (PATH, shell/tmp/home basics, the
 * shell-override escape hatches) or explicitly named in `config.requiredEnv`
 * / `config.safeEnv` survive. Everything else in the ambient `env` (CI
 * secrets, unrelated tokens, etc.) is dropped by default rather than passed
 * through and relied on to be redacted after the fact.
 * @param {NodeJS.ProcessEnv} env
 * @param {{requiredEnv?: string[], safeEnv?: string[]}} config
 * @returns {NodeJS.ProcessEnv}
 */
// Runner command-file names that must NEVER pass to PR-controlled processes
// (plan preflight or full-run commands) regardless of config. These are not
// credentials — they are runner-control surfaces.
const DENYLISTED_ENV_NAMES = new Set([
  'GH_TOKEN',
  'GITHUB_TOKEN',
  'GITHUB_ENV',
  'GITHUB_PATH',
  'GITHUB_OUTPUT',
  'GITHUB_STEP_SUMMARY',
  'GITHUB_STATE',
]);
// Mirrors pr_closeout_stream.js's SENSITIVE_ENV_NAME plus the NPM _auth suffix.
// Applied ONLY to untrusted plan admission (buildPlanPreflightEnvironment), NOT
// to full-run command execution (buildWorkflowEnvironment) — a full run is
// attested and may legitimately need credential-shaped requiredEnv/safeEnv.
// Broader than pr_closeout_stream.js's SENSITIVE_ENV_NAME: adds bare KEY,
// LICENSE, CONFIG (catches KUBECONFIG, AWS_SHARED_CREDENTIALS_FILE→FILE),
// CREDENTIALS (plural), and _AUTH suffix (catches NPM_CONFIG__AUTH).
const SENSITIVE_ENV_PATTERN = /(?:^|_)(?:ACCESS_KEY|API_KEY|AUTH|AUTH_CONFIG|AUTHORIZATION|AUTH_TOKEN|BEARER_TOKEN|CLIENT_SECRET|CONFIG|CONNECTION_STRING|COOKIE|CREDENTIAL|CREDENTIALS|DATABASE_URL|DSN|ENCRYPTION_KEY|FILE|KEY|KUBECONFIG|LICENSE|MYSQL_PWD|PASSWORD|PASSWD|PGPASSWORD|PRIVATE_KEY|REDIS_URL|SECRET|SESSION_TOKEN|SIGNING_KEY|TOKEN|URI)(?:$|_)/i;

// Full-run environment: ESSENTIAL_ENV + requiredEnv/safeEnv, minus the runner
// command-file denylist. Credential-shaped names ARE allowed here because a
// full run is attested and may legitimately need them (API_TOKEN, etc.).
const buildWorkflowEnvironment = (env, config) => {
  const explicit = new Set([
    ...(config.requiredEnv || []),
    ...(config.safeEnv || []),
  ].map((name) => String(name).toUpperCase()));
  return Object.fromEntries(Object.entries(env).filter(([name]) => {
    const upper = name.toUpperCase();
    if (DENYLISTED_ENV_NAMES.has(upper)) return false;
    return ESSENTIAL_ENV.has(upper) || explicit.has(upper);
  }));
};

// Plan-preflight environment: ESSENTIAL_ENV only — config.requiredEnv/safeEnv
// are NOT honored here (chatgpt-codex-connector PR7 #6Yb3lZ, P1). Plan
// admission runs BEFORE attestation on PR-controlled code, and `config` ITSELF
// is read from the checked-out (therefore PR-controlled) config path: a PR can
// add an existing job secret's NAME to safeEnv — however innocuously chosen,
// e.g. DEPLOY_CRED rather than DEPLOY_CREDENTIAL — and have it forwarded to a
// repository-local preflight probe it also controls (e.g. a `prisma`
// preflight), before any independent review ever runs. An earlier version of
// this function reused buildWorkflowEnvironment's explicit allowlist (which
// DOES honor config.requiredEnv/safeEnv, correct for the FULL attested run)
// and only additionally stripped names matching SENSITIVE_ENV_PATTERN — a
// finite, name-shape heuristic that a secret under an unrecognized name
// (DEPLOY_CRED does not match ACCESS_KEY/CREDENTIAL/SECRET/TOKEN/etc.) simply
// walks around. The PR-controlled allowlist itself was the hole, not the
// heuristic that tried to patch it after the fact. Once a run is attested,
// buildWorkflowEnvironment (above) is what legitimately restores the
// explicit-allowlist behavior for the full run's own credential needs.
//
// ANCESTOR-PROCFS EXPOSURE (chatgpt-codex-connector PR7 #6YaZ5K, and its P1
// follow-up #6Yd4Qv): filtering the probe's OWN spawn env does not stop it
// from reading an ANCESTOR process's environment. On Linux, another process
// sharing the UID may read /proc/<pid>/environ when the runner's ptrace policy
// permits it — not only a child (access is gated by a PTRACE_MODE_READ_FSCREDS
// check; the classic same-UID case allows it, but a stricter Yama
// ptrace_scope, a non-dumpable target, or a missing CAP_SYS_PTRACE/CAP_PERFMON
// can each independently deny it — CodeRabbit PR7 #6YbIQJ) — and reflects a
// process's env as of its OWN execve(), unaffected by any later env filtering
// an ancestor performs on ITS OWN process.env. Every process in this job's
// tree (the runner's shell, this Node process, the spawned CLI, and the probe
// itself) shares one UID.
//
// FIXED for GH_TOKEN in the plan tier (#6Yd4Qv): the GH_TOKEN that once
// reached this whole tree via the WORKFLOW/action `env:` on the gate step is
// no longer set there at all. It is staged into an owner-only FILE by a
// separate earlier step and handed only to the short-lived `gh` LEAF process
// via that leaf's own spawn env (pr_closeout_github.js
// acquireDelegatedGhToken), and resolvePlanAdmission REVOKES that file (see
// revokeDelegatedGhToken, called just above the runPreflight probe below)
// before any repository-controlled code runs. So for a plan preview no probe
// ancestor has ever held GH_TOKEN in its exec-time environ, and the token file
// is gone before the probe spawns — the /proc/<pid>/environ read no longer
// yields the token.
//
// STILL a residual, deliberately not chased further here: (1) the denylisted
// runner command-file PATHS (GITHUB_ENV/GITHUB_OUTPUT/…) are still present in
// ancestor environs, though they are not credentials; (2) in the FULL,
// attested tier the token file necessarily outlives the preflight probe
// (authenticated reads follow it), so a full-tier probe — which runs only
// after a WRITE-access reviewer attested this exact snapshot — could still
// read the token file by path; (3) a same-UID ptrace attach could read this
// CLI's heap where the runner's ptrace_scope permits attaching to an ancestor.
// A complete fix for those requires an OS-level process/privilege boundary (a
// container, a different UID) — out of scope for a targeted change here. The
// token itself is scoped to the consuming job's `permissions:` grant, which
// bounds the practical impact of any residual leak.
//
// EXPLORED, deliberately NOT implemented (owner-approved investigation, this
// PR): wrapping the plan-mode probe spawn in `unshare --user --map-root-user
// --pid --mount-proc --fork -- <shell> ...` so the probe process gets its own
// PID namespace with a freshly-mounted, namespace-scoped /proc — the standard
// way to make a child unable to see (or read /proc/<pid>/environ for)
// anything outside its own subtree, while the PARENT retains full visibility
// (PID namespaces nest: an ancestor namespace always sees descendant-
// namespace processes too, just under different numbering — verified against
// util-linux's own unshare(1) documentation of `--mount-proc`/`--fork`).
// runPreflight already accepts a `probeCommand` override and
// probeCommandDefault a `spawnProcess` override, so wiring this in would not
// have required touching either shared primitive.
//
// Two independent reasons this was not wired into the live spawn path:
//   1. It may not even work on the actual target runner (GitHub-hosted
//      ubuntu-latest). Recent Ubuntu releases ship an AppArmor
//      `unprivileged_userns` restriction (a downstream hardening patch, ON
//      BY DEFAULT specifically to reduce attack surface on hosts that run
//      untrusted code — precisely this runner's own threat model) that can
//      make unprivileged `unshare --user ...` fail with EPERM even when the
//      `kernel.unprivileged_userns_clone` sysctl itself is 1. Whether
//      GitHub's current runner image allows it is not something this
//      repository controls or can assume, and could change on any future
//      image update regardless. Any implementation MUST self-verify success
//      (e.g. spawn `unshare --user --map-root-user --pid --mount-proc
//      --fork -- sh -c 'echo $$'` once and confirm it prints `1`, proving a
//      genuinely new PID namespace) and fall back to the unwrapped spawn on
//      any failure — silently claiming isolation that did not actually take
//      effect would be worse than the status quo.
//   2. probeCommandDefaultInner's own orphan-sweep/termination path
//      (terminateProcessTree) kills the POSIX process GROUP via
//      `kill(-child.pid, signal)`, relying on every descendant remaining in
//      the process group `detached: true` placed the spawned root in.
//      `unshare --fork`'s forked child does not itself call `setsid`/
//      `setpgid`, so group membership should be preserved through the extra
//      layer — but this interaction between process-group signal delivery
//      and PID-namespace nesting is exactly the kind of kernel behavior that
//      needs verifying with a real spawn-and-kill integration test on actual
//      Linux, which this development environment could not provide. Wiring
//      an unverified extra process layer into the spawn path risks a
//      regression in the existing, heavily-tested no-orphaned-process
//      guarantee — a strictly worse outcome than leaving this gap as-is,
//      for a mitigation whose own benefit is already bounded by the token's
//      narrow read-only scope. Left for a maintainer with real Linux CI
//      access to implement and verify, following the self-check-first
//      design above.
// HOME/USERPROFILE/APPDATA/LOCALAPPDATA are in ESSENTIAL_ENV because ordinary
// tool invocation needs SOME profile directory to resolve against — but their
// REAL values point at the runner's actual home/profile, where credential-
// bearing files live on disk regardless of what is or is not in process.env:
// ~/.npmrc, ~/.netrc, ~/.gitconfig (credential helpers), ~/.config/gh
// (the GitHub CLI's own token store), cloud CLI config directories, etc. A
// repository-controlled preflight probe (an arbitrary command this same
// config names) can read those files directly by path -- entirely bypassing
// the env-NAME filtering above, which only ever controlled what appears as
// an env VALUE (CodeRabbit PR7 #6Yb44Sd, following up on the earlier,
// distinct #6YaZ5K procfs-ancestor finding). isolatedHomeDir (when provided
// by the caller, which creates and cleans up a fresh empty temp directory
// around the probe call) replaces all four names with that path, so any
// profile-relative credential lookup resolves to an empty directory instead
// of the real one.
const HOME_ENV_NAMES = ['HOME', 'USERPROFILE', 'APPDATA', 'LOCALAPPDATA'];

const buildPlanPreflightEnvironment = (env, isolatedHomeDir = null) => {
  const filtered = Object.fromEntries(Object.entries(env).filter(([name]) => {
    const upper = name.toUpperCase();
    if (DENYLISTED_ENV_NAMES.has(upper)) return false;
    return ESSENTIAL_ENV.has(upper);
  }));
  // Belt-and-suspenders only at this point: no PR-controlled name can reach
  // `filtered` above, so this can only ever fire against a future accidental
  // credential-shaped addition to the fixed ESSENTIAL_ENV list itself.
  const sanitized = Object.fromEntries(Object.entries(filtered).filter(([name]) => (
    !SENSITIVE_ENV_PATTERN.test(name)
  )));
  if (isolatedHomeDir) {
    for (const name of HOME_ENV_NAMES) {
      // Preserve the ambient casing (env.HOME vs env.Home never both exist on
      // one platform) when the name was already present; otherwise set the
      // canonical (already-uppercase) name outright. A name absent from the
      // ambient env must still be forced to the isolated directory, not left
      // unset — Node's os.homedir() (and other profile-resolving platform
      // APIs) falls back to OS-level lookups (getpwuid on POSIX, the
      // Windows profile API) when its env var is undefined, which would
      // silently resolve to the REAL home directory and defeat the
      // isolation this function exists to provide (CodeRabbit PR7 #6Yb44Sl).
      const actualName = Object.keys(sanitized).find((key) => key.toUpperCase() === name) || name;
      sanitized[actualName] = isolatedHomeDir;
    }
  }
  return sanitized;
};

/**
 * Redacts absolute local paths from a persisted evidence value: recursively
 * replaces every occurrence of `repo`/`outputDir` (and their forward- and
 * backslash-normalized forms, case-insensitively for drive-letter paths)
 * with `<repo>`/`<evidence>` placeholders, in both string values and object
 * keys, so evidence written to disk is portable across machines and doesn't
 * leak the local filesystem layout. A lookahead boundary keeps a match from
 * firing inside a longer unrelated path segment. Walks objects/arrays with a
 * clone cache: a value reachable via more than one reference stays a single
 * shared reference after normalization (same contract as `redactStructure`),
 * and only a genuine cycle collapses to the string `'[Circular]'`.
 * @param {unknown} value
 * @param {string} repo
 * @param {string} outputDir
 * @returns {unknown} a new value with paths/keys normalized; non-string primitives pass through unchanged.
 */
const normalizePersistedPaths = (value, repo, outputDir, clones = new WeakMap(), stack = new WeakSet()) => {
  const replacements = [
    [repo, '<repo>'],
    [repo?.replaceAll('\\', '/'), '<repo>'],
    [repo?.replaceAll('/', '\\'), '<repo>'],
    [outputDir, '<evidence>'],
    [outputDir?.replaceAll('\\', '/'), '<evidence>'],
    [outputDir?.replaceAll('/', '\\'), '<evidence>'],
  ].filter(([candidate]) => candidate);
  const normalize = (text) => {
    let result = String(text);
    for (const [candidate, replacement] of replacements) {
      const escaped = candidate.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const flags = /^[A-Za-z]:[\\/]/.test(candidate) ? 'gi' : 'g';
      result = result.replace(
        new RegExp(`${escaped}(?=$|[\\\\/]|[^A-Za-z0-9._-])`, flags),
        replacement,
      );
    }
    return result;
  };
  if (typeof value === 'string') return normalize(value);
  if (!value || typeof value !== 'object') return value;
  // Stack first (true cycle while building); clones second (shared refs done).
  if (stack.has(value)) return '[Circular]';
  if (clones.has(value)) return clones.get(value);
  stack.add(value);
  try {
    if (Array.isArray(value)) {
      const out = [];
      clones.set(value, out);
      for (const entry of value) out.push(normalizePersistedPaths(entry, repo, outputDir, clones, stack));
      return out;
    }
    const out = {};
    clones.set(value, out);
    for (const [key, entry] of Object.entries(value)) {
      out[normalize(key)] = normalizePersistedPaths(entry, repo, outputDir, clones, stack);
    }
    return out;
  } finally {
    stack.delete(value);
  }
};

/**
 * Order-sensitive list equality (not set equality) — used to detect whether
 * `touchedFiles` changed between two repository-state snapshots, where a
 * reordering is as meaningful a change as an addition or removal.
 * @param {unknown[]} left
 * @param {unknown[]} right
 * @returns {boolean}
 */
const sameList = (left = [], right = []) => (
  left.length === right.length && left.every((value, index) => value === right[index])
);

/**
 * The "did the repository move under us" integrity check, run at multiple
 * checkpoints during a closeout (once comparing validation-time state
 * through the post-GitHub-verification and final-seal states, and again
 * later comparing post-GitHub state through the post-evidence-write state).
 * Compares base/merge-base/head SHAs and the ordered touched-files list
 * across `validatedState` -> `observedState` -> `sealedState`, and compares
 * working-tree fingerprints to catch content-level drift (untracked/ignored
 * changes) that SHA/file-list comparisons alone would miss. Any mismatch —
 * including the optional `initialFingerprint` differing from
 * `afterFingerprint` — is accumulated and returned as BLOCKED with every
 * reason concatenated; a clean comparison returns PASS.
 * @returns {{status: 'PASS'|'BLOCKED', evidence: string, initialFingerprint?: string|null, beforeFingerprint: string|null, afterFingerprint: string|null}}
 */
const sealRepository = ({
  validatedState,
  observedState,
  sealedState,
  initialFingerprint,
  beforeFingerprint,
  afterFingerprint,
}) => {
  const problems = [];
  const compareState = (candidate, phase) => {
    for (const field of ['baseSha', 'mergeBaseSha', 'headSha']) {
      if ((validatedState[field] || null) !== (candidate[field] || null)) {
        problems.push(`${field} changed ${phase}: ${validatedState[field] || '<missing>'} -> ${candidate[field] || '<missing>'}.`);
      }
    }
    if (!sameList(validatedState.touchedFiles, candidate.touchedFiles)) problems.push(`Touched files changed ${phase}.`);
  };
  compareState(observedState, 'after live GitHub verification');
  compareState(sealedState, 'during the final repository seal');
  if (beforeFingerprint !== afterFingerprint) {
    problems.push(`Working-tree fingerprint changed after live GitHub verification: ${beforeFingerprint} -> ${afterFingerprint}.`);
  }
  if (initialFingerprint && initialFingerprint !== afterFingerprint) {
    problems.push(`Working-tree fingerprint differs from clean admission: ${initialFingerprint} -> ${afterFingerprint}.`);
  }
  return problems.length
    ? { status: 'BLOCKED', evidence: problems.join(' '), beforeFingerprint, afterFingerprint }
    : {
      status: 'PASS',
      evidence: `Post-GitHub repository seal matches base ${sealedState.baseSha}, head ${sealedState.headSha}, and working-tree fingerprint ${afterFingerprint}.`,
      initialFingerprint,
      beforeFingerprint,
      afterFingerprint,
    };
};

/**
 * Gates whether `runCloseoutWorkflow` is allowed to actually execute the
 * configured checks: any FAIL among the plan/preflight/gate-integrity/
 * initial-tree statuses, or any pre-existing suppression finding, is a hard
 * FAIL; anything short of all four being exactly PASS is BLOCKED. Only a
 * PASS here lets validation phases run — an incomplete or dirty admission
 * never silently proceeds to executing checks.
 * @returns {'PASS'|'FAIL'|'BLOCKED'}
 */
const admissionStatus = ({ planStatus, preflight, gateIntegrity, initialTree, initialSuppressions }) => {
  if (planStatus === 'FAIL' || preflight.status === 'FAIL' || gateIntegrity.status === 'FAIL'
    || initialTree.status === 'FAIL' || initialSuppressions.length) return 'FAIL';
  if (planStatus !== 'PASS' || preflight.status !== 'PASS' || gateIntegrity.status !== 'PASS'
    || initialTree.status !== 'PASS') return 'BLOCKED';
  return 'PASS';
};

/**
 * Merge per-check inline engine timeouts into the id-keyed timeoutsMs map
 * the command executor consumes. The engine matrix is authoritative for its
 * own checks, so an inline timeoutMs wins over a config.timeoutsMs entry for
 * the same id; ids without a truthy inline value keep whatever config
 * supplied (validateEngineChecks bounds real inline values to 1..2^31-1
 * upstream, so 0/negative can only reach this helper via direct calls).
 * @param {Record<string, number>|undefined} configTimeouts
 * @param {Array<{id: string, timeoutMs?: number}>} checks
 * @returns {Record<string, number>}
 */
const mergeEngineTimeouts = (configTimeouts, checks) => ({
  ...(configTimeouts || {}),
  ...Object.fromEntries(checks.filter((check) => check.timeoutMs).map((check) => [check.id, check.timeoutMs])),
});

const ENGINE_BASE_TOOLS = ['git', 'node'];

/**
 * Engine-mode preflight probe selection (spec: "Engine-only config.requiredTools").
 * Returns the filtered [name, command] probe entries — always git + node (the
 * gate's own dependencies) plus the declared names, deduplicated, in catalog
 * order — or named errors when the declaration is malformed or names a probe
 * outside the catalog. Fail-closed: errors mean NO probe list; the caller feeds
 * them into the existing errors → FAIL containment chain.
 */
const resolveEngineToolProbes = (requiredTools, toolProbes) => {
  if (requiredTools !== undefined && !Array.isArray(requiredTools)) {
    return { probes: null, errors: ['config.requiredTools must be an array of preflight probe names.'] };
  }
  const errors = [];
  const catalog = new Set(toolProbes.map(([name]) => name));
  const declared = requiredTools || [];
  declared.forEach((name, index) => {
    if (typeof name !== 'string' || !name) {
      errors.push(`config.requiredTools[${index}] must be a non-empty string.`);
    } else if (!catalog.has(name)) {
      errors.push(`config.requiredTools[${index}] names unknown preflight probe "${name}". Known probes: ${[...catalog].join(', ')}.`);
    }
  });
  if (errors.length > 0) return { probes: null, errors };
  const wanted = new Set([...ENGINE_BASE_TOOLS, ...declared]);
  return { probes: toolProbes.filter(([name]) => wanted.has(name)), errors };
};

/**
 * Read-only admission readiness for plan mode: WHY would the full gate block
 * right now? Consumed by the Action's push-time preview (sub-project B) so an
 * ordinary push gets an honest "attestation absent / gh unavailable / tree
 * dirty" answer without paying for the full gate. Every probe failure is
 * caught into a structured state — plan mode must never throw because gh is
 * unauthenticated or a probe crashed; that is precisely what it exists to
 * report. Attestation mapping is the spec's four-state vocabulary: PASS →
 * `present`; FAIL → `weakened` (an attestation for this snapshot exists but
 * records a weakened decision — hiding it inside "absent" would suppress an
 * active weakening signal); BLOCKED carrying the reader's machine-readable
 * `reason: 'unavailable'` discriminator → `unavailable` (the read itself
 * could not complete); any other BLOCKED → `absent` (snapshot reasons: no
 * matching review, or the PR head/base moved). A reader that throws (test
 * fakes; the real reader never throws) also maps to `unavailable`.
 * @param {{repo: string, baseSha: string, headSha: string, configDigest: string, config?: object, toolProbes?: Array, d: object}} options
 * @returns {Promise<{attestation: object, cleanTree: object, preflight: object}>}
 */
const resolvePlanAdmission = async ({ repo, baseSha, headSha, configDigest, config = {}, toolProbes, d }) => {
  let attestation;
  try {
    const live = await d.readLiveGateAttestation({
      repo,
      expectedBaseSha: baseSha,
      expectedHeadSha: headSha,
      expectedConfigDigest: configDigest,
    });
    attestation = live?.status === 'PASS'
      ? { status: 'present', evidence: live.evidence }
      : live?.status === 'FAIL'
        ? { status: 'weakened', evidence: live.evidence || 'A live attestation matching this snapshot records a weakened decision.' }
        : live?.reason === 'unavailable'
          ? { status: 'unavailable', evidence: live.evidence || 'Live attestation lookup could not complete.' }
          : { status: 'absent', evidence: live?.evidence || 'No live attestation matches the current base, head, and config digest.' };
  } catch (error) {
    attestation = { status: 'unavailable', evidence: `Attestation lookup failed: ${error.message}` };
  }
  let cleanTree;
  try {
    cleanTree = await d.cleanTreeStatus(repo);
  } catch (error) {
    cleanTree = { status: 'BLOCKED', evidence: `Working tree inspection failed: ${error.message}` };
  }
  let preflight;
  if (cleanTree?.status !== 'PASS') {
    // Mirror the full-gate precondition (runCloseoutWorkflowBody): runPreflight
    // spawns binaries and contacts config.services/config.ports, so it must not
    // run against an unclean snapshot. A dirty tree is already its own admission
    // blocker; reporting preflight as BLOCKED keeps the preview honest without
    // probing a tree admission would reject anyway.
    preflight = {
      status: 'BLOCKED',
      evidence: `Preflight did not run because the working tree was not clean: ${cleanTree?.evidence}`,
    };
  } else {
    // Mirror the full-gate seal (runCloseoutWorkflowBody): capture a
    // working-tree fingerprint BEFORE the probe so a repository-local binary
    // mutating a GITIGNORED path (node_modules/.bin, generated artifacts, the
    // prisma client dirs) is caught — cleanTreeStatus respects .gitignore and
    // would miss such a mutation. The fingerprint folds in the
    // reproducibilityPaths (config.reproducibilityPaths + the prisma client
    // dirs) so the same set is observed before and after.
    const reproducibilityPaths = [...new Set([
      'node_modules/.prisma',
      'node_modules/@prisma/client',
      ...(config.reproducibilityPaths || []),
    ])];
    let preProbeFingerprint;
    try {
      preProbeFingerprint = await d.workingTreeFingerprint(repo, reproducibilityPaths);
    } catch (error) {
      preflight = { status: 'BLOCKED', evidence: `Pre-preflight fingerprint failed: ${error.message}` };
      return { attestation, cleanTree, preflight };
    }
    try {
      // Plan probes get a fixed, code-defined environment (ESSENTIAL_ENV
      // only — see buildPlanPreflightEnvironment), not raw process.env:
      // preflight spawns repository-controlled binaries (e.g. `pnpm prisma
      // --version`), and forwarding the full step env would expose runner
      // command files (GITHUB_ENV/GITHUB_OUTPUT) and job secrets to
      // PR-controlled code in a preview advertised as read-only. The parent
      // gh lookups do not use this env — they authenticate via the delegated
      // token file (pr_closeout_github.js acquireDelegatedGhToken), which is
      // handed only to the `gh` leaf process and has been revoked just above
      // this point so it is no longer readable by the probe about to spawn
      // (chatgpt-codex-connector PR7 #6Yd4Qv).
      //
      // `config` itself is passed with requiredEnv/safeEnv cleared
      // (CodeRabbit PR7 #6Yb44Sc): runPreflight (scripts/pr_closeout_process.js)
      // separately checks EVERY config.requiredEnv name for presence in the
      // given env and reports each missing one as its own BLOCKED
      // `env:<name>` check. Since the env above deliberately no longer
      // carries config-named credentials at all, passing the untouched
      // config through would report every configured requiredEnv name as
      // missing on every plan preview -- a false BLOCKED for any repo that
      // legitimately requires a credential for its ATTESTED full run,
      // which plan preflight was never supposed to need in the first
      // place. Every other config field (services, ports, requiredTools,
      // reproducibilityPaths, minFreeDiskGb, etc.) is preserved unchanged.
      //
      // isolatedHomeDir (CodeRabbit PR7 #6Yb44Sd): HOME/USERPROFILE/APPDATA/
      // LOCALAPPDATA in the env above still carry the runner's REAL profile
      // paths, where credential-bearing files (~/.npmrc, ~/.netrc, the gh
      // CLI's own token store, cloud CLI configs) live on disk regardless of
      // what is or is not in process.env -- a repository-controlled probe
      // can read those directly by path. A fresh, empty temp directory
      // substituted for all four names means any such profile-relative
      // lookup resolves to nothing. Removed in the finally below regardless
      // of how the probe call ends, including a throw.
      const planPreflightConfig = { ...config, requiredEnv: [], safeEnv: [] };
      // Revoke the delegated workflow token BEFORE spawning the first (and, in
      // the plan tier, only) repository-controlled probe (chatgpt-codex-
      // connector PR7 #6Yd4Qv, P1). The attestation read above is the sole
      // authenticated GitHub call in this tier and has already completed, so
      // the off-environment token file staged for it is no longer needed. The
      // token never sat in this process's (or any ancestor's) exec-time
      // environ — action.yml keeps GH_TOKEN out of the gate step entirely — so
      // the file was the only remaining path by which a same-UID probe could
      // reach the token; deleting it here removes that too. A no-op unless the
      // hardened action path is in use (CLOSEOUT_GH_TOKEN_FILE set); it throws
      // only if the file is present but cannot be removed, in which case the
      // outer catch turns preflight into a BLOCKED preview rather than run an
      // untrusted probe while the token file still exists. Called as the
      // module import (not through `d`) so revocation can never be silently
      // dropped by a caller that supplies a partial dependency object.
      revokeDelegatedGhToken(process.env);
      let isolatedHomeDir;
      try {
        isolatedHomeDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-plan-home-'));
        preflight = await d.runPreflight({
          repo,
          config: planPreflightConfig,
          env: buildPlanPreflightEnvironment(process.env, isolatedHomeDir),
          toolProbes,
        });
      } finally {
        // Not best-effort (CodeRabbit PR7 #6Yb44Sp): a cleanup failure here
        // means the isolated profile directory a repository-controlled probe
        // may have written into was NOT removed. Letting the error propagate
        // (rather than swallowing it) reaches the outer catch below, which
        // forces preflight to BLOCKED instead of returning a PASS/FAIL result
        // computed while that leftover data still exists.
        if (isolatedHomeDir) await rm(isolatedHomeDir, { recursive: true, force: true });
      }
    } catch (error) {
      preflight = { status: 'BLOCKED', evidence: `Preflight probe failed: ${error.message}` };
    }
    // Recheck the tree after preflight regardless of PASS/FAIL: a probe binary
    // could modify a tracked file even on a failing/throwing exit. A dirty
    // post-probe tree must BLOCK the preview and surface the dirt. Use BOTH
    // cleanTreeStatus (catches tracked-file mutations) AND the fingerprint
    // (catches gitignored-path mutations cleanTreeStatus cannot see).
    try {
      const postProbeTree = await d.cleanTreeStatus(repo);
      if (postProbeTree.status !== 'PASS') {
        preflight = { status: 'BLOCKED', evidence: `Working tree was clean before preflight but dirty after: ${postProbeTree.evidence}` };
      } else {
        const postProbeFingerprint = await d.workingTreeFingerprint(repo, reproducibilityPaths);
        if (postProbeFingerprint !== preProbeFingerprint) {
          preflight = {
            status: 'BLOCKED',
            evidence: `Working tree fingerprint changed during preflight (a gitignored path was mutated): ${postProbeFingerprint}`,
          };
        }
      }
    } catch (error) {
      preflight = { status: 'BLOCKED', evidence: `Post-preflight tree check failed: ${error.message}` };
    }
  }
  return { attestation, cleanTree, preflight };
};

/**
 * Orchestrates a full PR closeout run end to end: resolve repo state, build
 * and admit the check plan, run validation, independently verify GitHub's
 * live gate/PR state, seal the repository against drift, and persist
 * evidence. `planOnly` short-circuits after building the plan and returns a
 * redacted preview without touching disk or running anything.
 *
 * Admission is gated on an independent live GitHub gate attestation
 * (`readLiveGateAttestation`) matching this exact base/head/configDigest —
 * only then do preflight, the initial suppression scan, and the initial
 * clean-tree fingerprint run, and only a clean admission (`admissionStatus`)
 * lets the configured checks actually execute. Each check runs through
 * `executeChecked`, which re-runs generator checks twice to prove
 * reproducibility and falls back to a serialized baseline comparison
 * (`verifyBaseline`, one at a time — they share a disposable git worktree)
 * when a check fails, to distinguish a pre-existing failure from one this PR
 * introduced.
 *
 * The tail of the run enforces ordering deliberately: the tree is
 * fingerprinted before and after the live-GitHub round trip
 * (`beforeGithubFingerprint`/`afterGithubFingerprint`) so a mutation that
 * happens purely around that network call is caught by `sealRepository`;
 * gate integrity is then re-classified against the *final* observed gate
 * changes and live attestation, not the initial local view. Evidence is
 * written twice: a PROVISIONAL report (forced BLOCKED, with its
 * evidence-write seal marked pending — that sub-seal cannot be computed
 * before something is actually on disk to compare against) is written
 * first, so a crash mid-run still leaves an unambiguously-incomplete report
 * on disk rather than a false PASS; only after that write is the tree
 * fingerprinted once more, the evidence-write seal computed by comparing
 * pre- and post-write state, and the final report (true `overallStatus`,
 * completed seal) written over it.
 * @param {{repo: string, baseRef: string, config?: object, outputDir?: string, planOnly?: boolean, mode?: 'strict'|'engine', dependencies?: object}} options `mode` defaults to `'strict'` and is invocation-only (config.mode is rejected); `dependencies` overrides any of `DEFAULTS` (repo-state/git/GitHub/process/report I/O) for tests.
 * @returns {Promise<{report: object, paths: object}|object>} the full evidence report and its written paths; a redacted plan preview when `planOnly` is true.
 */
const runCloseoutWorkflow = async ({
  repo,
  baseRef,
  config = {},
  outputDir,
  planOnly = false,
  mode = 'strict',
  dependencies = {},
} = {}) => {
  // Per-invocation lock box so concurrent runCloseoutWorkflow calls only
  // release their own exclusive --output-dir lock (Codex #4782132804).
  const lockOut = { lock: null };
  const d = { ...DEFAULTS, ...dependencies };
  const prepareWrapped = async (args) => d.prepareOutputDirectory({
    ...args,
    // Only the first exclusive prepare for this invocation owns the lock.
    lockOut: args.exclusive && !lockOut.lock ? lockOut : null,
    // Every prepare (including the ones after the lock is already held)
    // re-verifies the output directory still matches the lock's identity.
    verifyLock: lockOut.lock,
  });
  try {
    return await runCloseoutWorkflowBody({
      repo,
      baseRef,
      config,
      outputDir,
      planOnly,
      mode,
      dependencies: { ...d, prepareOutputDirectory: prepareWrapped },
    });
  } finally {
    await releaseOutputDirLock(lockOut.lock);
  }
};

const runCloseoutWorkflowBody = async ({
  repo,
  baseRef,
  config = {},
  outputDir,
  planOnly = false,
  mode = 'strict',
  dependencies = {},
} = {}) => {
  // Mode is invocation-only: a config file that could switch a strict run
  // into engine mode would be a silent weakening channel, so its presence in
  // config is a hard error rather than an ignored key.
  if (Object.hasOwn(config, 'mode')) {
    throw new Error('The closeout mode cannot be set from config; pass --mode on the invocation.');
  }
  if (mode !== 'strict' && mode !== 'engine') {
    throw new Error(`Unknown closeout mode "${mode}". Use strict or engine.`);
  }
  const d = { ...DEFAULTS, ...dependencies };
  const startedAt = new Date().toISOString();
  const initial = await d.resolveRepositoryState({ repo, baseRef });
  const metadata = await d.readProjectMetadata(initial.repo);
  const plan = buildCheckPlan({
    mode,
    config,
    ...metadata,
    touchedFiles: initial.touchedFiles,
    // Expand fixed range checks (git-diff-check) from the live merge-base,
    // not a hard-coded origin/main, so non-main PR bases are correct.
    mergeBaseSha: initial.mergeBaseSha || initial.baseSha,
  });
  // Engine-only requiredTools narrows the preflight probe catalog to git+node
  // plus the declared names (spec: "Engine-only config.requiredTools"); a
  // malformed or unknown-name declaration is fail-closed — its errors join
  // the plan's existing errors → FAIL containment chain rather than being
  // reported separately. Strict runs never override the probe list: passing
  // `undefined` keeps runPreflight's own default (the full hardcoded
  // catalog), byte-identical to today's strict behavior.
  const toolProbeResolution = mode === 'engine'
    ? resolveEngineToolProbes(config.requiredTools, TOOL_PROBES)
    : { probes: undefined, errors: [] };
  if (toolProbeResolution.errors.length) {
    plan.errors = [...plan.errors, ...toolProbeResolution.errors];
  }
  const toolProbes = toolProbeResolution.probes ?? undefined;
  const planStatus = planStatusFor(plan);
  const baselineSetupCommand = config.baselineSetupCommand || 'pnpm install --frozen-lockfile --ignore-scripts';
  const { gateIntegrityReview: _gateIntegrityReview, ...validationConfig } = config;
  const configDigest = d.digestValidationConfig({
    // schemaVersion 2 -> 3: the digest now binds the gate tier. Deliberate
    // one-time invalidation of outstanding attestations (spec: Migration
    // consequence) — a strict-minted attestation can never admit an engine
    // run because the digests can no longer collide across modes.
    schemaVersion: 3,
    mode,
    config: validationConfig,
    resolved: {
      baselineSetupCommand,
      checks: plan.checks.map((check) => ({
        id: check.id,
        command: check.command,
        resolution: check.resolution,
        qualificationSafe: check.qualificationSafe,
        resourceGroup: check.resourceGroup,
        baselineSafe: check.baselineSafe,
        generator: check.generator,
        proof: check.proof,
      })),
    },
  });
  const configuredCommands = [
    `baseline-dependency-setup:${baselineSetupCommand}`,
    ...plan.checks.filter(({ command }) => command).map(({ id, resolution, command }) => `${id}:${resolution}:${command}`),
    ...plan.checks
      .filter(({ proof }) => proof?.type === 'command' && proof.command)
      .map(({ id, proof }) => `${id}:postcondition:${proof.command}`),
  ];
  if (planOnly) {
    const admission = await resolvePlanAdmission({
      repo: initial.repo,
      baseSha: initial.baseSha,
      headSha: initial.headSha,
      configDigest,
      config,
      toolProbes,
      d,
    });
    return redactStructure({
      execution: 'not-started',
      mode,
      admission,
      repository: initial.repo,
      baseRef: initial.baseRef,
      baseSha: initial.baseSha,
      headSha: initial.headSha,
      configDigest,
      gateIntegrityAttestationRequired: {
        provider: 'github-pull-request-review',
        baseSha: initial.baseSha,
        headSha: initial.headSha,
        configDigest,
        decision: 'not-weakened',
        marker: gateAttestationMarker({ baseSha: initial.baseSha, headSha: initial.headSha, configDigest }),
      },
      touchedFiles: initial.touchedFiles,
      planStatus,
      errors: plan.errors,
      checks: plan.checks.map(({ id, label, command, resolution, status, evidence }) => ({
        id, label, command, resolution, status, evidence,
      })),
    }, process.env, [...(config.requiredEnv || []), ...(config.safeEnv || [])]);
  }

  // Explicit --output-dir is shared-name; take an exclusive lock. Default dirs
  // already include pid+random uniqueness (Codex #4781560042).
  const explicitOutputDir = Boolean(outputDir);
  const requestedOutput = path.resolve(outputDir || defaultOutputDir(initial.repo, initial.headSha));
  assertOutputOutsideRepository(initial.repo, requestedOutput);
  const resolvedOutput = await d.prepareOutputDirectory({
    repo: initial.repo,
    outputDir: requestedOutput,
    exclusive: explicitOutputDir,
  });
  const childEnv = buildWorkflowEnvironment(process.env, config);
  // FIX (Qodo #5): engine check processes run under the allowlisted childEnv,
  // which drops `GITHUB_BASE_REF`, so engine commands that referenced it
  // silently fell back to `main` even when the gate ran against a different PR
  // base. Plumb the already-resolved base ref through a dedicated,
  // non-secret, repo-derived env var that engine commands can rely on. This
  // does NOT widen the allowlist for ambient env — it injects one trusted
  // value derived from `initial.baseRef` (already rev-parsed to a stable ref
  // by resolveRepositoryState), and the engine command's own `:-origin/main`
  // fallback keeps it safe for any bare invocation that omits it.
  childEnv.CLOSEOUT_RESOLVED_BASE_REF = initial.baseSha;
  const execute = d.execute || d.createCommandExecutor({
    repo: initial.repo,
    outputDir: resolvedOutput,
    env: childEnv,
    secretNames: [...(config.requiredEnv || []), ...(config.safeEnv || [])],
    timeoutMs: config.timeoutMs,
    timeoutsMs: mergeEngineTimeouts(config.timeoutsMs, mode === 'engine' ? plan.checks : []),
    grafanaServiceUrl: config.services?.grafana?.url || null,
  });
  const initialAttestation = await d.readLiveGateAttestation({
    repo: initial.repo,
    expectedBaseSha: initial.baseSha,
    expectedHeadSha: initial.headSha,
    expectedConfigDigest: configDigest,
  });
  let preflight = {
    status: 'BLOCKED',
    checks: [],
    toolVersions: {},
    evidence: 'Preflight did not run because independent attestation admission was not clean.',
  };
  let initialSuppressions = [];
  let initialTree = {
    status: 'BLOCKED',
    evidence: 'Initial working tree was not inspected because attestation admission was not clean.',
  };
  let initialFingerprint = null;
  let gateIntegrity = {
    status: initialAttestation.status === 'FAIL' ? 'FAIL' : 'BLOCKED',
    evidence: initialAttestation.evidence || 'Independent live GitHub attestation was not clean.',
  };
  // Ignored generator outputs are invisible to cleanTreeStatus and the
  // tracked-diff hash, so fingerprint them at every seal point (admission,
  // post-validation, post-GitHub, post-evidence-write); a validation or
  // confirmation step mutating them after the generator reproducibility
  // check must break a seal instead of passing unnoticed.
  const reproducibilityPaths = [...new Set([
    'node_modules/.prisma',
    'node_modules/@prisma/client',
    ...(config.reproducibilityPaths || []),
  ])];
  const attestationAdmitted = initialAttestation.status === 'PASS';
  if (attestationAdmitted) {
    // Inspect and fingerprint the working tree BEFORE launching any executable
    // preflight probe. runPreflight may run repository-local binaries or
    // contact services, and admission will reject a dirty tree anyway, so do
    // not execute unreviewed commands against an unclean snapshot (Codex
    // M6UFnGb). readGateChanges and scanTouchedSuppressions are read-only
    // analysis (no spawned commands), so they stay concurrent with preflight
    // once the tree is confirmed clean.
    initialTree = await d.cleanTreeStatus(initial.repo);
    if (initialTree.status === 'PASS') {
      initialFingerprint = await d.workingTreeFingerprint(initial.repo, reproducibilityPaths);
      const [observedPreflight, initialGateChanges, observedSuppressions] = await Promise.all([
        d.runPreflight({ repo: initial.repo, config, env: childEnv, toolProbes }),
        d.readGateChanges(initial.repo, initial.mergeBaseSha || initial.baseSha),
        d.scanTouchedSuppressions(initial.repo, initial.touchedFiles),
      ]);
      preflight = observedPreflight;
      initialSuppressions = observedSuppressions;
      gateIntegrity = classifyGateIntegrity({
        ...initialGateChanges,
        configuredCommands,
        baseSha: initial.baseSha,
        headSha: initial.headSha,
        configDigest,
        attestation: initialAttestation,
      });
    } else {
      preflight = {
        ...preflight,
        evidence: `Preflight did not run because the initial working tree was not clean: ${initialTree.evidence}`,
      };
      gateIntegrity = {
        status: 'BLOCKED',
        evidence: `Gate integrity was not classified because the initial working tree was not clean: ${initialTree.evidence}`,
      };
    }
  }
  const admitted = admissionStatus({
    planStatus,
    preflight,
    gateIntegrity,
    initialTree,
    initialSuppressions,
  });
  let reproducibility = {
    status: admitted === 'PASS' ? 'BLOCKED' : admitted,
    evidence: admitted === 'PASS' ? 'Generator confirmation has not run.' : 'Admission gate was not clean.',
  };
  let phases = {
    status: admitted,
    qualification: [],
    confirmation: admitted === 'PASS'
      ? []
      : blockedConfirmationRows(plan.checks, 'Confirmation did not run because admission was not clean.'),
  };

  if (admitted === 'PASS') {
    let baselineChain = Promise.resolve();
    let baselineAttempt = 0;
    const serializeBaseline = (operation) => {
      const pending = baselineChain.then(operation, operation);
      baselineChain = pending.catch(() => undefined);
      return pending;
    };
    const executeChecked = async (check, phase) => {
      let result;
      if (check.generator && phase === 'confirmation') {
        reproducibility = await verifyGeneratorReproducibility({
          executeGenerator: (run) => execute(check, `confirmation-generator-${run}`),
          fingerprint: () => d.workingTreeFingerprint(initial.repo, reproducibilityPaths),
        });
        reproducibility.paths = reproducibilityPaths;
        // A generator run that fails is returned as the top-level result
        // rather than under first/second; fall back to it so the row and the
        // head-side baseline signature keep the real exit code, output, and
        // timing instead of an empty terminal.
        const firstRun = reproducibility.first || reproducibility;
        const terminal = reproducibility.second || firstRun;
        // Preserve both generator attempts so renderMarkdown can count two
        // confirmation executions (Reruns observed / attempt IDs) instead of
        // treating the dual run as a single terminal-only row.
        const generatorAttempts = [reproducibility.first, reproducibility.second]
          .filter(Boolean);
        result = {
          ...check,
          phase,
          status: reproducibility.status,
          exitCode: terminal.exitCode ?? null,
          startedAt: firstRun.startedAt,
          finishedAt: terminal.finishedAt,
          durationMs: (firstRun.durationMs || 0) + (reproducibility.second?.durationMs || 0),
          stdout: terminal.stdout || '',
          stderr: terminal.stderr || '',
          evidence: reproducibility.evidence,
          first: reproducibility.first,
          second: reproducibility.second,
          attempts: generatorAttempts.length > 0 ? generatorAttempts : undefined,
        };
      } else {
        result = await execute(check, phase);
      }
      if (result.status === 'PASS') return result;
      // Baseline attribution is optional once head already failed. An
      // infrastructure throw from verifyBaseline (worktree create, filter
      // enumeration, etc.) must not replace a proven FAIL with BLOCKED.
      try {
        const baselineRow = await serializeBaseline(() => d.verifyBaseline({
          repo: initial.repo,
          baseSha: initial.baseSha,
          check,
          headResult: result,
          // Thread the sanitized childEnv into the disposable baseline worktree so
          // the internal git worktree add/remove runs with the filtered environment
          // (not ambient process.env/CI secrets), matching the command executor.
          env: childEnv,
          // Generator head failures use two-pass fingerprinting; baseline must
          // reproduce with the same two-run protocol, not a single generator exec.
          execute: async (baselineCheck, cwd) => {
            if (check.generator) {
              const repro = await verifyGeneratorReproducibility({
                executeGenerator: (run) => execute({
                  ...baselineCheck,
                  id: `${check.id}-baseline-comparison-gen-${run}`,
                  associatedCheckId: check.id,
                  attemptId: `${check.id}:baseline-gen-${run}:${++baselineAttempt}`,
                  generator: true,
                }, 'baseline', cwd),
                fingerprint: () => d.workingTreeFingerprint(cwd, reproducibilityPaths),
              });
              const firstRun = repro.first || repro;
              const terminal = repro.second || firstRun;
              return {
                ...baselineCheck,
                phase: 'baseline',
                status: repro.status,
                exitCode: terminal.exitCode ?? null,
                startedAt: firstRun.startedAt,
                finishedAt: terminal.finishedAt,
                durationMs: (firstRun.durationMs || 0) + (repro.second?.durationMs || 0),
                stdout: terminal.stdout || '',
                stderr: terminal.stderr || '',
                evidence: repro.evidence,
                first: repro.first,
                second: repro.second,
              };
            }
            return execute({
              ...baselineCheck,
              id: `${check.id}-baseline-comparison`,
              associatedCheckId: check.id,
              attemptId: `${check.id}:baseline:${++baselineAttempt}`,
            }, 'baseline', cwd);
          },
          setup: (cwd) => execute({
            id: `${check.id}-baseline-dependency-setup`,
            associatedCheckId: check.id,
            attemptId: `${check.id}:baseline-setup:${++baselineAttempt}`,
            command: baselineSetupCommand,
            baselineSafe: false,
          }, 'baseline-setup', cwd),
          toolVersions: preflight.toolVersions,
          captureVersions: async (cwd) => (await d.runPreflight({
            repo: cwd,
            config: { minFreeDiskGb: 0 },
            // Pass the sanitized childEnv so the disposable base worktree's
            // version probes use the same isolated environment as admission
            // preflight and command execution, instead of falling back to
            // process.env and leaking ambient CI credentials into the baseline
            // comparison.
            env: childEnv,
            toolProbes,
          })).toolVersions,
        }));
        // verifyBaseline can reclassify a generator confirmation row away
        // from its pre-baseline status (most notably FAIL -> BASELINE when
        // the failure reproduces exactly at base). The shared
        // `reproducibility` value assigned above is what evaluateOverallStatus
        // reads independently of this row, so leaving it at the stale status
        // here would let a resolved BASELINE/BLOCKED confirmation still
        // report the overall run as FAIL (FAIL outranks BASELINE/BLOCKED in
        // evaluateOverallStatus), misattributing a pre-existing generator
        // failure to this PR.
        if (check.generator && baselineRow.status !== result.status) {
          reproducibility = { ...reproducibility, status: baselineRow.status, evidence: baselineRow.evidence };
        }
        return baselineRow;
      } catch (error) {
        const note = error?.message || String(error);
        return {
          ...result,
          status: result.status === 'FAIL' ? 'FAIL' : 'BLOCKED',
          evidence: [
            result.evidence,
            `Baseline comparison unavailable (infrastructure error; head result preserved): ${note}`,
          ].filter(Boolean).join('\n'),
        };
      }
    };
    phases = await runValidationPhases({
      checks: plan.checks,
      execute: executeChecked,
      parallelism: Math.max(1, Math.min(Number(config.parallelism) || 4, 8)),
    });
  }

  const finalState = await d.resolveRepositoryState({ repo: initial.repo, baseRef });
  const consistencyProblems = [];
  if (finalState.headSha !== initial.headSha) {
    consistencyProblems.push(`HEAD changed during validation: ${initial.headSha} -> ${finalState.headSha}.`);
  }
  if (finalState.baseSha !== initial.baseSha) {
    consistencyProblems.push(`Live base changed during validation: ${initial.baseSha} -> ${finalState.baseSha}.`);
  }
  const headConsistency = consistencyProblems.length
    ? { status: 'BLOCKED', evidence: consistencyProblems.join(' ') }
    : { status: 'PASS', evidence: `Evidence belongs to final base ${finalState.baseSha} and head ${finalState.headSha}.` };
  // Cheap clean-tree probe before any fingerprint: a dirty tree already fails
  // closeout, so skip streaming multi-gigabyte untracked artifacts through
  // workingTreeFingerprint on the dirty path (before and after GitHub).
  const preGithubCleanTree = attestationAdmitted
    ? await d.cleanTreeStatus(finalState.repo)
    : { status: 'BLOCKED', evidence: 'Pre-GitHub tree inspection did not run because attestation admission was not clean.' };
  const beforeGithubFingerprint = (attestationAdmitted && preGithubCleanTree.status === 'PASS')
    ? await d.workingTreeFingerprint(finalState.repo, reproducibilityPaths)
    : null;
  const livePrState = await d.readLivePrState({
    repo: finalState.repo,
    expectedHeadSha: finalState.headSha,
    expectedBaseSha: finalState.baseSha,
    expectedConfigDigest: configDigest,
  });
  const observedState = await d.resolveRepositoryState({ repo: finalState.repo, baseRef });
  let finalSuppressions = [];
  let cleanTree = { status: 'BLOCKED', evidence: 'Final tree inspection did not run because attestation admission was not clean.' };
  let finalGateChanges = { changedFiles: [], addedLines: [] };
  if (attestationAdmitted) {
    [finalSuppressions, cleanTree, finalGateChanges] = await Promise.all([
      d.scanTouchedSuppressions(observedState.repo, observedState.touchedFiles),
      d.cleanTreeStatus(observedState.repo),
      d.readGateChanges(observedState.repo, observedState.mergeBaseSha || observedState.baseSha),
    ]);
    // Surface pre-GitHub dirt: a dirty probe that later cleans up must still
    // fail the clean-tree gate so the run cannot PASS after skipping the
    // before-GitHub fingerprint for performance.
    if (preGithubCleanTree.status !== 'PASS' && cleanTree.status === 'PASS') {
      cleanTree = {
        status: preGithubCleanTree.status === 'FAIL' ? 'FAIL' : 'BLOCKED',
        evidence: `Pre-GitHub working tree was not clean before live verification: ${preGithubCleanTree.evidence}`,
      };
    }
  }
  const afterGithubFingerprint = (attestationAdmitted && cleanTree.status === 'PASS')
    ? await d.workingTreeFingerprint(observedState.repo, reproducibilityPaths)
    : null;
  const sealedState = await d.resolveRepositoryState({ repo: observedState.repo, baseRef });
  let repositorySeal = attestationAdmitted
    ? sealRepository({
      validatedState: finalState,
      observedState,
      sealedState,
      initialFingerprint,
      beforeFingerprint: beforeGithubFingerprint,
      afterFingerprint: afterGithubFingerprint,
    })
    : {
      status: 'BLOCKED',
      evidence: 'Repository seal did not run because attestation admission was not clean.',
      initialFingerprint,
      beforeFingerprint: null,
      afterFingerprint: null,
    };
  if (attestationAdmitted && initialTree.status === 'PASS') {
    gateIntegrity = classifyGateIntegrity({
      ...finalGateChanges,
      configuredCommands,
      baseSha: sealedState.baseSha,
      headSha: sealedState.headSha,
      configDigest,
      attestation: livePrState.gateAttestation,
    });
  }
  // Include safeEnv alongside requiredEnv so custom secrets named only in
  // safeEnv (and embedded in configuredCommands / gateIntegrity) are redacted
  // from workflow-level reports — executors already redact both lists.
  const reportSecretNames = [...(config.requiredEnv || []), ...(config.safeEnv || [])];
  let report = normalizePersistedPaths(redactStructure({
    schemaVersion: 2,
    repository: sealedState.repo,
    baseRef: sealedState.baseRef,
    baseSha: sealedState.baseSha,
    mergeBaseSha: sealedState.mergeBaseSha,
    headSha: sealedState.headSha,
    configDigest,
    mode,
    // Engine runs name their matrix provenance so a reader of report.json can
    // never mistake a repo-defined matrix for the strict 19-check gate.
    matrixSource: mode === 'engine'
      ? { source: 'config.engineChecks', digest: configDigest, checkCount: plan.checks.length }
      : null,
    startedAt,
    finishedAt: new Date().toISOString(),
    toolVersions: preflight.toolVersions,
    preflight,
    planErrors: plan.errors,
    planStatus,
    gateIntegrity,
    reproducibility,
    headConsistency,
    repositorySeal,
    initialTree: { ...initialTree, fingerprint: initialFingerprint },
    preGithubCleanTree,
    cleanTree,
    livePrState,
    touchedFiles: sealedState.touchedFiles,
    suppressionFindings: finalSuppressions,
    qualificationChecks: phases.qualification,
    checks: phases.confirmation,
  }, process.env, reportSecretNames), sealedState.repo, resolvedOutput);
  report.overallStatus = evaluateOverallStatus({
    planStatus,
    preflight,
    gateIntegrity,
    phases,
    reproducibility,
    preGithubCleanTree,
    cleanTree,
    headConsistency,
    repositorySeal,
    livePrState,
    suppressionFindings: finalSuppressions,
  });
  const provisional = {
    ...report,
    overallStatus: 'BLOCKED',
    repositorySeal: {
      ...report.repositorySeal,
      status: 'BLOCKED',
      evidence: 'Provisional evidence was written; the evidence-write repository seal is pending.',
      evidenceWrite: {
        status: 'BLOCKED',
        evidence: 'Pending verification after the provisional evidence write.',
        fingerprint: null,
      },
    },
  };
  await d.prepareOutputDirectory({ repo: initial.repo, outputDir: resolvedOutput });
  await d.writeEvidenceReport({ outputDir: resolvedOutput, report: provisional });
  const evidenceState = await d.resolveRepositoryState({ repo: sealedState.repo, baseRef });
  const evidenceFingerprint = attestationAdmitted
    ? await d.workingTreeFingerprint(evidenceState.repo, reproducibilityPaths)
    : null;
  const evidenceSeal = attestationAdmitted
    ? sealRepository({
      validatedState: sealedState,
      observedState: evidenceState,
      sealedState: evidenceState,
      beforeFingerprint: afterGithubFingerprint,
      afterFingerprint: evidenceFingerprint,
    })
    : {
      status: 'BLOCKED',
      evidence: 'Evidence-write seal did not run because attestation admission was not clean.',
    };
  repositorySeal = {
    ...repositorySeal,
    status: repositorySeal.status === 'PASS' && evidenceSeal.status === 'PASS'
      ? 'PASS'
      : (repositorySeal.status === 'FAIL' || evidenceSeal.status === 'FAIL' ? 'FAIL' : 'BLOCKED'),
    evidenceWrite: {
      status: evidenceSeal.status,
      evidence: evidenceSeal.evidence,
      fingerprint: evidenceFingerprint,
    },
  };
  report = {
    ...report,
    repositorySeal: normalizePersistedPaths(repositorySeal, sealedState.repo, resolvedOutput),
  };
  report.overallStatus = evaluateOverallStatus({
    planStatus,
    preflight,
    gateIntegrity,
    phases,
    reproducibility,
    preGithubCleanTree,
    cleanTree,
    headConsistency,
    repositorySeal,
    livePrState,
    suppressionFindings: finalSuppressions,
  });
  await d.prepareOutputDirectory({ repo: initial.repo, outputDir: resolvedOutput });
  let paths = await d.writeEvidenceReport({ outputDir: resolvedOutput, report });
  // Post-write seal: a same-user swap of the output directory (or an ancestor)
  // after prepareOutputDirectory could redirect report.json/report.md into the
  // repository. Re-fingerprint and rewrite the report as non-PASS if the tree
  // moved after the evidence write.
  if (attestationAdmitted) {
    const postWriteState = await d.resolveRepositoryState({ repo: sealedState.repo, baseRef });
    const postWriteFingerprint = await d.workingTreeFingerprint(postWriteState.repo, reproducibilityPaths);
    const postWriteSeal = sealRepository({
      validatedState: evidenceState,
      observedState: postWriteState,
      sealedState: postWriteState,
      beforeFingerprint: evidenceFingerprint,
      afterFingerprint: postWriteFingerprint,
    });
    if (postWriteSeal.status !== 'PASS') {
      repositorySeal = {
        ...repositorySeal,
        status: repositorySeal.status === 'FAIL' || postWriteSeal.status === 'FAIL' ? 'FAIL' : 'BLOCKED',
        evidenceWrite: {
          status: postWriteSeal.status,
          evidence: `Post-write seal failed: ${postWriteSeal.evidence}`,
          fingerprint: postWriteFingerprint,
        },
      };
      report = {
        ...report,
        repositorySeal: normalizePersistedPaths(repositorySeal, sealedState.repo, resolvedOutput),
      };
      report.overallStatus = evaluateOverallStatus({
        planStatus,
        preflight,
        gateIntegrity,
        phases,
        reproducibility,
        preGithubCleanTree,
        cleanTree,
        headConsistency,
        repositorySeal,
        livePrState,
        suppressionFindings: finalSuppressions,
      });
      await d.prepareOutputDirectory({ repo: initial.repo, outputDir: resolvedOutput });
      paths = await d.writeEvidenceReport({ outputDir: resolvedOutput, report });
    }
  }
  return { report, paths };
};

module.exports = {
  acquireOutputDirLock,
  assertOutputDirLockIdentity,
  defaultOutputDir,
  evaluateOverallStatus,
  isSameLockIdentity,
  mergeEngineTimeouts,
  normalizePersistedPaths,
  prepareOutputDirectory,
  releaseOutputDirLock,
  resolveEngineToolProbes,
  resolvePlanAdmission,
  runCloseoutWorkflow,
  sealRepository,
};
