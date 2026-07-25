const { constants } = require('node:fs');
const { lstat, open } = require('node:fs/promises');

/**
 * Reject a pre-existing symlink at `target` (fail-closed), tolerating ENOENT
 * (the path is about to be created). Shared by report writes, evidence logs,
 * and the debug collector so symlink guards stay in lockstep.
 * @param {string} target
 * @param {string} message - Error message when the path is a symlink.
 */
const assertNotSymlink = async (target, message) => {
  let info;
  try {
    info = await lstat(target);
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }
  if (info.isSymbolicLink()) {
    throw new Error(message);
  }
};

/**
 * Ordered open-flag attempts for openNoFollow when both O_NOFOLLOW and
 * O_NONBLOCK may be unavailable on a given platform/FS.
 *
 * Order:
 * 1. preferred = flags | NOFOLLOW | NONBLOCK
 * 2. drop NOFOLLOW, keep NONBLOCK (FIFO hang defense)
 * 3. drop NONBLOCK, keep NOFOLLOW (symlink TOCTOU defense when NONBLOCK is
 *    the unsupported bit — never skip this after a failed NONBLOCK-only try)
 * 4. plain flags (last resort; callers still use assertNotSymlink + fd.stat)
 *
 * Duplicates are collapsed so platforms missing one constant still get a
 * short path (preferred → plain).
 * @param {number} flags
 * @param {number} noFollow
 * @param {number} nonBlock
 * @returns {number[]}
 */
const openNoFollowFlagAttempts = (flags, noFollow, nonBlock) => {
  const attempts = [];
  const add = (value) => {
    if (!attempts.includes(value)) attempts.push(value);
  };
  add(flags | noFollow | nonBlock);
  if (noFollow && nonBlock) {
    add(flags | nonBlock);
    add(flags | noFollow);
  }
  add(flags);
  return attempts;
};

/**
 * Open `target` without following a symlinked final component.
 * `O_NOFOLLOW` is OR'd into `flags` when the platform defines it. On platforms
 * without the flag (or filesystems that reject it with EINVAL/ENOTSUP/
 * EOPNOTSUPP), falls back through openNoFollowFlagAttempts — callers must
 * still run assertNotSymlink first as the primary guard when NOFOLLOW is
 * unavailable. ELOOP is rethrown as-is so callers can map it to a
 * domain-specific message.
 *
 * `O_NONBLOCK` is also OR'd when defined so a TOCTOU swap to a FIFO between
 * the caller's lstat and this open cannot hang indefinitely waiting for a
 * writer/reader. Callers that open for read then re-check `handle.stat()`
 * and reject non-regular descriptors (suppression/gate scanners, hashFile,
 * evidence logs). Regular-file I/O is unaffected; the constant is 0 on
 * platforms that lack it (e.g. some Windows builds).
 *
 * Unsupported-flag recovery never retries the same combo twice. When both
 * extras are present and the combo fails, it tries NONBLOCK-only, then
 * NOFOLLOW-only, then plain flags — so a platform that rejects NONBLOCK still
 * keeps NOFOLLOW protection instead of falling straight to a following open.
 *
 * `flags` defaults to `O_RDONLY` so one-argument callers (suppression/gate
 * scanners that open for read) keep working. Explicit non-integer flags
 * (e.g. string modes like `'a'`) still throw TypeError so they cannot coerce
 * via `|` to O_RDONLY.
 * @param {string} target
 * @param {number} [flags=constants.O_RDONLY]
 * @param {number} [mode=0o666]
 * @returns {Promise<import('node:fs/promises').FileHandle>}
 */
const openNoFollow = async (target, flags = constants.O_RDONLY, mode = 0o666) => {
  if (!Number.isInteger(flags)) {
    throw new TypeError('openNoFollow requires numeric fs.constants flags.');
  }
  const noFollow = constants.O_NOFOLLOW || 0;
  const nonBlock = constants.O_NONBLOCK || 0;
  const attempts = openNoFollowFlagAttempts(flags, noFollow, nonBlock);
  const unsupported = (code) => ['EINVAL', 'ENOTSUP', 'EOPNOTSUPP'].includes(code);

  let lastError;
  for (let i = 0; i < attempts.length; i += 1) {
    try {
      return await open(target, attempts[i], mode);
    } catch (error) {
      lastError = error;
      const canRetry = i < attempts.length - 1 && unsupported(error?.code);
      if (!canRetry) throw error;
    }
  }
  throw lastError;
};

module.exports = {
  assertNotSymlink,
  openNoFollow,
  openNoFollowFlagAttempts,
};
