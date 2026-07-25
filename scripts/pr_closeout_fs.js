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
 * Open `target` without following a symlinked final component.
 * `O_NOFOLLOW` is OR'd into `flags` when the platform defines it. On platforms
 * without the flag (or filesystems that reject it with EINVAL/ENOTSUP/
 * EOPNOTSUPP), falls back to a plain open — callers must still run
 * assertNotSymlink first as the primary guard there. ELOOP is rethrown as-is
 * so callers can map it to a domain-specific message.
 *
 * `O_NONBLOCK` is also OR'd when defined so a TOCTOU swap to a FIFO between
 * the caller's lstat and this open cannot hang indefinitely waiting for a
 * writer/reader. Callers that open for read then re-check `handle.stat()`
 * and reject non-regular descriptors (suppression/gate scanners, hashFile,
 * evidence logs). Regular-file I/O is unaffected; the constant is 0 on
 * platforms that lack it (e.g. some Windows builds).
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
  const preferred = flags | noFollow | nonBlock;
  try {
    return await open(target, preferred, mode);
  } catch (error) {
    if (!['EINVAL', 'ENOTSUP', 'EOPNOTSUPP'].includes(error?.code)) throw error;
    // Platform rejected the flag combo. Drop NOFOLLOW first (keep NONBLOCK
    // so a FIFO still cannot hang), then plain flags as last resort.
    if (noFollow) {
      try {
        return await open(target, flags | nonBlock, mode);
      } catch (error2) {
        if (!nonBlock || !['EINVAL', 'ENOTSUP', 'EOPNOTSUPP'].includes(error2?.code)) {
          throw error2;
        }
      }
    }
    if (nonBlock) {
      try {
        return await open(target, flags | nonBlock, mode);
      } catch (error3) {
        if (!['EINVAL', 'ENOTSUP', 'EOPNOTSUPP'].includes(error3?.code)) throw error3;
      }
    }
    return open(target, flags, mode);
  }
};

module.exports = {
  assertNotSymlink,
  openNoFollow,
};
