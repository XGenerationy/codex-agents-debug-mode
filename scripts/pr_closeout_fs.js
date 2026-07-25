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
 * @param {string} target
 * @param {number} flags
 * @param {number} [mode=0o666]
 * @returns {Promise<import('node:fs/promises').FileHandle>}
 */
const openNoFollow = async (target, flags, mode = 0o666) => {
  const noFollow = constants.O_NOFOLLOW || 0;
  try {
    return await open(target, flags | noFollow, mode);
  } catch (error) {
    if (!noFollow || !['EINVAL', 'ENOTSUP', 'EOPNOTSUPP'].includes(error?.code)) throw error;
    return open(target, flags, mode);
  }
};

module.exports = {
  assertNotSymlink,
  openNoFollow,
};
