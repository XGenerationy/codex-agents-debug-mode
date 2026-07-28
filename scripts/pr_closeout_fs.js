const { execFileSync } = require('node:child_process');
const { constants, existsSync } = require('node:fs');
const { lstat, open } = require('node:fs/promises');
const path = require('node:path');

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

// Windows does not implement POSIX 0600 semantics: fs.chmod() only affects
// the writable bit, leaving inherited DACL entries able to read a private
// file (collector_token, a session log, an evidence log) in a shared
// checkout. Configure an explicit, protected DACL before any secret or
// captured evidence is written. The PowerShell program is fixed and the path
// is embedded only as UTF-16 base64, so repository-controlled path
// characters cannot become code. If PowerShell, the filesystem, or ACL
// verification fails, the caller must fail closed before the file receives
// any bytes.
// Resolve powershell.exe by absolute system path rather than PATH lookup: a
// PATH-relative execFileSync could run an attacker-controlled powershell.exe
// earlier on PATH instead of the trusted system one. SystemRoot itself is
// untrusted process.env input (Codex UfzOm) -- joining it in unconditionally
// would let a caller point it at a writable planted tree and get arbitrary
// code execution via execFileSync. Prefer the hard-coded C:\Windows whenever
// it actually contains powershell.exe, and only fall back to an env-supplied
// root that both looks like a Windows install (final path component
// "Windows") and is independently verified to contain powershell.exe at that
// exact location.
const looksLikeWindowsRoot = (root) => {
  const normalized = path.normalize(root).replace(/[\\/]+$/u, '');
  return /^[A-Za-z]:[\\/]/u.test(normalized)
    && path.basename(normalized).toLowerCase() === 'windows';
};

const isTrustedSystemRoot = (root, pathExists) => {
  if (!looksLikeWindowsRoot(root)) return false;
  return pathExists(path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'));
};

const resolvePowerShellExecutable = ({ env = process.env, pathExists = existsSync } = {}) => {
  const hardcodedRoot = 'C:\\Windows';
  const envRoot = String(env.SystemRoot || '').trim();
  let safeRoot = hardcodedRoot;
  if (!isTrustedSystemRoot(hardcodedRoot, pathExists) && isTrustedSystemRoot(envRoot, pathExists)) {
    safeRoot = envRoot;
  }
  return path.join(safeRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
};

/**
 * Establish and verify a protected, current-user-only Windows DACL on
 * `privateFile` (owner FullControl, inheritance broken, every other rule
 * removed). No-op on non-Windows platforms. Shared by the debug collector
 * (token file, session logs) and closeout evidence logs so the guard stays
 * one implementation across security-critical write paths.
 * @param {string} privateFile
 */
const protectWindowsPrivateFile = (privateFile) => {
  if (process.platform !== 'win32') return;
  const encodedPath = Buffer.from(privateFile, 'utf16le').toString('base64');
  const script = [
    '$ErrorActionPreference = "Stop"',
    `$path = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${encodedPath}'))`,
    '$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User',
    '$acl = [IO.File]::GetAccessControl($path)',
    '$acl.SetAccessRuleProtection($true, $false)',
    'foreach ($rule in @($acl.Access)) { [void]$acl.RemoveAccessRuleSpecific($rule) }',
    '$ownerRule = New-Object Security.AccessControl.FileSystemAccessRule($sid, [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.AccessControlType]::Allow)',
    '$acl.SetAccessRule($ownerRule)',
    '[IO.File]::SetAccessControl($path, $acl)',
    '$verified = [IO.File]::GetAccessControl($path)',
    'if (-not $verified.AreAccessRulesProtected) { exit 1 }',
    '$rules = @($verified.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))',
    'if ($rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid.Value -or $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or (($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl)) { exit 1 }',
  ].join('; ');
  execFileSync(
    resolvePowerShellExecutable(),
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    // Hosted and freshly provisioned Windows profiles can take more than five
    // seconds to load PowerShell/.NET ACL types. Keep the operation bounded
    // and fail closed, but allow a realistic startup budget before reporting
    // failure.
    { stdio: 'ignore', timeout: 15_000, windowsHide: true },
  );
};

// Some Windows filesystems (and older Node releases on certain mounts) report
// dev/ino as 0 for every file. A same-path swap between two stat calls would
// otherwise pass this identity check vacuously when both sides read 0/0, so a
// zero ino is rejected outright rather than trusted as a real identity.
// Shared by the debug collector (token/session-log/port writes) and closeout
// evidence logs so this TOCTOU binding stays one implementation.
const isSameFileIdentity = (preInfo, postInfo) => (
  preInfo.ino !== 0
  && postInfo.dev === preInfo.dev
  && postInfo.ino === preInfo.ino
  && postInfo.nlink <= 1
);

module.exports = {
  assertNotSymlink,
  isSameFileIdentity,
  isTrustedSystemRoot,
  looksLikeWindowsRoot,
  openNoFollow,
  openNoFollowFlagAttempts,
  protectWindowsPrivateFile,
  resolvePowerShellExecutable,
};
