const { execFile, execFileSync } = require('node:child_process');
const { constants, existsSync } = require('node:fs');
const { lstat, open } = require('node:fs/promises');
const path = require('node:path');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);

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
// These three helpers model an inherently Windows-shaped path (a
// backslash-separated "C:\Windows"/SystemRoot root) regardless of which OS
// actually runs this code, so they must use path.win32 explicitly rather
// than the platform-dependent `path` import above: on POSIX (e.g. this
// suite's Linux CI job), the generic `path` module treats `\` as a literal
// character rather than a separator, so path.basename/path.normalize/
// path.join silently mis-parse "C:\Windows" and both looksLikeWindowsRoot
// checks (hard-coded and env root) would break the same way, always
// falling through to an un-joined hard-coded root instead of exercising the
// intended trust logic (CI failure on Node 24/ubuntu-latest: resolved
// 'C:\Windows' instead of falling back to a verified env root).
// "Windows" must sit directly at a drive root (X:\Windows), not merely be the
// final component of a deeper path. A basename-only check (`...\Windows`)
// accepts an attacker-writable nested directory such as
// C:\Users\<user>\Windows, which -- with a planted powershell.exe/taskkill.exe
// at the matching relative path -- would be handed to execFile/execFileSync
// whenever the hard-coded C:\Windows probe is unavailable (Codex UiTMt).
// Anchoring to the drive root fails that shape closed while still accepting a
// genuine Windows install on any volume (C:\Windows, D:\Windows).
const looksLikeWindowsRoot = (root) => {
  const normalized = path.win32.normalize(root).replace(/[\\/]+$/u, '');
  return /^[A-Za-z]:[\\/]Windows$/iu.test(normalized);
};

// extraRelativePaths lets callers that resolve additional root-relative
// binaries (e.g. pr_closeout_process.js also needs a verified taskkill.exe)
// fold that requirement into the same trust check instead of forking their
// own copy of the powershell.exe verification it depends on.
const isTrustedSystemRoot = (root, pathExists, extraRelativePaths = []) => {
  if (!looksLikeWindowsRoot(root)) return false;
  const requiredRelativePaths = [
    path.win32.join('System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    ...extraRelativePaths,
  ];
  return requiredRelativePaths.every((relativePath) => pathExists(path.win32.join(root, relativePath)));
};

const resolvePowerShellExecutable = ({ env = process.env, pathExists = existsSync } = {}) => {
  const hardcodedRoot = 'C:\\Windows';
  const envRoot = String(env.SystemRoot || '').trim();
  // Fail closed to the hard-coded root: the env-supplied root is only trusted
  // when it is a drive-root-anchored Windows install (looksLikeWindowsRoot,
  // now `X:\Windows` only) AND independently verified to contain the real
  // powershell.exe. When the hard-coded C:\Windows probe fails, an
  // attacker-controlled SystemRoot with a planted binary at a nested,
  // non-anchored path (e.g. C:\Users\<user>\Windows) is rejected by the shape
  // check and safeRoot stays C:\Windows rather than the planted tree (UiTMt).
  let safeRoot = hardcodedRoot;
  if (!isTrustedSystemRoot(hardcodedRoot, pathExists) && isTrustedSystemRoot(envRoot, pathExists)) {
    safeRoot = envRoot;
  }
  return path.win32.join(safeRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
};

// PowerShell/execFile arguments that establish and verify a protected,
// current-user-only Windows DACL on `privateFile`. Shared by the synchronous
// and asynchronous entry points so they stay byte-for-byte identical. The
// program is fixed and the path is embedded only as UTF-16 base64, so
// repository-controlled path characters cannot become code.
//
// Beyond the DACL (inheritance broken, every rule removed, single owner
// FullControl rule), the script also calls $acl.SetOwner($sid) before writing
// and verifies GetOwner() on read-back: a Windows file OWNER retains implicit
// WRITE_DAC and can rewrite the DACL later, so a file that already existed
// under a different owner in a shared location must be taken over, not just
// re-permissioned (Codex UiXEn). Any failed step exits non-zero so the Node
// wrapper throws and the caller fails closed before any bytes are written.
const buildProtectWindowsPrivateFileArgs = (privateFile) => {
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
    '$acl.SetOwner($sid)',
    '[IO.File]::SetAccessControl($path, $acl)',
    '$verified = [IO.File]::GetAccessControl($path)',
    'if (-not $verified.AreAccessRulesProtected) { exit 1 }',
    'if ($verified.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { exit 1 }',
    '$rules = @($verified.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))',
    'if ($rules.Count -ne 1 -or $rules[0].IdentityReference.Value -ne $sid.Value -or $rules[0].AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or (($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne [Security.AccessControl.FileSystemRights]::FullControl)) { exit 1 }',
  ].join('; ');
  return ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')];
};

// Hosted and freshly provisioned Windows profiles can take more than five
// seconds to load PowerShell/.NET ACL types. Keep the operation bounded and
// fail closed, but allow a realistic startup budget before reporting failure.
const PROTECT_WINDOWS_PRIVATE_FILE_TIMEOUT_MS = 15_000;

/**
 * Establish and verify a protected, current-user-only Windows DACL (and owner)
 * on `privateFile` (owner FullControl, inheritance broken, every other rule
 * removed, owner set to the current user). No-op on non-Windows platforms.
 * Shared by the debug collector (token file, session logs) and closeout
 * evidence logs so the guard stays one implementation across security-critical
 * write paths. Synchronous: only use on startup/CLI paths where blocking the
 * event loop is acceptable; request handlers must use
 * protectWindowsPrivateFileAsync instead.
 * @param {string} privateFile
 */
const protectWindowsPrivateFile = (privateFile) => {
  if (process.platform !== 'win32') return;
  execFileSync(
    resolvePowerShellExecutable(),
    buildProtectWindowsPrivateFileArgs(privateFile),
    { stdio: 'ignore', timeout: PROTECT_WINDOWS_PRIVATE_FILE_TIMEOUT_MS, windowsHide: true },
  );
};

/**
 * Asynchronous sibling of protectWindowsPrivateFile: runs the identical fixed
 * PowerShell program (same DACL + owner hardening and verification, same 15s
 * timeout) via a promisified child_process.execFile instead of execFileSync,
 * so a request-serving path (the /session handler) does not block the Node
 * event loop for up to the full timeout on every call. No-op on non-Windows
 * platforms. Rejects (fails closed) on any non-zero exit exactly as the
 * synchronous variant throws.
 * @param {string} privateFile
 * @returns {Promise<void>}
 */
const protectWindowsPrivateFileAsync = async (privateFile) => {
  if (process.platform !== 'win32') return;
  await execFileAsync(
    resolvePowerShellExecutable(),
    buildProtectWindowsPrivateFileArgs(privateFile),
    { timeout: PROTECT_WINDOWS_PRIVATE_FILE_TIMEOUT_MS, windowsHide: true },
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

/**
 * True when `postInfo` still identifies the exact same on-disk file as
 * `preInfo` (same device/inode, and not multiply-linked since the snapshot).
 * Stricter than isSameFileIdentity: also requires ctimeMs to match, so it is
 * only appropriate for reclaim-style checks where no legitimate operation is
 * expected to change the file's metadata between the two snapshots (a stale
 * lock or claim record being re-verified immediately before deletion) --
 * unlike isSameFileIdentity's other callers (write/ACL-protect
 * verification), where the intervening operation itself legitimately changes
 * ctimeMs and this check would wrongly reject the very write it is meant to
 * confirm.
 *
 * dev/ino alone is not sufficient: on Linux (notably tmpfs, which is a common
 * CI /tmp mount), an inode number freed by unlink can be reused by the very
 * next file created in the same directory, so a peer that unlinks a stale
 * lock/claim and immediately writes its own successor can end up with the
 * exact same dev/ino the stale snapshot recorded. Requiring ctimeMs to also
 * match closes that gap: any unlink+recreate (even one that lands on a
 * reused inode) gives the occupant a fresh change time the original stale
 * file's snapshot cannot share (Codex Uert4 follow-up, caught by CI on Linux
 * after the dev/ino-only check shipped).
 *
 * ctimeMs still has only millisecond resolution, so an unlink+recreate that
 * both reuses the inode AND lands inside the same millisecond can collide on
 * ctimeMs too (Codex UkAeu, reproduced on the CI filesystem). birthtimeMs is
 * required as an independent second time dimension to shrink that window: it
 * records the file's creation time and -- unlike ctimeMs -- is not advanced by
 * the ACL-protection and content writes these lock/claim records undergo after
 * they are created, so a stale record whose ctimeMs was bumped post-creation
 * cannot match a same-millisecond successor on birthtimeMs unless BOTH the
 * birth time and the change time collide within the same millisecond. It never
 * wrongly rejects a genuine same file: birthtime is immutable for an inode's
 * lifetime, and on filesystems that do not record it (Node falls birthtimeMs
 * back to ctimeMs or 0) the term is a harmless no-op because ctimeMs is already
 * required to match. This is defense in depth, not a full guarantee -- the
 * sub-millisecond residual is deliberately closed at the call sites
 * (pr_closeout_workflow.js output-dir lock, debug_server.js collector-claim
 * reclaim) by quarantining the entry and re-verifying its bytes before
 * deletion; strengthening this predicate narrows the window each independent
 * layer must otherwise cover.
 * @param {import('node:fs').Stats} preInfo
 * @param {import('node:fs').Stats} postInfo
 * @returns {boolean}
 */
const isSameLockIdentity = (preInfo, postInfo) => (
  preInfo.ino !== 0
  && postInfo.dev === preInfo.dev
  && postInfo.ino === preInfo.ino
  && postInfo.nlink <= 1
  && postInfo.ctimeMs === preInfo.ctimeMs
  && postInfo.birthtimeMs === preInfo.birthtimeMs
);

module.exports = {
  assertNotSymlink,
  isSameFileIdentity,
  isSameLockIdentity,
  isTrustedSystemRoot,
  looksLikeWindowsRoot,
  openNoFollow,
  openNoFollowFlagAttempts,
  protectWindowsPrivateFile,
  protectWindowsPrivateFileAsync,
  resolvePowerShellExecutable,
};
