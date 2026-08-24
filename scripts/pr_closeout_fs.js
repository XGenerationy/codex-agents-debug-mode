const { execFileSync, spawn } = require('node:child_process');
const { constants, existsSync, openSync } = require('node:fs');
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
 *
 * `requireNoFollow` (default false, CodeRabbit PR7 #6Yb1dD): when true, every
 * returned attempt keeps `noFollow` set — the NONBLOCK-only and plain-flags
 * fallbacks (which drop it) are omitted entirely. A caller doing a
 * destructive, truncating WRITE (unlike a read, whose result can simply be
 * discarded if the opened fd turns out not to be the expected file) cannot
 * safely fall through to a link-following open: `O_TRUNC` destroys whatever
 * the open resolves to at open time, before any caller-side check can run.
 * If `noFollow` itself is 0 (the platform has no O_NOFOLLOW at all), there is
 * no attempt that can carry real link-following protection. A destructive
 * caller must apply an independent symlink guard before calling this helper
 * (writeEvidenceFile's lstat-based guard on Windows is exactly this).
 * @param {number} flags
 * @param {number} noFollow
 * @param {number} nonBlock
 * @param {boolean} [requireNoFollow=false]
 * @returns {number[]}
 */
const openNoFollowFlagAttempts = (flags, noFollow, nonBlock, requireNoFollow = false) => {
  const attempts = [];
  const add = (value) => {
    if (!attempts.includes(value)) attempts.push(value);
  };
  add(flags | noFollow | nonBlock);
  if (noFollow && nonBlock) {
    if (!requireNoFollow) add(flags | nonBlock);
    add(flags | noFollow);
  }
  if (!requireNoFollow) add(flags);
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

/**
 * Synchronous counterpart to openNoFollow, for callers (like the closeout
 * action's support.js) that are fully sync throughout and cannot take on an
 * async conversion just for this one open call. Identical flag-selection and
 * unsupported-flag-recovery behavior — same openNoFollowFlagAttempts,
 * fs.openSync in place of fs.promises.open. Returns a numeric file
 * descriptor (not a FileHandle); callers are responsible for fs.closeSync.
 *
 * `requireNoFollow` (default false, CodeRabbit PR7 #6Yb1dD): set true for a
 * destructive, truncating write (an evidence file, e.g. `O_WRONLY|O_CREAT|
 * O_TRUNC`) where following a raced-in symlink would destroy an arbitrary
 * target the instant the open succeeds — unlike a read, there is no
 * after-the-fact check that can undo that. With it set, this drops the
 * fully-bare fallback attempt (the one with NEITHER extra flag), so if the
 * platform genuinely supports O_NOFOLLOW (a nonzero `constants.O_NOFOLLOW`)
 * but the OS rejects every attempt that carries it as unsupported, this
 * throws that real error instead of silently opening through a followed
 * symlink. On a platform where O_NOFOLLOW is entirely unavailable
 * (`constants.O_NOFOLLOW` reports 0, e.g. some Windows builds) OR'ing it in
 * is already a no-op, so this is unaffected there — those platforms never
 * had NOFOLLOW-level protection from this function to begin with; the
 * caller's own primary guard (an lstat-based symlink check before calling
 * this, as writeEvidenceFile already runs) is what protects them, exactly
 * as openNoFollow's own documented contract already requires.
 * @param {string} target
 * @param {number} [flags=constants.O_RDONLY]
 * @param {number} [mode=0o666]
 * @param {boolean} [requireNoFollow=false]
 * @returns {number} file descriptor
 */
const openNoFollowSync = (target, flags = constants.O_RDONLY, mode = 0o666, requireNoFollow = false) => {
  if (!Number.isInteger(flags)) {
    throw new TypeError('openNoFollowSync requires numeric fs.constants flags.');
  }
  const noFollow = constants.O_NOFOLLOW || 0;
  const nonBlock = constants.O_NONBLOCK || 0;
  const attempts = openNoFollowFlagAttempts(flags, noFollow, nonBlock, requireNoFollow);
  const unsupported = (code) => ['EINVAL', 'ENOTSUP', 'EOPNOTSUPP'].includes(code);

  let lastError;
  for (let i = 0; i < attempts.length; i += 1) {
    try {
      return openSync(target, attempts[i], mode);
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
const PROTECT_WINDOWS_PRIVATE_FILE_EXEC_OPTIONS = Object.freeze({
  stdio: 'ignore',
  timeout: PROTECT_WINDOWS_PRIVATE_FILE_TIMEOUT_MS,
  windowsHide: true,
});

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
 * @param {{execFileSyncFn?: typeof execFileSync, platform?: string}} [overrides]
 *   Test-only seam, mirroring resolvePowerShellExecutable's own options;
 *   production callers pass only `privateFile`.
 */
const protectWindowsPrivateFile = (privateFile, {
  execFileSyncFn = execFileSync, platform = process.platform,
} = {}) => {
  if (platform !== 'win32') return;
  execFileSyncFn(
    resolvePowerShellExecutable(),
    buildProtectWindowsPrivateFileArgs(privateFile),
    PROTECT_WINDOWS_PRIVATE_FILE_EXEC_OPTIONS,
  );
};

/**
 * Asynchronous sibling of protectWindowsPrivateFile: runs the identical fixed
 * PowerShell program (same DACL + owner hardening and verification, same 15s
 * timeout via the shared exec options) without blocking the Node event loop,
 * so a request-serving path (the /session handler) stays responsive for the
 * duration of the ACL work. No-op on non-Windows platforms. Rejects (fails
 * closed) on spawn failure, a non-zero exit, or signal death (including the
 * timeout kill) exactly where the synchronous variant throws.
 *
 * Built on spawn + the shared `stdio: 'ignore'`, NOT on a promisified
 * execFile: execFile does not honor `stdio` — it always buffers stdout and
 * stderr through pipes and settles only when those pipes close, and on hosted
 * windows-latest a PowerShell descendant held the inherited pipe handles open
 * past exit, so the promisified call hung until the 15s timeout on every
 * mint (POST /session → HTTP 500; the sync switch in 31c1f48 worked around
 * exactly this). spawn with stdio ignored creates no pipes to hold, and the
 * 'exit' event fires on process exit regardless of descendants.
 * @param {string} privateFile
 * @param {{spawnFn?: typeof spawn, platform?: string}} [overrides]
 *   Test-only seam, mirroring protectWindowsPrivateFile's above.
 * @returns {Promise<void>}
 */
const protectWindowsPrivateFileAsync = (privateFile, {
  spawnFn = spawn, platform = process.platform,
  deadlineMs = PROTECT_WINDOWS_PRIVATE_FILE_TIMEOUT_MS + 5_000,
} = {}) => new Promise((resolve, reject) => {
  if (platform !== 'win32') {
    resolve();
    return;
  }
  let child;
  try {
    child = spawnFn(
      resolvePowerShellExecutable(),
      buildProtectWindowsPrivateFileArgs(privateFile),
      PROTECT_WINDOWS_PRIVATE_FILE_EXEC_OPTIONS,
    );
  } catch (error) {
    reject(error);
    return;
  }
  // BACKSTOP DEADLINE, past the shared timeout's own kill: spawn's timeout
  // initiates TerminateProcess, but 'exit' fires only after the kernel
  // finishes tearing every thread down — a thread wedged in a non-alertable
  // kernel wait (hung filter driver, AV) can defer that indefinitely, and a
  // promise that settles only on 'error'/'exit' would then never settle,
  // holding its awaiting request open forever. The REJECT is the
  // load-bearing half (it bounds settlement whatever the child's fate); the
  // extra kill is best-effort. unref'd so a settled call never holds the
  // process open; a late 'exit' after this fires is a no-op on the settled
  // promise (review V2c hardening — the replaced sync variant wedged the
  // whole event loop in this same scenario).
  const deadline = setTimeout(() => {
    try { child.kill(); } catch { /* best effort */ }
    reject(new Error('windows_private_file_acl_failed: deadline'));
  }, deadlineMs);
  deadline.unref?.();
  child.once('error', (error) => {
    clearTimeout(deadline);
    reject(error);
  });
  child.once('exit', (code, signal) => {
    clearTimeout(deadline);
    if (code === 0) resolve();
    else reject(new Error(`windows_private_file_acl_failed: ${signal ?? code}`));
  });
});

// Some Windows filesystems (and older Node releases on certain mounts) report
// dev/ino as 0 for every file. A same-path swap between two stat calls would
// otherwise pass this identity check vacuously when both sides read 0/0, so a
// zero ino is rejected outright rather than trusted as a real identity.
// Shared by the debug collector (token/session-log/port writes) and closeout
// evidence logs so this TOCTOU binding stays one implementation.
//
// STRENGTH OF THE ino TERM: it is a float64 comparison, not an exact one.
// Node's default lstat reports ino as a Number, and on NTFS a 64-bit file
// reference above 2**53 loses its low bits, so two distinct files can compare
// equal here (measured on Windows 10 19045 / NTFS: 800 files in one directory,
// 797 distinct Number inos against 800 distinct BigInt inos, and this
// predicate returned true for two different files). It still rejects the
// same-path unlink+recreate, which moves the reference by a full 2**48. The
// residual is an opportunistic false match -- 0% to 2.7% of files depending on
// how heavily the volume's MFT records have been recycled, with no attacker
// lever found in 300+ deliberate-attack trials -- not a steerable bypass.
// Callers that need identity rather than recreate-rejection must carry an
// independent term (birthtimeMs, size, or a content digest).
const isSameFileIdentity = (preInfo, postInfo) => (
  preInfo.ino !== 0
  && postInfo.dev === preInfo.dev
  && postInfo.ino === preInfo.ino
  && postInfo.nlink <= 1
);

/**
 * True when `postInfo` still identifies the same on-disk file as `preInfo`
 * ACROSS A DACL APPLICATION: isSameFileIdentity plus a birth-time term that is
 * SKIPPED whenever either side cannot report one.
 *
 * WHAT THE BIRTH TERM IS FOR: POSIX inode reuse, and nothing else. On Linux
 * (notably tmpfs, a common CI /tmp mount) an inode freed by unlink is handed
 * to the very next file created in that directory, so a delete+recreate can
 * present the SAME dev/ino the pre-snapshot recorded (Codex Uert4, caught by
 * CI). The successor's creation time is its own, so the term rejects what
 * dev/ino alone accepts. The deferred ACL caller runs this comparison on EVERY
 * platform -- only the protect() call it follows is win32-gated -- which is
 * where the term earns its place.
 *
 * WHAT IT DOES NOT PROVE: on win32 it is not evidence of anything. Measured on
 * Windows 10 19045 / NTFS: a same-name unlink+recreate inherits the original's
 * birthtimeMs EXACTLY (0.0000 ms delta) through NTFS file tunneling, for the
 * documented default 15 s window (MaximumTunnelEntryAgeInSeconds unset under
 * HKLM\SYSTEM\CurrentControlSet\Control\FileSystem) -- a window that spans the
 * mint -> PowerShell protect -> re-stat gap -- and the file's owner can set
 * CreationTime outright with SetFileTime, no privilege required.
 *
 * What rejects a same-path swap on NTFS is the ino term -- but only that one
 * shape, and not because the comparison is exact. NTFS increments the 16-bit
 * sequence number in the high bits of the file reference when a freed MFT
 * record is reused, so an unlink+recreate at the same name moves the value by
 * exactly 2**48 (measured on Windows 10 19045: 60/60 recreates, delta exactly
 * 281474976710656 every trial). That margin is ~1.8e13 doubles wide, so the
 * recreate primitive is caught with room to spare. Identity in general is NOT
 * caught: Node's default lstat reports ino as a Number, so any 64-bit file
 * reference above 2**53 is rounded to float64 and DISTINCT files whose
 * references share a ULP bucket compare EQUAL -- 800 files created in one
 * directory on this machine reported 797 distinct Number inos against 800
 * distinct BigInt inos, and isSameFileIdentity returned true for two different
 * files whose true references were 17 apart. Cite this predicate as rejecting
 * the recreate, never as proving the file is the same file.
 *
 * WHY TOLERANT, NEVER A BARE `===`: one caller's preInfo is a JSON wire object
 * (the collector's /session mint identity), and mounts that do not record a
 * birth time report 0 -- or, where statx is unavailable, a copy of ctimeMs. A
 * bare equality would abort every deferred start on the first shape and
 * silently become a ctimeMs comparison on the second, which is exactly what
 * isSameFileIdentity's contract forbids for write/ACL-protect callers. Falsy on
 * either side therefore skips the term rather than failing it.
 *
 * WHY NOT isSameLockIdentity: its ctimeMs term is advanced by the very ACL
 * these callers just applied, so it would reject every healthy file.
 * @param {import('node:fs').Stats|{dev:number,ino:number,nlink?:number,birthtimeMs?:number}} preInfo
 * @param {import('node:fs').Stats} postInfo
 * @returns {boolean}
 */
const isSameProtectedFileIdentity = (preInfo, postInfo) => (
  isSameFileIdentity(preInfo, postInfo)
  && (!preInfo.birthtimeMs || !postInfo.birthtimeMs
    || postInfo.birthtimeMs === preInfo.birthtimeMs)
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
 * ctimeMs too (Codex UkAeu, reproduced on the CI filesystem). birthtimeMs is a
 * second time dimension for that window ON POSIX FILESYSTEMS: a successor
 * created after the stale snapshot has its own creation time, which the ctimeMs
 * bumps these records take after creation (ACL protection, content writes)
 * cannot forge. It does not wrongly reject a genuine same file: where the
 * filesystem records no birth time Node reports 0 or a copy of ctimeMs on BOTH
 * sides, and ctimeMs is already required to match.
 *
 * THE TERM IS NOT INDEPENDENT ON WINDOWS and this predicate must not be cited
 * as if it were. Measured on Windows 10 19045 / NTFS: a same-name
 * unlink+recreate inherits the original's birthtimeMs EXACTLY (0.0000 ms delta)
 * through NTFS file tunneling, for the documented default 15 s window
 * (MaximumTunnelEntryAgeInSeconds unset under
 * HKLM\SYSTEM\CurrentControlSet\Control\FileSystem), so inside that window the
 * birthtimeMs term is a guaranteed pass. Creation time is also not immutable:
 * the file's owner sets it with SetFileTime, no privilege required. What holds
 * these reclaim paths on win32 is the ino term (a reused MFT record comes back
 * with an incremented sequence number, moving the reference by 2**48) together
 * with the call-site mitigation below.
 *
 * This is defense in depth, not a full guarantee -- the
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
  isSameProtectedFileIdentity,
  isTrustedSystemRoot,
  looksLikeWindowsRoot,
  openNoFollow,
  openNoFollowFlagAttempts,
  openNoFollowSync,
  PROTECT_WINDOWS_PRIVATE_FILE_EXEC_OPTIONS,
  PROTECT_WINDOWS_PRIVATE_FILE_TIMEOUT_MS,
  protectWindowsPrivateFile,
  protectWindowsPrivateFileAsync,
  resolvePowerShellExecutable,
};
