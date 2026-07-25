const { execFile, spawn } = require('node:child_process');
const { createHash, randomBytes } = require('node:crypto');
const { constants, createWriteStream, readdirSync, readFileSync } = require('node:fs');
const { access, chmod, lstat, mkdir, open, realpath, statfs } = require('node:fs/promises');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');
const { StringDecoder } = require('node:string_decoder');
const { Writable } = require('node:stream');
const { promisify } = require('node:util');

/**
 * Env var name injected into every validation spawn so descendants that
 * leave the process group (setsid / detached:true) can still be found via
 * /proc/<pid>/environ and reaped. The name itself avoids the
 * isSensitiveEnvName TOKEN/SECRET patterns, so it is never stripped from the
 * child environment or redacted out of captured evidence.
 */
const SPAWN_MARK_ENV = 'OMO_CLOSEOUT_SPAWN_MARK';

const { classifyOutput, findStatusSignals } = require('./pr_closeout_core');
const {
  buildChildEnvironment,
  buildSecretReplacements,
  /**
   * Wraps createStreamingRedactor with a StringDecoder so raw Buffer chunks
   * are UTF-8-decoded before redaction — a multi-byte character split across
   * two chunk boundaries is completed first, instead of being corrupted or
   * letting a secret that straddles the split slip through. Defined in
   * ./pr_closeout_stream; re-exported here as part of this module's public
   * surface.
   * @returns {{push(chunk: Buffer|string): string, flush(): string}}
   */
  createDecodedRedactor,
  /**
   * Streaming secret redactor (push/flush) preloaded with the replacement
   * list from buildSecretReplacements(env, names). Withholds up to
   * (longest-replacement-length - 1) trailing characters on each push so a
   * secret split across two chunks is still caught whole, emitting the
   * withheld remainder on flush(). Defined in ./pr_closeout_stream;
   * re-exported here as part of this module's public surface.
   * @returns {{push(chunk: string): string, flush(): string}}
   */
  createStreamingRedactor,
  createStreamingReplacer,
  createStreamingSignalScanner,
} = require('./pr_closeout_stream');
const { assertNotSymlink: assertNotSymlinkShared, openNoFollow: openNoFollowShared } = require('./pr_closeout_fs');

const CAPTURE_LIMIT = 2_000_000;
/** Hard ceiling for artifact hashing so a multi-GB proof path cannot stall closeout. */
const MAX_ARTIFACT_HASH_BYTES = 5 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 20 * 60 * 1000;
const execFileAsync = promisify(execFile);

/**
 * Picks the shell binary used to run every check and proof command. Honors
 * an explicit override (`OMO_CODEX_SHELL_PATH` / `OMO_CODEX_GIT_BASH_PATH`)
 * on either platform; otherwise falls back to the bare name `bash` on POSIX
 * — resolved through PATH by child_process.spawn, not hard-coded to
 * /bin/bash, so minimal/container images that only have bash on PATH still
 * work — or the default Git Bash install path on Windows.
 * @returns {string} A shell path or bare command name suitable for spawn().
 */
const resolveCommandShell = ({ platform = process.platform, env = process.env } = {}) => {
  if (platform !== 'win32') {
    // Allow an explicit override for *nix too, mirroring the Windows override
    // below. Fall back to `bash` resolved through PATH (POSIX `execvp`
    // semantics via child_process.spawn) instead of hard-coding /bin/bash,
    // so minimal/container images without /bin/bash but with bash on PATH
    // still work. If bash is unavailable the spawn will surface a clear
    // ENOENT rather than failing every check silently.
    return env.OMO_CODEX_SHELL_PATH || 'bash';
  }
  return env.OMO_CODEX_GIT_BASH_PATH || 'C:\\Program Files\\Git\\bin\\bash.exe';
};

/**
 * Whether `shell` is bash-compatible enough to accept `--noprofile`/`--norc`.
 * Bare `sh`, `dash`, `zsh`, `ksh`, or other POSIX shells reject those flags
 * (or treat them as unknown options) and never reach `-c`.
 * @param {string} [shell]
 * @returns {boolean}
 */
const isBashCompatibleShell = (shell) => {
  const base = path.basename(String(shell || 'bash')).toLowerCase().replace(/\.exe$/i, '');
  return base === 'bash' || base.endsWith('-bash') || base.includes('bash');
};

/**
 * Default argv for every check/proof/preflight spawn. For bash-compatible
 * shells uses a non-login, non-interactive argv (`--noprofile --norc -c`) so
 * `~/.bash_profile`, `~/.bashrc`, and other shell startup files cannot inject
 * PATH rewrites, aliases, or arbitrary commands into the validation trust
 * domain. For non-bash shells (zsh, dash, ksh, …) emits only `-c` so the
 * command still runs instead of dying on unknown flags.
 *
 * Profile-dependent tool discovery is intentionally NOT performed here:
 * callers must put required tools on the parent process `PATH` (CI runners
 * and developer terminals already do). Isolating PATH setup outside the
 * per-command shell is the safe alternative to `bash -lc`.
 *
 * @param {string} command shell command string to execute
 * @param {string} [shell='bash'] shell binary path or name (from resolveCommandShell)
 * @returns {string[]} argv for spawn/execFile after the shell binary
 */
const defaultShellArgs = (command, shell = 'bash') => (
  isBashCompatibleShell(shell)
    ? ['--noprofile', '--norc', '-c', command]
    : ['-c', command]
);

/**
 * Confirms the shell resolved by resolveCommandShell is actually runnable
 * before any check spawns it. fs.access on a bare command name (no path
 * separator) only checks the process cwd, not PATH — but
 * child_process.spawn resolves bare names through PATH — so a naive
 * access(shell) check would report the default `bash` as BLOCKED on a
 * normal Linux runner even though spawn would succeed. Manually walks PATH
 * (and PATHEXT on Windows) for bare names; an explicit path is checked
 * directly with fs.access.
 * @throws {Error} When the shell cannot be found/executed anywhere searched.
 */
const probeCommandShell = async (shell, env = process.env) => {
  // A bare command name (no path separator) is resolved through PATH by
  // child_process.spawn, but fs.access checks only the process cwd. On normal
  // Linux runners the default `bash` lives at /usr/bin/bash (on PATH, not in
  // cwd), so probing access('bash') would report BLOCKED before any other
  // preflight probe can pass even though spawn would succeed. Search PATH
  // (and PATHEXT on Windows) for bare names; for an explicit path, access is
  // authoritative.
  if (/[\\/]/.test(shell)) {
    await access(shell, constants.X_OK);
    return shell;
  }
  const pathEntries = String(env.PATH || env.Path || '').split(path.delimiter).filter(Boolean);
  const extensions = process.platform === 'win32'
    ? String(env.PATHEXT || '.EXE;.CMD;.BAT').split(';').filter(Boolean)
    : [''];
  for (const dir of pathEntries) {
    for (const ext of extensions) {
      try {
        // Probe with X_OK so a non-executable file on PATH does not PASS the
        // command-shell row and then fail at spawn. On Windows X_OK is a no-op.
        await access(path.join(dir, shell + ext), constants.X_OK);
        return shell;
      } catch {}
    }
  }
  throw new Error(`not found on PATH: ${shell}`);
};

const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

/**
 * Resolves the timeout budget (ms) for a check's primary or proof spawn.
 * Looks up `check.id` first, then `check.associatedCheckId`, then — for a
 * synthesized `${checkId}-baseline-comparison` id — strips that suffix and
 * looks up the parent check, so a baseline rerun inherits the same budget as
 * the head run instead of falling through to the generic default.
 * @returns {number} The timeout in milliseconds for this check.
 */
const resolveCheckTimeout = (check, timeoutsMs = {}, timeoutMs) => {
  if (timeoutsMs[check?.id] != null) return timeoutsMs[check.id];
  if (check?.associatedCheckId && timeoutsMs[check.associatedCheckId] != null) {
    return timeoutsMs[check.associatedCheckId];
  }
  if (typeof check?.id === 'string' && check.id.endsWith('-baseline-comparison')) {
    const parentId = check.id.slice(0, -'-baseline-comparison'.length);
    if (timeoutsMs[parentId] != null) return timeoutsMs[parentId];
  }
  return timeoutMs;
};

/**
 * Finds live (non-zombie) PIDs whose /proc/<pid>/environ contains
 * `SPAWN_MARK_ENV=mark`. Used to re-find descendants that escaped the
 * original process group (setsid / detached:true) after that group already
 * looks empty — a plain kill(-pgid) cannot reach them.
 * @returns {number[]|null} Matching PIDs, or null when /proc is unavailable
 *   (non-Linux), which callers must treat as "unknown", not "none".
 */
const listLivePidsWithSpawnMark = (mark, { selfPid = process.pid } = {}) => {
  if (!mark) return [];
  const target = `${SPAWN_MARK_ENV}=${mark}`;
  let entries;
  try {
    entries = readdirSync('/proc');
  } catch {
    return null;
  }
  const live = [];
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    if (pid === selfPid) continue;
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
      const afterComm = stat.lastIndexOf(')');
      if (afterComm < 0) continue;
      const state = stat.slice(afterComm + 1).trimStart().split(/\s+/)[0];
      if (state === 'Z') continue;
      const environ = readFileSync(`/proc/${pid}/environ`);
      const vars = environ.toString('utf8').split('\0');
      if (vars.includes(target)) live.push(pid);
    } catch {
      // Process exited between readdir and read, or environ is unreadable.
    }
  }
  return live;
};

/**
 * Secondary containment for setsid orphans that stripped the spawn mark
 * (e.g. `env -u <mark> setsid sh -c '...'`): finds live, non-zombie
 * processes that started at/after `minStarttime`, left the runner's session
 * (a same-session peer is a parallel test worker sharing process.cwd() as
 * the repo and must never be reaped), and either have a cwd under
 * `rootCwd` or — for an orphan that already chdir'd away — hold an open
 * file descriptor that resolves under `rootCwd`, a common precursor to a
 * late absolute-path write.
 * @returns {number[]|null} Matching PIDs, or null when /proc is unavailable
 *   (non-Linux).
 */
const listLivePidsWithCwdUnder = (rootCwd, {
  selfPid = process.pid,
  minStarttime = 0,
  selfSession = null,
} = {}) => {
  if (!rootCwd) return [];
  let entries;
  try {
    entries = readdirSync('/proc');
  } catch {
    return null;
  }
  const { readlinkSync } = require('node:fs');
  let rootReal;
  try {
    rootReal = require('node:fs').realpathSync(rootCwd);
  } catch {
    rootReal = path.resolve(rootCwd);
  }
  let runnerSession = selfSession;
  if (runnerSession == null) {
    try {
      const selfStat = readFileSync(`/proc/${selfPid}/stat`, 'utf8');
      const after = selfStat.lastIndexOf(')');
      if (after >= 0) {
        const fields = selfStat.slice(after + 1).trimStart().split(/\s+/);
        // post-comm: state(0) ppid(1) pgrp(2) session(3)
        runnerSession = Number(fields[3]);
      }
    } catch {
      runnerSession = null;
    }
  }
  const live = [];
  const underRoot = (real) => {
    const rel = path.relative(rootReal, real);
    return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel));
  };
  // Secondary containment for mark-stripped setsid orphans: a descendant that
  // ran `env -u <mark> setsid sh -c 'cd /tmp; ...; write <repo>/file'` drops the
  // spawn mark and leaves the repo cwd, so neither the mark sweep nor the cwd
  // check finds it. Probe its open file descriptors for one that resolves under
  // the repo — a common precursor to a late absolute-path write. This is scoped
  // to the few processes that already passed the session+starttime filter, and
  // bounded per process, so it stays cheap. A long-sleeping orphan with no open
  // repo fd still requires OS-level containment (cgroup/pidfd or a read-only
  // repo bind), which is a broad architectural change tracked separately.
  const hasOpenFdUnder = (pid) => {
    let fds;
    try {
      fds = readdirSync(`/proc/${pid}/fd`);
    } catch {
      return false;
    }
    let checked = 0;
    for (const fd of fds) {
      if (checked++ > 256) break;
      let target;
      try {
        target = readlinkSync(`/proc/${pid}/fd/${fd}`);
      } catch {
        continue;
      }
      // Only a real (absolute) file path can point under the repo. Pseudo
      // descriptors readlink to non-path targets like `pipe:[123]`, `socket:[…]`,
      // or `anon_inode:[eventfd]`; feeding those through path.resolve would make
      // them relative to the runner cwd (commonly the repo) and falsely mark an
      // unrelated pipe/socket-holding process for reaping.
      if (!path.isAbsolute(target)) continue;
      if (underRoot(path.resolve(target))) return true;
    }
    return false;
  };
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    if (pid === selfPid || pid === 1) continue;
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
      const afterComm = stat.lastIndexOf(')');
      if (afterComm < 0) continue;
      const fields = stat.slice(afterComm + 1).trimStart().split(/\s+/);
      const state = fields[0];
      if (state === 'Z') continue;
      // /proc/pid/stat: after (comm) → state ppid pgrp session ... starttime is
      // field index 19 in the post-comm fields (man proc_pid_stat).
      const session = Number(fields[3]);
      const starttime = Number(fields[19]);
      if (Number.isFinite(minStarttime) && Number.isFinite(starttime) && starttime < minStarttime) {
        continue;
      }
      // Only target processes that left the runner session (setsid/detached).
      // Same-session peers (parallel node:test workers) must not be reaped.
      if (Number.isFinite(runnerSession) && Number.isFinite(session) && session === runnerSession) {
        continue;
      }
      let cwdLink = null;
      try {
        cwdLink = readlinkSync(`/proc/${pid}/cwd`);
      } catch {
        // cwd unreadable (EACCES on another user's process, or the orphan
        // chdir'd somewhere odd); fall through to fd probing below.
      }
      if (cwdLink && underRoot(path.resolve(cwdLink))) {
        live.push(pid);
      } else if (hasOpenFdUnder(pid)) {
        live.push(pid);
      }
    } catch {
      // Process exited or unreadable.
    }
  }
  return live;
};

/**
 * Reaps descendants that survived terminateProcessTree's process-group kill
 * by escaping via setsid/detached:true. Merges the spawn-mark and
 * worktree-cwd PID lists, sends SIGTERM, gives the group a short soft wait
 * (`min(terminationGraceMs, 500)`) to exit, then escalates to SIGKILL and
 * waits up to the full `terminationGraceMs`. Returns BLOCKED only if PIDs
 * are still alive after both signals; returns PASS (with `escalated: true`)
 * as soon as the list is empty, even when SIGKILL was required.
 * @returns {{status: 'PASS'|'BLOCKED', evidence: string, escalated: boolean}}
 */
const sweepDetachedOrphans = async ({
  mark,
  cwd, // used for mark-free cwd/fd discovery when a child stripped the mark
  minStarttime = 0,
  kill = process.kill.bind(process),
  terminationGraceMs = 2000,
  selfPid = process.pid,
  platform = process.platform,
} = {}) => {
  // Only *reap* PIDs that carry this spawn's mark. A cwd/fd-only scan can hit
  // unrelated processes that merely work in the same repository and must not
  // be signaled. Mark-free candidates discovered via cwd/fd still force
  // BLOCKED so closeout cannot PASS while a setsid orphan may keep mutating
  // the tree after `env -u` stripped the spawn mark.
  const list = () => {
    if (!mark) return [];
    return listLivePidsWithSpawnMark(mark, { selfPid });
  };
  let remaining = list();
  if (remaining === null) {
    // /proc is required to re-find setsid escapees after process-group kill.
    // On Linux its absence is an incomplete containment proof → BLOCKED.
    // On non-Linux hosts /proc is never present; process-group kill is the
    // only available containment and the authoritative gate runs on Linux CI.
    if (platform === 'linux') {
      return {
        status: 'BLOCKED',
        evidence: 'Detached orphan sweep unavailable (/proc missing on Linux); cannot prove setsid descendants exited.',
        escalated: false,
      };
    }
    return {
      status: 'PASS',
      evidence: 'Detached orphan sweep skipped (/proc unavailable; process-group containment only).',
      escalated: false,
    };
  }
  if (remaining.length === 0) {
    if (cwd) {
      const unmarked = listLivePidsWithCwdUnder(cwd, { selfPid, minStarttime });
      if (unmarked === null) {
        if (platform === 'linux') {
          return {
            status: 'BLOCKED',
            evidence: 'No detached spawn-mark descendants remained, but cwd/fd orphan probe is unavailable on Linux; cannot prove mark-free descendants exited.',
            escalated: false,
          };
        }
        return {
          status: 'PASS',
          evidence: 'No detached spawn-mark descendants remained; cwd/fd orphan probe unavailable (process-group containment only).',
          escalated: false,
        };
      }
      if (unmarked.length > 0) {
        return {
          status: 'BLOCKED',
          evidence: `Detached mark-free descendant(s) still live under the worktree (pids ${unmarked.slice(0, 8).join(', ')}); cannot safely attribute/terminate without spawn mark.`,
          escalated: false,
        };
      }
    }
    return {
      status: 'PASS',
      evidence: mark
        ? 'No detached spawn-mark descendants remained.'
        : 'Detached orphan sweep skipped (no spawn mark; refusing cwd-only reaping).',
      escalated: false,
    };
  }
  for (const pid of remaining) {
    try { kill(pid, 'SIGTERM'); } catch {}
  }
  const softDeadline = Date.now() + Math.min(terminationGraceMs, 500);
  while (Date.now() < softDeadline) {
    remaining = list() || [];
    if (remaining.length === 0) {
      return {
        status: 'PASS',
        evidence: 'Detached descendants stopped after SIGTERM (spawn-mark sweep).',
        escalated: false,
      };
    }
    await delay(25);
  }
  remaining = list() || [];
  for (const pid of remaining) {
    try { kill(pid, 'SIGKILL'); } catch {}
  }
  const hardDeadline = Date.now() + terminationGraceMs;
  while (Date.now() < hardDeadline) {
    remaining = list() || [];
    if (remaining.length === 0) {
      return {
        status: 'PASS',
        evidence: 'Detached descendants required SIGKILL and are gone (spawn-mark sweep).',
        escalated: true,
      };
    }
    await delay(25);
  }
  remaining = list() || [];
  if (remaining.length === 0) {
    return {
      status: 'PASS',
      evidence: 'Detached descendants required SIGKILL and are gone (spawn-mark sweep).',
      escalated: true,
    };
  }
  return {
    status: 'BLOCKED',
    evidence: `Detached descendants still live after SIGTERM/SIGKILL: pids ${remaining.slice(0, 8).join(',')}.`,
    escalated: true,
  };
};

/**
 * Enumerate live descendant PIDs of `parentPid` via a full Windows process
 * table snapshot (ProcessId + ParentProcessId), then BFS. Unlike a single
 * `ParentProcessId=root` filter, this finds grandchildren while intermediate
 * parents are still alive. Fully orphaned multi-level trees (every intermediate
 * already exited) are unrecoverable via ParentProcessId alone.
 * @param {number} parentPid
 * @param {{runExecFile: Function, powershell: string}} options
 * @returns {Promise<number[]>} live descendant PIDs (empty if none).
 */
const listWindowsChildPids = async (parentPid, { runExecFile, powershell }) => {
  const root = Number(parentPid);
  const script = 'Get-CimInstance Win32_Process | ForEach-Object { $_.ProcessId.ToString() + [char]32 + $_.ParentProcessId.ToString() }';
  const { stdout } = await runExecFile(powershell, ['-NoProfile', '-NonInteractive', '-Command', script], {
    encoding: 'utf8',
    timeout: 15_000,
    windowsHide: true,
  });
  const childrenByParent = new Map();
  for (const line of String(stdout).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split(/\s+/);
    if (parts.length < 2) continue;
    const pid = Number(parts[0]);
    const parent = Number(parts[1]);
    if (!Number.isInteger(pid) || !Number.isInteger(parent) || pid <= 0) continue;
    if (!childrenByParent.has(parent)) childrenByParent.set(parent, []);
    childrenByParent.get(parent).push(pid);
  }
  const found = [];
  const seen = new Set([root]);
  const queue = [root];
  while (queue.length) {
    const current = queue.shift();
    for (const child of childrenByParent.get(current) || []) {
      if (seen.has(child)) continue;
      seen.add(child);
      found.push(child);
      queue.push(child);
    }
  }
  return found;
};

/**
 * Proves the entire process tree a spawned command created is gone, not
 * just its root PID — a command can exit 0 while a detached descendant
 * keeps running and mutates evidence after the "clean" result is already
 * recorded. On Windows, shells out to `taskkill /PID <pid> /T /F`;
 * taskkill.exe is resolved from SystemRoot only when that env value is an
 * absolute drive-letter path (never trust an injected value as an
 * executable path), and `/T` is attempted even when the root PID has
 * already exited, since children can outlive it. If that invocation fails
 * because the root no longer exists, taskkill never got to identify (let
 * alone terminate) the tree — Microsoft documents `/T` as terminating the
 * specified process and the children it started, so a nonzero result
 * against an absent PID is not proof of anything about descendants. That
 * case falls back to listWindowsChildPids to independently enumerate and
 * individually taskkill any survivors, only concluding PASS once none
 * remain (or none existed); enumeration failure or an unkillable survivor
 * is reported BLOCKED rather than assumed clean. On POSIX, signals the
 * process group (`kill(-pgid, ...)`), escalating SIGTERM to SIGKILL across
 * `terminationGraceMs`; because `kill(-pgid, 0)` reports a group as alive
 * even when every member is an unreaped zombie (common in containers with a
 * slow PID 1), it prefers enumerating /proc/<pid>/stat for live non-zombie
 * members when /proc is available. Once the group is confirmed gone, hands
 * off to sweepDetachedOrphans to catch descendants that escaped the group
 * via setsid/detached:true. Never throws — unrecoverable errors become a
 * BLOCKED result.
 * @returns {{status: 'PASS'|'BLOCKED', evidence: string, escalated: boolean}}
 */
const terminateProcessTree = async ({
  child,
  platform = process.platform,
  env = process.env,
  terminationGraceMs = 2000,
  runExecFile = execFileAsync,
  kill = process.kill.bind(process),
  pathExists,
  closePromise,
  spawnMark,
  cwd,
  minStarttime = 0,
} = {}) => {
  if (!Number.isInteger(child?.pid) || child.pid <= 0) {
    return { status: 'BLOCKED', evidence: 'Process-tree termination has no valid process identifier.', escalated: false };
  }
  try {
    if (platform === 'win32') {
      // Resolve taskkill/powershell only from a verified Windows system root.
      // An absolute drive path in SystemRoot is not enough: an attacker can
      // point it at a planted tree with a fake System32\\taskkill.exe. Require
      // the path to look like a Windows install (final component "Windows")
      // and that the real taskkill + powershell binaries exist there; otherwise
      // fall back to the hard-coded C:\\Windows default (which tests also use
      // as a pure path-construction base when pathExists is not injected).
      // Existence probe is an explicit DI option (never read from env — env is
      // untrusted process.env in production). Default to fs.existsSync.
      const existsCheck = typeof pathExists === 'function'
        ? pathExists
        : (candidate) => {
          try {
            const { existsSync } = require('node:fs');
            return existsSync(candidate);
          } catch {
            return false;
          }
        };
      const looksLikeWindowsRoot = (root) => {
        const normalized = path.normalize(root).replace(/[\\/]+$/u, '');
        return /^[A-Za-z]:[\\/]/u.test(normalized)
          && path.basename(normalized).toLowerCase() === 'windows';
      };
      const isTrustedSystemRoot = (root) => {
        if (!looksLikeWindowsRoot(root)) return false;
        const taskkillPath = path.join(root, 'System32', 'taskkill.exe');
        const powershellPath = path.join(root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
        return existsCheck(taskkillPath) && existsCheck(powershellPath);
      };
      const envRoot = String(env.SystemRoot || env.SYSTEMROOT || '').trim();
      const hardcodedRoot = 'C:\\Windows';
      // Prefer hard-coded C:\\Windows whenever it exists and is trusted.
      // On real win32 hosts, never accept a merely Windows-shaped envRoot when
      // the hard-coded install is missing — fall back to C:\\Windows for path
      // construction rather than attacker-controlled SystemRoot.
      // On non-win32 (unit tests with mocked runExecFile), a Windows-shaped
      // envRoot is allowed for path construction only.
      let safeRoot = hardcodedRoot;
      if (isTrustedSystemRoot(hardcodedRoot)) {
        safeRoot = hardcodedRoot;
      } else if (platform === 'win32') {
        if (isTrustedSystemRoot(envRoot)) {
          safeRoot = envRoot;
        } else {
          safeRoot = hardcodedRoot;
        }
      } else if (looksLikeWindowsRoot(envRoot)) {
        safeRoot = envRoot;
      } else {
        safeRoot = hardcodedRoot;
      }
      const taskkill = path.join(safeRoot, 'System32', 'taskkill.exe');
      // taskkill exits non-zero when the root PID is already gone (for
      // example a command that exited cleanly before termination was even
      // considered), which the outer catch would misreport as a termination
      // failure. Probe the root first and again after a failed taskkill: an
      // already-gone root means there is no tree left to terminate.
      const rootGone = () => {
        try {
          kill(child.pid, 0);
          return false;
        } catch (probeError) {
          return probeError?.code === 'ESRCH';
        }
      };
      // Always run taskkill /T even when the root PID is already gone: child
      // processes may still be alive after the root exits, and Microsoft's
      // /T flag terminates the process and its children. Proving only that the
      // root is ESRCH is not proof the tree is gone.
      try {
        await runExecFile(taskkill, ['/PID', String(child.pid), '/T', '/F'], {
          encoding: 'utf8',
          timeout: Math.max(terminationGraceMs * 5, 10_000),
          windowsHide: true,
        });
      } catch (error) {
        // taskkill exits non-zero when the PID is already gone. If the root is
        // still present, this is a genuine failure - surface it.
        if (!rootGone()) throw error;
        // The root exited before taskkill could identify the tree, so this
        // failure is not proof /T ever reached any children: taskkill needs
        // the target PID to exist to walk its tree, and a nonzero result
        // against an absent PID means it never got that far. Independently
        // enumerate any live descendants (Windows tracks each child's
        // ParentProcessId regardless of whether the parent is still alive)
        // and terminate them directly; only PASS once none remain.
        const powershell = path.join(safeRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
        let survivors;
        try {
          survivors = await listWindowsChildPids(child.pid, { runExecFile, powershell });
        } catch (enumerationError) {
          return {
            status: 'BLOCKED',
            evidence: `Windows process tree ${child.pid}'s root exited before taskkill /T could target it, and descendant enumeration failed: ${enumerationError?.message || enumerationError}. Cannot prove the tree is clean.`,
            escalated: true,
          };
        }
        if (survivors.length === 0) {
          return {
            status: 'PASS',
            evidence: `Windows process tree ${child.pid}'s root already exited and no live descendants were found.`,
            escalated: true,
          };
        }
        const stillAlive = [];
        for (const survivorPid of survivors) {
          try {
            await runExecFile(taskkill, ['/PID', String(survivorPid), '/T', '/F'], {
              encoding: 'utf8',
              timeout: Math.max(terminationGraceMs * 5, 10_000),
              windowsHide: true,
            });
          } catch {
            stillAlive.push(survivorPid);
          }
        }
        if (stillAlive.length) {
          return {
            status: 'BLOCKED',
            evidence: `Windows process tree ${child.pid}'s root exited before taskkill /T could target it; descendant(s) ${stillAlive.join(', ')} could not be confirmed terminated.`,
            escalated: true,
          };
        }
        return {
          status: 'PASS',
          evidence: `Windows process tree ${child.pid}'s root already exited; ${survivors.length} live descendant(s) were independently found and terminated.`,
          escalated: true,
        };
      }
      return {
        status: 'PASS',
        evidence: `Windows process tree ${child.pid} was terminated with taskkill /T /F.`,
        escalated: true,
      };
    }

    // `kill(-pgid, 0)` succeeds for zombie (<defunct>) descendants too, so on
    // Linux containers where PID 1 does not promptly reap killed descendants
    // we would report BLOCKED even though no live process can mutate evidence.
    // Read /proc/<pid>/stat for the root child and treat a zombie state as
    // "group is gone" since a defunct root cannot do anything either.
    const isDefunct = (pid) => {
      try {
        const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
        // /proc/$pid/stat is `pid (comm) state ...`; comm may contain spaces
        // and parens, so parse from the LAST ')' in the line.
        const afterComm = stat.lastIndexOf(')');
        if (afterComm < 0) return false;
        const state = stat.slice(afterComm + 1).trimStart().split(/\s+/)[0];
        return state === 'Z';
      } catch {
        return false;
      }
    };
    // Enumerate the process group via /proc and return the PIDs of members
    // that are NOT zombies. Returns null when /proc is unavailable (non-Linux);
    // the caller falls back to the kill(-pgid, 0) + isDefunct(root) probe.
    // kill(-pgid, 0) succeeds for a reaped descendant zombie too, so on Linux
    // containers where PID 1 does not promptly reap killed descendants this
    // probe can stay green even though no live process can mutate evidence.
    // Enumerating the group lets us prove the group is gone when every member
    // is a zombie (including the root-reaped case isDefunct(root) misses).
    const liveMembersInGroup = (pgid) => {
      let entries;
      try {
        entries = readdirSync('/proc');
      } catch {
        return null;
      }
      const live = [];
      for (const entry of entries) {
        if (!/^\d+$/.test(entry)) continue;
        try {
          const stat = readFileSync(`/proc/${entry}/stat`, 'utf8');
          const afterComm = stat.lastIndexOf(')');
          if (afterComm < 0) continue;
          const fields = stat.slice(afterComm + 1).trimStart().split(/\s+/);
          const state = fields[0];
          // /proc/$pid/stat layout after (comm): state ppid pgrp session ...
          const memberPgrp = Number(fields[2]);
          if (Number.isInteger(memberPgrp) && memberPgrp === pgid && state !== 'Z') {
            live.push(Number(entry));
          }
        } catch {
          // The process exited between readdir and read; ignore it.
        }
      }
      return live;
    };
    const groupExists = () => {
      const liveMembers = liveMembersInGroup(child.pid);
      if (liveMembers !== null) {
        return liveMembers.length > 0;
      }
      try {
        kill(-child.pid, 0);
        // kill(0) succeeded, but if the root child is a defunct zombie and
        // there are no other live processes in the group, treat the group as
        // gone (it cannot mutate evidence).
        if (isDefunct(child.pid)) {
          return false;
        }
        return true;
      } catch (error) {
        if (error?.code === 'ESRCH') return false;
        throw error;
      }
    };
    const awaitRootClose = async () => {
      if (closePromise) await Promise.race([closePromise, delay(terminationGraceMs)]);
    };
    // After the process group looks gone, still sweep descendants that left
    // the group (setsid / detached:true) via the per-spawn environ mark and
    // worktree-cwd + starttime containment (covers env -u mark stripping).
    const withOrphanSweep = async (groupResult) => {
      if (groupResult.status === 'BLOCKED') return groupResult;
      const sweep = await sweepDetachedOrphans({
        mark: spawnMark,
        cwd,
        minStarttime,
        kill,
        terminationGraceMs,
        platform,
      });
      if (sweep.status === 'BLOCKED') {
        return {
          status: 'BLOCKED',
          evidence: `${groupResult.evidence} ${sweep.evidence}`,
          escalated: true,
        };
      }
      return {
        status: 'PASS',
        evidence: `${groupResult.evidence} ${sweep.evidence}`,
        escalated: Boolean(groupResult.escalated || sweep.escalated),
      };
    };
    try {
      kill(-child.pid, 'SIGTERM');
    } catch (error) {
      if (error?.code === 'ESRCH') {
        return withOrphanSweep({
          status: 'PASS',
          evidence: `Process group ${child.pid} had already exited.`,
          escalated: false,
        });
      }
      throw error;
    }
    // awaitRootClose already bounds the wait to terminationGraceMs via its
    // internal race against closePromise. An additional unconditional delay
    // here would stack a second full grace period before SIGKILL escalation
    // is even considered, doubling worst-case time-to-SIGKILL when the
    // process ignores SIGTERM.
    await awaitRootClose();
    if (!groupExists()) {
      return withOrphanSweep({
        status: 'PASS',
        evidence: `Process group ${child.pid} stopped after SIGTERM.`,
        escalated: false,
      });
    }
    try {
      kill(-child.pid, 'SIGKILL');
    } catch (error) {
      // The group may exit between the groupExists() probe above and the
      // SIGKILL call. ESRCH here means the group is already gone, which is a
      // successful termination -- do not let the outer catch convert it into
      // a spurious BLOCKED result.
      if (error?.code === 'ESRCH') {
        return withOrphanSweep({
          status: 'PASS',
          evidence: `Process group ${child.pid} exited before SIGKILL was delivered.`,
          escalated: true,
        });
      }
      throw error;
    }
    const deadline = Date.now() + terminationGraceMs;
    while (Date.now() < deadline) {
      await awaitRootClose();
      if (!groupExists()) {
        return withOrphanSweep({
          status: 'PASS',
          evidence: `Process group ${child.pid} required SIGKILL and is gone.`,
          escalated: true,
        });
      }
      await delay(25);
    }
    return {
      status: 'BLOCKED',
      evidence: `Process group ${child.pid} still exists after SIGTERM and SIGKILL.`,
      escalated: true,
    };
  } catch (error) {
    return {
      status: 'BLOCKED',
      evidence: `Process-tree termination could not be proven: ${error.message}`,
      escalated: false,
    };
  }
};

/**
 * Variant of redactSecrets that takes a precomputed replacement list
 * instead of rebuilding one. Hot callers (safeStatusSignal, redactStructure
 * during a single executor run) call buildSecretReplacements(env, names)
 * once and reuse the result here on every call, instead of paying the
 * URL/base64/hex variant-generation cost per chunk.
 * @param {Array<[string, string]>} replacements [value, replacement] pairs.
 */
const redactSecretsReplacements = (text, replacements) => {
  let redacted = String(text ?? '');
  for (const [value, replacement] of replacements) {
    redacted = redacted.replaceAll(value, replacement);
  }
  return redacted;
};

/**
 * Redacts every configured/auto-discovered secret value — and its
 * URL/base64/hex-encoded variants — out of `text`. Rebuilds the replacement
 * list from `env`/`names` on every call via buildSecretReplacements; fine
 * for one-off calls, but code redacting many chunks against the same
 * env/names should precompute the list once and call
 * redactSecretsReplacements directly instead.
 * @returns {string} `text` with every matched secret variant replaced by
 *   `[REDACTED]`.
 */
const redactSecrets = (text, env = process.env, names = []) => (
  redactSecretsReplacements(text, buildSecretReplacements(env, names))
);

/**
 * Recursively redacts secrets from every string reachable inside a value
 * (objects, arrays, Errors, Maps, Sets, Buffers, and object keys). Uses a
 * per-branch `stack` to detect true cycles and a traversal-wide `clones` map
 * to detect shared references: a re-visit while still on the current branch
 * is a cycle and becomes `'[Circular]'`, but a re-visit of an object that
 * already finished (e.g. report.toolVersions and
 * report.preflight.toolVersions pointing at the same object) reuses its
 * already-redacted clone instead of re-walking it or corrupting it with
 * `'[Circular]'`. A non-plain-object instance (other than Error/Map/Set) is
 * returned unredacted rather than risking corruption of an opaque
 * structure.
 * @param {WeakMap} clones Internal recursion accumulator; callers should not
 *   pass this.
 * @param {WeakSet} stack Internal recursion accumulator; callers should not
 *   pass this.
 */
const redactStructure = (value, env = process.env, names = [], clones = new WeakMap(), stack = new WeakSet()) => {
  if (typeof value === 'string') return redactSecrets(value, env, names);
  if (Buffer.isBuffer(value)) return redactSecrets(value.toString('utf8'), env, names);
  if (!value || typeof value !== 'object') return value;
  // Stack first: a re-visit while still building this object is a true cycle.
  // Clones second: a re-visit after the object left the stack is a shared ref.
  if (stack.has(value)) return '[Circular]';
  if (clones.has(value)) return clones.get(value);
  stack.add(value);
  try {
    if (Array.isArray(value)) {
      const out = [];
      clones.set(value, out);
      for (const entry of value) out.push(redactStructure(entry, env, names, clones, stack));
      return out;
    }
    if (value instanceof Error) {
      const out = redactStructure(
        { name: value.name, message: value.message, stack: value.stack },
        env,
        names,
        clones,
        stack,
      );
      clones.set(value, out);
      return out;
    }
    if (value instanceof Map) {
      const out = {};
      clones.set(value, out);
      for (const [key, entry] of value.entries()) {
        out[redactSecrets(String(key), env, names)] = redactStructure(entry, env, names, clones, stack);
      }
      return out;
    }
    if (value instanceof Set) {
      const out = [];
      clones.set(value, out);
      for (const entry of value) out.push(redactStructure(entry, env, names, clones, stack));
      return out;
    }
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) {
      return value;
    }
    const out = {};
    clones.set(value, out);
    for (const [key, entry] of Object.entries(value)) {
      out[redactSecrets(key, env, names)] = redactStructure(entry, env, names, clones, stack);
    }
    return out;
  } finally {
    stack.delete(value);
  }
};

/**
 * Appends `chunk` to `current` and truncates to CAPTURE_LIMIT. Once
 * `current` is already at the cap, returns it unchanged instead of
 * concatenating first and slicing after, so a long-running, chatty command
 * cannot force a repeated multi-megabyte string rebuild on every further
 * chunk.
 */
const cappedAppend = (current, chunk) => {
  if (current.length >= CAPTURE_LIMIT) return current;
  return `${current}${chunk}`.slice(0, CAPTURE_LIMIT);
};

/**
 * Returns `value` plus its forward-slash and back-slash variants, deduped.
 * Captured command output can mix separator styles regardless of host
 * platform (e.g. a tool printing forward-slash paths on Windows), so
 * callers building replacement lists from this need every variant to match.
 * @returns {string[]} Empty array for a non-string or blank input.
 */
const pathVariants = (value) => {
  if (typeof value !== 'string' || !value.trim()) return [];
  return [...new Set([
    value,
    value.replaceAll('\\', '/'),
    value.replaceAll('/', '\\'),
  ])];
};

/**
 * Builds the ordered [needle, placeholder] pairs used to normalize `cwd`,
 * `outputDir`, and the caller's home directory (HOME / USERPROFILE /
 * HOMEDRIVE+HOMEPATH) out of captured evidence, replacing each with
 * `<repo>`, `<output>`, or `<home>` respectively. Each path is expanded to
 * its pathVariants() so either separator style is caught.
 * @returns {Array<[string, string]>}
 */
const buildPathReplacements = ({ cwd, outputDir, env = process.env } = {}) => {
  const entries = [
    ...pathVariants(cwd).map((value) => [value, '<repo>']),
    ...pathVariants(outputDir).map((value) => [value, '<output>']),
  ];
  for (const home of [env.USERPROFILE, env.HOME, env.HOMEDRIVE && env.HOMEPATH
    ? `${env.HOMEDRIVE}${env.HOMEPATH}`
    : null]) {
    entries.push(...pathVariants(home).map((value) => [value, '<home>']));
  }
  return entries;
};

/**
 * Applies a one-shot pass (push then immediately flush) of `replacements`
 * over `text` via the streaming replacer, collapsing cwd/output/home paths
 * to their placeholders. Matches case-insensitively on Windows, where paths
 * are case-insensitive but the casing captured in command output is not
 * guaranteed to match `replacements` exactly.
 */
const normalizePaths = (text, replacements, platform = process.platform) => {
  const replacer = createStreamingReplacer(replacements, { caseInsensitive: platform === 'win32' });
  return replacer.push(String(text ?? '')) + replacer.flush();
};

/**
 * Recursively applies `transform` to every string in an arbitrary value
 * (used to path-normalize a structure already redacted by redactStructure).
 * Unlike redactStructure, `seen` is never pruned once an object has been
 * visited, so this only distinguishes a first visit from every later one —
 * a true cycle and a non-cyclic shared reference (the same object reachable
 * from two branches) both collapse to the literal string `'[Circular]'` on
 * the second visit.
 */
const mapStructureStrings = (value, transform, seen = new WeakSet()) => {
  if (typeof value === 'string') return transform(value);
  if (!value || typeof value !== 'object') return value;
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  if (Array.isArray(value)) return value.map((entry) => mapStructureStrings(entry, transform, seen));
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) return value;
  return Object.fromEntries(Object.entries(value).map(([key, entry]) => [
    transform(key),
    mapStructureStrings(entry, transform, seen),
  ]));
};

/**
 * Categorizes a raw detected status signal into a fixed label by matching an
 * ordered list of keyword patterns — first match wins, in the order
 * BLOCKED, WARNING, PROBLEM, SKIPPED, TODO, FAIL — defaulting to ERROR when
 * none match.
 * @returns {string} `"<CATEGORY>: raw output contained a status signal."`
 */
const summarizeStatusSignal = (signal) => {
  const value = String(signal);
  if (/\bblocks?|blocked\b/i.test(value)) return 'BLOCKED: raw output contained a status signal.';
  if (/warn(?:ing)?s?/i.test(value)) return 'WARNING: raw output contained a status signal.';
  if (/\bproblems?\b/i.test(value)) return 'PROBLEM: raw output contained a status signal.';
  if (/\bskips?|skipped\b/i.test(value)) return 'SKIPPED: raw output contained a status signal.';
  if (/\btodos?\b/i.test(value)) return 'TODO: raw output contained a status signal.';
  if (/\bfail(?:ed|ures?)?\b/i.test(value)) return 'FAIL: raw output contained a status signal.';
  return 'ERROR: raw output contained a status signal.';
};

/**
 * Turns a raw detected signal into a report-safe summary without ever
 * exposing the raw text. Classification runs on the raw `signal` first (so
 * an accurate category survives even when the triggering text is itself a
 * secret); a separately redacted, path-normalized, whitespace-collapsed
 * copy — capped at 500 characters — is what actually gets embedded in the
 * returned string, and the raw signal itself is never returned.
 * @returns {string} `"<CATEGORY>: <redacted, truncated evidence>"`
 */
const safeStatusSignal = ({
  signal,
  secretReplacements,
  pathReplacements,
  platform,
}) => {
  const category = summarizeStatusSignal(signal).split(':', 1)[0];
  const safe = normalizePaths(
    redactSecretsReplacements(String(signal), secretReplacements),
    pathReplacements,
    platform,
  ).replace(/\s+/gu, ' ').trim().slice(0, 500);
  return `${category}: ${safe || 'redacted status signal'}`;
};

// Reject a pre-existing symlink at `target` (fail-closed), tolerating ENOENT.
// Shared with report/collector via pr_closeout_fs.js so the guard stays one
// implementation across security-critical write paths.
const assertLogNotSymlink = async (target) => {
  await assertNotSymlinkShared(
    target,
    `Refusing to write evidence log through an existing symlink: ${target}`,
  );
};

// Open a raw evidence log path without following a symlinked final component.
// Mode 0600 at create time; fchmod after open so a permissive umask cannot
// leave evidence world-readable under a shared temp directory.
const openLogNoFollow = async (target, flags) => {
  await assertLogNotSymlink(target);
  try {
    const handle = await openNoFollowShared(target, flags, 0o600);
    try {
      await handle.chmod(0o600);
    } catch (error) {
      // Windows and some network FS ignore or reject chmod; keep the handle
      // when the platform cannot enforce Unix modes.
      if (error?.code && !['ENOTSUP', 'EPERM', 'EINVAL', 'EACCES'].includes(error.code)
        && process.platform !== 'win32') {
        await handle.close().catch(() => undefined);
        throw error;
      }
    }
    return handle;
  } catch (error) {
    if (error?.code === 'ELOOP') {
      throw new Error(`Refusing to write evidence log through an existing symlink: ${target}`);
    }
    throw error;
  }
};

/**
 * Write a one-shot evidence log header (truncating any prior content),
 * no-follow. Used for the "command: ...\ncwd: ..." header written before a
 * command or command-proof spawn begins.
 *
 * Opens without O_TRUNC first so a hard-linked log path cannot truncate a
 * second name on the same inode before identity checks run. Requires a
 * regular file with nlink === 1, then truncates through the verified
 * descriptor.
 * @param {string} target
 * @param {string} contents
 */
const writeLogHeaderNoFollow = async (target, contents) => {
  // O_CREAT without O_TRUNC: create if missing, never truncate until fstat.
  const handle = await openLogNoFollow(target, constants.O_WRONLY | constants.O_CREAT);
  try {
    const info = await handle.stat();
    if (!info.isFile()) {
      throw new Error(`Refusing to write evidence log that is not a regular file: ${target}`);
    }
    if (info.nlink !== 1) {
      throw new Error(
        `Refusing to write evidence log with hard links (nlink=${info.nlink}): ${target}`,
      );
    }
    await handle.truncate(0);
    await handle.writeFile(contents, 'utf8');
  } finally {
    await handle.close();
  }
};

/**
 * Open an evidence log for streaming append, no-follow. Opens the
 * descriptor directly (rather than letting createWriteStream open the path
 * itself, which would follow a symlink) and hands the resulting FileHandle
 * to createWriteStream via its `fd` option so the stream still owns normal
 * close/error semantics.
 * @param {string} target
 * @returns {Promise<import('node:fs').WriteStream>}
 */
const createLogAppendStreamNoFollow = async (target) => {
  const handle = await openLogNoFollow(target, constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND);
  return createWriteStream(undefined, { fd: handle, autoClose: true, encoding: 'utf8' });
};

/**
 * Spawns one command and captures its full lifecycle as report-safe
 * evidence. Every stdout/stderr chunk is decoded, redacted, and
 * path-normalized before it is ever appended to `stdout`/`stderr`, written
 * to `logPath`, or hashed — raw unredacted bytes are never persisted or
 * returned. The child is spawned detached (POSIX) under a unique per-call
 * `spawnMark` env var so terminateProcessTree/sweepDetachedOrphans can later
 * re-find descendants that escape the process group. Races the child's
 * `close` against `timeoutMs`; either path always calls `terminateTree`
 * before trusting the outcome, because a command can exit 0 while a
 * detached descendant keeps mutating the worktree. On timeout, if the root
 * still has not closed after `terminateTree` plus one grace period, sends a
 * direct SIGKILL to the child handle and, failing that too, tears down the
 * stdout/stderr listeners instead of waiting forever. Log-stream
 * backpressure pauses the offending source and resumes it on `'drain'`; a
 * log write error is captured in the result (`logWriteError`) instead of
 * silently losing evidence or stalling the child on a full pipe.
 * @returns {object} Includes `terminationStatus`/`terminationEvidence`/
 *   `escalated` from `terminateTree`, `outputDigest` (sha256 of the full
 *   normalized stdout/stderr, independent of the CAPTURE_LIMIT-capped
 *   strings), and `detectedSignals` found by the raw, pre-redaction scanner.
 */
const spawnCaptured = async ({
  command,
  cwd,
  shell,
  shellArgs,
  timeoutMs,
  env,
  redactionEnv = env,
  secretNames,
  logPath,
  pathReplacements = buildPathReplacements({ cwd, env: redactionEnv }),
  platform = process.platform,
  spawnProcess = spawn,
  terminateTree = terminateProcessTree,
  terminationGraceMs = 2000,
}) => {
  const startedAt = new Date().toISOString();
  let stdout = '';
  let stderr = '';
  let timedOut = false;
  // Opened no-follow (see createLogAppendStreamNoFollow): a pre-existing
  // symlink at this predictable path is refused rather than followed. Like
  // any other open failure (missing parent dir, permissions), that is
  // captured softly as logWriteError below rather than aborting a command
  // that has not even started yet — classifyExecution already treats a
  // populated logWriteError as blocking regardless of the command's own
  // exit code, so the incomplete evidence trail still cannot pass silently.
  let log;
  let logError = null;
  try {
    log = await createLogAppendStreamNoFollow(logPath);
  } catch (error) {
    logError = error;
    log = new Writable({ write(_chunk, _encoding, callback) { callback(); } });
  }
  // Track sources paused on backpressure so they can be resumed if the log
  // stream errors mid-write. Without this, an append-mode open failure, disk
  // full, or locked-file error would leave 'drain' waiting forever and the
  // paused source would stall the child process on its stdout/stderr pipe
  // until timeoutMs fires.
  const pausedSources = new Set();
  const resumePausedSources = () => {
    for (const source of pausedSources) {
      try {
        if (typeof source.resume === 'function') source.resume();
      } catch {}
    }
    pausedSources.clear();
  };
  log.on('error', (error) => {
    logError = error;
    resumePausedSources();
  });
  const writeLog = (chunk, source) => {
    if (logError) return;
    if (!log.write(chunk) && source && typeof source.pause === 'function') {
      source.pause();
      pausedSources.add(source);
      log.once('drain', () => {
        pausedSources.delete(source);
        try {
          source.resume();
        } catch {}
      });
    }
  };
  // Precompute the secret replacement list once per spawnCaptured() call so
  // the status-signal summarizer and downstream redactors do not rebuild the
  // URL/base64/hex variants on every chunk.
  const secretReplacements = buildSecretReplacements(redactionEnv, secretNames);
  const makeState = () => ({
    redactor: createDecodedRedactor(redactionEnv, secretNames),
    normalizer: createStreamingReplacer(pathReplacements, { caseInsensitive: platform === 'win32' }),
    signalDecoder: new StringDecoder('utf8'),
    scanner: createStreamingSignalScanner(findStatusSignals, {
      summarizeSignal: (signal) => safeStatusSignal({
        signal,
        secretReplacements,
        pathReplacements,
        platform,
      }),
    }),
    hash: createHash('sha256'),
  });
  const states = { stdout: makeState(), stderr: makeState() };
  // Unique mark inherited by every descendant of this spawn. terminateProcessTree
  // uses it to re-find processes that leave the process group (setsid /
  // detached:true) after the original group appears empty.
  const spawnMark = platform === 'win32' ? '' : randomBytes(16).toString('hex');
  const spawnEnv = spawnMark
    ? { ...env, [SPAWN_MARK_ENV]: spawnMark }
    : env;
  // Capture approximate starttime for /proc-based cwd sweeps. On Linux this
  // is jiffies since boot; we re-read the child's starttime after spawn when
  // /proc is available so the orphan filter is exact.
  let minStarttime = 0;
  const child = spawnProcess(shell, shellArgs(command, shell), {
    cwd,
    env: spawnEnv,
    // Detached so the child is a process-group leader and kill(-pid) works.
    detached: platform !== 'win32',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (platform !== 'win32' && Number.isInteger(child?.pid)) {
    try {
      const stat = readFileSync(`/proc/${child.pid}/stat`, 'utf8');
      const afterComm = stat.lastIndexOf(')');
      if (afterComm >= 0) {
        const fields = stat.slice(afterComm + 1).trimStart().split(/\s+/);
        const starttime = Number(fields[19]);
        if (Number.isFinite(starttime)) minStarttime = starttime;
      }
    } catch {
      minStarttime = 0;
    }
  }
  const emitNormalized = (stream, normalized) => {
    if (!normalized) return;
    if (stream === 'stdout') stdout = cappedAppend(stdout, normalized);
    else stderr = cappedAppend(stderr, normalized);
    writeLog(`[${stream}] ${normalized}`, child[stream]);
    states[stream].hash.update(normalized);
  };
  const emitSafe = (stream, safe) => {
    if (!safe) return;
    emitNormalized(stream, states[stream].normalizer.push(safe));
  };
  const record = (stream, chunk) => {
    const raw = Buffer.isBuffer(chunk)
      ? states[stream].signalDecoder.write(chunk)
      : String(chunk ?? '');
    states[stream].scanner.push(raw);
    emitSafe(stream, states[stream].redactor.push(chunk));
  };
  const flush = (stream) => {
    states[stream].scanner.push(states[stream].signalDecoder.end());
    states[stream].scanner.flush();
    emitSafe(stream, states[stream].redactor.flush());
    emitNormalized(stream, states[stream].normalizer.flush());
  };
  const onStdout = (chunk) => record('stdout', chunk);
  const onStderr = (chunk) => record('stderr', chunk);
  child.stdout.on('data', onStdout);
  child.stderr.on('data', onStderr);

  let closeResolved = false;
  let resolveClose;
  const closePromise = new Promise((resolve) => { resolveClose = resolve; });
  const close = (outcome) => {
    if (closeResolved) return;
    closeResolved = true;
    resolveClose(outcome);
  };
  child.once('error', (error) => close({ exitCode: null, signal: null, spawnError: error }));
  child.once('close', (exitCode, signal) => close({ exitCode, signal }));
  let timer;
  const timeoutPromise = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ kind: 'timeout' }), timeoutMs);
  });
  const first = await Promise.race([
    closePromise.then((outcome) => ({ kind: 'close', outcome })),
    timeoutPromise,
  ]);

  let outcome = first.outcome;
  let termination;
  if (first.kind === 'close') {
    clearTimeout(timer);
    // A command can exit 0 while detached background descendants keep running
    // in its process group, still able to mutate the worktree after the final
    // seal. Prove the group is gone (terminating any stragglers) before
    // treating the clean exit as clean. A spawn error means the command never
    // started, so there is no group to sweep.
    termination = outcome?.spawnError
      ? { status: 'PASS', evidence: 'Command did not start; no process group was created.', escalated: false }
      : await terminateTree({
        child,
        platform,
        env,
        terminationGraceMs,
        closePromise,
        spawnMark,
        cwd,
        minStarttime,
      });
  } else {
    timedOut = true;
    termination = await terminateTree({
      child,
      platform,
      env,
      terminationGraceMs,
      closePromise,
      spawnMark,
      cwd,
      minStarttime,
    });
    outcome = await Promise.race([
      closePromise,
      delay(terminationGraceMs).then(() => null),
    ]);
    if (!outcome) {
      try {
        child.kill('SIGKILL');
      } catch {}
      outcome = await Promise.race([
        closePromise,
        delay(terminationGraceMs).then(() => null),
      ]);
    }
    if (!outcome) {
      termination = {
        status: 'BLOCKED',
        evidence: `${termination.evidence} The root process did not close after bounded termination.`,
        escalated: true,
      };
      child.stdout.off('data', onStdout);
      child.stderr.off('data', onStderr);
      child.stdout.destroy();
      child.stderr.destroy();
    }
  }

  if (outcome?.spawnError) record('stderr', outcome.spawnError.message);
  flush('stdout');
  flush('stderr');
  // Drain the evidence log BEFORE building the result so a write error during
  // the final flush (ENOSPC on buffered data, perms change, removed logs dir)
  // is reflected in result.logWriteError instead of being lost: the result
  // previously captured logError before this flush ran, so a late flush error
  // could let a command PASS while the durable raw evidence was incomplete.
  await new Promise((resolve) => {
    if (logError) return resolve();
    log.once('error', resolve);
    log.end(resolve);
  });
  const finishedAt = new Date().toISOString();
  const result = {
    exitCode: outcome?.exitCode ?? null,
    signal: outcome?.signal ?? null,
    timedOut,
    terminationStatus: termination.status,
    terminationEvidence: termination.evidence,
    escalated: termination.escalated,
    stdout,
    stderr,
    startedAt,
    finishedAt,
    durationMs: new Date(finishedAt) - new Date(startedAt),
    cwd: '<repo>',
    outputDigest: {
      stdout: states.stdout.hash.digest('hex'),
      stderr: states.stderr.hash.digest('hex'),
    },
    detectedSignals: [
      ...states.stdout.scanner.values(),
      ...states.stderr.scanner.values(),
    ],
    logWriteError: logError ? logError.message : null,
  };
  return result;
};

/**
 * Checks whether `target` resolves inside `root` using path.relative (no
 * leading `..` segment, not itself `..`, not absolute). Returns false when
 * `target` equals `root` — `path.relative(root, root)` is `''`, which is
 * falsy — so a caller that needs to treat an exact match as contained must
 * check that separately.
 */
const isContainedPath = (root, target) => {
  const relative = path.relative(root, target);
  return Boolean(relative) && relative !== '..'
    && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
};

/**
 * Opens `artifact` read-only for TOCTOU-safe proof verification: O_NOFOLLOW
 * rejects a symlink swapped in after the caller's lstat, and O_NONBLOCK
 * (where the platform defines it) stops an open on a FIFO from hanging the
 * proof instead of failing it cleanly. Falls back to a plain open only when
 * the initial open fails because the platform itself rejects those flags
 * (EINVAL/ENOTSUP/EOPNOTSUPP), never because the target turned out to be a
 * symlink. Closes and throws if the opened handle is not a regular file.
 * @returns {import('node:fs/promises').FileHandle}
 */
const openArtifact = async (artifact) => {
  const noFollow = constants.O_NOFOLLOW || 0;
  // A proof command can leave a background process that swaps the verified
  // artifact for a FIFO (or another non-regular file) between the lstat in
  // snapshotArtifactProof and this open. On POSIX, opening a FIFO read-only
  // without O_NONBLOCK waits for a writer, so the proof would hang instead of
  // returning a structured FAIL. Open with O_NONBLOCK where the platform
  // supports it (regular-file reads are unaffected; the constant is absent on
  // Windows) and fail closed below if the opened handle is not a regular
  // file, before any read can block or stream unbounded device data.
  const nonBlock = constants.O_NONBLOCK || 0;
  let handle;
  try {
    handle = await open(artifact, constants.O_RDONLY | noFollow | nonBlock);
  } catch (error) {
    if (!noFollow || !['EINVAL', 'ENOTSUP', 'EOPNOTSUPP'].includes(error?.code)) throw error;
    handle = await open(artifact, constants.O_RDONLY | nonBlock);
  }
  const info = await handle.stat();
  if (!info.isFile()) {
    await handle.close();
    throw new Error(`Artifact is not a regular file: ${artifact}`);
  }
  return handle;
};

/**
 * Hashes `artifact` (sha256, streamed in 64 KiB chunks) via an already-open,
 * symlink/FIFO-safe handle from openArtifact. Stats the file before and
 * after the read and reports `stable: false` if dev/ino/size/mtimeMs/ctimeMs
 * changed in between, so a caller can detect a proof artifact that was
 * mutated concurrently with verification instead of trusting a digest that
 * may not describe the file's final contents.
 * @returns {{digest: string, before: object, after: object, stable: boolean}}
 */
const hashArtifactDefault = async (artifact) => {
  const handle = await openArtifact(artifact);
  try {
    const before = await handle.stat();
    if (Number(before.size) > MAX_ARTIFACT_HASH_BYTES) {
      throw new Error(
        `Artifact exceeds hash size limit (${before.size} > ${MAX_ARTIFACT_HASH_BYTES} bytes): ${artifact}`,
      );
    }
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    let totalRead = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (!bytesRead) break;
      totalRead += bytesRead;
      if (totalRead > MAX_ARTIFACT_HASH_BYTES) {
        throw new Error(
          `Artifact exceeded hash size limit while reading (> ${MAX_ARTIFACT_HASH_BYTES} bytes): ${artifact}`,
        );
      }
      hash.update(buffer.subarray(0, bytesRead));
      position += bytesRead;
    }
    const after = await handle.stat();
    const stable = ['dev', 'ino', 'size', 'mtimeMs', 'ctimeMs']
      .every((field) => before[field] === after[field]);
    return { digest: hash.digest('hex'), before, after, stable };
  } finally {
    await handle.close();
  }
};

/**
 * Walks up from `path.dirname(target)` until it finds an ancestor directory
 * that actually exists, realpath-resolving it through any symlinks. Used to
 * establish where a not-yet-created artifact's parent really points, so a
 * proof path that does not exist yet can still be checked for worktree
 * containment. Rethrows any error other than ENOENT, and stops once a
 * candidate has no distinct parent left (filesystem root) to avoid an
 * infinite loop.
 */
const resolveExistingParent = async (target, filesystem) => {
  let candidate = path.dirname(target);
  while (true) {
    try {
      return await filesystem.realpath(candidate);
    } catch (error) {
      const parent = path.dirname(candidate);
      if (error?.code !== 'ENOENT' || parent === candidate) throw error;
      candidate = parent;
    }
  }
};

/**
 * Takes a TOCTOU-hardened snapshot of a proof artifact, used both as the
 * "before" state (pre-command) and, via verifyArtifactProof, the "after"
 * state (post-command). Rejects an absolute `proof.path`, any path segment
 * that is literally `.git` (case-insensitive), and anything that resolves
 * outside the command's `cwd` — checked both for the literal path and, once
 * resolved, for its realpath, so a path component that is itself a symlink
 * pointing outside the worktree is caught even though the final component
 * is an ordinary file. When the artifact does not exist yet, still resolves
 * its nearest existing ancestor through symlinks (resolveExistingParent)
 * and requires that ancestor to be contained too, so a not-yet-created path
 * cannot pre-snapshot as PASS via a symlinked parent that escapes the
 * worktree. When it exists, rejects a symbolic link and a hard-linked file
 * (nlink > 1 — a hard link lets another path mutate "the same" file without
 * this recorded path ever changing) before hashing it, and fails if the
 * hash step detects the file changed mid-read.
 * @returns {{status: 'PASS'|'FAIL', evidence?: string, exists?: boolean,
 *   digest?: string, dev?: number, ino?: number, size?: number}}
 */
const snapshotArtifactProof = async ({
  proof,
  cwd,
  filesystem = { lstat, realpath },
  hashArtifact = hashArtifactDefault,
}) => {
  if (path.isAbsolute(proof.path)) {
    return { status: 'FAIL', evidence: `Artifact proof path must be relative to the command worktree: ${proof.path}` };
  }
  const normalizedProof = path.posix.normalize(proof.path.replaceAll('\\', '/'));
  const proofSegments = normalizedProof.split('/').filter((segment) => segment && segment !== '.');
  if (proofSegments.some((segment) => segment.toLowerCase() === '.git')) {
    return { status: 'FAIL', evidence: `Artifact proof cannot target Git metadata: ${proof.path}` };
  }
  const artifact = path.resolve(cwd, proof.path);
  if (!isContainedPath(path.resolve(cwd), artifact)) {
    return { status: 'FAIL', evidence: `Artifact proof path is outside the command worktree: ${proof.path}` };
  }
  try {
    const realRoot = await filesystem.realpath(path.resolve(cwd));
    let info;
    try {
      info = await filesystem.lstat(artifact);
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
      const realParent = await resolveExistingParent(artifact, filesystem);
      if (realParent !== realRoot && !isContainedPath(realRoot, realParent)) {
        return { status: 'FAIL', evidence: `Artifact proof parent resolves outside the command worktree: ${proof.path}` };
      }
      return { status: 'PASS', exists: false, path: artifact, realRoot };
    }
    if (info.isSymbolicLink()) {
      return { status: 'FAIL', evidence: `Artifact proof cannot use a symbolic link: ${proof.path}` };
    }
    const realArtifact = await filesystem.realpath(artifact);
    if (!isContainedPath(realRoot, realArtifact)) {
      return { status: 'FAIL', evidence: `Artifact proof real path resolves outside the command worktree: ${proof.path}` };
    }
    if (!info.isFile()) return { status: 'FAIL', evidence: `Artifact proof is not a file: ${proof.path}` };
    const hashed = await hashArtifact(realArtifact);
    const digest = typeof hashed === 'string' ? hashed : hashed.digest;
    const handleInfo = typeof hashed === 'string' ? info : hashed.after;
    if (typeof hashed !== 'string' && !hashed.stable) {
      return { status: 'FAIL', evidence: `Artifact changed while it was being verified: ${proof.path}` };
    }
    if (typeof hashed !== 'string' && (info.dev !== hashed.before.dev || info.ino !== hashed.before.ino)) {
      return { status: 'FAIL', evidence: `Artifact path changed while it was being verified: ${proof.path}` };
    }
    if (Number(handleInfo.nlink || info.nlink || 1) > 1) {
      return { status: 'FAIL', evidence: `Artifact proof cannot use a hard-linked file: ${proof.path}` };
    }
    return {
      status: 'PASS',
      exists: true,
      path: artifact,
      realPath: realArtifact,
      realRoot,
      size: handleInfo.size,
      mtimeMs: handleInfo.mtimeMs,
      ctimeMs: handleInfo.ctimeMs,
      dev: handleInfo.dev,
      ino: handleInfo.ino,
      digest,
    };
  } catch (error) {
    return { status: 'FAIL', evidence: `Artifact proof failed for ${proof.path}: ${error.message}` };
  }
};

/**
 * Proves a command actually (re)produced its declared artifact, not just
 * that the artifact happens to exist. Re-snapshots the artifact after the
 * command via snapshotArtifactProof and requires it to exist as a
 * non-empty file; if a `before` snapshot showed the artifact already
 * existed, also requires its digest, dev, ino, or size to have actually
 * changed — otherwise a stale leftover from a previous run would pass as
 * fresh evidence. Short-circuits and returns `before` unchanged if `before`
 * was already a FAIL.
 */
const verifyArtifactProof = async ({ proof, cwd, before }) => {
  if (before?.status === 'FAIL') return before;
  const after = await snapshotArtifactProof({ proof, cwd });
  if (after.status === 'FAIL') return after;
  if (!after.exists || after.size === 0) {
    return { status: 'FAIL', evidence: `Artifact proof is missing a non-empty file: ${proof.path}` };
  }
  if (before?.exists) {
    const contentOrIdentityChanged = before.digest !== after.digest
      || before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size;
    if (!contentOrIdentityChanged) {
      return { status: 'FAIL', evidence: `Artifact was not refreshed by this run: ${proof.path}` };
    }
  }
  return {
    ...after,
    evidence: `Verified refreshed non-empty artifact ${proof.path} (${after.size} bytes).`,
  };
};

/**
 * Reads and parses a verified artifact as JSON, re-checking identity before
 * and after the read against the already-verified `proofResult` (dev, ino,
 * size, and — after reading — mtimeMs and digest) so a swap or edit that
 * happens between snapshotArtifactProof and this read is caught instead of
 * silently trusting stale bytes. Refuses anything without a realPath/size on
 * `proofResult`, or larger than 1 MiB.
 * @returns {{status: 'PASS', value: unknown}|{status: 'FAIL', evidence: string}}
 */
const readBoundArtifactJson = async (proofResult) => {
  if (!proofResult?.realPath || !Number.isFinite(proofResult.size) || proofResult.size > 1_000_000) {
    return { status: 'FAIL', evidence: 'Semantic artifact proof must be a verified JSON file no larger than 1 MiB.' };
  }
  const handle = await openArtifact(proofResult.realPath);
  try {
    const before = await handle.stat();
    if (before.dev !== proofResult.dev || before.ino !== proofResult.ino || before.size !== proofResult.size) {
      return { status: 'FAIL', evidence: 'Semantic artifact identity changed after artifact verification.' };
    }
    const content = await handle.readFile();
    const after = await handle.stat();
    const digest = createHash('sha256').update(content).digest('hex');
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size
      || before.mtimeMs !== after.mtimeMs || digest !== proofResult.digest) {
      return { status: 'FAIL', evidence: 'Semantic artifact changed while it was being verified.' };
    }
    return { status: 'PASS', value: JSON.parse(content.toString('utf8')) };
  } catch (error) {
    return { status: 'FAIL', evidence: `Semantic artifact JSON could not be verified: ${error.message}` };
  } finally {
    await handle.close();
  }
};

/**
 * Validates that a `grafana-live-render` artifact JSON payload actually
 * proves a live Grafana call was made, not just that some JSON file exists.
 * Requires `proof.semantic === 'grafana-live-result'`, an http(s) `endpoint`
 * matching the independently probed `expectedGrafanaOrigin` (from
 * `services.grafana.url`), and a 2xx `httpStatus`.
 * For a `query` operation, additionally requires the request to have
 * targeted `/api/ds/query` with at least one query, every result entry to
 * be error-free, and at least one result to carry a genuinely non-empty
 * series — an empty frames array, a frame with only null/undefined/empty
 * values, and the legacy single-result shape without real datapoints are
 * all rejected alike. For a `render` operation, requires an image
 * content-type, a positive byte count, and a well-formed sha256 in the
 * response metadata. Any other operation, or a missing/malformed field,
 * fails closed.
 */
const verifyGrafanaLiveArtifact = async ({ proof, proofResult, expectedGrafanaOrigin = null }) => {
  if (proof.semantic !== 'grafana-live-result') {
    return { status: 'FAIL', evidence: 'Grafana live proof requires semantic=grafana-live-result.' };
  }
  const parsed = await readBoundArtifactJson(proofResult);
  if (parsed.status !== 'PASS') return parsed;
  const payload = parsed.value;
  if (!payload || typeof payload !== 'object' || String(payload.provider).toLowerCase() !== 'grafana') {
    return { status: 'FAIL', evidence: 'Grafana live proof did not identify Grafana as the provider.' };
  }
  let endpoint;
  try {
    endpoint = new URL(payload.endpoint);
    if (!['http:', 'https:'].includes(endpoint.protocol)) throw new Error('unsupported protocol');
    // Require the independently probed services.grafana.url origin. Do not
    // let proof.grafanaOrigin from closeout config override it: a config
    // proof path can otherwise point the artifact check at a different host
    // than the one preflight actually probed.
    if (!expectedGrafanaOrigin) {
      return { status: 'FAIL', evidence: 'Grafana live proof requires a configured Grafana origin (services.grafana.url).' };
    }
    if (endpoint.origin !== new URL(expectedGrafanaOrigin).origin) {
      return { status: 'FAIL', evidence: 'Grafana live proof endpoint did not match the probed Grafana origin.' };
    }
  } catch (error) {
    return { status: 'FAIL', evidence: `Grafana live proof endpoint was invalid: ${error.message}` };
  }
  if (!Number.isInteger(payload.httpStatus) || payload.httpStatus < 200 || payload.httpStatus >= 300) {
    return { status: 'FAIL', evidence: 'Grafana live proof did not record a successful HTTP status.' };
  }
  if (payload.operation === 'query') {
    const queries = payload.request?.queries;
    const results = payload.response?.results;
    if (endpoint.pathname !== '/api/ds/query' || !Array.isArray(queries) || queries.length === 0
      || !results || typeof results !== 'object' || Object.keys(results).length === 0) {
      return { status: 'FAIL', evidence: 'Grafana live query proof lacked a bound query request and non-empty result.' };
    }
    // A 200 response can still carry per-refId errors (e.g. datasource
    // unavailable). Require every result entry to be error-free and to expose
    // a usable frame, otherwise the proof does not establish a clean result.
    const resultEntries = Object.values(results);
    const errorEntries = resultEntries.filter((entry) => entry && typeof entry === 'object' && (
      String(entry.error || '').trim()
      || String(entry.errorSource || '').trim()
      || String(entry.status || '').toLowerCase() === 'error'
    ));
    if (errorEntries.length) {
      return { status: 'FAIL', evidence: 'Grafana live query proof contained a result entry with an error.' };
    }
    const usableFrames = resultEntries.filter((entry) => {
      if (!entry || typeof entry !== 'object') return false;
      if (Array.isArray(entry.frames)) {
        // Require at least one frame to actually contain data values, not
        // just an empty object/array shape. frames: [{}], frames: [{ data:
        // { values: [] } }], or frames: [{ data: { values: [null] } }] does
        // not establish a non-empty Grafana result; at least one series must
        // be a non-empty array of real values.
        return entry.frames.some((frame) => {
          if (!frame || typeof frame !== 'object') return false;
          const values = frame?.data?.values;
          if (Array.isArray(values)) {
            // Require at least one non-null/non-empty datapoint, not just a
            // series of nulls (e.g. values: [[null, null]]).
            return values.length > 0 && values.some((series) => (
              Array.isArray(series)
              && series.some((point) => point !== null && point !== undefined && point !== '')
            ));
          }
          // Some Grafana responses carry a schema/len pair without inline
          // values; accept only when at least one numeric field is non-empty.
          const numeric = frame?.data?.numeric ?? frame?.schema?.length;
          return Number.isFinite(numeric) && numeric > 0;
        });
      }
      // Legacy single-result shape: require at least one real datapoint.
      return Array.isArray(entry?.data?.values) && entry.data.values.length > 0
        && entry.data.values.some((series) => (
          Array.isArray(series)
          && series.some((point) => point !== null && point !== undefined && point !== '')
        ));
    });
    if (!usableFrames.length) {
      return { status: 'FAIL', evidence: 'Grafana live query proof contained no result entry with non-empty frame data.' };
    }
    return { status: 'PASS', evidence: 'Verified refreshed artifact and bound Grafana live query result.' };
  }
  if (payload.operation === 'render') {
    const response = payload.response;
    if (!endpoint.pathname.startsWith('/render/') || !/^image\/(?:png|jpeg|svg\+xml)$/i.test(response?.contentType || '')
      || !Number.isInteger(response?.bytes) || response.bytes <= 0
      || !/^[a-f0-9]{64}$/i.test(response?.sha256 || '')) {
      return { status: 'FAIL', evidence: 'Grafana live render proof lacked bound render response metadata.' };
    }
    return { status: 'PASS', evidence: 'Verified refreshed artifact and bound Grafana live render result.' };
  }
  return { status: 'FAIL', evidence: 'Grafana live proof operation must be query or render.' };
};

/**
 * Parses `docker compose ps --format json` output, which can be either a
 * single JSON array/object or NDJSON (one JSON value per line). Tries the
 * whole text as JSON first, falls back to per-line parsing, and returns an
 * empty array — fail closed, not throw — if neither succeeds.
 */
const parseDockerComposeRows = (text) => {
  const trimmed = String(text ?? '').trim();
  if (!trimmed) return [];
  const flatten = (value) => (Array.isArray(value) ? value : [value]);
  try {
    return flatten(JSON.parse(trimmed));
  } catch {
    try {
      return trimmed.split(/\r?\n/).filter(Boolean).flatMap((line) => flatten(JSON.parse(line)));
    } catch {
      return [];
    }
  }
};

/**
 * Evaluates a command proof's output against its declared policy.
 * `hunter-build` is a hard-coded semantic policy requiring
 * `docker compose ps --format json` to include a `Service: "hunter"` row
 * (rows without a `Service` field are ignored rather than treated as a
 * match) with `State: running` and `Health: healthy`. Every other check
 * must use a bounded `literal:<text>` policy — a case-insensitive substring
 * match against combined stdout+stderr — capped at 264 characters with no
 * control characters; anything else, in particular regex syntax, is
 * rejected as an invalid policy rather than evaluated, so a check config
 * can never smuggle in arbitrary pattern evaluation.
 * @returns {{matched: boolean, policyValid: boolean, evidence: string}}
 */
const evaluateCommandProof = ({ check, execution }) => {
  const policy = String(check.proof.expectedPattern || '');
  if (check.id === 'hunter-build') {
    if (policy !== 'semantic:docker-compose-running-healthy') {
      return {
        matched: false,
        policyValid: false,
        evidence: 'Hunter proof requires semantic:docker-compose-running-healthy.',
      };
    }
    const rows = parseDockerComposeRows(execution.stdout);
    // Require an explicit Service=hunter row. docker compose ps --format json
    // always includes Service; JSON without any Service field cannot prove the
    // running/healthy row is the hunter service (another container could
    // satisfy State/Health), so fail closed instead of treating every row as
    // hunter.
    const hunterRows = rows
      .filter((row) => row && typeof row === 'object' && Object.hasOwn(row, 'Service'))
      .filter((row) => String(row.Service).toLowerCase() === 'hunter');
    const matched = hunterRows.length > 0 && hunterRows.every((row) => (
      String(row.State).toLowerCase() === 'running' && String(row.Health).toLowerCase() === 'healthy'
    ));
    return {
      matched,
      policyValid: true,
      evidence: matched
        ? 'Docker JSON proved hunter State=running and Health=healthy.'
        : 'Docker JSON did not prove hunter State=running and Health=healthy.',
    };
  }
  if (!policy.startsWith('literal:') || policy.length > 264 || /[\u0000-\u001f\u007f]/u.test(policy)) {
    return {
      matched: false,
      policyValid: false,
      evidence: 'Command proof expectedPattern must use a bounded literal:<text> policy or a supported semantic policy.',
    };
  }
  const literal = policy.slice('literal:'.length);
  if (!literal) {
    return { matched: false, policyValid: false, evidence: 'Command proof literal must not be empty.' };
  }
  return {
    matched: `${execution.stdout}\n${execution.stderr}`.toLowerCase().includes(literal.toLowerCase()),
    policyValid: true,
    evidence: 'Command proof used a bounded literal policy.',
  };
};

/**
 * Builds the executor function used to run every closeout check against one
 * repo. Returns an async `(check, phase, cwd = repo) => result` closure;
 * call this factory once per workflow run and reuse the returned function
 * for every check so the per-check log-attempt counter, unsafe-termination
 * latch, and precomputed path/env replacement lists are shared. Once any
 * spawned command's process-tree termination cannot be proven (BLOCKED),
 * the latch trips and every later call short-circuits to BLOCKED without
 * spawning anything — a previous command's unaccounted-for escaped process
 * could still be mutating the worktree, so running further commands
 * concurrently with it is unsafe regardless of what they check. When `cwd`
 * differs from `repo` (a baseline/worktree comparison run), extends the
 * redaction set so the baseline path is also normalized to `<repo>` rather
 * than leaking as a raw temp path. Handles both proof kinds: an `artifact`
 * proof is snapshotted before the command runs and re-verified after (see
 * verifyArtifactProof); a `command` proof runs as a second, separately
 * logged spawn and is evaluated by evaluateCommandProof. Every returned
 * field — including the check definition itself — passes through redaction
 * and path normalization before it leaves this function.
 */
const createCommandExecutor = ({
  repo,
  outputDir,
  env = process.env,
  shell = resolveCommandShell({ env }),
  shellArgs = defaultShellArgs,
  secretNames = [],
  timeoutMs = DEFAULT_TIMEOUT_MS,
  timeoutsMs = {},
  platform = process.platform,
  spawnProcess = spawn,
  terminateTree = terminateProcessTree,
  terminationGraceMs = 2000,
  grafanaServiceUrl = null,
} = {}) => {
  let unsafeTermination;
  const attempts = new Map();
  const pathReplacements = buildPathReplacements({ cwd: repo, outputDir, env });
  const childEnv = buildChildEnvironment(env, secretNames);
  const nextLogPath = (phase, id, kind = '') => {
    const safePhase = String(phase).replace(/[^a-z0-9_-]/gi, '-');
    const safeId = String(id).replace(/[^a-z0-9_-]/gi, '-');
    const key = `${safePhase}.${safeId}${kind ? `.${kind}` : ''}`;
    const attempt = (attempts.get(key) || 0) + 1;
    attempts.set(key, attempt);
    return path.join(outputDir, 'logs', `${key}.attempt-${String(attempt).padStart(3, '0')}.log`);
  };
  const safeEvidencePath = (value) => normalizePaths(
    value,
    pathReplacements,
    platform,
  ).replaceAll('\\', '/');
  const classifyExecution = (execution) => {
    if (execution.terminationStatus === 'BLOCKED') {
      return { status: 'BLOCKED', evidence: execution.terminationEvidence };
    }
    // If the raw evidence log became unwritable mid-run (disk full, perms
    // changed, logs dir removed), the persisted evidence is incomplete.
    // Treat that as a blocking evidence failure even if the command itself
    // exited cleanly with no status signals — otherwise closeout could PASS
    // while pointing at a log file that does not contain the full record.
    if (execution.logWriteError) {
      return {
        status: 'BLOCKED',
        evidence: `Raw evidence log was not writable for the full run: ${execution.logWriteError.message || execution.logWriteError}`,
      };
    }
    return classifyOutput(execution);
  };
  return async (check, phase, cwd = repo) => {
  // When the caller supplies a baseline/worktree cwd that differs from the
  // primary repo, extend the redaction set so baseline paths are normalized
  // (and hashed) the same way as the head run, instead of leaking as /tmp/...
  const effectivePathReplacements = cwd && path.resolve(cwd) !== path.resolve(repo)
    ? [...pathReplacements, ...pathVariants(cwd).map((value) => [value, '<repo>'])]
    : pathReplacements;
  const finalize = (value) => mapStructureStrings(
    redactStructure(value, env, secretNames),
    (text) => normalizePaths(text, effectivePathReplacements, platform),
  );
  const safeCheck = finalize(check);
  if (unsafeTermination) {
    return finalize({
      ...safeCheck,
      phase,
      status: 'BLOCKED',
      exitCode: null,
      evidence: `Validation halted after an unsafe process tree: ${unsafeTermination}`,
    });
  }
  const artifactBefore = check.proof?.type === 'artifact'
    ? await snapshotArtifactProof({ proof: check.proof, cwd })
    : null;
  if (artifactBefore?.status === 'FAIL') {
    return finalize({ ...safeCheck, phase, status: 'FAIL', evidence: artifactBefore.evidence, proofResult: artifactBefore });
  }
  const logsDir = path.join(outputDir, 'logs');
  await mkdir(logsDir, { recursive: true, mode: 0o700 });
  try {
    await chmod(logsDir, 0o700);
  } catch {
    // Platform may ignore directory modes.
  }
  const logPath = nextLogPath(phase, check.id);
  const safeCommand = normalizePaths(redactSecrets(check.command, env, secretNames), effectivePathReplacements, platform);
  await writeLogHeaderNoFollow(logPath, `command: ${safeCommand}\ncwd: <repo>\n`);
  const execution = await spawnCaptured({
    command: check.command,
    cwd,
    shell,
    shellArgs,
    // Baseline comparison ids inherit the parent check's configured timeout.
    timeoutMs: resolveCheckTimeout(check, timeoutsMs, timeoutMs),
    env: childEnv,
    redactionEnv: env,
    secretNames,
    logPath,
    pathReplacements: effectivePathReplacements,
    platform,
    spawnProcess,
    terminateTree,
    terminationGraceMs,
  });
  if (execution.terminationStatus === 'BLOCKED') unsafeTermination = execution.terminationEvidence;
  const classification = classifyExecution(execution);
  const result = {
    ...safeCheck,
    phase,
    ...execution,
    ...classification,
    logPath: safeEvidencePath(logPath),
  };
  if (result.status !== 'PASS' || !check.proof) return finalize(result);
  if (check.proof.type === 'artifact') {
    const proofResult = await verifyArtifactProof({ proof: check.proof, cwd, before: artifactBefore });
    if (proofResult.status !== 'PASS' || check.id !== 'grafana-live-render') {
      return finalize({ ...result, status: proofResult.status, evidence: proofResult.evidence, proofResult });
    }
    const semantic = await verifyGrafanaLiveArtifact({
      proof: check.proof,
      proofResult,
      expectedGrafanaOrigin: grafanaServiceUrl,
    });
    return finalize({ ...result, status: semantic.status, evidence: semantic.evidence, proofResult });
  }
  if (check.proof.type === 'command') {
    const proofLogPath = nextLogPath(phase, check.id, 'proof');
    const safeProofCommand = normalizePaths(
      redactSecrets(check.proof.command, env, secretNames),
      effectivePathReplacements,
      platform,
    );
    await writeLogHeaderNoFollow(proofLogPath, `command: ${safeProofCommand}\ncwd: <repo>\n`);
    const proofExecution = await spawnCaptured({
      command: check.proof.command,
      cwd,
      shell,
      shellArgs,
      timeoutMs: resolveCheckTimeout(check, timeoutsMs, timeoutMs),
      env: childEnv,
      redactionEnv: env,
      secretNames,
      logPath: proofLogPath,
      pathReplacements: effectivePathReplacements,
      platform,
      spawnProcess,
      terminateTree,
      terminationGraceMs,
    });
    if (proofExecution.terminationStatus === 'BLOCKED') unsafeTermination = proofExecution.terminationEvidence;
    const proofClassification = classifyExecution(proofExecution);
    const evaluation = evaluateCommandProof({ check, execution: proofExecution });
    const proofResult = {
      ...proofExecution,
      ...proofClassification,
      logPath: safeEvidencePath(proofLogPath),
      matched: evaluation.matched,
      matchPolicyValid: evaluation.policyValid,
    };
    if (proofClassification.status !== 'PASS') {
      return finalize({ ...result, status: proofClassification.status, evidence: `Postcondition command was not clean. ${proofClassification.evidence}`, proofResult });
    }
    if (!evaluation.matched) {
      return finalize({ ...result, status: 'FAIL', evidence: evaluation.evidence, proofResult });
    }
    return finalize({ ...result, evidence: evaluation.evidence, proofResult });
  }
  return finalize({ ...result, status: 'FAIL', evidence: `Unsupported proof type: ${check.proof.type}` });
  };
};

/**
 * Default TCP reachability probe: resolves true on `connect`, false on
 * `error` or after `timeoutMs`, and always destroys the socket before
 * resolving.
 * @returns {Promise<boolean>}
 */
const probeTcpDefault = ({ host, port, timeoutMs = 1500 }) => new Promise((resolve) => {
  const socket = net.createConnection({ host, port: Number(port) });
  const done = (value) => {
    socket.destroy();
    resolve(value);
  };
  socket.setTimeout(timeoutMs, () => done(false));
  socket.once('connect', () => done(true));
  socket.once('error', () => done(false));
});

/**
 * Default Redis health probe: sends a raw RESP `PING` and requires an exact
 * `+PONG\r\n` reply. Guards with an explicit `settled` flag — unlike the
 * once-only 'connect'/'error' races used elsewhere in this file — because
 * `'data'` is a persistent listener that can fire repeatedly; without the
 * guard, a multi-chunk response would call `done()` more than once. Caps
 * the accumulated response at 64 bytes and fails closed if that is exceeded
 * without a terminating CRLF.
 * @returns {Promise<boolean>}
 */
const probeRedisDefault = ({ host, port, timeoutMs = 1500 }) => new Promise((resolve) => {
  const socket = net.createConnection({ host, port: Number(port) });
  let response = '';
  let settled = false;
  const done = (value) => {
    if (settled) return;
    settled = true;
    socket.destroy();
    resolve(value);
  };
  socket.setTimeout(timeoutMs, () => done(false));
  socket.once('connect', () => socket.write('*1\r\n$4\r\nPING\r\n'));
  socket.on('data', (chunk) => {
    response += chunk.toString('utf8');
    if (response.length > 64) return done(false);
    if (response.endsWith('\r\n')) done(response === '+PONG\r\n');
  });
  socket.once('end', () => done(response === '+PONG\r\n'));
  socket.once('error', () => done(false));
});

/**
 * Default Grafana health probe. Requires the URL to be http(s) with a path
 * of exactly `/api/health` before issuing the request. Caps the response
 * body at 64 KiB — destroying the response and failing closed if exceeded —
 * requires a 2xx status with a JSON content-type, and then requires the
 * parsed body to prove real Grafana identity (`database === 'ok'` plus
 * non-empty `version` and `commit` strings) rather than treating any 2xx
 * JSON response as healthy. Settles exactly once even though a response can
 * emit `'close'` after a normal `'end'`, or before one on an abort.
 * @returns {Promise<{healthy: boolean, evidence: string}>}
 */
const probeGrafanaHealthDefault = (url, timeoutMs = 2500) => new Promise((resolve) => {
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)
      || parsedUrl.pathname.replace(/\/+$/u, '') !== '/api/health') {
      resolve({ healthy: false, evidence: 'Grafana health URL must target /api/health over HTTP or HTTPS.' });
      return;
    }
  } catch {
    resolve({ healthy: false, evidence: 'Grafana health URL is invalid.' });
    return;
  }
  const client = parsedUrl.protocol === 'https:' ? https : http;
  let settled = false;
  const done = (value) => {
    if (settled) return;
    settled = true;
    resolve(value);
  };
  const request = client.get(parsedUrl, { timeout: timeoutMs }, (response) => {
    const chunks = [];
    let length = 0;
    response.on('data', (chunk) => {
      length += chunk.length;
      if (length > 65_536) {
        response.destroy();
        done({ healthy: false, evidence: 'Grafana health response exceeded 64 KiB.' });
        return;
      }
      chunks.push(chunk);
    });
    response.once('end', () => {
      if (response.statusCode < 200 || response.statusCode >= 300
        || !String(response.headers['content-type'] || '').toLowerCase().includes('application/json')) {
        done({ healthy: false, evidence: 'Grafana health endpoint did not return successful JSON.' });
        return;
      }
      try {
        const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        const healthy = payload?.database === 'ok'
          && typeof payload.version === 'string' && payload.version.length > 0
          && typeof payload.commit === 'string' && payload.commit.length > 0;
        done(healthy
          ? { healthy: true, evidence: 'Grafana API identity and database health were verified.' }
          : { healthy: false, evidence: 'Grafana health JSON lacked the required identity or database status.' });
      } catch {
        done({ healthy: false, evidence: 'Grafana health response was not valid JSON.' });
      }
    });
    // If the endpoint sends headers (and possibly partial data) then aborts or
    // closes the socket before 'end', the promise would otherwise hang: the
    // request timeout does not re-fire once a response has begun. 'close' runs
    // after a normal 'end' too, but done() is idempotent so the late call is a
    // no-op; in the abort case it is the only path that settles the probe, so
    // runPreflight records a BLOCKED Grafana row instead of hanging forever.
    response.once('close', () => done({ healthy: false, evidence: 'Grafana health response closed before completion.' }));
    response.once('error', () => done({ healthy: false, evidence: 'Grafana health response stream errored before completion.' }));
  });
  request.once('timeout', () => {
    request.destroy();
    done({ healthy: false, evidence: 'Grafana health request timed out.' });
  });
  request.once('error', () => done({ healthy: false, evidence: 'Grafana health endpoint was unavailable.' }));
});

/**
 * Default free-disk-space probe. Uses `stats.bavail` (blocks available to
 * an unprivileged user), not `bfree` (which includes blocks reserved for
 * root), so the reported free space matches what the check-running user can
 * actually consume.
 * @returns {Promise<number>} Free space in GiB.
 */
const diskFreeGbDefault = async (repo) => {
  const stats = await statfs(repo, { bigint: true });
  return Number(stats.bavail * stats.bsize) / (1024 ** 3);
};

const TOOL_PROBES = [
  ['git', 'git --version'],
  ['node', 'node --version'],
  ['pnpm', 'pnpm --version'],
  ['make', 'make --version'],
  ['docker', 'docker --version'],
  ['docker-compose', 'docker compose version'],
  ['docker-daemon', "docker info --format '{{.ServerVersion}}'"],
  ['prisma', 'pnpm prisma --version'],
];

/**
 * Default tool-version probe used by runPreflight. Runs `command` through
 * the same non-login shell argv as the command executor
 * (`--noprofile --norc -c`), so preflight tool discovery matches what
 * checks can actually resolve at run time and shell profiles cannot inject
 * side effects. Tools must already be on the parent process PATH.
 *
 * Spawns detached (POSIX) under a unique SPAWN_MARK so a probe such as
 * `pnpm prisma --version` that starts a detached helper and exits cannot
 * leave an unmarked orphan that later mutates the worktree after the final
 * seal. terminateProcessTree runs after close/timeout the same way as the
 * validation executor.
 *
 * Never throws: spawn errors and non-zero exits are normalized into the same
 * `{exitCode, stdout, stderr}` shape so every probe result can be handled
 * uniformly by the caller.
 * @returns {Promise<{exitCode: number|null, stdout: string, stderr: string}>}
 */
const probeCommandDefault = async ({
  command,
  repo,
  shell,
  env,
  platform = process.platform,
  spawnProcess = spawn,
  terminateTree = terminateProcessTree,
  timeoutMs = 120_000,
  terminationGraceMs = 2000,
}) => {
  const spawnMark = platform === 'win32' ? '' : randomBytes(16).toString('hex');
  const spawnEnv = spawnMark ? { ...env, [SPAWN_MARK_ENV]: spawnMark } : env;
  let minStarttime = 0;
  let stdout = '';
  let stderr = '';
  const child = spawnProcess(shell, defaultShellArgs(command, shell), {
    cwd: repo,
    env: spawnEnv,
    detached: platform !== 'win32',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (platform !== 'win32' && Number.isInteger(child?.pid)) {
    try {
      const stat = readFileSync(`/proc/${child.pid}/stat`, 'utf8');
      const afterComm = stat.lastIndexOf(')');
      if (afterComm >= 0) {
        const fields = stat.slice(afterComm + 1).trimStart().split(/\s+/);
        const starttime = Number(fields[19]);
        if (Number.isFinite(starttime)) minStarttime = starttime;
      }
    } catch {
      minStarttime = 0;
    }
  }
  const cap = (acc, chunk) => {
    const next = acc + String(chunk ?? '');
    return next.length > CAPTURE_LIMIT ? next.slice(0, CAPTURE_LIMIT) : next;
  };
  child.stdout?.on('data', (chunk) => { stdout = cap(stdout, chunk); });
  child.stderr?.on('data', (chunk) => { stderr = cap(stderr, chunk); });

  let closeResolved = false;
  let resolveClose;
  const closePromise = new Promise((resolve) => { resolveClose = resolve; });
  const close = (outcome) => {
    if (closeResolved) return;
    closeResolved = true;
    resolveClose(outcome);
  };
  child.once('error', (error) => close({ exitCode: null, signal: null, spawnError: error }));
  child.once('close', (exitCode, signal) => close({ exitCode, signal }));

  const first = await Promise.race([
    closePromise.then((outcome) => ({ kind: 'close', outcome })),
    new Promise((resolve) => {
      setTimeout(() => resolve({ kind: 'timeout' }), timeoutMs);
    }),
  ]);

  let outcome = first.outcome;
  if (first.kind === 'close') {
    if (!outcome?.spawnError) {
      await terminateTree({
        child,
        platform,
        env,
        terminationGraceMs,
        closePromise,
        spawnMark,
        cwd: repo,
        minStarttime,
      });
    }
  } else {
    await terminateTree({
      child,
      platform,
      env,
      terminationGraceMs,
      closePromise,
      spawnMark,
      cwd: repo,
      minStarttime,
    });
    outcome = await Promise.race([
      closePromise,
      new Promise((resolve) => { setTimeout(() => resolve(null), terminationGraceMs); }),
    ]);
    if (!outcome) {
      try { child.kill('SIGKILL'); } catch { /* already gone */ }
      outcome = await Promise.race([
        closePromise,
        new Promise((resolve) => { setTimeout(() => resolve(null), terminationGraceMs); }),
      ]);
    }
  }

  if (outcome?.spawnError) {
    return {
      exitCode: null,
      stdout,
      stderr: outcome.spawnError.message || String(outcome.spawnError),
    };
  }
  if (!outcome) {
    return { exitCode: null, stdout, stderr: stderr || 'probe timed out' };
  }
  return {
    exitCode: Number.isInteger(outcome.exitCode) ? outcome.exitCode : null,
    stdout,
    stderr,
  };
};

/**
 * Runs every preflight gate before a closeout workflow is allowed to admit
 * commands: the configured shell is executable, each tool in TOOL_PROBES
 * resolves and reports a clean version (a probe that exits 0 but prints a
 * warning/problem/skip/fail signal is still not PASS — see classifyOutput),
 * every `config.requiredEnv` name is present AND at least 4 characters long
 * (too short to redact reliably, so it is reported BLOCKED rather than
 * risking an unredactable secret in evidence), free disk space meets
 * `config.minFreeDiskGb`, and any configured Redis/Grafana/TCP-port
 * services are reachable. Every probe is individually try/caught into a
 * BLOCKED check with evidence instead of rejecting, so one flaky service
 * probe cannot abort the whole preflight report. Overall `status` is FAIL
 * if any individual check is FAIL, else BLOCKED if any check is not PASS,
 * else PASS.
 * @returns {{status: 'PASS'|'BLOCKED'|'FAIL', checks: object[], toolVersions: object}}
 */
const runPreflight = async ({
  repo,
  config = {},
  env = process.env,
  probeCommand,
  diskFreeGb = diskFreeGbDefault,
  probeTcp = probeTcpDefault,
  probeRedis = probeRedisDefault,
  probeHttp = probeGrafanaHealthDefault,
} = {}) => {
  const checks = [];
  const toolVersions = {};
  const shell = resolveCommandShell({ env });
  // Redact personal home prefixes from shell evidence so absolute shell paths
  // under the caller's home (e.g. OMO_CODEX_SHELL_PATH) do not leak into reports.
  const redactShellEvidence = (value) => {
    let text = String(value ?? '');
    const homes = [
      env.HOME,
      env.USERPROFILE,
      env.HOMEDRIVE && env.HOMEPATH ? `${env.HOMEDRIVE}${env.HOMEPATH}` : null,
    ].filter(Boolean);
    for (const home of homes) {
      for (const candidate of [home, String(home).replaceAll('\\', '/'), String(home).replaceAll('/', '\\')]) {
        if (!candidate) continue;
        text = text.split(candidate).join('<home>');
      }
    }
    return text;
  };
  try {
    await probeCommandShell(shell, env);
    checks.push({ name: 'command-shell', status: 'PASS', evidence: redactShellEvidence(shell) });
  } catch {
    checks.push({
      name: 'command-shell',
      status: 'BLOCKED',
      evidence: redactShellEvidence(`Required shell not found: ${shell}`),
    });
  }
  // Tool probes run with, and have their evidence redacted against, BOTH
  // configured env lists: safeEnv entries are deliberately preserved for the
  // child environment and must also be treated as explicitly-redacted inputs,
  // exactly like the executor path (which passes requiredEnv + safeEnv as
  // secretNames).
  const sensitiveEnvNames = [...(config.requiredEnv || []), ...(config.safeEnv || [])];
  const commandEnv = buildChildEnvironment(env, sensitiveEnvNames);
  const runProbe = probeCommand || ((command) => probeCommandDefault({
    command,
    repo,
    shell,
    env: commandEnv,
  }));
  for (const [name, command] of TOOL_PROBES) {
    const result = await runProbe(command);
    const classification = classifyOutput(result);
    const status = result.exitCode === 0 ? classification.status : 'BLOCKED';
    const rawEvidence = status === 'PASS'
      ? (result.stdout || result.stderr || `exit ${result.exitCode}`).trim().split(/\r?\n/)[0]
      : classification.evidence;
    const evidence = redactSecrets(rawEvidence, env, sensitiveEnvNames);
    checks.push({ name, status, evidence });
    if (status === 'PASS') toolVersions[name] = evidence;
  }
  const envNames = Object.keys(env);
  for (const name of config.requiredEnv || []) {
    // Resolve the configured name to the actual env key case-insensitively,
    // mirroring buildChildEnvironment/buildSecretReplacements: a config
    // listing "npm_token" must see NPM_TOKEN instead of reporting it missing.
    const actualName = envNames.find((key) => key.toUpperCase() === String(name).toUpperCase());
    const value = actualName === undefined ? undefined : env[actualName];
    const present = typeof value === 'string' && value.length > 0;
    const reliable = present && value.length >= 4;
    checks.push({
      name: `env:${name}`,
      status: reliable ? 'PASS' : 'BLOCKED',
      evidence: reliable ? 'present' : (present ? 'value is too short for reliable evidence redaction' : 'missing'),
    });
  }
  const minimum = Number(config.minFreeDiskGb ?? 2);
  // Wrap the disk-space probe the same way the service probes below are
  // wrapped: statfs can reject on an unsupported or transiently unavailable
  // filesystem, and a bare await would bubble out of runPreflight into
  // runCloseoutWorkflow's admission Promise.all and skip the structured
  // evidence report.
  let freeGb;
  try {
    freeGb = await diskFreeGb(repo);
  } catch (error) {
    checks.push({
      name: 'disk',
      status: 'BLOCKED',
      evidence: `Disk-space probe rejected: ${error?.message || error}`,
    });
    freeGb = -Infinity;
  }
  if (Number.isFinite(freeGb)) {
    checks.push({ name: 'disk', status: freeGb >= minimum ? 'PASS' : 'BLOCKED', evidence: `${freeGb.toFixed(2)} GiB free; ${minimum} GiB required` });
  }
  if (config.services?.redis) {
    let healthy = false;
    let evidence = 'Redis RESP PING did not return +PONG.';
    try {
      healthy = await probeRedis(config.services.redis);
    } catch (error) {
      healthy = false;
      evidence = `Redis probe rejected: ${error?.message || error}`;
    }
    checks.push({
      name: 'redis',
      status: healthy ? 'PASS' : 'BLOCKED',
      evidence: healthy ? 'Redis RESP PING returned +PONG.' : evidence,
    });
  }
  if (config.services?.grafana?.url) {
    let health = null;
    try {
      health = await probeHttp(config.services.grafana.url);
    } catch (error) {
      health = { healthy: false, evidence: `Grafana probe rejected: ${error?.message || error}` };
    }
    checks.push({
      name: 'grafana',
      status: health?.healthy === true ? 'PASS' : 'BLOCKED',
      evidence: health?.evidence || 'Grafana identity and health were not verified.',
    });
  }
  for (const service of config.ports || []) {
    let healthy = false;
    let evidence = 'TCP unavailable';
    try {
      healthy = await probeTcp(service);
      evidence = healthy ? 'TCP reachable' : 'TCP unavailable';
    } catch (error) {
      healthy = false;
      evidence = `TCP probe rejected: ${error?.message || error}`;
    }
    checks.push({ name: `port:${service.name || `${service.host}:${service.port}`}`, status: healthy ? 'PASS' : 'BLOCKED', evidence });
  }
  const status = checks.some((check) => check.status === 'FAIL')
    ? 'FAIL'
    : (checks.every((check) => check.status === 'PASS') ? 'PASS' : 'BLOCKED');
  return { status, checks, toolVersions };
};

module.exports = {
  SPAWN_MARK_ENV,
  MAX_ARTIFACT_HASH_BYTES,
  createCommandExecutor,
  createDecodedRedactor,
  createStreamingRedactor,
  defaultShellArgs,
  listLivePidsWithCwdUnder,
  listLivePidsWithSpawnMark,
  probeCommandDefault,
  probeGrafanaHealthDefault,
  probeRedisDefault,
  redactSecrets,
  redactStructure,
  resolveCheckTimeout,
  resolveCommandShell,
  runPreflight,
  spawnCaptured,
  snapshotArtifactProof,
  sweepDetachedOrphans,
  terminateProcessTree,
  verifyArtifactProof,
};
