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
// Shared empty default for callers that omit a sibling-mark registry: no
// mark is "known", so the fail-closed default is to exclude nothing.
const EMPTY_MARK_SET = new Set();

const { classifyOutput, findStatusSignals, STATUS_TERM } = require('./pr_closeout_core');
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
const {
  assertNotSymlink: assertNotSymlinkShared,
  isTrustedSystemRoot,
  looksLikeWindowsRoot,
  openNoFollow: openNoFollowShared,
  protectWindowsPrivateFile,
} = require('./pr_closeout_fs');

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
    // Enable errexit + pipefail so compound forms cannot discard earlier
    // failures: without `-e`, `false; printf done` exits 0 and classifyOutput
    // records PASS; without pipefail, `false | cat` is the same class of
    // silent success (Codex #4781366510 / #4781495663).
    ? ['--noprofile', '--norc', '-c', `set -eo pipefail; ${command}`]
    // Non-bash shells (dash/sh/ksh/zsh): still require pipefail semantics.
    // `set -o pipefail` is accepted by zsh/ksh and bash-as-sh; dash rejects
    // it and the command fails closed rather than PASS-ing a failed left
    // pipeline leg (Codex #4781637950). Errexit remains enabled either way.
    : ['-c', `set -e; set -o pipefail; ${command}`]
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
/**
 * Whether raw `/proc/<pid>/environ` bytes contain a `SPAWN_MARK_ENV=...`
 * entry whose value is a member of `knownMarks`. A process carrying some
 * other check's own spawn mark is not "mark-free" -- it is (or was) tracked
 * by that other check's own primary mark-based sweep -- so
 * listLivePidsWithCwdUnder's mark-free fallback must exclude it rather than
 * attribute it to an unrelated spawn (Codex UfzOf: with the default
 * test-runner parallelism, check B's still-alive descendant can have a PPID
 * chain broken relative to check A, causing A's cwd/fd probe to misattribute
 * B's legitimate, actively-tracked process as A's mark-free orphan and
 * spuriously BLOCK).
 *
 * `knownMarks` must be the closeout run's own registry of marks it actually
 * generated for still-in-flight sibling spawns -- matching ANY self-reported
 * value (the prior behavior) let a hostile detached descendant simply set
 * `SPAWN_MARK_ENV` to an arbitrary string and escape both the primary
 * mark-based reap (its forged mark never matches the spawn hunting it) and
 * this mark-free fallback (Codex UikN4). A mark is a 128-bit random hex
 * string, so forging an actual match against `knownMarks` is infeasible.
 * Omitting `knownMarks` defaults to the empty set -- nothing is "known", so
 * nothing is excluded and every candidate stays fail-closed/flagged.
 * @param {Buffer|string} environBuffer - Raw contents of /proc/<pid>/environ.
 * @param {Set<string>} [knownMarks] - Marks this run generated for
 *   currently-in-flight sibling spawns.
 * @returns {boolean}
 */
const environHasAnySpawnMark = (environBuffer, knownMarks = EMPTY_MARK_SET) => {
  const prefix = `${SPAWN_MARK_ENV}=`;
  const vars = environBuffer.toString('utf8').split('\0');
  return vars.some((entry) => entry.startsWith(prefix) && knownMarks.has(entry.slice(prefix.length)));
};

/**
 * Whether raw `/proc/<pid>/environ` bytes contain a `SPAWN_MARK_ENV=...`
 * entry whose value is NOT a member of `knownMarks` -- an explicit but
 * unrecognized mark, as opposed to no mark at all. This is stronger evidence
 * of tampering or staleness than plain mark-freeness (Codex UrfC6): a
 * candidate that self-reports a mark absent from the registry must never
 * ride listLivePidsWithCwdUnder's PPID-chain-to-runner exemption through --
 * that exemption exists for legitimate siblings that carry no mark at all
 * (or a registered one, already excluded by `environHasAnySpawnMark`), not
 * for processes actively claiming an unverifiable identity.
 * @param {Buffer|string} environBuffer - Raw contents of /proc/<pid>/environ.
 * @param {Set<string>} [knownMarks] - Marks this run generated for
 *   currently-in-flight sibling spawns.
 * @returns {boolean}
 */
const environHasUnregisteredSpawnMark = (environBuffer, knownMarks = EMPTY_MARK_SET) => {
  const prefix = `${SPAWN_MARK_ENV}=`;
  const vars = environBuffer.toString('utf8').split('\0');
  return vars.some((entry) => entry.startsWith(prefix) && !knownMarks.has(entry.slice(prefix.length)));
};

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
 * processes that left the runner's session (a same-session peer is a
 * parallel test worker sharing process.cwd() as the repo and must never be
 * reaped), and either have a cwd under `rootCwd` or — for an orphan that
 * already chdir'd away — hold an open file descriptor that resolves under
 * `rootCwd`, a common precursor to a late absolute-path write.
 *
 * Deliberately NOT exempted: a candidate merely because it started before
 * this spawn's own child (Codex UrfC6). The Windows CommandLine-based
 * classifier treats a confidently-older process as proof of innocence
 * because a path substring match is the only signal it has; this POSIX
 * sweep already has strictly stronger evidence -- resolved `cwd`, the
 * spawn-mark registry, and the PPID chain-to-runner check below -- so a
 * pre-existing process is judged by those, not by its age. An unregistered
 * or forged-mark process already sitting under the repo before the probe
 * started is exactly the untrusted case this sweep exists to catch; a free
 * pass for "older" would reopen that gap.
 *
 * A candidate that is an ANCESTOR of `selfPid` IS excluded unconditionally
 * (Codex Uwnuu/UxMWt), e.g. the Codex app server or code-mode host that
 * launched this runner, possibly in a different session with its own cwd or
 * an open fd under the worktree. This is not the rejected age heuristic
 * above: age/CommandLine matching is an unreliable proxy, whereas process
 * ancestry is a hard structural fact fixed at creation time that no spawned
 * validation command can retroactively forge -- a candidate already on
 * `selfPid`'s own PPID chain cannot simultaneously be a descendant this spawn
 * created, so it is judged by the strongest evidence available, not skipped.
 *
 * When `rootPid` (the spawn's root pid) is given, a candidate whose UNBROKEN
 * PPID chain reaches the runner (`selfPid`) without passing through `rootPid`
 * is excluded: it belongs to the runner's own tree — e.g. a concurrent
 * validation check sharing the repo cwd in its own session — and is not a
 * detached orphan of this spawn. A genuine orphan's chain is broken by
 * construction (it dead-ends at the exited spawn root or below it), so it
 * stays flagged; unknown/unreadable chains stay flagged too (fail-closed).
 * This chain exemption is itself overridden when the candidate self-reports
 * an explicit but UNREGISTERED spawn mark (Codex UrfC6): a process the runner
 * spawned directly (chain reaches `selfPid` at hop zero, indistinguishable
 * from a legitimate sibling's own root spawn by topology alone) that also
 * claims an identity absent from the registry is exactly the untrusted
 * pre-existing-process case this sweep exists to catch, so it stays flagged
 * regardless of the chain result.
 *
 * A candidate carrying ANY check's spawn mark (`environHasAnySpawnMark`) is
 * also excluded, even when its PPID chain to the runner is broken (Codex
 * UfzOf): under the default test-runner parallelism, a sibling check's own
 * live, mark-tracked descendant can have a chain that looks detached relative
 * to THIS spawn's `rootPid`/`selfPid` purely because it descends from a
 * different root. Without this check that sibling's legitimate process gets
 * misattributed as this spawn's mark-free orphan and BLOCKs the sweep
 * spuriously. An unreadable environ is treated as mark-free (fail-closed) and
 * stays subject to the existing chain/cwd checks.
 * @returns {number[]|null} Matching PIDs, or null when /proc is unavailable
 *   (non-Linux).
 */
const listLivePidsWithCwdUnder = (rootCwd, {
  selfPid = process.pid,
  selfSession = null,
  rootPid = 0,
  knownSiblingMarks = EMPTY_MARK_SET,
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
    const cap = 257;
    for (let i = 0; i < fds.length && i < cap; i += 1) {
      const fd = fds[i];
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
    // Reaching the cap without a match is an INCOMPLETE containment proof,
    // not evidence the process holds no repo-rooted descriptor (Codex
    // UzZZv): a mark-stripped orphan holding thousands of unrelated
    // descriptors could place a repository-rooted fd past the scanned
    // prefix and evade detection entirely. Only a scan that covers every
    // descriptor (fds.length <= cap) and finds no match proves the process
    // clean; treat a truncated scan as unproven and keep it flagged,
    // matching this function's fail-closed default everywhere else.
    if (fds.length > cap) return true;
    return false;
  };
  // Walk a candidate's PPID chain (bounded, cycle-safe). Only an UNBROKEN
  // chain that reaches the runner (or one of the runner's own ancestors,
  // e.g. a shared supervisor -- see selfAncestors below) without passing
  // through this spawn's root proves the candidate is a sibling spawned by
  // the runner's own tree (e.g. a concurrent qualification check sharing the
  // repo cwd, or a long-lived supervisor-owned sidecar such as
  // codex-code-mode-host / make_pr.py that shares the repo cwd with this
  // runner -- Codex UzZZc/Uz6AT), never a detached orphan of this spawn —
  // exclude it. Every uncertain outcome (broken or unreadable link, chain
  // through the spawn root, cycle, hop bound, chain leaving the runner's
  // tree) keeps the candidate flagged. This exemption is for a candidate
  // that is mark-free or carries a registered mark only -- the caller must
  // additionally reject an explicit unregistered mark before trusting this
  // result (Codex UrfC6). Reaching an ancestor of selfPid is, like reaching
  // selfPid itself, hard unforgeable /proc topology (a genuinely detached
  // setsid orphan's chain dead-ends at init or the exited spawn root and can
  // never climb back into the runner's own ancestry) -- unlike the
  // deliberately-rejected "started before this spawn" age heuristic
  // (Codex UrfC6) that a forged-mark pre-existing process could exploit
  // for a free pass, this generalization is not a free pass by age but a
  // structural-ancestry proof, so it does not reopen that gap.
  const chainsToRunner = (pid) => {
    if (!Number.isInteger(rootPid) || rootPid <= 0) return false;
    const chainVisited = new Set();
    let current = pid;
    for (let hop = 0; hop < 64 && current > 1; hop += 1) {
      if (chainVisited.has(current)) return false;
      chainVisited.add(current);
      let stat;
      try {
        stat = readFileSync(`/proc/${current}/stat`, 'utf8');
      } catch {
        return false; // broken chain (e.g. dead-ended at the exited spawn root).
      }
      const afterComm = stat.lastIndexOf(')');
      if (afterComm < 0) return false;
      // /proc/pid/stat: after (comm) → state(0) ppid(1).
      const ppid = Number(stat.slice(afterComm + 1).trimStart().split(/\s+/)[1]);
      if (!Number.isInteger(ppid) || ppid <= 0) return false;
      if (ppid === rootPid) return false; // chain through the spawn root — keep flagged.
      if (ppid === selfPid || selfAncestors.has(ppid)) return true; // unbroken chain to the runner or its own ancestry — sibling.
      current = ppid;
    }
    return false;
  };
  // A candidate that is an ANCESTOR of this runner (e.g. the Codex app
  // server, code-mode host, or another long-lived process that launched this
  // spawn, possibly in a different session with its own cwd/fd under the
  // worktree) can never be this spawn's escaped descendant: process ancestry
  // is fixed at creation time and cannot be rewritten after the fact, no
  // matter what a validation command's child does. This is the mirror of
  // chainsToRunner above (which walks a CANDIDATE's ancestry looking for
  // selfPid); here we walk selfPid's own ancestry looking for the candidate.
  // Unlike the deliberately-rejected "started before this spawn" heuristic
  // (Codex UrfC6 — unreliable signals like process age or CommandLine
  // substring matching), ancestry-of-self is hard, unforgeable /proc
  // evidence, so this closes Codex Uwnuu/UxMWt without reopening that gap.
  const selfAncestors = new Set();
  {
    let current = selfPid;
    for (let hop = 0; hop < 64 && current > 1; hop += 1) {
      if (selfAncestors.has(current)) break;
      selfAncestors.add(current);
      let stat;
      try {
        stat = readFileSync(`/proc/${current}/stat`, 'utf8');
      } catch {
        break;
      }
      const afterComm = stat.lastIndexOf(')');
      if (afterComm < 0) break;
      const ppid = Number(stat.slice(afterComm + 1).trimStart().split(/\s+/)[1]);
      if (!Number.isInteger(ppid) || ppid <= 0) break;
      current = ppid;
    }
  }
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue;
    const pid = Number(entry);
    if (pid === selfPid || pid === 1) continue;
    if (selfAncestors.has(pid)) continue; // pre-existing ancestor of the runner — never our orphan.
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
      const afterComm = stat.lastIndexOf(')');
      if (afterComm < 0) continue;
      const fields = stat.slice(afterComm + 1).trimStart().split(/\s+/);
      const state = fields[0];
      if (state === 'Z') continue;
      // /proc/pid/stat: after (comm) → state ppid pgrp session (man proc_pid_stat).
      const session = Number(fields[3]);
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
      const underTree = (cwdLink && underRoot(path.resolve(cwdLink))) || hasOpenFdUnder(pid);
      // A sibling check still running under the runner (unbroken PPID chain
      // to the runner that never passes through this spawn's root) must not
      // be attributed to this spawn as a mark-free detached descendant.
      // Nor must a live process that carries a REGISTERED sibling's spawn
      // mark (its own or a different parallel check's, per knownSiblingMarks
      // -- Codex UikN4: a self-reported mark with no registry match proves
      // nothing) -- this fallback only exists for genuinely mark-free
      // escapees; an unreadable environ (EACCES, exited between readdir and
      // read) is treated as mark-free and stays flagged, matching this
      // function's fail-closed default for every other uncertain outcome.
      //
      // An explicit but UNREGISTERED mark must never ride the chain-to-runner
      // exemption through, even when the chain reaches the runner directly
      // (Codex UrfC6): the chain exemption is meant for a legitimate sibling
      // that is either mark-free or carries a registered mark, not for a
      // process actively self-reporting an identity the registry does not
      // recognize -- that combination (under the repo tree, chains to the
      // runner, but claims an unverifiable mark) is exactly the untrusted
      // pre-existing-process case this sweep exists to catch.
      let carriesSpawnMark = false;
      let hasUnregisteredMark = false;
      try {
        const environBuf = readFileSync(`/proc/${pid}/environ`);
        carriesSpawnMark = environHasAnySpawnMark(environBuf, knownSiblingMarks);
        hasUnregisteredMark = environHasUnregisteredSpawnMark(environBuf, knownSiblingMarks);
      } catch {
        carriesSpawnMark = false;
        hasUnregisteredMark = false;
      }
      if (underTree && !carriesSpawnMark && (hasUnregisteredMark || !chainsToRunner(pid))) {
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
 * as soon as the list is empty, even when SIGKILL was required. The
 * mark-free cwd/fd probe excludes live processes whose unbroken PPID chain
 * reaches the runner without passing through `rootPid` — those are sibling
 * checks spawned by the runner itself (default parallelism 4), not detached
 * descendants of this spawn. Both the spawn-mark and cwd/fd probes require
 * `/proc`; its absence is always treated as an incomplete containment proof
 * and forces BLOCKED regardless of host platform (Codex Ugisk) -- macOS and
 * other non-Linux POSIX hosts never have `/proc`, so silently downgrading to
 * PASS there would let a real setsid orphan keep mutating the repository
 * after the seal, undetected, on every non-Linux run. Windows never reaches
 * either probe: its spawn mark is always empty (setsid/process-groups are a
 * POSIX concept), so `list()` short-circuits to `[]` instead of calling into
 * the `/proc`-based scan.
 * @returns {{status: 'PASS'|'BLOCKED', evidence: string, escalated: boolean}}
 */
const sweepDetachedOrphans = async ({
  mark,
  cwd, // used for mark-free cwd/fd discovery when a child stripped the mark
  minStarttime = 0,
  kill = process.kill.bind(process),
  terminationGraceMs = 2000,
  selfPid = process.pid,
  rootPid = 0,
  knownSiblingMarks = EMPTY_MARK_SET,
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
    // Its absence -- whether Linux with /proc unmounted, or any non-Linux
    // POSIX host, which never has /proc -- is always an incomplete
    // containment proof and must BLOCK; the host being non-Linux is not a
    // reason to accept weaker (process-group-only) evidence as PASS.
    return {
      status: 'BLOCKED',
      evidence: 'Detached orphan sweep unavailable (/proc missing); cannot prove setsid descendants exited.',
      escalated: false,
    };
  }
  // After marked PIDs are gone (initially or post-reap), always run the
  // mark-free cwd/fd probe. Otherwise a descendant that stripped
  // OMO_CLOSEOUT_SPAWN_MARK while a sibling was still marked would be skipped
  // on the first scan and never rechecked after the marked set empties
  // (Codex #4781366510).
  const afterMarkedEmpty = (evidence, escalated) => {
    if (cwd) {
      const unmarked = listLivePidsWithCwdUnder(cwd, { selfPid, minStarttime, rootPid, knownSiblingMarks });
      if (unmarked === null) {
        return {
          status: 'BLOCKED',
          evidence: `${evidence} cwd/fd orphan probe is unavailable (/proc missing); cannot prove mark-free descendants exited.`,
          escalated,
        };
      }
      if (unmarked.length > 0) {
        return {
          status: 'BLOCKED',
          evidence: `Detached mark-free descendant(s) still live under the worktree (pids ${unmarked.slice(0, 8).join(', ')}); cannot safely attribute/terminate without spawn mark.`,
          escalated,
        };
      }
    }
    return {
      status: 'PASS',
      evidence: mark
        ? evidence
        : 'Detached orphan sweep skipped (no spawn mark; refusing cwd-only reaping).',
      escalated,
    };
  };
  if (remaining.length === 0) {
    return afterMarkedEmpty(
      mark
        ? 'No detached spawn-mark descendants remained.'
        : 'Detached orphan sweep skipped (no spawn mark; refusing cwd-only reaping).',
      false,
    );
  }
  for (const pid of remaining) {
    try { kill(pid, 'SIGTERM'); } catch {}
  }
  const softDeadline = Date.now() + Math.min(terminationGraceMs, 500);
  while (Date.now() < softDeadline) {
    remaining = list() || [];
    if (remaining.length === 0) {
      return afterMarkedEmpty('Detached descendants stopped after SIGTERM (spawn-mark sweep).', false);
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
      return afterMarkedEmpty('Detached descendants required SIGKILL and are gone (spawn-mark sweep).', true);
    }
    await delay(25);
  }
  remaining = list() || [];
  if (remaining.length === 0) {
    return afterMarkedEmpty('Detached descendants required SIGKILL and are gone (spawn-mark sweep).', true);
  }
  return {
    status: 'BLOCKED',
    evidence: `Detached descendants still live after SIGTERM/SIGKILL: pids ${remaining.slice(0, 8).join(',')}.`,
    escalated: true,
  };
};

/**
 * Parse the line-per-process snapshot emitted by snapshotWindowsProcessTable
 * (`pid parentPid createdMs commandLine...`). Rows with only the two numeric
 * fields are accepted as well so existing table fixtures stay valid. An
 * unreadable/absent CreationDate becomes createdMs 0 ("unknown age"); such
 * rows are never excluded by the minStartMs filter, keeping the worktree
 * scan fail-closed.
 * @returns {Array<{pid: number, parentPid: number, createdMs: number, commandLine: string}>}
 */
const parseWindowsProcessTable = (stdout) => {
  const rows = [];
  for (const line of String(stdout).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const match = /^(\d+)\s+(\d+)(?:\s+(\d+))?(?:\s+(.*))?$/u.exec(trimmed);
    if (!match) continue;
    const pid = Number(match[1]);
    const parentPid = Number(match[2]);
    if (!Number.isInteger(pid) || !Number.isInteger(parentPid) || pid <= 0) continue;
    rows.push({
      pid,
      parentPid,
      createdMs: match[3] ? Number(match[3]) : 0,
      commandLine: match[4] || '',
    });
  }
  return rows;
};

/**
 * Snapshot Windows PID/PPID/start-time data from PowerShell 7's Get-Process
 * Parent adapter. Do not ask the Win32_Process provider for a full process
 * table: even a property-limited PID/PPID CIM query repeatedly exceeded the
 * 20s budget on windows-latest runners. PowerShell 7 resolves Parent through
 * the native process API, so the clean path has no WMI dependency.
 *
 * When CommandLine attribution is required, query only the candidate PIDs
 * plus processes that appeared after the command started. This preserves the
 * fail-closed young/unknown-age sweep and catches processes born between the
 * two snapshots without paying for every process's PEB. Inputs interpolated
 * into the PowerShell are validated integers only, and the probe receives no
 * ambient environment or CI secrets.
 * @param {{
 *   runExecFile: Function,
 *   powershell: string,
 *   withCommandLine?: boolean,
 *   candidatePids?: number[],
 *   minStartMs?: number,
 *   useNativeParent?: boolean,
 * }} options
 * @returns {Promise<Array<{pid: number, parentPid: number, createdMs: number, commandLine: string}>>}
 */
const snapshotWindowsProcessTable = async ({
  runExecFile,
  powershell,
  withCommandLine = false,
  candidatePids = [],
  minStartMs = 0,
  useNativeParent = false,
}) => {
  const safeCandidatePids = [...new Set(candidatePids)]
    .filter((pid) => Number.isInteger(pid) && pid > 0);
  const safeMinStartMs = Number.isFinite(minStartMs) && minStartMs > 0
    ? Math.floor(minStartMs)
    : 0;
  const scriptLines = [
    '$ErrorActionPreference = "Stop"',
    '$createdByPid = @{}',
    '$livePids = New-Object "System.Collections.Generic.HashSet[int]"',
    'Get-Process | ForEach-Object {',
    '  $createdMs = 0L',
    '  try { $createdMs = [DateTimeOffset]::new($_.StartTime).ToUnixTimeMilliseconds() } catch { }',
    '  $pidValue = [int]$_.Id',
    '  $createdByPid[$pidValue] = $createdMs',
    '  [void]$livePids.Add($pidValue)',
    ...(useNativeParent
      ? [
        '  $parentPid = 0',
        '  try { if ($_.Parent) { $parentPid = [int]$_.Parent.Id } } catch { }',
        '  "{0} {1} {2}" -f $pidValue, $parentPid, $createdMs',
      ]
      : []),
    '}',
  ];
  if (withCommandLine) {
    scriptLines.push(
      `$candidatePids = New-Object "System.Collections.Generic.HashSet[int]"`,
      ...safeCandidatePids.map((pid) => `[void]$candidatePids.Add(${pid})`),
      '$livePids | ForEach-Object {',
      '  $createdMs = [long]$createdByPid[$_]',
      `  if ($createdMs -eq 0 -or $createdMs -ge ${safeMinStartMs}L) { [void]$candidatePids.Add([int]$_) }`,
      '}',
      'if ($candidatePids.Count -gt 0) {',
      '  $where = (($candidatePids | Sort-Object) | ForEach-Object { "ProcessId = $_" }) -join " OR "',
      '  $query = "SELECT ProcessId,ParentProcessId,CommandLine FROM Win32_Process WHERE $where"',
      '  Get-CimInstance -Query $query | ForEach-Object {',
      '    $pidValue = [int]$_.ProcessId',
      '    $createdMs = 0L',
      '    if ($createdByPid.ContainsKey($pidValue)) { $createdMs = [long]$createdByPid[$pidValue] }',
      '    $cl = [string]$_.CommandLine',
      '    if ($cl) { $cl = $cl -replace "[`r`n]+", " " }',
      '    "{0} {1} {2} {3}" -f $pidValue, [int]$_.ParentProcessId, $createdMs, $cl',
      '  }',
      '}',
    );
  } else if (!useNativeParent) {
    scriptLines.push(
      'Get-CimInstance -Query "SELECT ProcessId,ParentProcessId FROM Win32_Process" | ForEach-Object {',
      '  $pidValue = [int]$_.ProcessId',
      '  $createdMs = 0L',
      '  if ($createdByPid.ContainsKey($pidValue)) { $createdMs = [long]$createdByPid[$pidValue] }',
      '  "{0} {1} {2}" -f $pidValue, [int]$_.ParentProcessId, $createdMs',
      '}',
    );
  }
  const script = scriptLines.join('\n');
  const minimalEnv = {
    SystemRoot: process.env.SystemRoot || process.env.SYSTEMROOT || 'C:\\Windows',
    SYSTEMROOT: process.env.SystemRoot || process.env.SYSTEMROOT || 'C:\\Windows',
    PATHEXT: process.env.PATHEXT || '.COM;.EXE;.BAT;.CMD;.VBS;.JS;.WS',
    ComSpec: process.env.ComSpec || process.env.COMSPEC || 'C:\\Windows\\System32\\cmd.exe',
  };
  const { stdout } = await runExecFile(powershell, [
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-Command',
    script,
  ], {
    encoding: 'utf8',
    // Same budget as the heavier of the two previous probes; a single bounded
    // retry at the call site absorbs transient shared-runner load.
    timeout: 20_000,
    windowsHide: true,
    env: minimalEnv,
  });
  return parseWindowsProcessTable(stdout);
};

/**
 * Enumerate live descendant PIDs of `parentPid` from a parsed process-table
 * snapshot via ParentProcessId BFS. Unlike a single `ParentProcessId=root`
 * filter, this finds grandchildren while intermediate parents are still
 * alive. Fully orphaned multi-level trees (every intermediate already
 * exited) are unrecoverable via ParentProcessId alone — the caller covers
 * those with findWindowsPidsWithCommandLineHint over the same snapshot.
 * @param {Array<{pid: number, parentPid: number}>} table
 * @param {number} parentPid
 * @returns {number[]} live descendant PIDs (empty if none).
 */
const listWindowsChildPids = (table, parentPid) => {
  const root = Number(parentPid);
  const childrenByParent = new Map();
  for (const row of table) {
    if (!childrenByParent.has(row.parentPid)) childrenByParent.set(row.parentPid, []);
    childrenByParent.get(row.parentPid).push(row.pid);
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
 * Shared orphan-candidate classification over a parsed process-table
 * snapshot. Catches the multi-level orphans the ParentProcessId BFS cannot
 * reconstruct once intermediate parents have exited (Codex #4781560042).
 * Pure JS over the already-fetched rows: the ancestor-chain exclusion walks
 * the same ParentProcessId data instead of paying one filtered CIM query
 * per hop. Excludes the caller ancestor chain and processes provably
 * started before `minStartMs` so editors, CI agents, and package-manager
 * parents that merely mention the worktree path do not false-BLOCK a clean
 * tree (CodeRabbit #4781622077 semantics, preserved); rows of unknown age
 * are kept (fail-closed).
 *
 * Pre-existing-root exclusion (second Windows CI flake root cause — local
 * full-suite flake evidence + original CI failure analysis): under a full
 * `node --test` run, sibling per-file worker processes carry the repo path
 * in their command lines and start AFTER the checked command's minStartMs,
 * so neither the caller-ancestor exclusion nor the young-match age filter
 * excludes them, and a plain needle match false-BLOCKs a clean tree. The
 * invariant that makes excluding them sound rather than a weakening:
 * Windows never reassigns a process's ParentProcessId, so any real orphan
 * of the validated child has a BROKEN ancestor chain by construction (it
 * dead-ends at the exited child or another absent PID). A match whose
 * UNBROKEN chain reaches a process with confidently-known createdMs <
 * minStartMs chains to a pre-existing root (the `node --test` runner, a CI
 * agent) and cannot be our orphan. Everything unproven stays flagged:
 * chain broken at an absent PID, an ancestor of unknown age (createdMs 0),
 * a cycle, the hop bound, or no time floor at all.
 *
 * The classifier is shared by the orphan-attribution gate in
 * terminateProcessTree: the same exclusions decide whether a cheap
 * CommandLine-free snapshot contains any rows that still need the
 * CommandLine-bearing attribution probe at all.
 * @param {Array<{pid: number, parentPid: number, createdMs: number, commandLine: string}>} table
 * @param {{excludePids?: Set<number>, minStartMs?: number, selfPid?: number}} options
 * @returns {{isOrphanCandidate: (row: object) => boolean}}
 */
const createWindowsOrphanClassifier = (table, {
  excludePids = new Set(),
  minStartMs = 0,
  selfPid = process.pid,
} = {}) => {
  const parentByPid = new Map();
  const rowByPid = new Map();
  for (const row of table) {
    parentByPid.set(row.pid, row.parentPid);
    rowByPid.set(row.pid, row);
  }
  const excluded = new Set(excludePids);
  const visited = new Set();
  let walk = Number.isInteger(selfPid) && selfPid > 0 ? selfPid : 0;
  for (let hop = 0; hop < 64 && walk > 0 && !visited.has(walk); hop += 1) {
    visited.add(walk);
    excluded.add(walk);
    const parent = parentByPid.get(walk);
    walk = Number.isInteger(parent) && parent > 0 ? parent : 0;
  }
  // Walk a row's OWN ancestor chain (cycle-safe, bounded) looking for a
  // process provably older than the spawn. Only a confidently-known
  // createdMs < minStartMs proves the chain predates the spawn; an absent
  // link, an unknown-age link, a cycle, or the hop bound all stop the walk
  // without proof (fail-closed — the caller keeps the row flagged).
  const reachesPreExistingRoot = (startPid) => {
    if (minStartMs <= 0) return false;
    const chainVisited = new Set();
    let current = startPid;
    for (let hop = 0; hop < 64 && current > 0; hop += 1) {
      if (chainVisited.has(current)) return false;
      chainVisited.add(current);
      const row = rowByPid.get(current);
      if (!row) return false; // broken chain at an absent PID — cannot prove.
      if (row.createdMs <= 0) return false; // unknown-age link — cannot prove.
      if (row.createdMs < minStartMs) return true; // provably pre-existing.
      current = row.parentPid;
    }
    return false;
  };
  // A row still needs worktree attribution when it is not excluded, is not
  // provably pre-existing (young or unknown age — fail-closed), and its
  // chain cannot reach a pre-existing root (not a sibling of the runner).
  const isOrphanCandidate = (row) => {
    if (excluded.has(row.pid)) return false;
    // Only confidently-older rows are skipped; unknown age stays (fail-closed).
    if (minStartMs > 0 && row.createdMs > 0 && row.createdMs < minStartMs) return false;
    if (reachesPreExistingRoot(row.pid)) return false;
    return true;
  };
  return { isOrphanCandidate };
};

/**
 * Live PIDs in a parsed snapshot whose CommandLine contains `cwd`
 * (case-insensitive, separators canonicalized to `/` on both sides).
 * Pure JS over the already-fetched snapshot: candidate selection reuses
 * createWindowsOrphanClassifier (see its rationale for the exclusion
 * invariants).
 * @param {Array<{pid: number, parentPid: number, createdMs: number, commandLine: string}>} table
 * @param {string} cwd
 * @param {{excludePids?: Set<number>, minStartMs?: number, selfPid?: number}} options
 * @returns {number[]}
 */
const findWindowsPidsWithCommandLineHint = (table, cwd, options = {}) => {
  // Canonicalize separators on both sides: a descendant that spells the
  // worktree with `/` instead of `\` must not escape the scan.
  const needle = String(cwd || '').trim().toLowerCase().replaceAll('\\', '/');
  if (!needle) return [];
  const { isOrphanCandidate } = createWindowsOrphanClassifier(table, options);
  const found = [];
  for (const row of table) {
    if (!row.commandLine) continue;
    if (!row.commandLine.toLowerCase().replaceAll('\\', '/').includes(needle)) continue;
    if (!isOrphanCandidate(row)) continue;
    found.push(row.pid);
  }
  return [...new Set(found)];
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
 * case falls back to a single full-table snapshot (one property-limited CIM
 * query with one bounded probe-only retry) to independently enumerate and
 * individually taskkill any survivors, cross-checked by a CommandLine
 * worktree scan over the same rows, only concluding PASS once none remain
 * (or none existed); snapshot failure or an unkillable survivor is reported
 * BLOCKED rather than assumed clean. On POSIX, signals the
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
  knownSiblingMarks = EMPTY_MARK_SET,
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
      // isTrustedSystemRoot/looksLikeWindowsRoot are imported from
      // ./pr_closeout_fs (shared with resolvePowerShellExecutable) and always
      // use path.win32 internally, so they parse a backslash-separated root
      // correctly even when this file's generic `path` import resolves to
      // path.posix (test-injected platform: 'win32' on a non-Windows CI
      // host). This call site also needs taskkill.exe verified (it resolves
      // a taskkill path from safeRoot below, not just powershell.exe), so it
      // passes that as an extra required relative path rather than forking
      // its own copy of the trust check.
      const taskkillRelativePath = path.win32.join('System32', 'taskkill.exe');
      const envRoot = String(env.SystemRoot || env.SYSTEMROOT || '').trim();
      const hardcodedRoot = 'C:\\Windows';
      // Prefer hard-coded C:\\Windows whenever it exists and is trusted.
      // On real win32 hosts, never accept a merely Windows-shaped envRoot when
      // the hard-coded install is missing — fall back to C:\\Windows for path
      // construction rather than attacker-controlled SystemRoot.
      // On non-win32 (unit tests with mocked runExecFile), a Windows-shaped
      // envRoot is allowed for path construction only.
      let safeRoot = hardcodedRoot;
      if (isTrustedSystemRoot(hardcodedRoot, existsCheck, [taskkillRelativePath])) {
        safeRoot = hardcodedRoot;
      } else if (platform === 'win32') {
        if (isTrustedSystemRoot(envRoot, existsCheck, [taskkillRelativePath])) {
          safeRoot = envRoot;
        } else {
          safeRoot = hardcodedRoot;
        }
      } else if (looksLikeWindowsRoot(envRoot)) {
        safeRoot = envRoot;
      } else {
        safeRoot = hardcodedRoot;
      }
      const taskkill = path.win32.join(safeRoot, 'System32', 'taskkill.exe');
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
        const windowsPowershell = path.join(safeRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe');
        const pwsh = 'C:\\Program Files\\PowerShell\\7\\pwsh.exe';
        // PowerShell 7 exposes Get-Process.Parent through a native adapter;
        // Windows PowerShell 5 does not. Prefer the fixed, existence-checked
        // pwsh installation path used by hosted Windows runners. If it is not
        // installed, the legacy fallback stays fail-closed.
        const powershell = existsCheck(pwsh) ? pwsh : windowsPowershell;
        const useNativeParent = powershell === pwsh;
        // The cheap CommandLine-free snapshot feeds the ParentProcessId BFS
        // and the orphan-candidate classification below; the expensive
        // CommandLine-bearing table is queried ONLY when the cheap rows
        // still contain young/unknown-age processes that need worktree
        // attribution — on a clean tree that is typically zero rows, so the
        // per-process PEB reads that blew the 20s probe budget on loaded
        // windows-latest CI runners never happen. The full adjacency snapshot
        // itself is native Get-Process.Parent rather than WMI. Each snapshot is read-only
        // and idempotent, so a single bounded retry of the PROBE ONLY —
        // never of taskkill or of the validated command — absorbs transient
        // CIM slowness on shared CI runners; two failed attempts still fail
        // closed to BLOCKED, so the gate is not weakened.
        const snapshotWithRetry = async (options = {}) => {
          let lastError = null;
          for (let attempt = 1; attempt <= 2; attempt += 1) {
            try {
              return await snapshotWindowsProcessTable({
                runExecFile,
                powershell,
                useNativeParent,
                ...options,
              });
            } catch (error) {
              lastError = error;
              if (attempt < 2) await delay(250);
            }
          }
          throw lastError;
        };
        let table;
        let enumerationError = null;
        try {
          table = await snapshotWithRetry();
        } catch (error) {
          enumerationError = error;
        }
        if (!table) {
          return {
            status: 'BLOCKED',
            evidence: `Windows process tree ${child.pid}'s root exited before taskkill /T could target it, and descendant enumeration failed: ${enumerationError?.message || enumerationError}. Cannot prove the tree is clean.`,
            escalated: true,
          };
        }
        const survivors = listWindowsChildPids(table, child.pid);
        if (survivors.length === 0) {
          // ParentProcessId BFS cannot reach multi-level orphans once every
          // intermediate PID is gone (grandchild's parent is dead and absent
          // from the live table). Young or unknown-age rows that survive the
          // orphan-candidate exclusions still need worktree attribution via
          // the CommandLine probe; any hit is fail-closed BLOCKED because we
          // cannot safely attribute kill without spawn-tree identity
          // (Codex #4781560042).
          if (cwd) {
            // minStarttime is wall-clock epoch ms on Windows (set at spawn).
            // Exclude self+child and the ancestor chain so CI agents / npm
            // parents that embed the repo path do not false-BLOCK; matches
            // whose unbroken ancestor chain predates the spawn (sibling
            // `node --test` workers) are excluded the same way.
            const orphanScanOptions = {
              excludePids: new Set([child.pid, process.pid]),
              minStartMs: Number.isFinite(minStarttime) ? minStarttime : 0,
              selfPid: process.pid,
            };
            const { isOrphanCandidate } = createWindowsOrphanClassifier(table, orphanScanOptions);
            const candidates = table.filter(isOrphanCandidate);
            if (candidates.length > 0) {
              let attributed;
              let attributionError = null;
              try {
                const commandLineRows = await snapshotWithRetry({
                  withCommandLine: true,
                  candidatePids: candidates.map((row) => row.pid),
                  minStartMs: orphanScanOptions.minStartMs,
                });
                const commandLineByPid = new Map(
                  commandLineRows.map((row) => [row.pid, row.commandLine]),
                );
                const knownPids = new Set(table.map((row) => row.pid));
                attributed = table.map((row) => ({
                  ...row,
                  commandLine: commandLineByPid.get(row.pid) || '',
                }));
                for (const row of commandLineRows) {
                  if (!knownPids.has(row.pid)) attributed.push(row);
                }
              } catch (error) {
                attributionError = error;
              }
              if (!attributed) {
                return {
                  status: 'BLOCKED',
                  evidence: `Windows process tree ${child.pid}'s root exited before taskkill /T could target it; ParentProcessId BFS found no descendants but ${candidates.length} young or unknown-age process(es) still need worktree attribution and the CommandLine probe failed: ${attributionError?.message || attributionError}. Cannot prove the tree is clean.`,
                  escalated: true,
                };
              }
              const cwdHints = findWindowsPidsWithCommandLineHint(attributed, cwd, orphanScanOptions);
              if (cwdHints.length > 0) {
                return {
                  status: 'BLOCKED',
                  evidence: `Windows process tree ${child.pid}'s root exited before taskkill /T could target it; ParentProcessId BFS found no descendants but CommandLine still references the worktree (pids ${cwdHints.slice(0, 8).join(', ')}). Multi-level orphan ancestry is unproven.`,
                  escalated: true,
                };
              }
              return {
                status: 'PASS',
                evidence: `Windows process tree ${child.pid}'s root already exited and no live descendants were found (ParentProcessId BFS empty; worktree CommandLine probe clean for ${candidates.length} attributed process(es)).`,
                escalated: true,
              };
            }
          }
          return {
            status: 'PASS',
            evidence: `Windows process tree ${child.pid}'s root already exited and no live descendants were found (ParentProcessId BFS empty; no unattributed young processes needed the worktree CommandLine probe).`,
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
        rootPid: child.pid,
        knownSiblingMarks,
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

// Status-term alternation shared with pr_closeout_core.js (imported as
// STATUS_TERM, not re-declared here). Used only by the `test files 0` no-work
// regex below so it does not fire on a bucket count in a richer summary
// (`Test Files 0 failed | 2 passed`). Importing the single source of truth
// keeps this scanner from drifting when a term is added in core (CodeRabbit
// UmlJV).

// Streaming no-work detection (Codex UikNz).
//
// classifyOutput() in pr_closeout_core.js decides "the test runner did no
// work" (Jest "No tests found", unittest "Ran 0 tests", Node TAP "# tests 0",
// Mocha "0 passing", empty TAP "1..0"/"# pass 0", Go/Rust empty packages)
// from the *capped* combined stdout/stderr -- only the first CAPTURE_LIMIT
// bytes cappedAppend() retained. A runner that streams more than
// CAPTURE_LIMIT of output before its terminal no-work summary pushes that
// summary past the head cap, so classifyOutput never sees it and the check is
// misreported PASS. The scanners below run on the *raw, uncapped* stream (fed
// the same chunks as the status scanner) so a late no-work summary is still
// caught, then thread a signal into result.detectedSignals -- which
// classifyOutput already honors: any non-empty detectedSignals entry that is
// not a warn/error/block keyword still short-circuits away from PASS via its
// `if (signals.length) return FAIL` fallthrough, so no pr_closeout_core.js
// change is required. The combined-string checks in classifyOutput are left
// intact (they still power the hasAuthoritativeTestEvidence override for
// mixed Go/Rust runs within the head cap); this is a second, independent
// detection path, not a replacement.

// Unconditional no-work: classifyOutput FAILs on these regardless of any
// other evidence in the stream, so they are always safe to latch and emit.
const STREAM_NO_WORK_UNCONDITIONAL = [
  { label: 'no tests found/executed', re: /\bno\s+tests?\s+(?:found|executed|ran|were run|to run)\b/i },
  { label: 'no test files found', re: /\bno\s+test\s+files?\s+found\b/i },
  { label: 'ran 0 tests', re: /\bran\s+0\s+tests?\b/i },
  { label: '0 tests run', re: /\b0\s+tests?\s+(?:run|ran|executed)\b/i },
  { label: '# tests 0', re: /^[ \t]*#\s*tests?\s+0\b/im },
  { label: 'tests 0 passed', re: /\btests?\s+0\s+passed\b/i },
  { label: 'test files 0', re: new RegExp(`\\btest\\s+files?\\s+0(?!\\s+${STATUS_TERM}\\b)`, 'i') },
  { label: '0 passing', re: /(?:^|\n)\s*0\s+passing\b/i },
];

// Conditional no-work: package-level empty markers (Go/Rust workspaces) and an
// empty TAP plan. classifyOutput only FAILs these when NO authoritative test
// evidence appears elsewhere, so they are latched but emitted only when the
// stream carried no authoritative evidence (see STREAM_AUTHORITATIVE and the
// harvest in spawnCaptured), mirroring its mixed-run guard exactly.
const STREAM_NO_WORK_CONDITIONAL = [
  { label: 'no test files (package)', re: /\[no test files\]/i },
  { label: 'no tests to run', re: /\bno tests to run\b/i },
  { label: 'running 0 tests', re: /\brunning\s+0\s+tests?\b/i },
  { label: 'empty TAP plan (1..0)', re: /^[ \t]*1\.\.0\b/m },
  { label: '# pass 0', re: /^[ \t]*#\s*pass\s+0\b/im },
];

// Authoritative test evidence, mirrored from classifyOutput's
// hasAuthoritativeTestEvidence. Seeing any of these anywhere in the stream
// suppresses the conditional markers above (mixed Go/Rust workspace runs that
// have real tests alongside empty packages).
const STREAM_AUTHORITATIVE = [
  /\bok\t\S+/,
  /test result:\s*ok\.\s*[1-9]\d*\s+passed/i,
  /\btests?\s+[1-9]\d*\s+passed\b/i,
  /^[ \t]*#\s*tests?\s+[1-9]/im,
  /(?:^|\n)\s*[1-9]\d*\s+passing\b/i,
];

/**
 * Per-stream no-work scanner backing (Codex UikNz). Latches authoritative
 * evidence and conditional markers into `state` as a side effect and yields
 * the unconditional no-work labels for createStreamingSignalScanner to
 * collect and dedup. Called with one complete line at a time (or a
 * force-drained window for a pathologically long line).
 * @param {{authoritative: boolean, conditional: Set<string>}} state
 * @returns {(line: string) => string[]}
 */
const scanNoWorkSignals = (state) => (line) => {
  const text = String(line ?? '');
  for (const re of STREAM_AUTHORITATIVE) {
    if (re.test(text)) { state.authoritative = true; break; }
  }
  for (const { label, re } of STREAM_NO_WORK_CONDITIONAL) {
    if (re.test(text)) state.conditional.add(label);
  }
  const found = [];
  for (const { label, re } of STREAM_NO_WORK_UNCONDITIONAL) {
    if (re.test(text)) found.push(`no-work: ${label}`);
  }
  return found;
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
 * True when `value` is an entire filesystem root (POSIX `/`, a bare `\`, or a
 * drive spelling like `C:`, `C:\`, `C:/`) rather than a directory under one.
 * Redacting a root would add it as a needle matching every path separator
 * (or every path on that drive) in captured evidence instead of scoping to
 * an actual directory — e.g. a container or service account where
 * `HOME=/` (CodeRabbit review).
 * @param {string} value
 * @returns {boolean}
 */
const isFilesystemRoot = (value) => value === '/' || value === '\\' || /^[A-Za-z]:[\\/]?$/.test(value);

/**
 * Expand a path to every spelling that may appear in evidence: the given
 * form, and — when resolvable — its physical realpath. Symlinked worktrees
 * otherwise leave the real directory unredacted when tools print `pwd`.
 * Filesystem roots are excluded (see isFilesystemRoot) since they would
 * over-match instead of identifying a specific directory to redact.
 * @param {string} value
 * @returns {string[]}
 */
const pathRootsForRedaction = (value) => {
  if (typeof value !== 'string' || !value.trim()) return [];
  const roots = [value, path.resolve(value)];
  try {
    const { realpathSync } = require('node:fs');
    roots.push(realpathSync(value));
  } catch {
    // Path may not exist yet (output dir); keep resolve-only spellings.
  }
  return [...new Set(roots.filter((root) => root && !isFilesystemRoot(root)))];
};

/**
 * Builds the ordered [needle, placeholder] pairs used to normalize `cwd`,
 * `outputDir`, and the caller's home directory (HOME / USERPROFILE /
 * HOMEDRIVE+HOMEPATH) out of captured evidence, replacing each with
 * `<repo>`, `<output>`, or `<home>` respectively. Each path is expanded to
 * its pathVariants() so either separator style is caught, and realpath is
 * included so a symlinked `--repo` still redacts the physical target.
 * @returns {Array<[string, string]>}
 */
const buildPathReplacements = ({ cwd, outputDir, env = process.env } = {}) => {
  const entries = [
    ...pathRootsForRedaction(cwd).flatMap((root) => pathVariants(root).map((value) => [value, '<repo>'])),
    ...pathRootsForRedaction(outputDir).flatMap((root) => pathVariants(root).map((value) => [value, '<output>'])),
  ];
  for (const home of [env.USERPROFILE, env.HOME, env.HOMEDRIVE && env.HOMEPATH
    ? `${env.HOMEDRIVE}${env.HOMEPATH}`
    : null]) {
    entries.push(...pathRootsForRedaction(home).flatMap((root) => pathVariants(root).map((value) => [value, '<home>'])));
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

// Linux only: /proc/self/fd/<fd>/<name> is a kernel-maintained magic symlink
// that always resolves relative to whatever directory the fd currently
// refers to, so opening a child through it is equivalent to a true
// openat(dirfd, name) even if the `logs` name itself is renamed or replaced
// with a symlink afterward. No other platform exposes an equivalent public
// primitive (Codex UrfDG).
const canBindLogParentByFd = (platform) => platform === 'linux';

// Open `target` bound to the logs-directory identity ensureLogsDirSecured()
// validated, closing (not just narrowing) the residual TOCTOU window
// documented on assertLogParentIdentity below. Opens the parent directory
// itself no-follow and fstats it against `expected` before ever touching the
// child, then opens the child through that fd-bound /proc path so a later
// rename/symlink swap of `logs` cannot redirect where the child lands.
// Throws assertLogParentIdentity's own "swapped after validation" message on
// an identity mismatch, and a distinct "symlinked logs directory" message
// when the parent itself is already a symlink, so both stay recognizable to
// callers already matching those strings. ENOENT from the /proc child open
// is tagged `.procUnavailable = true` so openLogNoFollow can fall back to the
// plain path-based open when /proc is not mounted, rather than failing
// closed on an unrelated environment gap.
const openLogBoundToParent = async (target, expected, flags, mode) => {
  const parent = path.dirname(target);
  const base = path.basename(target);
  let dirHandle;
  try {
    dirHandle = await open(parent, constants.O_DIRECTORY | constants.O_NOFOLLOW);
  } catch (error) {
    // Linux reports ENOTDIR (not ELOOP) here: O_NOFOLLOW stops the kernel
    // from resolving the symlink, so O_DIRECTORY's "must be a directory"
    // check applies to the unresolved link itself (S_IFLNK), not its target.
    if (error?.code === 'ELOOP' || error?.code === 'ENOTDIR') {
      throw new Error(`Refusing to write evidence log through a symlinked logs directory: ${parent}`);
    }
    throw error;
  }
  try {
    const info = await dirHandle.stat();
    if (!expected || expected.ino === 0 || info.dev !== expected.dev || info.ino !== expected.ino) {
      throw new Error(`Refusing to write evidence log through a logs directory swapped after validation: ${parent}`);
    }
    try {
      // Without O_NOFOLLOW here, a leaf symlink swapped in for `base` after
      // assertLogNotSymlink's check (but before this open) would be silently
      // followed even though the parent-directory identity is verified --
      // the fd bind above only protects against a *directory* swap, not a
      // same-directory leaf-name swap (Codex #4781366510 follow-up).
      return await open(`/proc/self/fd/${dirHandle.fd}/${base}`, flags | (constants.O_NOFOLLOW || 0), mode);
    } catch (error) {
      if (error?.code === 'ENOENT') error.procUnavailable = true;
      throw error;
    }
  } finally {
    await dirHandle.close().catch(() => undefined);
  }
};

// Open a raw evidence log path without following a symlinked final component.
// Mode 0600 at create time; fchmod after open so a permissive umask cannot
// leave evidence world-readable under a shared temp directory. Verifies the
// descriptor is a regular, single-link file before either permission call
// below: chmod/protectWindowsPrivateFile mutate the target's underlying
// identity (POSIX: every name sharing its inode; Windows: the path
// re-resolved by protectWindowsPrivateFile), so a pre-planted hard link must
// be rejected before those calls run, not only before content is written --
// otherwise the outside file's permissions are silently tightened even
// though the write itself is later refused (Codex UiXEj).
const openLogNoFollow = async (
  target,
  flags,
  verb = 'write',
  securedDirIdentity = null,
  platform = process.platform,
) => {
  await assertLogNotSymlink(target);
  try {
    let handle;
    if (securedDirIdentity && canBindLogParentByFd(platform)) {
      try {
        handle = await openLogBoundToParent(target, securedDirIdentity, flags, 0o600);
      } catch (error) {
        if (!error?.procUnavailable) throw error;
        handle = await openNoFollowShared(target, flags, 0o600);
      }
    } else {
      handle = await openNoFollowShared(target, flags, 0o600);
    }
    try {
      const info = await handle.stat();
      if (!info.isFile()) {
        throw new Error(`Refusing to ${verb} evidence log that is not a regular file: ${target}`);
      }
      if (info.nlink !== 1) {
        throw new Error(`Refusing to ${verb} evidence log with hard links (nlink=${info.nlink}): ${target}`);
      }
    } catch (error) {
      await handle.close().catch(() => undefined);
      throw error;
    }
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
    if (process.platform === 'win32') {
      // chmod(0600) above is a no-op against Windows' inherited DACL, so
      // another local user with inherited access to a shared checkout could
      // read this evidence log. Establish a protected, current-user-only ACL
      // before any evidence bytes are written (mirrors the debug collector's
      // own token/session-log/port hardening in debug_server.js).
      const preProtectInfo = await handle.stat();
      try {
        protectWindowsPrivateFile(target);
      } catch {
        await handle.close().catch(() => undefined);
        throw new Error(`Failed to protect evidence log with an owner-only ACL: ${target}`);
      }
      // protectWindowsPrivateFile re-resolves the path by name in a separate
      // PowerShell process; if the path was swapped between the open above
      // and that call returning, the ACL could land on a different
      // filesystem object than this handle. Only dev/ino identity is checked
      // here -- nlink was already verified to be exactly 1 immediately after
      // opening, before this call or the chmod above ever ran, so a hard
      // link cannot reach this point. A zero ino is rejected outright: some
      // Windows filesystems report dev/ino as 0 for every file, which would
      // otherwise compare equal vacuously.
      let postProtectInfo;
      try {
        postProtectInfo = await lstat(target);
      } catch {
        await handle.close().catch(() => undefined);
        throw new Error(`Refusing to write evidence log with an unverifiable identity: ${target}`);
      }
      if (
        preProtectInfo.ino === 0
        || postProtectInfo.dev !== preProtectInfo.dev
        || postProtectInfo.ino !== preProtectInfo.ino
      ) {
        await handle.close().catch(() => undefined);
        throw new Error(
          `Refusing to write evidence log through a path swapped during ACL protection: ${target}`,
        );
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
 * Confirm the just-opened evidence log still resolves inside the directory
 * identity that ensureLogsDirSecured() validated. openLogNoFollow's O_NOFOLLOW
 * only guards the FINAL path component, not the parent `logs` directory, so a
 * concurrent check (or the command under test, if it has write access to
 * outputDir) that swaps outputDir/logs for a symlink after
 * ensureLogsDirSecured() ran but before this open could still land the
 * descriptor inside an attacker directory (CodeRabbit UguCb).
 *
 * On Linux, openLogNoFollow binds the open itself to the validated directory
 * fd (openLogBoundToParent) whenever a securedDirIdentity is supplied,
 * closing this window instead of merely narrowing it. This check stays the
 * sole guard on every other platform, and the Linux path falls back to it
 * too whenever /proc is unavailable or no securedDirIdentity was supplied, so
 * it remains unconditional at both call sites below.
 *
 * Residual limitation (non-Linux, or whenever the fd bind above falls back):
 * Node's fs/promises exposes no openat/dir-fd primitive, so the parent cannot
 * be opened and fstat'd atomically with the file. We re-lstat the parent PATH
 * (no-follow, so a symlinked `logs` is caught outright) and compare dev/ino
 * against the captured identity. This narrows the TOCTOU window from "before
 * the open" to "between this lstat and the open" rather than closing it
 * fully; a swap-back to a real directory within that residual window is not
 * detectable without a true dir-fd bind. A zero ino is rejected outright:
 * some Windows filesystems report ino 0 for every file, which would
 * otherwise compare equal vacuously.
 * @param {string} target log file path whose parent directory must match.
 * @param {{dev: number, ino: number}} expected captured logsDir identity.
 */
const assertLogParentIdentity = async (target, expected) => {
  const parent = path.dirname(target);
  let info;
  try {
    info = await lstat(parent);
  } catch {
    throw new Error(`Refusing to write evidence log with an unverifiable parent directory: ${parent}`);
  }
  if (
    !expected
    || expected.ino === 0
    || info.dev !== expected.dev
    || info.ino !== expected.ino
  ) {
    throw new Error(`Refusing to write evidence log through a logs directory swapped after validation: ${parent}`);
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
 * @param {{dev: number, ino: number}|null} [securedDirIdentity] identity of the
 *   logs directory captured by ensureLogsDirSecured(); when provided, the open
 *   is bound to it and a mismatch is rejected before any truncate/write.
 * @param {string} [platform] injectable for tests; real callers always pass
 *   process.platform so the Linux fd-bind (see openLogBoundToParent) only
 *   ever engages on an actual Linux host.
 * @returns {Promise<{dev: number, ino: number}>} identity of the written
 *   header file, so the caller can bind a later append reopen of the same path
 *   to the exact file this header landed on (CodeRabbit UmlJX / Codex UnKZ4).
 */
const writeLogHeaderNoFollow = async (
  target,
  contents,
  securedDirIdentity = null,
  platform = process.platform,
) => {
  // O_CREAT without O_TRUNC: create if missing, never truncate until fstat.
  const handle = await openLogNoFollow(
    target,
    constants.O_WRONLY | constants.O_CREAT,
    'write',
    securedDirIdentity,
    platform,
  );
  try {
    // Bind the open to the directory ensureLogsDirSecured() just validated,
    // before any bytes are written (throw, do not truncate, on mismatch).
    if (securedDirIdentity) await assertLogParentIdentity(target, securedDirIdentity);
    await handle.truncate(0);
    await handle.writeFile(contents, 'utf8');
    // Capture the verified file's dev/ino (openLogNoFollow already proved it a
    // regular, single-link file) so the append reopen can confirm it lands on
    // this same inode, not a replacement swapped in afterwards.
    const info = await handle.stat();
    return { dev: info.dev, ino: info.ino };
  } finally {
    await handle.close();
  }
};

/**
 * Open an evidence log for streaming append, no-follow. Opens the
 * descriptor directly (rather than letting createWriteStream open the path
 * itself, which would follow a symlink) and hands the resulting FileHandle
 * to createWriteStream via its `fd` option so the stream still owns normal
 * close/error semantics. Like the header writer, the opened descriptor is
 * revalidated before use: a pre-existing hard link — or a swap between the
 * header write and this open — must fail softly (the caller's logWriteError
 * path) rather than append command evidence to an outside file.
 *
 * openLogNoFollow's O_NOFOLLOW only guards the FINAL path component, so a
 * `logs` swap or a file swap landing between the header write and this open
 * could otherwise redirect every captured byte into a substituted directory
 * or file while the report still names the original evidence path. When the
 * caller threads the identities captured at header time, the append is bound
 * to BOTH the validated logs directory (parent dev/ino) and the exact header
 * file (dev/ino): either mismatch throws before the stream is returned, so
 * the reopen cannot silently follow a redirect (CodeRabbit UmlJX / Codex
 * UnKZ4). Both are optional so direct/unit-test callers keep working unbound.
 * @param {string} target
 * @param {{dev: number, ino: number}|null} [securedDirIdentity] validated logs
 *   directory identity; when provided, a swapped parent is rejected.
 * @param {{dev: number, ino: number}|null} [securedFileIdentity] identity of
 *   the header file; when provided, a swapped leaf is rejected.
 * @param {string} [platform] injectable for tests; real callers always pass
 *   process.platform so the Linux fd-bind (see openLogBoundToParent) only
 *   ever engages on an actual Linux host.
 * @returns {Promise<import('node:fs').WriteStream>}
 */
const createLogAppendStreamNoFollow = async (
  target,
  securedDirIdentity = null,
  securedFileIdentity = null,
  platform = process.platform,
) => {
  const handle = await openLogNoFollow(
    target,
    constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND,
    'append',
    securedDirIdentity,
    platform,
  );
  try {
    // Bind the reopen to the validated parent directory and the header file's
    // own identity before any command output is streamed to it.
    if (securedDirIdentity) await assertLogParentIdentity(target, securedDirIdentity);
    if (securedFileIdentity) {
      const info = await handle.stat();
      // Only compare identity when BOTH the recorded and observed inode are
      // non-zero: some Windows volumes and network mounts report ino: 0 for
      // every file, which would otherwise make this comparison reject every
      // append on those hosts as a "swap" even with no swap at all. When the
      // platform cannot supply a real inode, skip the bind here and rely on
      // O_NOFOLLOW plus the parent-directory identity check above instead
      // (CodeRabbit UohnP).
      if (
        securedFileIdentity.ino !== 0
        && info.ino !== 0
        && (info.dev !== securedFileIdentity.dev || info.ino !== securedFileIdentity.ino)
      ) {
        throw new Error(
          `Refusing to append evidence to a log file swapped after its header write: ${target}`,
        );
      }
    }
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw error;
  }
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
  // Registry of marks this closeout run has generated for still-in-flight
  // sibling spawns (shared across a run's parallel checks; see
  // createCommandExecutor). Optional so direct/unit-test callers keep
  // working with the safe empty-registry default.
  knownSiblingMarks,
  // Identities captured when the log header was written, threaded through so
  // the append reopen below can be bound to the validated logs directory and
  // the exact header file (CodeRabbit UmlJX / Codex UnKZ4). Optional so
  // direct/unit-test callers keep working unbound.
  securedDirIdentity = null,
  securedFileIdentity = null,
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
    log = await createLogAppendStreamNoFollow(logPath, securedDirIdentity, securedFileIdentity, platform);
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
  const makeState = () => {
    // Side-channel state for the no-work detector: an authoritative-evidence
    // latch and the set of conditional markers seen, resolved against each
    // other across both streams at harvest time (see below).
    const noWork = { authoritative: false, conditional: new Set() };
    return {
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
      noWork,
      // Second streaming scanner (Codex UikNz): catches a no-work summary that
      // lands beyond CAPTURE_LIMIT, where classifyOutput's capped combined
      // string can no longer see it. Fed the same raw chunks as `scanner`.
      noWorkScanner: createStreamingSignalScanner(scanNoWorkSignals(noWork)),
      hash: createHash('sha256'),
      // Codex UrfC1: whether the next byte emitNormalized() receives for this
      // stream starts a fresh logical line. A push()/flush() call boundary
      // does not imply a line boundary -- the normalizer can return a chunk's
      // first character alone and the rest on the very next call -- so this
      // must be tracked across calls rather than assumed true every time.
      atLineStart: true,
    };
  };
  const states = { stdout: makeState(), stderr: makeState() };
  // Unique mark inherited by every descendant of this spawn. terminateProcessTree
  // uses it to re-find processes that leave the process group (setsid /
  // detached:true) after the original group appears empty.
  const spawnMark = platform === 'win32' ? '' : randomBytes(16).toString('hex');
  const spawnEnv = spawnMark
    ? { ...env, [SPAWN_MARK_ENV]: spawnMark }
    : env;
  // Register this mark as belonging to a genuine, currently-in-flight spawn
  // for the run's whole duration so a concurrent sibling's orphan sweep can
  // recognize it (Codex UikN4); unregistered below once this spawn's own
  // termination/sweep is settled.
  if (spawnMark) knownSiblingMarks?.add(spawnMark);
  try {
    // Capture approximate starttime for orphan filters:
    // - POSIX: /proc starttime jiffies (exact after spawn when available)
    // - Windows: wall-clock epoch ms for CommandLine CreationDate filtering
    //   so pre-existing editors/CI agents are not treated as orphans.
    let minStarttime = platform === 'win32' ? Date.now() : 0;
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
      // Codex UrfC1: `normalized` is one streaming-replacer output chunk, and
      // a push()/flush() call boundary is not necessarily a line boundary --
      // the replacer can hold back a possible partial match and return the
      // rest of the same logical line on a later call. Labeling every call
      // unconditionally spliced `[stream] ` into the middle of persisted
      // bytes (observed as `u[stdout] navailable-ino-evidence`). Only prefix
      // the label at a real line start: the first bytes written for this
      // stream, and immediately after each newline already inside
      // `normalized` -- except a trailing newline, which starts a line that
      // has not arrived yet and is deferred to the next call via
      // `atLineStart`.
      const label = `[${stream}] `;
      const withLabel = (states[stream].atLineStart ? label : '')
        + normalized.replace(/\n(?!$)/g, `\n${label}`);
      states[stream].atLineStart = normalized.endsWith('\n');
      writeLog(withLabel, child[stream]);
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
      states[stream].noWorkScanner.push(raw);
      emitSafe(stream, states[stream].redactor.push(chunk));
    };
    const flush = (stream) => {
      // Drain the decoder's trailing bytes once and feed both raw scanners so a
      // no-work summary that arrives without a trailing newline is still seen.
      const tail = states[stream].signalDecoder.end();
      states[stream].scanner.push(tail);
      states[stream].scanner.flush();
      states[stream].noWorkScanner.push(tail);
      states[stream].noWorkScanner.flush();
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
          knownSiblingMarks,
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
        knownSiblingMarks,
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
    // Resolve the streaming no-work detectors (Codex UikNz). Unconditional
    // markers were already collected by each noWorkScanner. Conditional markers
    // (Go/Rust empty packages, empty TAP plan) mirror classifyOutput's mixed-run
    // guard: emit them only when NO authoritative test evidence (ok\t.., "N
    // passed", "N passing") appeared in EITHER stream, matching how
    // classifyOutput computes hasAuthoritativeTestEvidence over the combined
    // output.
    const sawAuthoritativeTests = states.stdout.noWork.authoritative || states.stderr.noWork.authoritative;
    const conditionalNoWork = sawAuthoritativeTests
      ? []
      : [...new Set([...states.stdout.noWork.conditional, ...states.stderr.noWork.conditional])]
        .slice(0, 20)
        .map((label) => `no-work: ${label}`);
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
        ...states.stdout.noWorkScanner.values(),
        ...states.stderr.noWorkScanner.values(),
        ...conditionalNoWork,
      ],
      logWriteError: logError ? logError.message : null,
    };
    return result;
  } finally {
    // Settled either way (PASS, BLOCKED, or a throw): stop advertising the
    // mark to concurrent siblings' orphan sweeps now that it no longer
    // identifies an actively-tracked spawn (CodeRabbit UmlJY).
    if (spawnMark) knownSiblingMarks?.delete(spawnMark);
  }
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
  // Use the shared openNoFollow attempt sequence (NOFOLLOW+NONBLOCK →
  // NONBLOCK-only → NOFOLLOW-only → plain) so a platform that rejects only
  // O_NONBLOCK still keeps O_NOFOLLOW, and vice versa (Codex #4781366510).
  // The previous two-step fallback dropped NOFOLLOW whenever the combined
  // open failed, which broke ordinary proof artifacts on NONBLOCK-hostile FS.
  const handle = await openNoFollowShared(artifact, constants.O_RDONLY);
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
const readBoundArtifactJson = async (proofResult, { openArtifactFn = openArtifact } = {}) => {
  if (!proofResult?.realPath || !Number.isFinite(proofResult.size) || proofResult.size > 1_000_000) {
    return { status: 'FAIL', evidence: 'Semantic artifact proof must be a verified JSON file no larger than 1 MiB.' };
  }
  const handle = await openArtifactFn(proofResult.realPath);
  try {
    const before = await handle.stat();
    if (before.dev !== proofResult.dev || before.ino !== proofResult.ino || before.size !== proofResult.size) {
      return { status: 'FAIL', evidence: 'Semantic artifact identity changed after artifact verification.' };
    }
    // Read exactly the verified size at fixed positions instead of
    // handle.readFile(), which reads to whatever EOF exists at read time: a
    // writer that keeps appending after the stat above would otherwise let
    // this allocate far past the documented 1 MiB bound (or stall) before the
    // dev/ino/size/mtimeMs/digest comparison below ever gets a chance to
    // reject the mutation.
    const size = proofResult.size;
    const content = Buffer.alloc(size);
    let offset = 0;
    while (offset < size) {
      const { bytesRead } = await handle.read(content, offset, size - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    if (offset !== size) {
      return { status: 'FAIL', evidence: 'Semantic artifact was truncated while it was being verified.' };
    }
    // A concurrent writer could still have appended past the verified size;
    // confirm no extra byte exists there before trusting the bounded read.
    const probe = Buffer.alloc(1);
    const { bytesRead: extraBytesRead } = await handle.read(probe, 0, 1, size);
    if (extraBytesRead > 0) {
      return { status: 'FAIL', evidence: 'Semantic artifact changed while it was being verified.' };
    }
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
  // Marks this run has generated for still-in-flight checks (added when a
  // spawn starts, removed once its own termination/sweep is settled). Shared
  // across every check dispatched through this executor's `execute` so a
  // parallel sibling's orphan sweep can recognize a genuinely-tracked mark
  // instead of trusting any self-reported value (Codex UikN4).
  const activeSpawnMarks = new Set();
  const pathReplacements = buildPathReplacements({ cwd: repo, outputDir, env });
  const childEnv = buildChildEnvironment(env, secretNames);
  const logsDir = path.join(outputDir, 'logs');
  const nextLogPath = (phase, id, kind = '') => {
    const safePhase = String(phase).replace(/[^a-z0-9_-]/gi, '-');
    const safeId = String(id).replace(/[^a-z0-9_-]/gi, '-');
    const key = `${safePhase}.${safeId}${kind ? `.${kind}` : ''}`;
    const attempt = (attempts.get(key) || 0) + 1;
    attempts.set(key, attempt);
    return path.join(logsDir, `${key}.attempt-${String(attempt).padStart(3, '0')}.log`);
  };
  // Re-run before every path-based log open in a single check, not just
  // once at the top: a check's main command can run for up to its full
  // configured timeout between the header write for `logPath` and the one
  // for `proofLogPath`, and a concurrently running check (or the command
  // under test, if it has write access to outputDir) could replace
  // outputDir/logs with a symlink in that window. openLogNoFollow only
  // guards the final log-file component, not this parent directory, so a
  // stale one-time check here would let a later open silently follow the
  // substituted logs directory (CodeRabbit UguCb).
  // Identity (dev/ino) of the logs directory captured at the end of the most
  // recent ensureLogsDirSecured() call, so each path-based log open can be
  // bound to the directory that was just validated (CodeRabbit UguCb). Null
  // until the first successful validation, or if the post-validation stat
  // fails (in which case the open still fails closed on its own guards).
  let securedLogsDirIdentity = null;
  const ensureLogsDirSecured = async () => {
    await mkdir(logsDir, { recursive: true, mode: 0o700 });
    // mkdir recursive accepts a pre-existing symlink named `logs`. Fail
    // closed before any evidence open: only a real directory under
    // outputDir is OK.
    await assertNotSymlinkShared(
      logsDir,
      `Refusing to write evidence logs through a symlinked logs directory: ${logsDir}`,
    );
    const realLogs = await realpath(logsDir);
    const realOut = await realpath(outputDir);
    const rel = path.relative(realOut, realLogs);
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
      throw new Error(
        `Refusing to write evidence logs outside the output directory: ${logsDir}`,
      );
    }
    try {
      await chmod(logsDir, 0o700);
    } catch {
      // Platform may ignore directory modes.
    }
    // Capture the just-validated directory's identity for the bind above.
    // logsDir is confirmed non-symlink here, so lstat gives the real
    // directory's dev/ino (the same object path.dirname(logPath) resolves to
    // at write time).
    try {
      const info = await lstat(logsDir);
      securedLogsDirIdentity = { dev: info.dev, ino: info.ino };
    } catch {
      securedLogsDirIdentity = null;
    }
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
  await ensureLogsDirSecured();
  const logPath = nextLogPath(phase, check.id);
  const safeCommand = normalizePaths(redactSecrets(check.command, env, secretNames), effectivePathReplacements, platform);
  const logFileIdentity = await writeLogHeaderNoFollow(logPath, `command: ${safeCommand}\ncwd: <repo>\n`, securedLogsDirIdentity, platform);
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
    knownSiblingMarks: activeSpawnMarks,
    // Bind the append stream to the same directory/file the header write just
    // validated, so a swap between them cannot redirect captured evidence.
    securedDirIdentity: securedLogsDirIdentity,
    securedFileIdentity: logFileIdentity,
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
    // The main command above can run for up to its full timeout between
    // ensureLogsDirSecured()'s first call and this proof-command log open;
    // revalidate immediately before this second path-based write rather
    // than trusting the earlier check for the whole check() lifetime.
    await ensureLogsDirSecured();
    const proofLogPath = nextLogPath(phase, check.id, 'proof');
    const safeProofCommand = normalizePaths(
      redactSecrets(check.proof.command, env, secretNames),
      effectivePathReplacements,
      platform,
    );
    const proofLogFileIdentity = await writeLogHeaderNoFollow(proofLogPath, `command: ${safeProofCommand}\ncwd: <repo>\n`, securedLogsDirIdentity, platform);
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
      knownSiblingMarks: activeSpawnMarks,
      // Bind the proof append stream to the just-validated proof log identity.
      securedDirIdentity: securedLogsDirIdentity,
      securedFileIdentity: proofLogFileIdentity,
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
  let deadline;
  const done = (value) => {
    if (settled) return;
    settled = true;
    clearTimeout(deadline);
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
  // A request timeout is reset by every received byte. Bound the total health
  // probe as well, so a peer cannot keep preflight waiting indefinitely by
  // trickling a small response without ever ending it (M6UJi6O).
  deadline = setTimeout(() => {
    request.destroy();
    done({ healthy: false, evidence: 'Grafana health request exceeded its wall-clock deadline.' });
  }, timeoutMs);
  deadline.unref();
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
 * `{exitCode, stdout, stderr, terminationStatus, terminationEvidence}` shape
 * so every probe result can be handled uniformly by the caller. A successful
 * exit with BLOCKED process-tree cleanup is still returned so preflight can
 * refuse admission (matching the main command executor).
 * @returns {Promise<{exitCode: number|null, stdout: string, stderr: string, terminationStatus?: 'PASS'|'BLOCKED', terminationEvidence?: string}>}
 */
// Codex Uonld (P1): runPreflight calls this once per TOOL_PROBES entry,
// sequentially, against the same repo cwd -- but until this fix the function
// never accepted a knownSiblingMarks registry at all, unlike the validation
// executor's activeSpawnMarks (createCommandExecutor, below). A probe whose
// command spawns a slow-to-exit helper (docker/docker-compose/docker-daemon
// commonly do) could leave a live, mark-carrying descendant that the NEXT
// probe's own orphan sweep had no way to recognize as "a known sibling",
// misattributing it as a mark-free foreign descendant and forcing a spurious
// BLOCKED on an otherwise-clean tool probe. Separately verified empirically
// (see the two probeCommandDefault sibling-mark tests below) that
// `node --test --test-concurrency=1` does not wait for a detached
// grandchild to die before the next test/file proceeds, so this class of
// leftover is real, not hypothetical, within a single `npm test` invocation.
// probeCommandDefaultInner does the actual work; the thin wrapper below owns
// mark generation/registration in a try/finally so a synchronous throw from
// an injected spawnProcess mock still cannot leak the mark forever (mirrors
// the CodeRabbit UmlJY fix already applied to spawnCaptured).
const probeCommandDefaultInner = async ({
  command,
  repo,
  shell,
  env,
  platform,
  spawnProcess,
  terminateTree,
  timeoutMs,
  terminationGraceMs,
  spawnMark,
  knownSiblingMarks,
}) => {
  const spawnEnv = spawnMark ? { ...env, [SPAWN_MARK_ENV]: spawnMark } : env;
  // Windows: wall-clock ms for CommandLine CreationDate filter; POSIX: jiffies.
  let minStarttime = platform === 'win32' ? Date.now() : 0;
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
  // Full-stream signal scanners (Codex UnKZ9): `cap` above discards everything
  // past CAPTURE_LIMIT, so a probe that streams more than that before a
  // warning/failure/skip signal (then exits 0) would push the signal past the
  // cap where classifyOutput can no longer see it and mark the required tool
  // probe PASS. Scan every raw chunk here -- bounding only the persisted text --
  // and thread the matches into detectedSignals, mirroring spawnCaptured's own
  // raw scanner so classifyOutput still refuses to PASS.
  const signalScanners = {
    stdout: createStreamingSignalScanner(findStatusSignals),
    stderr: createStreamingSignalScanner(findStatusSignals),
  };
  const signalDecoders = {
    stdout: new StringDecoder('utf8'),
    stderr: new StringDecoder('utf8'),
  };
  const scanChunk = (stream, chunk) => {
    signalScanners[stream].push(
      Buffer.isBuffer(chunk) ? signalDecoders[stream].write(chunk) : String(chunk ?? ''),
    );
  };
  child.stdout?.on('data', (chunk) => { stdout = cap(stdout, chunk); scanChunk('stdout', chunk); });
  child.stderr?.on('data', (chunk) => { stderr = cap(stderr, chunk); scanChunk('stderr', chunk); });

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

  // Store the timeout handle so a clean exit does not leave an unref'd timer
  // that keeps the Node process alive until timeoutMs (runPreflight runs many
  // probes; leaked timers stacked to ~2 minutes of hang after PASS).
  let timer;
  const timeoutPromise = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ kind: 'timeout' }), timeoutMs);
  });
  const first = await Promise.race([
    closePromise.then((outcome) => ({ kind: 'close', outcome })),
    timeoutPromise,
  ]);
  if (first.kind === 'close') clearTimeout(timer);

  let outcome = first.outcome;
  let termination = { status: 'PASS', evidence: 'No process group was created.', escalated: false };
  if (first.kind === 'close') {
    if (!outcome?.spawnError) {
      termination = await terminateTree({
        child,
        platform,
        env,
        terminationGraceMs,
        closePromise,
        spawnMark,
        cwd: repo,
        minStarttime,
        knownSiblingMarks,
      });
    }
  } else {
    termination = await terminateTree({
      child,
      platform,
      env,
      terminationGraceMs,
      closePromise,
      spawnMark,
      cwd: repo,
      minStarttime,
      knownSiblingMarks,
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
    if (!outcome && termination.status !== 'BLOCKED') {
      termination = {
        status: 'BLOCKED',
        evidence: `${termination.evidence || 'Process-tree termination incomplete.'} The root process did not close after bounded termination.`,
        escalated: true,
      };
    }
  }

  const terminationFields = {
    terminationStatus: termination.status === 'BLOCKED' ? 'BLOCKED' : 'PASS',
    terminationEvidence: termination.evidence || '',
  };
  // Drain each decoder's trailing bytes and flush the scanner so a signal on a
  // final line without a trailing newline is still recorded, then dedup across
  // both streams. classifyOutput() honors this list even when the capped
  // stdout/stderr no longer carry the signal (Codex UnKZ9).
  const detectedSignals = [];
  for (const stream of ['stdout', 'stderr']) {
    signalScanners[stream].push(signalDecoders[stream].end());
    signalScanners[stream].flush();
    detectedSignals.push(...signalScanners[stream].values());
  }

  if (outcome?.spawnError) {
    return {
      exitCode: null,
      stdout,
      stderr: outcome.spawnError.message || String(outcome.spawnError),
      ...terminationFields,
      detectedSignals,
    };
  }
  if (!outcome) {
    return {
      exitCode: null,
      stdout,
      stderr: stderr || 'probe timed out',
      ...terminationFields,
      detectedSignals,
    };
  }
  return {
    exitCode: Number.isInteger(outcome.exitCode) ? outcome.exitCode : null,
    stdout,
    stderr,
    ...terminationFields,
    detectedSignals,
  };
};

/**
 * Public entry point wrapping {@link probeCommandDefaultInner}. Generates and
 * registers this probe's spawn mark (Codex Uonld: into `knownSiblingMarks`
 * when the caller shares one across sequential probes, e.g. runPreflight's
 * `activeSpawnMarks`) before doing any work, and always unregisters it in
 * `finally` -- including when `spawnProcess` throws synchronously -- so the
 * mark never leaks into the shared registry past this probe's own lifetime.
 * @returns {Promise<{exitCode: number|null, stdout: string, stderr: string, terminationStatus?: 'PASS'|'BLOCKED', terminationEvidence?: string}>}
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
  knownSiblingMarks,
}) => {
  // Never mutate a caller-omitted registry: EMPTY_MARK_SET is a single
  // module-scoped instance shared by every default-valued caller, so adding
  // this probe's own mark to it would leak across concurrent probes that
  // also omitted knownSiblingMarks (Codex UrL5U). Allocate a fresh registry
  // when none was supplied instead of defaulting the parameter itself.
  const marks = knownSiblingMarks ?? new Set();
  const spawnMark = platform === 'win32' ? '' : randomBytes(16).toString('hex');
  if (spawnMark) marks.add(spawnMark);
  try {
    return await probeCommandDefaultInner({
      command,
      repo,
      shell,
      env,
      platform,
      spawnProcess,
      terminateTree,
      timeoutMs,
      terminationGraceMs,
      spawnMark,
      knownSiblingMarks: marks,
    });
  } finally {
    if (spawnMark) marks.delete(spawnMark);
  }
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
  // Codex Uonld (P1): shared across every sequential TOOL_PROBES call below so
  // one probe's still-in-flight spawn mark is recognized by the NEXT probe's
  // own orphan sweep instead of being misattributed as a mark-free foreign
  // descendant -- mirrors createCommandExecutor's activeSpawnMarks, which
  // already closed this same gap for validation checks.
  const activeSpawnMarks = new Set();
  const runProbe = probeCommand || ((command) => probeCommandDefault({
    command,
    repo,
    shell,
    env: commandEnv,
    knownSiblingMarks: activeSpawnMarks,
  }));
  for (const [name, command] of TOOL_PROBES) {
    // A probe that rejects (spawn throws synchronously under resource
    // exhaustion, or an infrastructure error) must not escape this loop and
    // abort runCloseoutWorkflow -- that would emit only the top-level error and
    // skip the structured evidence report. Convert a rejected probe into a
    // redacted per-tool BLOCKED row so the workflow completes and reports it
    // like any other failing preflight check (Codex U3w6p).
    let result;
    try {
      result = await runProbe(command);
    } catch (error) {
      checks.push({
        name,
        status: 'BLOCKED',
        evidence: redactShellEvidence(`Tool probe failed to run: ${error?.message || error}`),
      });
      continue;
    }
    // Process-tree cleanup failure is admission-blocking even when the probe
    // itself exited 0: a surviving descendant can mutate the worktree after
    // the seal, same as the main command executor.
    if (result.terminationStatus === 'BLOCKED') {
      const evidence = redactSecrets(
        result.terminationEvidence
          || 'Preflight process-tree cleanup could not prove descendants exited.',
        env,
        sensitiveEnvNames,
      );
      checks.push({ name, status: 'BLOCKED', evidence });
      continue;
    }
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
  environHasAnySpawnMark,
  environHasUnregisteredSpawnMark,
  listLivePidsWithCwdUnder,
  listLivePidsWithSpawnMark,
  probeCommandDefault,
  probeGrafanaHealthDefault,
  probeRedisDefault,
  readBoundArtifactJson,
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
  writeLogHeaderNoFollow,
};
