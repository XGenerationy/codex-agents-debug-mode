const { execFile, spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const { constants, createWriteStream } = require('node:fs');
const { access, lstat, mkdir, open, realpath, statfs, writeFile } = require('node:fs/promises');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const path = require('node:path');
const { StringDecoder } = require('node:string_decoder');
const { promisify } = require('node:util');

const { classifyOutput, findStatusSignals } = require('./pr_closeout_core');
const {
  buildChildEnvironment,
  buildSecretReplacements,
  createDecodedRedactor,
  createStreamingRedactor,
  createStreamingReplacer,
  createStreamingSignalScanner,
} = require('./pr_closeout_stream');

const CAPTURE_LIMIT = 2_000_000;
const DEFAULT_TIMEOUT_MS = 20 * 60 * 1000;
const execFileAsync = promisify(execFile);

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

const terminateProcessTree = async ({
  child,
  platform = process.platform,
  env = process.env,
  terminationGraceMs = 2000,
  runExecFile = execFileAsync,
  kill = process.kill.bind(process),
  closePromise,
} = {}) => {
  if (!Number.isInteger(child?.pid) || child.pid <= 0) {
    return { status: 'BLOCKED', evidence: 'Process-tree termination has no valid process identifier.', escalated: false };
  }
  try {
    if (platform === 'win32') {
      // Resolve taskkill.exe from SystemRoot but fall back to the canonical
      // C:\Windows\System32 location if SystemRoot is missing/relative/looks
      // unusual. We never execute a path that was injected via the env: the
      // value must be an absolute drive-letter Windows path that points at
      // an existing directory, otherwise we use the hard-coded default.
      const candidateRoot = String(env.SystemRoot || env.SYSTEMROOT || '').trim();
      const isAbsoluteDrivePath = /^[A-Za-z]:[\\/]/.test(candidateRoot);
      const safeRoot = isAbsoluteDrivePath ? candidateRoot : 'C:\\Windows';
      const taskkill = path.join(safeRoot, 'System32', 'taskkill.exe');
      await runExecFile(taskkill, ['/PID', String(child.pid), '/T', '/F'], {
        encoding: 'utf8',
        timeout: Math.max(terminationGraceMs * 5, 10_000),
        windowsHide: true,
      });
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
        const stat = require('node:fs').readFileSync(`/proc/${pid}/stat`, 'utf8');
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
        entries = require('node:fs').readdirSync('/proc');
      } catch {
        return null;
      }
      const live = [];
      for (const entry of entries) {
        if (!/^\d+$/.test(entry)) continue;
        try {
          const stat = require('node:fs').readFileSync(`/proc/${entry}/stat`, 'utf8');
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
    try {
      kill(-child.pid, 'SIGTERM');
    } catch (error) {
      if (error?.code === 'ESRCH') {
        return { status: 'PASS', evidence: `Process group ${child.pid} had already exited.`, escalated: false };
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
      return { status: 'PASS', evidence: `Process group ${child.pid} stopped after SIGTERM.`, escalated: false };
    }
    try {
      kill(-child.pid, 'SIGKILL');
    } catch (error) {
      // The group may exit between the groupExists() probe above and the
      // SIGKILL call. ESRCH here means the group is already gone, which is a
      // successful termination -- do not let the outer catch convert it into
      // a spurious BLOCKED result.
      if (error?.code === 'ESRCH') {
        return { status: 'PASS', evidence: `Process group ${child.pid} exited before SIGKILL was delivered.`, escalated: true };
      }
      throw error;
    }
    const deadline = Date.now() + terminationGraceMs;
    while (Date.now() < deadline) {
      await awaitRootClose();
      if (!groupExists()) {
        return { status: 'PASS', evidence: `Process group ${child.pid} required SIGKILL and is gone.`, escalated: true };
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

// Variant of redactSecrets that takes a precomputed replacement list so hot
// callers (safeStatusSignal, redactStructure during a single executor run)
// do not rebuild the URL/base64/hex variants on every call. Use
// buildSecretReplacements(env, names) once per executor and pass the result
// here for each call.
const redactSecretsReplacements = (text, replacements) => {
  let redacted = String(text ?? '');
  for (const [value, replacement] of replacements) {
    redacted = redacted.replaceAll(value, replacement);
  }
  return redacted;
};

const redactSecrets = (text, env = process.env, names = []) => (
  redactSecretsReplacements(text, buildSecretReplacements(env, names))
);

const redactStructure = (value, env = process.env, names = [], seen = new WeakSet()) => {
  if (typeof value === 'string') return redactSecrets(value, env, names);
  if (Buffer.isBuffer(value)) return redactSecrets(value.toString('utf8'), env, names);
  if (!value || typeof value !== 'object') return value;
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  if (Array.isArray(value)) return value.map((entry) => redactStructure(entry, env, names, seen));
  if (value instanceof Error) {
    return redactStructure({ name: value.name, message: value.message, stack: value.stack }, env, names, seen);
  }
  if (value instanceof Map) {
    return Object.fromEntries([...value.entries()].map(([key, entry]) => [
      redactSecrets(String(key), env, names),
      redactStructure(entry, env, names, seen),
    ]));
  }
  if (value instanceof Set) return [...value].map((entry) => redactStructure(entry, env, names, seen));
  if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) return value;
  return Object.fromEntries(Object.entries(value)
    .map(([key, entry]) => [
      redactSecrets(key, env, names),
      redactStructure(entry, env, names, seen),
    ]));
};

const cappedAppend = (current, chunk) => {
  if (current.length >= CAPTURE_LIMIT) return current;
  return `${current}${chunk}`.slice(0, CAPTURE_LIMIT);
};

const pathVariants = (value) => {
  if (typeof value !== 'string' || !value.trim()) return [];
  return [...new Set([
    value,
    value.replaceAll('\\', '/'),
    value.replaceAll('/', '\\'),
  ])];
};

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

const normalizePaths = (text, replacements, platform = process.platform) => {
  const replacer = createStreamingReplacer(replacements, { caseInsensitive: platform === 'win32' });
  return replacer.push(String(text ?? '')) + replacer.flush();
};

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
  const log = createWriteStream(logPath, { flags: 'a', encoding: 'utf8' });
  let logError = null;
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
  const child = spawnProcess(shell, shellArgs(command), {
    cwd,
    env,
    detached: platform !== 'win32',
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
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
  let termination = {
    status: 'PASS',
    evidence: 'Command exited before timeout; no process-tree termination was required.',
    escalated: false,
  };
  if (first.kind === 'close') {
    clearTimeout(timer);
  } else {
    timedOut = true;
    termination = await terminateTree({
      child,
      platform,
      env,
      terminationGraceMs,
      closePromise,
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
    log.end(resolve);
    log.once('error', resolve);
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

const isContainedPath = (root, target) => {
  const relative = path.relative(root, target);
  return Boolean(relative) && relative !== '..'
    && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
};

const openArtifact = async (artifact) => {
  const noFollow = constants.O_NOFOLLOW || 0;
  try {
    return await open(artifact, constants.O_RDONLY | noFollow);
  } catch (error) {
    if (!noFollow || !['EINVAL', 'ENOTSUP', 'EOPNOTSUPP'].includes(error?.code)) throw error;
    return open(artifact, constants.O_RDONLY);
  }
};

const hashArtifactDefault = async (artifact) => {
  const handle = await openArtifact(artifact);
  try {
    const before = await handle.stat();
    const hash = createHash('sha256');
    const buffer = Buffer.allocUnsafe(64 * 1024);
    let position = 0;
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, position);
      if (!bytesRead) break;
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

const verifyGrafanaLiveArtifact = async ({ proof, proofResult }) => {
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
    if (proof.grafanaOrigin && endpoint.origin !== new URL(proof.grafanaOrigin).origin) {
      return { status: 'FAIL', evidence: 'Grafana live proof endpoint did not match the configured Grafana origin.' };
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
        // just an empty object/array shape. frames: [{}] or frames: [{ data:
        // { values: [] } }] does not establish a non-empty Grafana result.
        return entry.frames.some((frame) => {
          if (!frame || typeof frame !== 'object') return false;
          const values = frame?.data?.values;
          if (Array.isArray(values)) {
            return values.length > 0 && values.some((series) => Array.isArray(series) ? series.length > 0 : true);
          }
          // Some Grafana responses carry a schema/len pair without inline
          // values; accept only when at least one numeric field is non-empty.
          const numeric = frame?.data?.numeric ?? frame?.schema?.length;
          return Number.isFinite(numeric) && numeric > 0;
        });
      }
      // Legacy single-result shape: require a non-empty values array.
      return Array.isArray(entry?.data?.values) && entry.data.values.length > 0
        && entry.data.values.some((series) => Array.isArray(series) ? series.length > 0 : true);
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

const createCommandExecutor = ({
  repo,
  outputDir,
  env = process.env,
  shell = resolveCommandShell({ env }),
  shellArgs = (command) => ['-lc', command],
  secretNames = [],
  timeoutMs = DEFAULT_TIMEOUT_MS,
  timeoutsMs = {},
  platform = process.platform,
  spawnProcess = spawn,
  terminateTree = terminateProcessTree,
  terminationGraceMs = 2000,
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
  await mkdir(logsDir, { recursive: true });
  const logPath = nextLogPath(phase, check.id);
  const safeCommand = normalizePaths(redactSecrets(check.command, env, secretNames), effectivePathReplacements, platform);
  await writeFile(logPath, `command: ${safeCommand}\ncwd: <repo>\n`, 'utf8');
  const execution = await spawnCaptured({
    command: check.command,
    cwd,
    shell,
    shellArgs,
    timeoutMs: timeoutsMs[check.id] || timeoutMs,
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
    const semantic = await verifyGrafanaLiveArtifact({ proof: check.proof, proofResult });
    return finalize({ ...result, status: semantic.status, evidence: semantic.evidence, proofResult });
  }
  if (check.proof.type === 'command') {
    const proofLogPath = nextLogPath(phase, check.id, 'proof');
    const safeProofCommand = normalizePaths(
      redactSecrets(check.proof.command, env, secretNames),
      effectivePathReplacements,
      platform,
    );
    await writeFile(proofLogPath, `command: ${safeProofCommand}\ncwd: <repo>\n`, 'utf8');
    const proofExecution = await spawnCaptured({
      command: check.proof.command,
      cwd,
      shell,
      shellArgs,
      timeoutMs: timeoutsMs[check.id] || timeoutMs,
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

const probeCommandDefault = async ({ command, repo, shell, env }) => {
  try {
    const result = await execFileAsync(shell, ['-lc', command], {
      cwd: repo,
      env,
      encoding: 'utf8',
      maxBuffer: 2_000_000,
      timeout: 120_000,
      windowsHide: true,
    });
    return { exitCode: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    return {
      exitCode: Number.isInteger(error.code) ? error.code : null,
      stdout: error.stdout || '',
      stderr: error.stderr || error.message,
    };
  }
};

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
  try {
    await probeCommandShell(shell, env);
    checks.push({ name: 'command-shell', status: 'PASS', evidence: shell });
  } catch {
    checks.push({ name: 'command-shell', status: 'BLOCKED', evidence: `Required shell not found: ${shell}` });
  }
  const commandEnv = buildChildEnvironment(env, [...(config.requiredEnv || []), ...(config.safeEnv || [])]);
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
    const evidence = redactSecrets(rawEvidence, env, config.requiredEnv);
    checks.push({ name, status, evidence });
    if (status === 'PASS') toolVersions[name] = evidence;
  }
  for (const name of config.requiredEnv || []) {
    const value = env[name];
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
  createCommandExecutor,
  createDecodedRedactor,
  createStreamingRedactor,
  probeGrafanaHealthDefault,
  probeRedisDefault,
  redactSecrets,
  redactStructure,
  resolveCommandShell,
  runPreflight,
  spawnCaptured,
  snapshotArtifactProof,
  terminateProcessTree,
  verifyArtifactProof,
};
