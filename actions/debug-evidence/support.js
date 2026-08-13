'use strict';

// All logic for actions/debug-evidence lives here; action.yml is wiring only.
// Subcommands: start | run | report | teardown | finish, driven by
// DEBUG_ACTION_* env vars. State travels via action-state.json at the
// OUTPUT-DIR ROOT — deliberately outside the evidence child, because it
// carries the collector launch token and must never be uploaded.

const {
  appendFileSync, closeSync, constants, copyFileSync, fstatSync, lstatSync, mkdirSync,
  openSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync,
} = require('node:fs');
const { spawn, spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const { probeLaunchToken, probeReadyCollector, probeServer } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_server.js'));

const STATE_FILE = 'action-state.json';
const EVIDENCE_SUBDIR = 'debug-evidence-files';
const BOOT_SHIM = path.join(__dirname, 'collector_boot.js');
const REPORT_CLI = path.join(__dirname, '..', '..', 'scripts', 'debug_report.js');
const NAME_PATTERN = /^[A-Za-z0-9_-]+$/;

const resolveEvidenceDir = (outputDir) => path.join(outputDir, EVIDENCE_SUBDIR);

// Same helper contract as actions/closeout: the env-file path is the first
// argument so tests inject a temp file instead of the real GITHUB_OUTPUT.
const writeOutputs = (outputFile, pairs) => {
  const lines = Object.entries(pairs)
    .map(([name, value]) => `${name}=${String(value ?? '').replace(/\r?\n|\r/g, ' ')}`)
    .join('\n');
  appendFileSync(outputFile, `${lines}\n`);
};

const defaultStdoutWrite = (text) => process.stdout.write(text);

// Register a value with the RUNNER's own redactor, so every later log line
// that happens to contain it is replaced with '***' by Actions itself.
//
// This is not belt-and-braces over redactKnownSecrets: that one only cleans
// strings THIS process chooses to print, and the leak Codex reproduced comes
// from a printer we do not control. `NODE_DEBUG=http` anywhere in the job env
// makes Node's own http client dump every request header — `Authorization:
// Bearer <launch token>` included — straight to stderr, before any of our
// code sees it (Codex T4 #1). Only the runner can censor that, and only for
// values it was told about first, which is why both call sites mask BEFORE
// the token is put on the wire.
//
// Gated on the literal 'true' because outside Actions the ::add-mask::
// command is not interpreted by anything: it would just print the secret it
// was meant to hide onto a developer's terminal or into a test's stdout.
const maskValue = (env, value, write = defaultStdoutWrite) => {
  if (env?.GITHUB_ACTIONS !== 'true' || !value) return;
  write(`::add-mask::${value}\n`);
};

const redactKnownSecrets = (text, secrets) => {
  let result = String(text);
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 8) {
      result = result.split(secret).join('[REDACTED]');
    }
  }
  return result;
};

// Is `candidate` the directory `parent` itself, or somewhere under it? The
// relative path escapes only when it IS '..' or starts with '..' + separator;
// a bare `startsWith('..')` test does NOT mean that, because it also matches
// an ordinary child whose name merely begins with two dots — so
// `<workspace>/..cache` read as "outside the workspace" and sailed through
// the containment check it was supposed to fail (Codex T3 #3).
const isInsideDirectory = (parent, candidate) => {
  const relative = path.relative(path.resolve(parent), path.resolve(candidate));
  return relative === ''
    || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
};

const validateActionInputs = ({
  runCommand, sessionName, failOnCommandFailure, port, maxEvents, maxBytes,
  hypothesisId, workingDirectory = '.', outputDir = '', workspace = '',
}) => {
  const errors = [];
  if (!runCommand || !runCommand.trim()) errors.push('run: a command is required');
  if (!NAME_PATTERN.test(sessionName)) errors.push('session-name: must match [A-Za-z0-9_-]+');
  if (failOnCommandFailure !== 'true' && failOnCommandFailure !== 'false') {
    errors.push("fail-on-command-failure: must be 'true' or 'false'");
  }
  const portNumber = Number(port);
  if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
    errors.push('port: must be an integer between 1 and 65535');
  }
  for (const [name, value] of [['max-events', maxEvents], ['max-bytes', maxBytes]]) {
    if (value !== '' && (!/^\d+$/.test(value) || Number(value) < 1)) {
      errors.push(`${name}: must be a positive integer or empty`);
    }
  }
  if (hypothesisId !== '' && !NAME_PATTERN.test(hypothesisId)) {
    errors.push('hypothesis-id: must match [A-Za-z0-9_-]+ or be empty');
  }
  if (/[\r\n]/.test(workingDirectory) || /[\r\n]/.test(outputDir)) {
    errors.push('working-directory/output-dir: must not contain a CR or LF');
  }
  if (workspace && isInsideDirectory(workspace, outputDir)) {
    errors.push('output-dir: must be outside the repository workspace');
  }
  return errors;
};

// The state file carries the collector's LAUNCH TOKEN, so it is written the
// way actions/closeout writes its own private evidence (same discipline,
// deliberately re-stated rather than imported — the two actions stay
// independently deployable): never through a pre-existing link, never with a
// window in which the bytes exist at a wider mode.
//
// 1. lstat the target: an existing symlink or non-regular entry is REFUSED,
//    never followed — a plain writeFileSync would happily write the token
//    through a symlink a local user pre-planted at this well-known path.
// 2. Stage into a temp sibling opened O_WRONLY|O_CREAT|O_EXCL at 0600, so the
//    open either creates a fresh inode or fails closed on anything already
//    there (a hard link included, which no-follow alone would not catch).
// 3. rename() over the target: path-based and atomic, and it REPLACES a
//    destination entry rather than writing through it. Windows cannot always
//    rename over an existing file, so EEXIST/EPERM there falls back to
//    unlink-then-rename; Linux runners always take the atomic path.
//
// The staged bytes are written with writeFileSync — which loops until the
// whole payload lands — rather than a bare writeSync, whose return value is a
// COUNT that a caller must honour: a legal short write (1 of 85 bytes, say)
// silently renamed truncated JSON into place, so `start` reported success
// while readState() returned null forever after and teardown, finding no
// usable pid, orphaned the collector (Codex T3 r2). The staged size is then
// verified against the payload before the commit, so the invariant holds for
// ANY writer, not merely the one this code happens to call today: a committed
// action-state.json always parses to the full state.
const writeState = (outputDir, state, { writeAll = writeFileSync } = {}) => {
  mkdirSync(outputDir, { recursive: true });
  const target = path.join(outputDir, STATE_FILE);
  let existing = null;
  try {
    existing = lstatSync(target);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  if (existing && !existing.isFile()) {
    throw new Error(`refusing to write action state through a non-regular file (symlink, directory, or special): ${target}`);
  }
  const tempPath = path.join(outputDir, `.${STATE_FILE}.${process.pid}.${Date.now()}.tmp`);
  const payload = `${JSON.stringify(state)}\n`;
  const expectedBytes = Buffer.byteLength(payload, 'utf8');
  const fd = openSync(tempPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  let staged = false;
  try {
    writeAll(fd, payload);
    const stagedBytes = fstatSync(fd).size;
    if (stagedBytes !== expectedBytes) {
      throw new Error(`refusing to commit a partially written action state (${stagedBytes} of ${expectedBytes} bytes): ${tempPath}`);
    }
    staged = true;
  } finally {
    // Close before any cleanup: Windows refuses to unlink a file that is
    // still open, which would strand a half-written staging file.
    closeSync(fd);
    if (!staged) {
      try { unlinkSync(tempPath); } catch { /* best-effort cleanup */ }
    }
  }
  try {
    renameSync(tempPath, target);
  } catch (error) {
    if (error?.code !== 'EEXIST' && error?.code !== 'EPERM') {
      try { unlinkSync(tempPath); } catch { /* best-effort cleanup */ }
      throw error;
    }
    try {
      unlinkSync(target);
      renameSync(tempPath, target);
    } catch (retryError) {
      try { unlinkSync(tempPath); } catch { /* best-effort cleanup */ }
      throw retryError;
    }
  }
};

// Lock parameters. The retry budget (~450ms) is deliberately far below the
// staleness threshold: a live holder finishes a state write in microseconds,
// so anything still held after half a second is contention worth failing on
// rather than waiting out, while anything held for THIRTY seconds is not a
// holder at all — it is a crashed invocation's litter.
const LOCK_FILE = 'action-state.lock';
const LOCK_RETRY_LIMIT = 10;
const LOCK_RETRY_DELAY_MS = 50;
const LOCK_STALE_MS = 30_000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A real critical section for the state file, honored by every writer.
//
// writeState alone is not enough. Its rename is atomic, but atomic means the
// file is never torn — not that a decision made by reading it is still valid
// when the write lands. `run` re-read the state, compared nonces, then wrote;
// a second invocation could commit in that gap and the first would rename its
// stale snapshot straight over the top, restoring a dead pid and port over a
// live collector's and orphaning it (Codex T4 r2). Check-then-act cannot be
// fixed by checking harder; the read and the write have to be indivisible,
// which is what holding this lock across BOTH of them buys.
//
// O_CREAT|O_EXCL is the primitive: the open either creates the lock or fails
// EEXIST, with no window between testing and taking it.
const withStateLock = async (outputDir, fn) => {
  mkdirSync(outputDir, { recursive: true });
  const lockPath = path.join(outputDir, LOCK_FILE);
  let fd = null;
  let reaped = false;
  let attempts = 0;
  while (fd === null) {
    try {
      fd = openSync(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
      break;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
    }
    // Someone holds it. Reap it ONCE, and only when it is old enough that no
    // live invocation could still own it — a runner that was cancelled or
    // OOM-killed mid-write leaves this file behind forever, and without a
    // stale sweep every later job on that output-dir would fail to start.
    if (!reaped) {
      let held = null;
      try {
        held = lstatSync(lockPath);
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
      if (held && Date.now() - held.mtimeMs > LOCK_STALE_MS) {
        reaped = true;
        try {
          unlinkSync(lockPath);
        } catch (error) {
          if (error?.code !== 'ENOENT') throw error;
        }
        continue; // retry immediately against the now-free path
      }
    }
    attempts += 1;
    if (attempts >= LOCK_RETRY_LIMIT) {
      throw new Error(`could not acquire the action state lock at ${lockPath} after ${attempts} attempts over ~${attempts * LOCK_RETRY_DELAY_MS}ms`);
    }
    await sleep(LOCK_RETRY_DELAY_MS);
  }
  try {
    return await fn();
  } finally {
    // Close before unlink: Windows refuses to remove a file that is still
    // open, which would leave the lock standing until the stale sweep.
    try { closeSync(fd); } catch { /* best-effort release */ }
    try { unlinkSync(lockPath); } catch { /* a stale sweep may have taken it */ }
  }
};

const readState = (outputDir) => {
  try {
    return JSON.parse(readFileSync(path.join(outputDir, STATE_FILE), 'utf8'));
  } catch {
    return null;
  }
};

const rejectForeignNonce = (state, env, subcommand) => {
  if (env.DEBUG_ACTION_INVOCATION_NONCE && state.nonce !== env.DEBUG_ACTION_INVOCATION_NONCE) {
    process.stderr.write(`debug-evidence-action: ${subcommand}: recorded state does not carry this invocation's nonce (output-dir overwritten by a concurrent run, or never written by this run); refusing to trust it.\n`);
    return true;
  }
  return false;
};

const defaultSpawnShim = (args, { env }) => spawn(process.execPath, [BOOT_SHIM, ...args], {
  env,
  detached: true,
  stdio: ['ignore', 'pipe', 'pipe'],
});

// Read the shim's single startup line (private pipe). Resolves the parsed
// JSON object; rejects on timeout, spawn failure, child exit, or unparsable
// output.
const readShimStartLine = (child, timeoutMs) => new Promise((resolve, reject) => {
  let settled = false;
  let stdout = '';
  let stderr = '';
  const settle = (fn, value) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    fn(value);
  };
  const timer = setTimeout(() => {
    settle(reject, new Error(`collector shim did not report startup within ${timeoutMs}ms`));
  }, timeoutMs);
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
    const newline = stdout.indexOf('\n');
    if (newline === -1) return;
    try {
      settle(resolve, JSON.parse(stdout.slice(0, newline)));
    } catch {
      settle(reject, new Error('collector shim printed an unparsable startup line'));
    }
  });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  // A spawn failure (ENOENT on the node binary, EACCES, fork limits) emits
  // 'error' and NO exit — without this listener it surfaces as an uncaught
  // exception on an EventEmitter instead of this promise's rejection
  // (Codex T3 #6).
  child.on('error', (error) => {
    settle(reject, new Error(`collector shim failed to spawn: ${error?.message ?? error}`));
  });
  // 'close', not 'exit': 'exit' fires as soon as the process is gone, which
  // can precede the final stderr chunk, so the shim's own structured reason
  // ({"status":"error","reason":"port_in_use"}) was routinely lost and
  // replaced by the generic message. 'close' waits for the stdio streams to
  // drain first (Codex T3 #6).
  child.on('close', () => {
    let reason = 'exited before startup';
    try { reason = JSON.parse(stderr.split('\n')[0]).reason ?? reason; } catch {}
    settle(reject, new Error(`collector shim did not report startup: ${reason}`));
  });
});

const startSubcommand = async ({
  inputs, outputDir, env = process.env, projectRoot = process.cwd(),
  spawnShim = defaultSpawnShim, probeReady = probeReadyCollector, kill = process.kill,
  writeStdout = defaultStdoutWrite,
  nonce = randomUUID(), readyTimeoutMs = Number(env.DEBUG_ACTION_READY_TIMEOUT_MS || 15_000),
}) => {
  const workspace = env.GITHUB_WORKSPACE || '';
  const errors = validateActionInputs({ ...inputs, outputDir, workspace });
  if (errors.length > 0) throw new Error(`invalid inputs: ${errors.join('; ')}`);
  // Containment layer 2 (Codex T3 #3): the check above compares the paths as
  // WRITTEN, so an output-dir that merely RESOLVES into the workspace — a
  // symlink pointing back inside the checkout, or a workspace that is itself
  // a link — passes it. Create the directory (it has to exist to be
  // resolved), then compare real paths, before anything is spawned or
  // written. A workspace that does not resolve contains nothing.
  mkdirSync(outputDir, { recursive: true });
  if (workspace) {
    let realWorkspace = null;
    try {
      realWorkspace = realpathSync(workspace);
    } catch { /* no such workspace on disk — nothing to be contained by */ }
    if (realWorkspace !== null && isInsideDirectory(realWorkspace, realpathSync(outputDir))) {
      throw new Error('invalid inputs: output-dir: must be outside the repository workspace (it resolves inside it)');
    }
  }
  if (env.GITHUB_ENV) writeOutputs(env.GITHUB_ENV, { DEBUG_ACTION_INVOCATION_NONCE: nonce });
  const shimEnv = { ...env, DEBUG_PORT: inputs.port };
  if (inputs.maxEvents) shimEnv.DEBUG_ACTION_MAX_EVENTS = inputs.maxEvents;
  if (inputs.maxBytes) shimEnv.DEBUG_ACTION_MAX_BYTES = inputs.maxBytes;
  // Input redact-names EXTENDS (never replaces) any job-level DEBUG_REDACT_NAMES.
  if (inputs.redactNames) {
    shimEnv.DEBUG_REDACT_NAMES = [env.DEBUG_REDACT_NAMES, inputs.redactNames].filter(Boolean).join(',');
  }
  const child = spawnShim([projectRoot], { env: shimEnv });
  let startLine;
  try {
    startLine = await readShimStartLine(child, readyTimeoutMs);
  } catch (error) {
    try { child.kill(); } catch {}
    throw error;
  }
  if (startLine.status !== 'started') {
    throw new Error(`collector failed to start: ${startLine.reason ?? 'unknown'}`);
  }
  // The FIRST thing done with a freshly minted launch token, ahead of the
  // readiness probe and the state write: from here on the runner scrubs it
  // out of anything this job logs, including output nobody here wrote.
  maskValue(env, startLine.launch_token, writeStdout);
  const identity = await probeReady(Number(inputs.port), startLine.project_hash, { deadlineMs: readyTimeoutMs });
  if (!identity || identity.project_hash !== startLine.project_hash || identity.ready !== true) {
    try { kill(startLine.pid); } catch {}
    throw new Error('collector did not become ready before the timeout');
  }
  // Persist BEFORE releasing the pipes, and kill the child if persisting
  // fails (Codex T3 #2). teardown stops the collector by reading its pid out
  // of this file, so a live collector whose state never landed is a collector
  // nothing can stop: it would hold the port and keep writing session logs
  // for the rest of the runner's life.
  try {
    await withStateLock(outputDir, () => writeState(outputDir, {
      nonce,
      pid: startLine.pid,
      port: Number(inputs.port),
      launchToken: startLine.launch_token,
      projectRoot,
      sessionName: inputs.sessionName,
      hypothesisId: inputs.hypothesisId,
      hypothesisTitle: inputs.hypothesisTitle,
      failOnCommandFailure: inputs.failOnCommandFailure,
    }));
  } catch (error) {
    // Covers a failed lock acquisition too, and must: a collector whose state
    // was never recorded is a collector nothing can stop.
    try { kill(startLine.pid); } catch {}
    throw error;
  }
  // RELEASE the pipes, never destroy them (Codex T3 #1): destroying this end
  // leaves the collector writing into a closed pipe for the rest of the job,
  // which is the exact EPIPE the shim's no-op handlers are the backstop for.
  // Dropping the 'data' listeners and resuming leaves the pipe drained and
  // discarded; unref stops it from holding this process open.
  for (const stream of [child.stdout, child.stderr]) {
    stream.removeAllListeners('data');
    stream.resume();
    stream.unref();
  }
  child.unref();
  return 0;
};

const teardownSubcommand = ({ outputDir, env = process.env, kill = process.kill }) => {
  const state = readState(outputDir);
  if (!state) return 0; // start never wrote state — nothing to tear down
  if (rejectForeignNonce(state, env, 'teardown')) return 3;
  if (!Number.isInteger(state.pid) || state.pid < 1) {
    process.stderr.write('debug-evidence-action: teardown: recorded state carries no usable pid.\n');
    return 3;
  }
  try {
    kill(state.pid);
  } catch (error) {
    if (error?.code === 'ESRCH') return 0; // already gone — success, not a leak
    process.stderr.write(`debug-evidence-action: teardown: failed to stop collector pid ${state.pid}: ${error?.code ?? error}\n`);
    return 3;
  }
  return 0;
};

// A collector answer is a status line and a small JSON object; a megabyte is
// already far past anything the contract produces, so treat more as hostile
// rather than buffering it into this process's heap.
const RESPONSE_BYTE_CAP = 1024 * 1024;
// Inactivity timeout: no bytes moved for this long.
const REQUEST_IDLE_TIMEOUT_MS = 5_000;
// Wall-clock ceiling for the WHOLE exchange. The idle timeout alone is not a
// bound: a peer that dribbles one byte every second resets it forever and the
// subcommand hangs for the life of the job (Codex T4 #2).
const REQUEST_DEADLINE_MS = 10_000;

// Minimal JSON-over-loopback helper (node:http; fetch is avoided so tests can
// inject `request` and so no keep-alive agent outlives the subcommand).
//
// Every exit from this promise is guarded by settle(), because the failure
// this replaced was not a wrong answer but NO answer: a peer that declared
// Content-Length: 100, sent ten bytes and hung up produced a response stream
// that emitted neither 'end' nor 'error', so the promise was never settled
// and `run` waited forever holding the whole job (Codex T4 #2, reproduced).
const httpRequestJson = ({
  port, method, path: requestPath, headers = {}, body,
  idleTimeoutMs = REQUEST_IDLE_TIMEOUT_MS, deadlineMs = REQUEST_DEADLINE_MS,
}) => new Promise((resolve, reject) => {
  const payload = body === undefined ? null : JSON.stringify(body);
  let settled = false;
  let deadline;
  const settle = (fn, value) => {
    if (settled) return;
    settled = true;
    clearTimeout(deadline);
    fn(value);
  };
  const request = http.request({
    host: '127.0.0.1',
    port,
    method,
    path: requestPath,
    headers: payload === null ? headers : { ...headers, 'content-type': 'application/json' },
  }, (response) => {
    let text = '';
    let bytes = 0;
    let ended = false;
    // Decode through a StringDecoder rather than concatenating Buffers, so a
    // multi-byte character split across two chunks cannot be mangled.
    response.setEncoding('utf8');
    response.on('data', (chunk) => {
      bytes += Buffer.byteLength(chunk, 'utf8');
      if (bytes > RESPONSE_BYTE_CAP) {
        request.destroy();
        settle(reject, new Error(`collector response exceeded ${RESPONSE_BYTE_CAP} bytes`));
        return;
      }
      text += chunk;
    });
    response.on('end', () => {
      ended = true;
      let json = null;
      try { json = JSON.parse(text); } catch {}
      settle(resolve, { status: response.statusCode, json });
    });
    response.on('aborted', () => settle(reject, new Error('collector aborted the response')));
    response.on('error', (error) => settle(reject, error));
    // 'close' AFTER 'end' is the ordinary finish and settle() already ignores
    // it; 'close' WITHOUT 'end' is the peer hanging up mid-body — the lying
    // Content-Length shape above.
    response.on('close', () => {
      if (!ended) settle(reject, new Error('collector closed the response before it completed'));
    });
  });
  request.on('error', (error) => settle(reject, error));
  request.setTimeout(idleTimeoutMs, () => request.destroy(new Error('collector request timed out')));
  deadline = setTimeout(() => {
    request.destroy();
    settle(reject, new Error(`collector request exceeded ${deadlineMs}ms`));
  }, deadlineMs);
  if (payload !== null) request.write(payload);
  request.end();
});

// stdio: 'inherit' — the wrapped command's output belongs in the step log.
const defaultSpawnCommand = (command, { cwd, env }) => spawnSync('bash', ['-c', command], { cwd, env, stdio: 'inherit' });

const runSubcommand = async ({
  inputs, outputDir, env = process.env,
  request = httpRequestJson, spawnCommand = defaultSpawnCommand,
  probeToken = probeLaunchToken, writeStdout = defaultStdoutWrite,
}) => {
  const state = readState(outputDir);
  if (!state) {
    process.stderr.write('debug-evidence-action: run: no recorded state; the start step never completed.\n');
    return 3;
  }
  if (rejectForeignNonce(state, env, 'run')) return 3;
  // Recorded state proves a collector was ours WHEN START RAN; it proves
  // nothing about who holds the port now. If that collector died and any
  // other local process rebound the port, the very next line would hand a
  // stranger the launch token in an Authorization header — a credential good
  // for minting sessions and posting hypotheses for the rest of the job
  // (Codex T4 #4). probeLaunchToken settles that first and non-mutatingly: it
  // sends a random challenge and verifies the HMAC proof LOCALLY, so a forged
  // listener that cannot compute the proof never receives the token at all.
  if (!(await probeToken(state.port, state.launchToken))) {
    process.stderr.write(`debug-evidence-action: run: collector identity could not be verified on port ${state.port}; refusing to send the launch token.\n`);
    return 3;
  }
  const mint = await request({
    port: state.port,
    method: 'POST',
    path: '/session',
    headers: { Authorization: `Bearer ${state.launchToken}` },
    body: { name: state.sessionName },
  });
  if (mint.status !== 201 || !mint.json?.session_id || !mint.json?.session_token) {
    process.stderr.write(`debug-evidence-action: run: session mint failed (HTTP ${mint.status ?? 'no response'}).\n`);
    return 3;
  }
  const sessionId = mint.json.session_id;
  const sessionToken = mint.json.session_token;
  // Masked before the token is used for anything: the hypothesis post below,
  // the wrapped command's own logging, and Node's http tracing all come after
  // this line.
  maskValue(env, sessionToken, writeStdout);
  if (state.hypothesisId) {
    // POST /hypothesis is a LAUNCH-token capability the wrapped command never
    // holds; the action records intent (OPEN) here and never any verdict —
    // judgment stays with humans/agents (spec amendment, planning round).
    const hypothesis = await request({
      port: state.port,
      method: 'POST',
      path: '/hypothesis',
      headers: { Authorization: `Bearer ${state.launchToken}` },
      body: {
        sessionId,
        hypothesisId: state.hypothesisId,
        status: 'OPEN',
        ...(state.hypothesisTitle ? { title: state.hypothesisTitle } : {}),
      },
    });
    if (hypothesis.status !== 202) {
      process.stderr.write(`debug-evidence-action: run: hypothesis post failed (HTTP ${hypothesis.status ?? 'no response'}).\n`);
      return 3;
    }
  }
  const commandEnv = {
    ...env,
    DEBUG_LOG_URL: `http://127.0.0.1:${state.port}/log`,
    DEBUG_SESSION_ID: sessionId,
    DEBUG_SESSION_TOKEN: sessionToken,
  };
  if (state.hypothesisId) {
    commandEnv.DEBUG_HYPOTHESIS_ID = state.hypothesisId;
  } else {
    // The `...env` spread above would otherwise let a job-level
    // DEBUG_HYPOTHESIS_ID through, and every event the wrapped command logged
    // would be attributed to a hypothesis THIS action never opened — evidence
    // filed under a claim nobody made (Codex T4 #5). Delete rather than set to
    // '', because an empty string is still a present variable.
    delete commandEnv.DEBUG_HYPOTHESIS_ID;
  }
  // Awaited so a seam can be asynchronous; defaultSpawnCommand is spawnSync
  // and resolves immediately.
  const result = await spawnCommand(inputs.runCommand, { cwd: inputs.workingDirectory, env: commandEnv });
  const commandExitCode = result.error ? 127 : (result.status ?? 128);
  // Ownership check and commit as ONE indivisible step. The snapshot in
  // `state` was read before a wrapped command that may have run for an hour,
  // and the write below is a blind whole-file overwrite: if another
  // invocation claimed this output-dir meanwhile, it would restore OUR stale
  // pid/port/token over theirs and strand their live collector. Re-reading
  // first was not enough on its own — between the compare and the rename a
  // second invocation could still commit, and this one would clobber it
  // anyway (Codex T4 #3, then r2). Under the lock the re-read and the write
  // cannot be split, so whoever the compare saw is still who is there.
  const committed = await withStateLock(outputDir, () => {
    const current = readState(outputDir);
    if (!current || current.nonce !== state.nonce) return false;
    writeState(outputDir, {
      ...current,
      sessionId,
      sessionToken,
      commandExitCode,
      commandSignal: result.signal ?? null,
      commandError: result.error ? String(result.error.message) : null,
    });
    return true;
  });
  // Refuse completely: no state write, and no outputs either, since a
  // session-id emitted from state we just declined to own would be a lie.
  if (!committed) {
    process.stderr.write('debug-evidence-action: run: recorded state changed while the wrapped command ran (another invocation now owns this output-dir); refusing to overwrite it.\n');
    return 3;
  }
  if (env.GITHUB_OUTPUT) {
    writeOutputs(env.GITHUB_OUTPUT, { 'command-exit-code': commandExitCode, 'session-id': sessionId });
  }
  return 0; // command failure is finish's decision, never run's
};

// Implemented in later tasks — stable export surface from day one.
const reportSubcommand = async () => { throw new Error('not implemented: reportSubcommand (Task 5)'); };
const finishSubcommand = () => { throw new Error('not implemented: finishSubcommand (Task 5)'); };

const collectStateSecrets = (state) => [state?.launchToken, state?.sessionToken].filter(Boolean);

const main = async () => {
  const [subcommand] = process.argv.slice(2);
  const env = process.env;
  const outputDir = env.DEBUG_ACTION_OUTPUT_DIR
    || path.join(env.RUNNER_TEMP || os.tmpdir(), 'debug-evidence');
  const inputs = {
    runCommand: env.DEBUG_ACTION_RUN || '',
    sessionName: env.DEBUG_ACTION_SESSION_NAME || 'ci-debug',
    workingDirectory: env.DEBUG_ACTION_WORKDIR || '.',
    failOnCommandFailure: env.DEBUG_ACTION_FAIL_ON_COMMAND_FAILURE || 'true',
    port: env.DEBUG_ACTION_PORT || '8787',
    redactNames: env.DEBUG_ACTION_REDACT_NAMES || '',
    maxEvents: env.DEBUG_ACTION_MAX_EVENTS_INPUT || '',
    maxBytes: env.DEBUG_ACTION_MAX_BYTES_INPUT || '',
    hypothesisId: env.DEBUG_ACTION_HYPOTHESIS_ID || '',
    hypothesisTitle: env.DEBUG_ACTION_HYPOTHESIS_TITLE || '',
  };
  try {
    if (subcommand === 'start') {
      process.exitCode = await startSubcommand({ inputs, outputDir, env, projectRoot: env.GITHUB_WORKSPACE || process.cwd() });
    } else if (subcommand === 'run') {
      process.exitCode = await runSubcommand({ inputs, outputDir, env });
    } else if (subcommand === 'report') {
      process.exitCode = await reportSubcommand({ outputDir, env });
    } else if (subcommand === 'teardown') {
      process.exitCode = teardownSubcommand({ outputDir, env });
    } else if (subcommand === 'finish') {
      process.exitCode = finishSubcommand({ outputDir, env });
    } else {
      throw new Error(`Unknown subcommand: ${subcommand ?? '(none)'}. Use start, run, report, teardown, or finish.`);
    }
  } catch (error) {
    const secrets = collectStateSecrets(readState(outputDir));
    process.stderr.write(`debug-evidence-action: ${redactKnownSecrets(error?.message ?? String(error), secrets)}\n`);
    process.exitCode = 1;
  }
};

if (require.main === module) void main();

module.exports = {
  defaultSpawnCommand,
  finishSubcommand,
  httpRequestJson,
  maskValue,
  readShimStartLine,
  readState,
  redactKnownSecrets,
  reportSubcommand,
  resolveEvidenceDir,
  runSubcommand,
  startSubcommand,
  teardownSubcommand,
  validateActionInputs,
  withStateLock,
  writeOutputs,
  writeState,
};
