'use strict';

// All logic for actions/debug-evidence lives here; action.yml is wiring only.
// Subcommands: start | run | report | teardown | finish, driven by
// DEBUG_ACTION_* env vars. State travels via action-state.json at the
// OUTPUT-DIR ROOT — deliberately outside the evidence child, because it
// carries this run's session token and must never be uploaded.

const {
  appendFileSync, closeSync, constants, fstatSync, lstatSync, mkdirSync,
  openSync, readFileSync, realpathSync, renameSync, unlinkSync, writeFileSync,
} = require('node:fs');
const { spawn, spawnSync } = require('node:child_process');
const {
  createHash, createPublicKey, randomBytes, randomUUID, verify,
} = require('node:crypto');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const { canonicalResponderRecord, probeLaunchToken, probeReadyCollector } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_server.js'));
const { parseSessionText, readSessionLive } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_evidence.js'));
const { buildReport, renderJson, renderMarkdown } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_report.js'));

const STATE_FILE = 'action-state.json';
const EVIDENCE_SUBDIR = 'debug-evidence-files';
const BOOT_SHIM = path.join(__dirname, 'collector_boot.js');
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

// The state file carries this run's SESSION TOKEN, so it is written the
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

// The lock's current bytes, or null when it is gone. Never throws for the
// ordinary "someone deleted it" case, because both callers race deletion by
// construction.
const readLockToken = (lockPath) => {
  try {
    return readFileSync(lockPath, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw error;
  }
};

// Take the WHOLE staleness observation from one descriptor: the timestamp the
// verdict is computed from and the bytes that verdict will be checked against
// must describe the same file.
//
// Statting the path and then reading the path are two independent lookups. A
// replacement landing between them yields a verdict assembled from the OLD
// file's mtime and the NEW file's content — evidence that never coexisted, and
// a wider race than the final check-to-unlink window (Codex T4 r4). One open
// pins one inode and both facts come off it.
//
// O_RDONLY follows symlinks where the lstat it replaces did not, which is
// harmless here: a lock can never be CREATED through a link, because
// O_CREAT|O_EXCL fails outright on one, and the unlink below removes the link
// itself rather than anything it points at. (O_NOFOLLOW is not portable to
// Windows, so it is not an option.)
const observeLock = (lockPath) => {
  let fd;
  try {
    fd = openSync(lockPath, constants.O_RDONLY);
  } catch (error) {
    if (error?.code === 'ENOENT') return null; // released while we looked
    throw error;
  }
  try {
    return { mtimeMs: fstatSync(fd).mtimeMs, content: readFileSync(fd, 'utf8') };
  } finally {
    closeSync(fd);
  }
};

// Create the lock and stamp it with WHO holds it. Returns the open fd, or
// null when someone else already holds the path.
//
// The ownership stamp is what makes an unlink decidable: without it every
// deleter is blind, and "remove the lock file" cannot distinguish the lock it
// created from a successor's that merely lives at the same path.
const tryAcquireLock = (lockPath, ownership) => {
  let fd;
  try {
    fd = openSync(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
  } catch (error) {
    if (error?.code === 'EEXIST') return null;
    throw error;
  }
  // Full-write discipline, same as writeState (T3 r2): a lock whose ownership
  // bytes landed short would match NOBODY, so its own holder could not
  // release it and every later invocation would have to wait out the whole
  // staleness threshold to make progress.
  try {
    writeFileSync(fd, ownership);
    const staged = fstatSync(fd).size;
    const expected = Buffer.byteLength(ownership, 'utf8');
    if (staged !== expected) {
      throw new Error(`refusing to hold a partially stamped lock (${staged} of ${expected} bytes): ${lockPath}`);
    }
  } catch (error) {
    closeSync(fd);
    try { unlinkSync(lockPath); } catch { /* best-effort cleanup */ }
    throw error;
  }
  return fd;
};

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
const withStateLock = async (outputDir, fn, { onStaleObserved = null } = {}) => {
  mkdirSync(outputDir, { recursive: true });
  const lockPath = path.join(outputDir, LOCK_FILE);
  // Unique per acquisition, not per process: one process may take this lock
  // several times, and a recycled pid must never be able to impersonate an
  // earlier holder.
  const ownership = `${process.pid}\n${randomUUID()}\n`;
  let fd = null;
  let reaped = false;
  let attempts = 0;
  while (fd === null) {
    fd = tryAcquireLock(lockPath, ownership);
    if (fd !== null) break;
    // Someone holds it. Reap it ONCE, and only when it is old enough that no
    // live invocation could still own it — a runner that was cancelled or
    // OOM-killed mid-write leaves this file behind forever, and without a
    // stale sweep every later job on that output-dir would fail to start.
    if (!reaped) {
      const observation = observeLock(lockPath);
      if (observation && Date.now() - observation.mtimeMs > LOCK_STALE_MS) {
        reaped = true;
        // The EXACT bytes staleness was judged against, off the same inode as
        // the timestamp. Everything below is about not deleting anything else.
        const observed = observation.content;
        if (onStaleObserved) await onStaleObserved({ lockPath, observed });
        // Two reapers can both find the same stale lock. One wins the
        // O_EXCL re-create; if the loser then unlinks blindly it deletes the
        // WINNER's fresh lock and a third writer walks in — the clobber this
        // whole round exists to close (Codex T4 r3). Re-read immediately
        // before deleting: if the path no longer holds the bytes we judged,
        // it belongs to someone live now, so leave it and keep retrying.
        if (readLockToken(lockPath) === observed) {
          try {
            unlinkSync(lockPath);
          } catch (error) {
            if (error?.code !== 'ENOENT') throw error;
          }
        }
        continue; // retry against the path, freed or not
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
    // Close before touching the path: Windows refuses to remove a file that
    // is still open.
    try { closeSync(fd); } catch { /* best-effort release */ }
    try {
      // Ownership-verified release. A holder that ran long enough to be
      // judged stale no longer owns this path — a reaper deleted its lock and
      // a successor created their own. Unlinking on the way out would evict
      // that live successor, which is the same clobber by a different route,
      // so release only what is still demonstrably ours (Codex T4 r3).
      if (readLockToken(lockPath) === ownership) unlinkSync(lockPath);
    } catch { /* best-effort release */ }
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

// start owns the LAUNCH TOKEN's entire lifecycle, and it ends here.
//
// The token is the collector's operator credential: it mints sessions and,
// crucially, it is the only thing that can POST a hypothesis line. Persisting
// it in action-state.json put that capability on disk for the rest of the
// job, where the wrapped command — same OS user, derivable path — could pick
// it up and forge a verdict the evidence contract then had to detect after
// the fact (Codex T5 r3). So the token is used and dropped inside this one
// process: handshake, mask, prove the port occupant holds it, mint the
// session, open the hypothesis, and write state carrying only the SESSION
// token. After start returns, no credential capable of writing a verdict
// exists anywhere in the job — the hypothesis-set contract stops being a
// detection and becomes a structural fact.
const startSubcommand = async ({
  inputs, outputDir, env = process.env, projectRoot = process.cwd(),
  spawnShim = defaultSpawnShim, probeReady = probeReadyCollector, kill = process.kill,
  request = httpRequestJson, probeToken = probeLaunchToken,
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
  // From here on the collector is RUNNING and outlives this process, so every
  // failure has to take it down first: nothing has recorded its pid yet, and
  // a collector nothing can stop holds the port and writes session logs for
  // the rest of the runner's life.
  const abort = (message) => {
    try { kill(startLine.pid); } catch {}
    return new Error(message);
  };
  // The PUBLIC verification key. Deliberately not masked: it is public by
  // design, and masking it would only litter later logs with '***' where a
  // harmless value belongs. What matters is where it travels, not who sees
  // it — see the step-output write below.
  if (typeof startLine.verify_key !== 'string' || startLine.verify_key === '') {
    // Without it, `report` can never prove who served a log, and would fail
    // every capture. Better to stop here, while the collector can still be
    // killed cleanly, than to run a whole job that cannot produce evidence.
    throw abort('collector did not report a verification key; capture could never be verified');
  }
  const port = Number(inputs.port);
  const identity = await probeReady(port, startLine.project_hash, { deadlineMs: readyTimeoutMs });
  if (!identity || identity.project_hash !== startLine.project_hash || identity.ready !== true) {
    throw abort('collector did not become ready before the timeout');
  }
  // Prove the port occupant actually holds the token before handing it over.
  // The shim reported a pid and a token, but between that report and this
  // line the collector could have died and any local process could have taken
  // the port; the very next request puts the launch token in an Authorization
  // header (Codex T4 #4). probeLaunchToken settles it non-mutatingly — a
  // random challenge whose HMAC proof is verified locally, so a listener that
  // cannot compute it never receives the token.
  if (!(await probeToken(port, startLine.launch_token))) {
    throw abort(`collector identity could not be verified on port ${port}; refusing to send the launch token`);
  }
  const mint = await request({
    port,
    method: 'POST',
    path: '/session',
    headers: { Authorization: `Bearer ${startLine.launch_token}` },
    body: { name: inputs.sessionName },
  });
  if (mint.status !== 201 || !mint.json?.session_id || !mint.json?.session_token) {
    throw abort(`session mint failed (HTTP ${mint.status ?? 'no response'})`);
  }
  const sessionId = mint.json.session_id;
  const sessionToken = mint.json.session_token;
  // Masked before the token is used for anything else, and before it is
  // written anywhere.
  maskValue(env, sessionToken, writeStdout);
  if (inputs.hypothesisId) {
    // The ONLY hypothesis line this action will ever post, and the last thing
    // the launch token is used for. It records intent (OPEN) and never a
    // verdict — judgment stays with humans and agents (spec amendment,
    // planning round). Because the token dies with this process, this is also
    // the only hypothesis line that CAN exist in the session.
    const hypothesis = await request({
      port,
      method: 'POST',
      path: '/hypothesis',
      headers: { Authorization: `Bearer ${startLine.launch_token}` },
      body: {
        sessionId,
        hypothesisId: inputs.hypothesisId,
        status: 'OPEN',
        ...(inputs.hypothesisTitle ? { title: inputs.hypothesisTitle } : {}),
      },
    });
    if (hypothesis.status !== 202) {
      throw abort(`hypothesis post failed (HTTP ${hypothesis.status ?? 'no response'})`);
    }
  }
  // Persist BEFORE releasing the pipes, and kill the child if persisting
  // fails (Codex T3 #2). teardown stops the collector by reading its pid out
  // of this file, so a live collector whose state never landed is a collector
  // nothing can stop: it would hold the port and keep writing session logs
  // for the rest of the runner's life.
  //
  // Note what is NOT in here: the launch token. The session token that is
  // recorded can append events and read this session's own log back, and
  // nothing else — it cannot mint, and it cannot post a hypothesis line.
  try {
    await withStateLock(outputDir, () => writeState(outputDir, {
      nonce,
      pid: startLine.pid,
      port,
      projectRoot,
      sessionName: inputs.sessionName,
      sessionId,
      sessionToken,
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
  // The verification key travels as a STEP OUTPUT, never in state. That
  // routing is the whole security property, and it is about INTEGRITY rather
  // than secrecy: the runner parses this file when the start step ends —
  // before the wrapped command exists — and interpolates the value into later
  // steps' env from its own memory. A same-user process can rewrite
  // action-state.json at leisure, and could happily put ITS OWN public key
  // there and sign with the matching private one; it cannot reach into the
  // runner to change what a later step is handed. State stays routing data;
  // trust is anchored in memory (Codex T5 r4 #1 / r5 #2, ruling iii).
  if (env.GITHUB_OUTPUT) {
    writeOutputs(env.GITHUB_OUTPUT, { 'collector-verify-key': startLine.verify_key });
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
  spawnCommand = defaultSpawnCommand, writeStdout = defaultStdoutWrite,
}) => {
  const state = readState(outputDir);
  if (!state) {
    process.stderr.write('debug-evidence-action: run: no recorded state; the start step never completed.\n');
    return 3;
  }
  if (rejectForeignNonce(state, env, 'run')) return 3;
  // The session was minted in start, while the launch token still existed.
  // This step talks to no one: it injects what start recorded, runs the
  // command, and records how it went. Nothing here holds a credential that
  // could mint a session or post a hypothesis, because no such credential
  // survives into this process (Codex T5 r3).
  if (!state.sessionId || !state.sessionToken) {
    process.stderr.write('debug-evidence-action: run: recorded state carries no session; the start step never completed its mint.\n');
    return 3;
  }
  // Re-registering a value the runner already masks in start is a no-op for
  // Actions and cheap insurance for this step's own log, which is where the
  // token is about to be put into a child process's environment.
  maskValue(env, state.sessionToken, writeStdout);
  const commandEnv = {
    ...env,
    DEBUG_LOG_URL: `http://127.0.0.1:${state.port}/log`,
    DEBUG_SESSION_ID: state.sessionId,
    DEBUG_SESSION_TOKEN: state.sessionToken,
  };
  // The action's own wiring is not part of the contract the wrapped command
  // is promised, and DEBUG_ACTION_OUTPUT_DIR points straight at
  // action-state.json — which no longer carries a launch token, but does
  // carry the session token and this invocation's nonce. The wrapped command
  // runs as the same OS user, so the file's 0600 mode is no boundary against
  // it; handing over the path is (Codex T5 r2 #1). Stripping the whole prefix
  // rather than one name keeps the rule stable as more wiring vars appear.
  for (const key of Object.keys(commandEnv)) {
    if (key.startsWith('DEBUG_ACTION_')) delete commandEnv[key];
  }
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
  // pid/port/session over theirs and strand their live collector. Re-reading
  // first was not enough on its own — between the compare and the rename a
  // second invocation could still commit, and this one would clobber it
  // anyway (Codex T4 #3, then r2). Under the lock the re-read and the write
  // cannot be split, so whoever the compare saw is still who is there.
  const committed = await withStateLock(outputDir, () => {
    const current = readState(outputDir);
    if (!current || current.nonce !== state.nonce) return false;
    writeState(outputDir, {
      ...current,
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
    writeOutputs(env.GITHUB_OUTPUT, { 'command-exit-code': commandExitCode, 'session-id': state.sessionId });
  }
  return 0; // command failure is finish's decision, never run's
};

// Render both surfaces from bytes ALREADY IN MEMORY.
//
// The renderer used to be a child process reading the staged session.log back
// off disk. That path is a race with teeth: a detached child of the wrapped
// command could swap the staged bytes between capture and render, and because
// the digests were also computed by re-reading the same path, report.md,
// report.json and all three hashes ended up consistently describing the
// forgery (Codex T5 r4 #2). A pathname is a shared, writable name; a buffer
// this process holds is not. So the captured bytes are rendered, hashed and
// written from one immutable in-memory value, and the staged files become
// write-only sinks — nothing downstream ever reads them back.
//
// In-process rather than piping to the CLI's stdin: debug_report.js already
// exports exactly the three functions its own main() composes, so importing
// them removes the serialization boundary entirely instead of narrowing it
// (precedent: collector_boot requires debug_server directly). It also lets
// the report carry the real session id, which the CLI could only derive from
// a filename — the staged copy is called session.log, so the CLI rendered
// every report as "(file)".
const defaultRenderReport = (sessionText, sessionId) => {
  const report = buildReport(parseSessionText(sessionText), { sessionId });
  return { markdown: renderMarkdown(report), json: renderJson(report) };
};

// The staged files are WRITE-ONLY SINKS. Nothing downstream reads them back —
// not the renderer, not the digests — so this is the single point where the
// in-memory payload leaves the process, and injecting it is how a test can
// prove the digests describe the payload rather than whatever ended up on
// disk.
const defaultStageFile = (filePath, bytes) => writeFileSync(filePath, bytes);

// Rebuild the collector's public verification key from the SPKI DER base64
// that travelled as a step output. Anything unparsable is treated as no key
// at all — a verifier that cannot verify must not proceed.
const responderVerifyKey = (encoded) => {
  if (typeof encoded !== 'string' || encoded === '') return null;
  try {
    return createPublicKey({ key: Buffer.from(encoded, 'base64'), format: 'der', type: 'spki' });
  } catch {
    return null;
  }
};

// Does this answer carry proof that it came from the collector `start`
// booted, AND that it answers the question this process actually asked?
//
// The record is rebuilt from INTENT, never from the response: the target is
// the unfiltered `/sessions/<id>/logs` this capture meant to fetch, the nonce
// is the one this capture generated, and the digest is over the bytes that
// came back. A relay that forwarded the challenge to the real collector with
// `?limit=1` gets back a perfectly valid signature — over a DIFFERENT target
// — and it will not verify against this reconstruction. No comparison logic
// is needed for that; the signature simply fails (Codex T5 r5 #1).
//
// The key is public, so this is verification, not a shared secret: nothing
// here could sign anything even if the whole environment leaked.
const verifyResponderProof = ({ verifyKey, sessionId, challenge, text, proof }) => {
  if (verifyKey === null || typeof proof !== 'string' || proof === '') return false;
  const signature = Buffer.from(proof, 'base64');
  // Ed25519 signatures are exactly 64 bytes; anything else is not one, and
  // base64 decoding never throws, so the length is the guard.
  if (signature.length !== 64) return false;
  const record = Buffer.from(canonicalResponderRecord({
    method: 'GET',
    target: `/sessions/${sessionId}/logs`,
    challenge,
    bodyDigest: createHash('sha256').update(text, 'utf8').digest('hex'),
  }), 'utf8');
  try {
    return verify(null, record, verifyKey, signature) === true;
  } catch {
    return false;
  }
};

// A renderer that exited 0 has not thereby produced a report. Its stdout is
// what report.json and the event-count output are made of, so it is parsed
// and shape-checked BEFORE either is committed: a status-0 child that printed
// truncated JSON, a report from some future schema, or a nonsense event count
// would otherwise be published as authoritative evidence, and the old
// `catch {}` around the count turned exactly that into a silently empty
// output (Codex T5 #2). Returns the validated report, or null.
const parseRenderedReport = (text) => {
  let report;
  try {
    report = JSON.parse(text);
  } catch {
    return null;
  }
  if (!report || typeof report !== 'object' || Array.isArray(report) || report.schema !== 1) return null;
  const events = report.session?.events;
  return Number.isInteger(events) && events >= 0 ? report : null;
};

// Exactly what the upload step enumerates, and therefore exactly what has to
// belong to THIS invocation.
const EVIDENCE_FILES = ['session.log', 'report.md', 'report.json'];

// The action is the ONLY legitimate holder of the launch token in the
// wrap-one-command model, and POST /hypothesis is a launch-token capability
// the wrapped command is never given. That makes a captured session's
// hypothesis lines DECIDABLE: there must be exactly the line this action
// posted — an OPEN for the configured hypothesis-id, carrying the title it
// sent — or none at all when no hypothesis-id was configured. Any other
// hypothesis line was forged, by definition.
//
// As of T5 r3 this is a BELT, not the braces. It was introduced when the
// launch token was persisted in action-state.json, where the wrapped command
// — same OS user, derivable path — could take it and post a CONFIRMED verdict
// through the real endpoint for authenticated capture to bless (Codex T5 r2
// #1). That token now lives and dies inside start's process, so no credential
// able to write a hypothesis line exists while the wrapped command runs and
// this check should never fire. It stays precisely because of that: if it
// ever does fire, the structural guarantee has been broken somewhere and the
// evidence must not be published on the strength of an assumption.
//
// EVENTS are deliberately not checked: they come from the instrumented
// process and are attacker-authored by design — recording what that process
// says is the entire point of the evidence.
//
// Returns null when the set is exactly right, or a short reason.
const describeHypothesisDeviation = (entries, state) => {
  const posted = [];
  for (const entry of entries) {
    const parsed = entry?.parsed;
    // Served entries are {raw, parsed} by contract. A line this check cannot
    // read is not evidence that there is nothing to find.
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return 'the collector served an entry in a shape this check cannot inspect';
    }
    if (parsed.type === 'hypothesis') posted.push(parsed);
  }
  const expected = state.hypothesisId ? 1 : 0;
  if (posted.length !== expected) {
    return `expected exactly ${expected} hypothesis line${expected === 1 ? '' : 's'}, captured ${posted.length}`;
  }
  if (expected === 0) return null;
  const [line] = posted;
  // Values below are attacker-influenced; JSON.stringify neutralizes quotes
  // and newlines before they reach a log line.
  if (line.hypothesisId !== state.hypothesisId) {
    return `hypothesis id ${JSON.stringify(line.hypothesisId)} is not the ${JSON.stringify(state.hypothesisId)} this action opened`;
  }
  if (line.status !== 'OPEN') {
    return `status ${JSON.stringify(line.status)} — this action opens hypotheses and never records a verdict`;
  }
  if (state.hypothesisTitle && line.title !== state.hypothesisTitle) {
    return `title ${JSON.stringify(line.title)} is not the one this action posted`;
  }
  return null;
};

// Ceiling on the authoritative read. A collector that accepts the connection
// and then says nothing must not hold the capture step open for the rest of
// the job; timing out here is an evidence-integrity failure like any other.
const LIVE_READ_TIMEOUT_MS = 5_000;

// And the absolute one. The idle timeout above is reset by every byte, so a
// listener dripping a byte every four seconds satisfies it forever; only a
// wall-clock ceiling ends that. Thirty seconds is far longer than a loopback
// read of a capped session log has any business taking, and it bounds the
// capture step no matter what is on the other end.
const LIVE_READ_DEADLINE_MS = 30_000;

// Which live-read failures mean "there is no collector to ask" rather than
// "the collector answered and refused". Only the first class may fall back to
// the on-disk log, and only as labeled partial evidence: nothing answered
// (connect failure), nothing answered in time, or what answered does not hold
// this session's token — a foreign process that rebound the port. Every other
// failure came from a collector that authenticated us and then declined, and
// preferring the file on disk over its refusal would stage the exact bytes it
// refused to vouch for.
const UNREACHABLE_READ = /^live_read_(connect_failed|timeout|unauthorized)/;

// SHA-256 of every payload this invocation intends to stage, as one line,
// computed from the IN-MEMORY bytes.
//
// Prevention is not available here: staging and upload are separate steps of
// the same composite action running as the same user, so a detached child of
// the wrapped command can rewrite a staged file in the window between them.
// Detection is. The step log is streamed and immutable once emitted, so a
// digest printed at staging time is a record no later rewrite can revise —
// compare the uploaded artifact against this line and any swap is visible
// (Codex T5 r3, threat-model option taken with teeth).
//
// Hashing the FILES back off disk would have quietly destroyed that: a swap
// landing before the hash produced digests that described the forgery
// perfectly, and the step log would have blessed it (Codex T5 r4 #2). These
// digests describe what this process decided to write, so any later
// divergence is exactly what the comparison is meant to catch.
//
// Only payloads that exist appear; a run that staged nothing claims nothing.
const payloadDigestLine = (payloads) => {
  const parts = [];
  for (const name of EVIDENCE_FILES) {
    const bytes = payloads[name];
    if (bytes === undefined) continue;
    parts.push(`${name}=${createHash('sha256').update(bytes, 'utf8').digest('hex')}`);
  }
  return parts.length === 0 ? null : `evidence-sha256 ${parts.join(' ')}`;
};

// One diagnostic is one line. The values interpolated into report's stderr
// come from a state file and from OS/collector errors quoting it, so a raw
// newline in either would split one message into what reads as two — the same
// discipline debug_report.js applies to its own error line.
const oneLine = (value) => String(value).replace(/\r?\n|\r/g, ' ');

// Capture: stage the session log and both rendered surfaces into the evidence
// child, record what actually happened, and leave every VERDICT to finish.
//
// Three decisions here are load-bearing:
//
// 1. Evidence is captured FROM THE COLLECTOR, never by pathname. The wrapped
//    command is handed DEBUG_SESSION_ID and shares the filesystem, so it can
//    overwrite .debug/debug-<id>.log with whatever NDJSON it likes — including
//    hypothesis lines carrying a CONFIRMED verdict it has no credential to
//    POST — and a copyFileSync would stage that forgery and render it as the
//    run's official evidence (Codex T5 #1, Critical). Reading back through
//    GET /sessions/:id/logs puts the collector's own checks in the path —
//    dev/ino/birthtime/size identity, and since r2 a SHA-256 of every byte it
//    appended — so a tampered log is a 409 rather than a report, including
//    the same-length in-place rewrite metadata alone cannot see.
// 2. Aliveness is the authenticated read itself. An unauthenticated /health
//    answer only says SOMETHING is listening — exactly what a process that
//    rebound the port would also produce. A served log proves the occupant
//    holds the session this run minted; a foreign one answers 401.
// 3. Live read and renderer both run BEFORE the lock is taken. That
//    work can take seconds; the state lock's staleness threshold is 30s and
//    its retry budget ~450ms, so a holder doing it inside the critical
//    section would make every concurrent invocation fail to acquire — and, at
//    the tail, would itself risk being judged stale and reaped mid-flight
//    (recorded T4 r2 requirement: no holder approaches the threshold). The
//    commit is then a compare-and-set under that lock, exactly as run's is:
//    re-read, compare nonces, and spread the CURRENT state rather than the
//    snapshot this function opened with (Codex T4 #3/r2).
const reportSubcommand = async ({
  outputDir, env = process.env,
  renderReport = defaultRenderReport, readLive = readSessionLive,
  stageFile = defaultStageFile, writeStdout = defaultStdoutWrite,
}) => {
  // FIRST, before state is even read. Staging is invocation-scoped: an
  // output-dir can be reused — across steps, across jobs on a self-hosted
  // runner — and the upload step enumerates three fixed filenames, so a
  // previous invocation's report left sitting there ships as this run's
  // evidence under this run's artifact name. A failed start, an absent state
  // file and a foreign nonce are exactly the paths that used to return
  // without clearing, and they are the ones where stale evidence is most
  // plausible (Codex T5 r2 #3, hoisted in r3). Anything other than "it was
  // not there" is left to throw: a staging slot that cannot be cleared cannot
  // be scoped either.
  const evidenceDir = resolveEvidenceDir(outputDir);
  mkdirSync(evidenceDir, { recursive: true });
  for (const name of EVIDENCE_FILES) {
    try {
      unlinkSync(path.join(evidenceDir, name));
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
  const state = readState(outputDir);
  if (!state) return 0; // start never completed; finish owns that failure
  if (rejectForeignNonce(state, env, 'report')) return 3;
  if (!state.sessionId || !state.sessionToken) {
    process.stderr.write('debug-evidence-action: report: recorded state carries no session; nothing to capture.\n');
    return 0; // finish fails on the missing commandExitCode
  }
  // Aliveness is a PROVEN read succeeding. An authenticated read alone is not
  // enough any more: Bearer proves this caller to the listener, and the port,
  // session id and token it used all came out of a file the wrapped command
  // can rewrite — so a counterfeit listener serving contract-shaped NDJSON
  // would have satisfied every check (Codex T5 r4 #1). The responder key
  // closes the loop in the other direction, and it reaches this process
  // through runner memory rather than through anything on disk.
  let collectorAlive = false;
  // Did the staged bytes come from the collector, or off a filesystem the
  // wrapped command can write? Recorded either way, so the artifact's
  // provenance is a fact in the state file rather than an assumption.
  let evidenceAuthentic = false;
  let entries = null;
  let capturedText = null;
  let readFailure = null;
  // From the ENVIRONMENT only, never from state. The key's secrecy no longer
  // matters — it is public — but its INTEGRITY is everything: a same-user
  // process that could substitute its own public key could then sign answers
  // with the matching private one. Runner memory is the only channel here
  // that such a process cannot rewrite, so state and every other file on disk
  // are excluded as sources by construction (Codex T5 r5 #2).
  const verifyKey = responderVerifyKey(env.DEBUG_ACTION_COLLECTOR_VERIFY_KEY);
  if (verifyKey === null) {
    // Valid state, no usable key: the wiring that carries it from start's
    // step output into this step's env is broken or absent. That is an
    // integrity failure, not a missing collector — capture cannot prove
    // anything, so it must not fall back to the on-disk log and call the
    // result evidence.
    readFailure = 'responder_key_missing';
    process.stderr.write('debug-evidence-action: report: no usable collector verification key in this step\'s environment; capture cannot verify who it is talking to.\n');
  } else {
    // Fresh per capture. A nonce reused across captures would let a recorded
    // answer be replayed by anything that saw it.
    const challenge = randomBytes(32).toString('hex');
    try {
      const answer = await readLive({
        port: state.port,
        // The session's OWN token. GET /sessions/:id/logs accepts it for this
        // session and nothing else, which is why start could drop the launch
        // token and still leave capture possible.
        token: state.sessionToken,
        sessionId: state.sessionId,
        timeoutMs: LIVE_READ_TIMEOUT_MS,
        deadlineMs: LIVE_READ_DEADLINE_MS,
        challenge,
      });
      if (!verifyResponderProof({
        verifyKey, sessionId: state.sessionId, challenge, text: answer.text, proof: answer.proof,
      })) {
        readFailure = 'responder_proof_invalid';
        process.stderr.write(oneLine(`debug-evidence-action: report: whatever served session ${state.sessionId} on port ${state.port} could not prove it is this run's collector; refusing to treat its answer as evidence.`) + '\n');
      } else {
        entries = answer.entries;
        // The bytes the proof covers, and the only copy anything downstream
        // will read. Staging exactly these keeps the artifact byte-identical
        // to what was proven.
        capturedText = answer.text;
        collectorAlive = true;
      }
    } catch (error) {
      readFailure = String(error?.message ?? error);
    }
  }
  // Everything from here works on in-memory payloads; the staged files are
  // written once, at the end, and never read back.
  const payloads = {};
  if (entries !== null) {
    const deviation = describeHypothesisDeviation(entries, state);
    if (deviation !== null) {
      // Belt to the structural braces. No credential capable of posting a
      // hypothesis line survives start, so this should now be unreachable —
      // which is exactly why it stays: if it ever fires, something about that
      // invariant is wrong and the evidence must not be published.
      process.stderr.write(oneLine(`debug-evidence-action: report: the captured session's hypothesis lines are not the set this action posted (${deviation}); refusing to stage evidence carrying a verdict it never made.`) + '\n');
    } else {
      payloads['session.log'] = capturedText;
      evidenceAuthentic = true;
    }
  } else if (UNREACHABLE_READ.test(readFailure)) {
    // Nothing answered, or what answered is not our collector. There is no
    // authoritative source to prefer, so the on-disk log is read best-effort
    // and LABELED: whatever is readable is still worth a human's eyes, and
    // finish refuses the run on collectorAlive, so unverifiable bytes can be
    // inspected but can never ride a green build. Read into memory like every
    // other payload — a copyFileSync would put the render back on a pathname.
    process.stderr.write(oneLine(`debug-evidence-action: report: no collector on port ${state.port} would serve session ${state.sessionId} (${readFailure}); staging the on-disk log as UNAUTHENTICATED partial evidence.`) + '\n');
    try {
      payloads['session.log'] = readFileSync(path.join(state.projectRoot, '.debug', `debug-${state.sessionId}.log`), 'utf8');
    } catch (error) {
      process.stderr.write(`debug-evidence-action: report: session log unreadable (${error?.code ?? error}).\n`);
    }
  } else {
    // The collector answered us and refused — session_log_tampered or
    // session_log_replaced surfacing as live_read_log_replaced, an unknown
    // session, a torn line, an unprovable responder. Falling back to the file
    // on disk would stage precisely the bytes nothing will vouch for, so this
    // is an evidence-integrity failure and nothing else.
    process.stderr.write(oneLine(`debug-evidence-action: report: the collector refused to serve session ${state.sessionId} (${readFailure}); the on-disk log is not a substitute for it.`) + '\n');
  }
  const evidenceCopied = payloads['session.log'] !== undefined;
  let reportRendered = false;
  let markdownText = '';
  let eventCount = '';
  if (evidenceCopied) {
    let rendered = null;
    try {
      rendered = renderReport(payloads['session.log'], state.sessionId);
    } catch (error) {
      process.stderr.write(oneLine(`debug-evidence-action: report: renderer failed (${error?.message ?? error}).`) + '\n');
    }
    if (rendered !== null) {
      const validated = parseRenderedReport(rendered.json);
      if (validated === null) {
        process.stderr.write('debug-evidence-action: report: the renderer returned no schema-1 report; refusing to publish it.\n');
      } else {
        payloads['report.md'] = rendered.markdown;
        payloads['report.json'] = rendered.json;
        reportRendered = true;
        markdownText = rendered.markdown;
        eventCount = String(validated.session.events);
      }
    }
  }
  // Hash from memory, THEN write. The order is the guarantee: the digest
  // describes what this invocation decided to stage, so anything that reaches
  // the files afterwards is a mismatch rather than a blessing. Computing it
  // from the files instead would hand a swap the step log's endorsement.
  const digestLine = payloadDigestLine(payloads);
  for (const name of EVIDENCE_FILES) {
    if (payloads[name] !== undefined) stageFile(path.join(evidenceDir, name), payloads[name]);
  }
  // Printed as soon as the bytes exist and BEFORE the ownership commit: this
  // line is a forensic record of what this process wrote to disk, not a claim
  // about which invocation owns the output-dir. Emitting it late — or only on
  // the paths that go on to succeed — would leave exactly the failure windows
  // undocumented.
  if (digestLine !== null) writeStdout(`${digestLine}\n`);
  const committed = await withStateLock(outputDir, () => {
    const current = readState(outputDir);
    if (!current || current.nonce !== state.nonce) return false;
    writeState(outputDir, { ...current, collectorAlive, evidenceAuthentic, evidenceCopied, reportRendered });
    return true;
  });
  if (!committed) {
    process.stderr.write('debug-evidence-action: report: recorded state changed while evidence was captured (another invocation now owns this output-dir); refusing to overwrite it.\n');
    return 3;
  }
  // Published only AFTER the commit succeeds. The staged files are already on
  // disk — they have to be, since the render runs outside the lock — but a
  // report-path or a step summary announced from state this invocation just
  // declined to own would be advertising someone else's run as its own, the
  // same lie run refuses to tell with a session-id.
  if (reportRendered) {
    if (env.GITHUB_STEP_SUMMARY) appendFileSync(env.GITHUB_STEP_SUMMARY, `${markdownText}\n`);
    if (env.GITHUB_OUTPUT) {
      writeOutputs(env.GITHUB_OUTPUT, {
        'event-count': eventCount,
        'report-path': path.join(evidenceDir, 'report.md'),
        // Byte-identical to the stdout line, so a consumer can compare the
        // artifact against either surface.
        'evidence-digest': digestLine ?? '',
      });
    }
  }
  return evidenceCopied && reportRendered ? 0 : 3; // capture is the product — fail closed
};

// The exit taxonomy, and the only place the action turns evidence into a
// verdict. Read-only by construction, so it takes no lock (recorded
// decision: lock-free read paths). Every failure mode of the machinery is a
// 3; only a wrapped command's own non-zero exit is mirrored, so a consumer
// can always tell "your build failed" from "this action failed".
const finishSubcommand = ({ outputDir, env = process.env }) => {
  const state = readState(outputDir);
  if (!state) {
    process.stderr.write('debug-evidence-action: finish: no recorded state; the start step never completed.\n');
    return 3;
  }
  if (rejectForeignNonce(state, env, 'finish')) return 3;
  if (!Number.isInteger(state.commandExitCode)) {
    process.stderr.write('debug-evidence-action: finish: the run step never completed.\n');
    return 3;
  }
  if (state.collectorAlive !== true) {
    process.stderr.write('debug-evidence-action: finish: the collector was not alive and ready at capture time; evidence may be incomplete.\n');
    return 3;
  }
  if (state.evidenceCopied !== true || state.reportRendered !== true) {
    process.stderr.write('debug-evidence-action: finish: evidence capture or report rendering failed.\n');
    return 3;
  }
  // Validated on EVERY run, green ones included. The toggle is read out of a
  // state file, and a state file that carries a value validateActionInputs
  // could never have produced is corrupt or forged — which says nothing good
  // about the exit code sitting next to it. Deferring this check to the
  // failure branch would let exactly that state pass as a success (Codex T5
  // #3).
  if (state.failOnCommandFailure !== 'true' && state.failOnCommandFailure !== 'false') {
    process.stderr.write(`debug-evidence-action: finish: recorded fail-on-command-failure is neither 'true' nor 'false'; refusing to interpret this state.\n`);
    return 3;
  }
  if (state.commandExitCode !== 0) {
    if (state.failOnCommandFailure === 'false') {
      process.stderr.write(`debug-evidence-action: wrapped command exited ${state.commandExitCode}; fail-on-command-failure is false, so the action succeeds. Evidence is in the artifact.\n`);
      return 0;
    }
    // Anything but the literal 'false' mirrors — fail closed on unknowns.
    process.stderr.write(`debug-evidence-action: wrapped command exited ${state.commandExitCode}.\n`);
    // Out of range (a 128+signal sentinel above 255, or anything a shell
    // could not have produced) becomes a plain 1: process.exitCode is taken
    // modulo 256, so passing 300 through would surface as 44 — a code that
    // looks like a real, different failure.
    return state.commandExitCode >= 1 && state.commandExitCode <= 255 ? state.commandExitCode : 1;
  }
  return 0;
};

// The session token is the only credential a state file can carry now — the
// launch token never reaches disk (Codex T5 r3), so there is nothing else
// here to redact out of a terminal diagnostic.
const collectStateSecrets = (state) => [state?.sessionToken].filter(Boolean);

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
  defaultRenderReport,
  defaultSpawnCommand,
  defaultSpawnShim,
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
