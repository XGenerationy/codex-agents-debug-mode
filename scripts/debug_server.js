#!/usr/bin/env node

const { createHmac, randomBytes, timingSafeEqual } = require('node:crypto');
const { closeSync, constants, fstatSync, lstatSync, mkdirSync, openSync, readdirSync, readSync, realpathSync, renameSync, unlinkSync, writeSync } = require('node:fs');
const { link, lstat, mkdir, realpath, rename, unlink } = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const {
  assertNotSymlink: assertNotSymlinkShared,
  isSameFileIdentity,
  isSameLockIdentity,
  openNoFollow: openNoFollowShared,
  openNoFollowFlagAttempts,
  protectWindowsPrivateFile,
  protectWindowsPrivateFileAsync,
  resolvePowerShellExecutable,
} = require('./pr_closeout_fs');
const { buildSecretReplacements } = require('./pr_closeout_stream');

/**
 * Synchronous stdout/stderr writes for CLI terminal paths that call
 * process.exit immediately afterward. Stream `.write()` is async when piped
 * and can be truncated by process.exit (CodeRabbit #4781360793).
 * @param {1|2} fd
 * @param {string} text
 */
const writeFdSync = (fd, text) => {
  writeSync(fd, text);
};

// protectWindowsPrivateFile/resolvePowerShellExecutable establish and verify
// a protected, current-user-only Windows DACL before a secret or captured
// evidence file receives any bytes; isSameFileIdentity binds a descriptor to
// a later path-based (l)stat. Shared via pr_closeout_fs.js (imported above)
// so the collector's token/session-log/port writes and closeout's evidence
// log writes stay one implementation.

const launchTokenProof = (token, challenge) =>
  createHmac('sha256', token).update(`codex-debug-collector-auth-v1:${challenge}`, 'utf8').digest('base64url');

// Session logs deliberately outlive the collector process (see
// retireInactiveSessions), so a restarted collector must fold their bytes
// back into the aggregate cap instead of starting totalBytes from zero.
// Without this, repeated restarts each grant another full maxTotalBytes
// allowance while every prior log stays on disk, letting .debug grow without
// bound. lstatSync (not statSync) so a symlink planted under .debug is
// skipped rather than followed and counted as/instead of the real file.
// This accounting is explicitly best-effort: it runs synchronously inside
// createDebugServer's construction path in main(), with no surrounding
// try/catch, so any readdirSync failure (not just ENOENT/ENOTDIR -- e.g.
// EACCES/EPERM on an unreadable .debug) must fail open to 0 rather than
// crash startup with a raw stack trace instead of the structured
// startup.failed JSON every other failure path emits (CodeRabbit review).
const computeRetainedLogBytes = (logDir) => {
  let names;
  try {
    names = readdirSync(logDir);
  } catch {
    return 0;
  }
  let bytes = 0;
  for (const name of names) {
    if (!/^debug-.*\.log$/.test(name)) continue;
    let info;
    try {
      info = lstatSync(path.join(logDir, name));
    } catch {
      continue;
    }
    if (info.isFile()) bytes += info.size;
  }
  return bytes;
};

// Keys projectHash below so it cannot be brute-forced from the unauthenticated
// /health response (Codex UwnvH): hashing the raw canonicalProjectRoot alone
// is a deterministic, unkeyed fingerprint of low-entropy data (a filesystem
// path), so any other local process could hash likely canonical roots (e.g.
// /home/<user>/<repo>) until one matched and recover the project path despite
// /health never printing it directly. A random per-project salt persisted
// under .debug/ (0600, current-user-only) closes that: two invocations of the
// SAME project's collector still agree, because both read the same on-disk
// salt, but an outside guesser would also need to guess the unpublished salt.
// Runs synchronously during createDebugServer's construction, like
// computeRetainedLogBytes below; every failure (unreadable/corrupt/racing
// create) falls open to a private, unpersisted salt rather than crashing
// startup -- worst case is two invocations disagreeing on project_hash, which
// only affects the already_running convenience check, never authentication.
const readOrCreateProjectSalt = (debugDir, resolvedProjectRoot) => {
  const saltFile = path.join(debugDir, 'project_salt');
  const readExisting = () => {
    // Refuse a symlinked salt file, mirroring collector_token's own guard: an
    // attacker-planted link could otherwise redirect the read. Open through
    // the shared no-follow helper (not a plain openSync after lstatSync) so a
    // symlink swapped in during the window between the lstat and the open
    // cannot still be followed (Codex UzKDl). A hard-linked salt file
    // (nlink > 1) shares its inode with another, unrelated file; refuse to
    // trust its content here too, for the same reason the create/repair path
    // below refuses to ever write through it (Codex Uzynn).
    const fd = openNoFollowSync(saltFile, constants.O_RDONLY);
    try {
      // Validate the OPENED descriptor (fstatSync), not the pre-open path: an
      // lstat(path) identity check can be defeated by swapping the path for a
      // different (e.g. hard-linked) regular file in the window between the
      // lstat and the open -- the TOCTOU the collector_token and session-log
      // paths in this file were hardened to close by checking the descriptor
      // itself (CodeRabbit U03Xw). fstatSync is already imported alongside
      // lstatSync. Throws project_salt_not_regular_file on a non-regular or
      // hard-linked (nlink > 1) descriptor; the finally still closes it.
      const info = fstatSync(fd);
      if (!info.isFile() || info.nlink > 1) throw new Error('project_salt_not_regular_file');
      const buffer = Buffer.alloc(32);
      // Loop until all 32 bytes are read or a genuine EOF is hit: some
      // filesystems/mounts return a short read (fewer than the requested
      // bytes) before EOF, which a single read would misclassify as a corrupt
      // salt and needlessly rotate, churning project_hash while a live
      // collector still uses the original (Codex U2TI9).
      let bytesRead = 0;
      while (bytesRead < 32) {
        const n = readSync(fd, buffer, bytesRead, 32 - bytesRead, bytesRead);
        if (n <= 0) break; // 0 => real EOF before 32 bytes.
        bytesRead += n;
      }
      if (bytesRead !== 32) throw new Error('project_salt_short_read');
      return buffer;
    } finally {
      closeSync(fd);
    }
  };
  // Refuse to read or create project_salt through a symlinked or
  // root-escaping .debug: the later per-session handler's .debug guard only
  // runs on the first /session request, so a .debug symlink already planted
  // before the collector even starts would otherwise redirect this earlier,
  // unguarded write/read outside the project root (Codex UzJxy). A missing
  // .debug is fine -- mkdirSync below creates a fresh, safe directory.
  const debugDirIsSafe = () => {
    try {
      const dirInfo = lstatSync(debugDir);
      if (dirInfo.isSymbolicLink() || !dirInfo.isDirectory()) return false;
      return isInsideRoot(realpathSync(resolvedProjectRoot), realpathSync(debugDir));
    } catch (error) {
      return error?.code === 'ENOENT';
    }
  };
  if (!debugDirIsSafe()) return randomBytes(32);
  try {
    return readExisting();
  } catch {
    // Missing, corrupt, unreadable, or hard-linked: fall through to
    // (re)generate below.
  }
  try { mkdirSync(debugDir, { recursive: true }); } catch {}
  // Re-check right before writing: mkdirSync above silently no-ops if the
  // path already resolves to a directory, so an attacker racing a .debug
  // symlink into place after the first check above (during the window this
  // ENOENT-tolerant path leaves open) would otherwise go undetected --
  // O_NOFOLLOW on the final path component below cannot catch a symlinked
  // PARENT segment (Codex UzZZk). This narrows, but does not fully close,
  // the window; the same residual gap is already accepted elsewhere in this
  // file for the same reason (see unlinkOwnedClaimIfUnchanged).
  if (!debugDirIsSafe()) return randomBytes(32);
  try {
    // A concurrent invocation may have already finished writing a valid salt
    // while this one was creating .debug; prefer agreeing with it over
    // unconditionally replacing it below.
    return readExisting();
  } catch {
    // Still missing, corrupt, unreadable, or hard-linked: proceed to
    // (re)generate.
  }
  const salt = randomBytes(32);
  // Create-once / first-writer-wins: only the first concurrent first-launch
  // actually creates saltFile (O_CREAT|O_EXCL). O_EXCL on a non-existent path
  // makes a brand-new inode this process owns (nlink 1), so unlike truncating
  // an existing file there is no hard-linked inode to clobber (Codex
  // Uzynn/Uz6Aw). Every concurrent loser takes the EEXIST branch and adopts the
  // winner's salt (retrying briefly while the winner finishes its 32-byte
  // write) instead of overwriting it, so all collectors agree on project_hash
  // rather than one retaining a stale salt that misclassifies a same-project
  // relaunch as port_in_use_by_other_process (Codex U2TI8/U25na). With no
  // concurrency this writes the salt once and reads it straight back.
  let wroteWinner = false;
  try {
    try {
      const fd = openNoFollowSync(saltFile, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      wroteWinner = true;
      try {
        // Loop until all 32 bytes are written: a short write (possible on some
        // filesystems/mounts) would otherwise publish a truncated salt, the
        // symmetric of the short-read fix in readExisting (Codex U2TI9).
        for (let written = 0; written < 32; ) {
          const n = writeSync(fd, salt, written, 32 - written, written);
          if (n <= 0) throw new Error('project_salt_short_write');
          written += n;
        }
      } catch (error) {
        // A failed first-write must not leave an empty/partial saltFile that a
        // concurrent loser would then adopt as the winner. Close before
        // unlinking: on Windows unlinkSync of an open fd is a sharing
        // violation.
        try { closeSync(fd); } catch { /* fd cleanup */ }
        try { unlinkSync(saltFile); } catch { /* best effort cleanup */ }
        throw error;
      }
      closeSync(fd);
      // Apply the same owner-only Windows ACL the collector_token and session
      // logs get: mode 0o600 above does not strip inherited NTFS read perms on
      // Windows, so without this a project_salt in a shared/permissive
      // checkout stays readable by other local users, who could combine it
      // with the unauthenticated /health project_hash to test candidate
      // canonical paths and defeat the path-privacy the keyed hash was
      // introduced to provide (Codex U1D5A). POSIX is a no-op.
      try {
        protectWindowsPrivateFile(saltFile);
      } catch (error) {
        try { unlinkSync(saltFile); } catch { /* best effort cleanup */ }
        throw error;
      }
    } catch (error) {
      if (error?.code !== 'EEXIST' || wroteWinner) throw error;
      // saltFile already exists (a concurrent winner or a prior run): adopt it
      // rather than overwriting. It may briefly be empty while the winner
      // finishes its 32-byte write, so retry readExisting for a short window; a
      // genuinely untrusted inode (hard-linked / corrupt / unreadable) keeps
      // throwing and falls through to the replace-fallback below.
      // A zero-delay loop finishes in microseconds and cannot actually wait for
      // a concurrent winner's 32-byte write to flush, so the loser would
      // exhaust immediately and fall through to the replace path --
      // reintroducing the project_hash disagreement this loop exists to prevent
      // (CodeRabbit U3Q0J). Atomics.wait is the standard synchronous sleep. A
      // genuinely untrusted inode keeps throwing on every attempt and still
      // reaches the replace fallback below, just ~160ms later on the true-stale
      // path only.
      const adoptWait = new Int32Array(new SharedArrayBuffer(4));
      for (let attempt = 0; attempt < 32; attempt += 1) {
        try { return readExisting(); } catch { /* winner still publishing or untrusted */ }
        if (attempt < 31) Atomics.wait(adoptWait, 0, 0, 5);
      }
      // Persistently unreadable (e.g. hard-linked): never write through
      // saltFile's existing inode -- a hard link would clobber the linked file
      // (Codex Uzynn/Uz6Aw). Replace only the directory entry via a private temp
      // file + atomic rename; rename swaps the directory entry, leaving the
      // previously hard-linked inode untouched.
      const tempFile = path.join(debugDir, `.project_salt.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
      const tfd = openNoFollowSync(tempFile, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      try {
        for (let written = 0; written < 32; ) {
          const n = writeSync(tfd, salt, written, 32 - written, written);
          if (n <= 0) throw new Error('project_salt_short_write');
          written += n;
        }
      } catch (error2) {
        try { unlinkSync(tempFile); } catch { /* best effort cleanup */ }
        throw error2;
      } finally {
        try { closeSync(tfd); } catch { /* best effort cleanup */ }
      }
      try {
        protectWindowsPrivateFile(tempFile);
      } catch (error2) {
        try { unlinkSync(tempFile); } catch { /* best effort cleanup */ }
        throw error2;
      }
      try {
        renameSync(tempFile, saltFile);
      } catch (error2) {
        try { unlinkSync(tempFile); } catch { /* best effort cleanup */ }
        throw error2;
      }
    }
    // Read back the on-disk winner so every publisher returns the same bytes
    // (Codex U16Cd); with no concurrency this is exactly the salt just written.
    try {
      return readExisting();
    } catch {
      return salt;
    }
  } catch {
    // Any failure keeps this invocation's own unpersisted salt (fail-open per
    // the note above): worst case is two invocations disagreeing on
    // project_hash, which only affects the already_running convenience check,
    // never authentication.
    return salt;
  }
};

const DEFAULT_PORT = 8787;
const COLLECTOR_SERVICE = 'codex-debug-collector';
const COLLECTOR_VERSION = 1;
const DEFAULT_LIMITS = Object.freeze({
  maxBodyBytes: 64 * 1024,
  bodyTimeoutMs: 30_000,
  maxSessions: 32,
  // Completed sessions are retired after inactivity so a long-lived reused
  // collector does not permanently exhaust maxSessions (Codex #4781596467).
  sessionIdleTimeoutMs: 15 * 60 * 1_000,
  maxEventsPerSession: 2_000,
  maxTotalBytes: 16 * 1024 * 1024,
});

/**
 * A structured, expected request failure: `code` is the machine-readable
 * JSON `error` field returned to the client and `status` is the HTTP status
 * to send. Thrown from request handling and readJson; caught at the top of
 * the request handler and mapped straight to a response, so throwing this
 * (instead of a bare Error) is how a handler fails closed with a specific
 * status/code pair rather than falling through to a generic 500.
 * `closeConnection` marks a failure where the server intentionally stopped
 * reading the request body before it was fully drained (see readJson's
 * body_too_large path): the response must close the underlying socket
 * instead of returning it to a keep-alive pool, because whatever bytes the
 * client still has in flight for the abandoned body would otherwise be
 * misparsed as the start of the next request on a reused connection.
 */
class RequestError extends Error {
  constructor(code, status = 400, { closeConnection = false } = {}) {
    super(code);
    this.name = 'RequestError';
    this.code = code;
    this.status = status;
    this.closeConnection = closeConnection;
  }
}

const sendJson = (response, status, payload, close = false) => {
  // Guard against secondary throws when the client already closed the socket
  // (e.g. after request_aborted); writableEnded/destroyed means we cannot
  // respond. `close` sends `Connection: close` so the caller can request the
  // socket be torn down cleanly right after this response flushes (see
  // RequestError.closeConnection) instead of being returned to a keep-alive
  // pool -- used when the server intentionally stopped reading an oversized
  // body without draining it.
  if (response.writableEnded || response.destroyed) return;
  if (close) response.setHeader('Connection', 'close');
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(`${JSON.stringify(payload)}\n`);
};

/**
 * Buffer an HTTP request body, enforce `maxBodyBytes`, and parse it as a JSON
 * object (arrays and primitives are rejected). Oversize uploads stop being
 * read as soon as the limit is crossed -- the loop `break`s instead of
 * buffering further chunks -- and always surface as
 * `RequestError('body_too_large', 413, { closeConnection: true })`. The
 * break deliberately does NOT call `request.destroy()`: for a real
 * `http.IncomingMessage`, the request and response share one HTTP/1.1
 * socket, and destroying the request also destroys that shared socket
 * (verified against Node's actual runtime behavior, not assumed), so the
 * handler's 413 response would never reach the client -- it would observe
 * ECONNRESET instead. Breaking out of the `for await...of` loop still
 * releases the request object itself (Node's async-iterator `return()`
 * protocol marks it destroyed) without touching the socket, so the caller
 * can still write the response through it. `closeConnection: true` then
 * tells the caller (see sendJson) to send `Connection: close`, because the
 * remaining unread body bytes the client may still be sending are never
 * drained and would otherwise corrupt the framing of a reused keep-alive
 * connection. Client disconnects (ECONNRESET/EPIPE/abort) map to
 * `RequestError('request_aborted', 400)`; any other stream failure maps to
 * `RequestError('request_failed', 400)` (logged to stderr) instead of
 * bubbling up as an uncaught rejection.
 * @param {AsyncIterable<Buffer>} request
 * @param {number} maxBodyBytes
 * @returns {Promise<object>} the parsed JSON body.
 */
const readJson = async (request, maxBodyBytes, bodyTimeoutMs = 30_000) => {
  const chunks = [];
  let size = 0;
  let tooLarge = false;
  let timedOut = false;
  // Bound the body read by wall-clock time: an authenticated client can send
  // /session headers and a partial chunked body without ever ending the
  // request, which would otherwise keep a provisional session slot reserved
  // forever (repeated up to maxSessions → permanent session_limit_reached).
  // Do not destroy IncomingMessage on deadline: it shares the response
  // socket, so destruction prevents the handler from returning its 408.
  // Pause the unread body, reject the foreground read, and let the handler
  // close the connection after it has flushed the structured response.
  let rejectTimeout;
  const timeout = new Promise((_, reject) => {
    rejectTimeout = reject;
  });
  const timer = setTimeout(() => {
    timedOut = true;
    try { request.pause?.(); } catch { /* already closed */ }
    rejectTimeout(new RequestError('request_body_timeout', 408, { closeConnection: true }));
  }, bodyTimeoutMs);
  if (typeof timer.unref === 'function') timer.unref();

  try {
    await Promise.race([
      (async () => {
        for await (const chunk of request) {
          size += chunk.length;
          if (size > maxBodyBytes) {
            tooLarge = true;
            // Stop reading instead of continuing to drain the upload (a local
            // client could otherwise keep the collector busy with an arbitrarily
            // large body even though the limit was already exceeded), but do NOT
            // call request.destroy(): for a real socket that also tears down the
            // response's shared connection before the 413 can be written (see the
            // JSDoc above). `break` alone still stops buffering and releases the
            // request object without touching the socket.
            break;
          }
          chunks.push(chunk);
        }
      })(),
      timeout,
    ]);
  } catch (error) {
    // A timed-out incomplete body is reported as 408 before any other
    // classification so the caller can free the provisional /session slot.
    if (timedOut) throw new RequestError('request_body_timeout', 408, { closeConnection: true });
    // Defense in depth: if some other failure races with the oversize break
    // above, still classify it as the deterministic 413 limit violation
    // rather than a 400-class abort, so an oversized upload is always
    // reported as body_too_large.
    if (tooLarge) throw new RequestError('body_too_large', 413, { closeConnection: true });
    // Client disconnect / stream reset is not a server fault; map to a
    // structured RequestError so the handler does not log request.failed and
    // respond with 500 internal_error when a response can still be written.
    if (error instanceof RequestError) throw error;
    const code = error?.code;
    if (code === 'ECONNRESET' || code === 'EPIPE' || code === 'ABORT_ERR' || error?.name === 'AbortError') {
      throw new RequestError('request_aborted', 400);
    }
    // Unmatched stream errors may indicate a server-side bug; keep a structured
    // 400 response for the client but retain stderr visibility (previously 500).
    process.stderr.write(
      `${JSON.stringify({ level: 'error', event: 'request.body_read_failed', reason: code || error?.message || String(error) })}\n`,
    );
    throw new RequestError('request_failed', 400);
  } finally {
    clearTimeout(timer);
  }

  if (tooLarge) throw new RequestError('body_too_large', 413, { closeConnection: true });

  try {
    const value = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
      throw new RequestError('invalid_json_object');
    }
    return value;
  } catch (error) {
    if (error instanceof RequestError) throw error;
    throw new RequestError('invalid_json');
  }
};

const normalizeSessionName = (value) => {
  if (typeof value !== 'string') return 'debug';
  const normalized = value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 48);
  return normalized || 'debug';
};

const safeTokenEqual = (actual, expected) => {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  const actualBuffer = Buffer.from(actual);
  const expectedBuffer = Buffer.from(expected);
  return (
    actualBuffer.length === expectedBuffer.length && timingSafeEqual(actualBuffer, expectedBuffer)
  );
};

const bearerToken = (request) => {
  const authorization = request.headers.authorization;
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) return undefined;
  return authorization.slice('Bearer '.length);
};

// Single choke point for every authenticated, evidence-mutating path: the
// server-wide launch token gates /session and the per-session token gates
// /log. Routing both through one function (instead of an inline
// safeTokenEqual + sendJson pair at each call site) means a future
// authenticated endpoint cannot add its own check and forget the
// timing-safe comparison or the 401 response shape.
//
// There is no multi-tenant/client_id model here: this collector is a
// single-operator, loopback-only server bound to one projectRoot per
// process (see isAllowedHost). The per-session token — 256 bits of random
// entropy, generated in /session and required by every subsequent /log call
// for that session — is the actual scoping boundary between concurrent
// sessions, and this function is what enforces it uniformly.
const authorizeRequest = (response, suppliedToken, expectedToken) => {
  if (safeTokenEqual(suppliedToken, expectedToken)) return true;
  sendJson(response, 401, { error: 'unauthorized' });
  return false;
};

const isLoopbackAddress = (address) => {
  if (typeof address !== 'string') return false;
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1';
};

const isAllowedHost = (request) => {
  // The Host header is client-controlled and alone cannot prove the TCP peer
  // is loopback. Require the socket's remote address to be a loopback address
  // first, so a remote client cannot bypass the guard by sending a localhost
  // Host header when a caller binds the exported server to a non-loopback
  // interface.
  if (!isLoopbackAddress(request.socket.remoteAddress)) return false;
  const port = request.socket.localPort;
  const host = request.headers.host;
  // IPv4, localhost, and bracketed IPv6 loopback authorities are accepted.
  // Node HTTP clients targeting ::1 send Host: [::1]:<port>.
  if (
    host === `127.0.0.1:${port}`
    || host === `localhost:${port}`
    || host === `[::1]:${port}`
  ) {
    return true;
  }
  // Conforming HTTP clients omit the default port on HTTP/80, so Host is
  // `127.0.0.1` / `localhost` / `[::1]` without `:80` (Codex #4781637950).
  if (port === 80) {
    return host === '127.0.0.1' || host === 'localhost' || host === '[::1]';
  }
  return false;
};

// Reject a path that is a symlink (fail-closed), tolerating ENOENT (the path
// is about to be created). Used for both the .debug directory and the
// collector_token file so the guard has one owner. Implementation shared with
// PR closeout evidence writers via pr_closeout_fs.js.
const assertNotSymlink = async (target, label) => {
  await assertNotSymlinkShared(target, label);
};

// Reject a pre-existing path that is not a private regular file: a hard link
// (nlink > 1) shares its inode with another file, so truncating the path would
// clobber that outside file through the link, and a non-regular entry (FIFO,
// device, directory) cannot safely receive token material. ENOENT is
// tolerated because the path is about to be created.
const assertPrivateRegularFile = async (target, label) => {
  try {
    const info = await lstat(target);
    if (!info.isFile() || info.nlink > 1) throw new Error(label);
  } catch (error) {
    if (error.message === label) throw error;
    if (error.code !== 'ENOENT') throw error;
  }
};

// Open a path without following a symlinked final component: writeFile and
// appendFile follow symlinks, while O_NOFOLLOW rejects one with ELOOP at open
// time. O_NONBLOCK keeps a FIFO at the path from parking a libuv worker (the
// open then fails with ENXIO when no reader is attached); it has no effect on
// regular files. Shared openNoFollow lives in pr_closeout_fs.js; this wrapper
// always adds O_NONBLOCK for the collector's FIFO safety invariant.
const openNoFollow = async (target, flags, mode) => {
  const nonBlock = constants.O_NONBLOCK || 0;
  return openNoFollowShared(target, flags | nonBlock, mode);
};

// Synchronous sibling of openNoFollow for code that must run inside a
// process 'exit' listener, where awaits are impossible. Reuses the shared
// openNoFollowFlagAttempts ladder so O_NOFOLLOW/O_NONBLOCK degrade exactly
// like the async version on platforms that lack or reject them (both are
// undefined on Windows, collapsing the ladder to plain flags). Callers must
// still run an lstat-based guard first as the primary check -- the same
// contract the async wrapper documents (CodeRabbit discussion_r3652923124).
const openNoFollowSync = (target, flags, mode) => {
  // Same fail-closed flags guard the async openNoFollow enforces: a
  // non-integer would silently coerce through `|` in the attempt ladder and
  // defeat the no-follow intent instead of throwing.
  if (!Number.isInteger(flags)) {
    throw new TypeError('openNoFollowSync requires numeric fs.constants flags.');
  }
  const attempts = openNoFollowFlagAttempts(flags, constants.O_NOFOLLOW || 0, constants.O_NONBLOCK || 0);
  const unsupported = (code) => ['EINVAL', 'ENOTSUP', 'EOPNOTSUPP'].includes(code);
  let lastError;
  for (let i = 0; i < attempts.length; i += 1) {
    try {
      return openSync(target, attempts[i], mode);
    } catch (error) {
      lastError = error;
      if (i >= attempts.length - 1 || !unsupported(error?.code)) throw error;
    }
  }
  throw lastError;
};

// True iff an already-realpath'd candidate still resolves strictly inside an
// already-realpath'd root: reject an exact match (the candidate IS the root,
// never valid for a file that must live under it), `..`, any `../`-prefixed
// relative path, and any absolute `path.relative` result (a different drive
// on Windows). Comparing resolved paths through path.relative -- rather than
// a string-prefix check -- also refuses a sibling that merely shares a
// prefix, e.g. root `/a/b` vs candidate `/a/b-evil`.
//
// This is the shared "did the filesystem move out from under an earlier
// trust decision" check used everywhere a path is re-verified after a window
// where it could have been mutated: the /session handler's .debug escape
// check, appendSessionEvent's post-open session-log check, and the startup
// token-file post-open check in main() (see the comment there for why the
// parent directory, not just the final path component, needs this).
const isInsideRoot = (resolvedRoot, candidateRealPath) => {
  const rel = path.relative(resolvedRoot, candidateRealPath);
  return rel !== '' && rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel);
};

const configureOrigin = (request, response, allowedOrigins) => {
  const origin = request.headers.origin;
  if (origin === undefined) return true;
  if (!allowedOrigins.has(origin)) return false;
  response.setHeader('Access-Control-Allow-Origin', origin);
  response.setHeader('Vary', 'Origin');
  return true;
};

// Append a serialized event to a session log without trusting the recorded
// path. The debugged project can mutate .debug after the session is created,
// so a path-based append would follow a swapped symlink or parent directory
// outside projectRoot, or block on a FIFO. The descriptor is opened with
// no-follow semantics and must still be the original regular file before any
// bytes are written; identity is checked by dev/ino plus creation birth time
// and the exact byte count this server has written, because POSIX filesystems
// can recycle a just-freed inode for a deleted-and-recreated log. Every
// replacement shape fails closed with the same structured conflict.
//
// Concurrent /log requests for the same session are serialized on
// session.appendChain so the size check, write, and bytesWritten update cannot
// race each other (a parallel append would otherwise grow the file while a
// second request still holds a stale identity.bytesWritten and false-positive
// session_log_replaced).
const appendSessionEvent = (session, serializedEvent) => {
  const previous = session.appendChain || Promise.resolve();
  const run = previous.catch(() => {}).then(async () => {
    let handle;
    try {
      handle = await openNoFollow(session.logFile, constants.O_WRONLY | constants.O_APPEND);
    } catch (error) {
      // EISDIR: POSIX reports a directory swap as EISDIR, Windows as EPERM
      // (or EACCES on some setups) when a path is opened for writing. Any of
      // these means the path no longer names our regular session file, so
      // fail closed with the same structured conflict instead of a 500.
      if (['ELOOP', 'ENXIO', 'ENOENT', 'ENOTDIR', 'EISDIR', 'EPERM', 'EACCES'].includes(error?.code)) {
        throw new RequestError('session_log_replaced', 409);
      }
      throw error;
    }
    try {
      const info = await handle.stat();
      const identity = session.logFileIdentity;
      // dev/ino can survive a delete+recreate through inode reuse, so also
      // require the recorded birth time (when the filesystem reports one on
      // both sides) and exactly the byte count this server has appended — a
      // replacement file starts with different content or an empty size.
      const sameBirth = !identity.birthtimeMs || !info.birthtimeMs
        || info.birthtimeMs === identity.birthtimeMs;
      // nlink > 1 means the session log was hard-linked to another path after
      // /session; the token/artifact writers already fail closed on that shape.
      if (
        !info.isFile() || !identity
        || info.nlink > 1
        || info.dev !== identity.dev || info.ino !== identity.ino
        || !sameBirth
        || info.size !== identity.bytesWritten
      ) {
        throw new RequestError('session_log_replaced', 409);
      }
      // Re-verify the opened log still resolves inside the project even if the
      // original .debug directory was renamed out and replaced with a symlink
      // to an outside path (inode can still match the moved tree).
      if (identity.projectRootReal) {
        let realLog;
        try {
          realLog = await realpath(session.logFile);
        } catch {
          throw new RequestError('session_log_replaced', 409);
        }
        if (!isInsideRoot(identity.projectRootReal, realLog)) {
          throw new RequestError('session_log_replaced', 409);
        }
      }
      await handle.writeFile(serializedEvent, 'utf8');
      identity.bytesWritten += Buffer.byteLength(serializedEvent, 'utf8');
    } finally {
      await handle.close();
    }
  });
  session.appendChain = run;
  return run;
};

// --- Collector-side secret redaction (spec:
// docs/superpowers/specs/2026-08-05-collector-redaction-design.md) ---

// Escape the regex meta-characters in a literal needle so it matches as a
// verbatim substring inside a combined RegExp alternation. Mirrors the
// escapeRegex helper used by the closeout signal scanner.
const escapeRegExp = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

// Compile a needle list into ONE alternation RegExp and cache it by the
// replacements array reference. The list is rebuilt only on registerToken
// (once per session mint), but applyReplacements runs once per event string
// AND once per object key on every authenticated /log append, so a single
// combined scan (one engine pass over the text) replaces one full rescan per
// needle variant. At the default 512-token cap (~7k variants) that turns
// millions of String.replaceAll comparisons per 64 KB event into one match.
// Needles are sorted longest-first (buildSecretReplacements guarantees this):
// in a leftmost alternation the first alternative to match at a position wins,
// so a longer needle must precede a shorter overlapping one (e.g.
// "supersecret" before "super") or the shorter would consume its span first.
// Every needle shares the single replacement '[REDACTED]'; if a caller ever
// supplied mixed replacements, this fast path is bypassed for the per-needle
// reduce path that honors each pair individually.
const combinedScannerCache = new WeakMap();
// Sentinel cached for a replacements list that cannot use a combined scanner
// (empty, or mixed replacement values): distinguishes "cached as not eligible"
// from "not yet cached" (undefined), so the uniformity scan never repeats.
const NO_COMBINED_SCANNER = Symbol('no-combined-scanner');
const getCombinedScanner = (replacements) => {
  if (replacements.length === 0) return null;
  // Cache lookup FIRST: applyReplacements runs once per string/key on every
  // /log event, so the uniformity scan must not repeat O(#needles) work once
  // the combined regex is built. The cache is keyed by the replacements array
  // reference (rebuilt only on registerToken), so a hit is a single WeakMap
  // lookup with no per-needle iteration.
  const cached = combinedScannerCache.get(replacements);
  if (cached) return cached === NO_COMBINED_SCANNER ? null : cached;
  // All production needles map to '[REDACTED]'; mixed replacements would make
  // a single replacement ambiguous, so fall back to the per-needle path. This
  // uniformity scan runs at most once per replacements list (then cached).
  const firstReplacement = replacements[0][1];
  if (!replacements.every(([, replacement]) => replacement === firstReplacement)) {
    combinedScannerCache.set(replacements, NO_COMBINED_SCANNER);
    return null;
  }
  // Pre-sorted longest-first by buildSecretReplacements; re-sort defensively
  // so a caller-built list cannot break the longest-match-first guarantee.
  const pattern = replacements
    .map(([needle]) => needle)
    .sort((left, right) => right.length - left.length)
    .map(escapeRegExp)
    .join('|');
  const scanner = { replacement: firstReplacement, regex: new RegExp(pattern, 'g') };
  combinedScannerCache.set(replacements, scanner);
  return scanner;
};

// Apply an already-built [needle, replacement] list to one string. The list
// must be sorted longest-first (buildSecretReplacements guarantees this):
// that prevents a shorter needle from consuming a longer needle's span
// first. It does NOT prevent a needle from matching text inserted by an
// earlier replacement (e.g. a secret whose value is literally "REDACTED"
// re-matches inside "[REDACTED]") — that direction can only over-redact,
// never reveal. Matching is case-sensitive, same as the closeout streaming
// redactor's default. Longest-first ordering is a hard precondition for
// callers that build their own list.
const applyReplacements = (text, replacements) => {
  const scanner = getCombinedScanner(replacements);
  if (scanner) return text.replace(scanner.regex, scanner.replacement);
  return replacements.reduce(
    (current, [needle, replacement]) => current.replaceAll(needle, replacement),
    text,
  );
};

// Deep-walk a parsed /log event and redact every string it contains — leaf
// values, array items, and object KEYS (a client could use a secret as a
// key). Input always comes from JSON.parse, so only plain objects, arrays,
// strings, numbers, booleans, and null occur, and cycles are impossible.
// Rebuilds containers instead of mutating, so a failure part-way can never
// leave a half-redacted event that later gets persisted. When two sibling
// keys collide after redaction (or a redacted key collides with a literal
// one), the later entry is suffixed deterministically ([REDACTED]#2, ...)
// rather than silently overwriting the earlier entry. Entries are installed
// with Object.defineProperty rather than plain assignment: JSON.parse
// produces "__proto__" as an ordinary own enumerable property, but
// `output[key] = value` would instead invoke the inherited
// Object.prototype.__proto__ setter — silently dropping the entry from the
// output and repointing the rebuilt object's prototype. defineProperty
// always creates/overwrites an own data property regardless of the key's
// name, so "__proto__" round-trips like any other key.
// An explicit depth bound (REDACTION_MAX_DEPTH) makes the fail-closed path
// for hostile nesting deterministic: instead of relying on whichever native
// stack (the walk itself or a later JSON.stringify) exhausts first — which
// varies by platform stack size and Node version — input deeper than the
// bound throws a defined error that redactEventForAppend maps to a single
// documented code. 64 is far above any legitimate event shape (real /log
// events nest a handful of levels) while staying well clear of stack limits.
const REDACTION_MAX_DEPTH = 64;
const redactEventValue = (value, replacements, depth = 0) => {
  if (depth > REDACTION_MAX_DEPTH) throw new Error('redaction_depth_exceeded');
  if (typeof value === 'string') return applyReplacements(value, replacements);
  if (Array.isArray(value)) return value.map((item) => redactEventValue(item, replacements, depth + 1));
  if (value && typeof value === 'object') {
    const output = {};
    for (const [key, entry] of Object.entries(value)) {
      let redactedKey = applyReplacements(key, replacements);
      if (Object.hasOwn(output, redactedKey)) {
        let suffix = 2;
        while (Object.hasOwn(output, `${redactedKey}#${suffix}`)) suffix += 1;
        redactedKey = `${redactedKey}#${suffix}`;
      }
      Object.defineProperty(output, redactedKey, {
        value: redactEventValue(entry, replacements, depth + 1),
        writable: true,
        enumerable: true,
        configurable: true,
      });
    }
    return output;
  }
  return value;
};

// Fail-closed wrapper used by the /log handler: any walk failure rejects the
// event (nothing is persisted) instead of falling back to raw evidence.
const redactEventForAppend = (event, replacements) => {
  try {
    return redactEventValue(event, replacements);
  } catch {
    throw new RequestError('log_redaction_failed', 500);
  }
};

// Owns the needle list for one collector process. `tokens` is an append-only
// registry (launch token first, then every minted session token — retired
// sessions' tokens deliberately stay registered so a stale token in a later
// event body still redacts). Rebuilds derive entirely from the registry
// (push-then-rebuild in the /session handler), so concurrent rebuilds are
// idempotent and last-writer-wins can never drop a concurrent session's
// token. Tokens enter buildSecretReplacements as explicitly-named synthetic
// env entries, which grants them full encoded-variant expansion with no
// minimum-length filter and requires no change to the reviewed closeout
// module. `envSnapshot` is copied once at construction (not re-read on each
// rebuild), so a caller mutating the object it passed in — or live
// `process.env` — after construction cannot change the needle set out from
// under an already-built context. The synthetic name prefix is derived to
// provably avoid colliding with any real env var name already in the
// snapshot: a literal `__COLLECTOR_TOKEN_0` in the environment must not
// shadow (and thereby un-redact) either that real value or a token
// registered under the same index. The registry is capped (default 512
// tokens per process) so a client looping failed /session calls cannot grow
// rebuild cost at request rate; exceeding the cap throws and the /session
// handler must treat that as fail-closed (reject the mint) rather than
// degrade redaction or rebuild cost. Every token — supplied at construction
// or via registerToken — is validated as a non-empty string; silently
// accepting anything else would register a token that can never actually
// redact, i.e. a fail-open hole. Misconfigured option inputs (names, env
// snapshot, token list, maxTokens) throw rather than silently weakening
// redaction or disabling the registry cap.
const createRedactionContext = (envSnapshot, explicitNames, initialTokens, { maxTokens = 512 } = {}) => {
  if (!Array.isArray(explicitNames)) throw new Error('invalid_redaction_names');
  // Validate maxTokens before either token-limit comparison: a non-integer or
  // sub-1 value (e.g. NaN passed via `redactionMaxTokens: Number(envVar)`)
  // makes both `length > maxTokens` and `length >= maxTokens` evaluate to
  // false, growing the registry without bound and disabling the cap that
  // bounds per-event redaction cost. Reject fail-closed, matching the other
  // option-input validations.
  if (!Number.isInteger(maxTokens) || maxTokens < 1) throw new Error('invalid_redaction_max_tokens');
  if (envSnapshot === null || typeof envSnapshot !== 'object' || Array.isArray(envSnapshot)) {
    throw new Error('invalid_redaction_env');
  }
  if (!Array.isArray(initialTokens)) throw new Error('invalid_redaction_tokens');
  const snapshot = { ...envSnapshot };
  for (const initial of initialTokens) {
    if (typeof initial !== 'string' || initial.length === 0) {
      throw new Error('invalid_redaction_token');
    }
  }
  if (initialTokens.length > maxTokens) throw new Error('redaction_token_registry_full');
  const tokens = [...initialTokens];
  // Keep prepending underscores until no real env var name in the snapshot
  // starts with the candidate prefix, so synthetic names can never collide
  // with (and thereby shadow) an actual environment variable.
  let syntheticPrefix = '__COLLECTOR_TOKEN_';
  while (Object.keys(snapshot).some((key) => key.startsWith(syntheticPrefix))) {
    syntheticPrefix = `_${syntheticPrefix}`;
  }
  let replacements;
  const rebuild = () => {
    const synthetic = {};
    const syntheticNames = [];
    tokens.forEach((tokenValue, index) => {
      const name = `${syntheticPrefix}${index}`;
      synthetic[name] = tokenValue;
      syntheticNames.push(name);
    });
    replacements = buildSecretReplacements(
      { ...snapshot, ...synthetic },
      [...explicitNames, ...syntheticNames],
    );
  };
  rebuild();
  return {
    registerToken(tokenValue) {
      if (typeof tokenValue !== 'string' || tokenValue.length === 0) {
        throw new Error('invalid_redaction_token');
      }
      if (tokens.length >= maxTokens) throw new Error('redaction_token_registry_full');
      tokens.push(tokenValue);
      rebuild();
    },
    replacements: () => replacements,
    // Cardinality only (never a token value); used for the /health headroom
    // fields and the single 80%-threshold warning, so an operator can restart
    // the collector before the lifetime cap starts refusing mints.
    tokenCount: () => tokens.length,
    maxTokens: () => maxTokens,
  };
};

// Valid hypothesis lifecycle statuses (spec:
// docs/superpowers/specs/2026-08-06-hypothesis-endpoint-design.md). Any
// status may follow any status — the append-only log preserves the audit
// trail; only the vocabulary is fixed.
const HYPOTHESIS_STATUSES = new Set(['OPEN', 'CONFIRMED', 'REJECTED', 'INCONCLUSIVE']);

/**
 * Build (but do not start) the loopback-only debug-session HTTP collector.
 * Every request is gated by `isAllowedHost` (TCP peer must be loopback, Host
 * header must match) before any route logic runs. Routes: `GET /health`
 * (unauthenticated identity probe), `POST /session` (requires the launch
 * `token`, creates a session and its append-only NDJSON log under
 * `<projectRoot>/.debug`), `POST /log` (requires that session's own token —
 * see authorizeRequest — and appends one event line after fail-closed
 * known-secret redaction; see createRedactionContext), `POST /hypothesis`
 * (launch token; appends one hypothesis lifecycle line through the same
 * redaction and append path), and `GET /sessions/:id/logs` (launch token;
 * filtered verbatim NDJSON read of a live session's log).
 * The returned server exposes `collectorToken`/`collectorInstanceId`/
 * `collectorProjectHash` read-only properties for callers that built it with
 * a generated token; `collectorProjectHash` is what main()'s EADDRINUSE
 * handler compares against a probed instance's reported `project_hash` to
 * tell "the same collector already running" apart from "a different
 * project's collector occupying this port" (see probeServer).
 * @param {object} [options]
 * @param {string} [options.projectRoot] - directory whose `.debug/` subdir holds session logs; defaults to cwd.
 * @param {string} [options.token] - launch token required by POST /session; defaults to a fresh random one.
 * @param {string} [options.instanceId] - identity returned by /health and used by probeServer; defaults to random hex.
 * @param {string[]} [options.allowedOrigins] - browser Origins allowed to receive CORS headers; the Host/loopback check applies regardless.
 * @param {object} [options.limits] - overrides for DEFAULT_LIMITS (maxBodyBytes, bodyTimeoutMs, maxSessions, sessionIdleTimeoutMs, maxEventsPerSession, maxTotalBytes).
 * @param {NodeJS.ProcessEnv} [options.redactionEnv] - env snapshot the redaction needle list is built from; defaults to a copy of process.env taken at build time.
 * @param {string[]} [options.redactionNames] - extra env-var names always redacted regardless of length (DEBUG_REDACT_NAMES in the CLI).
 * @param {number} [options.redactionMaxTokens] - lifetime cap on registered tokens (launch + every session mint); at the cap further mints fail closed with session_registry_full. Default 512 bounds worst-case per-event redaction cost.
 * @returns {import('node:http').Server} an unstarted HTTP server; call `.listen()`.
 */
const createDebugServer = ({
  projectRoot = process.cwd(),
  token = randomBytes(32).toString('base64url'),
  instanceId = randomBytes(16).toString('hex'),
  allowedOrigins = [],
  limits = {},
  redactionEnv = { ...process.env },
  redactionNames = [],
  redactionMaxTokens = 512,
} = {}) => {
  const resolvedProjectRoot = path.resolve(projectRoot);
  // Canonical identity: realpath + Windows case fold so a symlink spelling
  // and its target hash to the same project_hash (already_running, not
  // port_in_use_by_other_process).
  let canonicalProjectRoot = resolvedProjectRoot;
  try {
    canonicalProjectRoot = realpathSync(resolvedProjectRoot);
  } catch {
    // Missing path: keep lexical resolve for first-run startup.
  }
  if (process.platform === 'win32') {
    canonicalProjectRoot = canonicalProjectRoot.replace(/\\/g, '/').toLowerCase();
  }
  const logDir = path.join(resolvedProjectRoot, '.debug');
  // A one-way fingerprint of the canonical project root, keyed by a random
  // per-project salt (see readOrCreateProjectSalt above) so it cannot be
  // brute-forced from the unauthenticated /health response. /health must
  // never leak the raw path, but the EADDRINUSE probe in main() still needs
  // a way for two invocations to agree they mean the SAME project without
  // either being able to recover the other's path from what /health reports.
  const projectHash = createHmac('sha256', readOrCreateProjectSalt(logDir, resolvedProjectRoot)).update(canonicalProjectRoot).digest('hex');
  const sessions = new Map();
  const effectiveLimits = { ...DEFAULT_LIMITS, ...limits };
  // Fail-closed secret redaction for every persisted event. Built here so a
  // broken needle build prevents the collector from starting at all; the
  // launch token is registered from the first build.
  const redaction = createRedactionContext(redactionEnv, redactionNames, [token], {
    maxTokens: redactionMaxTokens,
  });
  // One structured line on FIRST cap exhaustion only: the terminal state is
  // otherwise invisible on the collector side (RequestError responses skip
  // the request.failed stderr line). Event name only — no captured data —
  // matching the file's opaque-error policy. The write is best-effort: a
  // broken/closed stderr (EPIPE, destroyed stream) must never turn an
  // otherwise-successful /session mint into an error response, so the signal
  // flag is set BEFORE the write and the write is guarded. "Attempted once"
  // semantics (rather than "written once") keep a permanently-broken stderr
  // from retrying on every subsequent mint.
  // process.stderr.write can fail two ways: a synchronous throw (destroyed
  // stream) and an asynchronous 'error' event (EPIPE on a piped stderr that
  // surfaces after the write returns). With no 'error' listener, the async
  // kind would crash the process as an uncaughtException. Attach a no-op
  // 'error' listener once so either failure mode is absorbed, and use the
  // write callback as a second net so a callback-reported error never throws.
  let stderrErrorListenerAttached = false;
  const writeStderrBestEffort = (line) => {
    if (!stderrErrorListenerAttached) {
      stderrErrorListenerAttached = true;
      // No-op listener: swallows async stream errors (EPIPE, etc.) so they
      // never become uncaughtException. Re-added only on the first call, so
      // adding is idempotent across the process lifetime.
      process.stderr.on('error', () => {});
    }
    try {
      process.stderr.write(line, () => {});
    } catch {
      // Observability only; never propagate a stream failure into /session.
    }
  };
  let redactionRegistryFullSignaled = false;
  const signalRegistryFull = () => {
    if (redactionRegistryFullSignaled) return;
    redactionRegistryFullSignaled = true;
    writeStderrBestEffort('{"level":"error","event":"redaction.registry_full"}\n');
  };
  // One structured warning the FIRST time the registry crosses 80% of the
  // lifetime cap, so an operator can restart the collector before mints start
  // failing (the cap is permanent until process restart; retired sessions keep
  // their tokens registered by design). Emitted from checkRegistryHeadroom()
  // right after every successful registerToken. Cardinality only — no token
  // values — matching the opaque-error policy. 80% bounds headroom for the
  // remaining 20% of slots at the configured cap (e.g. ~410 of 512). Like the
  // registry-full signal, the write is best-effort and the flag is set first.
  const REDACTION_REGISTRY_HEADROOM_THRESHOLD = 0.8;
  let redactionRegistryHeadroomSignaled = false;
  const checkRegistryHeadroom = () => {
    if (redactionRegistryHeadroomSignaled) return;
    const count = redaction.tokenCount();
    const cap = redaction.maxTokens();
    if (cap > 0 && count >= Math.ceil(cap * REDACTION_REGISTRY_HEADROOM_THRESHOLD)) {
      redactionRegistryHeadroomSignaled = true;
      writeStderrBestEffort('{"level":"warn","event":"redaction.registry_headroom","tokens":' +
        `${count},"max":${cap}}\n`);
    }
  };
  const sessionIdleTimeoutMs = Number.isFinite(effectiveLimits.sessionIdleTimeoutMs)
    && effectiveLimits.sessionIdleTimeoutMs >= 1
    ? effectiveLimits.sessionIdleTimeoutMs
    : DEFAULT_LIMITS.sessionIdleTimeoutMs;
  const originSet = new Set(allowedOrigins);
  let totalBytes = computeRetainedLogBytes(logDir);
  // Token-file persistence finishes after listen(); until then the collector
  // is not ready for already_running relaunch claims.
  let collectorReady = false;

  // Session logs deliberately remain on disk and continue to count toward the
  // aggregate byte cap; this only retires in-memory credentials after client
  // inactivity. A subsequent /log therefore gets unknown_session instead of
  // reviving an old bearer capability.
  const retireInactiveSessions = () => {
    const expiration = Date.now() - sessionIdleTimeoutMs;
    for (const [sessionId, session] of sessions) {
      if (!session.provisional && session.lastActivityAt <= expiration) {
        sessions.delete(sessionId);
      }
    }
  };

  const server = http.createServer(async (request, response) => {
    if (!isAllowedHost(request)) {
      sendJson(response, 421, { error: 'invalid_host' });
      return;
    }
    if (!configureOrigin(request, response, originSet)) {
      sendJson(response, 403, { error: 'origin_not_allowed' });
      return;
    }

    response.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    response.setHeader(
      'Access-Control-Allow-Headers',
      'Authorization, Content-Type, X-Debug-Session-Token',
    );

    if (request.method === 'OPTIONS') {
      response.writeHead(204);
      response.end();
      return;
    }

    // Parse the request target inside the caught section so a malformed
    // absolute target (e.g. `GET http://[ HTTP/1.1`) returns a fail-closed
    // 400/404 response instead of rejecting the async request handler
    // outside the JSON error path and terminating the collector under Node's
    // default unhandled-rejection behavior.
    let pathname;
    try {
      pathname = new URL(request.url, 'http://127.0.0.1').pathname;
    } catch (error) {
      sendJson(response, 400, { error: 'invalid_request_target' });
      return;
    }

    try {
      if (request.method === 'GET' && pathname === '/health') {
        sendJson(response, 200, {
          service: COLLECTOR_SERVICE,
          version: COLLECTOR_VERSION,
          instance_id: instanceId,
          project_hash: projectHash,
          ready: collectorReady,
          // Redaction registry headroom (cardinality only — never a token
          // value): a supervisor can alert before the lifetime cap starts
          // refusing mints. Both are 0-based counts of registered tokens vs
          // the cap; retired sessions keep their tokens registered by design.
          redaction_tokens: redaction.tokenCount(),
          redaction_max_tokens: redaction.maxTokens(),
        });
        return;
      }

      // Non-mutating launch-token proof for already_running relaunch checks.
      // The probe sends a fresh public challenge and verifies this HMAC proof
      // locally; it never transmits the bearer token to an unverified port
      // occupant (Codex #4781637950 / #4781645480).
      if (request.method === 'GET' && pathname === '/auth') {
        const challenge = new URL(request.url, 'http://127.0.0.1').searchParams.get('challenge');
        if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
          sendJson(response, 400, { error: 'invalid_auth_challenge' });
          return;
        }
        sendJson(response, 200, { proof: launchTokenProof(token, challenge) });
        return;
      }

      if (request.method === 'POST' && pathname === '/session') {
        if (!authorizeRequest(response, bearerToken(request), token)) return;
        retireInactiveSessions();
        if (sessions.size >= effectiveLimits.maxSessions) {
          throw new RequestError('session_limit_reached', 429);
        }

        // Reserve a provisional session slot BEFORE the awaited readJson so
        // two chunked /session requests that flush headers before sending
        // their bodies cannot both pass the maxSessions check while readJson
        // is pending. The slot is removed if any later step fails.
        const reservationId = `pending-${randomBytes(12).toString('hex')}`;
        sessions.set(reservationId, { eventCount: 0, logFile: null, sessionToken: null, provisional: true });
        let payload;
        try {
          payload = await readJson(request, effectiveLimits.maxBodyBytes, effectiveLimits.bodyTimeoutMs);
        } catch (error) {
          sessions.delete(reservationId);
          throw error;
        }
        const sessionId = `${normalizeSessionName(payload.name)}-${randomBytes(12).toString('hex')}`;
        const sessionToken = randomBytes(32).toString('base64url');
        const fileName = `debug-${sessionId}.log`;
        const logFile = path.join(logDir, fileName);
        sessions.delete(reservationId);
        // Re-check the session limit after the reservation is released because
        // a concurrent request may have finalized its own session in the window.
        if (sessions.size >= effectiveLimits.maxSessions) {
          throw new RequestError('session_limit_reached', 429);
        }
        sessions.set(sessionId, {
          eventCount: 0,
          lastActivityAt: Date.now(),
          logFile,
          sessionToken,
          provisional: true,
        });
        try {
          // Session setup runs to completion BEFORE the session token is
          // registered. registerToken consumes an append-only registry slot;
          // if it ran first (as it once did), a caller able to force any later
          // setup failure (debug_dir_not_directory, mkdir EPERM, ...) could
          // repeat /session and burn registry slots until
          // redaction_token_registry_full, permanently disabling new sessions
          // until restart. Registering in the successful path means only
          // tokens actually handed to a usable client consume slots. /log
          // refuses a provisional session with session_initializing, so the
          // token is still registered before the session can accept /log,
          // preserving the ordering invariant that a rebuild failure rejects
          // the session fail-closed.
          // Reject a symlinked, non-directory, or escaped .debug path before
          // writing session evidence. A regular *file* named .debug would make
          // mkdir throw ENOTDIR and surface as an unstructured 500; a
          // PR-controlled symlink could point outside projectRoot.
          try {
            const dirInfo = await lstat(logDir);
            if (dirInfo.isSymbolicLink()) throw new RequestError('debug_dir_is_symlink', 409);
            if (!dirInfo.isDirectory()) throw new RequestError('debug_dir_not_directory', 409);
          } catch (error) {
            if (error instanceof RequestError) throw error;
            if (error.code !== 'ENOENT') throw error;
          }
          try {
            await mkdir(logDir, { recursive: true });
          } catch (error) {
            // Race: path became a file/symlink between lstat and mkdir.
            if (['EEXIST', 'ENOTDIR', 'EPERM', 'EACCES'].includes(error?.code)) {
              throw new RequestError('debug_dir_not_directory', 409);
            }
            throw error;
          }
          const resolvedLogDir = await realpath(logDir);
          const resolvedRoot = await realpath(resolvedProjectRoot);
          if (!isInsideRoot(resolvedRoot, resolvedLogDir)) {
            throw new RequestError('debug_dir_escapes_root', 409);
          }
          // Re-lstat the real parent after realpath: openNoFollow only guards
          // the leaf name, so a TOCTOU swap of `.debug` for a symlink between
          // realpath and open would otherwise create the log outside the root.
          // Pin creation to the resolved absolute parent path and re-verify
          // containment on the created file before recording identity.
          try {
            const pinnedDirInfo = await lstat(resolvedLogDir);
            if (pinnedDirInfo.isSymbolicLink()) throw new RequestError('debug_dir_is_symlink', 409);
            if (!pinnedDirInfo.isDirectory()) throw new RequestError('debug_dir_not_directory', 409);
          } catch (error) {
            if (error instanceof RequestError) throw error;
            throw new RequestError('debug_dir_not_directory', 409);
          }
          const resolvedLogFile = path.join(resolvedLogDir, fileName);
          // Create the empty session log through a no-follow descriptor and
          // record its identity. /log re-opens this path for every event and
          // requires the opened file to still be the same regular file, so a
          // swapped symlink, parent directory, or FIFO under .debug cannot
          // redirect or block appends (see appendSessionEvent). dev/ino alone
          // is not enough: POSIX filesystems eagerly reuse a just-freed inode,
          // so a deleted-and-recreated log can present the SAME dev/ino. Bind
          // the creation-time birth time (where the filesystem reports one)
          // and the byte count this server has written — a replacement starts
          // life with a different birth time and unexpected content/size.
          const handle = await openNoFollow(
            resolvedLogFile,
            constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
            0o600,
          );
          try {
            const info = await handle.stat();
            if (!info.isFile()) throw new RequestError('session_log_not_regular', 409);
            // /log events are redacted only for KNOWN secrets (see
            // createRedactionContext); treat log contents as sensitive. The
            // 0600 mode above is a no-op against Windows' inherited DACL, so
            // another local
            // user with inherited access to a shared checkout could read this
            // log; establish a protected, current-user-only ACL before any
            // event can be appended (mirrors collector_token's own Windows
            // hardening).
            if (process.platform === 'win32') {
              try {
                // Async (execFile) variant, not the synchronous
                // protectWindowsPrivateFile: this runs inside the /session
                // HTTP request handler, and execFileSync would block the Node
                // event loop for up to the full 15s ACL timeout on every
                // session creation (UiTMS). The startup token path keeps the
                // sync variant where blocking is harmless.
                await protectWindowsPrivateFileAsync(resolvedLogFile);
              } catch {
                throw new RequestError('session_log_acl_failed', 500);
              }
              // protectWindowsPrivateFile re-resolves the path by name in a
              // separate PowerShell process; if the path was swapped between
              // handle.stat() above and that call returning, the ACL could
              // land on a different filesystem object than this handle. Fail
              // closed rather than trust an unverified file as protected.
              let postProtectInfo;
              try {
                postProtectInfo = await lstat(resolvedLogFile);
              } catch {
                throw new RequestError('session_log_escapes_root', 409);
              }
              if (!isSameFileIdentity(info, postProtectInfo)) {
                throw new RequestError('session_log_escapes_root', 409);
              }
            }
            let createdReal;
            try {
              createdReal = await realpath(resolvedLogFile);
            } catch {
              throw new RequestError('session_log_escapes_root', 409);
            }
            if (!isInsideRoot(resolvedRoot, createdReal)) {
              throw new RequestError('session_log_escapes_root', 409);
            }
            const createdParent = path.dirname(createdReal);
            if (createdParent !== resolvedLogDir) {
              // Case-normalization / trailing-separator platforms: compare via realpath.
              let parentReal;
              try {
                parentReal = await realpath(createdParent);
              } catch {
                throw new RequestError('session_log_escapes_root', 409);
              }
              if (parentReal !== resolvedLogDir) {
                throw new RequestError('session_log_escapes_root', 409);
              }
            }
            // Prefer the post-create real path so later /log opens do not walk
            // through a later-replaced `.debug` symlink intermediate.
            sessions.get(sessionId).logFile = createdReal;
            sessions.get(sessionId).logFileIdentity = {
              dev: info.dev,
              ino: info.ino,
              birthtimeMs: info.birthtimeMs,
              bytesWritten: 0,
              projectRootReal: resolvedRoot,
              logDirReal: resolvedLogDir,
            };
          } catch (error) {
            // Best-effort remove a partially created file that failed containment.
            try {
              await handle.close();
            } catch {
              // ignore
            }
            try {
              await unlink(resolvedLogFile);
            } catch {
              // ignore
            }
            throw error;
          }
          await handle.close();
          // Push-then-rebuild at the END of the successful setup path: the
          // token joins the append-only registry only once .debug validation,
          // directory creation, and the session log all succeeded, so only
          // tokens handed out to clients consume registry slots. Concurrent
          // mints still converge (whichever rebuild runs last includes every
          // registered token). A late failure here (registry cap or rebuild)
          // is caught below: the session is deleted and the mint rejected, but
          // the already-created session log file remains on disk (it was
          // written through a no-follow, contained descriptor and holds no
          // captured evidence yet, so leaving it is safe and consistent with
          // retireInactiveSessions keeping retired logs on disk).
          try {
            redaction.registerToken(sessionToken);
          } catch (error) {
            // redaction_token_registry_full is a permanent, restart-only
            // condition (the lifetime mint cap); everything else is a
            // transient rebuild failure a client may retry. Distinct codes
            // keep the two diagnosable; neither leaks captured data.
            if (error?.message === 'redaction_token_registry_full') {
              signalRegistryFull();
              throw new RequestError('session_registry_full', 500);
            }
            throw new RequestError('session_redaction_failed', 500);
          }
          // Warn once when the registry crosses 80% of the lifetime cap, so an
          // operator can restart before mints start failing. Runs only on a
          // successful registration (the cap check above threw otherwise).
          checkRegistryHeadroom();
          delete sessions.get(sessionId).provisional;
        } catch (error) {
          sessions.delete(sessionId);
          throw error;
        }
        sendJson(response, 201, {
          session_id: sessionId,
          session_token: sessionToken,
          log_file: `.debug/${fileName}`,
        });
        return;
      }

      if (request.method === 'POST' && pathname === '/log') {
        // Without this, a collector that only ever receives /log calls after
        // its one /session call (the normal usage pattern) never reclaims
        // idle sessions, defeating the idle-timeout accounting this function
        // exists for (see sessionIdleTimeoutMs above).
        retireInactiveSessions();
        const payload = await readJson(request, effectiveLimits.maxBodyBytes, effectiveLimits.bodyTimeoutMs);
        // /session returns snake_case keys (session_id, session_token) but
        // older docs and several SDKs use camelCase (sessionId, sessionToken).
        // Accept both shapes so a client that reuses the /session response
        // payload directly does not fail with unknown_session/unauthorized.
        const sessionId = payload.sessionId || payload.session_id;
        const session = typeof sessionId === 'string' ? sessions.get(sessionId) : undefined;
        if (!session) {
          sendJson(response, 404, { error: 'unknown_session' });
          return;
        }
        if (session.provisional) {
          sendJson(response, 425, { error: 'session_initializing' });
          return;
        }
        const suppliedToken =
          request.headers['x-debug-session-token'] || payload.sessionToken || payload.session_token;
        if (!authorizeRequest(response, suppliedToken, session.sessionToken)) return;
        if (typeof payload.msg !== 'string' || payload.msg.trim() === '') {
          throw new RequestError('invalid_message');
        }
        // Refresh after authentication and message validation, before the
        // awaited append, so concurrent allocation cannot retire a session
        // whose valid event is in flight.
        session.lastActivityAt = Date.now();
        if (session.eventCount >= effectiveLimits.maxEventsPerSession) {
          throw new RequestError('event_limit_reached', 429);
        }

        const event = { ts: new Date().toISOString(), msg: payload.msg };
        for (const key of ['data', 'hypothesisId', 'loc', 'runId']) {
          if (payload[key] === undefined) continue;
          // hypothesisId is the join key that POST /hypothesis lines and
          // sub-project B's filters/diff match on byte-exactly; trim string
          // values here and in /hypothesis so "  H1  " and "H1" cannot
          // silently become distinct hypotheses. 'type' is deliberately
          // absent from this allowlist: adding it would let the instrumented
          // app forge hypothesis lines (see the POST /hypothesis capability
          // split).
          event[key] = key === 'hypothesisId' && typeof payload[key] === 'string'
            ? payload[key].trim()
            : payload[key];
        }
        // Redact BEFORE serialization and BEFORE capacity reservation: a
        // redaction failure rejects the event with nothing persisted and no
        // reservation to roll back. Byte accounting below intentionally uses
        // post-redaction bytes ([REDACTED] may shrink or grow an event).
        const redactedEvent = redactEventForAppend(event, redaction.replacements());
        const serializedEvent = `${JSON.stringify(redactedEvent)}\n`;
        const eventBytes = Buffer.byteLength(serializedEvent);
        if (totalBytes + eventBytes > effectiveLimits.maxTotalBytes) {
          throw new RequestError('storage_limit_reached', 429);
        }

        // Reserve capacity before yielding so concurrent /log requests see
        // both the per-session event cap and the aggregate byte cap, then
        // roll the reservation back if the append fails. The append itself
        // re-validates the session log (see appendSessionEvent) because the
        // debugged project can mutate .debug between /session and /log.
        session.eventCount += 1;
        totalBytes += eventBytes;
        try {
          await appendSessionEvent(session, serializedEvent);
        } catch (error) {
          session.eventCount -= 1;
          totalBytes -= eventBytes;
          throw error;
        }
        sendJson(response, 202, { status: 'recorded' });
        return;
      }

      if (request.method === 'POST' && pathname === '/hypothesis') {
        // Hypotheses are agent/operator artifacts: they authenticate with the
        // LAUNCH token (the capability the operator already holds via
        // .debug/collector_token), never the per-session token — the
        // instrumented app keeps exactly one write capability: /log events.
        // Auth precedes the body read, like /session.
        if (!authorizeRequest(response, bearerToken(request), token)) return;
        retireInactiveSessions();
        const payload = await readJson(request, effectiveLimits.maxBodyBytes, effectiveLimits.bodyTimeoutMs);
        const sessionId = payload.sessionId || payload.session_id;
        const session = typeof sessionId === 'string' ? sessions.get(sessionId) : undefined;
        if (!session) {
          sendJson(response, 404, { error: 'unknown_session' });
          return;
        }
        if (session.provisional) {
          sendJson(response, 425, { error: 'session_initializing' });
          return;
        }
        if (typeof payload.hypothesisId !== 'string' || payload.hypothesisId.trim() === '') {
          throw new RequestError('invalid_hypothesis_id');
        }
        const hypothesisId = payload.hypothesisId.trim();
        if (!HYPOTHESIS_STATUSES.has(payload.status)) {
          throw new RequestError('invalid_hypothesis_status');
        }
        // Optional fields must be strings when present: silently dropping or
        // coercing a non-string would hide caller bugs (fail-open by another
        // name), so reject with a structured code instead.
        for (const key of ['title', 'note', 'runId']) {
          if (payload[key] !== undefined && typeof payload[key] !== 'string') {
            throw new RequestError('invalid_hypothesis_field');
          }
        }
        // Same refresh point as /log: after auth and validation, before the
        // awaited append, so concurrent retirement cannot race a valid write.
        session.lastActivityAt = Date.now();
        if (session.eventCount >= effectiveLimits.maxEventsPerSession) {
          throw new RequestError('event_limit_reached', 429);
        }
        // Server-stamped, allowlisted assembly mirrors /log: ts and type are
        // never client-controlled, and only known optional fields are copied.
        const line = {
          ts: new Date().toISOString(),
          type: 'hypothesis',
          hypothesisId,
          status: payload.status,
        };
        for (const key of ['title', 'note', 'runId']) {
          if (payload[key] !== undefined) line[key] = payload[key];
        }
        const redactedLine = redactEventForAppend(line, redaction.replacements());
        const serializedLine = `${JSON.stringify(redactedLine)}\n`;
        const lineBytes = Buffer.byteLength(serializedLine);
        if (totalBytes + lineBytes > effectiveLimits.maxTotalBytes) {
          throw new RequestError('storage_limit_reached', 429);
        }
        session.eventCount += 1;
        totalBytes += lineBytes;
        try {
          await appendSessionEvent(session, serializedLine);
        } catch (error) {
          session.eventCount -= 1;
          totalBytes -= lineBytes;
          throw error;
        }
        sendJson(response, 202, { status: 'recorded' });
        return;
      }

      const sessionLogsMatch = request.method === 'GET'
        ? pathname.match(/^\/sessions\/([A-Za-z0-9_-]+)\/logs$/)
        : null;
      if (sessionLogsMatch) {
        // Reads are a launch-token capability (see POST /hypothesis). The id
        // is used ONLY as a map key — client input never reaches filesystem
        // path construction, so there is no traversal surface.
        if (!authorizeRequest(response, bearerToken(request), token)) return;
        retireInactiveSessions();
        const session = sessions.get(sessionLogsMatch[1]);
        if (!session) {
          sendJson(response, 404, { error: 'unknown_session' });
          return;
        }
        if (session.provisional) {
          sendJson(response, 425, { error: 'session_initializing' });
          return;
        }
        // Fail-closed query parsing: unknown parameter names are rejected so
        // a typo cannot silently disable a filter and widen what is returned.
        const query = new URL(request.url, 'http://127.0.0.1').searchParams;
        const allowedParams = new Set(['hypothesisId', 'type', 'sinceTs', 'untilTs', 'runId', 'limit']);
        const seenParams = new Set();
        for (const name of query.keys()) {
          // Unknown names AND duplicates are rejected: a typo or a stray
          // repeated parameter must never silently change what is returned.
          if (!allowedParams.has(name) || seenParams.has(name)) {
            throw new RequestError('invalid_query');
          }
          seenParams.add(name);
        }
        const typeFilter = query.get('type') ?? 'all';
        if (!['all', 'event', 'hypothesis'].includes(typeFilter)) {
          throw new RequestError('invalid_query');
        }
        const parseBound = (name) => {
          const value = query.get(name);
          if (value === null) return undefined;
          const parsed = Date.parse(value);
          if (Number.isNaN(parsed)) throw new RequestError('invalid_query');
          return parsed;
        };
        const sinceTs = parseBound('sinceTs');
        const untilTs = parseBound('untilTs');
        let limit = effectiveLimits.maxEventsPerSession;
        const rawLimit = query.get('limit');
        if (rawLimit !== null) {
          if (!/^\d+$/.test(rawLimit) || Number(rawLimit) < 1) throw new RequestError('invalid_query');
          limit = Math.min(Number(rawLimit), effectiveLimits.maxEventsPerSession);
        }
        const hypothesisFilter = query.get('hypothesisId') ?? undefined;
        const runFilter = query.get('runId') ?? undefined;
        // Serialize the read on the same per-session chain as appends: no
        // append can interleave mid-read, so the identity check and the byte
        // window are consistent and a torn trailing line cannot be observed.
        // The identity discipline mirrors appendSessionEvent exactly.
        const previous = session.appendChain || Promise.resolve();
        // The chain must resolve to undefined (parity with appendSessionEvent):
        // resolving to the log text would leave session.appendChain retaining
        // the whole response body until the next append replaces it.
        let text;
        const run = previous.catch(() => {}).then(async () => {
          let handle;
          try {
            handle = await openNoFollow(session.logFile, constants.O_RDONLY);
          } catch (error) {
            if (['ELOOP', 'ENXIO', 'ENOENT', 'ENOTDIR', 'EISDIR', 'EPERM', 'EACCES'].includes(error?.code)) {
              throw new RequestError('session_log_replaced', 409);
            }
            throw error;
          }
          try {
            const info = await handle.stat();
            const identity = session.logFileIdentity;
            const sameBirth = !identity.birthtimeMs || !info.birthtimeMs
              || info.birthtimeMs === identity.birthtimeMs;
            if (
              !info.isFile() || !identity
              || info.nlink > 1
              || info.dev !== identity.dev || info.ino !== identity.ino
              || !sameBirth
              || info.size !== identity.bytesWritten
            ) {
              throw new RequestError('session_log_replaced', 409);
            }
            if (identity.projectRootReal) {
              let realLog;
              try {
                realLog = await realpath(session.logFile);
              } catch {
                throw new RequestError('session_log_replaced', 409);
              }
              if (!isInsideRoot(identity.projectRootReal, realLog)) {
                throw new RequestError('session_log_replaced', 409);
              }
            }
            // Read exactly the bytes this server wrote: bytesWritten bounds
            // the window, so appended-after or truncated content can never
            // slip in (size was already checked equal above).
            const buffer = Buffer.alloc(identity.bytesWritten);
            let offset = 0;
            while (offset < buffer.length) {
              const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
              if (bytesRead === 0) throw new RequestError('session_log_replaced', 409);
              offset += bytesRead;
            }
            text = buffer.toString('utf8');
          } finally {
            await handle.close();
          }
        });
        session.appendChain = run;
        await run;
        const matched = [];
        for (const rawLine of text.split('\n')) {
          if (!rawLine) continue;
          // Server-written lines always parse (they were JSON.stringify'd at
          // append time); a parse failure here would mean identity-checked
          // bytes changed underneath us and surfaces as internal_error.
          const parsed = JSON.parse(rawLine);
          // Lines WITHOUT type are events (spec definition). An unknown future
          // type must not be swept into ?type=event — it matches only type=all.
          const lineType = parsed.type === undefined ? 'event' : parsed.type;
          if (typeFilter !== 'all' && lineType !== typeFilter) continue;
          if (hypothesisFilter !== undefined && parsed.hypothesisId !== hypothesisFilter) continue;
          if (runFilter !== undefined && parsed.runId !== runFilter) continue;
          if (sinceTs !== undefined || untilTs !== undefined) {
            const lineTs = Date.parse(parsed.ts);
            if (Number.isNaN(lineTs)) continue;
            if (sinceTs !== undefined && lineTs < sinceTs) continue;
            if (untilTs !== undefined && lineTs > untilTs) continue;
          }
          matched.push(rawLine);
        }
        const tail = matched.slice(-limit);
        response.writeHead(200, { 'Content-Type': 'application/x-ndjson' });
        response.end(tail.length ? `${tail.join('\n')}\n` : '');
        return;
      }

      sendJson(response, 404, { error: 'not_found' });
    } catch (error) {
      if (error instanceof RequestError) {
        sendJson(response, error.status, { error: error.code }, error.closeConnection);
        return;
      }
      process.stderr.write(`${JSON.stringify({ level: 'error', event: 'request.failed' })}\n`);
      sendJson(response, 500, { error: 'internal_error' });
    }
  });

  Object.defineProperties(server, {
    collectorToken: { value: token },
    collectorInstanceId: { value: instanceId },
    collectorProjectHash: { value: projectHash },
    markCollectorReady: {
      value: () => {
        collectorReady = true;
      },
    },
  });
  return server;
};

/**
 * Ask whatever is listening on `port` (127.0.0.1) whether it is this same
 * collector, by hitting `/health` and checking the reported service name,
 * version, a well-formed instance_id, and a well-formed project_hash — never
 * assumed just because the port answers. Used from the EADDRINUSE path in
 * main() to tell "another instance of this collector is already up" apart
 * from "some unrelated process (or an attacker) is squatting on the port".
 * This only validates that project_hash is well-formed, NOT that it matches
 * any particular project: /health never leaks the raw projectRoot, and a
 * collector for a genuinely different project answers with a syntactically
 * valid but different hash. The caller is responsible for comparing the
 * returned project_hash against its own (see main()'s EADDRINUSE handler,
 * which compares it to `server.collectorProjectHash`) before treating this
 * as "the same collector already running" rather than "a different
 * collector occupying this port". Resolves to the parsed identity object on
 * a valid match, or `null` for any failure, timeout, malformed body, or
 * non-200/non-matching response — this never rejects.
 * @param {number} port
 * @param {{deadlineMs?: number}} [options]
 * @returns {Promise<{service: string, version: number, instance_id: string, project_hash: string, ready: boolean}|null>}
 */
const probeServer = (port, { deadlineMs = 2_000 } = {}) =>
  new Promise((resolve) => {
    let settled = false;
    let deadline;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      resolve(value);
    };
    const request = http.get(
      { hostname: '127.0.0.1', port, path: '/health', timeout: 500 },
      (response) => {
        let body = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => {
          body += chunk;
          if (body.length > 4_096) {
            // Destroy alone may only emit 'close' on some Node versions; settle
            // synchronously so the probe cannot stall the EADDRINUSE handler.
            request.destroy();
            finish(null);
          }
        });
        response.on('end', () => {
          if (response.statusCode !== 200) {
            finish(null);
            return;
          }
          try {
            const identity = JSON.parse(body);
            const valid =
              identity.service === COLLECTOR_SERVICE &&
              identity.version === COLLECTOR_VERSION &&
              typeof identity.instance_id === 'string' &&
              /^[a-f0-9]{32}$/.test(identity.instance_id) &&
              typeof identity.project_hash === 'string' &&
              /^[a-f0-9]{64}$/.test(identity.project_hash);
            // ready may be absent on older collectors; treat as not ready so
            // already_running cannot claim success before token persistence.
            if (valid) {
              finish({ ...identity, ready: identity.ready === true });
              return;
            }
            finish(null);
          } catch (error) {
            if (error instanceof SyntaxError) {
              finish(null);
              return;
            }
            finish(null);
          }
        });
        // Some abort paths emit only 'close' (no 'end'/'error'), so without
        // this listener the promise would stay pending and debug_server could
        // hang during EADDRINUSE handling instead of reporting already_running.
        response.on('close', () => finish(null));
        response.on('error', () => finish(null));
      },
    );
    request.on('timeout', () => {
      request.destroy();
      finish(null);
    });
    request.on('error', () => finish(null));
    request.on('close', () => finish(null));
    // Independent wall-clock deadline: the socket `timeout` above is an
    // inactivity timer, so a peer trickling a byte every <500ms resets it
    // forever and can pin the EADDRINUSE startup path for as long as it keeps
    // the response open. Settle null after a bounded period regardless of
    // ongoing traffic; unref so the timer itself cannot hold the process open.
    deadline = setTimeout(() => {
      request.destroy();
      finish(null);
    }, deadlineMs);
    deadline.unref();
  });

/**
 * Probe until the same-project collector reports ready (token persisted), or
 * until the wall-clock deadline elapses. Avoids already_running while the
 * first process is still mid token-file write after listen().
 * @param {number} port
 * @param {string} expectedProjectHash
 * @param {{delayMs?: number, deadlineMs?: number}} [options]
 */
const probeReadyCollector = async (
  port,
  expectedProjectHash,
  { delayMs = 50, deadlineMs = 10_000 } = {},
) => {
  const deadlineAt = Date.now() + deadlineMs;
  // Bounded by deadlineAt below, not by a fixed attempt count: a collector
  // that answers /health promptly with ready:false for longer than a handful
  // of delayMs sleeps (e.g. mid async claim or token-file work) must keep
  // being retried for the whole declared deadline. An attempt-count cap here
  // previously let the loop give up after ~20 * delayMs (~1s), long before a
  // responsive-but-not-ready peer had reached the 10s deadline, and the final
  // probe's result (still not ready) was reported as port_in_use_by_other_process.
  for (;;) {
    const remainingBeforeProbe = deadlineAt - Date.now();
    if (remainingBeforeProbe <= 0) return null;
    const identity = await probeServer(port, { deadlineMs: Math.min(2_000, remainingBeforeProbe) });
    if (identity && identity.project_hash === expectedProjectHash && identity.ready) {
      return identity;
    }
    if (identity && identity.project_hash !== expectedProjectHash) {
      return identity; // different project — caller maps to port_in_use
    }
    const remainingMs = deadlineAt - Date.now();
    if (remainingMs <= 0) return null;
    await new Promise((resolve) => setTimeout(resolve, Math.min(delayMs, remainingMs)));
  }
};

/**
 * Non-mutating proof that `token` is the peer collector's current launch
 * token. A random challenge is sent to the peer; the caller verifies an HMAC
 * proof locally, so a forged listener never receives the bearer credential.
 * Used before already_running so a replaced on-disk token cannot claim success
 * while /session would 401 (Codex #4781645480).
 * @param {number} port
 * @param {string} token
 * @returns {Promise<boolean>}
 */
const probeLaunchToken = (port, token) => new Promise((resolve) => {
  let settled = false;
  let deadline;
  const challenge = randomBytes(32).toString('base64url');
  const expectedProof = launchTokenProof(token, challenge);
  const finish = (value) => {
    if (settled) return;
    settled = true;
    clearTimeout(deadline);
    resolve(value);
  };
  const request = http.request(
    {
      hostname: '127.0.0.1',
      port,
      path: `/auth?challenge=${encodeURIComponent(challenge)}`,
      method: 'GET',
      headers: {
        Host: `127.0.0.1:${port}`,
      },
      timeout: 500,
    },
    (response) => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        body += chunk;
        if (body.length > 4_096) {
          request.destroy();
          finish(false);
        }
      });
      response.on('end', () => {
        if (response.statusCode !== 200) {
          finish(false);
          return;
        }
        try {
          const proof = JSON.parse(body)?.proof;
          finish(typeof proof === 'string' && safeTokenEqual(proof, expectedProof));
        } catch {
          finish(false);
        }
      });
      response.on('close', () => finish(false));
      response.on('error', () => finish(false));
    },
  );
  request.on('timeout', () => {
    request.destroy();
    finish(false);
  });
  request.on('error', () => finish(false));
  request.on('close', () => finish(false));
  // `timeout` is an inactivity timeout. A peer that continuously trickles
  // /auth bytes can reset it forever, pinning the EADDRINUSE path after the
  // health probe already succeeded. Bound total probe time independently.
  deadline = setTimeout(() => {
    request.destroy();
    finish(false);
  }, 2_000);
  deadline.unref();
  request.end();
});

// A well-formed completed collector_claim records three newline-separated
// fields: a positive integer port, a non-empty opaque instance ID, and a
// positive integer owner PID. Shared by the claim-acquisition grace check and
// the reclaim re-verification so both agree on what "a real claim" is.
const isCompleteClaimText = (text) => {
  if (typeof text !== 'string' || text.length === 0) return false;
  const lines = text.split(/\r?\n/);
  const port = Number(String(lines[0] || '').trim());
  const pid = Number(String(lines[2] || '').trim());
  return Number.isInteger(port) && port > 0
    && Boolean(String(lines[1] || '').trim())
    && Number.isInteger(pid) && pid > 0;
};

/**
 * Reclaim (or refuse to reclaim) a stale collector_claim after an O_EXCL
 * create observed EEXIST. Ports pr_closeout_workflow.js's identity-only lock
 * reclaim: the dev/ino/ctimeMs identity match that gates deletion has only
 * filesystem/clock resolution, so on a filesystem with rapid inode reuse a
 * peer that unlinked this stale claim and wrote its own successor can land on
 * the exact same inode with a same-millisecond ctimeMs collision. A bare
 * unlink would then delete that live successor (UkNET/UkXzk). Instead,
 * quarantine the entry under a private name first, then re-read it: only the
 * same stale record we already inspected (byte-for-byte, or -- when the
 * original was unreadable -- one that still fails to parse as a claim) is
 * deleted; anything else is a live successor that is restored to its original
 * path via a no-clobber link+unlink (or, when hard links are unsupported, an
 * equivalent O_CREAT|O_EXCL recreate) so this launch backs off instead.
 *
 * Errors are funneled to `collector_claim_contention` (ENOENT is a benign
 * "someone else already moved it" back-off), matching the bare-unlink branch
 * this replaces.
 *
 * @param {string} claimFile
 * @param {object} deps
 * @param {import('node:fs').Stats|null} deps.claimInfo  lstat captured before reclaim.
 * @param {string|null} deps.claimText  claim bytes captured before reclaim (null if unreadable).
 * @param {(target: string) => Promise<string|null>} deps.readClaimText  guarded re-reader.
 * @returns {Promise<'reclaimed'|'restored'|'backed-off'>}
 */
const reclaimStaleCollectorClaim = async (claimFile, {
  claimInfo,
  claimText,
  readClaimText,
  assertNotSymlinkFn = assertNotSymlink,
  lstatFn = lstat,
  renameFn = rename,
  linkFn = link,
  unlinkFn = unlink,
  sameIdentity = isSameLockIdentity,
  quarantineSuffix = () => randomBytes(8).toString('hex'),
  // No-clobber restore used when link() cannot run at all (see below): create
  // the destination the same way every claim is created, O_CREAT|O_EXCL, so a
  // fresh claim -- or a symlink -- already at claimFile fails this closed
  // with EEXIST instead of being silently overwritten the way rename() would.
  restoreClaimExclusiveFn = async (target, contents) => {
    const handle = await openNoFollow(target, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    try {
      await handle.writeFile(contents, 'utf8');
    } finally {
      await handle.close();
    }
  },
} = {}) => {
  try {
    await assertNotSymlinkFn(claimFile, 'collector_claim_is_symlink');
    // A null claimInfo means the up-front lstat already failed -- most likely
    // a concurrent launch already replaced the stale record -- so there is no
    // captured identity to re-verify against; do not delete blindly.
    if (!claimInfo) return 'backed-off';
    let currentClaimInfo;
    try {
      currentClaimInfo = await lstatFn(claimFile);
    } catch (error) {
      if (error?.code === 'ENOENT') return 'backed-off';
      throw error;
    }
    if (!sameIdentity(claimInfo, currentClaimInfo)) return 'backed-off';

    // Quarantine before deleting so a same-identity successor is isolated
    // under a private name rather than removed from the shared claim path.
    // A concurrent reclaimer that already renamed it away leaves ENOENT here;
    // this launch simply backs off and re-evaluates on the next attempt.
    const quarantinePath = `${claimFile}.reclaim-${process.pid}-${quarantineSuffix()}`;
    try {
      await renameFn(claimFile, quarantinePath);
    } catch (error) {
      if (error?.code === 'ENOENT') return 'backed-off';
      throw error;
    }

    // Re-verify the quarantined entry. It is the same stale record only when
    // its content is byte-for-byte what we inspected (or, when the original
    // was unreadable, when it still fails to parse as a claim). Anything else
    // is a live successor that collided on identity.
    let requarantinedText = null;
    try {
      requarantinedText = await readClaimText(quarantinePath);
    } catch {
      requarantinedText = null;
    }
    const stillSameStaleRecord = claimText !== null
      ? requarantinedText === claimText
      : !isCompleteClaimText(requarantinedText);

    if (!stillSameStaleRecord) {
      // Live successor misidentified as stale: restore it to the original name
      // without clobbering a third contender's fresh claim, then back off.
      try {
        await linkFn(quarantinePath, claimFile);
        await unlinkFn(quarantinePath);
      } catch (error) {
        if (error?.code === 'EEXIST') {
          // A third contender already created a fresh claim at claimFile while
          // this successor was quarantined; it is no longer needed here.
          await unlinkFn(quarantinePath).catch(() => {});
          return 'backed-off';
        }
        // Hard links are unavailable on some filesystems (FAT/exFAT, some
        // network mounts, certain Windows shares), where link() fails with
        // EPERM/ENOSYS/EXDEV rather than ENOENT/EEXIST. Without a fallback the
        // successor stays orphaned under the quarantine name while claimFile is
        // left empty for the next launch to wrongly claim (CodeRabbit UmlJJ).
        // A plain rename() restore would reopen that same hazard from the
        // other direction: rename() clobbers whatever now occupies claimFile,
        // so a third contender's fresh claim created while this successor sat
        // quarantined would be silently destroyed (Qodo Uod10). Recreate the
        // destination via restoreClaimExclusiveFn instead, which fails closed
        // with EEXIST against a fresh claim (or a planted symlink) rather than
        // overwriting it. A vanished quarantine entry re-throws the original
        // ENOENT and is funneled to a benign back-off by the outer catch.
        if (requarantinedText === null) {
          // No verified byte-for-byte content to recreate the destination
          // with (the quarantined entry became unreadable on re-read);
          // surface contention rather than fabricate a claim record.
          throw error;
        }
        try {
          await restoreClaimExclusiveFn(claimFile, requarantinedText);
        } catch (restoreError) {
          if (restoreError?.code === 'EEXIST') {
            // Same third-contender race as the link() EEXIST branch above,
            // just hit via the no-hard-link fallback path instead.
            await unlinkFn(quarantinePath).catch(() => {});
            return 'backed-off';
          }
          throw restoreError;
        }
        await unlinkFn(quarantinePath);
        return 'restored';
      }
      return 'restored';
    }

    await unlinkFn(quarantinePath);
    return 'reclaimed';
  } catch (error) {
    if (error?.code === 'ENOENT') return 'backed-off';
    throw new Error('collector_claim_contention');
  }
};

/**
 * Path-based release of a collector_claim this process owns, gated on the path
 * still identifying the exact inode whose descriptor was read and validated.
 * `releaseOwnedClaim` reads and ownership-checks the claim through an
 * O_NOFOLLOW descriptor, but that descriptor is closed before the unlink and
 * `unlinkSync` acts on the PATH: a peer that reclaims this (now stale) claim
 * and writes its own successor at claimFile between that read and this unlink
 * would otherwise have its live successor deleted, because the descriptor still
 * carried this process's own owner fields and the ownership check passed
 * (Codex Ummsi). Re-lstat the path and unlink only while it still matches the
 * read descriptor's identity (dev/ino/nlink/ctimeMs via isSameLockIdentity,
 * which also rejects an inode-reuse collision); a successor now at the path is
 * left intact. The residual lstat->unlink gap cannot be closed in pure Node
 * (no unlink-by-descriptor), but this narrows it from the whole read to a
 * single syscall pair.
 *
 * @param {string} claimFile
 * @param {import('node:fs').Stats|null} openedIdentity fstat of the validated descriptor.
 * @param {object} [deps]
 * @returns {boolean} whether the claim was unlinked.
 */
const unlinkOwnedClaimIfUnchanged = (claimFile, openedIdentity, {
  lstatSyncFn = lstatSync,
  unlinkSyncFn = unlinkSync,
  sameIdentity = isSameLockIdentity,
} = {}) => {
  if (!openedIdentity) return false;
  let currentInfo;
  try {
    currentInfo = lstatSyncFn(claimFile);
  } catch {
    return false;
  }
  if (!sameIdentity(openedIdentity, currentInfo)) return false;
  unlinkSyncFn(claimFile);
  return true;
};

const parseAllowedOrigins = (value) =>
  (value || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);

// DEBUG_REDACT_NAMES: comma-separated env-var names that must always be
// redacted from persisted events regardless of value length (the CLI-facing
// mirror of the closeout config's `names` opt-in).
const parseRedactNames = (value) => String(value ?? '')
  .split(',')
  .map((name) => name.trim())
  .filter(Boolean);

const main = () => {
  const [projectArgument] = process.argv.slice(2);
  if (projectArgument === '--help' || projectArgument === '-h') {
    process.stdout.write(
      'Usage: debug_server.js [project-path]\n\nStart the authenticated local debug log collector on port 8787.\n',
    );
    return;
  }

  const projectRoot = path.resolve(projectArgument || process.cwd());
  const port = Number(process.env.DEBUG_PORT || DEFAULT_PORT);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    process.stderr.write('{"level":"error","event":"startup.failed","reason":"invalid_port"}\n');
    process.exitCode = 1;
    return;
  }

  const token = randomBytes(32).toString('base64url');
  const server = createDebugServer({
    projectRoot,
    token,
    allowedOrigins: parseAllowedOrigins(process.env.DEBUG_ALLOWED_ORIGIN),
    redactionNames: parseRedactNames(process.env.DEBUG_REDACT_NAMES),
  });
  server.once('error', async (error) => {
    if (error.code === 'EADDRINUSE') {
      // Wait for the peer collector to finish token persistence before
      // claiming already_running; listen-only readiness is insufficient.
      const identity = await probeReadyCollector(port, server.collectorProjectHash);
      // A syntactically valid collector identity is not enough: this
      // collector is single-project (one projectRoot per process), so an
      // instance answering for a DIFFERENT project must not be reported as
      // "already running" for THIS invocation -- that would leave the
      // current project with neither a running collector nor a token file,
      // while silently pointing it at an unrelated project's session store.
      // Compare project_hash (a one-way fingerprint of projectRoot; see
      // createDebugServer) against this invocation's own hash before
      // concluding it is the same collector; a mismatch falls through to the
      // port_in_use_by_other_process failure below, same as no identity at all.
      if (identity && identity.project_hash === server.collectorProjectHash && identity.ready) {
        // ready is latched in the peer's memory after token persistence, but
        // the file can still be deleted/replaced afterward. The documented
        // client flow authorizes /session via `cat .debug/collector_token`, so
        // already_running without a usable token leaves the collector running
        // and unusable. Revalidate the on-disk token and authenticate it
        // against the peer before accepting the probe (Codex #4780351874 /
        // #4781366510).
        const tokenFile = path.join(projectRoot, '.debug', 'collector_token');
        // Read through openNoFollow (not path-based readFile): a TOCTOU
        // symlink swap between lstat and read would otherwise send arbitrary
        // file bytes as Authorization: Bearer … (CodeRabbit #4781498400).
        // Tokens are base64url(32 bytes) ≈ 43 chars; cap well above that.
        const MAX_LAUNCH_TOKEN_BYTES = 256;
        let tokenHandle;
        try {
          tokenHandle = await openNoFollow(tokenFile, constants.O_RDONLY);
          const tokenInfo = await tokenHandle.stat();
          if (
            !tokenInfo.isFile()
            || tokenInfo.nlink > 1
            || tokenInfo.size < 1
            || tokenInfo.size > MAX_LAUNCH_TOKEN_BYTES
          ) {
            throw new Error('collector_token_unavailable');
          }
          const tokenBuf = Buffer.alloc(tokenInfo.size);
          let tokenOffset = 0;
          while (tokenOffset < tokenInfo.size) {
            const { bytesRead } = await tokenHandle.read(
              tokenBuf,
              tokenOffset,
              tokenInfo.size - tokenOffset,
              tokenOffset,
            );
            if (bytesRead === 0) break;
            tokenOffset += bytesRead;
          }
          const diskToken = tokenBuf.subarray(0, tokenOffset).toString('utf8').trim();
          if (!diskToken || !(await probeLaunchToken(port, diskToken))) {
            throw new Error('collector_token_auth_failed');
          }
          // Close before process.exit: an async finally would not run after
          // the force-exit used for the EADDRINUSE hang path.
          await tokenHandle.close().catch(() => {});
          tokenHandle = null;
          // Sync write + force-exit: piped stdout.write can be truncated by
          // process.exit, and a failed-listen Server handle can park the
          // process on some Node/Windows builds (CodeRabbit #4781360793 /
          // Node 24 windows hang).
          writeFdSync(1, `${JSON.stringify({
            status: 'already_running',
            port,
            service: identity.service,
            version: identity.version,
            instance_id: identity.instance_id,
          })}\n`);
          process.exit(0);
        } catch {
          if (tokenHandle) await tokenHandle.close().catch(() => {});
          writeFdSync(2, `${JSON.stringify({
            level: 'error',
            event: 'startup.failed',
            reason: 'already_running_token_unavailable',
          })}\n`);
          process.exit(1);
        }
      }
    }
    writeFdSync(2, `${JSON.stringify({
      level: 'error',
      event: 'startup.failed',
      reason: error.code === 'EADDRINUSE' ? 'port_in_use_by_other_process' : 'listen_failed',
    })}\n`);
    process.exit(1);
  });
  server.listen(port, '127.0.0.1', async () => {
    // Persist the runtime collector_token to a 0600 file under .debug/ and
    // print only the file path in stdout. stdout is captured by wrappers as
    // a structured startup line and is routinely logged, piped, or
    // persisted, so we never print the token itself there; instead the
    // documented workflow reads it via `export COLLECTOR_TOKEN=$(cat
    // .debug/collector_token)`. The token also stays available
    // programmatically via the server object's collectorToken property.
    const debugDir = path.join(projectRoot, '.debug');
    const tokenFile = path.join(debugDir, 'collector_token');
    try {
      // Reject a symlinked or escaped .debug directory before writing the
      // startup collector_token, mirroring the /session handler's guard: a
      // repo-controlled .debug symlink could otherwise redirect the write
      // outside projectRoot and clobber an arbitrary writable file.
      await assertNotSymlink(debugDir, 'debug_dir_is_symlink');
      await mkdir(debugDir, { recursive: true });
      const resolvedLogDir = await realpath(debugDir);
      const resolvedRoot = await realpath(path.resolve(projectRoot));
      if (!isInsideRoot(resolvedRoot, resolvedLogDir)) {
        throw new Error('debug_dir_escapes_root');
      }
      // Refuse to reuse a pre-existing collector_token that is not a private
      // regular file before opening it: a hard-linked token shares its inode
      // with another file (symlink case is rejected above). The open path
      // deliberately avoids O_TRUNC so a TOCTOU swap to a hard-linked inode
      // between these checks and open cannot truncate an outside file at open
      // time; we only truncate after fstat proves the opened inode is still a
      // private regular file.
      await assertNotSymlink(tokenFile, 'collector_token_is_symlink');
      await assertPrivateRegularFile(tokenFile, 'collector_token_not_private');
      // Atomic per-project ownership before mutating token/port files.
      // Two concurrent launches on different DEBUG_PORTs can both observe a
      // missing collector_port and race to write the shared token; O_EXCL on
      // collector_claim serializes the winner (Codex #4781560042). A stale
      // claim from a dead peer is reclaimed only after probing its port.
      const portFile = path.join(debugDir, 'collector_port');
      const claimFile = path.join(debugDir, 'collector_claim');
      const MAX_PORT_FILE_BYTES = 32;
      const MAX_CLAIM_FILE_BYTES = 256;
      // `O_EXCL` publishes the claim pathname before writeFile() persists its
      // owner record. A concurrent launcher must not reclaim that short,
      // ordinary-file creation window merely because there is no probeable
      // port yet; doing so would let both launches mutate shared token/port
      // files. An old incomplete record remains reclaimable after this bounded
      // grace, just as explicit closeout output locks do.
      const COLLECTOR_CLAIM_INITIALIZING_GRACE_MS = 5_000;
      const readSmallRegularFile = async (target, maxBytes) => {
        const handle = await openNoFollow(target, constants.O_RDONLY);
        try {
          const info = await handle.stat();
          if (!info.isFile() || info.nlink > 1 || info.size < 1 || info.size > maxBytes) {
            return null;
          }
          const buf = Buffer.alloc(info.size);
          let offset = 0;
          while (offset < info.size) {
            const { bytesRead } = await handle.read(buf, offset, info.size - offset, offset);
            if (bytesRead === 0) break;
            offset += bytesRead;
          }
          return buf.subarray(0, offset).toString('utf8');
        } finally {
          await handle.close().catch(() => {});
        }
      };
      // A peer is "active" when it answers as this project's collector,
      // whether or not it has latched ready yet. Requiring ready alone let a
      // second launch reclaim the claim mid token-persist (Qodo #4781599754 /
      // CodeRabbit #4781622077 / Codex #4781637950).
      const peerStillActive = async (peerPort) => {
        if (!Number.isInteger(peerPort) || peerPort <= 0 || peerPort === port) return false;
        for (let attempt = 0; attempt < 4; attempt += 1) {
          const peer = await probeServer(peerPort);
          if (peer && peer.project_hash === server.collectorProjectHash) return true;
          if (peer && peer.project_hash !== server.collectorProjectHash) {
            // A claim belongs to one project root. A different collector can
            // legitimately reuse the recorded port after this project's old
            // owner died; it does not own this project's token/claim files.
            // Reclaim the stale claim and let this invocation start on its
            // own requested port (Codex M6UI75x).
            return false;
          }
          await new Promise((resolve) => setTimeout(resolve, 40));
        }
        return false;
      };
      let claimHeld = false;
      for (let attempt = 0; attempt < 5 && !claimHeld; attempt += 1) {
        try {
          const claimHandle = await openNoFollow(
            claimFile,
            constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
            0o600,
          );
          try {
            await claimHandle.chmod(0o600);
            await claimHandle.writeFile(`${port}\n${server.collectorInstanceId}\n${process.pid}\n`, 'utf8');
          } finally {
            await claimHandle.close();
          }
          claimHeld = true;
        } catch (error) {
          if (error?.code !== 'EEXIST') throw error;
          let claimedPort = null;
          let claimText = null;
          // Captured once, up front, so the stale-reclaim unlink below can
          // verify it is still deleting this exact record rather than
          // whatever now occupies the path.
          let claimInfo = null;
          try {
            claimInfo = await lstat(claimFile);
          } catch {
            claimInfo = null;
          }
          try {
            claimText = await readSmallRegularFile(claimFile, MAX_CLAIM_FILE_BYTES);
            if (claimText) {
              const firstLine = claimText.split(/\r?\n/, 1)[0];
              claimedPort = Number(String(firstLine).trim());
            }
          } catch {
            claimedPort = null;
            claimText = null;
          }
          // A valid completed claim has port, opaque instance ID, and PID.
          // Treat only a fresh, private regular-file record that is incomplete
          // as initializing; malformed old files must still be reclaimable,
          // and links/special files are never trusted for the grace.
          const completeClaim = isCompleteClaimText(claimText);
          if (!completeClaim && claimInfo) {
            const freshPrivateRegularClaim = claimInfo.isFile()
              && !claimInfo.isSymbolicLink()
              && claimInfo.nlink === 1
              && claimInfo.size <= MAX_CLAIM_FILE_BYTES
              && Date.now() - claimInfo.mtimeMs < COLLECTOR_CLAIM_INITIALIZING_GRACE_MS;
            if (freshPrivateRegularClaim) {
              throw new Error('collector_claim_initializing');
            }
          }
          // Owner PID is authoritative: a starting peer is not ready yet but
          // still holds the claim and must not be unlinked.
          // Require a matching collector probe before treating the claim as
          // held: an alive owner PID alone is not authoritative because the OS
          // can reuse a holder's PID for an unrelated process after it died,
          // which would lock startup with collector_already_running_on_other_port
          // forever. peerStillActive probes the actual collector identity on the
          // recorded port (with a short retry grace for a still-starting holder
          // that has not bound its port yet), so only a real serving collector
          // blocks; a live-but-portless PID is treated as reuse and falls
          // through to stale reclaim (Codex M6UFnGI).
          if (await peerStillActive(claimedPort)) {
            throw new Error('collector_already_running_on_other_port');
          }
          // Also honor collector_port when the claim file is unreadable but a
          // live peer still owns the port file from a prior build.
          try {
            const portText = await readSmallRegularFile(portFile, MAX_PORT_FILE_BYTES);
            const existingPort = portText ? Number(portText.trim()) : null;
            if (await peerStillActive(existingPort)) {
              throw new Error('collector_already_running_on_other_port');
            }
          } catch (portError) {
            if (portError?.message === 'collector_already_running_on_other_port') throw portError;
          }
          // Stale claim: quarantine-then-verify before deleting, then retry
          // exclusive create. Two concurrent launches can both inspect this
          // same stale record; if the first already unlinked it and wrote its
          // own fresh claim by the time the second gets here, a bare unlink
          // would delete that legitimate successor. reclaimStaleCollectorClaim
          // re-verifies the path still identifies that same record using
          // isSameLockIdentity (dev/ino/nlink + ctimeMs -- ctimeMs is fresh on
          // any unlink+recreate, even a reused inode on Linux/tmpfs), then
          // renames the entry to a private quarantine name and re-reads it so
          // a live successor that collided on identity within a single
          // millisecond is restored rather than deleted -- the same pattern
          // pr_closeout_workflow.js uses for its output-dir lock
          // (Codex Ua4p7/UiXEg/UkNET/UkXzk). Its three resolved outcomes
          // (reclaimed/restored/backed-off) fall through so this for-loop
          // re-evaluates whatever now occupies the path from scratch; an
          // unexpected collector_claim_contention instead propagates out of
          // the loop to the caller rather than looping (CodeRabbit UmlJJ).
          await reclaimStaleCollectorClaim(claimFile, {
            claimInfo,
            claimText,
            readClaimText: (target) => readSmallRegularFile(target, MAX_CLAIM_FILE_BYTES),
          });
        }
      }
      if (!claimHeld) throw new Error('collector_claim_failed');
      // Release our claim on clean shutdown so a restart does not always burn
      // an EEXIST+reclaim cycle (CodeRabbit #4781622077).
      const releaseOwnedClaim = () => {
        try {
          let text = '';
          // Identity of the descriptor actually read below, captured so the
          // path-based unlink can confirm the path still names this same inode
          // before deleting it (Codex Ummsi).
          let openedIdentity = null;
          try {
            // Read through an lstat guard + no-follow descriptor, not a
            // path-based readFileSync: .debug is writable by the debugged
            // project, so claimFile can be swapped for a symlink (or a hard
            // link to an outside inode) between acquire and this read, and a
            // following read would let that outside content drive the
            // ownership unlink below (CodeRabbit discussion_r3652923124).
            // Sync mirrors of the async guards are required because this runs
            // from server 'close' and process 'exit', where awaits are
            // impossible; the lstat guard stays the primary check, with
            // O_NOFOLLOW as defense-in-depth where the platform has it.
            const info = lstatSync(claimFile);
            if (
              info.isSymbolicLink()
              || !info.isFile()
              || info.nlink > 1
              || info.size < 1
              || info.size > MAX_CLAIM_FILE_BYTES
            ) {
              return;
            }
            const fd = openNoFollowSync(claimFile, constants.O_RDONLY);
            try {
              // Re-stat the opened descriptor before reading, mirroring
              // readSmallRegularFile's post-open handle.stat(): the lstat
              // metadata above is stale the instant the path could be swapped
              // between lstat and open, so size/link checks and the buffer
              // sizing must come from the descriptor actually being read
              // (CodeRabbit discussion_r3652923124).
              const opened = fstatSync(fd);
              if (
                !opened.isFile()
                || opened.nlink > 1
                || opened.size < 1
                || opened.size > MAX_CLAIM_FILE_BYTES
              ) {
                return;
              }
              openedIdentity = opened;
              const buf = Buffer.alloc(opened.size);
              let offset = 0;
              while (offset < opened.size) {
                const bytesRead = readSync(fd, buf, offset, opened.size - offset, offset);
                if (bytesRead === 0) break;
                offset += bytesRead;
              }
              text = buf.subarray(0, offset).toString('utf8');
            } finally {
              closeSync(fd);
            }
          } catch {
            return;
          }
          const lines = String(text).split(/\r?\n/);
          const claimInstance = String(lines[1] || '').trim();
          const claimPid = Number(String(lines[2] || '').trim());
          if (claimInstance === server.collectorInstanceId || claimPid === process.pid) {
            // Bind the unlink to the descriptor we validated, not just the
            // path: a peer that reclaimed this claim and swapped in its own
            // successor between the read above and here must keep it, since the
            // ownership check above reflects the descriptor's now-stale bytes,
            // not whatever occupies the path now (Codex Ummsi).
            unlinkOwnedClaimIfUnchanged(claimFile, openedIdentity);
          }
        } catch {
          // Best-effort release; stale reclaim handles crash leftovers.
        }
      };
      server.once('close', releaseOwnedClaim);
      process.once('exit', releaseOwnedClaim);
      // Prefer create-exclusive for a fresh path; if the file already exists
      // (previous run), open it for write WITHOUT truncation. O_NOFOLLOW
      // blocks a symlink swap of the FINAL path component after the lstat
      // checks above -- but it cannot protect the PARENT directory chain: if
      // .debug itself was renamed out and replaced with a symlink after the
      // resolvedLogDir check above but before this open(), the open would
      // transparently follow the substituted parent even though tokenFile's
      // own final component was never a symlink. Node has no portable
      // openat()-style "open relative to an already-verified directory
      // descriptor" primitive, so this window cannot be fully closed in pure
      // Node; the post-open isInsideRoot re-verification below (mirroring
      // appendSessionEvent's post-open realpath check) narrows it instead of
      // eliminating it.
      let handle;
      try {
        handle = await openNoFollow(
          tokenFile,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
          0o600,
        );
      } catch (error) {
        if (error?.code !== 'EEXIST') throw error;
        handle = await openNoFollow(tokenFile, constants.O_WRONLY, 0o600);
      }
      try {
        const info = await handle.stat();
        if (!info.isFile() || info.nlink > 1) throw new Error('collector_token_not_private');
        // Re-verify the just-opened path still resolves inside projectRoot.
        // This is the post-open half of the TOCTOU narrowing described
        // above: if the parent was swapped for a symlink between the
        // resolvedLogDir check and this open(), the descriptor above now
        // points outside projectRoot even though O_NOFOLLOW never saw a
        // symlink at the final component. Fail closed without writing.
        let realTokenFile;
        try {
          realTokenFile = await realpath(tokenFile);
        } catch {
          throw new Error('collector_token_parent_replaced');
        }
        if (!isInsideRoot(resolvedRoot, realTokenFile)) {
          throw new Error('collector_token_parent_replaced');
        }
        // Apply private access BEFORE truncating/writing the secret, not
        // after. POSIX uses the descriptor chmod; Windows requires an actual
        // protected DACL because Node's chmod cannot remove inherited reader
        // permissions there. Either protection is established before fresh
        // token bytes reach disk, or startup fails closed.
        if (process.platform === 'win32') {
          protectWindowsPrivateFile(tokenFile);
          // protectWindowsPrivateFile re-resolves tokenFile by path in a
          // separate PowerShell process. If the path was swapped between the
          // handle.stat() above and that call returning, the ACL hardening
          // could land on a different filesystem object than the one
          // `handle` still refers to, leaving the secret about to be written
          // below unprotected. Re-verify the path still identifies the same
          // inode as the open handle before writing.
          let postProtectInfo;
          try {
            postProtectInfo = await lstat(tokenFile);
          } catch {
            throw new Error('collector_token_parent_replaced');
          }
          if (!isSameFileIdentity(info, postProtectInfo)) {
            throw new Error('collector_token_parent_replaced');
          }
        } else {
          await handle.chmod(0o600);
        }
        await handle.truncate(0);
        await handle.writeFile(token, 'utf8');
      } finally {
        await handle.close();
      }
      // Record which port owns the shared collector_token so a second
      // same-project collector on a different DEBUG_PORT cannot silently
      // overwrite it while the first is still ready. Mirror collector_token
      // hardening: no O_TRUNC at open, refuse hard-linked/non-private inodes,
      // re-check containment after open (Qodo/Codex/CodeRabbit #4781478035 /
      // #4781495663 / #4781498400).
      await assertNotSymlink(portFile, 'collector_port_is_symlink');
      await assertPrivateRegularFile(portFile, 'collector_port_not_private');
      const portHandle = await openNoFollow(
        portFile,
        constants.O_WRONLY | constants.O_CREAT,
        0o600,
      );
      try {
        const portWriteInfo = await portHandle.stat();
        if (!portWriteInfo.isFile() || portWriteInfo.nlink > 1) {
          throw new Error('collector_port_not_private');
        }
        let realPortFile;
        try {
          realPortFile = await realpath(portFile);
        } catch {
          throw new Error('collector_port_parent_replaced');
        }
        if (!isInsideRoot(resolvedRoot, realPortFile)) {
          throw new Error('collector_port_parent_replaced');
        }
        // On Windows, or any filesystem where the O_NOFOLLOW ladder falls
        // back to a plain open, openNoFollow above may have transparently
        // followed a symlink planted at portFile after the pre-open
        // assertNotSymlink/assertPrivateRegularFile checks. stat()/realpath()
        // above both read through that same symlink, so both checks pass for
        // the symlink's TARGET rather than portFile itself -- if that target
        // is a regular file inside the project, this handle is about to
        // truncate and overwrite an unrelated project file. A fresh lstat of
        // the path (which does not follow a symlink) must still identify the
        // exact object this descriptor already holds before the destructive
        // write below reaches disk (mirrors collector_token's
        // isSameFileIdentity binding).
        let portPathIdentity;
        try {
          portPathIdentity = await lstat(portFile);
        } catch {
          throw new Error('collector_port_parent_replaced');
        }
        if (!isSameFileIdentity(portWriteInfo, portPathIdentity)) {
          throw new Error('collector_port_parent_replaced');
        }
        await portHandle.chmod(0o600);
        await portHandle.truncate(0);
        await portHandle.writeFile(String(port), 'utf8');
      } finally {
        await portHandle.close();
      }
      // Only after the token file is on disk may relaunch probes claim
      // already_running for this project.
      server.markCollectorReady();
      process.stdout.write(
        `${JSON.stringify({
          status: 'started',
          port,
          service: COLLECTOR_SERVICE,
          version: COLLECTOR_VERSION,
          instance_id: server.collectorInstanceId,
          log_dir: '.debug',
          token_file: '.debug/collector_token',
        })}\n`,
      );
    } catch (error) {
      process.stderr.write(
        `${JSON.stringify({
          level: 'error',
          event: 'startup.token_write_failed',
          reason: error?.code || (error?.message || String(error)),
        })}\n`,
      );
      process.exitCode = 1;
      server.close();
    }
  });
};

if (require.main === module) main();

module.exports = {
  COLLECTOR_SERVICE,
  COLLECTOR_VERSION,
  REDACTION_MAX_DEPTH,
  RequestError,
  createDebugServer,
  createRedactionContext,
  isInsideRoot,
  isSameFileIdentity,
  openNoFollowSync,
  parseRedactNames,
  probeLaunchToken,
  probeReadyCollector,
  probeServer,
  readJson,
  reclaimStaleCollectorClaim,
  redactEventForAppend,
  redactEventValue,
  resolvePowerShellExecutable,
  unlinkOwnedClaimIfUnchanged,
};
