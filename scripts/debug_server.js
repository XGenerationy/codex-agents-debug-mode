#!/usr/bin/env node

const { createHash, createHmac, randomBytes, timingSafeEqual } = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync, unlinkSync, writeSync } = require('node:fs');
const { lstat, mkdir, realpath, unlink } = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const { assertNotSymlink: assertNotSymlinkShared, openNoFollow: openNoFollowShared, openNoFollowFlagAttempts } = require('./pr_closeout_fs');

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

// Windows does not implement POSIX 0600 semantics: fs.chmod() only affects
// the writable bit, leaving inherited DACL entries able to read a token in a
// shared checkout. Configure an explicit, protected DACL before the secret is
// written. The PowerShell program is fixed and the path is embedded only as
// UTF-16 base64, so repository-controlled path characters cannot become code.
// If PowerShell, the filesystem, or ACL verification fails, startup fails
// before collector_token receives any token bytes.
const protectWindowsTokenFile = (tokenFile) => {
  if (process.platform !== 'win32') return;
  const encodedPath = Buffer.from(tokenFile, 'utf16le').toString('base64');
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
    'powershell.exe',
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    { stdio: 'ignore', timeout: 5_000, windowsHide: true },
  );
};

const launchTokenProof = (token, challenge) =>
  createHmac('sha256', token).update(`codex-debug-collector-auth-v1:${challenge}`, 'utf8').digest('base64url');

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
const openNoFollowSync = (target, flags) => {
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
      return openSync(target, attempts[i]);
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

/**
 * Build (but do not start) the loopback-only debug-session HTTP collector.
 * Every request is gated by `isAllowedHost` (TCP peer must be loopback, Host
 * header must match) before any route logic runs. Routes: `GET /health`
 * (unauthenticated identity probe), `POST /session` (requires the launch
 * `token`, creates a session and its append-only NDJSON log under
 * `<projectRoot>/.debug`), and `POST /log` (requires that session's own
 * token — see authorizeRequest — and appends one redaction-free event line).
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
 * @returns {import('node:http').Server} an unstarted HTTP server; call `.listen()`.
 */
const createDebugServer = ({
  projectRoot = process.cwd(),
  token = randomBytes(32).toString('base64url'),
  instanceId = randomBytes(16).toString('hex'),
  allowedOrigins = [],
  limits = {},
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
  // A one-way, non-reversible fingerprint of the canonical project root.
  // /health is deliberately unauthenticated (see isAllowedHost) and must
  // never leak the raw path, but the EADDRINUSE probe in main() still needs
  // a way for two invocations to agree they mean the SAME project without
  // either being able to recover the other's path from what /health reports.
  const projectHash = createHash('sha256').update(canonicalProjectRoot).digest('hex');
  const sessions = new Map();
  const effectiveLimits = { ...DEFAULT_LIMITS, ...limits };
  const sessionIdleTimeoutMs = Number.isFinite(effectiveLimits.sessionIdleTimeoutMs)
    && effectiveLimits.sessionIdleTimeoutMs >= 1
    ? effectiveLimits.sessionIdleTimeoutMs
    : DEFAULT_LIMITS.sessionIdleTimeoutMs;
  const originSet = new Set(allowedOrigins);
  let totalBytes = 0;
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
          if (payload[key] !== undefined) event[key] = payload[key];
        }
        const serializedEvent = `${JSON.stringify(event)}\n`;
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
 * until the retry budget is exhausted. Avoids already_running while the first
 * process is still mid token-file write after listen().
 * @param {number} port
 * @param {string} expectedProjectHash
 * @param {{attempts?: number, delayMs?: number, deadlineMs?: number}} [options]
 */
const probeReadyCollector = async (
  port,
  expectedProjectHash,
  { attempts = 20, delayMs = 50, deadlineMs = 10_000 } = {},
) => {
  const deadlineAt = Date.now() + deadlineMs;
  for (let i = 0; i < attempts; i += 1) {
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
  // The final health probe must fit in the same overall startup budget. Each
  // probe has an inactivity and wall-clock timeout, but without this outer
  // deadline a continuously trickling listener could multiply those costs by
  // every retry and outlive the documented startup-capture polling window.
  const remainingBeforeFinalProbe = deadlineAt - Date.now();
  return remainingBeforeFinalProbe > 0
    ? probeServer(port, { deadlineMs: Math.min(2_000, remainingBeforeFinalProbe) })
    : null;
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

const parseAllowedOrigins = (value) =>
  (value || '')
    .split(',')
    .map((origin) => origin.trim())
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
          const claimLines = String(claimText || '').split(/\r?\n/);
          const completeClaim = Number.isInteger(claimedPort) && claimedPort > 0
            && Boolean(String(claimLines[1] || '').trim())
            && Number.isInteger(Number(String(claimLines[2] || '').trim()))
            && Number(String(claimLines[2] || '').trim()) > 0;
          if (!completeClaim) {
            try {
              const claimInfo = await lstat(claimFile);
              const freshPrivateRegularClaim = claimInfo.isFile()
                && !claimInfo.isSymbolicLink()
                && claimInfo.nlink === 1
                && claimInfo.size <= MAX_CLAIM_FILE_BYTES
                && Date.now() - claimInfo.mtimeMs < COLLECTOR_CLAIM_INITIALIZING_GRACE_MS;
              if (freshPrivateRegularClaim) {
                throw new Error('collector_claim_initializing');
              }
            } catch (claimInfoError) {
              if (claimInfoError?.message === 'collector_claim_initializing') throw claimInfoError;
              // A disappeared or uninspectable record can proceed to the
              // guarded stale-reclaim path below, which still refuses links.
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
          // Stale claim: remove and retry exclusive create.
          try {
            await assertNotSymlink(claimFile, 'collector_claim_is_symlink');
            await unlink(claimFile);
          } catch (unlinkError) {
            if (unlinkError?.code !== 'ENOENT') {
              throw new Error('collector_claim_contention');
            }
          }
        }
      }
      if (!claimHeld) throw new Error('collector_claim_failed');
      // Release our claim on clean shutdown so a restart does not always burn
      // an EEXIST+reclaim cycle (CodeRabbit #4781622077).
      const releaseOwnedClaim = () => {
        try {
          let text = '';
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
            unlinkSync(claimFile);
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
          protectWindowsTokenFile(tokenFile);
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
  RequestError,
  createDebugServer,
  isInsideRoot,
  openNoFollowSync,
  probeLaunchToken,
  probeReadyCollector,
  probeServer,
  readJson,
};
