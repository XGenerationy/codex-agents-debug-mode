#!/usr/bin/env node

const { createHash, randomBytes, timingSafeEqual } = require('node:crypto');
const { constants, realpathSync } = require('node:fs');
const { lstat, mkdir, open, realpath, unlink } = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const { assertNotSymlink: assertNotSymlinkShared, openNoFollow: openNoFollowShared } = require('./pr_closeout_fs');

const DEFAULT_PORT = 8787;
const COLLECTOR_SERVICE = 'codex-debug-collector';
const COLLECTOR_VERSION = 1;
const DEFAULT_LIMITS = Object.freeze({
  maxBodyBytes: 64 * 1024,
  maxSessions: 32,
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
const readJson = async (request, maxBodyBytes) => {
  const chunks = [];
  let size = 0;
  let tooLarge = false;

  try {
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
  } catch (error) {
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
  return host === `127.0.0.1:${port}`
    || host === `localhost:${port}`
    || host === `[::1]:${port}`;
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
 * @param {object} [options.limits] - overrides for DEFAULT_LIMITS (maxBodyBytes, maxSessions, maxEventsPerSession, maxTotalBytes).
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
  const originSet = new Set(allowedOrigins);
  let totalBytes = 0;

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
        });
        return;
      }

      if (request.method === 'POST' && pathname === '/session') {
        if (!authorizeRequest(response, bearerToken(request), token)) return;
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
          payload = await readJson(request, effectiveLimits.maxBodyBytes);
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
        sessions.set(sessionId, { eventCount: 0, logFile, sessionToken, provisional: true });
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
        const payload = await readJson(request, effectiveLimits.maxBodyBytes);
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
 * @returns {Promise<{service: string, version: number, instance_id: string, project_hash: string}|null>}
 */
const probeServer = (port) =>
  new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
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
            finish(valid ? identity : null);
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
      const identity = await probeServer(port);
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
      if (identity && identity.project_hash === server.collectorProjectHash) {
        process.stdout.write(
          `${JSON.stringify({
            status: 'already_running',
            port,
            service: identity.service,
            version: identity.version,
            instance_id: identity.instance_id,
          })}\n`,
        );
        return;
      }
    }
    process.stderr.write(
      `${JSON.stringify({
        level: 'error',
        event: 'startup.failed',
        reason: error.code === 'EADDRINUSE' ? 'port_in_use_by_other_process' : 'listen_failed',
      })}\n`,
    );
    process.exitCode = 1;
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
        // Apply the private mode BEFORE truncating/writing the secret, not
        // after. A freshly-created file already got 0600 atomically from
        // O_CREAT's mode argument above, but the EEXIST/reuse branch (a
        // few lines up) opens a PRE-EXISTING file whose mode is whatever it
        // already was: assertPrivateRegularFile only checks isFile/nlink,
        // never mode, and open()'s mode argument has no effect when O_CREAT
        // does not actually create the file. Chmod through the descriptor
        // first so a permissive pre-existing mode (e.g. a stale 0644 file
        // left by a prior process or misconfiguration) can never expose the
        // fresh secret to another local user, even for the brief window
        // between write and close.
        await handle.chmod(0o600);
        await handle.truncate(0);
        await handle.writeFile(token, 'utf8');
      } finally {
        await handle.close();
      }
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
  probeServer,
  readJson,
};
