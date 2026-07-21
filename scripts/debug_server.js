#!/usr/bin/env node

const { randomBytes, timingSafeEqual } = require('node:crypto');
const { constants } = require('node:fs');
const { lstat, mkdir, open, realpath } = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');

const DEFAULT_PORT = 8787;
const COLLECTOR_SERVICE = 'codex-debug-collector';
const COLLECTOR_VERSION = 1;
const DEFAULT_LIMITS = Object.freeze({
  maxBodyBytes: 64 * 1024,
  maxSessions: 32,
  maxEventsPerSession: 2_000,
  maxTotalBytes: 16 * 1024 * 1024,
});

class RequestError extends Error {
  constructor(code, status = 400) {
    super(code);
    this.name = 'RequestError';
    this.code = code;
    this.status = status;
  }
}

const sendJson = (response, status, payload) => {
  // Guard against secondary throws when the client already closed the socket
  // (e.g. after request_aborted); writableEnded/destroyed means we cannot respond.
  if (response.writableEnded || response.destroyed) return;
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(`${JSON.stringify(payload)}\n`);
};

const readJson = async (request, maxBodyBytes) => {
  const chunks = [];
  let size = 0;
  let tooLarge = false;

  try {
    for await (const chunk of request) {
      size += chunk.length;
      if (size > maxBodyBytes) {
        tooLarge = true;
        // Abort the request immediately instead of continuing to drain the
        // upload. Without this, a local client could keep the collector busy
        // (bandwidth/CPU/socket time) with an arbitrarily large body even
        // though the configured limit has already been exceeded.
        request.destroy();
        break;
      }
      chunks.push(chunk);
    }
  } catch (error) {
    // Client disconnect / stream reset is not a server fault; map to a
    // structured RequestError so the handler does not log request.failed and
    // respond with 500 internal_error when a response can still be written.
    if (error instanceof RequestError) throw error;
    const code = error?.code;
    if (code === 'ECONNRESET' || code === 'EPIPE' || code === 'ABORT_ERR' || error?.name === 'AbortError') {
      throw new RequestError('request_aborted', 400);
    }
    throw new RequestError('request_failed', 400);
  }

  if (tooLarge) throw new RequestError('body_too_large', 413);

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
  return host === `127.0.0.1:${port}` || host === `localhost:${port}`;
};

// Reject a path that is a symlink (fail-closed), tolerating ENOENT (the path
// is about to be created). Used for both the .debug directory and the
// collector_token file so the guard has one owner.
const assertNotSymlink = async (target, label) => {
  try {
    const info = await lstat(target);
    if (info.isSymbolicLink()) throw new Error(label);
  } catch (error) {
    if (error.message === label) throw error;
    if (error.code !== 'ENOENT') throw error;
  }
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
// regular files. On platforms without O_NOFOLLOW the flag is undefined and the
// call reduces to a plain open; filesystems that reject O_NOFOLLOW get a
// fallback open that still keeps O_NONBLOCK, paired with the lstat-based
// guards callers run first.
const openNoFollow = async (target, flags, mode) => {
  const noFollow = constants.O_NOFOLLOW || 0;
  const nonBlock = constants.O_NONBLOCK || 0;
  try {
    return await open(target, flags | noFollow | nonBlock, mode);
  } catch (error) {
    if (!noFollow || !['EINVAL', 'ENOTSUP', 'EOPNOTSUPP'].includes(error?.code)) throw error;
    return await open(target, flags | nonBlock, mode);
  }
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
      await handle.writeFile(serializedEvent, 'utf8');
      identity.bytesWritten += Buffer.byteLength(serializedEvent, 'utf8');
    } finally {
      await handle.close();
    }
  });
  session.appendChain = run;
  return run;
};

const createDebugServer = ({
  projectRoot = process.cwd(),
  token = randomBytes(32).toString('base64url'),
  instanceId = randomBytes(16).toString('hex'),
  allowedOrigins = [],
  limits = {},
} = {}) => {
  const logDir = path.join(path.resolve(projectRoot), '.debug');
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
        });
        return;
      }

      if (request.method === 'POST' && pathname === '/session') {
        if (!safeTokenEqual(bearerToken(request), token)) {
          sendJson(response, 401, { error: 'unauthorized' });
          return;
        }
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
          // Reject a symlinked or escaped .debug directory before writing session
          // evidence: a PR-controlled worktree can point .debug at an external
          // directory, which would let the collector write outside projectRoot.
          try {
            const dirInfo = await lstat(logDir);
            if (dirInfo.isSymbolicLink()) throw new RequestError('debug_dir_is_symlink');
          } catch (error) {
            if (error instanceof RequestError) throw error;
            if (error.code !== 'ENOENT') throw error;
          }
          await mkdir(logDir, { recursive: true });
          const resolvedLogDir = await realpath(logDir);
          const resolvedRoot = await realpath(path.resolve(projectRoot));
          const rel = path.relative(resolvedRoot, resolvedLogDir);
          if (rel === '' || rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
            throw new RequestError('debug_dir_escapes_root');
          }
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
            logFile,
            constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL,
            0o600,
          );
          try {
            const info = await handle.stat();
            sessions.get(sessionId).logFileIdentity = {
              dev: info.dev,
              ino: info.ino,
              birthtimeMs: info.birthtimeMs,
              bytesWritten: 0,
            };
          } finally {
            await handle.close();
          }
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
        if (!safeTokenEqual(suppliedToken, session.sessionToken)) {
          sendJson(response, 401, { error: 'unauthorized' });
          return;
        }
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
        sendJson(response, error.status, { error: error.code });
        return;
      }
      process.stderr.write(`${JSON.stringify({ level: 'error', event: 'request.failed' })}\n`);
      sendJson(response, 500, { error: 'internal_error' });
    }
  });

  Object.defineProperties(server, {
    collectorToken: { value: token },
    collectorInstanceId: { value: instanceId },
  });
  return server;
};

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
              /^[a-f0-9]{32}$/.test(identity.instance_id);
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
      if (identity) {
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
      const rel = path.relative(resolvedRoot, resolvedLogDir);
      if (rel === '' || rel === '..' || rel.startsWith(`..${path.sep}`) || path.isAbsolute(rel)) {
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
      // blocks a symlink swap after the lstat checks. Then re-verify through
      // the descriptor and only then truncate + write. Permissions are applied
      // through the descriptor before close: a path-based chmod after close
      // could race a symlink swap and retarget an outside file.
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
        await handle.truncate(0);
        await handle.writeFile(token, 'utf8');
        await handle.chmod(0o600);
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
  probeServer,
  readJson,
};
