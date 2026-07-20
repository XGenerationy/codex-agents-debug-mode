#!/usr/bin/env node

const { randomBytes, timingSafeEqual } = require('node:crypto');
const { appendFile, mkdir, writeFile } = require('node:fs/promises');
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
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(`${JSON.stringify(payload)}\n`);
};

const readJson = async (request, maxBodyBytes) => {
  const chunks = [];
  let size = 0;
  let tooLarge = false;

  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxBodyBytes) {
      tooLarge = true;
      continue;
    }
    chunks.push(chunk);
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

const isAllowedHost = (request) => {
  const port = request.socket.localPort;
  const host = request.headers.host;
  return host === `127.0.0.1:${port}` || host === `localhost:${port}`;
};

const configureOrigin = (request, response, allowedOrigins) => {
  const origin = request.headers.origin;
  if (origin === undefined) return true;
  if (!allowedOrigins.has(origin)) return false;
  response.setHeader('Access-Control-Allow-Origin', origin);
  response.setHeader('Vary', 'Origin');
  return true;
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

    const pathname = new URL(request.url, 'http://127.0.0.1').pathname;

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

        const payload = await readJson(request, effectiveLimits.maxBodyBytes);
        const sessionId = `${normalizeSessionName(payload.name)}-${randomBytes(12).toString('hex')}`;
        const sessionToken = randomBytes(32).toString('base64url');
        const fileName = `debug-${sessionId}.log`;
        const logFile = path.join(logDir, fileName);
        // Reserve the session slot before any awaited I/O so concurrent
        // /session requests cannot all pass the maxSessions check at once.
        sessions.set(sessionId, { eventCount: 0, logFile, sessionToken, provisional: true });
        try {
          await mkdir(logDir, { recursive: true });
          await writeFile(logFile, '', { encoding: 'utf8', flag: 'wx', mode: 0o600 });
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
        const sessionId = payload.sessionId;
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
          request.headers['x-debug-session-token'] || payload.sessionToken;
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
        // roll the reservation back if the append fails.
        session.eventCount += 1;
        totalBytes += eventBytes;
        try {
          await appendFile(session.logFile, serializedEvent, 'utf8');
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
          if (body.length > 4_096) request.destroy();
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
      },
    );
    request.on('timeout', () => request.destroy());
    request.on('error', () => finish(null));
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
  server.listen(port, '127.0.0.1', () => {
    process.stdout.write(
      `${JSON.stringify({
        status: 'started',
        port,
        service: COLLECTOR_SERVICE,
        version: COLLECTOR_VERSION,
        instance_id: server.collectorInstanceId,
        collector_token: server.collectorToken,
        log_dir: '.debug',
      })}\n`,
    );
  });
};

if (require.main === module) main();

module.exports = {
  COLLECTOR_SERVICE,
  COLLECTOR_VERSION,
  createDebugServer,
  probeServer,
};
