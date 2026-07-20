const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { mkdtemp, readFile, rm } = require('node:fs/promises');
const http = require('node:http');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  COLLECTOR_SERVICE,
  COLLECTOR_VERSION,
  createDebugServer,
  probeServer,
} = require('./debug_server');

const TEST_LAUNCH_TOKEN = 'test-launch-token-with-enough-entropy-for-fixtures';

const listen = (server) =>
  new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });

const close = (server) =>
  new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });

const requestJson = (baseUrl, { body, headers = {}, method = 'GET', pathname = '/' } = {}) =>
  new Promise((resolve, reject) => {
    const url = new URL(pathname, baseUrl);
    const request = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method,
        headers,
      },
      (response) => {
        let responseBody = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => {
          responseBody += chunk;
        });
        response.on('end', () => {
          try {
            resolve({
              body: JSON.parse(responseBody || '{}'),
              headers: response.headers,
              status: response.statusCode,
            });
          } catch (error) {
            reject(error);
          }
        });
      },
    );
    request.on('error', reject);
    if (body !== undefined) request.write(JSON.stringify(body));
    request.end();
  });

const createSession = (baseUrl, name = 'Fix Null User ID', headers = {}) =>
  requestJson(baseUrl, {
    method: 'POST',
    pathname: '/session',
    headers: {
      Authorization: `Bearer ${TEST_LAUNCH_TOKEN}`,
      ...headers,
    },
    body: { name },
  });

const recordEvent = (baseUrl, session, msg = 'Function entry') =>
  requestJson(baseUrl, {
    method: 'POST',
    pathname: '/log',
    body: {
      sessionId: session.session_id,
      sessionToken: session.session_token,
      msg,
      data: { userId: null },
      hypothesisId: 'H1',
    },
  });

test('prints CLI help without starting the server', () => {
  const scriptPath = path.join(__dirname, 'debug_server.js');
  const result = spawnSync(process.execPath, [scriptPath, '--help'], { encoding: 'utf8' });

  assert.equal(result.status, 0);
  assert.match(result.stdout, /^Usage: debug_server\.js \[project-path\]/);
});

test('exposes collector-specific health without exposing credentials or paths', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);

  try {
    const response = await requestJson(baseUrl, { pathname: '/health' });

    assert.equal(response.status, 200);
    assert.equal(response.body.service, COLLECTOR_SERVICE);
    assert.equal(response.body.version, COLLECTOR_VERSION);
    assert.match(response.body.instance_id, /^[a-f0-9]{32}$/);
    assert.equal(JSON.stringify(response.body).includes(TEST_LAUNCH_TOKEN), false);
    assert.equal(JSON.stringify(response.body).includes(projectRoot), false);
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('probe accepts the collector identity and rejects an unrelated HTTP 200 server', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const collector = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const collectorUrl = await listen(collector);
  const unrelated = http.createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end('{"status":"ok"}\n');
  });
  const unrelatedUrl = await listen(unrelated);

  try {
    const identity = await probeServer(Number(new URL(collectorUrl).port));
    const unrelatedIdentity = await probeServer(Number(new URL(unrelatedUrl).port));

    assert.equal(identity.service, COLLECTOR_SERVICE);
    assert.equal(identity.version, COLLECTOR_VERSION);
    assert.equal(unrelatedIdentity, null);
  } finally {
    await close(collector);
    await close(unrelated);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('requires the launch token and returns only an opaque relative log path', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);

  try {
    const unauthorized = await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/session',
      body: { name: 'unauthorized' },
    });
    const authorized = await createSession(baseUrl);

    assert.equal(unauthorized.status, 401);
    assert.equal(authorized.status, 201);
    assert.match(authorized.body.session_id, /^fix-null-user-id-[a-f0-9]{24}$/);
    assert.match(authorized.body.session_token, /^[A-Za-z0-9_-]{43}$/);
    assert.match(authorized.body.log_file, /^\.debug\/debug-[a-z0-9-]+\.log$/);
    assert.equal(path.isAbsolute(authorized.body.log_file), false);
    assert.equal(JSON.stringify(authorized.body).includes(projectRoot), false);
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('creates a session and records one credential-free NDJSON event', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);

  try {
    const sessionResponse = await createSession(baseUrl);
    const session = sessionResponse.body;
    const logResponse = await recordEvent(baseUrl, session);
    const event = JSON.parse(
      (await readFile(path.join(projectRoot, session.log_file), 'utf8')).trim(),
    );

    assert.equal(sessionResponse.status, 201);
    assert.equal(logResponse.status, 202);
    assert.equal(event.msg, 'Function entry');
    assert.deepEqual(event.data, { userId: null });
    assert.equal(event.hypothesisId, 'H1');
    assert.match(event.ts, /^\d{4}-\d{2}-\d{2}T/);
    assert.equal(Object.hasOwn(event, 'sessionToken'), false);
    assert.equal(JSON.stringify(event).includes(session.session_token), false);
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('rejects an invalid Host and an untrusted browser origin', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const trustedOrigin = 'https://app.example.test';
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    allowedOrigins: [trustedOrigin],
  });
  const baseUrl = await listen(server);

  try {
    const invalidHost = await requestJson(baseUrl, {
      pathname: '/health',
      headers: { Host: 'attacker.example' },
    });
    const invalidOrigin = await createSession(baseUrl, 'blocked', {
      Origin: 'https://attacker.example',
    });
    const trusted = await createSession(baseUrl, 'trusted', { Origin: trustedOrigin });

    assert.equal(invalidHost.status, 421);
    assert.equal(invalidOrigin.status, 403);
    assert.equal(invalidOrigin.headers['access-control-allow-origin'], undefined);
    assert.equal(trusted.status, 201);
    assert.equal(trusted.headers['access-control-allow-origin'], trustedOrigin);
    assert.notEqual(trusted.headers['access-control-allow-origin'], '*');
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('requires the per-session token before accepting a log event', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);

  try {
    const session = (await createSession(baseUrl)).body;
    const response = await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: {
        sessionId: session.session_id,
        sessionToken: 'wrong-token',
        msg: 'drive-by write',
      },
    });

    assert.equal(response.status, 401);
    assert.deepEqual(response.body, { error: 'unauthorized' });
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('enforces bounded sessions and events', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    limits: { maxEventsPerSession: 1, maxSessions: 1 },
  });
  const baseUrl = await listen(server);

  try {
    const firstSession = await createSession(baseUrl, 'first');
    const firstEvent = await recordEvent(baseUrl, firstSession.body, 'first event');
    const secondEvent = await recordEvent(baseUrl, firstSession.body, 'second event');
    const secondSession = await createSession(baseUrl, 'second');

    assert.equal(firstSession.status, 201);
    assert.equal(firstEvent.status, 202);
    assert.deepEqual(secondEvent, {
      body: { error: 'event_limit_reached' },
      headers: secondEvent.headers,
      status: 429,
    });
    assert.equal(secondSession.status, 429);
    assert.deepEqual(secondSession.body, { error: 'session_limit_reached' });
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('enforces the aggregate log byte cap', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    limits: { maxTotalBytes: 1 },
  });
  const baseUrl = await listen(server);

  try {
    const session = (await createSession(baseUrl)).body;
    const response = await recordEvent(baseUrl, session);

    assert.equal(response.status, 429);
    assert.deepEqual(response.body, { error: 'storage_limit_reached' });
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});
