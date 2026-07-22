const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { existsSync } = require('node:fs');
const { link, mkdir, mkdtemp, readFile, rm, stat, symlink, writeFile } = require('node:fs/promises');
const http = require('node:http');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  COLLECTOR_SERVICE,
  COLLECTOR_VERSION,
  RequestError,
  createDebugServer,
  probeServer,
  readJson,
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

// Pick a currently-free loopback port for CLI startup tests. The server under
// test binds it a moment later, so a parallel process could theoretically win
// the gap; in practice the window is milliseconds.
const findFreePort = () =>
  new Promise((resolve, reject) => {
    const probe = http.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });

// Spawn the real CLI against a temp project root. Resolves with the parsed
// startup outcome as soon as the single structured startup line appears on
// stdout, or with the exit code when the process exits before printing one.
const launchCli = (projectRoot, port) => {
  const child = spawn(
    process.execPath,
    [path.join(__dirname, 'debug_server.js'), projectRoot],
    { env: { ...process.env, DEBUG_PORT: String(port) }, stdio: ['ignore', 'pipe', 'pipe'] },
  );
  const outcome = new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
      const line = stdout.split('\n').find((entry) => entry.trim().startsWith('{'));
      if (!line) return;
      try {
        finish({ status: JSON.parse(line).status, stdout, stderr, exitCode: null });
      } catch {
        // Partial line; keep collecting until it completes or the child exits.
      }
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('exit', (code) => finish({ status: null, stdout, stderr, exitCode: code }));
    child.on('error', reject);
  });
  return { child, outcome };
};

const stopCli = (child) => {
  if (child.exitCode === null && !child.killed) child.kill();
};

const bashProbe = spawnSync('bash', ['-c', 'true']);
const bashAvailable = !bashProbe.error && bashProbe.status === 0;

// Git Bash passes MSYS-style paths (/c/...) to the installer, which forwards
// them to the native node.exe; the emitted JSON then carries the Windows form
// (C:/...). Compare through path.normalize so the assertion holds on both
// POSIX shells and Git Bash.
const toBashPath = (nativePath) => {
  if (process.platform !== 'win32') return nativePath;
  const converted = spawnSync('cygpath', ['-u', nativePath], { encoding: 'utf8' });
  if (converted.error || converted.status !== 0) {
    throw converted.error || new Error(`cygpath failed: ${converted.stderr}`);
  }
  return converted.stdout.trim();
};

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

test('probeServer still settles when the /health response closes without end or error', async () => {
  // Some abort paths destroy the request mid-response and emit only 'close'
  // (no 'end' / 'error'); the probe must settle to null so the EADDRINUSE
  // handler cannot hang startup. Verify both an oversized-body abort and a
  // server-side socket destroy resolve to null.
  const oversized = http.createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.write('x'.repeat(8192));
    // Intentionally do not end(); the probe must abort and settle.
  });
  const oversizedUrl = await listen(oversized);

  const dropped = http.createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.destroy();
  });
  const droppedUrl = await listen(dropped);

  try {
    const oversizedResult = await probeServer(Number(new URL(oversizedUrl).port));
    const droppedResult = await probeServer(Number(new URL(droppedUrl).port));
    assert.equal(oversizedResult, null);
    assert.equal(droppedResult, null);
  } finally {
    await close(oversized);
    await close(dropped);
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

test('rejects POST /session when .debug is a regular file instead of a directory', async () => {
  // A worktree can place a regular file at .debug; mkdir would throw ENOTDIR
  // and previously surfaced as an unstructured 500. Map that to a structured
  // 409 so clients get a stable error code.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-file-'));
  await writeFile(path.join(projectRoot, '.debug'), 'not-a-directory');
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);
  try {
    const response = await createSession(baseUrl);
    assert.equal(response.status, 409, JSON.stringify(response.body));
    assert.equal(response.body.error, 'debug_dir_not_directory');
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

test('maps request stream errors to RequestError instead of bubbling as 500', async () => {
  // readJson wraps stream iteration so client disconnect / ECONNRESET becomes
  // RequestError(request_aborted|request_failed) rather than an uncaught error
  // that the HTTP handler would classify as internal_error 500.
  const { Readable } = require('node:stream');
  const failing = new Readable({
    read() {
      this.destroy(Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }));
    },
  });
  await assert.rejects(
    () => readJson(failing, 64 * 1024),
    (error) => error instanceof RequestError
      && error.status === 400
      && error.code === 'request_aborted',
  );
});

test('reports an oversized body as a deterministic 413 body_too_large', async () => {
  // Exceeding maxBodyBytes destroys the request mid-upload. If that destroy
  // surfaces as an async-iterator error, readJson must still classify the
  // failure as the deterministic 413 limit violation (body_too_large), not a
  // 400-class abort.
  const { Readable } = require('node:stream');
  const limit = 64 * 1024;
  const oversized = new Readable({
    read() {
      // A single chunk larger than the limit forces the oversize branch and the
      // immediate request.destroy() inside readJson.
      this.push(Buffer.alloc(limit + 1024, 0x61));
      this.push(null);
    },
  });
  await assert.rejects(
    () => readJson(oversized, limit),
    (error) => error instanceof RequestError
      && error.status === 413
      && error.code === 'body_too_large',
  );
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

test('/log accepts both snake_case and camelCase session keys', async () => {
  // /session returns session_id / session_token (snake_case) but older docs
  // and several SDKs use sessionId / sessionToken (camelCase). A client that
  // reuses the /session response payload directly must still be able to
  // post log events without transforming the keys.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);

  try {
    const session = (await createSession(baseUrl)).body;

    // snake_case (the exact /session response payload).
    const snake = await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: {
        session_id: session.session_id,
        session_token: session.session_token,
        msg: 'snake-case-event',
      },
    });
    assert.equal(snake.status, 202);

    // camelCase (the older documented form).
    const camel = await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: {
        sessionId: session.session_id,
        sessionToken: session.session_token,
        msg: 'camel-case-event',
      },
    });
    assert.equal(camel.status, 202);
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

test('refuses to write the launch token through a hard-linked collector_token', { timeout: 20000 }, async () => {
  // A repo-controlled .debug/collector_token hard link shares its inode with
  // an outside file; a truncating startup write would clobber that file
  // through the link. Startup must fail closed and leave the target intact.
  // Open must not use O_TRUNC before fstat: even if pre-checks race, the
  // outside inode must not be truncated at open time.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  let child;
  try {
    const debugDir = path.join(projectRoot, '.debug');
    const outsideFile = path.join(projectRoot, 'outside.txt');
    await mkdir(debugDir, { recursive: true });
    await writeFile(outsideFile, 'precious', 'utf8');
    await link(outsideFile, path.join(debugDir, 'collector_token'));

    const port = await findFreePort();
    const launched = launchCli(projectRoot, port);
    child = launched.child;
    const result = await launched.outcome;

    assert.equal(result.exitCode, 1);
    assert.equal(result.stdout.includes('"started"'), false);
    assert.match(result.stderr, /startup\.token_write_failed/);
    assert.match(result.stderr, /collector_token_not_private/);
    assert.equal(await readFile(outsideFile, 'utf8'), 'precious');
  } finally {
    if (child) stopCli(child);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('rewrites an existing private collector_token without open-time truncation', { timeout: 20000 }, async () => {
  // Second startup reuses an existing regular private token file. Open must
  // not pass O_TRUNC; validation then truncate-via-descriptor + write must
  // leave a fresh token. Exercises the EEXIST branch of the token writer.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  let child;
  try {
    const debugDir = path.join(projectRoot, '.debug');
    const tokenFile = path.join(debugDir, 'collector_token');
    await mkdir(debugDir, { recursive: true });
    await writeFile(tokenFile, 'stale-token-content-from-prior-run', { mode: 0o600 });

    const port = await findFreePort();
    const launched = launchCli(projectRoot, port);
    child = launched.child;
    const result = await launched.outcome;

    assert.equal(result.status, 'started');
    const contents = await readFile(tokenFile, 'utf8');
    assert.notEqual(contents, 'stale-token-content-from-prior-run');
    assert.match(contents, /^[A-Za-z0-9_-]{43}$/);
    const info = await stat(tokenFile);
    assert.equal(info.isFile(), true);
    assert.equal(info.nlink, 1);
  } finally {
    if (child) stopCli(child);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('writes the launch token through the descriptor with owner-only permissions', { timeout: 20000 }, async () => {
  // The startup token write must succeed end to end through the opened file
  // descriptor (write + chmod before close), leaving a private regular file
  // that holds exactly the launch token.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  let child;
  try {
    const port = await findFreePort();
    const launched = launchCli(projectRoot, port);
    child = launched.child;
    const result = await launched.outcome;

    assert.equal(result.status, 'started');
    const tokenFile = path.join(projectRoot, '.debug', 'collector_token');
    const info = await stat(tokenFile);
    assert.equal(info.isFile(), true);
    assert.equal(info.nlink, 1);
    if (process.platform !== 'win32') {
      assert.equal(info.mode & 0o777, 0o600);
    }
    assert.match(await readFile(tokenFile, 'utf8'), /^[A-Za-z0-9_-]{43}$/);
  } finally {
    if (child) stopCli(child);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('rejects appends after the session log is swapped for a hard link', async () => {
  // The debugged project can mutate .debug after session creation. Swapping
  // the session log for a hard link to an outside file must fail closed
  // instead of appending the event through the shared inode.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);

  try {
    const session = (await createSession(baseUrl)).body;
    const logPath = path.join(projectRoot, session.log_file);
    const outsideFile = path.join(projectRoot, 'outside.log');
    await writeFile(outsideFile, '', 'utf8');
    await rm(logPath);
    await link(outsideFile, logPath);

    const response = await recordEvent(baseUrl, session);

    assert.equal(response.status, 409);
    assert.deepEqual(response.body, { error: 'session_log_replaced' });
    assert.equal(await readFile(outsideFile, 'utf8'), '');
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('rejects appends after the session log is recreated at the same path', async () => {
  // A deleted-and-recreated session log must be treated as a different file
  // even though the path string is unchanged. POSIX filesystems can recycle
  // the just-freed inode, so dev/ino alone cannot prove replacement — the
  // server also binds the recorded byte count and creation birth time.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);

  try {
    const session = (await createSession(baseUrl)).body;
    const logPath = path.join(projectRoot, session.log_file);
    await rm(logPath);
    await writeFile(logPath, 'sentinel\n', 'utf8');

    const response = await recordEvent(baseUrl, session);

    assert.equal(response.status, 409);
    assert.deepEqual(response.body, { error: 'session_log_replaced' });
    assert.equal(await readFile(logPath, 'utf8'), 'sentinel\n');
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('rejects appends after out-of-band bytes appear in the session log', async () => {
  // The server tracks exactly how many bytes it has appended; a writer that
  // adds content out of band (forged events, truncation games) breaks that
  // binding even when dev/ino still match, so the next append must fail
  // closed instead of building on a tampered log.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);

  try {
    const session = (await createSession(baseUrl)).body;
    const logPath = path.join(projectRoot, session.log_file);
    const first = await recordEvent(baseUrl, session);
    assert.equal(first.status, 202);
    await writeFile(logPath, 'forged\n', { flag: 'a' });

    const response = await recordEvent(baseUrl, session);

    assert.equal(response.status, 409);
    assert.deepEqual(response.body, { error: 'session_log_replaced' });
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test(
  'rejects appends after the session log is swapped for a symlink',
  { skip: process.platform === 'win32' && 'Windows cannot create file symlinks without elevation' },
  async () => {
    // A symlinked session log must be rejected by the no-follow open instead
    // of appending the event outside projectRoot.
    const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
    const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
    const baseUrl = await listen(server);
    let outsideDir;

    try {
      const session = (await createSession(baseUrl)).body;
      const logPath = path.join(projectRoot, session.log_file);
      outsideDir = await mkdtemp(path.join(tmpdir(), 'debug-skill-outside-'));
      const outsideFile = path.join(outsideDir, 'outside.log');
      await rm(logPath);
      await symlink(outsideFile, logPath);

      const response = await recordEvent(baseUrl, session);

      assert.equal(response.status, 409);
      assert.deepEqual(response.body, { error: 'session_log_replaced' });
      assert.equal(existsSync(outsideFile), false);
    } finally {
      await close(server);
      await rm(projectRoot, { recursive: true, force: true });
      if (outsideDir) await rm(outsideDir, { recursive: true, force: true });
    }
  },
);

test('rejects appends after the session log path is swapped for a directory', async () => {
  // open(O_WRONLY | O_APPEND) on a directory raises EISDIR on POSIX and
  // EPERM/EACCES on Windows; every shape must map to the same structured
  // conflict instead of a generic 500.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);

  try {
    const session = (await createSession(baseUrl)).body;
    const logPath = path.join(projectRoot, session.log_file);
    await rm(logPath);
    await mkdir(logPath);

    const response = await recordEvent(baseUrl, session);

    assert.equal(response.status, 409);
    assert.deepEqual(response.body, { error: 'session_log_replaced' });
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('serializes concurrent /log appends for the same session', async () => {
  // Two concurrent /log requests must not race the size check against
  // identity.bytesWritten: without a per-session queue one append can grow
  // the file while the other still holds a stale byte count and returns
  // session_log_replaced for a valid event.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);

  try {
    const session = (await createSession(baseUrl)).body;
    const responses = await Promise.all(
      Array.from({ length: 20 }, (_, index) => recordEvent(baseUrl, session, `concurrent-event-${index}`)),
    );
    for (const response of responses) {
      assert.equal(response.status, 202, JSON.stringify(response.body));
      assert.deepEqual(response.body, { status: 'recorded' });
    }
    const logPath = path.join(projectRoot, session.log_file);
    const lines = (await readFile(logPath, 'utf8')).trim().split('\n');
    assert.equal(lines.length, 20);
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test(
  'install.sh emits the real target and backup paths in its JSON result',
  { skip: !bashAvailable && 'bash is required to run tools/install.sh', timeout: 60000 },
  async () => {
    // Regression guard for the embedded `node -e` emit snippet: the install
    // result must carry the real target and backup values in the right
    // fields, never the eval context string or shifted arguments.
    const homeNative = await mkdtemp(path.join(tmpdir(), 'debug-skill-home-'));
    try {
      const home = toBashPath(homeNative);
      const installer = toBashPath(path.join(__dirname, '..', 'tools', 'install.sh'));
      const expectedTarget = path.join(homeNative, '.codex', 'skills', 'debug');

      const fresh = spawnSync('bash', [installer, '--home', home, '--target', 'codex'], {
        encoding: 'utf8',
      });
      assert.equal(fresh.status, 0, fresh.stderr);
      const freshResult = JSON.parse(fresh.stdout.trim());
      assert.deepEqual(Object.keys(freshResult).sort(), ['backup', 'status', 'target']);
      assert.equal(freshResult.status, 'installed');
      assert.equal(path.normalize(freshResult.target), expectedTarget);
      assert.equal(freshResult.backup, '');
      assert.equal(existsSync(path.join(expectedTarget, 'SKILL.md')), true);

      const forced = spawnSync('bash', [installer, '--home', home, '--target', 'codex', '--force'], {
        encoding: 'utf8',
      });
      assert.equal(forced.status, 0, forced.stderr);
      const forcedResult = JSON.parse(forced.stdout.trim());
      assert.equal(forcedResult.status, 'installed');
      assert.equal(path.normalize(forcedResult.target), expectedTarget);
      assert.equal(
        path.normalize(forcedResult.backup).startsWith(`${expectedTarget}.backup.`),
        true,
      );
      assert.equal(existsSync(path.normalize(forcedResult.backup)), true);
    } finally {
      await rm(homeNative, { recursive: true, force: true });
    }
  },
);
