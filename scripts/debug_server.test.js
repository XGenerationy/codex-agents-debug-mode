const assert = require('node:assert/strict');
const { spawn, spawnSync } = require('node:child_process');
const { constants, existsSync, renameSync, rmSync } = require('node:fs');
const { chmod, copyFile, link, lstat, mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, utimes, writeFile } = require('node:fs/promises');
const http = require('node:http');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
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

const requestJson = (baseUrl, { agent, body, headers = {}, method = 'GET', pathname = '/' } = {}) =>
  new Promise((resolve, reject) => {
    const url = new URL(pathname, baseUrl);
    const request = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method,
        headers,
        agent,
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
// A hard timeout kills the child so a hung collector cannot park the whole
// suite (Node 24 / windows-latest previously hit the 45m job timeout when a
// single EADDRINUSE child never settled).
const launchCli = (projectRoot, port, { timeoutMs = 20_000 } = {}) => {
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
      clearTimeout(timer);
      resolve(value);
    };
    const timer = setTimeout(() => {
      stopCli(child);
      finish({ status: null, stdout, stderr, exitCode: child.exitCode, timedOut: true });
    }, timeoutMs);
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
    // Route spawn errors through finish so the startup force-exit timer is cleared
    // (CodeRabbit #4781360793). A bare reject left the timer armed and could
    // call stopCli long after the test settled.
    child.on('error', (error) => {
      stopCli(child);
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
  });
  return { child, outcome };
};

const stopCli = (child) => {
  if (!child || child.exitCode !== null || child.killed) return;
  try {
    if (process.platform === 'win32') {
      // Plain child.kill() does not tear down the process tree on Windows.
      spawnSync('taskkill', ['/pid', String(child.pid), '/T', '/F'], {
        stdio: 'ignore',
        windowsHide: true,
      });
    } else {
      child.kill('SIGKILL');
    }
  } catch {
    try {
      child.kill();
    } catch {
      // already gone
    }
  }
};

const windowsAclIsCurrentUserOnly = (filePath) => {
  const encodedPath = Buffer.from(filePath, 'utf16le').toString('base64');
  const script = [
    `$path = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${encodedPath}'))`,
    '$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User',
    '$acl = [IO.File]::GetAccessControl($path)',
    '$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))',
    'if ($acl.AreAccessRulesProtected -and $rules.Count -eq 1 -and $rules[0].IdentityReference.Value -eq $sid.Value -and $rules[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and (($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl)) { [Console]::Out.Write("ok") } else { [Console]::Out.Write("not-owner-only"); exit 1 }',
  ].join('; ');
  return spawnSync(
    'powershell.exe',
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    { encoding: 'utf8', windowsHide: true },
  );
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
    // project_hash (added so main()'s EADDRINUSE handler can tell two
    // invocations mean the same project apart from different ones sharing a
    // port -- see probeServer) must be well-formed and must never be, or
    // trivially contain, the raw path it was derived from.
    assert.match(response.body.project_hash, /^[a-f0-9]{64}$/);
    assert.notEqual(response.body.project_hash, projectRoot);
    assert.equal(response.body.project_hash.includes(projectRoot), false);
    assert.equal(response.body.project_hash, server.collectorProjectHash);
    // Before markCollectorReady(), /health must report ready:false so a
    // concurrent relaunch cannot claim already_running mid token write.
    assert.equal(response.body.ready, false);
    server.markCollectorReady();
    const readyResponse = await requestJson(baseUrl, { pathname: '/health' });
    assert.equal(readyResponse.body.ready, true);
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

test('probeServer settles within a bounded wall-clock period against a trickling /health response', { timeout: 15000 }, async () => {
  // The 500ms socket timeout is an inactivity timer: a peer emitting a byte
  // every <500ms resets it forever, and a slow trickle never reaches the
  // 4 KiB abort threshold or 'end'. An independent wall-clock deadline must
  // still destroy the request and settle null so the EADDRINUSE startup path
  // stays bounded (Codex review: trickling listener pinned the probe).
  const trickler = http.createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    const interval = setInterval(() => {
      if (!response.destroyed) response.write('x');
    }, 100);
    response.on('close', () => clearInterval(interval));
    response.on('error', () => clearInterval(interval));
  });
  const tricklerUrl = await listen(trickler);

  try {
    const startedAt = Date.now();
    const result = await probeServer(Number(new URL(tricklerUrl).port));
    const elapsedMs = Date.now() - startedAt;
    assert.equal(result, null);
    assert.ok(elapsedMs < 5_000, `probe must respect its wall-clock deadline (took ${elapsedMs}ms)`);
  } finally {
    await close(trickler);
  }
});

test('probeLaunchToken settles within a bounded wall-clock period against a trickling /auth response', { timeout: 15000 }, async () => {
  const trickler = http.createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    const interval = setInterval(() => {
      if (!response.destroyed) response.write('x');
    }, 100);
    response.on('close', () => clearInterval(interval));
    response.on('error', () => clearInterval(interval));
  });
  const tricklerUrl = await listen(trickler);

  try {
    const startedAt = Date.now();
    const result = await probeLaunchToken(Number(new URL(tricklerUrl).port), TEST_LAUNCH_TOKEN);
    const elapsedMs = Date.now() - startedAt;
    assert.equal(result, false);
    assert.ok(elapsedMs < 5_000, `launch-token probe must respect its wall-clock deadline (took ${elapsedMs}ms)`);
  } finally {
    await close(trickler);
  }
});

test('launch-token proof authenticates a collector without putting the bearer in HTTP headers', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-proof-'));
  const collector = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const collectorUrl = await listen(collector);

  try {
    const port = Number(new URL(collectorUrl).port);
    assert.equal(await probeLaunchToken(port, TEST_LAUNCH_TOKEN), true);
    assert.equal(await probeLaunchToken(port, 'wrong-token'), false);
  } finally {
    await close(collector);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('probeReadyCollector bounds all retries against a trickling /health response', { timeout: 10000 }, async () => {
  const trickler = http.createServer((_request, response) => {
    response.writeHead(200, { 'Content-Type': 'application/json' });
    const interval = setInterval(() => {
      if (!response.destroyed) response.write('x');
    }, 100);
    response.on('close', () => clearInterval(interval));
    response.on('error', () => clearInterval(interval));
  });
  const tricklerUrl = await listen(trickler);

  try {
    const startedAt = Date.now();
    const result = await probeReadyCollector(
      Number(new URL(tricklerUrl).port),
      'a'.repeat(64),
      { attempts: 20, delayMs: 50, deadlineMs: 2_500 },
    );
    const elapsedMs = Date.now() - startedAt;
    assert.equal(result, null);
    assert.ok(elapsedMs < 4_000, `ready probe retries must honor one deadline (took ${elapsedMs}ms)`);
  } finally {
    await close(trickler);
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

test('accepts bracketed IPv6 loopback Host when the peer is loopback', async () => {
  // Node clients targeting ::1 send Host: [::1]:<port>. The peer-address
  // check already accepts ::1; the Host allowlist must match the bracketed form.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);
  try {
    const port = new URL(baseUrl).port;
    const health = await requestJson(baseUrl, {
      pathname: '/health',
      headers: { Host: `[::1]:${port}` },
    });
    assert.equal(health.status, 200, JSON.stringify(health.body));
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
  // Exceeding maxBodyBytes stops the read (break, not request.destroy() --
  // see readJson's JSDoc for why: destroying a real IncomingMessage also
  // destroys the shared response socket). readJson must still classify the
  // failure as the deterministic 413 limit violation (body_too_large), not a
  // 400-class abort, and must mark it closeConnection so the caller closes
  // the connection instead of returning it to a keep-alive pool.
  const { Readable } = require('node:stream');
  const limit = 64 * 1024;
  const oversized = new Readable({
    read() {
      // A single chunk larger than the limit forces the oversize branch and
      // the loop `break` inside readJson.
      this.push(Buffer.alloc(limit + 1024, 0x61));
      this.push(null);
    },
  });
  await assert.rejects(
    () => readJson(oversized, limit),
    (error) => error instanceof RequestError
      && error.status === 413
      && error.code === 'body_too_large'
      && error.closeConnection === true,
  );
});

test('delivers a real 413 body_too_large to the client instead of ECONNRESET', async () => {
  // Regression for the request.destroy()-kills-the-shared-socket bug: for a
  // REAL http.IncomingMessage (unlike the synthetic Readable used in the
  // unit test above), request/response share one HTTP/1.1 socket, so
  // destroying the request used to destroy the response's socket too --
  // verified empirically against Node's actual runtime behavior before this
  // fix landed, the client observed ECONNRESET and never saw the structured
  // 413 body at all. This exercises the REAL createDebugServer end to end
  // over a real HTTP client, which the direct-readJson unit tests above
  // cannot: they never touch a real socket.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    limits: { maxBodyBytes: 1024 },
  });
  const baseUrl = await listen(server);

  try {
    const response = await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/session',
      headers: { Authorization: `Bearer ${TEST_LAUNCH_TOKEN}` },
      body: { name: 'x'.repeat(4096) },
    });

    assert.equal(response.status, 413);
    assert.deepEqual(response.body, { error: 'body_too_large' });
    assert.equal(response.headers.connection, 'close');
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('delivers a real 408 request_body_timeout to a stalled client instead of ECONNRESET', { timeout: 10000 }, async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    limits: { bodyTimeoutMs: 50 },
  });
  const baseUrl = await listen(server);

  try {
    const response = await new Promise((resolve, reject) => {
      const url = new URL('/session', baseUrl);
      const request = http.request({
        hostname: url.hostname,
        port: url.port,
        path: url.pathname,
        method: 'POST',
        headers: { Authorization: `Bearer ${TEST_LAUNCH_TOKEN}` },
      }, (incoming) => {
        let text = '';
        incoming.setEncoding('utf8');
        incoming.on('data', (chunk) => { text += chunk; });
        incoming.on('end', () => {
          try {
            resolve({ status: incoming.statusCode, headers: incoming.headers, body: JSON.parse(text) });
          } catch (error) {
            reject(error);
          }
        });
      });
      request.on('error', reject);
      request.write('{"name":"incomplete');
    });

    assert.equal(response.status, 408);
    assert.deepEqual(response.body, { error: 'request_body_timeout' });
    assert.equal(response.headers.connection, 'close');
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('keeps a keep-alive connection reusable after an oversized-body 413 closes it cleanly', { timeout: 10000 }, async () => {
  // Justifies the Connection: close decision made in sendJson/RequestError:
  // readJson intentionally stops reading an oversized body without draining
  // the client's remaining in-flight bytes. Left on a reused keep-alive
  // socket, those bytes would be misparsed as the start of the next request
  // (verified empirically while designing this fix: without Connection:
  // close, a second request on the same reused socket hangs indefinitely).
  // Sending Connection: close makes the client's own keep-alive agent open a
  // FRESH socket for the next request instead, so the collector keeps
  // working normally right after a 413. Both requests share one Agent with
  // maxSockets: 1 so the second request is FORCED to either reuse or replace
  // the first connection -- it has no other socket available to fall back
  // to, so a regression here would hang (bounded by the test's timeout)
  // rather than silently passing via an unrelated fresh connection.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    limits: { maxBodyBytes: 1024 },
  });
  const baseUrl = await listen(server);
  const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });

  try {
    const oversized = await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/session',
      agent,
      headers: { Authorization: `Bearer ${TEST_LAUNCH_TOKEN}` },
      body: { name: 'x'.repeat(4096) },
    });
    assert.equal(oversized.status, 413);
    assert.deepEqual(oversized.body, { error: 'body_too_large' });
    assert.equal(oversized.headers.connection, 'close');

    // A second request through the SAME keep-alive agent (maxSockets: 1)
    // must complete normally -- not hang -- right after the 413 closed the
    // first socket.
    const second = await requestJson(baseUrl, { pathname: '/health', agent });
    assert.equal(second.status, 200);
    assert.equal(second.body.service, COLLECTOR_SERVICE);
  } finally {
    agent.destroy();
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

test('rejects a genuinely valid session token when presented against a different session', async () => {
  // The collector has no multi-tenant/client_id concept; the per-session
  // token is the only scoping boundary between concurrent sessions (see
  // authorizeRequest in debug_server.js). A credential that is valid for
  // session A must never authorize a write against session B, even though
  // the token itself is real (not guessed/forged) and passes safeTokenEqual
  // for its own session.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
  const server = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const baseUrl = await listen(server);

  try {
    const sessionA = (await createSession(baseUrl, 'session-a')).body;
    const sessionB = (await createSession(baseUrl, 'session-b')).body;
    assert.notEqual(sessionA.session_id, sessionB.session_id);
    assert.notEqual(sessionA.session_token, sessionB.session_token);

    const ownSessionWrite = await recordEvent(baseUrl, sessionA, 'writes to its own session');
    assert.equal(ownSessionWrite.status, 202);

    const crossSessionWrite = await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: {
        sessionId: sessionB.session_id,
        sessionToken: sessionA.session_token,
        msg: 'cross-session write attempt',
      },
    });
    assert.equal(crossSessionWrite.status, 401);
    assert.deepEqual(crossSessionWrite.body, { error: 'unauthorized' });

    const sessionBLog = await readFile(path.join(projectRoot, sessionB.log_file), 'utf8');
    assert.equal(sessionBLog, '', "session B's log must not receive session A's event");
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

test('retires inactive sessions before enforcing the session cap', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-session-retire-'));
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    limits: { maxSessions: 1, sessionIdleTimeoutMs: 40 },
  });
  const baseUrl = await listen(server);

  try {
    const first = await createSession(baseUrl);
    assert.equal(first.status, 201);
    await new Promise((resolve) => setTimeout(resolve, 90));

    const second = await createSession(baseUrl, 'fresh-debugging-run');
    assert.equal(second.status, 201, JSON.stringify(second.body));

    // Retirement revokes only the in-memory credential. The old evidence file
    // remains on disk and still counts toward aggregate storage accounting.
    const staleWrite = await recordEvent(baseUrl, first.body);
    assert.equal(staleWrite.status, 404);
    assert.deepEqual(staleWrite.body, { error: 'unknown_session' });
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

test('isInsideRoot rejects a path that resolves outside the verified root', async () => {
  // Unit-level regression for the startup token-file post-open
  // re-verification (main()'s TOCTOU-narrowing fix, mirroring
  // appendSessionEvent's post-open realpath check): openNoFollow's
  // O_NOFOLLOW only protects the FINAL path component, not a parent
  // directory swapped for a symlink between the earlier realpath(debugDir)
  // check and the open() call. isInsideRoot is the predicate the post-open
  // check calls to detect that the resolved path escaped the already-
  // verified root. Exercised directly here (deterministic) rather than by
  // racing a real filesystem swap against main()'s internal await points,
  // which has no reliable external synchronization point and would be
  // inherently flaky.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-inside-root-'));
  const outsideDir = await mkdtemp(path.join(tmpdir(), 'debug-skill-outside-root-'));
  try {
    const resolvedRoot = await realpath(projectRoot);
    const resolvedOutside = await realpath(outsideDir);

    // Simulates the parent (.debug) having been swapped for a symlink to an
    // outside directory: the token file's realpath now lands under the
    // outside tree even though the path STRING still says
    // "<root>/.debug/collector_token".
    const swappedTokenFile = path.join(resolvedOutside, 'collector_token');
    assert.equal(isInsideRoot(resolvedRoot, swappedTokenFile), false);

    // The legitimate, unswapped case must still pass.
    const legitimateTokenFile = path.join(resolvedRoot, '.debug', 'collector_token');
    assert.equal(isInsideRoot(resolvedRoot, legitimateTokenFile), true);

    // Exact-match (candidate equals root itself) must be rejected -- a real
    // token file can never legitimately BE the project root directory.
    assert.equal(isInsideRoot(resolvedRoot, resolvedRoot), false);

    // A sibling directory that merely shares a string prefix with the root
    // (e.g. root vs root-evil) must not be treated as "inside" by a naive
    // startsWith check; path.relative-based comparison must reject it.
    assert.equal(isInsideRoot(resolvedRoot, `${resolvedRoot}-evil`), false);
  } finally {
    await rm(projectRoot, { recursive: true, force: true });
    await rm(outsideDir, { recursive: true, force: true });
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

test(
  'tightens a pre-existing permissive token file to 0600 before writing the fresh secret',
  { skip: process.platform === 'win32' && 'POSIX file mode bits are not meaningfully enforced on Windows', timeout: 20000 },
  async () => {
    // assertPrivateRegularFile only checks isFile/nlink, never mode, so a
    // pre-existing collector_token left behind with a permissive mode (e.g.
    // 0644 from a prior process or misconfiguration) reaches the EEXIST/reuse
    // open branch unchanged. The fix chmods 0600 through the open descriptor
    // BEFORE truncate+write (see main()'s startup flow), so by the time any
    // fresh token bytes reach disk the file is already private -- previously
    // chmod ran AFTER the write, leaving a window where the new secret sat
    // under the file's old, possibly world/group-readable mode.
    //
    // This test cannot observe the mode DURING the write without
    // instrumenting fs internals, which is not worth the complexity for a
    // regression guard (a real race-timing test would be flaky with no
    // reliable synchronization point from outside the process). It instead
    // asserts the documented end state -- final mode is private regardless of
    // the file's prior mode -- and relies on the inline comment at the chmod
    // call site in debug_server.js to carry the ordering invariant.
    const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-'));
    let child;
    try {
      const debugDir = path.join(projectRoot, '.debug');
      const tokenFile = path.join(debugDir, 'collector_token');
      await mkdir(debugDir, { recursive: true });
      await writeFile(tokenFile, 'stale-token-with-permissive-mode', { mode: 0o644 });
      // writeFile's mode is masked by the process umask; chmod is not, so force
      // the fixture mode explicitly before asserting the reuse-branch pre-state.
      await chmod(tokenFile, 0o644);
      const preInfo = await stat(tokenFile);
      assert.equal(preInfo.mode & 0o777, 0o644, 'fixture must start permissive to exercise the reuse branch');

      const port = await findFreePort();
      const launched = launchCli(projectRoot, port);
      child = launched.child;
      const result = await launched.outcome;

      assert.equal(result.status, 'started');
      const contents = await readFile(tokenFile, 'utf8');
      assert.notEqual(contents, 'stale-token-with-permissive-mode');
      assert.match(contents, /^[A-Za-z0-9_-]{43}$/);
      const postInfo = await stat(tokenFile);
      assert.equal(postInfo.mode & 0o777, 0o600, 'token file must end private regardless of its prior mode');
    } finally {
      if (child) stopCli(child);
      await rm(projectRoot, { recursive: true, force: true });
    }
  },
);

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

test(
  'writes collector_token with a protected current-user-only Windows ACL',
  { skip: process.platform !== 'win32' && 'Windows ACL semantics only', timeout: 20000 },
  async () => {
    const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-windows-token-acl-'));
    let child;
    try {
      const port = await findFreePort();
      const launched = launchCli(projectRoot, port);
      child = launched.child;
      const result = await launched.outcome;
      assert.equal(result.status, 'started', result.stderr);

      const tokenFile = path.join(projectRoot, '.debug', 'collector_token');
      const acl = windowsAclIsCurrentUserOnly(tokenFile);
      assert.equal(acl.status, 0, `${acl.stdout}\n${acl.stderr}`);
      assert.equal(acl.stdout.trim(), 'ok');
    } finally {
      if (child) stopCli(child);
      await rm(projectRoot, { recursive: true, force: true });
    }
  },
);

test('releases its own collector_claim when startup fails after the claim is held', { timeout: 20000 }, async () => {
  // releaseOwnedClaim runs on server 'close' / process 'exit'. The externally
  // reachable path to it is a startup failure AFTER the claim is acquired:
  // here collector_port is pre-planted as a hard link to an outside file, so
  // the post-claim private-file assert fails the startup and closes the
  // server. The child's own regular claim must be read back through the
  // guarded sync read and unlinked, so a restart does not burn an
  // EEXIST+reclaim cycle (CodeRabbit #4781622077).
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-release-claim-'));
  let child;
  try {
    const debugDir = path.join(projectRoot, '.debug');
    const outsidePortFile = path.join(projectRoot, 'outside-port.txt');
    await mkdir(debugDir, { recursive: true });
    await writeFile(outsidePortFile, '1', 'utf8');
    await link(outsidePortFile, path.join(debugDir, 'collector_port'));

    const port = await findFreePort();
    const launched = launchCli(projectRoot, port);
    child = launched.child;
    const result = await launched.outcome;

    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /collector_port_not_private/);
    // The claim was acquired before the port-file failure and the ownership
    // check matched, so the release must have unlinked it.
    assert.equal(existsSync(path.join(debugDir, 'collector_claim')), false);
    // The token write precedes the port-file write, so it is on disk.
    assert.match(await readFile(path.join(debugDir, 'collector_token'), 'utf8'), /^[A-Za-z0-9_-]{43}$/);
    assert.equal(await readFile(outsidePortFile, 'utf8'), '1');
  } finally {
    if (child) stopCli(child);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('openNoFollowSync rejects non-integer flags before opening anything', () => {
  // Parity with the async openNoFollow guard in pr_closeout_fs.js: a
  // non-integer flags value must fail closed with a TypeError instead of
  // silently coercing through the attempt ladder's `|` (CodeRabbit review).
  const target = path.join(tmpdir(), 'debug-skill-nofollow-sync-flags');
  for (const flags of [undefined, null, 'r', 0.5, NaN]) {
    assert.throws(
      () => openNoFollowSync(target, flags),
      { name: 'TypeError', message: 'openNoFollowSync requires numeric fs.constants flags.' },
    );
  }
  // An integer flags value passes the guard and reaches the attempt ladder,
  // failing only on the missing target.
  assert.throws(() => openNoFollowSync(target, constants.O_RDONLY), { code: 'ENOENT' });
});

// Watch for the collector child to create its own regular collector_claim,
// then swap a pre-staged stand-in onto it, racing the release that runs when
// the sabotaged startup closes the server. POSIX renameSync replaces the
// claim atomically; Windows renameSync fails EPERM over an existing path, so
// it falls back to rmSync+renameSync -- a sub-millisecond gap that is NOT
// atomic, which is why callers must also require a measured swap->exit
// margin (see runClaimSwapAttempt) before treating an attempt as decisive:
// the release runs immediately before process exit, so a swap that completed
// well before the exit event necessarily preceded the release. The child is
// a separate process, so this setImmediate poll cannot starve it, and the
// token write between claim creation and the port-file failure leaves a wide
// window for the swap.
const swapClaimAfterCreate = (claimFile, stagedFile) => {
  const state = { landed: false, stopped: false, swapAt: 0 };
  const poll = async () => {
    while (!state.stopped && !state.landed) {
      let info = null;
      try {
        info = await lstat(claimFile);
      } catch {
        // Not created yet (or already released); keep polling.
      }
      if (info && info.isFile() && !info.isSymbolicLink() && info.nlink === 1) {
        try {
          try {
            renameSync(stagedFile, claimFile);
          } catch (error) {
            if (error?.code !== 'EPERM') throw error;
            rmSync(claimFile);
            renameSync(stagedFile, claimFile);
          }
          state.landed = true;
          state.swapAt = Date.now();
        } catch {
          // Lost the race against the child's own release; stop and let the
          // caller retry with a fresh launch.
          state.stopped = true;
        }
      }
      await new Promise((resolve) => setImmediate(resolve));
    }
  };
  poll().catch(() => {});
  return state;
};

// One sabotaged launch for the claim-swap tests: collector_port is a hard
// link to an outside file so startup fails at the post-claim port-file
// assert, which closes the server and runs releaseOwnedClaim. plantStaged
// receives { stagedFile, childPid, projectRoot } and must place the stand-in
// at stagedFile (swapClaimAfterCreate renames it onto the claim); it returns
// the exact stand-in target content for later intactness assertions.
const runClaimSwapAttempt = async (plantStaged) => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-claim-swap-'));
  const debugDir = path.join(projectRoot, '.debug');
  const claimFile = path.join(debugDir, 'collector_claim');
  const outsidePortFile = path.join(projectRoot, 'outside-port.txt');
  await mkdir(debugDir, { recursive: true });
  await writeFile(outsidePortFile, '1', 'utf8');
  await link(outsidePortFile, path.join(debugDir, 'collector_port'));

  const port = await findFreePort();
  const launched = launchCli(projectRoot, port);
  const { child } = launched;
  let swap = null;
  try {
    const stagedFile = path.join(debugDir, 'collector_claim.staged');
    const standInContent = await plantStaged({ stagedFile, childPid: child.pid, projectRoot });
    swap = swapClaimAfterCreate(claimFile, stagedFile);
    const result = await launched.outcome;
    const exitAt = Date.now();
    return { projectRoot, debugDir, claimFile, result, swapped: swap.landed, swapAt: swap.swapAt, exitAt, standInContent };
  } catch (error) {
    // On any throw (plantStaged failed, outcome rejected) the caller never
    // receives projectRoot, so its finally-based rm cannot run -- remove the
    // temp root here or every failed attempt leaks one (CodeRabbit review).
    // Kill the child FIRST: a still-booting child can otherwise recreate the
    // root between this rm and the finally's stopCli. stopCli is idempotent,
    // so the finally call below stays as the backstop.
    stopCli(child);
    await rm(projectRoot, { recursive: true, force: true });
    throw error;
  } finally {
    // Stop the swap poller on every path; left running it would keep lstat-ing
    // a deleted claim path on every setImmediate tick for the rest of the
    // process (CodeRabbit review).
    if (swap) swap.stopped = true;
    stopCli(child);
  }
};

// Shared driver for the swapped-claim release tests. plantStaged builds the
// stand-in (symlink or hard link) and verifyStandIn asserts the guarded
// release left it untouched at collector_claim. An attempt only counts when
// the swap landed measurably BEFORE the child exited (the release runs right
// before exit, so a >=3ms margin proves the release saw the stand-in, not
// the child's own claim) AND the exit came from the port-file sabotage;
// anything else is retried, never failed. The stand-in's pid line names the
// CHILD, so a release that followed the swap and parsed it WOULD pass the
// ownership check and unlink the path -- the stand-in's survival is what
// proves the read was refused (CodeRabbit discussion_r3652923124).
const assertReleaseRefusesSwappedClaim = async (t, plantStaged, verifyStandIn) => {
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const { projectRoot, claimFile, result, swapped, swapAt, exitAt, standInContent } = await runClaimSwapAttempt(plantStaged);
    try {
      const decisive = swapped
        && exitAt - swapAt >= 3
        && result.exitCode === 1
        && /collector_port_not_private/.test(result.stderr);
      if (!decisive) continue;
      await verifyStandIn(claimFile);
      assert.equal(await readFile(path.join(projectRoot, 'swap-target.txt'), 'utf8'), standInContent);
      return;
    } finally {
      await rm(projectRoot, { recursive: true, force: true });
    }
  }
  t.skip('claim swap never landed ahead of the release; nothing asserted');
};

test('does not read or unlink a collector_claim swapped for a symlink before release', { timeout: 30000 }, async (t) => {
  // A local attacker with .debug write access can replace collector_claim
  // with a symlink between acquire and the shutdown release. The release must
  // not follow it: no read of the target's bytes (which would pass the
  // ownership check here) and no unlink driven by them (CodeRabbit
  // discussion_r3652923124).
  const probeRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-symlink-probe-'));
  try {
    const probeTarget = path.join(probeRoot, 'target');
    await writeFile(probeTarget, 'x', 'utf8');
    await symlink(probeTarget, path.join(probeRoot, 'link'), 'file');
  } catch (error) {
    // File symlinks need SeCreateSymbolicLinkPrivilege on Windows.
    t.skip(`file symlinks unavailable here: ${error?.code || error}`);
    return;
  } finally {
    await rm(probeRoot, { recursive: true, force: true });
  }

  await assertReleaseRefusesSwappedClaim(
    t,
    async ({ stagedFile, childPid, projectRoot }) => {
      const content = `1\nnot-the-child\n${childPid}\n`;
      await writeFile(path.join(projectRoot, 'swap-target.txt'), content, 'utf8');
      await symlink(path.join(projectRoot, 'swap-target.txt'), stagedFile, 'file');
      return content;
    },
    async (claimFile) => {
      const info = await lstat(claimFile);
      assert.equal(info.isSymbolicLink(), true, 'claim symlink must survive the release unread and unlinked');
    },
  );
});

test('does not read or unlink a collector_claim swapped for a hard link before release', { timeout: 30000 }, async (t) => {
  // Hard-link variant of the symlink swap: claimFile renamed onto an inode
  // shared with an outside file (nlink > 1). The guarded release must refuse
  // it exactly like readSmallRegularFile does for the reclaim path, leaving
  // both names of the shared inode in place. Runs without the privileges
  // file symlinks need on Windows.
  await assertReleaseRefusesSwappedClaim(
    t,
    async ({ stagedFile, childPid, projectRoot }) => {
      const content = `1\nnot-the-child\n${childPid}\n`;
      await writeFile(path.join(projectRoot, 'swap-target.txt'), content, 'utf8');
      await link(path.join(projectRoot, 'swap-target.txt'), stagedFile);
      return content;
    },
    async (claimFile) => {
      const info = await lstat(claimFile);
      assert.equal(info.isFile(), true, 'hard-linked claim must survive the release');
      assert.equal(info.nlink, 2, 'hard-linked claim inode must keep both names');
    },
  );
});

test('runClaimSwapAttempt removes the temp root and stops the poller when plantStaged throws', async () => {
  // Before the finally-based cleanup, a throwing plantStaged leaked the
  // debug-skill-claim-swap-* directory and left the swap poller lstat-ing a
  // deleted path on every setImmediate tick (CodeRabbit review).
  let failedRoot = null;
  await assert.rejects(
    runClaimSwapAttempt(async ({ projectRoot }) => {
      failedRoot = projectRoot;
      throw new Error('plant failed on purpose');
    }),
    /plant failed on purpose/,
  );
  assert.equal(existsSync(failedRoot), false, 'error path must remove the temp project root');
});

test('reads and unlinks a collector_claim swapped for a still-valid regular file before release', { timeout: 30000 }, async (t) => {
  // The descriptor re-stat must not break the legitimate release path: a
  // swapped-in claim that still passes every post-open check (regular file,
  // single link, in-bounds size) is read through the descriptor and, because
  // its pid line names the child, drives the ownership unlink. The final
  // assertion inverts the refusal tests via the same measured-swap driver.
  await assertReleaseRefusesSwappedClaim(
    t,
    async ({ stagedFile, childPid, projectRoot }) => {
      const content = `1\nnot-the-child\n${childPid}\n`;
      await writeFile(path.join(projectRoot, 'swap-target.txt'), content, 'utf8');
      await writeFile(stagedFile, content, 'utf8');
      return content;
    },
    async (claimFile) => {
      assert.equal(existsSync(claimFile), false, 'valid swapped-in claim must be parsed and unlinked');
    },
  );
});

test('does not parse a collector_claim grown beyond the claim size cap before release', { timeout: 30000 }, async (t) => {
  // A swapped-in claim larger than MAX_CLAIM_FILE_BYTES must be refused even
  // though its leading lines parse as a valid claim naming the child pid:
  // the release re-stats the opened descriptor and enforces the size bound on
  // the descriptor's own metadata, so the oversized file survives unparsed
  // and unlinked (CodeRabbit discussion_r3652923124 follow-up).
  await assertReleaseRefusesSwappedClaim(
    t,
    async ({ stagedFile, childPid, projectRoot }) => {
      const content = `1\nnot-the-child\n${childPid}\n${'x'.repeat(512)}\n`;
      await writeFile(path.join(projectRoot, 'swap-target.txt'), content, 'utf8');
      await writeFile(stagedFile, content, 'utf8');
      return content;
    },
    async (claimFile) => {
      const info = await lstat(claimFile);
      assert.equal(info.isFile() && !info.isSymbolicLink(), true, 'oversized claim must survive the release unread and unlinked');
    },
  );
});

test('reports already_running when the SAME project root is relaunched on an occupied port', { timeout: 20000 }, async () => {
  // probeServer validates the /health identity shape but, on its own, cannot
  // tell whether a running collector serves THIS invocation's project. The
  // EADDRINUSE handler in main() must also compare project_hash before
  // concluding already_running; here the two launches share a projectRoot,
  // so the hashes match and the second launch must report already_running.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-eaddrinuse-same-'));
  let firstChild;
  let secondChild;
  try {
    const port = await findFreePort();
    const first = launchCli(projectRoot, port);
    firstChild = first.child;
    const firstResult = await first.outcome;
    assert.equal(firstResult.status, 'started', firstResult.stderr);

    const second = launchCli(projectRoot, port);
    secondChild = second.child;
    const secondResult = await second.outcome;

    assert.equal(secondResult.status, 'already_running', secondResult.stderr);
    const parsedLine = JSON.parse(secondResult.stdout.split('\n').find((line) => line.trim().startsWith('{')));
    assert.equal(parsedLine.service, COLLECTOR_SERVICE);
    assert.equal(parsedLine.port, port);
    assert.equal(JSON.stringify(parsedLine).includes(projectRoot), false);
  } finally {
    if (secondChild) stopCli(secondChild);
    if (firstChild) stopCli(firstChild);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('refuses a forged same-project listener without disclosing collector_token', { timeout: 20000 }, async () => {
  // The project hash is deliberately not a secret, so an attacker can forge a
  // plausible /health response. The relaunch must demand an HMAC proof and
  // never put collector_token in Authorization or any other request field.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-forged-peer-'));
  const identitySource = createDebugServer({ projectRoot, token: TEST_LAUNCH_TOKEN });
  const diskToken = 'private-token-that-must-not-reach-the-forged-listener';
  let forged;
  let secondChild;
  let observedAuthorization;
  let observedChallenge;
  try {
    const port = await findFreePort();
    await mkdir(path.join(projectRoot, '.debug'), { recursive: true });
    await writeFile(path.join(projectRoot, '.debug', 'collector_token'), diskToken, { mode: 0o600 });
    if (process.platform !== 'win32') await chmod(path.join(projectRoot, '.debug', 'collector_token'), 0o600);

    forged = http.createServer((request, response) => {
      const url = new URL(request.url, 'http://127.0.0.1');
      if (url.pathname === '/health') {
        response.writeHead(200, { 'Content-Type': 'application/json' });
        response.end(`${JSON.stringify({
          service: COLLECTOR_SERVICE,
          version: COLLECTOR_VERSION,
          instance_id: 'f'.repeat(32),
          project_hash: identitySource.collectorProjectHash,
          ready: true,
        })}\n`);
        return;
      }
      if (url.pathname === '/auth') {
        observedAuthorization = request.headers.authorization;
        observedChallenge = url.searchParams.get('challenge');
        response.writeHead(200, { 'Content-Type': 'application/json' });
        response.end('{"proof":"forged"}\n');
        return;
      }
      response.writeHead(404);
      response.end();
    });
    await new Promise((resolve, reject) => {
      forged.once('error', reject);
      forged.listen(port, '127.0.0.1', resolve);
    });

    const second = launchCli(projectRoot, port);
    secondChild = second.child;
    const result = await second.outcome;

    assert.equal(result.status, null);
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /already_running_token_unavailable/);
    assert.equal(observedAuthorization, undefined);
    assert.match(observedChallenge, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(observedChallenge.includes(diskToken), false);
  } finally {
    if (secondChild) stopCli(secondChild);
    if (forged) await close(forged);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('refuses already_running when the peer is ready but collector_token is missing', { timeout: 20000 }, async () => {
  // Codex #4780351874: readiness is latched in memory after token persistence.
  // If `.debug/collector_token` is deleted afterward, a successful
  // already_running exit would leave the documented client flow unable to
  // authorize /session. Relaunch must fail closed with a specific reason.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-eaddrinuse-notoken-'));
  let firstChild;
  let secondChild;
  try {
    const port = await findFreePort();
    const first = launchCli(projectRoot, port);
    firstChild = first.child;
    const firstResult = await first.outcome;
    assert.equal(firstResult.status, 'started', firstResult.stderr);

    await rm(path.join(projectRoot, '.debug', 'collector_token'));

    const second = launchCli(projectRoot, port);
    secondChild = second.child;
    const secondResult = await second.outcome;

    assert.equal(secondResult.status, null);
    assert.equal(secondResult.exitCode, 1);
    assert.equal(secondResult.stdout.includes('already_running'), false);
    assert.match(secondResult.stderr, /already_running_token_unavailable/);
  } finally {
    if (secondChild) stopCli(secondChild);
    if (firstChild) stopCli(firstChild);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('reports port_in_use_by_other_process (not a false already_running) when a DIFFERENT project root is launched on an occupied port', { timeout: 20000 }, async () => {
  // Finding: probeServer previously only verified /health's service/version/
  // instance_id, never which project the running instance actually serves.
  // A collector for project A occupying the port would make the EADDRINUSE
  // handler report already_running for a totally unrelated project B launch,
  // leaving B with neither a running collector nor a token file. The
  // project_hash comparison must treat a hash mismatch as a DIFFERENT
  // collector occupying the port, falling through to the existing
  // port_in_use_by_other_process failure path instead.
  const projectRootA = await mkdtemp(path.join(tmpdir(), 'debug-skill-eaddrinuse-a-'));
  const projectRootB = await mkdtemp(path.join(tmpdir(), 'debug-skill-eaddrinuse-b-'));
  let firstChild;
  let secondChild;
  try {
    const port = await findFreePort();
    const first = launchCli(projectRootA, port);
    firstChild = first.child;
    const firstResult = await first.outcome;
    assert.equal(firstResult.status, 'started', firstResult.stderr);

    const second = launchCli(projectRootB, port);
    secondChild = second.child;
    const secondResult = await second.outcome;

    // The second process must fail (never bind, never write projectRootB's
    // token) instead of reporting a false already_running for project A.
    assert.equal(secondResult.status, null);
    assert.equal(secondResult.exitCode, 1);
    assert.equal(secondResult.stdout.includes('already_running'), false);
    assert.match(secondResult.stderr, /port_in_use_by_other_process/);
    assert.equal(existsSync(path.join(projectRootB, '.debug', 'collector_token')), false);
  } finally {
    if (secondChild) stopCli(secondChild);
    if (firstChild) stopCli(firstChild);
    await rm(projectRootA, { recursive: true, force: true });
    await rm(projectRootB, { recursive: true, force: true });
  }
});

test('reclaims a stale collector_claim whose recorded port now serves a different project', { timeout: 20000 }, async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-claim-owner-a-'));
  const otherRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-claim-owner-b-'));
  const other = createDebugServer({ projectRoot: otherRoot, token: TEST_LAUNCH_TOKEN });
  const otherUrl = await listen(other);
  const port = await findFreePort();
  const claimPath = path.join(projectRoot, '.debug', 'collector_claim');
  await mkdir(path.dirname(claimPath), { recursive: true });
  await writeFile(claimPath, `${new URL(otherUrl).port}\nold-claim\n2147483646\n`, 'utf8');

  let launched;
  try {
    launched = launchCli(projectRoot, port);
    const result = await launched.outcome;
    assert.equal(result.status, 'started', result.stderr);
    assert.equal(await readFile(path.join(projectRoot, '.debug', 'collector_port'), 'utf8'), String(port));
  } finally {
    if (launched?.child) stopCli(launched.child);
    await close(other);
    await rm(projectRoot, { recursive: true, force: true });
    await rm(otherRoot, { recursive: true, force: true });
  }
});

test('does not reclaim a freshly created incomplete collector_claim', { timeout: 20000 }, async () => {
  // O_EXCL makes the claim visible before the creator's awaited writeFile.
  // A concurrent launcher must leave that fresh, empty regular file alone
  // rather than letting both processes acquire the same project ownership.
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-skill-claim-initializing-'));
  const port = await findFreePort();
  const claimPath = path.join(projectRoot, '.debug', 'collector_claim');
  await mkdir(path.dirname(claimPath), { recursive: true });
  await writeFile(claimPath, '', 'utf8');

  let launched;
  try {
    // The reclaim grace starts at the claim mtime. Refresh it immediately
    // before spawning so startup latency cannot consume the test fixture's
    // entire grace window on a busy runner.
    const now = new Date();
    await utimes(claimPath, now, now);
    launched = launchCli(projectRoot, port);
    const result = await launched.outcome;
    assert.equal(result.exitCode, 1);
    assert.match(result.stderr, /collector_claim_initializing/);
    assert.equal(await readFile(claimPath, 'utf8'), '');
    assert.equal(existsSync(path.join(projectRoot, '.debug', 'collector_token')), false);
  } finally {
    if (launched?.child) stopCli(launched.child);
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

test(
  'install.sh treats a dangling target symlink as an existing target',
  { skip: (!bashAvailable && 'bash is required') || (process.platform === 'win32' && 'POSIX-only: symlink'), timeout: 30000 },
  async () => {
    // bash's -e test follows a symlink and is false for one whose target is
    // missing, even though the symlink itself is a real filesystem entry at
    // that path. Without -L, that would let a non-forced install silently
    // proceed over a dangling symlink (bypassing the "target exists" refusal)
    // and then discard it with no backup ever made.
    const home = await mkdtemp(path.join(tmpdir(), 'install-dangling-home-'));
    const target = path.join(home, '.codex', 'skills', 'debug');
    const missingTarget = path.join(home, 'nowhere', 'does-not-exist');
    try {
      await mkdir(path.dirname(target), { recursive: true });
      await symlink(missingTarget, target);

      const installer = toBashPath(path.join(__dirname, '..', 'tools', 'install.sh'));
      const res = spawnSync('bash', [installer, '--home', toBashPath(home), '--target', 'codex'], { encoding: 'utf8' });
      assert.notEqual(res.status, 0, 'installer must refuse a dangling-symlink target without --force');
      assert.match(res.stderr || '', /target exists/i, `rejection message must mention the existing target: ${JSON.stringify(res)}`);

      const linkInfo = await lstat(target);
      assert.equal(linkInfo.isSymbolicLink(), true, 'the dangling symlink itself must still be there, not silently replaced');
      await assert.rejects(() => stat(target), { code: 'ENOENT' }, 'the symlink must still be dangling (untouched), not resolved to new content');

      const forced = spawnSync('bash', [installer, '--home', toBashPath(home), '--target', 'codex', '--force'], { encoding: 'utf8' });
      assert.equal(forced.status, 0, forced.stderr);
      const forcedResult = JSON.parse(forced.stdout.trim());
      assert.equal(forcedResult.status, 'installed');
      assert.notEqual(forcedResult.backup, '', '--force must back up the dangling symlink it replaces, not silently discard it');
      assert.equal(existsSync(path.join(target, 'SKILL.md')), true);
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  },
);

test(
  'install.sh reclaims a lock whose recorded local owner is gone',
  { skip: (!bashAvailable && 'bash is required') || (process.platform === 'win32' && 'POSIX-only: process ownership probe'), timeout: 30000 },
  async () => {
    // Lock files are created atomically with their owner metadata. A later
    // installer may reclaim one only after it can prove that the recorded
    // local PID no longer exists; this models an interrupted previous run
    // without ever removing an anonymous directory lock.
    const home = await mkdtemp(path.join(tmpdir(), 'install-stale-lock-home-'));
    const target = path.join(home, '.codex', 'skills', 'debug');
    try {
      const hostname = spawnSync('hostname', [], { encoding: 'utf8' }).stdout.trim();
      assert.notEqual(hostname, '', 'hostname is required for the stale-lock fixture');
      await mkdir(path.dirname(target), { recursive: true });
      await writeFile(
        `${target}.install-lock`,
        `pid=999999999\nhost=${hostname}\ntoken=interrupted-fixture\n`,
      );

      const installer = toBashPath(path.join(__dirname, '..', 'tools', 'install.sh'));
      const res = spawnSync('bash', [installer, '--home', toBashPath(home), '--target', 'codex'], { encoding: 'utf8' });
      assert.equal(res.status, 0, res.stderr);
      assert.equal(existsSync(target), true, 'installer must proceed after reclaiming the proven-stale lock');
      assert.equal(existsSync(`${target}.install-lock`), false, 'EXIT cleanup must release the newly acquired lock');
    } finally {
      await rm(home, { recursive: true, force: true });
    }
  },
);

test(
  'install.sh rejects a symlink payload entry before staging',
  { skip: (!bashAvailable && 'bash is required') || (process.platform === 'win32' && 'POSIX-only: symlink'), timeout: 30000 },
  async () => {
    // Exercise the REAL installer rather than duplicating its predicate: build a
    // minimal payload tree where one payload entry is a symlink to an outside
    // path, copy tools/install.sh into it, and assert the installer exits
    // non-zero at payload validation instead of staging the link.
    const root = await mkdtemp(path.join(tmpdir(), 'install-reject-src-'));
    const home = await mkdtemp(path.join(tmpdir(), 'install-reject-home-'));
    const outside = await mkdtemp(path.join(tmpdir(), 'install-reject-out-'));
    try {
      await mkdir(path.join(root, 'tools'));
      await writeFile(path.join(root, 'SKILL.md'), 'skill');
      await mkdir(path.join(root, 'agents'));
      await mkdir(path.join(root, 'references'));
      await mkdir(path.join(root, 'scripts'));
      await writeFile(path.join(outside, 'o'), 'x');
      // 'assets' payload entry is a symlink to an outside directory.
      await symlink(outside, path.join(root, 'assets'));
      await copyFile(path.join(__dirname, '..', 'tools', 'install.sh'), path.join(root, 'tools', 'install.sh'));
      const res = spawnSync('bash', [toBashPath(path.join(root, 'tools', 'install.sh')), '--home', toBashPath(home), '--target', 'codex'], { encoding: 'utf8' });
      assert.notEqual(res.status, 0, 'installer must exit non-zero for a symlink payload entry');
      assert.match((res.stderr || '') + (res.stdout || ''), /symlink|regular file/i, `rejection message must mention symlink/regular file: ${JSON.stringify(res)}`);
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(home, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  },
);

test(
  'install.sh rejects a nested symlink inside a payload directory before staging',
  { skip: (!bashAvailable && 'bash is required') || (process.platform === 'win32' && 'POSIX-only: symlink'), timeout: 30000 },
  async () => {
    // The top-level entry check alone is not enough: 'scripts' itself is a
    // real directory here (passes -f/-d/! -L), but a symlink one level
    // inside it must still be caught before cp -R stages the link into the
    // installed skill.
    const root = await mkdtemp(path.join(tmpdir(), 'install-reject-nested-src-'));
    const home = await mkdtemp(path.join(tmpdir(), 'install-reject-nested-home-'));
    const outside = await mkdtemp(path.join(tmpdir(), 'install-reject-nested-out-'));
    try {
      await mkdir(path.join(root, 'tools'));
      await writeFile(path.join(root, 'SKILL.md'), 'skill');
      await mkdir(path.join(root, 'agents'));
      await mkdir(path.join(root, 'assets'));
      await mkdir(path.join(root, 'references'));
      await mkdir(path.join(root, 'scripts'));
      await writeFile(path.join(outside, 'secret'), 'x');
      // Nested symlink: 'scripts' is a real directory, but 'scripts/helper.js'
      // points outside the tree.
      await symlink(path.join(outside, 'secret'), path.join(root, 'scripts', 'helper.js'));
      await copyFile(path.join(__dirname, '..', 'tools', 'install.sh'), path.join(root, 'tools', 'install.sh'));
      const res = spawnSync('bash', [toBashPath(path.join(root, 'tools', 'install.sh')), '--home', toBashPath(home), '--target', 'codex'], { encoding: 'utf8' });
      assert.notEqual(res.status, 0, 'installer must exit non-zero for a nested symlink payload entry');
      assert.match((res.stderr || '') + (res.stdout || ''), /symlink|special file/i, `rejection message must mention symlink/special file: ${JSON.stringify(res)}`);
      assert.equal(existsSync(path.join(home, '.codex', 'skills', 'debug', 'scripts', 'helper.js')), false, 'nested symlink must never be staged into an installed skill');
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(home, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  },
);

test(
  'install.sh never prints a stdout success record for a target that gets rolled back',
  {
    // mode 0555 does not block the installer when the suite runs as UID 0
    // (common in containers); skip rather than assert a permission model root
    // can always bypass.
    skip: (!bashAvailable && 'bash is required')
      || (process.platform === 'win32' && 'POSIX-only: chmod-based permission denial')
      || (typeof process.getuid === 'function' && process.getuid() === 0 && 'chmod denial is not observable as root'),
    timeout: 30000,
  },
  async () => {
    // For --target both, .codex commits first and .agents second. Deny write
    // on .agents/skills' parent so only the SECOND destination's commit
    // fails, forcing rollback of the already-committed first destination. A
    // consumer that processes emitted result lines must never see a success
    // record for .codex: by the time the script exits non-zero, that
    // destination has already been rolled back and no longer exists.
    const home = await mkdtemp(path.join(tmpdir(), 'install-partial-home-'));
    const agentsSkillsDir = path.join(home, '.agents', 'skills');
    await mkdir(agentsSkillsDir, { recursive: true });
    await chmod(agentsSkillsDir, 0o555);
    try {
      const res = spawnSync(
        'bash',
        [toBashPath(path.join(__dirname, '..', 'tools', 'install.sh')), '--home', toBashPath(home), '--target', 'both'],
        { encoding: 'utf8' },
      );
      assert.notEqual(res.status, 0, 'installer must exit non-zero when one of two targets fails to commit');
      assert.equal((res.stdout || '').trim(), '', `stdout must be empty for a transaction that failed overall: ${JSON.stringify(res)}`);
      assert.equal(
        existsSync(path.join(home, '.codex', 'skills', 'debug')),
        false,
        'the target that committed then had to be rolled back must not remain installed',
      );
    } finally {
      await chmod(agentsSkillsDir, 0o755);
      await rm(home, { recursive: true, force: true });
    }
  },
);

const pwshProbe = spawnSync('pwsh', ['-NoProfile', '-Command', '$true'], { encoding: 'utf8' });
const pwshAvailable = !pwshProbe.error && pwshProbe.status === 0;

const runInstallPs1 = (scriptPath, args) =>
  spawnSync('pwsh', ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, ...args], { encoding: 'utf8' });

test(
  'install.ps1 rejects a reparse-point payload entry before staging',
  { skip: (!pwshAvailable && 'pwsh is required') || (process.platform !== 'win32' && 'Windows-only: junction creation'), timeout: 30000 },
  async () => {
    // Mirrors 'install.sh rejects a symlink payload entry before staging'.
    // Junctions (unlike file/directory symlinks) do not require elevation or
    // Developer Mode on Windows, and set the same ReparsePoint attribute
    // install.ps1 must reject, so they are used as the fixture here.
    const root = await mkdtemp(path.join(tmpdir(), 'install-reject-src-'));
    const home = await mkdtemp(path.join(tmpdir(), 'install-reject-home-'));
    const outside = await mkdtemp(path.join(tmpdir(), 'install-reject-out-'));
    try {
      await mkdir(path.join(root, 'tools'));
      await writeFile(path.join(root, 'SKILL.md'), 'skill');
      await mkdir(path.join(root, 'agents'));
      await mkdir(path.join(root, 'references'));
      await mkdir(path.join(root, 'scripts'));
      await writeFile(path.join(outside, 'o'), 'x');
      // 'assets' payload entry is a junction to an outside directory.
      await symlink(outside, path.join(root, 'assets'), 'junction');
      await copyFile(path.join(__dirname, '..', 'tools', 'install.ps1'), path.join(root, 'tools', 'install.ps1'));
      const res = runInstallPs1(path.join(root, 'tools', 'install.ps1'), ['-Target', 'Codex', '-HomePath', home]);
      assert.notEqual(res.status, 0, 'installer must exit non-zero for a reparse-point payload entry');
      assert.match((res.stderr || '') + (res.stdout || ''), /symlink|junction|reparse|regular file/i, `rejection message must mention symlink/junction/reparse: ${JSON.stringify(res)}`);
      assert.equal(existsSync(path.join(home, '.codex', 'skills', 'debug')), false, 'reparse-point payload entry must never be staged into an installed skill');
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(home, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  },
);

test(
  'install.ps1 rejects a reparse point nested inside a payload directory before staging',
  { skip: (!pwshAvailable && 'pwsh is required') || (process.platform !== 'win32' && 'Windows-only: junction creation'), timeout: 30000 },
  async () => {
    // Get-ChildItem -Recurse would normally follow a symlinked/junctioned
    // subdirectory while walking the tree; the installer must instead walk
    // one level at a time and reject a nested reparse point before ever
    // recursing into it.
    const root = await mkdtemp(path.join(tmpdir(), 'install-reject-nested-src-'));
    const home = await mkdtemp(path.join(tmpdir(), 'install-reject-nested-home-'));
    const outside = await mkdtemp(path.join(tmpdir(), 'install-reject-nested-out-'));
    try {
      await mkdir(path.join(root, 'tools'));
      await writeFile(path.join(root, 'SKILL.md'), 'skill');
      await mkdir(path.join(root, 'agents'));
      await mkdir(path.join(root, 'assets'));
      await mkdir(path.join(root, 'references'));
      await mkdir(path.join(root, 'scripts'));
      // Nested junction: 'scripts' is a real directory, but
      // 'scripts/nested-dir' is a junction pointing outside the tree.
      await symlink(outside, path.join(root, 'scripts', 'nested-dir'), 'junction');
      await copyFile(path.join(__dirname, '..', 'tools', 'install.ps1'), path.join(root, 'tools', 'install.ps1'));
      const res = runInstallPs1(path.join(root, 'tools', 'install.ps1'), ['-Target', 'Codex', '-HomePath', home]);
      assert.notEqual(res.status, 0, 'installer must exit non-zero for a nested reparse-point payload entry');
      assert.match((res.stderr || '') + (res.stdout || ''), /symlink|junction|reparse|regular file/i, `rejection message must mention symlink/junction/reparse: ${JSON.stringify(res)}`);
      assert.equal(existsSync(path.join(home, '.codex', 'skills', 'debug')), false, 'nested reparse point must never be staged into an installed skill');
    } finally {
      await rm(root, { recursive: true, force: true });
      await rm(home, { recursive: true, force: true });
      await rm(outside, { recursive: true, force: true });
    }
  },
);
