# Hypothesis Lifecycle + Session Read Endpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `POST /hypothesis` (event-sourced hypothesis lifecycle lines through the existing hardened append path) and `GET /sessions/:id/logs` (launch-token, fail-closed filtered NDJSON reads) to `scripts/debug_server.js`, plus the documentation sync this implies.

**Architecture:** Hypotheses are typed lines in the existing session log, assembled server-side from an allowlist and passed through `redactEventForAppend` → capacity reservation → `appendSessionEvent`, exactly mirroring `/log`. Reads join the same per-session `appendChain`, re-verify the log-file identity with the append path's own discipline, read exactly `bytesWritten` bytes, and emit stored lines verbatim after filtering. Capability split: session token = event writes only (unchanged); launch token = hypothesis writes + reads.

**Tech Stack:** Node.js ≥20, zero runtime dependencies, `node:test` via `node --test --test-concurrency=1`, CommonJS.

**Spec:** `docs/superpowers/specs/2026-08-06-hypothesis-endpoint-design.md` (approved, commit `9092dfc`). Branch: `feat/hypothesis-endpoint`, stacked on the merged `codex/publish-debug-skill` (`372b553`).

**Line anchors** cite `372b553`-merged code: `appendSessionEvent` ~632, `HYPOTHESIS` insertion target = the single `sendJson(response, 404, { error: 'not_found' });` at ~1423, `/log` handler ~1355–1421, `/health` ~1092, `/session` ~1123. Lines shift as tasks land — always locate by quoted code, not number.

---

### Task 1: `POST /hypothesis` route

**Files:**
- Modify: `scripts/debug_server.js` — one module-level constant above `createDebugServer`'s JSDoc; one route block inserted immediately BEFORE the `sendJson(response, 404, { error: 'not_found' });` line
- Test: `scripts/debug_server.test.js` (append at end; one small helper)

- [ ] **Step 1: Write the failing integration tests**

Append at the end of `scripts/debug_server.test.js` (reuses existing `withRedactionServer`, `readSessionLines`, `createSession`, `requestJson`, `listen`, `close`, `TEST_LAUNCH_TOKEN`, and the `mkdtemp`/`rm`/`readFile`/`tmpdir`/`path` imports):

```js
const postHypothesis = (baseUrl, body, headers = { Authorization: `Bearer ${TEST_LAUNCH_TOKEN}` }) =>
  requestJson(baseUrl, { method: 'POST', pathname: '/hypothesis', headers, body });

test('POST /hypothesis appends a redacted, allowlisted, server-stamped line', async () => {
  await withRedactionServer({ API_TOKEN: 'supersecretvalue123' }, [], async ({ baseUrl, projectRoot }) => {
    const session = (await createSession(baseUrl)).body;
    const response = await postHypothesis(baseUrl, {
      sessionId: session.session_id,
      hypothesisId: 'H1',
      status: 'OPEN',
      title: 'token supersecretvalue123 leaks',
      note: 'seen in supersecretvalue123 header',
      runId: 'r1',
      extraneous: 'dropped',
      ts: 'client-supplied-ignored',
    });
    assert.equal(response.status, 202);
    assert.deepEqual(response.body, { status: 'recorded' });
    const [line] = await readSessionLines(projectRoot, session);
    assert.equal(line.type, 'hypothesis');
    assert.equal(line.hypothesisId, 'H1');
    assert.equal(line.status, 'OPEN');
    assert.equal(line.title, 'token [REDACTED] leaks');
    assert.equal(line.note, 'seen in [REDACTED] header');
    assert.equal(line.runId, 'r1');
    assert.equal(Object.hasOwn(line, 'extraneous'), false);
    assert.equal(Number.isNaN(Date.parse(line.ts)), false);
    assert.notEqual(line.ts, 'client-supplied-ignored');
  });
});

test('POST /hypothesis lifecycle appends event-sourced status lines in order', async () => {
  await withRedactionServer({}, [], async ({ baseUrl, projectRoot }) => {
    const session = (await createSession(baseUrl)).body;
    await postHypothesis(baseUrl, { sessionId: session.session_id, hypothesisId: 'H1', status: 'OPEN' });
    await postHypothesis(baseUrl, { session_id: session.session_id, hypothesisId: 'H1', status: 'CONFIRMED', note: 'later' });
    const lines = await readSessionLines(projectRoot, session);
    assert.deepEqual(lines.map((entry) => [entry.type, entry.hypothesisId, entry.status]), [
      ['hypothesis', 'H1', 'OPEN'],
      ['hypothesis', 'H1', 'CONFIRMED'],
    ]);
  });
});

test('POST /hypothesis validates fields fail-closed with nothing persisted', async () => {
  await withRedactionServer({}, [], async ({ baseUrl, projectRoot }) => {
    const session = (await createSession(baseUrl)).body;
    const cases = [
      [{ sessionId: session.session_id, status: 'OPEN' }, 'invalid_hypothesis_id'],
      [{ sessionId: session.session_id, hypothesisId: '', status: 'OPEN' }, 'invalid_hypothesis_id'],
      [{ sessionId: session.session_id, hypothesisId: '   ', status: 'OPEN' }, 'invalid_hypothesis_id'],
      [{ sessionId: session.session_id, hypothesisId: 42, status: 'OPEN' }, 'invalid_hypothesis_id'],
      [{ sessionId: session.session_id, hypothesisId: 'H1' }, 'invalid_hypothesis_status'],
      [{ sessionId: session.session_id, hypothesisId: 'H1', status: 'MAYBE' }, 'invalid_hypothesis_status'],
      [{ sessionId: session.session_id, hypothesisId: 'H1', status: 'open' }, 'invalid_hypothesis_status'],
      [{ sessionId: session.session_id, hypothesisId: 'H1', status: 'OPEN', title: 42 }, 'invalid_hypothesis_field'],
      [{ sessionId: session.session_id, hypothesisId: 'H1', status: 'OPEN', note: {} }, 'invalid_hypothesis_field'],
      [{ sessionId: session.session_id, hypothesisId: 'H1', status: 'OPEN', runId: [] }, 'invalid_hypothesis_field'],
    ];
    for (const [body, code] of cases) {
      const response = await postHypothesis(baseUrl, body);
      assert.equal(response.status, 400, code);
      assert.equal(response.body.error, code);
    }
    const raw = await readFile(path.join(projectRoot, session.log_file), 'utf8');
    assert.equal(raw, '');
  });
});

test('POST /hypothesis enforces the launch-token capability split both ways', async () => {
  await withRedactionServer({}, [], async ({ baseUrl, projectRoot }) => {
    const session = (await createSession(baseUrl)).body;
    const withSessionToken = await postHypothesis(
      baseUrl,
      { sessionId: session.session_id, hypothesisId: 'H1', status: 'OPEN' },
      { Authorization: `Bearer ${session.session_token}` },
    );
    assert.equal(withSessionToken.status, 401);
    const withNoToken = await postHypothesis(
      baseUrl,
      { sessionId: session.session_id, hypothesisId: 'H1', status: 'OPEN' },
      {},
    );
    assert.equal(withNoToken.status, 401);
    // /log stays session-token-only: the launch token must NOT write events.
    const launchOnLog = await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: { sessionId: session.session_id, sessionToken: TEST_LAUNCH_TOKEN, msg: 'nope' },
    });
    assert.equal(launchOnLog.status, 401);
    const raw = await readFile(path.join(projectRoot, session.log_file), 'utf8');
    assert.equal(raw, '');
  });
});

test('hypothesis lines consume the shared event and byte caps', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-hypo-'));
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    redactionEnv: {},
    limits: { maxEventsPerSession: 1 },
  });
  const baseUrl = await listen(server);
  try {
    const session = (await createSession(baseUrl)).body;
    const first = await postHypothesis(baseUrl, { sessionId: session.session_id, hypothesisId: 'H1', status: 'OPEN' });
    assert.equal(first.status, 202);
    const second = await postHypothesis(baseUrl, { sessionId: session.session_id, hypothesisId: 'H2', status: 'OPEN' });
    assert.equal(second.status, 429);
    assert.equal(second.body.error, 'event_limit_reached');
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('hypothesis lines respect the aggregate byte cap', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-hypo-'));
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    redactionEnv: {},
    limits: { maxTotalBytes: 10 },
  });
  const baseUrl = await listen(server);
  try {
    const session = (await createSession(baseUrl)).body;
    const response = await postHypothesis(baseUrl, { sessionId: session.session_id, hypothesisId: 'H1', status: 'OPEN' });
    assert.equal(response.status, 429);
    assert.equal(response.body.error, 'storage_limit_reached');
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('POST /hypothesis rejects unknown sessions', async () => {
  await withRedactionServer({}, [], async ({ baseUrl }) => {
    const unknown = await postHypothesis(baseUrl, {
      sessionId: 'debug-nope-000000000000',
      hypothesisId: 'H1',
      status: 'OPEN',
    });
    assert.equal(unknown.status, 404);
    assert.equal(unknown.body.error, 'unknown_session');
  });
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test --test-concurrency=1 --test-name-pattern "hypothesis" scripts/debug_server.test.js`
Expected: the new tests FAIL — the route doesn't exist, so authenticated calls get `404 not_found` (assertions on 202/400/etc. fail). The two pre-existing tests whose titles contain "hypothesis" (redactEventValue key tests) must still pass. Any other failure shape (syntax/import) → fix first.

- [ ] **Step 3: Implement**

(a) In `scripts/debug_server.js`, directly ABOVE the `/**` JSDoc of `createDebugServer` (locate with Grep `Build (but do not start)`), insert:

```js
// Valid hypothesis lifecycle statuses (spec:
// docs/superpowers/specs/2026-08-06-hypothesis-endpoint-design.md). Any
// status may follow any status — the append-only log preserves the audit
// trail; only the vocabulary is fixed.
const HYPOTHESIS_STATUSES = new Set(['OPEN', 'CONFIRMED', 'REJECTED', 'INCONCLUSIVE']);
```

(b) Insert this route block immediately BEFORE the single `sendJson(response, 404, { error: 'not_found' });` line (verify with Grep that it occurs exactly once):

```js
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
          hypothesisId: payload.hypothesisId,
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

```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test --test-concurrency=1 --test-name-pattern "hypothesis" scripts/debug_server.test.js`
Expected: all pass. Then `node --check scripts/debug_server.js` — clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/debug_server.js scripts/debug_server.test.js
git commit -m "feat(collector): POST /hypothesis event-sourced lifecycle lines

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 2: `GET /sessions/:id/logs` route

**Files:**
- Modify: `scripts/debug_server.js` — route block inserted BETWEEN the Task-1 `/hypothesis` block and the 404 line
- Test: `scripts/debug_server.test.js` (append; adds a raw-response helper)

- [ ] **Step 1: Write the failing integration tests**

Append (note: the existing `requestJson` drops the query string — `url.search` — and JSON-parses the body, so NDJSON responses need this additive helper):

```js
const requestRaw = (baseUrl, { headers = {}, method = 'GET', pathname = '/' } = {}) =>
  new Promise((resolve, reject) => {
    const url = new URL(pathname, baseUrl);
    const request = http.request(
      {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method,
        headers,
      },
      (response) => {
        let text = '';
        response.setEncoding('utf8');
        response.on('data', (chunk) => { text += chunk; });
        response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, text }));
      },
    );
    request.on('error', reject);
    request.end();
  });

const LAUNCH_AUTH = { Authorization: `Bearer ${TEST_LAUNCH_TOKEN}` };

const seedReadableSession = async (baseUrl) => {
  const session = (await createSession(baseUrl)).body;
  const log = (body) => requestJson(baseUrl, {
    method: 'POST',
    pathname: '/log',
    body: { sessionId: session.session_id, sessionToken: session.session_token, ...body },
  });
  await log({ msg: 'e1', hypothesisId: 'H1', runId: 'r1' });
  await log({ msg: 'e2', hypothesisId: 'H2' });
  await postHypothesis(baseUrl, { sessionId: session.session_id, hypothesisId: 'H1', status: 'OPEN' });
  await log({ msg: 'e3', runId: 'r2' });
  await postHypothesis(baseUrl, { sessionId: session.session_id, hypothesisId: 'H1', status: 'CONFIRMED' });
  return session;
};

test('GET /sessions/:id/logs requires the launch token and serves verbatim NDJSON', async () => {
  await withRedactionServer({}, [], async ({ baseUrl, projectRoot }) => {
    const session = await seedReadableSession(baseUrl);
    const noAuth = await requestRaw(baseUrl, { pathname: `/sessions/${session.session_id}/logs` });
    assert.equal(noAuth.status, 401);
    const sessionAuth = await requestRaw(baseUrl, {
      pathname: `/sessions/${session.session_id}/logs`,
      headers: { Authorization: `Bearer ${session.session_token}` },
    });
    assert.equal(sessionAuth.status, 401);
    const ok = await requestRaw(baseUrl, {
      pathname: `/sessions/${session.session_id}/logs`,
      headers: LAUNCH_AUTH,
    });
    assert.equal(ok.status, 200);
    assert.equal(ok.headers['content-type'], 'application/x-ndjson');
    const raw = await readFile(path.join(projectRoot, session.log_file), 'utf8');
    // Verbatim guarantee: an unfiltered read IS the stored bytes.
    assert.equal(ok.text, raw);
    for (const line of ok.text.split('\n').filter(Boolean)) JSON.parse(line);
  });
});

test('GET /sessions/:id/logs filters combine and limit is tail-biased', async () => {
  await withRedactionServer({}, [], async ({ baseUrl }) => {
    const session = await seedReadableSession(baseUrl);
    const fetchLogs = async (query) => {
      const res = await requestRaw(baseUrl, {
        pathname: `/sessions/${session.session_id}/logs${query}`,
        headers: LAUNCH_AUTH,
      });
      assert.equal(res.status, 200, query);
      return res.text.split('\n').filter(Boolean).map((line) => JSON.parse(line));
    };
    assert.deepEqual((await fetchLogs('?type=hypothesis')).map((l) => l.status), ['OPEN', 'CONFIRMED']);
    assert.deepEqual((await fetchLogs('?type=event')).map((l) => l.msg), ['e1', 'e2', 'e3']);
    assert.deepEqual((await fetchLogs('?hypothesisId=H1')).map((l) => l.msg ?? l.status), ['e1', 'OPEN', 'CONFIRMED']);
    assert.deepEqual((await fetchLogs('?runId=r2')).map((l) => l.msg), ['e3']);
    assert.deepEqual((await fetchLogs('?type=event&hypothesisId=H1')).map((l) => l.msg), ['e1']);
    assert.deepEqual((await fetchLogs('?limit=2')).map((l) => l.msg ?? l.status), ['e3', 'CONFIRMED']);
    const all = await fetchLogs('');
    const boundary = all[2].ts;
    const since = await fetchLogs(`?sinceTs=${encodeURIComponent(boundary)}`);
    assert.equal(since.length >= 3, true);
    assert.equal(since.every((l) => Date.parse(l.ts) >= Date.parse(boundary)), true);
    const until = await fetchLogs(`?untilTs=${encodeURIComponent(boundary)}`);
    assert.equal(until.every((l) => Date.parse(l.ts) <= Date.parse(boundary)), true);
  });
});

test('GET /sessions/:id/logs rejects malformed and unknown query parameters fail-closed', async () => {
  await withRedactionServer({}, [], async ({ baseUrl }) => {
    const session = await seedReadableSession(baseUrl);
    for (const query of ['?type=bogus', '?sinceTs=notadate', '?untilTs=', '?limit=0', '?limit=abc', '?limit=-1', '?surprise=1']) {
      const res = await requestRaw(baseUrl, {
        pathname: `/sessions/${session.session_id}/logs${query}`,
        headers: LAUNCH_AUTH,
      });
      assert.equal(res.status, 400, query);
      assert.equal(JSON.parse(res.text).error, 'invalid_query', query);
    }
  });
});

test('GET /sessions/:id/logs is live-only and fail-closed on identity change', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-read-'));
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    redactionEnv: {},
    limits: { sessionIdleTimeoutMs: 5 },
  });
  const baseUrl = await listen(server);
  try {
    const unknown = await requestRaw(baseUrl, { pathname: '/sessions/debug-nope-000000000000/logs', headers: LAUNCH_AUTH });
    assert.equal(unknown.status, 404);
    assert.equal(JSON.parse(unknown.text).error, 'unknown_session');
    const session = (await createSession(baseUrl)).body;
    // Swap the log file out from under the recorded identity.
    const logPath = path.join(projectRoot, session.log_file);
    await rm(logPath);
    await writeFile(logPath, '{"msg":"forged"}\n');
    const swapped = await requestRaw(baseUrl, { pathname: `/sessions/${session.session_id}/logs`, headers: LAUNCH_AUTH });
    assert.equal(swapped.status, 409);
    assert.equal(JSON.parse(swapped.text).error, 'session_log_replaced');
    // Idle retirement: after the timeout the map entry is gone → 404.
    await new Promise((resolve) => setTimeout(resolve, 25));
    const retired = await requestRaw(baseUrl, { pathname: `/sessions/${session.session_id}/logs`, headers: LAUNCH_AUTH });
    assert.equal(retired.status, 404);
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});

test('GET /sessions/:id/logs output never contains a raw known secret', async () => {
  await withRedactionServer({ API_TOKEN: 'supersecretvalue123' }, [], async ({ baseUrl }) => {
    const session = (await createSession(baseUrl)).body;
    await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: { sessionId: session.session_id, sessionToken: session.session_token, msg: 'leak supersecretvalue123' },
    });
    const res = await requestRaw(baseUrl, { pathname: `/sessions/${session.session_id}/logs`, headers: LAUNCH_AUTH });
    assert.equal(res.status, 200);
    assert.equal(res.text.includes('supersecretvalue123'), false);
    assert.equal(res.text.includes('[REDACTED]'), true);
  });
});
```

(`writeFile` is already imported from `node:fs/promises` at the top of the test file — verify; if not, add it to that import list.)

Spec deviation note (documented in Task 3): the spec's test group 6 lists a provisional-425 GET case, but a provisional session's id is never observable outside the `/session` handler (reservation ids are random and never returned; the real id is only returned after `provisional` clears), so the 425 branch is defensively present in the route but not black-box testable. Record, don't fake.

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test --test-concurrency=1 --test-name-pattern "GET /sessions" scripts/debug_server.test.js`
Expected: FAIL — every GET returns `404 not_found` (route missing).

- [ ] **Step 3: Implement**

Insert BETWEEN the Task-1 `/hypothesis` block's closing `}` and the `sendJson(response, 404, { error: 'not_found' });` line:

```js
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
        for (const name of query.keys()) {
          if (!allowedParams.has(name)) throw new RequestError('invalid_query');
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
            return buffer.toString('utf8');
          } finally {
            await handle.close();
          }
        });
        session.appendChain = run;
        const text = await run;
        const matched = [];
        for (const rawLine of text.split('\n')) {
          if (!rawLine) continue;
          // Server-written lines always parse (they were JSON.stringify'd at
          // append time); a parse failure here would mean identity-checked
          // bytes changed underneath us and surfaces as internal_error.
          const parsed = JSON.parse(rawLine);
          const lineType = parsed.type === 'hypothesis' ? 'hypothesis' : 'event';
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

```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test --test-concurrency=1 --test-name-pattern "GET /sessions|hypothesis" scripts/debug_server.test.js`
Expected: all pass. Then the full file: `node --test --test-concurrency=1 scripts/debug_server.test.js` — 0 fail (count grows by Task 1+2's new tests). `node --check scripts/debug_server.js` — clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/debug_server.js scripts/debug_server.test.js
git commit -m "feat(collector): GET /sessions/:id/logs launch-token filtered reads

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 3: Documentation + stale-doc sync

**Files:**
- Modify: `SKILL.md`, `README.md`, `scripts/debug_server.js` (JSDoc routes list only), `docs/superpowers/specs/2026-08-05-collector-redaction-design.md`, `docs/superpowers/specs/2026-08-06-hypothesis-endpoint-design.md`

- [ ] **Step 1: SKILL.md Log Format + workflow note**

After the existing NDJSON example in `## Log Format`, add:

```markdown
Hypothesis lifecycle lines share the same log (a line without `type` is an event):

```json
{"ts":"2026-08-06T09:07:11.000Z","type":"hypothesis","hypothesisId":"H1","status":"CONFIRMED","note":"null until session loads"}
```

Record status transitions (`OPEN`, `CONFIRMED`, `REJECTED`, `INCONCLUSIVE`) via
`POST /hypothesis` (launch token) as evidence accumulates; the latest line per
`hypothesisId` is its current status and the full history stays auditable.
```

- [ ] **Step 2: SKILL.md stale troubleshooting row**

Replace the row containing "roughly 1,700 levels" with:

```markdown
| `/log` returns `log_redaction_failed` | The event nests deeper than the collector's redaction depth bound (64 levels); flatten the logged `data` payload |
```

- [ ] **Step 3: README trust model**

In the "Debug collector trust model" section, replace the routes sentence fragment `Routes:` listing in `scripts/debug_server.js`'s factory JSDoc (see Step 5) and, in README, append after the redaction choke-point paragraph:

```markdown
Two launch-token capabilities extend the model: `POST /hypothesis` records
event-sourced hypothesis status lines through the same append and redaction
path, and `GET /sessions/:id/logs` serves filtered, verbatim, already-redacted
NDJSON for live sessions with the append path's own file-identity checks. The
per-session token keeps exactly one capability: writing events via `POST /log`.
`GET /health` additionally reports redaction registry headroom counts
(cardinality only, never token values).
```

- [ ] **Step 4: Redaction spec band-row sync**

In `docs/superpowers/specs/2026-08-05-collector-redaction-design.md`, replace the "Event walk/apply" row's band sentence ("In a narrow band just above the serializer's recursion limit… equally fail-closed.") with:

```markdown
Superseded by the explicit `REDACTION_MAX_DEPTH` (64) bound landed in the merged review pass: nesting beyond the bound throws a defined error mapped to `log_redaction_failed`, making the fail-closed code deterministic across platforms.
```

- [ ] **Step 5: Factory JSDoc routes list + hypothesis spec amendments**

In `scripts/debug_server.js`'s `createDebugServer` JSDoc, extend the `Routes:` sentence to include `POST /hypothesis` (launch token, hypothesis lifecycle line) and `GET /sessions/:id/logs` (launch token, filtered NDJSON read).

In `docs/superpowers/specs/2026-08-06-hypothesis-endpoint-design.md`: add `invalid_hypothesis_field` 400 to the error table (non-string `title`/`note`/`runId`); annotate test group 6 that the provisional-425 GET case is defensively implemented but not black-box reachable (provisional ids are never observable externally).

- [ ] **Step 6: Validate and commit**

Run: `npm run validate` → PASS. `node --check scripts/debug_server.js` → clean.

```bash
git add SKILL.md README.md scripts/debug_server.js docs/superpowers/specs/2026-08-05-collector-redaction-design.md docs/superpowers/specs/2026-08-06-hypothesis-endpoint-design.md
git commit -m "docs(collector): hypothesis lifecycle + read endpoint docs, depth-bound sync

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 4: Full verification

- [ ] **Step 1:** `npm test` — 0 fail (skips OK). Investigate any failure; never rerun-until-green.
- [ ] **Step 2:** `npm run validate` → PASS; `npm run scan:suppressions` → no findings.
- [ ] **Step 3:** `git diff 372b553...HEAD` reviewed against the spec: exactly one new constant, two route blocks, tests, docs. Nothing else drifted.
- [ ] **Step 4:** Report honestly; final whole-implementation review follows via the coordinator.
