# Collector-Side Secret Redaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enforce the secrets half of Critical Rule 5 inside `scripts/debug_server.js`: every persisted log event passes a fail-closed redaction choke point that strips known secrets (sensitive-named env values, `DEBUG_REDACT_NAMES` opt-ins, and the collector's own tokens) including all encoded variants.

**Architecture:** Reuse the self-contained `buildSecretReplacements` from `scripts/pr_closeout_stream.js` (its only import is `node:string_decoder`). A `createRedactionContext` owns an append-only token registry and a cached longest-first needle list, rebuilt push-then-rebuild at each `/session` mint. A pure `redactEventValue` deep-walks the event (string leaves + object keys, collision-disambiguated) between event assembly and `JSON.stringify` in the `/log` handler; `redactEventForAppend` maps any walk failure to `RequestError('log_redaction_failed', 500)` so nothing raw is ever written.

**Tech Stack:** Node.js ≥20, zero runtime dependencies, `node:test` (run with `--test-concurrency=1`), CommonJS.

**Spec:** `docs/superpowers/specs/2026-08-05-collector-redaction-design.md` (approved). Branch: `feat/collector-redaction` (already checked out, stacked on `codex/publish-debug-skill`).

**Line-number caveat:** anchors below cite the file as of commit `e6e1694`. Task 1 inserts code, shifting later lines — always locate edits by the quoted surrounding code, not the cited number.

---

### Task 1: Pure redaction helpers (module-level, unit-tested)

**Files:**
- Modify: `scripts/debug_server.js` (insert new section immediately after the `appendSessionEvent` function, which ends `};` at ~line 689; add exports to the `module.exports` block at end of file)
- Test: `scripts/debug_server.test.js` (append at end of file)

- [ ] **Step 1: Write the failing unit tests**

Append to `scripts/debug_server.test.js`:

```js
test('redactEventValue redacts string leaves, nested data, and object keys', () => {
  const replacements = buildSecretReplacements(
    { API_TOKEN: 'supersecretvalue123' },
    [],
  );
  const event = {
    ts: '2026-08-05T00:00:00.000Z',
    msg: 'auth failed for supersecretvalue123',
    data: {
      nested: { detail: 'retry with supersecretvalue123 now' },
      supersecretvalue123: 'used as key',
      list: ['supersecretvalue123', 42, true, null],
    },
  };
  const redacted = redactEventValue(event, replacements);
  assert.equal(redacted.msg, 'auth failed for [REDACTED]');
  assert.equal(redacted.data.nested.detail, 'retry with [REDACTED] now');
  assert.equal(redacted.data['[REDACTED]'], 'used as key');
  assert.deepEqual(redacted.data.list, ['[REDACTED]', 42, true, null]);
  assert.equal(Object.hasOwn(redacted.data, 'supersecretvalue123'), false);
});

test('redactEventValue leaves non-string leaves untouched and returns new objects', () => {
  const replacements = buildSecretReplacements({ API_TOKEN: 'supersecretvalue123' }, []);
  const event = { msg: 'clean', data: { count: 7, ok: false, none: null } };
  const redacted = redactEventValue(event, replacements);
  assert.deepEqual(redacted, event);
  assert.notEqual(redacted, event);
  assert.notEqual(redacted.data, event.data);
});

test('redactEventValue disambiguates colliding keys deterministically', () => {
  const replacements = buildSecretReplacements({ API_TOKEN: 'supersecretvalue123' }, []);
  const event = { data: { supersecretvalue123: 1, '[REDACTED]': 2 } };
  const redacted = redactEventValue(event, replacements);
  assert.deepEqual(redacted, { data: { '[REDACTED]': 1, '[REDACTED]#2': 2 } });
});

test('redactEventForAppend maps walk failures to log_redaction_failed 500', () => {
  // Covers spec test group 5 at unit level: with a well-formed needle list
  // the walk cannot be made to throw through HTTP without a fake injection
  // seam, so the RequestError mapping is verified here; the handler calls
  // this BEFORE capacity reservation and append, so a throw provably
  // persists nothing (see Task 2 wiring).
  // A RegExp needle makes String.prototype.replaceAll throw (non-global
  // regex), standing in for any unexpected walk failure.
  const poisoned = [[/x/, '[REDACTED]']];
  assert.throws(
    () => redactEventForAppend({ msg: 'x' }, poisoned),
    (error) => error instanceof RequestError
      && error.code === 'log_redaction_failed'
      && error.status === 500,
  );
});

test('createRedactionContext folds env, explicit names, and tokens; registry rebuild is idempotent', () => {
  const context = createRedactionContext(
    { API_TOKEN: 'supersecretvalue123', SHORT_TOKEN: 'tiny' },
    ['SHORT_TOKEN'],
    ['launch-token-value-with-entropy'],
  );
  const apply = (text) => redactEventValue({ msg: text }, context.replacements()).msg;
  assert.equal(apply('a supersecretvalue123 b'), 'a [REDACTED] b');
  assert.equal(apply('short tiny value'), 'short [REDACTED] value');
  assert.equal(apply('bearer launch-token-value-with-entropy'), 'bearer [REDACTED]');
  assert.equal(apply('session-token-added-later-abc'), 'session-token-added-later-abc');
  context.registerToken('session-token-added-later-abc');
  assert.equal(apply('session-token-added-later-abc'), '[REDACTED]');
  // Earlier tokens survive later registrations (append-only registry).
  context.registerToken('another-token-registered-after');
  assert.equal(apply('bearer launch-token-value-with-entropy'), 'bearer [REDACTED]');
  assert.equal(apply('session-token-added-later-abc'), '[REDACTED]');
});
```

Also extend the test file's existing import lists:
- In the destructured `require('./debug_server')` block (test file lines 11–26), add
  `createRedactionContext,`, `redactEventForAppend,`, and `redactEventValue,` in
  alphabetical position.
- Below the existing requires (after line 26), add:

```js
const { buildSecretReplacements } = require('./pr_closeout_stream');
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test --test-concurrency=1 --test-name-pattern "redact" scripts/debug_server.test.js`
Expected: FAIL — the new tests error because `redactEventValue`, `redactEventForAppend`, and `createRedactionContext` are `undefined` (not yet exported).

- [ ] **Step 3: Implement the helpers**

In `scripts/debug_server.js`, add to the top-of-file requires (after line 7, `const path = require('node:path');`):

```js
const { buildSecretReplacements } = require('./pr_closeout_stream');
```

Insert immediately after the `appendSessionEvent` function's closing (`};` followed by a blank line, before the `createDebugServer` doc-comment):

```js
// --- Collector-side secret redaction (spec:
// docs/superpowers/specs/2026-08-05-collector-redaction-design.md) ---

// Apply an already-built longest-first [needle, replacement] list to one
// string. buildSecretReplacements sorts longest-first, so a shorter needle
// can never re-match inside text a longer needle already replaced; matching
// is case-sensitive, same as the closeout streaming redactor's default.
const applyReplacements = (text, replacements) => replacements.reduce(
  (current, [needle, replacement]) => current.replaceAll(needle, replacement),
  text,
);

// Deep-walk a parsed /log event and redact every string it contains — leaf
// values, array items, and object KEYS (a client could use a secret as a
// key). Input always comes from JSON.parse, so only plain objects, arrays,
// strings, numbers, booleans, and null occur, and cycles are impossible.
// Rebuilds containers instead of mutating, so a failure part-way can never
// leave a half-redacted event that later gets persisted. When two sibling
// keys collide after redaction (or a redacted key collides with a literal
// one), the later entry is suffixed deterministically ([REDACTED]#2, ...)
// rather than silently overwriting the earlier entry.
const redactEventValue = (value, replacements) => {
  if (typeof value === 'string') return applyReplacements(value, replacements);
  if (Array.isArray(value)) return value.map((item) => redactEventValue(item, replacements));
  if (value && typeof value === 'object') {
    const output = {};
    for (const [key, entry] of Object.entries(value)) {
      let redactedKey = applyReplacements(key, replacements);
      if (Object.hasOwn(output, redactedKey)) {
        let suffix = 2;
        while (Object.hasOwn(output, `${redactedKey}#${suffix}`)) suffix += 1;
        redactedKey = `${redactedKey}#${suffix}`;
      }
      output[redactedKey] = redactEventValue(entry, replacements);
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
// module.
const createRedactionContext = (envSnapshot, explicitNames, initialTokens) => {
  const tokens = [...initialTokens];
  let replacements;
  const rebuild = () => {
    const synthetic = {};
    const syntheticNames = [];
    tokens.forEach((tokenValue, index) => {
      const name = `__COLLECTOR_TOKEN_${index}`;
      synthetic[name] = tokenValue;
      syntheticNames.push(name);
    });
    replacements = buildSecretReplacements(
      { ...envSnapshot, ...synthetic },
      [...explicitNames, ...syntheticNames],
    );
  };
  rebuild();
  return {
    registerToken(tokenValue) {
      tokens.push(tokenValue);
      rebuild();
    },
    replacements: () => replacements,
  };
};
```

In the `module.exports` block at the end of the file, add in alphabetical position:

```js
  createRedactionContext,
  redactEventForAppend,
  redactEventValue,
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test --test-concurrency=1 --test-name-pattern "redact" scripts/debug_server.test.js`
Expected: PASS (5 new tests).

- [ ] **Step 5: Commit**

```bash
git add scripts/debug_server.js scripts/debug_server.test.js
git commit -m "feat(collector): pure redaction helpers with fail-closed append wrapper

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 2: Factory wiring + /log enforcement (integration)

**Files:**
- Modify: `scripts/debug_server.js` — `createDebugServer` options (~line 713), context creation after `effectiveLimits` (~line 742), `/log` handler between event assembly and serialization (~lines 1052–1056), factory doc-comment (~lines 705–711)
- Test: `scripts/debug_server.test.js` (append)

**Review round-2 carry-ins (do these in this task too):**

1. In `createRedactionContext`, enforce the cap against `initialTokens` at construction: after
   the `initialTokens` validation loop and before `const tokens = [...initialTokens];`, add

```js
  if (initialTokens.length > maxTokens) throw new Error('redaction_token_registry_full');
```

   with this unit test appended alongside the others:

```js
test('createRedactionContext rejects initialTokens exceeding maxTokens', () => {
  assert.throws(
    () => createRedactionContext({}, [], ['t-0', 't-1', 't-2'], { maxTokens: 2 }),
    /redaction_token_registry_full/,
  );
});
```

2. Strengthen the round-1 synthetic-prefix collision test: change its second argument from
   `['__COLLECTOR_TOKEN_0']` to `[]` so the shadowed env value must redact via
   auto-discovery (`__COLLECTOR_TOKEN_0` matches `SENSITIVE_ENV_NAME` on its own) — the
   stronger, realistic property. Keep both assertions unchanged.

3. The cap default stays 512 (decision record: at a full registry a crafted 64KB object-dense
   event costs ~1.65s of walk CPU — an authenticated, loopback-only, self-inflicted ceiling —
   while a lower cap risks legitimate mint exhaustion on long-lived collectors; operators tune
   via the new `redactionMaxTokens` option below).

- [ ] **Step 1: Write the failing integration tests**

Append to `scripts/debug_server.test.js`. Reuse the file's existing helpers (`listen`, `close`, `createSession`, `requestJson`, `TEST_LAUNCH_TOKEN`) and this local fixture helper:

```js
const withRedactionServer = async (redactionEnv, redactionNames, run) => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-redact-'));
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    redactionEnv,
    redactionNames,
  });
  const baseUrl = await listen(server);
  try {
    return await run({ baseUrl, projectRoot });
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
};

const readSessionLines = async (projectRoot, session) => {
  const raw = await readFile(path.join(projectRoot, session.log_file), 'utf8');
  return raw.split('\n').filter(Boolean).map((line) => JSON.parse(line));
};

test('POST /log persists env secrets as [REDACTED] in msg, nested data, and keys', async () => {
  await withRedactionServer({ API_TOKEN: 'supersecretvalue123' }, [], async ({ baseUrl, projectRoot }) => {
    const session = (await createSession(baseUrl)).body;
    const response = await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: {
        sessionId: session.session_id,
        sessionToken: session.session_token,
        msg: 'refused supersecretvalue123 upstream',
        data: {
          nested: { echo: 'value supersecretvalue123 seen' },
          supersecretvalue123: 'as key',
        },
      },
    });
    assert.equal(response.status, 202);
    const [event] = await readSessionLines(projectRoot, session);
    assert.equal(event.msg, 'refused [REDACTED] upstream');
    assert.equal(event.data.nested.echo, 'value [REDACTED] seen');
    assert.equal(event.data['[REDACTED]'], 'as key');
    assert.equal(JSON.stringify(event).includes('supersecretvalue123'), false);
  });
});

test('POST /log redacts encoded variants (base64, URL-encoded, JSON-escaped)', async () => {
  const secret = 'p@ss word+42!"quoted"';
  await withRedactionServer({ DB_PASSWORD: secret }, [], async ({ baseUrl, projectRoot }) => {
    const session = (await createSession(baseUrl)).body;
    const base64 = Buffer.from(secret, 'utf8').toString('base64');
    const urlEncoded = encodeURIComponent(secret);
    const jsonEscaped = JSON.stringify(secret).slice(1, -1);
    await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: {
        sessionId: session.session_id,
        sessionToken: session.session_token,
        msg: 'variants observed',
        data: { base64, urlEncoded, jsonEscaped },
      },
    });
    const [event] = await readSessionLines(projectRoot, session);
    assert.equal(event.data.base64, '[REDACTED]');
    assert.equal(event.data.urlEncoded, '[REDACTED]');
    assert.equal(event.data.jsonEscaped, '[REDACTED]');
  });
});

test('short auto-discovered values persist; DEBUG_REDACT_NAMES opt-in redacts them', async () => {
  await withRedactionServer({ SHORT_TOKEN: 'tiny' }, [], async ({ baseUrl, projectRoot }) => {
    const session = (await createSession(baseUrl)).body;
    await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: { sessionId: session.session_id, sessionToken: session.session_token, msg: 'value tiny stays' },
    });
    const [event] = await readSessionLines(projectRoot, session);
    assert.equal(event.msg, 'value tiny stays');
  });
  await withRedactionServer({ SHORT_TOKEN: 'tiny' }, ['SHORT_TOKEN'], async ({ baseUrl, projectRoot }) => {
    const session = (await createSession(baseUrl)).body;
    await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: { sessionId: session.session_id, sessionToken: session.session_token, msg: 'value tiny goes' },
    });
    const [event] = await readSessionLines(projectRoot, session);
    assert.equal(event.msg, 'value [REDACTED] goes');
  });
});

test('secret-free events keep their exact shape (regression guard)', async () => {
  await withRedactionServer({}, [], async ({ baseUrl, projectRoot }) => {
    const session = (await createSession(baseUrl)).body;
    await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: {
        sessionId: session.session_id,
        sessionToken: session.session_token,
        msg: 'Function entry',
        data: { userId: null },
        hypothesisId: 'H1',
      },
    });
    const [event] = await readSessionLines(projectRoot, session);
    assert.deepEqual(
      { msg: event.msg, data: event.data, hypothesisId: event.hypothesisId },
      { msg: 'Function entry', data: { userId: null }, hypothesisId: 'H1' },
    );
  });
});

test('createDebugServer refuses to start when the initial redaction build fails', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-redact-'));
  const poisonedEnv = new Proxy({}, {
    ownKeys() { throw new Error('poisoned env'); },
  });
  try {
    assert.throws(() => createDebugServer({
      projectRoot,
      token: TEST_LAUNCH_TOKEN,
      redactionEnv: poisonedEnv,
    }), /poisoned env/);
  } finally {
    await rm(projectRoot, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test --test-concurrency=1 --test-name-pattern "redact|secret-free|SHORT_TOKEN|refuses to start" scripts/debug_server.test.js`
Expected: FAIL — secrets persist raw (no wiring yet) and the factory ignores `redactionEnv` (no throw).

- [ ] **Step 3: Wire the factory and the /log handler**

In `scripts/debug_server.js`:

(a) Extend the `createDebugServer` destructured options (currently `{ projectRoot..., token..., instanceId..., allowedOrigins = [], limits = {} }`):

```js
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
```

(b) In the factory doc-comment's `@param` list (after the `options.limits` line), add:

```js
 * @param {NodeJS.ProcessEnv} [options.redactionEnv] - env snapshot the redaction needle list is built from; defaults to a copy of process.env taken at build time.
 * @param {string[]} [options.redactionNames] - extra env-var names always redacted regardless of length (DEBUG_REDACT_NAMES in the CLI).
 * @param {number} [options.redactionMaxTokens] - lifetime cap on registered tokens (launch + every session mint); at the cap further mints fail closed with session_redaction_failed. Default 512 bounds worst-case per-event redaction cost.
```

(c) Directly after the `const effectiveLimits = { ...DEFAULT_LIMITS, ...limits };` line, create the context (a build failure throws out of the factory — startup stays fail-closed):

```js
  // Fail-closed secret redaction for every persisted event. Built here so a
  // broken needle build prevents the collector from starting at all; the
  // launch token is registered from the first build.
  const redaction = createRedactionContext(redactionEnv, redactionNames, [token], {
    maxTokens: redactionMaxTokens,
  });
```

(d) In the `/log` handler, replace the two lines

```js
        const serializedEvent = `${JSON.stringify(event)}\n`;
        const eventBytes = Buffer.byteLength(serializedEvent);
```

with

```js
        // Redact BEFORE serialization and BEFORE capacity reservation: a
        // redaction failure rejects the event with nothing persisted and no
        // reservation to roll back. Byte accounting below intentionally uses
        // post-redaction bytes ([REDACTED] may shrink or grow an event).
        const redactedEvent = redactEventForAppend(event, redaction.replacements());
        const serializedEvent = `${JSON.stringify(redactedEvent)}\n`;
        const eventBytes = Buffer.byteLength(serializedEvent);
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test --test-concurrency=1 --test-name-pattern "redact|secret-free|SHORT_TOKEN|refuses to start" scripts/debug_server.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/debug_server.js scripts/debug_server.test.js
git commit -m "feat(collector): enforce env-derived secret redaction at /log ingestion

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 3: Token registry wiring in /session (integration)

**Files:**
- Modify: `scripts/debug_server.js` — `/session` handler, first statement inside the `try {` that begins right after the `sessions.set(sessionId, {...})` block (~line 864)
- Test: `scripts/debug_server.test.js` (append)

- [ ] **Step 1: Write the failing integration tests**

Append to `scripts/debug_server.test.js` (reuses `withRedactionServer` / `readSessionLines` from Task 2):

```js
test('collector launch and session tokens are redacted from event bodies, cross-session', async () => {
  await withRedactionServer({}, [], async ({ baseUrl, projectRoot }) => {
    const sessionA = (await createSession(baseUrl, 'session-a')).body;
    const sessionB = (await createSession(baseUrl, 'session-b')).body;
    await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: {
        sessionId: sessionA.session_id,
        sessionToken: sessionA.session_token,
        msg: `launch=${TEST_LAUNCH_TOKEN} mine=${sessionA.session_token} other=${sessionB.session_token}`,
      },
    });
    const [event] = await readSessionLines(projectRoot, sessionA);
    assert.equal(event.msg, 'launch=[REDACTED] mine=[REDACTED] other=[REDACTED]');
  });
});

test('a full token registry rejects the session fail-closed with session_registry_full', async () => {
  const projectRoot = await mkdtemp(path.join(tmpdir(), 'debug-redact-'));
  // redactionMaxTokens: 2 = launch token + exactly one session mint. The
  // second mint exceeds the cap inside registerToken, which the /session
  // handler maps to session_registry_full (permanent cap state, signaled
  // once on stderr; distinguished from transient session_redaction_failed).
  // This exercises the fail-closed path through a supported seam. NOTE: a post-construction poisoned env
  // Proxy CANNOT trigger this path anymore — createRedactionContext
  // snapshots env once at construction (review round-1 hardening). If a
  // Proxy-based variant of this test goes red, the test is wrong, not the
  // snapshot: do NOT revert the snapshot to live env reads.
  const server = createDebugServer({
    projectRoot,
    token: TEST_LAUNCH_TOKEN,
    redactionMaxTokens: 2,
  });
  const baseUrl = await listen(server);
  try {
    const healthy = await createSession(baseUrl);
    assert.equal(healthy.status, 201);
    const rejected = await createSession(baseUrl);
    assert.equal(rejected.status, 500);
    assert.equal(rejected.body.error, 'session_registry_full');
    // The healthy session keeps recording after the failed mint: the
    // registry and needle list are intact (cap check precedes the push).
    const logged = await requestJson(baseUrl, {
      method: 'POST',
      pathname: '/log',
      body: {
        sessionId: healthy.body.session_id,
        sessionToken: healthy.body.session_token,
        msg: 'still recording',
      },
    });
    assert.equal(logged.status, 202);
  } finally {
    await close(server);
    await rm(projectRoot, { recursive: true, force: true });
  }
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test --test-concurrency=1 --test-name-pattern "cross-session|session_redaction_failed" scripts/debug_server.test.js`
Expected: FAIL — session tokens persist raw (registerToken never called), and the full-registry test's second mint gets `201` instead of `500` (the cap is never consulted because nothing registers tokens yet).

- [ ] **Step 3: Wire registerToken into /session**

In the `/session` handler, the code currently reads (right after the `sessions.set(sessionId, {..., provisional: true});` statement):

```js
        try {
          // Reject a symlinked, non-directory, or escaped .debug path before
```

Insert the registration as the first statement inside that `try` (its `catch` already deletes the session, so a failure cleans up and returns a structured 500):

```js
        try {
          // Push-then-rebuild BEFORE the session can accept /log: the token
          // joins the append-only registry first, so concurrent mints
          // converge (whichever rebuild runs last includes every registered
          // token) and a rebuild failure rejects this session fail-closed.
          try {
            redaction.registerToken(sessionToken);
          } catch {
            throw new RequestError('session_redaction_failed', 500);
          }
          // Reject a symlinked, non-directory, or escaped .debug path before
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test --test-concurrency=1 --test-name-pattern "cross-session|session_redaction_failed" scripts/debug_server.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/debug_server.js scripts/debug_server.test.js
git commit -m "feat(collector): register session tokens in the redaction needle registry

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 4: DEBUG_REDACT_NAMES in the CLI (main)

**Files:**
- Modify: `scripts/debug_server.js` — add `parseRedactNames` next to `parseAllowedOrigins`; use it in `main()`'s `createDebugServer` call (~line 1539); export it
- Test: `scripts/debug_server.test.js` (append)

- [ ] **Step 1: Write the failing unit test**

```js
test('parseRedactNames splits, trims, and drops empty entries', () => {
  assert.deepEqual(parseRedactNames('NPM_TOKEN, DOCKER_AUTH_CONFIG ,,EXTRA '), [
    'NPM_TOKEN',
    'DOCKER_AUTH_CONFIG',
    'EXTRA',
  ]);
  assert.deepEqual(parseRedactNames(undefined), []);
  assert.deepEqual(parseRedactNames(''), []);
});
```

Add `parseRedactNames,` to the test file's destructured `require('./debug_server')` import block.

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test --test-concurrency=1 --test-name-pattern "parseRedactNames" scripts/debug_server.test.js`
Expected: FAIL — `parseRedactNames` is `undefined`.

- [ ] **Step 3: Implement and wire**

In `scripts/debug_server.js`, next to the existing `parseAllowedOrigins` definition (locate it with `grep -n "parseAllowedOrigins" scripts/debug_server.js`; place `parseRedactNames` directly after it):

```js
// DEBUG_REDACT_NAMES: comma-separated env-var names that must always be
// redacted from persisted events regardless of value length (the CLI-facing
// mirror of the closeout config's `names` opt-in).
const parseRedactNames = (value) => String(value ?? '')
  .split(',')
  .map((name) => name.trim())
  .filter(Boolean);
```

In `main()`, extend the `createDebugServer` call:

```js
  const server = createDebugServer({
    projectRoot,
    token,
    allowedOrigins: parseAllowedOrigins(process.env.DEBUG_ALLOWED_ORIGIN),
    redactionNames: parseRedactNames(process.env.DEBUG_REDACT_NAMES),
  });
```

(`redactionEnv` stays defaulted — main's snapshot IS the process env.)

Add `parseRedactNames,` to `module.exports` in alphabetical position.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test --test-concurrency=1 --test-name-pattern "parseRedactNames" scripts/debug_server.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add scripts/debug_server.js scripts/debug_server.test.js
git commit -m "feat(collector): DEBUG_REDACT_NAMES opt-in names for CLI redaction

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 5: Stale comments + README + SKILL.md documentation

**Files:**
- Modify: `scripts/debug_server.js` (two comments), `README.md` (Safety + trust model), `SKILL.md` (Critical Rule 5)

- [ ] **Step 1: Rewrite the `/log` route doc-comment**

In the `createDebugServer` doc-comment, change

```
 * `<projectRoot>/.debug`), and `POST /log` (requires that session's own
 * token — see authorizeRequest — and appends one redaction-free event line).
```

to

```
 * `<projectRoot>/.debug`), and `POST /log` (requires that session's own
 * token — see authorizeRequest — and appends one event line after
 * fail-closed known-secret redaction; see createRedactionContext).
```

- [ ] **Step 2: Rewrite the ACL comment in /session**

Change

```js
            // /log writes redaction-free runtime evidence. The 0600 mode above
            // is a no-op against Windows' inherited DACL, so another local
```

to

```js
            // /log events are redacted only for KNOWN secrets (see
            // createRedactionContext); treat log contents as sensitive. The
            // 0600 mode above is a no-op against Windows' inherited DACL, so
            // another local
```

(keep the remainder of that comment block unchanged).

- [ ] **Step 3: README updates**

In `README.md` Safety section, after the sentence ending `...block a clean result.`, append a new paragraph:

```markdown
The collector additionally enforces the secrets half of Critical Rule 5 at ingestion: known
secrets — sensitive-named environment values, `DEBUG_REDACT_NAMES` opt-ins, and the collector's
own launch and session tokens — are replaced with `[REDACTED]`, including their URL-encoded,
JSON-escaped, base64, and hex variants and extracted components (URL credentials,
connection-string leaves), before any event byte is persisted. A redaction failure rejects the
write instead of storing raw evidence. Note the deliberate trade-off: if a secret value or one
of its components equals a common word (a dev-default `postgres` password, for example), that
word is scrubbed from all evidence — the guarantee is unconditional, so prefer distinct dev
credential values. `DEBUG_REDACT_NAMES` entries additionally bypass the 8-character
auto-discovery floor, so list only names whose values are genuinely high-entropy secrets — a
short or common value would be scrubbed wherever it appears as a substring. PII redaction
remains an agent responsibility.
```

In the "Debug collector trust model" section, append after the paragraph ending `...the timing-safe comparison or the `401` response shape.`:

```markdown
Every persisted event also passes one fail-closed redaction choke point
(`createRedactionContext` / `redactEventForAppend`): values of sensitive-named environment
variables, names listed in `DEBUG_REDACT_NAMES`, and the collector's own tokens can never reach
a session log in raw or encoded form. The token registry is capped per process (512 lifetime
session mints, failed mints included); at the cap further sessions are refused with
`session_registry_full`, signaled once on stderr as `redaction.registry_full` — restart the
collector to reset it.
```

- [ ] **Step 4: SKILL.md Critical Rule 5**

Change

```markdown
5. **Never expose secrets or PII**: redact credentials, tokens, cookies, and personal data from
   logs, replies, reports, and handoffs.
```

to

```markdown
5. **Never expose secrets or PII**: redact credentials, tokens, cookies, and personal data from
   logs, replies, reports, and handoffs. The collector enforces the known-secret classes at
   `/log` ingestion (sensitive-named environment values, `DEBUG_REDACT_NAMES` opt-ins, and its
   own tokens, including encoded variants); PII and secrets the collector cannot know remain
   your responsibility.
```

- [ ] **Step 4b: SKILL.md Troubleshooting row**

In the SKILL.md Troubleshooting table (under `## Troubleshooting`), add this row after the "Too many logs" row:

```markdown
| Common word shows as `[REDACTED]` | An env secret or one of its extracted components (e.g. a dev-default `postgres` DSN password) equals that word; use distinct dev credential values or unset the variable for the collector process |
| Sessions fail with `session_registry_full` | The collector's lifetime session-mint cap (512, failed mints included) is exhausted; restart the collector |
```

- [ ] **Step 5: Validate and commit**

Run: `npm run validate`
Expected: `{"status":"PASS",...}` (payload contract unchanged; SKILL.md/README are re-scanned).

```bash
git add scripts/debug_server.js README.md SKILL.md
git commit -m "docs(collector): document enforced known-secret redaction

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp"
```

---

### Task 6: Full verification

**Files:** none (verification only)

- [ ] **Step 1: Full test suite**

Run: `npm test`
Expected: all tests pass on the local platform, including the entire pre-existing `debug_server.test.js`, `pr_closeout_*` suites, and tools tests. This is the spec's "secret-free events unchanged" regression gate — investigate ANY failure before proceeding (do not rerun-until-green).

- [ ] **Step 2: Repository validator + suppression scan**

Run: `npm run validate`
Expected: `{"status":"PASS",...}`.

Run: `npm run scan:suppressions`
Expected: no suppression findings for the touched files.

- [ ] **Step 3: Review the complete diff against the spec**

Run: `git diff codex/publish-debug-skill...HEAD --stat` then `git diff codex/publish-debug-skill...HEAD`
Check against `docs/superpowers/specs/2026-08-05-collector-redaction-design.md`: one choke point in `/log`; push-then-rebuild in `/session`; fail-closed at startup/mint/append; no opt-out; docs updated; nothing else drifted.

- [ ] **Step 4: Final state**

No commit needed if Steps 1–3 are clean (Task 5 committed last changes). Report results honestly — if anything failed, fix under the relevant task's discipline before declaring done.
