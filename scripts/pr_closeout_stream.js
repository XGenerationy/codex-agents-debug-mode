const { StringDecoder } = require('node:string_decoder');

const SENSITIVE_ENV_NAME = /(?:^|_)(?:ACCESS_KEY|API_KEY|AUTH_CONFIG|AUTH_TOKEN|BEARER_TOKEN|CLIENT_SECRET|CONNECTION_STRING|COOKIE|CREDENTIAL|DATABASE_URL|DSN|ENCRYPTION_KEY|MYSQL_PWD|PASSWORD|PASSWD|PGPASSWORD|PRIVATE_KEY|REDIS_URL|SECRET|SESSION_TOKEN|SIGNING_KEY|TOKEN|URI)(?:$|_)/i;
// npm basic-auth config uses bare `_AUTH` / `_auth` (e.g. NPM_CONFIG__AUTH,
// npm_config__auth) which does not match the TOKEN/AUTH_TOKEN suffix patterns.
const SENSITIVE_NPM_AUTH = /(?:^|_)_?AUTH$/i;

/**
 * True if an env var NAME (not its value) looks credential-bearing: the
 * broad ACCESS_KEY/API_KEY/TOKEN/PASSWORD/... suffix pattern, or the bare
 * npm basic-auth `_auth`/`_AUTH` key that config files like
 * `NPM_CONFIG__AUTH` use and which the suffix pattern alone would miss.
 * Drives both `buildChildEnvironment` (what to strip) and
 * `buildSecretReplacements` (what values to redact).
 * @param {string} name
 * @returns {boolean}
 */
const isSensitiveEnvName = (name) => {
  const key = String(name);
  return SENSITIVE_ENV_NAME.test(key) || SENSITIVE_NPM_AUTH.test(key);
};

/**
 * Filters `env` down to a child-process-safe environment: any name that
 * `isSensitiveEnvName` flags is dropped unless it appears (case-insensitively)
 * in `allowedSensitiveNames` — the opt-in list of secrets the workflow
 * actually needs to pass through (e.g. required tool credentials).
 * @param {NodeJS.ProcessEnv} env
 * @param {string[]} allowedSensitiveNames
 * @returns {NodeJS.ProcessEnv}
 */
const buildChildEnvironment = (env = process.env, allowedSensitiveNames = []) => {
  const allowed = new Set(allowedSensitiveNames.map((name) => String(name).toUpperCase()));
  return Object.fromEntries(Object.entries(env).filter(([name]) => (
    !isSensitiveEnvName(name) || allowed.has(name.toUpperCase())
  )));
};

/**
 * Expands one raw secret value into every encoded form it could plausibly
 * appear as in captured stdout/stderr: URL-encoded (upper/lower hex, `+` for
 * spaces, double-encoded), JSON-string-escaped, `\uXXXX` unicode-escaped
 * (with surrogate pairs for astral code points), base64/base64url (padded
 * and unpadded), and hex. A tool that re-encodes a secret before printing it
 * (e.g. a URL-encoded token in a logged curl command) would otherwise slip
 * past a literal-match redactor.
 * @param {unknown} value
 * @returns {string[]} variant strings, still needing dedupe/length filtering by the caller.
 */
const secretVariants = (value) => {
  const raw = String(value);
  const encoded = encodeURIComponent(raw);
  const base64 = Buffer.from(raw, 'utf8').toString('base64');
  const base64url = Buffer.from(raw, 'utf8').toString('base64url');
  const unicodeEscaped = [...raw].map((character) => {
    const point = character.codePointAt(0);
    if (point <= 0xffff) return `\\u${point.toString(16).padStart(4, '0')}`;
    const adjusted = point - 0x10000;
    const high = 0xd800 + (adjusted >> 10);
    const low = 0xdc00 + (adjusted & 0x3ff);
    return `\\u${high.toString(16)}\\u${low.toString(16)}`;
  }).join('');
  return [
    raw,
    encoded,
    encoded.replace(/%[0-9A-F]{2}/g, (match) => match.toLowerCase()),
    encoded.replaceAll('%20', '+'),
    encodeURIComponent(encoded),
    JSON.stringify(raw).slice(1, -1),
    unicodeEscaped,
    base64,
    base64.replace(/=+$/u, ''),
    base64url,
    base64url.replace(/=+$/u, ''),
    // Lowercase hex (Buffer default) and uppercase hex (tools that print
    // conventional UPPER hex). Replacement is case-sensitive, so both forms
    // must be registered or an uppercase encoding would persist in evidence.
    Buffer.from(raw, 'utf8').toString('hex'),
    Buffer.from(raw, 'utf8').toString('hex').toUpperCase(),
  ];
};

/**
 * Extracts every credential-bearing sub-string embedded in one secret VALUE,
 * not just the value itself: a URL's username/password and any
 * credential-named query params (?token=...&api_key=...); or — for a
 * non-URL value — key=value pairs from a semicolon/whitespace-delimited
 * connection string (password=/token=/user=/...); or leaf string values
 * under credential-named keys anywhere inside a JSON auth blob (e.g.
 * `AUTH_CONFIG={"auth":{"token":"..."}}`). Needed because a tool can print
 * just one fragment of a compound secret (the URL's password, a JSON leaf)
 * without ever printing the whole original string, so redacting only the
 * full value would miss it.
 * @param {unknown} value
 * @returns {string[]} the original stringified value plus every extracted component, deduplicated.
 */
const secretComponents = (value) => {
  const components = [String(value)];
  // Include bare Docker registry key `auth` (DOCKER_AUTH_CONFIG leaf) as well as
  // keys that end with token/password/secret/key/credential. Encoded variants of
  // each leaf still flow through secretVariants below.
  const isCredentialKey = /(?:^auth$|(?:token|password|passwd|pwd|secret|key|credential)$)/i;
  try {
    const parsed = new URL(String(value));
    for (const component of [parsed.username, parsed.password]) {
      if (!component) continue;
      components.push(component);
      try {
        components.push(decodeURIComponent(component));
      } catch {}
    }
    // Query parameters can carry credentials too (?token=...&api_key=...): a
    // tool that prints just that leaf value would otherwise leak it even
    // though the whole URL is redacted.
    for (const [key, param] of parsed.searchParams) {
      if (param && isCredentialKey.test(key)) components.push(param);
    }
  } catch {
    // Include Azure-style AccountKey / SharedAccessKey / access-key leaves so
    // a CLI that prints only the key value (not the whole connection string)
    // is still redacted.
    for (const match of String(value).matchAll(/(?:^|[;\s])(?:password|passwd|pwd|secret|token|user(?:name| id)?|account[_-]?key|shared[_-]?access[_-]?key|access[_-]?key|api[_-]?key|private[_-]?key)=([^;\s]+)/gi)) {
      components.push(match[1]);
    }
  }
  // If the value is a JSON auth blob (e.g. AUTH_CONFIG={"token":"..."} or
  // {"auth":{"token":"..."}}), extract the leaf string values under
  // credential-bearing keys anywhere in the (possibly nested) structure so a
  // tool that prints just that leaf still gets redacted. The whole-string +
  // encoded variants cover the full blob but not an isolated leaf printed by
  // an SDK/CLI.
  try {
    const collectLeaves = (node) => {
      if (typeof node === 'string') return;
      if (Array.isArray(node)) {
        for (const item of node) collectLeaves(item);
        return;
      }
      if (node && typeof node === 'object') {
        for (const [key, val] of Object.entries(node)) {
          if (typeof val === 'string' && isCredentialKey.test(key)) components.push(val);
          collectLeaves(val);
        }
      }
    };
    collectLeaves(JSON.parse(String(value)));
  } catch {}
  return [...new Set(components.filter(Boolean))];
};

// Minimum length below which an AUTO-DISCOVERED sensitive env value is NOT
// added to the literal replaceAll redaction list. Short values (e.g. "ok",
// "1", "true", "x/", "tiny") would otherwise corrupt ordinary text throughout
// captured stdout/stderr and logs by being redacted everywhere they appear as
// a substring. Values from names EXPLICITLY listed in the `names` array are
// always redacted regardless of length, because the user opted in.
const MIN_AUTO_SECRET_LENGTH = 8;

/**
 * Builds the full [needle, '[REDACTED]'] replacement list for the streaming
 * redactor: every value/variant/component of an explicitly-named secret
 * (`names`, matched case-insensitively) is included regardless of length,
 * since the caller opted in; auto-discovered sensitive env vars (matched by
 * `isSensitiveEnvName`) are included only where the value — and each
 * expanded variant — is at least `MIN_AUTO_SECRET_LENGTH`, so a short
 * incidental value like "ok" or "true" doesn't get redacted throughout
 * ordinary captured output. Results are deduplicated and sorted longest-first
 * so a shorter needle can never shadow a longer overlapping one.
 * @param {NodeJS.ProcessEnv} env
 * @param {string[]} names explicit env-var names to always treat as secrets.
 * @returns {[string, string][]} needle/replacement pairs, longest needle first.
 */
const buildSecretReplacements = (env = process.env, names = []) => {
  // Match explicit names case-insensitively against actual env keys, mirroring
  // buildChildEnvironment (which uppercases the allowlist): a config listing
  // "npm_token" must redact NPM_TOKEN. Resolve each configured name to the
  // actual env key so the value lookup below succeeds.
  const explicitUpper = new Set(names.map((name) => String(name).toUpperCase()));
  const isExplicit = (name) => explicitUpper.has(String(name).toUpperCase());
  const explicitNames = Object.keys(env).filter((name) => isExplicit(name));
  // Auto-discovered sensitive names (matched by SENSITIVE_ENV_NAME) are only
  // included if their value is long enough not to cause over-broad
  // replacement of ordinary text. Explicit names are always included.
  const selected = [
    ...explicitNames,
    ...Object.keys(env).filter((name) => isSensitiveEnvName(name) && !isExplicit(name)),
  ];
  const values = selected
    .map((name) => {
      const value = env[name];
      if (typeof value !== 'string') return undefined;
      if (value.length === 0) return undefined;
      const explicit = isExplicit(name);
      if (!explicit && value.length < MIN_AUTO_SECRET_LENGTH) return undefined;
      return { value, explicit };
    })
    .filter(Boolean)
    .flatMap(({ value, explicit }) => {
      const variants = secretComponents(value).flatMap(secretVariants);
      // For auto-discovered (non-explicit) names, also drop short extracted
      // components/variants (e.g. a URL's "pw" fragment) so they cannot
      // over-redact ordinary text. Explicitly-listed names keep every variant.
      return explicit ? variants : variants.filter((variant) => typeof variant === 'string' && variant.length >= MIN_AUTO_SECRET_LENGTH);
    });
  return [...new Set(values)]
    .filter((value) => typeof value === 'string' && value.length > 0)
    .sort((left, right) => right.length - left.length)
    .map((value) => [value, '[REDACTED]']);
};

/**
 * Case-insensitive `replaceAll(needle, replacement)`: matches are located by
 * lowercasing both strings, but the surrounding text is sliced from the
 * original (unfolded) `value`, so casing outside the matched spans is left
 * exactly as it was. Returns `value` unchanged when there is no match.
 * @param {string} value
 * @param {string} needle
 * @param {string} replacement
 * @returns {string}
 */
const replaceCaseInsensitive = (value, needle, replacement) => {
  const foldedValue = value.toLowerCase();
  const foldedNeedle = needle.toLowerCase();
  let cursor = 0;
  let index = foldedValue.indexOf(foldedNeedle);
  if (index < 0) return value;
  let output = '';
  while (index >= 0) {
    output += value.slice(cursor, index) + replacement;
    cursor = index + needle.length;
    index = foldedValue.indexOf(foldedNeedle, cursor);
  }
  return output + value.slice(cursor);
};

/**
 * Turns a one-shot find/replace list into an incremental streaming replacer
 * safe for arbitrary chunk boundaries: a secret split across two `push()`
 * calls is still redacted, because each call only emits the prefix of its
 * buffer that cannot possibly be the start of a still-incoming needle. It
 * holds back at least `maxLength - 1` characters (the longest needle) on
 * every call, and — if a needle already fully present in the buffer happens
 * to straddle that cutoff — walks the cutoff back further to the start of
 * that match, so the whole needle stays buffered together rather than being
 * torn across two emitted outputs. Needles are applied longest-first so a
 * shorter needle can never re-match inside text a longer needle already
 * turned into `[REDACTED]`. `flush()` must be called once the source is
 * exhausted to emit whatever remains buffered.
 * @param {[string, string][]} replacements needle/replacement pairs.
 * @param {{caseInsensitive?: boolean}} [options]
 * @returns {{push: (chunk: unknown) => string, flush: () => string}}
 */
const createStreamingReplacer = (replacements = [], { caseInsensitive = false } = {}) => {
  const entries = replacements
    .filter(([needle]) => typeof needle === 'string' && needle.length)
    .sort(([left], [right]) => right.length - left.length);
  const maxLength = Math.max(1, ...entries.map(([needle]) => needle.length));
  let pending = '';
  const replace = (value) => entries.reduce((current, [needle, replacement]) => (
    caseInsensitive
      ? replaceCaseInsensitive(current, needle, replacement)
      : current.replaceAll(needle, replacement)
  ), value);
  const indexOf = (value, needle, from) => (
    caseInsensitive
      ? value.toLowerCase().indexOf(needle.toLowerCase(), from)
      : value.indexOf(needle, from)
  );
  return {
    push(chunk) {
      pending += String(chunk ?? '');
      if (!entries.length) {
        const output = pending;
        pending = '';
        return output;
      }
      let boundary = Math.max(0, pending.length - (maxLength - 1));
      for (const [needle] of entries) {
        const crossing = indexOf(pending, needle, Math.max(0, boundary - needle.length + 1));
        if (crossing >= 0 && crossing < boundary && crossing + needle.length > boundary) boundary = crossing;
      }
      const output = replace(pending.slice(0, boundary));
      pending = pending.slice(boundary);
      return output;
    },
    flush() {
      const output = replace(pending);
      pending = '';
      return output;
    },
  };
};

/**
 * Convenience wrapper: builds the secret replacement list from `env`/`names`
 * via `buildSecretReplacements` and feeds it straight into
 * `createStreamingReplacer` (case-sensitive matching).
 * @param {NodeJS.ProcessEnv} env
 * @param {string[]} names explicit secret env-var names, forwarded to `buildSecretReplacements`.
 * @returns {{push: (chunk: unknown) => string, flush: () => string}}
 */
const createStreamingRedactor = (env = process.env, names = []) => createStreamingReplacer(
  buildSecretReplacements(env, names),
);

/**
 * Layers UTF-8 decoding in front of `createStreamingRedactor` for raw process
 * output: `StringDecoder` buffers any multi-byte character split across two
 * `Buffer` chunks internally and only hands the redactor complete characters,
 * so the redactor's own needle-boundary buffering never sees a chopped code
 * point. Non-Buffer chunks are coerced to a string as-is. `flush()` drains
 * both the decoder's trailing bytes and the redactor's held-back tail.
 * @param {NodeJS.ProcessEnv} env
 * @param {string[]} names explicit secret env-var names, forwarded to `createStreamingRedactor`.
 * @returns {{push: (chunk: Buffer|string) => string, flush: () => string}}
 */
const createDecodedRedactor = (env = process.env, names = []) => {
  const decoder = new StringDecoder('utf8');
  const redactor = createStreamingRedactor(env, names);
  return {
    push(chunk) {
      const decoded = Buffer.isBuffer(chunk) ? decoder.write(chunk) : String(chunk ?? '');
      return redactor.push(decoded);
    },
    flush() {
      return redactor.push(decoder.end()) + redactor.flush();
    },
  };
};

/**
 * Streaming line-buffered scanner: `findSignals` only ever sees complete
 * lines (a partial trailing line is buffered until its newline arrives), and
 * matches are deduplicated by `summarizeSignal(signal)` and capped at 20
 * recorded entries. If a stream produces an unbounded line (or never emits a
 * newline at all), `pending` is force-drained once it exceeds `maxPending`,
 * scanning in `maxPending`-sized windows that retain `overlap` characters
 * between windows so a pattern near the cut point is still likely to appear
 * whole in one of the two overlapping scans — this is a memory/DoS bound,
 * not a correctness guarantee for a signal wider than `overlap`.
 * @param {(text: string) => Iterable<unknown>} findSignals called with each complete line (or forced window) to find raw signal matches.
 * @param {{maxPending?: number, overlap?: number, summarizeSignal?: (signal: unknown) => string}} [options]
 * @returns {{push: (chunk: unknown) => void, flush: () => void, values: () => string[]}}
 */
const createStreamingSignalScanner = (
  findSignals,
  {
    maxPending = 65_536,
    overlap = 512,
    summarizeSignal = (signal) => signal,
  } = {},
) => {
  let pending = '';
  const signals = [];
  const seen = new Set();
  const record = (value) => {
    for (const signal of findSignals(value)) {
      const summary = summarizeSignal(signal);
      if (typeof summary !== 'string' || !summary.trim() || seen.has(summary)) continue;
      seen.add(summary);
      if (signals.length < 20) signals.push(summary);
    }
  };
  const drain = () => {
    let newline = pending.search(/\r?\n/);
    while (newline >= 0) {
      const width = pending[newline] === '\r' && pending[newline + 1] === '\n' ? 2 : 1;
      record(pending.slice(0, newline));
      pending = pending.slice(newline + width);
      newline = pending.search(/\r?\n/);
    }
    while (pending.length > maxPending) {
      const boundary = Math.max(1, maxPending - overlap);
      record(pending.slice(0, boundary));
      pending = pending.slice(boundary);
    }
  };
  return {
    push(chunk) {
      pending += String(chunk ?? '');
      drain();
    },
    flush() {
      record(pending);
      pending = '';
    },
    values() {
      return [...signals];
    },
  };
};

module.exports = {
  MIN_AUTO_SECRET_LENGTH,
  buildChildEnvironment,
  buildSecretReplacements,
  createDecodedRedactor,
  createStreamingRedactor,
  createStreamingReplacer,
  createStreamingSignalScanner,
  isSensitiveEnvName,
};
