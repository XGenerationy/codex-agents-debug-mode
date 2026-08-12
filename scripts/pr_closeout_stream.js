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

// Pattern-based redaction for credential-bearing values that can leak into a
// thrown error.message from git/gh (or any wrapped CLI) and would NOT be caught
// by the value-based buildSecretReplacements redactor, because the credential
// is embedded in the diagnostic text rather than present as a known env value
// (e.g. a git remote URL embedding x-access-token:TOKEN, a gh error echoing an
// Authorization header, or a literal ghp_ token in a URL). Applied at the CLI's
// top-level error emission so neither stderr nor the machine-readable BLOCKED
// JSON record carries a raw credential, AND — via
// createStreamingPatternRedactor below — to live child-process output, where
// a chunk-aware stage is required because a credential can straddle a chunk
// boundary (CodeRabbit outside-diff (pr_closeout_stream.js:23-69)). A false
// positive (redacting a non-secret token-shaped string) is harmless; a miss is
// a credential exposure, so the set is deliberately broad. Mirrors
// actions/closeout/support.js's REDACT_PATTERNS so the action layer and the
// gate CLI agree on what a credential looks like.
const CREDENTIAL_PATTERNS = [
  // PEM-encoded secrets that span multiple physical lines (a private_key /
  // signing_key value is commonly a `-----BEGIN <TYPE>-----` ... `-----END
  // <TYPE>-----` block). The line-scoped key-name pattern below redacts only
  // the first line of such a value, so this multi-line pattern runs FIRST and
  // consumes the entire BEGIN..END span (including embedded newlines). Mirrors
  // support.js's REDACT_PATTERNS so both layers agree.
  [/\b(?:private[_-]?key|signing[_-]?key|client[_-]?secret|certificate|cert)\s*[:=]\s*-{5}BEGIN [A-Z0-9 -]+-{5}[\s\S]*?-{5}END [A-Z0-9 -]+-{5}/g, '[REDACTED:pem-block]'],
  // A PEM block with NO key-name prefix — a child process can emit a raw
  // `-----BEGIN …-----` block (e.g. a TLS library dumping a key to stderr).
  // The keyed pattern above only matches after `key=`/`key:`, so this generic
  // fallback catches an un-prefixed block. Runs AFTER the keyed pattern so a
  // `key=-----BEGIN…` is consumed with its key first (CodeRabbit 3745322356).
  [/-{5}BEGIN [A-Z0-9 -]+-{5}[\s\S]*?-{5}END [A-Z0-9 -]+-{5}/g, '[REDACTED:pem-block]'],
  // GitHub tokens (ghp_/gho_/ghu_/ghs_/ghr_/github_pat_), with a minimum length
  // so a short false-positive prefix does not match.
  [/(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}/g, '[REDACTED:token]'],
  // Credential embedding in a URL: scheme://user:pass@host. Replace the
  // credential part only, preserving the scheme and host for diagnostics (the
  // host is not secret — the credential is).
  [/(?:(?:https?|git|ssh):\/\/)[^\s@/]+@[^\s/]+/g, '[REDACTED:url-credential]@'],
  [/(x-access-token):[^\s@/]+@/g, '$1=[REDACTED:credential]@'],
  // Generic key=value pairs where the key looks credential-shaped, including
  // the full auth-scheme value (Authorization: Bearer eyJ... → all redacted).
  // Mirrors support.js's REDACT_PATTERNS and the gate CLI's
  // SENSITIVE_ENV_PATTERN: token/password/secret/credential PLUS the *_key
  // spellings (api_key, access_key, private_key, signing_key) and
  // client_secret, with underscore AND hyphen separators, so a diagnostic
  // echoing `api_key=...`/`access_key=...` is redacted too.
  // A standard space-delimited Bearer credential (`Bearer eyJ...` with no
  // colon or equals sign) — every alternation above requires `[:=]`, so a raw
  // bearer token emitted by a child process diagnostic would leak. Mirror of
  // the action-side redactor in support.js (CodeRabbit #6X72Zq).
  [/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED:token]'],
  [/(Authorization|Bearer|token|password|secret|credential|api[_-]?key|access[_-]?key|private[_-]?key|signing[_-]?key|client[_-]?secret)\s*[:=]\s*.+$/gim, '$1=[REDACTED]'],
];

/**
 * Redacts credential-bearing patterns from arbitrary text (typically a thrown
 * error.message). Unlike the value-based `redactSecrets`, this catches
 * credentials embedded in diagnostic text even when the raw secret value is not
 * a known env value. Returns the redacted string; non-string input is coerced.
 * @param {string} text
 * @returns {string}
 */
const redactCredentialPatterns = (text) => CREDENTIAL_PATTERNS.reduce(
  (acc, [pattern, replacement]) => acc.replace(pattern, replacement),
  String(text ?? ''),
);

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

// ---------------------------------------------------------------------------
// Chunk-aware application of CREDENTIAL_PATTERNS to live process output.
//
// CodeRabbit outside-diff (pr_closeout_stream.js:23-69): the live
// child-process output path applied ONLY the env-value replacements
// (createStreamingRedactor); CREDENTIAL_PATTERNS was used nowhere on that
// path, so a standalone Bearer token or PEM block that is not a known env
// value reached emitSafe unredacted. redactCredentialPatterns cannot simply
// be applied to each chunk independently because a credential can straddle a
// chunk boundary; createStreamingPatternRedactor below buffers just enough
// input that every emitted span carries the same redactions the one-shot
// helper would produce over the whole stream, within the bounded-memory
// limits documented on the factory.
// ---------------------------------------------------------------------------

// PEM framing used for hold/resync decisions. Must stay in sync with the two
// PEM entries in CREDENTIAL_PATTERNS above (same `-{5}` fence and label
// charset). An opener/closer never contains a line terminator, so each is
// always fully contained in one physical line.
const PEM_OPENER = /-{5}BEGIN [A-Z0-9 -]+-{5}/g;
const PEM_CLOSER = /-{5}END [A-Z0-9 -]+-{5}/g;
// Left-hand side of the KEYED PEM pattern (`private_key=-----BEGIN...`),
// anchored to end-of-prefix. When an unclosed opener is held back, the key
// name and separator immediately before it must be held with it so the keyed
// pattern later consumes them exactly like the one-shot reduce does. `\s`
// deliberately crosses newlines, mirroring `\s*[:=]\s*` in the keyed pattern.
const PEM_KEYED_PREFIX_TAIL = /\b(?:private[_-]?key|signing[_-]?key|client[_-]?secret|certificate|cert)\s*[:=]\s*$/;
// A `Bearer` keyword whose token may not have arrived yet. The one-shot
// pattern bridges ANY run of whitespace (`\bBearer\s+<token>`); bridging
// unbounded whitespace in a streaming hold would let a hostile stream pin the
// buffer, so only up to 16 whitespace characters are bridged — enough for the
// realistic `Bearer<space>` and `Bearer\n<indent>` log-wrapping shapes. A
// keyword separated from its token by more whitespace than that is NOT
// bridged (named residual gap; the bare token may then miss redaction unless
// another pattern — e.g. the gh-token shape — still matches it).
const BEARER_TAIL = /\bBearer\s{0,16}$/i;
// Union of the value character classes of the single-line credential
// patterns (gh tokens use [A-Za-z0-9_]; bare Bearer tokens use
// [A-Za-z0-9._~+/=-]). The overflow path refuses to cut inside a contiguous
// run of these characters (up to a bound) so it cannot strand a
// too-short-to-match prefix — e.g. `ghp_` plus 18 of its 20+ required
// trailing characters — on the emitted side of the cut.
const TOKEN_RUN_CHAR = /[A-Za-z0-9._~+/=-]/;
// While resynchronizing after an over-cap PEM block was replaced with its
// marker, this much tail is retained so a `-----END <TYPE>-----` closer is
// still recognized when it arrives split across chunk boundaries. A closer
// whose type label exceeds this window is not detected — discard then
// continues indefinitely, which fails SAFE (output suppression, never
// credential leakage).
const PEM_DISCARD_RETAIN = 512;

/**
 * Index of the first complete PEM opener in `text` that has no complete
 * closer after it, or -1. Closed BEGIN..END pairs are skipped the same way
 * the lazy `[\s\S]*?` in CREDENTIAL_PATTERNS pairs each opener with the
 * earliest following closer.
 * @param {string} text
 * @returns {number}
 */
const findUnclosedPemOpener = (text) => {
  let from = 0;
  for (;;) {
    PEM_OPENER.lastIndex = from;
    const opener = PEM_OPENER.exec(text);
    PEM_OPENER.lastIndex = 0;
    if (!opener) return -1;
    PEM_CLOSER.lastIndex = opener.index + opener[0].length;
    const closer = PEM_CLOSER.exec(text);
    PEM_CLOSER.lastIndex = 0;
    if (!closer) return opener.index;
    from = closer.index + closer[0].length;
  }
};

/**
 * Where the hold for an unclosed PEM opener must start: the beginning of a
 * keyed `private_key=`-style prefix immediately before the opener when one is
 * present (so the keyed CREDENTIAL_PATTERNS entry can consume it whole,
 * matching one-shot semantics), otherwise the opener itself.
 * @param {string} text
 * @param {number} openerIndex
 * @returns {number}
 */
const pemHoldStart = (text, openerIndex) => {
  const keyed = text.slice(0, openerIndex).search(PEM_KEYED_PREFIX_TAIL);
  return keyed >= 0 ? keyed : openerIndex;
};

/**
 * Every CREDENTIAL_PATTERNS match in `text` as [start, end) spans. Used only
 * by the overflow path to decide whether a suspected credential touches the
 * end of an over-cap window (and may therefore continue into unseen input)
 * and to keep a cut from tearing a complete match in two.
 * @param {string} text
 * @returns {[number, number][]}
 */
const collectCredentialSpans = (text) => {
  const spans = [];
  for (const [pattern] of CREDENTIAL_PATTERNS) {
    pattern.lastIndex = 0;
    let match = pattern.exec(text);
    while (match) {
      if (match[0].length === 0) {
        pattern.lastIndex += 1; // zero-width safety; no current pattern can match empty
      } else {
        spans.push([match.index, match.index + match[0].length]);
      }
      match = pattern.exec(text);
    }
    pattern.lastIndex = 0;
  }
  return spans;
};

/**
 * Incremental, chunk-boundary-safe application of CREDENTIAL_PATTERNS
 * (CodeRabbit outside-diff (pr_closeout_stream.js:23-69)). `push(chunk)`
 * returns the redacted text that is safe to emit so far; `flush()` must be
 * called once the source is exhausted to drain and redact the held tail.
 *
 * Boundary strategy — the fixed-length hold-back used by
 * createStreamingReplacer does not transfer to regex patterns (matches are
 * unbounded and a PEM block spans many lines), so this stage holds back, on
 * every push:
 *  1. the trailing line with no terminator yet — every non-PEM pattern match
 *     is contained in one physical line (their value charsets exclude
 *     terminators and the generic key=value pattern is `$`-anchored per
 *     line), so completed lines are safe to emit;
 *  2. everything from an unclosed `-----BEGIN ...-----` opener (plus a keyed
 *     `private_key=`-style prefix directly before it) — a PEM match needs its
 *     closer, so emitting any part of the block early would tear it;
 *  3. a trailing `Bearer` keyword bridged by at most 16 whitespace chars,
 *     whose token may still be in flight across a line wrap.
 * Each emitted segment is then redacted with the same one-shot reduce, so for
 * input within the buffer cap the concatenated output is byte-identical to
 * `redactCredentialPatterns(wholeStream)` — verified by the chunk-size sweep
 * in pr_closeout_stream.test.js — with one deliberate safe-side divergence:
 * an unclosed PEM opener still pending at flush() (or past the cap) becomes
 * `[REDACTED:pem-block]` even though the one-shot helper, lacking a closer,
 * would have emitted the block body raw.
 *
 * Bounded buffer: the held tail never exceeds `maxPending`. At the cap the
 * stage FAILS SAFE — a suspected credential span is never emitted unredacted
 * to reclaim memory:
 *  - unclosed PEM past the cap: the held region is replaced with
 *    `[REDACTED:pem-block]` and input is DISCARDED until a closer arrives
 *    (a stream that opens a block and never closes it therefore has its
 *    subsequent output suppressed, not leaked);
 *  - an unterminated over-cap line whose window ends inside a pattern match
 *    (e.g. `token=<endless value>`): the window is emitted redacted and the
 *    rest of that line is DISCARDED, because the match's continuation is by
 *    definition part of the suspected credential;
 *  - otherwise (no suspect at the window edge) the window is emitted
 *    redacted, cutting only at a point that no complete match straddles and
 *    that does not split a contiguous token-shaped run (bounded look-back),
 *    and the small tail is retained — benign over-cap lines (e.g. giant
 *    single-line JSON) are preserved, not dropped.
 *
 * NOT guaranteed (named residual gaps, all cap- or bound-scoped):
 *  - a `Bearer` keyword separated from its token by more than 16 whitespace
 *    characters is not bridged across an emit boundary;
 *  - in the over-cap window path, a contiguous token-shaped run longer than
 *    the look-back bound (1024 chars at the default cap) can still be torn,
 *    stranding an unmatched prefix on the emitted side, and a PEM opener
 *    straddling the overflow cut itself is not recognized;
 *  - after an over-cap PEM replacement, a closer whose type label exceeds
 *    PEM_DISCARD_RETAIN is not recognized (discard continues — fail-safe);
 *  - patterns added to CREDENTIAL_PATTERNS later must keep the invariants
 *    above (single-line, or PEM-framed) or extend the hold rules.
 * @param {{maxPending?: number}} [options]
 * @returns {{push: (chunk: unknown) => string, flush: () => string}}
 */
const createStreamingPatternRedactor = ({ maxPending = 65_536 } = {}) => {
  // Overflow-cut guards scale down for test-sized caps; at the production
  // default they are 256 (blind guard) and 1024 (token-run look-back).
  const overflowGuard = Math.max(16, Math.min(256, maxPending >> 2));
  const runBound = Math.max(overflowGuard, Math.min(1024, maxPending >> 1));
  let pending = '';
  // 'normal' | 'pem-discard' (over-cap PEM replaced by its marker; drop input
  // until its closer) | 'line-discard' (over-cap unterminated line ending in
  // a suspected credential; drop input until a line terminator).
  let mode = 'normal';
  const drain = () => {
    let output = '';
    for (;;) {
      if (mode === 'pem-discard') {
        PEM_CLOSER.lastIndex = 0;
        const closer = PEM_CLOSER.exec(pending);
        PEM_CLOSER.lastIndex = 0;
        if (!closer) {
          // Keep only enough tail to recognize a closer split across chunks.
          if (pending.length > PEM_DISCARD_RETAIN) pending = pending.slice(-PEM_DISCARD_RETAIN);
          return output;
        }
        pending = pending.slice(closer.index + closer[0].length);
        mode = 'normal';
        continue;
      }
      if (mode === 'line-discard') {
        const terminator = pending.search(/[\r\n]/);
        if (terminator < 0) {
          pending = '';
          return output;
        }
        // Keep the terminator itself so downstream line structure survives.
        pending = pending.slice(terminator);
        mode = 'normal';
        continue;
      }
      // Normal mode. Everything up to (and including) the last line
      // terminator is the emit candidate; the trailing unterminated line is
      // held (hold rule 1). `\r` counts as a terminator because the
      // m-flagged `$` in the generic key=value pattern anchors there too.
      let boundary = Math.max(pending.lastIndexOf('\n'), pending.lastIndexOf('\r')) + 1;
      // Hold rule 2 must be evaluated on the CANDIDATE, not all of pending: a
      // block whose closer sits in the unterminated trailing line is closed
      // in `pending` but would still be torn if the candidate (which stops at
      // the last terminator, BEFORE that closer) were emitted.
      const candidate = pending.slice(0, boundary);
      const opener = findUnclosedPemOpener(candidate);
      if (opener >= 0) {
        boundary = Math.min(boundary, pemHoldStart(candidate, opener));
      } else {
        // Hold rule 3. Only when no PEM hold applies: the one-shot reduce
        // consumes a PEM block before the Bearer pattern can see it, so the
        // PEM hold subsumes any Bearer bridging into the block.
        const bearerIndex = candidate.search(BEARER_TAIL);
        if (bearerIndex >= 0) boundary = bearerIndex;
      }
      if (pending.length - boundary <= maxPending) {
        output += redactCredentialPatterns(pending.slice(0, boundary));
        pending = pending.slice(boundary);
        return output;
      }
      // Held tail exceeds the cap. Emit the safe prefix, then fail SAFE on
      // the held region (see the factory doc for the exact contract).
      output += redactCredentialPatterns(pending.slice(0, boundary));
      const held = pending.slice(boundary);
      pending = '';
      if (opener >= 0) {
        // The held region is an unclosed PEM block (opener + body so far).
        // Its body is credential material: replace it with the marker and
        // discard until the closer. Never emit it raw to escape the cap.
        output += '[REDACTED:pem-block]';
        mode = 'pem-discard';
        return output;
      }
      const spans = collectCredentialSpans(held);
      if (spans.some(([, end]) => end === held.length)) {
        // A pattern match runs to the very edge of the window — its value may
        // continue in unseen input (`token=<endless>`: the m-flagged `$`
        // matches at end-of-string, so an unterminated key=value always lands
        // here). Emit the window redacted (the match becomes its replacement,
        // standing in for the unseen continuation too) and drop the rest of
        // the line.
        output += redactCredentialPatterns(held);
        mode = 'line-discard';
        return output;
      }
      // No suspect at the window edge: emit most of the window and RETAIN a
      // small tail (no data loss for benign over-cap lines). Walk the cut
      // back so it neither splits a contiguous token-shaped run (which could
      // strand an unmatched credential prefix on the emitted side) nor tears
      // a complete match, nor strands a trailing `Bearer`.
      let cut = held.length - overflowGuard;
      for (let steps = 0; cut > 0 && steps < runBound && TOKEN_RUN_CHAR.test(held[cut - 1]); steps += 1) {
        cut -= 1;
      }
      const bearerCut = held.slice(0, cut).search(BEARER_TAIL);
      if (bearerCut >= 0) cut = bearerCut;
      for (let moved = true; moved;) {
        moved = false;
        for (const [start, end] of spans) {
          if (start < cut && end > cut) {
            cut = start;
            moved = true;
          }
        }
      }
      if (cut <= 0) {
        // Degenerate: the whole window is one un-cuttable suspect region.
        // Same fail-safe treatment as a window-edge match.
        output += redactCredentialPatterns(held);
        mode = 'line-discard';
        return output;
      }
      output += redactCredentialPatterns(held.slice(0, cut));
      pending = held.slice(cut);
      return output;
    }
  };
  return {
    push(chunk) {
      pending += String(chunk ?? '');
      return drain();
    },
    flush() {
      const remainder = pending;
      pending = '';
      if (mode !== 'normal') {
        // pem-discard: the block's marker was already emitted and its closer
        // never arrived; line-discard: the redacted stand-in for the
        // over-cap line was already emitted. The retained resync tail can
        // only contain suspect bytes — dropping it is the fail-safe choice.
        mode = 'normal';
        return '';
      }
      const opener = findUnclosedPemOpener(remainder);
      if (opener >= 0) {
        // Deliberate safe-side divergence from the one-shot helper: with no
        // closer, redactCredentialPatterns would emit the partial block RAW
        // (its PEM patterns require the END fence). A child killed mid-dump
        // must not leak the body it managed to write, so the partial block
        // becomes the marker instead.
        const cut = pemHoldStart(remainder, opener);
        return redactCredentialPatterns(remainder.slice(0, cut)) + '[REDACTED:pem-block]';
      }
      return redactCredentialPatterns(remainder);
    },
  };
};

/**
 * The full redaction stack for live child-process output: UTF-8 decoding
 * (Buffer chunks split inside a multi-byte character are completed first),
 * then env-VALUE replacements (createStreamingRedactor), then chunk-aware
 * CREDENTIAL_PATTERNS redaction (createStreamingPatternRedactor). This is
 * what spawnCaptured wires into emitSafe, closing CodeRabbit outside-diff
 * (pr_closeout_stream.js:23-69): before this, a standalone Bearer token or
 * PEM block that was not a known env value flowed to the captured
 * stdout/stderr and the evidence log unredacted.
 *
 * Ordering — value replacement runs BEFORE pattern redaction, deliberately:
 *  1. the value replacer's needles are literal secret strings, so its
 *     correctness is only provable against the byte stream exactly as the
 *     child emitted it — running it first means no reasoning is needed about
 *     whether a pattern rewrite could alter or split a needle occurrence
 *     before the value layer sees it;
 *  2. defense in depth: the value layer is the precise, high-confidence
 *     redactor (exact known secrets including encoded variants); the pattern
 *     layer is the heuristic net. If one of the pattern stage's documented
 *     residual gaps lets a span through, known env secrets are already gone
 *     from it;
 *  3. the reverse order gains nothing: pattern replacements insert only
 *     literal `[REDACTED...]` markers, which contain no secret material and
 *     match no credential pattern, so value-first loses no pattern coverage.
 * @param {NodeJS.ProcessEnv} env
 * @param {string[]} names explicit secret env-var names, forwarded to `createStreamingRedactor`.
 * @param {{maxPatternPending?: number}} [options] test hook for the pattern stage's buffer cap.
 * @returns {{push: (chunk: Buffer|string) => string, flush: () => string}}
 */
const createProcessOutputRedactor = (env = process.env, names = [], { maxPatternPending } = {}) => {
  const decoder = new StringDecoder('utf8');
  const valueRedactor = createStreamingRedactor(env, names);
  const patternRedactor = createStreamingPatternRedactor(
    maxPatternPending === undefined ? {} : { maxPending: maxPatternPending },
  );
  return {
    push(chunk) {
      const decoded = Buffer.isBuffer(chunk) ? decoder.write(chunk) : String(chunk ?? '');
      return patternRedactor.push(valueRedactor.push(decoded));
    },
    flush() {
      const tail = valueRedactor.push(decoder.end()) + valueRedactor.flush();
      return patternRedactor.push(tail) + patternRedactor.flush();
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
      // Record a full maxPending-sized window, then retain its trailing
      // `overlap` characters as the start of the next window so a signal
      // straddling the cut still appears whole in one of the two windows.
      // Retaining strictly fewer than `boundary` characters guarantees the
      // loop always makes forward progress, even in a degenerate
      // `overlap >= boundary` config, so it can never spin.
      const boundary = Math.max(1, maxPending);
      record(pending.slice(0, boundary));
      pending = pending.slice(Math.max(1, boundary - overlap));
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
  createProcessOutputRedactor,
  createStreamingPatternRedactor,
  createStreamingRedactor,
  createStreamingReplacer,
  createStreamingSignalScanner,
  isSensitiveEnvName,
  redactCredentialPatterns,
};
