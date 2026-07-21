const { StringDecoder } = require('node:string_decoder');

const SENSITIVE_ENV_NAME = /(?:^|_)(?:ACCESS_KEY|API_KEY|AUTH_CONFIG|AUTH_TOKEN|BEARER_TOKEN|CLIENT_SECRET|CONNECTION_STRING|COOKIE|CREDENTIAL|DATABASE_URL|DSN|ENCRYPTION_KEY|MYSQL_PWD|PASSWORD|PASSWD|PGPASSWORD|PRIVATE_KEY|REDIS_URL|SECRET|SESSION_TOKEN|SIGNING_KEY|TOKEN|URI)(?:$|_)/i;
// npm basic-auth config uses bare `_AUTH` / `_auth` (e.g. NPM_CONFIG__AUTH,
// npm_config__auth) which does not match the TOKEN/AUTH_TOKEN suffix patterns.
const SENSITIVE_NPM_AUTH = /(?:^|_)_?AUTH$/i;

const isSensitiveEnvName = (name) => {
  const key = String(name);
  return SENSITIVE_ENV_NAME.test(key) || SENSITIVE_NPM_AUTH.test(key);
};

const buildChildEnvironment = (env = process.env, allowedSensitiveNames = []) => {
  const allowed = new Set(allowedSensitiveNames.map((name) => String(name).toUpperCase()));
  return Object.fromEntries(Object.entries(env).filter(([name]) => (
    !isSensitiveEnvName(name) || allowed.has(name.toUpperCase())
  )));
};

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
    Buffer.from(raw, 'utf8').toString('hex'),
  ];
};

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
    for (const match of String(value).matchAll(/(?:^|[;\s])(?:password|passwd|pwd|secret|token|user(?:name| id)?)=([^;\s]+)/gi)) {
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

const createStreamingRedactor = (env = process.env, names = []) => createStreamingReplacer(
  buildSecretReplacements(env, names),
);

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
