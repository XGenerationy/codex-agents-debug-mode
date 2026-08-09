const assert = require('node:assert/strict');
const test = require('node:test');

const { createStreamingSignalScanner, redactCredentialPatterns } = require('./pr_closeout_stream');

// A unique, self-contained marker whose prefix/suffix are not themselves
// signals under `findMarker`, so a torn marker cannot be "detected" by
// accident — the whole 20-char string must survive inside a single scan
// window for the assertion to pass.
const MARKER = 'STRADDLE_FAIL_MARKER';
const findMarker = (text) => (text.includes(MARKER) ? [MARKER] : []);

// Build a single newline-free line of `length` characters that carries MARKER
// centred on `straddleOffset` (so it spans that byte offset). No `\n`/`\r`
// anywhere, forcing the scanner's oversized-line drain path rather than the
// normal per-line path.
const straddlingLine = (straddleOffset, length) => {
  const start = straddleOffset - Math.floor(MARKER.length / 2);
  const filler = length - start - MARKER.length;
  return '.'.repeat(start) + MARKER + '.'.repeat(filler);
};

const feedInChunks = (scanner, text, chunkSize) => {
  for (let offset = 0; offset < text.length; offset += chunkSize) {
    scanner.push(text.slice(offset, offset + chunkSize));
  }
  scanner.flush();
};

test('forced-drain retains overlap so a signal straddling the legacy window cut is still detected', () => {
  // Regression for UikN3. With maxPending=65536/overlap=512 the legacy code
  // recorded [0,65024) then retained from 65024 with NO overlap, so a signal
  // spanning offset 65024 was torn: its prefix landed in window N and its
  // suffix only in window N+1, and it was never scanned whole in either. The
  // fix records a full [0,65536) window and retains from 65024, so the last
  // `overlap` chars of the recorded window head the next one and the marker
  // sits complete inside the first window.
  const maxPending = 65_536;
  const overlap = 512;
  const legacyCut = maxPending - overlap; // 65024 — old non-overlapping boundary
  const line = straddlingLine(legacyCut, maxPending + 1_498); // > maxPending, no newline
  const scanner = createStreamingSignalScanner(findMarker, { maxPending, overlap });
  feedInChunks(scanner, line, 7_000); // arbitrary, non-aligned chunk size
  assert.deepEqual(scanner.values(), [MARKER]);
});

test('forced-drain overlap holds across a later forced window boundary', () => {
  // The same straddle at the SECOND legacy cut (2*65024=130048), reached only
  // after >=2 forced-drain iterations, proving the overlap is preserved for
  // every window and not just the first. Under the old code this signal would
  // be split between the second and third windows and lost.
  const maxPending = 65_536;
  const overlap = 512;
  const secondLegacyCut = 2 * (maxPending - overlap); // 130048
  const line = straddlingLine(secondLegacyCut, secondLegacyCut + 2_010); // forces two drains
  const scanner = createStreamingSignalScanner(findMarker, { maxPending, overlap });
  feedInChunks(scanner, line, 8_192);
  assert.deepEqual(scanner.values(), [MARKER]);
});

test('forced-drain always makes forward progress when overlap >= window size', () => {
  // Degenerate config guard: with overlap (100) >= maxPending (16) the retain
  // step would compute a non-positive slice offset; the Math.max(1, ...) guard
  // keeps every iteration advancing by at least one char so the loop cannot
  // spin. If this regressed, the test process would hang rather than fail.
  const scanner = createStreamingSignalScanner(findMarker, { maxPending: 16, overlap: 100 });
  const line = '.'.repeat(40) + MARKER + '.'.repeat(40); // no newline, > maxPending
  scanner.push(line);
  scanner.flush();
  // 16-wide windows advancing 1 char at a time overlap by 15 chars, so the
  // 20-char marker is wider than any single window and is legitimately torn —
  // the point of this test is termination, not detection.
  assert.ok(Array.isArray(scanner.values()));
});

test('normal newline-delimited input is scanned line-by-line across chunk boundaries', () => {
  // The oversized-line fix must not disturb the ordinary path: complete lines
  // (LF and CRLF) are scanned as they arrive, a signal split across two push()
  // calls is detected once its line completes, and a trailing newline-free
  // line is scanned on flush().
  const finder = (text) => {
    const out = [];
    if (text.includes('FAILLINE')) out.push('FAIL');
    if (text.includes('SKIPLINE')) out.push('SKIP');
    return out;
  };
  const scanner = createStreamingSignalScanner(finder);
  scanner.push('ok line one\nFAIL'); // 'FAILLINE' begins here, line still open
  scanner.push('LINE here\r\nok two\nSKIPLI'); // completes FAILLINE (CRLF), opens SKIPLINE
  scanner.push('NE trailing'); // no newline -> buffered until flush
  scanner.flush();
  assert.deepEqual(scanner.values(), ['FAIL', 'SKIP']);
});

test('repeated signals are de-duplicated by summary and capped', () => {
  // Same-summary matches on different lines collapse to a single recorded
  // entry, unaffected by the drain changes.
  const scanner = createStreamingSignalScanner((text) => (text.includes('BOOM') ? ['BOOM'] : []));
  scanner.push('BOOM one\nBOOM two\nBOOM three\n');
  scanner.flush();
  assert.deepEqual(scanner.values(), ['BOOM']);
});

test('redactCredentialPatterns strips credentials embedded in git/gh diagnostics', () => {
  // A thrown error.message from git/gh can embed a credential that the
  // value-based streaming redactor cannot catch (the secret is woven into the
  // diagnostic text, not present as a known env value). The pattern redactor
  // must remove it from every common shape while leaving ordinary diagnostic
  // text intact. Token literals are built by concatenation so the repository's
  // own public-safety scanner (which flags `gh[pousr]_` + 20+ chars in source)
  // does not trip on the test fixture.
  const ghpToken = ['ghp', '_', 'AbCdEf0123456789Zabcdefghij0123'].join('');
  const ghsToken = ['ghs', '_', 'AbCdEf0123456789Zabcdefghij'].join('');
  assert.equal(
    redactCredentialPatterns(`fatal: could not read Username for https://${ghpToken}@github.com/org/repo.git`),
    'fatal: could not read Username for [REDACTED:url-credential]@/org/repo.git',
    'a token embedded in a URL userinfo section is redacted',
  );
  assert.equal(
    redactCredentialPatterns(`remote: https://x-access-token:${ghsToken}@github.com/org/repo`),
    'remote: [REDACTED:url-credential]@/org/repo',
    'an x-access-token URL credential is redacted',
  );
  assert.equal(
    redactCredentialPatterns('gh: HTTP 401 Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig'),
    'gh: HTTP 401 Authorization=[REDACTED]',
    'a Bearer token after an Authorization key is fully redacted',
  );
  assert.equal(
    redactCredentialPatterns(`error: ${ghpToken} invalid token`),
    'error: [REDACTED:token] invalid token',
    'a bare ghp_ token is redacted',
  );
  // The *_key / client_secret name families mirror the gate CLI's
  // SENSITIVE_ENV_PATTERN (Codex #3745074709): a diagnostic echoing
  // `api_key=...`/`access_key=...`/`private_key=...` must be redacted, with
  // underscore AND hyphen separators. The key NAME is preserved; the value
  // (the whole rest of the line, like Authorization: Bearer) is replaced —
  // greedy-to-EOL is the safer choice (never leaves a trailing credential
  // fragment).
  assert.equal(
    redactCredentialPatterns('config error: api_key=sk_live_AbCdEf0123456789 invalid'),
    'config error: api_key=[REDACTED]',
    'an api_key=... value is redacted (underscore separator)',
  );
  assert.equal(
    redactCredentialPatterns('probe: api-key=sk_live_AbCdEf0123456789 rejected'),
    'probe: api-key=[REDACTED]',
    'an api-key=... value is redacted (hyphen separator)',
  );
  assert.equal(
    redactCredentialPatterns('aws: access_key=AKIAIOSFODNN7EXAMPLE expired'),
    'aws: access_key=[REDACTED]',
    'an access_key=... value is redacted',
  );
  assert.equal(
    redactCredentialPatterns('tls: private_key=MIIEvQIBADANBgkqhkiG9w0BAQE leak'),
    'tls: private_key=[REDACTED]',
    'a private_key=... value is redacted',
  );
  assert.equal(
    redactCredentialPatterns('oauth: client_secret=cs_live_abc123 invalid'),
    'oauth: client_secret=[REDACTED]',
    'a client_secret=... value is redacted',
  );
  // A multi-line PEM block (a private_key/signing_key value spanning physical
  // newlines). The line-scoped key-name pattern would redact only the first
  // line; the PEM-block pattern runs FIRST and consumes the whole BEGIN..END
  // span so no continuation line leaks (Qodo #1 multiline gap). The block is
  // built with a placeholder label so the source stays clean of a literal
  // 'BEGIN PRIVATE KEY' that the repo's own validator would flag.
  const pemBlock = [
    'error: private_key=-----BEGIN PLACEHOLDER KEY-----',
    'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAqIBA',
    'M2dJJ9C7UcN3va1YqFn1n4kVbH0/keymaterialbase64==',
    '-----END PLACEHOLDER KEY-----',
    'rest of diagnostic',
  ].join('\n');
  assert.equal(
    redactCredentialPatterns(pemBlock),
    'error: [REDACTED:pem-block]\nrest of diagnostic',
    'a multi-line PEM block is redacted in full, including continuation lines',
  );
  // A PEM block with NO key-name prefix (CodeRabbit 3745322356): a child
  // process can emit a raw `-----BEGIN…-----` block. The keyed pattern only
  // matches after `key=`/`key:`; the generic fallback catches an un-prefixed
  // block so the body does not leak.
  const rawPem = [
    'stdout: -----BEGIN PLACEHOLDER KEY-----',
    'MIIBVwIBADANBgkqhkiG9w0BAQEFAASCAUEwamE=',
    '-----END PLACEHOLDER KEY-----',
    'end',
  ].join('\n');
  assert.equal(
    redactCredentialPatterns(rawPem),
    'stdout: [REDACTED:pem-block]\nend',
    'an un-prefixed PEM block is redacted by the generic fallback',
  );
  // Ordinary diagnostic text without a credential is preserved verbatim.
  const benign = 'fatal: not a git repository (or any of the parent directories): .git';
  assert.equal(redactCredentialPatterns(benign), benign, 'non-credential diagnostics are unchanged');
  // Non-string / empty input is coerced safely.
  assert.equal(redactCredentialPatterns(undefined), '', 'undefined coerces to empty');
  assert.equal(redactCredentialPatterns(null), '', 'null coerces to empty');
});
