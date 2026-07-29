const assert = require('node:assert/strict');
const test = require('node:test');

const { createStreamingSignalScanner } = require('./pr_closeout_stream');

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
