'use strict';

// Shallow, zero-dependency workflow hygiene predicates for the repository
// validator. Deliberately regex-level — no YAML parser exists in a
// zero-dependency repo — and honest about that limitation. The design is
// CONSERVATIVELY FAIL-CLOSED: any line that contains a `uses:` token the
// regex cannot positively confirm as a clean block-style pinned/local
// reference is flagged for manual review. This is the opposite of trying to
// enumerate every YAML flow/anchor/quoted-key variant (which is a losing
// game without a real parser): instead, the check trusts ONLY the narrow
// block-style form it can fully parse, and rejects everything else.
//
// What passes without a violation:
//   - uses: ./local/path           (same-repo local action)
//   - uses: owner/repo@<40-hex>    (SHA-pinned remote action)
//   - "uses": 'owner/repo@<40-hex>' (quoted key/value variants)
//   - uses : owner/repo@<40-hex>    (whitespace around the colon)
//
// What is flagged (fail-closed — rewrite in block style or review manually):
//   - Flow style: - {uses: ...}, release: {uses: ...}, [{uses: ...}]
//   - Anchors:    uses: &anchor owner/repo@v1
//   - Multi-entry flow sequences, nested flow mappings
//   - Any uses: whose ref is not a 40-hex SHA or local ./path
//
// Comment lines (#) and run: string values containing the text "uses:" are
// NOT flagged — they are not YAML keys. A real YAML parser would be the
// correct long-term fix; until one is added, the conservative fail-closed
// posture is the honest guarantee.

// A clean block-style `uses:` line whose value can be fully extracted. The
// key may be quoted; whitespace around the colon is tolerated (YAML spec).
// The value's opening/closing quote must match. An anchor (`&`) on the value
// or any non-whitespace before the key (flow context) prevents a match, so
// those lines fall through to the SUSPICIOUS_USES check below.
const USES_LINE = /^\s*(?:-\s+)?(['"]?)uses\1\s*:\s*(['"]?)([^\s&#]+)\2\s*(?:#.*)?$/;
// A `uses` token that looks like a YAML key but is NOT a clean USES_LINE
// match. This catches flow style (`- {uses: ...}`, `release: {uses: ...}`,
// `[{uses: ...}]`), anchors (`uses: &name ref`), multi-entry flow sequences,
// and any other form the block-style regex cannot parse. To avoid false
// positives on `run:` string values, the token must appear at a YAML KEY
// position: after optional indentation + optional `-` (block-style key), OR
// inside `{}`/`[]` (flow context). A `uses:` buried inside a `run: echo
// uses: foo` string scalar does NOT match because it is preceded by other
// non-key content, not by a line-start or brace boundary.
const SUSPICIOUS_USES = /(?:^\s*(?:-\s*)?|[{[]\s*)['"]?uses['"]?\s*:/;
const COMMENT_LINE = /^\s*#/;
// A line whose YAML value is a raw string scalar (shell script, command).
// Everything after `run:`/`entrypoint:` is string content, not YAML keys, so
// a `uses:` or `{uses:}` inside such a value is script text and must not be
// flagged. (A real `uses:` key cannot coexist with `run:` on one line.)
const RUN_SCALAR_LINE = /^\s*(?:-\s+)?(?:run|entrypoint|shell)\s*:/;
const PINNED_REF = /@[0-9a-f]{40}$/;

/**
 * Returns one violation per `uses:` line whose reference is neither a
 * same-repo local path (`./...`) nor pinned to a 40-hex commit SHA, PLUS any
 * `uses:` token the regex cannot positively parse (flow style, anchors, etc.)
 * reported as a suspicious-uses violation requiring manual review. Docker
 * references are flagged fail-closed. Line numbers are 1-indexed.
 * @param {string} content workflow or action YAML text.
 * @returns {Array<{line: number, ref: string}>}
 */
// A block-scalar indicator at the end of a key line (`run: |`, `shell: >`).
// The value continues on subsequent MORE-indented lines until indentation
// drops back to (or below) the key's level — those continuation lines are
// raw string content (script text), not YAML keys, and must not be scanned.
// A block-scalar indicator at the end of a key line (`run: |`, `shell: >`).
// YAML allows: an explicit indentation indicator after the style (`|2`), a
// chomping indicator (`|-`, `|+`), a comment after the indicator (`| # cmt`),
// and any order of indentation+chomping (`|2-`, `|-2`). The value continues
// on subsequent MORE-indented lines until indentation drops back.
const BLOCK_SCALAR_HEADER = /^\s*(?:-\s+)?\S.*:\s*[|>](?:[1-9][-+]?|[-+]?[1-9]?)[ \t]*(?:#.*)?$/;

const findUnpinnedUses = (content) => {
  const violations = [];
  const lines = String(content ?? '').split(/\r?\n/);
  // Block-scalar tracking: when a line opens a `|` or `>` scalar, record the
  // indentation of the KEY line. Subsequent lines indented MORE than that are
  // scalar body (script text) and must be skipped. The scalar ends when a line
  // is indented at or below the key level (or is blank, which YAML treats as
  // part of the scalar but carries no keys).
  let scalarKeyIndent = -1;
  lines.forEach((text, index) => {
    const indent = text.length - text.replace(/^\s+/, '').length;
    // Inside a block scalar? Skip body lines that are deeper-indented (or blank).
    if (scalarKeyIndent >= 0) {
      if (text.trim() === '' || indent > scalarKeyIndent) return;
      // Indentation dropped back: the scalar has ended; resume normal scanning.
      scalarKeyIndent = -1;
    }
    // Comment lines never carry a YAML key.
    if (COMMENT_LINE.test(text)) return;
    // A `run:` (or `entrypoint:`/`shell:`) line's value is a string scalar —
    // any `uses:` or braces inside it are script text, not YAML keys.
    if (RUN_SCALAR_LINE.test(text)) {
      // If this line opens a BLOCK scalar (run: |), track its body.
      if (BLOCK_SCALAR_HEADER.test(text)) scalarKeyIndent = indent;
      return;
    }
    const match = USES_LINE.exec(text);
    if (match) {
      const ref = match[3];
      if (ref.startsWith('./')) return;
      if (!PINNED_REF.test(ref)) violations.push({ line: index + 1, ref });
      return;
    }
    // The line is not a clean block-style uses: — but does it contain a
    // `uses:` token that looks like a YAML key? If so, flag it fail-closed:
    // the regex cannot confirm the ref is safe, so it must not pass silently.
    // This catches flow style, anchors, multi-entry sequences, and any other
    // form a regex cannot parse. The SUSPICIOUS_USES pattern avoids matching
    // `uses:` inside a quoted run: string value by requiring the token to
    // appear at a key position (start, after whitespace/dash/brace/semicolon).
    if (SUSPICIOUS_USES.test(text)) {
      violations.push({ line: index + 1, ref: '(uses: in non-block-style or unparseable form — rewrite in clean block style or review manually)' });
    }
  });
  return violations;
};

/**
 * True when the document declares a column-zero `permissions:` block — the
 * house convention (validate.yml) that every workflow states its token
 * scope explicitly instead of inheriting the default.
 * @param {string} content workflow YAML text.
 * @returns {boolean}
 */
const hasTopLevelPermissions = (content) => /^(['"]?)permissions\1\s*:(\s|$)/m.test(String(content ?? ''));

module.exports = { findUnpinnedUses, hasTopLevelPermissions };
