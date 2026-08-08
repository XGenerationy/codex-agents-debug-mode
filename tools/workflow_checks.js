'use strict';

// Shallow, zero-dependency workflow hygiene predicates for the repository
// validator. Deliberately regex-level — no YAML parser exists in a
// zero-dependency repo — and honest about it: these catch the failure modes
// that matter (a mutable action ref, a workflow with no permissions
// declaration) without claiming to understand YAML structure. A `uses:` in
// YAML flow style (`- {uses: x@v1}`) is matched by FLOW_USES and reported
// as an unsupported-flow-style violation rather than silently skipped: it
// is fail-closed (an unchecked ref is never allowed through), and parsing
// the ref out of a flow mapping without a real YAML parser would risk a
// bypass of its own. Whitespace around the colon is tolerated because the
// YAML spec permits it (`uses : ref` is the same key as `uses: ref`) and
// the ref still extracts cleanly. Block scalars, aliases, and every other
// near-miss form measured in review get captured as a garbage ref and
// flagged, which is the fail-closed direction.

const USES_LINE = /^\s*(?:-\s+)?uses\s*:\s*(['"]?)([^\s#]+)\1\s*(?:#.*)?$/;
// A `uses:` key inside a YAML flow mapping. Single-line flow mappings that
// contain `uses:` are the bypass surface (the block-style USES_LINE cannot
// reach inside `{ ... }`). `[^}]*` keeps the match on one logical mapping;
// a multi-line flow mapping is vanishingly rare in workflows and still
// fails closed via the garbage-ref path.
const FLOW_USES = /^\s*-?\s*\{[^}]*\buses\s*:/;
const PINNED_REF = /@[0-9a-f]{40}$/;

/**
 * Returns one violation per `uses:` line whose reference is neither a
 * same-repo local path (`./...`) nor pinned to a 40-hex commit SHA. Docker
 * references are flagged fail-closed. Line numbers are 1-indexed.
 * @param {string} content workflow or action YAML text.
 * @returns {Array<{line: number, ref: string}>}
 */
const findUnpinnedUses = (content) => {
  const violations = [];
  String(content ?? '').split(/\r?\n/).forEach((text, index) => {
    // A flow-style `uses:` (`- {uses: ...}`) cannot be parsed without a YAML
    // parser; report it as an unsupported-flow-style violation so the pin
    // check stays unbypassable rather than silently skipping the entry.
    if (FLOW_USES.test(text)) {
      violations.push({ line: index + 1, ref: '(flow-style uses: — rewrite in block style)' });
      return;
    }
    const match = USES_LINE.exec(text);
    if (!match) return;
    const ref = match[2];
    if (ref.startsWith('./')) return;
    if (!PINNED_REF.test(ref)) violations.push({ line: index + 1, ref });
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
const hasTopLevelPermissions = (content) => /^permissions:(\s|$)/m.test(String(content ?? ''));

module.exports = { findUnpinnedUses, hasTopLevelPermissions };
