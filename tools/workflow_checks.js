'use strict';

// Shallow, zero-dependency workflow hygiene predicates for the repository
// validator. Deliberately regex-level — no YAML parser exists in a
// zero-dependency repo — and honest about it: these catch the failure modes
// that matter (a mutable action ref, a workflow with no permissions
// declaration) without claiming to understand YAML structure. Known escape:
// a `uses:` written in YAML flow style (`- {uses: x@v1}`) is not matched
// and therefore not checked — flow style is never written by hand in
// workflows, and dodging the check requires deliberately reformatting your
// own file to evade your own validator. Block scalars, aliases, and every
// other near-miss form measured in review get captured as a garbage ref
// and flagged, which is the fail-closed direction.

const USES_LINE = /^\s*(?:-\s+)?uses:\s*(['"]?)([^\s#]+)\1\s*(?:#.*)?$/;
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
