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
// TAGGED keys (`- !!str uses: owner/action@main` — js-yaml resolves the tag
// and the line parses to an ordinary unpinned `uses` property, a real bypass),
// ANCHORED keys (`- &step uses: owner/action@main` — the anchor on the KEY,
// alone or combined with a tag: `&step !!str uses:` / `!!str &step uses:`,
// all resolve via js-yaml to `{uses: ...}`, a real bypass), and any other
// form the block-style regex cannot parse. To avoid false positives on
// `run:` string values, the token must appear at a YAML KEY position: after
// optional indentation + optional `-` (block-style key), OR inside `{}`/`[]`
// (flow context). A `uses:` buried inside a `run: echo uses: foo` string
// scalar does NOT match because it is preceded by other non-key content, not
// by a line-start or brace boundary. The optional tag (`!!str`, `!`, `!<...>`)
// OR anchor (`&name`) indicator before the key is matched explicitly, in
// either order and combination, so a tag/anchor that resolves to a real
// property cannot slip past — these forms are vanishingly rare in real
// workflow YAML, so matching them is fail-closed: flag for manual review
// rather than risk an unpinned-action bypass.
const SUSPICIOUS_USES = /(?:^\s*(?:-\s*)?(?:!\S*\s+|&\S+\s+)*|[{[][^}]*?|,\s*)((?:!\S*\s+|&\S+\s+)*['"]?uses['"]?\s*:)/g;
const COMMENT_LINE = /^\s*#/;
// Strip a trailing YAML comment (` #...` or `#...` at line start) from a line,
// respecting single- and double-quoted scalars — including one carried open
// from a PREVIOUS physical line via `startState` (a `#` genuinely INSIDE an
// open multiline quoted scalar is scalar content, not a comment-start, and
// must not be treated as one just because this call assumed a fresh line;
// CodeRabbit #6YbIQU / chatgpt-codex-connector PR7 #6YbKFc). YAML requires a
// `#` to be at the start of a line OR preceded by whitespace to begin a
// comment, so `key:value#foo` is NOT a comment.
//
// Delegates entirely to walkQuoteState's `stopAtComment` mode (CodeRabbit
// #6YbIQS) instead of maintaining its own separate quote-tracking loop. This
// function used to carry its OWN copy of the position-aware quote-open-
// context walk, which had already drifted from isInsideQuotedScalar's copy
// once and reintroduced a bug fixed there first (chatgpt-codex-connector PR7
// #6Yap8e — a plain scalar's own embedded apostrophe, e.g. `don't`, was
// wrongly treated as opening a string, hiding the real trailing comment and
// letting comment text reach the SUSPICIOUS_USES scan as if it were a key;
// originally fixed in isInsideQuotedScalar under CodeRabbit #6YSoOn/#6YW1O6).
// A second, independently-maintained copy here can only drift the same way
// again through a different door — sharing one walker (the same one
// isInsideQuotedScalar uses) is the fix this file's own policy already
// commits to after that incident.
const stripTrailingYamlComment = (text, startState = { inDouble: false, inSingle: false }) => {
  const str = String(text);
  const { commentIndex } = walkQuoteState(str, str.length, startState, true);
  return commentIndex >= 0 ? str.substring(0, commentIndex) : str;
};
// True when the character at `matchIndex` in `text` sits inside a YAML quoted
// scalar (single- or double-quoted). Used by the flow-boundary scanners
// (FLOW_QUOTED_USES_KEY, FLOW_ALIAS_KEY) and the SUSPICIOUS_USES scanner to
// suppress matches that are string content, not YAML keys (CodeRabbit #6YEr9a).
// A naive quote COUNT is wrong when one quote type appears inside a value
// quoted with the OTHER type — e.g. `name: "can't"` has an apostrophe inside a
// double-quoted string, and counting it as an unmatched single quote would
// falsely mark a later `{uses: ...}` as "inside a string" (Codex 3745211657).
// Walk the prefix tracking the active quote context: a quote char only toggles
// state when it matches the currently-open quote type (or opens a new context
// when none is open). Backslash escapes inside double quotes are respected;
// YAML single-quoted strings escape a quote by doubling it ('').
//
// A bare `'` or `"` does NOT always open a quoted scalar: YAML plain
// (unquoted) scalars may contain either character anywhere except as their
// first character — `name: don't` and `name: a"b` are both valid plain
// scalars, not quote delimiters. Treating every quote char as toggling state
// means a plain scalar's embedded quote swallows the rest of the line into a
// phantom "string", hiding a REAL later match (e.g. an escape-obfuscated flow
// `uses:` key) and causing a fail-OPEN bypass. Originally fixed for `'` only
// (CodeRabbit #6YSoOn); `"` had the identical gap (CodeRabbit #6YW1O6). Both
// quote types share one gate: a quote char only opens a quoted scalar when it
// is the first non-whitespace character at a value/key position — i.e.
// immediately (modulo whitespace) after start-of-line, `:`, `-`, `{`, `[`,
// `,`, or `?` (the explicit-key indicator).
//
// `?` and `-` are TRANSITIVE, not a flat membership test (Qodo #1,
// question-mark quote bypass; CodeRabbit #6YXkRo, hyphen in a plain scalar):
// each only extends valid quote-open context to what follows it when the
// character ITSELF sat at a valid position. `name: ok? "x` has `?` as
// ordinary plain-scalar content (preceded by `k`, not a real boundary), and
// `name: abc-'def` has `-` the same way (preceded by `c`, not a sequence
// dash) — neither may re-open context for the quote after it, or the walker
// misclassifies the rest of the line as string content and hides a real key
// that follows. `{? "uses": ref}` (a genuine explicit-key marker right after
// `{`) and `- 'value'` (a genuine sequence dash at line start) correctly
// preserve context, because in both cases it was already valid when the
// character was reached. `{`, `[`, and `,` do NOT need this treatment: YAML
// forbids them inside a flow-context plain scalar entirely, so unlike
// `?`/`-` they can never appear as ambiguous literal content in the position
// that matters here — a flat membership check for them is safe.
//
// `:` needs its OWN check, not membership at all (CodeRabbit #6YXkRy, Qodo
// #2, colon quote-context bypass): YAML only treats `:` as a real key/value
// separator when it is followed by whitespace or end-of-line; `a:"b` is
// valid plain-scalar CONTENT (colon with no following space), not a
// boundary. A flat membership check granted quote-open context after any
// `:` regardless of what followed it, so `name: a:"b, uses: owner/action@main`
// let the `"` after the content-only colon forge a phantom quoted scalar
// that swallowed the real `uses:` key past the comma. Only a `:` actually
// followed by whitespace/EOL may grant context; a content-only `:` must
// behave like ordinary content (in particular it must NOT be treated as
// transitive either — YAML's rule depends on what follows it, not on
// whatever context preceded it).
const QUOTE_OPEN_CONTEXT = new Set(['{', '[', ',']);
const TRANSITIVE_QUOTE_OPEN_CONTEXT = new Set(['-', '?']);
// Walks `str` from index 0 up to (not including) `endIndex`, applying the
// same quote-open-context rules isInsideQuotedScalar and the cross-line
// carryover computation both need — a single shared implementation so the
// two cannot drift (matching this file's own stated policy after the
// SUSPICIOUS_USES/isInsideQuotedScalar drift under CodeRabbit #6YSoOn).
// `startState.inDouble`/`inSingle` seed an ALREADY-OPEN scalar carried over
// from a previous line (chatgpt-codex-connector PR7 #6YaZ5F) — a fresh
// per-line call passes `{inDouble: false, inSingle: false}`, matching the
// original always-fresh behavior exactly (a quote can never be open at the
// very start, so atQuoteOpenContext derives to `true`, same as before).
//
// `stopAtComment` (default false, CodeRabbit #6YbIQS): when true, the walk
// stops at the first `#` that opens a real YAML comment (outside any quote,
// at line-start or preceded by whitespace) and reports its index as
// `commentIndex` instead of walking the comment text itself — comment
// content must never influence quote state (a stray quote inside a comment
// must not corrupt what carries to the next line) nor be scanned for keys.
// The check runs AFTER the inDouble/inSingle branches' own `continue`s, so a
// `#` that is genuinely INSIDE an open quote (including one carried over
// from a previous line) is left alone as ordinary content, not mistaken for
// a comment-start. isInsideQuotedScalar's positional lookups leave this
// false: they want the state at one specific index, not early termination.
const walkQuoteState = (str, endIndex, startState, stopAtComment = false) => {
  let inDouble = startState.inDouble;
  let inSingle = startState.inSingle;
  let atQuoteOpenContext = !inDouble && !inSingle;
  let commentIndex = -1;
  for (let i = 0; i < endIndex; i += 1) {
    const ch = str[i];
    if (inDouble) {
      if (ch === '\\') { i += 1; } // skip the escaped char
      else if (ch === '"') { inDouble = false; atQuoteOpenContext = false; }
      continue;
    }
    if (inSingle) {
      if (ch === "'") {
        if (str[i + 1] === "'") { i += 1; } // escaped '' — stay in string
        else { inSingle = false; atQuoteOpenContext = false; }
      }
      continue;
    }
    if (stopAtComment && ch === '#' && (i === 0 || /\s/.test(str[i - 1]))) {
      commentIndex = i;
      break;
    }
    if (ch === '"' && atQuoteOpenContext) {
      inDouble = true;
    } else if (ch === "'" && atQuoteOpenContext) {
      inSingle = true;
    } else if (ch === ':') {
      const next = str[i + 1];
      atQuoteOpenContext = next === undefined || /\s/.test(next);
    } else if (TRANSITIVE_QUOTE_OPEN_CONTEXT.has(ch)) {
      // Preserve the current context, but ONLY when this marker is actually
      // followed by whitespace/EOL: a real YAML sequence dash or explicit-key
      // marker requires trailing separation to introduce the next token —
      // `-"def` / `?"def` (no space) is ordinary plain-scalar content, not a
      // marker, and the quote right after it is NOT a real quote-open
      // (chatgpt-codex-connector PR7 #6Yap8Z). Valid stays valid only when
      // separation follows; invalid always stays invalid either way.
      const next = str[i + 1];
      atQuoteOpenContext = atQuoteOpenContext && (next === undefined || /\s/.test(next));
    } else if (!/\s/.test(ch)) {
      atQuoteOpenContext = QUOTE_OPEN_CONTEXT.has(ch);
    }
  }
  return { inDouble, inSingle, commentIndex };
};
// True when the character at `matchIndex` sits inside a YAML quoted scalar.
// `startState` (default: not in a quote) seeds a scalar carried over from a
// previous line — see walkQuoteState and findUnpinnedUses' per-line loop.
const isInsideQuotedScalar = (text, matchIndex, startState = { inDouble: false, inSingle: false }) => {
  const { inDouble, inSingle } = walkQuoteState(String(text), matchIndex, startState);
  return inDouble || inSingle;
};
// A double-quoted YAML mapping key at a block-style key position, capturing the
// raw (escape-laden) key text. Used to catch an obfuscated `uses` key spelled
// with unicode/hex escapes that YAML resolves to an ordinary `uses` property —
// e.g. `"u\u0073es": owner/action@main` parses (js-yaml verified) to
// `{uses: "owner/action@main"}`, a real unpinned-action bypass that neither
// USES_LINE (its key group requires the literal `uses`) nor SUSPICIOUS_USES
// (its `['"]?uses['"]?` is also literal) recognizes. The optional tag/anchor
// prefix mirrors SUSPICIOUS_USES so a tagged/anchored quoted-escape key is also
// caught. Single quotes are excluded: YAML single-quoted strings have NO
// unicode/hex escape processing (only `''` for a literal quote), so an escape
// in single quotes stays literal and cannot spell `uses` obliquely.
const QUOTED_USES_KEY = /^\s*(?:-\s*)?(?:!\S*\s+|&\S+\s+)*"([^"]*)"\s*:/;
// A double-quoted YAML mapping key INSIDE a flow mapping/sequence — after a
// `{`, `[`, or `,` boundary (optionally preceded by a key:value pair's value
// and whitespace). Catches the flow-style escape-obfuscated `uses` key that
// QUOTED_USES_KEY (anchored to a block-style line start) misses — e.g.
// `steps: [{"u\u0073es": owner/action@main}]` parses (js-yaml verified) to
// `{uses: ...}`, a real bypass. The decode check is the same as the block
// case; only the boundary preceding the quoted key differs. Single quotes
// are excluded for the same reason as QUOTED_USES_KEY (no escape processing).
const FLOW_QUOTED_USES_KEY = /[{[,]\s*(?:!\S*\s+|&\S+\s+)*\??\s*"([^"]*)"\s*:/g;
// A YAML ALIAS used as a mapping key INSIDE a flow mapping/sequence — after a
// `{`, `[`, or `,` boundary (optionally preceded by a key:value pair's value
// and whitespace). When the anchor names `uses` (`name: &action_key uses`),
// js-yaml resolves `steps: [{*action_key: ref}]` to `{uses: ref}`, a real
// unpinned-action bypass. The scanner cannot resolve aliases, so fail-closed:
// flag ANY alias in flow-key position. Alias keys are vanishingly rare in real
// workflow YAML flow mappings, so this cannot cause false positives on clean
// pinned actions. Mirrors the block-style ALIAS_IMPLICIT_KEY posture.
const FLOW_ALIAS_KEY = /[{[,]\s*(?:!\S*\s+|&\S+\s+)*\??\s*\*([A-Za-z0-9_-]+)\s*:/g;
// Resolve YAML double-quoted escape sequences into the actual characters they
// denote. YAML double-quoted scalars support \uXXXX (4 hex), \UXXXXXXXX (8
// hex), \xXX (2 hex), plus named escapes (\n, \t, ...); only the code-point
// escapes can form characters that spell `uses` obliquely, so decoding those
// three is sufficient to decide whether a quoted key RESOLVES to `uses`.
const decodeDoubleQuotedEscapes = (raw) => String(raw)
  .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
  .replace(/\\U([0-9a-fA-F]{8})/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)))
  .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16)));
// YAML explicit mapping-key marker: `? <key>` on its own line, with the value
// on a following `: <value>` line. The scanner is line-oriented and cannot
// re-associate the value line, but it does not need to: `? uses` (with the
// value pending on the next line) is itself proof of a `uses` key whose
// reference this regex cannot positively pin-check, so it is flagged
// fail-closed. Optional tag/anchor prefix mirrors SUSPICIOUS_USES. The key
// may be double-quoted AND escape-obfuscated — `- ? "u\u0073es"` (js-yaml
// verified to resolve to {uses: ...}) — so EXPLICIT_QUOTED_KEY captures the
// raw quoted text for the same decode check QUOTED_USES_KEY applies. (Single
// quotes are excluded: no escape processing in YAML single-quoted scalars.)
const EXPLICIT_USES_KEY = /^\s*(?:-\s*)?(?:!\S*\s+|&\S+\s+)*\?\s+['"]?uses['"]?\s*(?::[^#]*)?(?:#.*)?$/;
const EXPLICIT_QUOTED_KEY = /^\s*(?:-\s*)?(?:!\S*\s+|&\S+\s+)*\?\s+"([^"]*)"\s*(?::[^#]*)?(?:#.*)?$/;
// An explicit mapping key that is a YAML ALIAS (`? *action_key`). The scanner
// is line-oriented and cannot resolve aliases, but an alias CAN name `uses`
// (verified: `name: &action_key uses` then `- ? *action_key` resolves via
// js-yaml to {uses: ...}). Fail-closed: flag ANY alias explicit key, since the
// resolver cannot confirm it is NOT `uses`. Alias explicit keys are vanishingly
// rare in real workflow YAML, so this cannot cause false positives on clean
// pinned actions.
const EXPLICIT_ALIAS_KEY = /^\s*(?:-\s*)?(?:!\S*\s+|&\S+\s+)*\?\s+\*\S+\s*(?::[^#]*)?(?:#.*)?$/;
// An explicit mapping key whose VALUE is a block scalar (`? |`, `? >`, with
// optional chomping `-`/`+` and explicit indent-indicator digit): `? |-`
// opens a literal scalar body on following indented lines, and the RESOLVED
// scalar text becomes the key. `- ? |-` / `    uses` / `  : owner/action@main`
// resolves (js-yaml verified) to {uses: "owner/action@main"} (CodeRabbit
// #6YW9UB). Mirrors BLOCK_SCALAR_HEADER's trailing indicator syntax.
const EXPLICIT_BLOCK_SCALAR_KEY = /^\s*(?:-\s*)?(?:!\S*\s+|&\S+\s+)*\?\s*[|>](?:[1-9][-+]?|[-+]?[1-9]?)\s*(?:#.*)?$/;
// An alias used as an IMPLICIT block-style mapping key — `- *action_key : ref`
// (with optional whitespace around the colon). When the anchor names `uses`
// (`name: &action_key uses`), js-yaml resolves this to {uses: ref}. The scanner
// cannot resolve aliases, so it cannot confirm an alias does NOT name `uses`.
// Fail-closed: flag any alias in implicit-key position (Codex 3745389802).
// Anchored to a sequence-item or mapping position so an alias that is a VALUE
// (`uses: *ref` — a legitimate alias value) is NOT flagged.
const ALIAS_IMPLICIT_KEY = /^\s*(?:-\s+)?\*\S+\s*:/;
// A line whose YAML value is a raw string scalar (shell script, command).
// Everything after `run:`/`entrypoint:` is string content, not YAML keys, so
// a `uses:` or `{uses:}` inside such a value is script text and must not be
// flagged. (A real `uses:` key cannot coexist with `run:` on one line.)
const RUN_SCALAR_LINE = /^\s*(?:-\s+)?(?:['"]?)(?:run|entrypoint|shell)(?:['"]?)\s*:/;
// Any YAML key line that opens a block scalar (`key: |` or `key: >`),
// regardless of which key it is. A block scalar's body is raw string content
// on subsequent more-indented lines — `with.script: |` (github-script bodies
// commonly contain `{ uses: ... }` JS objects), `env:`, `description:`, etc.
// Tracking must not be scoped to run/shell/entrypoint only. YAML allows: an
// optional anchor/tag indicator before the scalar (`key: &name |`), an
// explicit indentation indicator (`|2`), a chomping indicator (`|-`, `|+`),
// a trailing comment (`| # cmt`), and any order of indentation+chomping.
const BLOCK_SCALAR_HEADER = /^\s*(?:-\s+)?\S.*:\s*(?:&\S+\s+|[!&].*?\s+)*[|>](?:([1-9])[-+]?|[-+]?([1-9])?)[ \t]*(?:#.*)?$/;
// A pinned action reference: a full 40-character commit SHA. Git object IDs
// are case-insensitive hexadecimal, so a SHA may contain A-F as well as a-f
// (GitHub renders them in either case). The match is case-insensitive so a
// valid immutable pin like actions/checkout@DF4CB1C... is not falsely flagged
// as unpinned (Codex 3745211652).
const PINNED_REF = /@[0-9a-fA-F]{40}$/;

/**
 * Returns one violation per `uses:` line whose reference is neither a
 * same-repo local path (`./...`) nor pinned to a 40-hex commit SHA, PLUS any
 * `uses:` token the regex cannot positively parse (flow style, anchors, etc.)
 * reported as a suspicious-uses violation requiring manual review. Docker
 * references are flagged fail-closed. Line numbers are 1-indexed.
 * @param {string} content workflow or action YAML text.
 * @returns {Array<{line: number, ref: string}>}
 */
const findUnpinnedUses = (content) => {
  const violations = [];
  // Split on CRLF, lone LF, lone CR (legacy Mac), or mixed line endings.
  const rawLines = String(content ?? '').split(/\r\n|\r|\n/);
  // Pre-fold YAML double-quoted line continuations inside explicit-key markers.
  // A continued quoted explicit key like `- ? "u\<NL>  ses"` resolves (js-yaml
  // verified) to `? "uses"`, but the line-oriented scanner sees two lines and
  // misses the resolved key (CodeRabbit #6XsD7p). YAML folds `\<newline>` to
  // empty inside double-quoted strings ONLY — single-quoted strings have no
  // escape processing, and a `\` at end of line outside any string is invalid
  // YAML. The pre-fold is conservative: it only joins when a line opens an
  // explicit-key quoted scalar (`? "..."`) that is unclosed AND ends with `\`,
  // then appends the next line's content with the `\<newline>` and following
  // leading whitespace removed, repeating until the quote closes. This cannot
  // affect `run: |` block scalars (which don't open an explicit-key quoted
  // marker).
  //
  // The opener may sit at block-style line start (`- ? "...`) OR right after a
  // flow boundary (`steps: [{? "u\<NL>ses": ref}]` — js-yaml verified to
  // resolve identically). The original opener only matched line start, so a
  // flow-embedded continuation was never folded and its resolved `uses` key
  // slipped past the scanner entirely (CodeRabbit #6YSx9t).
  const EXPLICIT_KEY_QUOTE_OPEN = /(?:^\s*(?:-\s*)?|[{[,]\s*)(?:!\S*\s+|&\S+\s+)*\?\s*"[^"]*\\$/;
  const lines = [];
  // Record any explicit-key fold that overflowed the safety cap. The cap
  // exists to stop a never-closing quoted key from eating the whole file; when
  // it fires, the partial line still ends inside an unterminated double-quoted
  // scalar and would not match any downstream pattern, producing a fail-OPEN
  // path (CodeRabbit #6YEr9d). Fail closed instead: report the overflow as a
  // violation on the line where the explicit-key marker opened.
  const foldOverflowLines = [];
  for (let i = 0; i < rawLines.length; i += 1) {
    let line = rawLines[i];
    let folds = 0;
    const openedAt = i + 1; // 1-based source line index where the marker opened
    // Match an explicit-key marker (block-start or flow-boundary) opening a
    // double-quoted scalar whose quote is unclosed and whose last
    // non-whitespace char is a backslash.
    while (EXPLICIT_KEY_QUOTE_OPEN.test(line)) {
      const next = rawLines[i + 1] ?? '';
      // Drop the trailing `\`, append the next line's leading-whitespace-stripped
      // content. Re-check (the continuation may itself end with `\`).
      line = line.replace(/\\$/, '') + next.replace(/^\s+/, '');
      i += 1;
      folds += 1;
      // Safety cap: a quoted key that never closes would otherwise eat the
      // whole file. 16 continuation lines is far beyond any real key. When the
      // cap fires, record the overflow — the partial line cannot be parsed and
      // must not pass silently (fail-closed, CodeRabbit #6YEr9d).
      if (folds > 16) {
        foldOverflowLines.push(openedAt);
        break;
      }
    }
    lines.push(line);
  }
  // Block-scalar tracking: when a line opens a `|` or `>` scalar, enter a
  // "pending" state. The FIRST non-blank body line's indentation determines
  // the scalar body indent — subsequent lines at or deeper than that are body
  // (script text) and must be skipped. The scalar ends when a non-blank line
  // is less indented than the body indent. This correctly handles sequence
  // items where sibling keys share the dash level but body is deeper.
  let scalarBodyIndent = -1;  // active body indent, or -1 when not in a scalar
  let scalarPending = false;   // header seen, waiting for first body line
  // The column at which the header's mapping KEY begins, used to detect an
  // EMPTY block scalar (first body line at or below this column → sibling key,
  // not body). For a plain mapping line this equals the line's leading-
  // whitespace `indent` (the key sits at the start of the non-whitespace text).
  // For a sequence item it is the END of the actual dash prefix
  // (`  - name:` → column 4, from the matched `\s*-\s+` prefix), so any amount
  // of post-dash whitespace is handled. Tracked in its OWN coordinate (the key
  // column) and compared only against a following line's column — never against
  // the leading-whitespace `indent`, which is a different unit for seq items.
  let scalarHeaderKeyColumn = -1;
  let scalarExplicitIndent = 0;  // explicit block-scalar indent indicator (e.g. |2)
  // Cross-line quote-scalar carryover: a double/single-quoted scalar INSIDE a
  // flow mapping/sequence can legally continue across physical lines (YAML
  // folds an embedded newline to a space in a double-quoted scalar, keeps it
  // literal in a single-quoted one) — no trailing backslash is needed, unlike
  // the explicit-key continuation folded above. isInsideQuotedScalar resets
  // its quote state fresh at the start of every line, so a scalar's CLOSING
  // quote on a later line was mistaken for a NEW opener, and a real `uses:`
  // key right after it on that same line was hidden as if still inside a
  // string (chatgpt-codex-connector PR7 #6YaZ5F). Tracks the state left open
  // at the end of the previous line's raw text and seeds it into this line's
  // isInsideQuotedScalar calls.
  let quoteCarryover = { inDouble: false, inSingle: false };
  // Report any fold-overflow violations (CodeRabbit #6YEr9d): an explicit-key
  // quoted marker whose continuation exceeded the 16-line safety cap. The
  // partial line cannot be parsed by any downstream pattern, so without this
  // the unpinned-action bypass would pass silently (fail-open).
  for (const overflowLine of foldOverflowLines) {
    violations.push({ line: overflowLine, ref: '(explicit ? quoted mapping key exceeded the 16-line continuation cap — rewrite in clean block style or review manually)' });
  }
  lines.forEach((text, index) => {
    const indent = text.length - text.replace(/^\s+/, '').length;
    // Inside a block scalar? Skip body lines.
    if (scalarBodyIndent >= 0) {
      if (text.trim() === '' || indent >= scalarBodyIndent) return;
      scalarBodyIndent = -1; // indentation dropped: scalar ended
    }
    // Pending (header seen, no body yet)? First NON-BLANK line sets body indent.
    // Blank lines between the header and the first body line do not end the
    // scalar in YAML — they are part of the scalar's content. Stay pending.
    if (scalarPending) {
      if (text.trim() === '') return; // blank: still waiting for first body line
      scalarPending = false;
      // An empty block scalar: the first non-blank line's column is at or below
      // the header's mapping KEY column. YAML parses the header key as an empty
      // string and this line as a SIBLING key, not body content. Fall through to
      // normal processing so a sibling `uses:` is scanned instead of being
      // silently swallowed as the scalar body. Compares against the KEY column
      // (not the leading-whitespace indent) — the two differ for sequence items.
      if (indent <= scalarHeaderKeyColumn) {
        scalarHeaderKeyColumn = -1;
        scalarExplicitIndent = 0;
        // fall through: reprocess this line as a normal key line
      } else {
        scalarBodyIndent = scalarExplicitIndent > 0
          ? scalarHeaderKeyColumn + scalarExplicitIndent
          : indent;
        scalarHeaderKeyColumn = -1;
        scalarExplicitIndent = 0;
        return; // this line is body
      }
    }
    // Seed this line's quote-context walk with whatever the PREVIOUS line's
    // raw text left open (chatgpt-codex-connector PR7 #6YaZ5F), then
    // immediately compute this line's own end-of-line state for the NEXT
    // line — independent of which branch below this line ultimately takes,
    // since it depends only on this line's raw content and its own start
    // state, not on how the rest of this callback processes it. `stopAtComment`
    // (true) makes this walk itself comment-aware: a quote character INSIDE a
    // real trailing comment no longer corrupts the carried state for the next
    // line (CodeRabbit #6YbIQU / chatgpt-codex-connector PR7 #6YbKFc) — and
    // because the in-quote branches run BEFORE the stopAtComment check, a `#`
    // that is actually CONTENT of an already-open carried scalar (not a real
    // comment) is walked through correctly instead of stopping the walk
    // early, so this line's own closing quote is still found (chatgpt-codex-
    // connector PR7 #6YbMwW).
    const lineStartQuoteState = quoteCarryover;
    quoteCarryover = walkQuoteState(text, text.length, lineStartQuoteState, true);
    // Comment lines never carry a YAML key — but this only applies when the
    // line did NOT begin inside a carried-open scalar: the state update above
    // already handles a comment-shaped CONTINUATION of an open scalar
    // (including finding its closing quote, if any) correctly, so early-
    // returning unconditionally here (as before) would skip that update
    // entirely and leave a since-closed scalar looking permanently open to
    // every later line (chatgpt-codex-connector PR7 #6YbMwW).
    if (!lineStartQuoteState.inDouble && !lineStartQuoteState.inSingle && COMMENT_LINE.test(text)) return;
    // A clean block-style uses: is parsed first — it is the one form whose ref
    // we can extract and pin-check. Skipped entirely when the line begins
    // inside a carried-open scalar (chatgpt-codex-connector PR7 #6YbMwS):
    // such a line is STRING CONTENT of a multi-line scalar, not a real
    // mapping key, even when its own text happens to look exactly like
    // `uses: owner/action@main` — e.g. the middle line of
    // `name: "foo\n  uses: owner/action@main\n  bar"` (js-yaml verified to
    // resolve to one scalar value, not a real `uses` key).
    const match = (lineStartQuoteState.inDouble || lineStartQuoteState.inSingle)
      ? null
      : USES_LINE.exec(text);
    if (match) {
      const ref = match[3];
      if (ref.startsWith('./')) return;
      if (!PINNED_REF.test(ref)) violations.push({ line: index + 1, ref });
      return;
    }
    // An obfuscated `uses` key spelled with YAML double-quoted escapes that
    // resolve to `uses` — e.g. `"u\u0073es": owner/action@main` (js-yaml
    // verified to parse to {uses: ...}). USES_LINE and SUSPICIOUS_USES match
    // only the literal `uses` token, so the escape form bypasses them both.
    // Decode the quoted key's code-point escapes and, if it resolves to
    // `uses`, flag the line fail-closed (the reference is unparseable by this
    // line-oriented regex because the value may carry its own quoting).
    const quotedMatch = QUOTED_USES_KEY.exec(text);
    // Only flag when the RAW key differs from its decoded value — a plain
    // `"uses"` (raw === decoded) is a clean quoted key already caught by
    // USES_LINE/SUSPICIOUS_USES, so let it fall through. The decode check
    // exists solely for escape-obfuscated keys (raw `u\u0073es` → `uses`).
    if (quotedMatch && quotedMatch[1] !== 'uses' && decodeDoubleQuotedEscapes(quotedMatch[1]) === 'uses') {
      violations.push({ line: index + 1, ref: '(quoted uses: key resolves to uses via escape sequences — rewrite in clean block style or review manually)' });
      return;
    }
    // The flow-mapping variant: an escape-obfuscated quoted uses key inside
    // `{...}`/`[...]` (e.g. `steps: [{"u\u0073es": ref}]`). QUOTED_USES_KEY is
    // anchored to a block-style line start and misses this; decode at the flow
    // boundary the same way. A flow mapping can carry MULTIPLE quoted keys on
    // one line (`[{"name": setup, "u\u0073es": ref}]`), so iterate EVERY match
    // (CodeRabbit 3745322365) — `.exec` returns only the first. Same
    // raw !== decoded guard so a plain flow `{"uses": ref}` falls through to
    // SUSPICIOUS_USES.
   for (const flowMatch of text.matchAll(FLOW_QUOTED_USES_KEY)) {
     const raw = flowMatch[1];
      // Suppress matches whose boundary character sits inside a quoted scalar
      // (e.g. `name: "a, {\"u\\u0073es\": b}"` — the inner `{` is string
      // content, not a flow boundary). Mirrors the SUSPICIOUS_USES walker
      // (CodeRabbit #6YEr9a).
      if (isInsideQuotedScalar(text, flowMatch.index, lineStartQuoteState)) continue;
     if (raw !== 'uses' && decodeDoubleQuotedEscapes(raw) === 'uses') {
       violations.push({ line: index + 1, ref: '(quoted uses: key resolves to uses via escape sequences — rewrite in clean block style or review manually)' });
       return;
     }
   }
    // A flow-mapping alias key: `steps: [{*action_key: ref}]` (js-yaml verified
    // to resolve to {uses: ref} when the anchor names `uses`). The scanner
    // cannot resolve aliases, so fail-closed: flag any alias in flow-key
    // position. Iterate matchAll in case multiple aliases appear on one line,
    // and apply the quote-context walker so an alias-shaped token inside a
    // quoted scalar (e.g. `name: "a, *k: b"`) does not false-positive
    // (CodeRabbit #6YEr9a).
    for (const aliasMatch of text.matchAll(FLOW_ALIAS_KEY)) {
      if (isInsideQuotedScalar(text, aliasMatch.index, lineStartQuoteState)) continue;
      violations.push({ line: index + 1, ref: '(*alias: flow mapping key — alias may resolve to uses; rewrite in clean block style or review manually)' });
      return;
    }
    // An explicit mapping key `? uses` (value on the following `:` line).
    // The line-oriented scanner cannot re-associate the value, but the marker
    // alone proves a `uses` key exists whose ref cannot be pin-checked here —
    // flag fail-closed rather than let an unpinned reference pass unseen.
    if (EXPLICIT_USES_KEY.test(text)) {
      violations.push({ line: index + 1, ref: '(explicit ? uses mapping key — rewrite in clean block style or review manually)' });
      return;
    }
    // The escape-obfuscated explicit-key variant: `- ? "u\u0073es"` (js-yaml
    // verified to resolve to {uses: ...}). EXPLICIT_USES_KEY matches only the
    // literal `uses` spelling; decode the quoted explicit key the same way and
    // flag fail-closed when it resolves to `uses`.
    const explicitQuotedMatch = EXPLICIT_QUOTED_KEY.exec(text);
    if (explicitQuotedMatch && explicitQuotedMatch[1] !== 'uses' && decodeDoubleQuotedEscapes(explicitQuotedMatch[1]) === 'uses') {
      violations.push({ line: index + 1, ref: '(quoted uses: key resolves to uses via escape sequences — rewrite in clean block style or review manually)' });
      return;
    }
    // An alias-backed explicit key: `- ? *action_key` (js-yaml verified to
    // resolve to {uses: ...} when the anchor names `uses`). The scanner cannot
    // resolve aliases, so fail-closed: any alias in explicit-key position is
    // flagged for manual review (Codex 3745332784).
    if (EXPLICIT_ALIAS_KEY.test(text)) {
      violations.push({ line: index + 1, ref: '(explicit ? *alias mapping key — alias may resolve to uses; rewrite in clean block style or review manually)' });
      return;
    }
    // An alias used as an IMPLICIT block-style mapping key: `- *action_key : ref`
    // (js-yaml verified to resolve to {uses: ref} when the anchor names `uses`).
    // The scanner cannot resolve aliases, so fail-closed: any alias in implicit-
    // key position is flagged. An alias that is a VALUE (`uses: *ref`) is NOT
    // matched — the alias must precede the colon to be a key (Codex 3745389802).
    if (ALIAS_IMPLICIT_KEY.test(text)) {
      violations.push({ line: index + 1, ref: '(*alias: implicit mapping key — alias may resolve to uses; rewrite in clean block style or review manually)' });
      return;
    }
    // An explicit mapping key whose VALUE is itself a block scalar (`? |`,
    // `? >`, with optional chomping/indent modifiers): `- ? |-` then an
    // indented `uses` then `: owner/action@main` resolves (js-yaml verified)
    // to {uses: "owner/action@main"}. BLOCK_SCALAR_HEADER cannot match this —
    // it requires a preceding `:` (it targets `key: |` mapping VALUES, not
    // explicit KEYS) — and no explicit-key scanner recognizes a block-scalar
    // key either, so the resolved `uses` key slips past every check below
    // (CodeRabbit #6YW9UB). The scalar's content also spans multiple physical
    // lines, which a line-oriented regex cannot rejoin to verify. Fail-closed
    // unconditionally: any explicit key spelled as a block scalar is
    // unresolvable here, mirroring EXPLICIT_ALIAS_KEY's posture.
    if (EXPLICIT_BLOCK_SCALAR_KEY.test(text)) {
      violations.push({ line: index + 1, ref: '(explicit ? block-scalar mapping key — rewrite in clean block style or review manually)' });
      return;
    }
    // Any key line that opens a block scalar: start tracking its body so a
    // `uses:` inside the string content is not flagged. Checked after
    // USES_LINE (a uses: key never opens a scalar in valid workflow YAML —
    // its value is an action reference) and before SUSPICIOUS_USES. Record the
    // header's leading-whitespace indent AND its mapping KEY column separately:
    // for a plain mapping line the key column equals the indent; for a sequence
    // item it is the END of the actual dash prefix (`  - name:` → column 4),
    // measured from the matched prefix so any post-dash whitespace is handled.
    // The empty-scalar sibling decision compares the next line's column against
    // the KEY column, never against the leading-whitespace indent (Qodo #10).
    //
    // Tested against the COMMENT-STRIPPED line, not `text` — BLOCK_SCALAR_HEADER's
    // own `\S.*:` prefix is greedy and, on a line whose trailing COMMENT itself
    // contains a `key: |`-shaped fragment (`jobs: # bogus: |`), can swallow past
    // the real comment-start `#` and match the comment's OWN colon+chomping
    // indicator as if it were a genuine block-scalar header. That falsely marks
    // this line as opening a scalar, and the block's real (more-indented) body —
    // which can contain a genuine unpinned `uses:` — is then silently skipped as
    // scalar content instead of scanned (chatgpt-codex-connector PR7 #6Yap8d).
    // Scoped to this one test only — every OTHER check in this function already
    // has its own `(?:#.*)?$` handling built into its own pattern and operates
    // on `text` unchanged, so stripping here does not touch their behavior.
    const scalarHeaderMatch = BLOCK_SCALAR_HEADER.exec(stripTrailingYamlComment(text));
    if (scalarHeaderMatch) {
      scalarPending = true;
      scalarExplicitIndent = Number(scalarHeaderMatch[1] || scalarHeaderMatch[2]) || 0;
      const seqPrefix = text.match(/^(\s*-\s+)/);
      scalarHeaderKeyColumn = seqPrefix ? seqPrefix[1].length : indent;
      return;
    }
    // A `run:` (or `entrypoint:`/`shell:`) line whose value is inline (not a
    // block scalar): any `uses:` or braces inside it are script text.
    if (RUN_SCALAR_LINE.test(text)) return;
    // The line is not a clean block-style uses: — but does it contain a
    // `uses:` token that looks like a YAML key? If so, flag it fail-closed:
    // the regex cannot confirm the ref is safe, so it must not pass silently.
    // This catches flow style, anchors, multi-entry sequences, and any other
    // form a regex cannot parse. BUT: exclude lines where the `uses:` match is
    // inside a quoted scalar value (e.g. `name: "{uses: foo}"`), where it is
    // string text, not a YAML key. A simple quote-count check: if the match
    // position is between an odd number of quotes, it's inside a string.
    //
    // Residual (Qodo #14, accepted limitation): a `uses:` that is a VALUE-LEVEL
    // key inside a flow mapping for a non-action context — `env: {uses: production}`
    // or `with: {uses: x}` — is also flagged. A regex cannot distinguish that
    // from a real reusable-workflow reference `release: {uses: owner/repo/.github/...}`,
    // which MUST be caught. The fail-closed posture (flag what cannot be
    // positively confirmed) is the documented contract: rewrite value-level
    // `uses:` keys in block style, or rename the env/with key, to clear the flag.
    // Strip a trailing YAML comment BEFORE scanning for suspicious uses. A
    // `# don't use {uses: ...}` trailing comment is comment text, not a key,
    // and the apostrophe inside it would otherwise corrupt the quote-context
    // walker below (Codex #1659). Strip at the first `#` outside a quoted
    // scalar so the walker sees only real YAML tokens. Seeded with
    // lineStartQuoteState (CodeRabbit #6YbIQU) so a `#` that is genuinely
    // CONTENT of a scalar carried open from a previous line is not mistaken
    // for this line's own comment-start.
    const stripped = stripTrailingYamlComment(text, lineStartQuoteState);
    // Iterate EVERY match, not just the first (`.exec` returns only the first).
    // A flow line can contain a quoted `uses:` (matched first, but inside a
    // string so discarded by the quote walker) followed by a real unquoted
    // `uses:` — single-match would miss the real one (CodeRabbit #6X9422).
    for (const suspiciousMatch of stripped.matchAll(SUSPICIOUS_USES)) {
      // Determine whether the match sits inside a quoted YAML scalar. Shares
      // isInsideQuotedScalar with the flow-boundary scanners above instead of
      // re-implementing the walker — the two copies previously drifted (this
      // one lacked the apostrophe-in-plain-scalar fix), which is exactly the
      // kind of divergence a single shared implementation prevents
      // (CodeRabbit #6YSoOn).
      //
      // Check quote context at the START OF THE KEY CANDIDATE (group 1:
      // optional anchor/tag, then optional quote, then `uses`, then optional
      // quote, then colon) — not at suspiciousMatch.index (CodeRabbit PR7
      // #6YYcNX). The `[{[][^}]*` branch starts its OVERALL match at the
      // `{`/`[` boundary, well before the actual key candidate — e.g.
      // `steps: [{name: "text, uses: real@main"}]` matches starting at `[`,
      // which is never inside the later quoted scalar even though the
      // `uses:` text it precedes IS; checking the match start reported a
      // safe, quoted `uses:` as "outside quotes" and rejected valid
      // workflows. Checking at the literal `uses` word instead (skipping an
      // optional LEADING quote) is ALSO wrong: for
      // `{"uses": actions/checkout@main}`, the `"` opening the quoted KEY
      // must be attributed to the key candidate, not swallowed by `[^}]*`'s
      // greedy match — a GREEDY `[^}]*` prefers consuming that quote itself
      // (backtracking finds success sooner that way), which then makes a
      // legitimate quoted `uses` key look "inside a string" and suppresses a
      // real violation. Changed `[^}]*` to LAZY (`[^}]*?`) so it consumes as
      // LITTLE as possible, leaving any immediately-adjacent quote for
      // group 1's own `['"]?` to capture — this also naturally finds the
      // EARLIEST valid `uses:` candidate first, which is what "iterate every
      // match" below relies on. Checking at the key candidate's own start —
      // right where its OWN optional quote would be, if the regex captured
      // one — correctly distinguishes "this whole key: construct is
      // quoted content inside someone else's string" from "this key's own
      // quote marks are the only quoting present".
      const keyCandidateIndex = suspiciousMatch.index + suspiciousMatch[0].length - suspiciousMatch[1].length;
      if (!isInsideQuotedScalar(stripped, keyCandidateIndex, lineStartQuoteState)) {
        violations.push({ line: index + 1, ref: '(uses: in non-block-style or unparseable form — rewrite in clean block style or review manually)' });
        break; // one violation per line is enough
      }
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
const hasTopLevelPermissions = (content) => {
  // Strip a leading UTF-8 BOM so a `permissions:` block at column zero is still
  // detected when the file is saved as UTF-8 with BOM (Codex #1658).
  const text = String(content ?? '').replace(/^\uFEFF/, '');
  return /^(['"]?)permissions\1\s*:(\s|$)/m.test(text);
};

module.exports = { findUnpinnedUses, hasTopLevelPermissions };
