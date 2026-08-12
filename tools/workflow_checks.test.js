'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const test = require('node:test');

const { findUnpinnedUses, hasTopLevelPermissions } = require('./workflow_checks');

test('findUnpinnedUses flags tags, branches, and docker refs but not 40-hex pins or local paths', () => {
  const pinned = 'steps:\n  - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3\n';
  assert.deepEqual(findUnpinnedUses(pinned), []);
  const quoted = "  - uses: 'actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10'\n";
  assert.deepEqual(findUnpinnedUses(quoted), []);
  const local = '  - uses: ./actions/closeout\n';
  assert.deepEqual(findUnpinnedUses(local), []);

  const tag = '  - uses: actions/checkout@v6\n';
  assert.equal(findUnpinnedUses(tag).length, 1);
  assert.equal(findUnpinnedUses(tag)[0].ref, 'actions/checkout@v6');
  const branch = '  - uses: someone/thing@main\n';
  assert.equal(findUnpinnedUses(branch).length, 1);
  const short = '  - uses: actions/checkout@df4cb1c\n';
  assert.equal(findUnpinnedUses(short).length, 1);
  // Docker refs are flagged fail-closed: pin-by-digest is out of scope, and
  // an unpinned image is exactly what this check exists to catch.
  const docker = '  - uses: docker://alpine:3.20\n';
  assert.equal(findUnpinnedUses(docker).length, 1);
  // Line numbers are 1-indexed for actionable failure messages.
  const multi = 'a: 1\n  - uses: x/y@v1\n';
  assert.equal(findUnpinnedUses(multi)[0].line, 2);
});

test('findUnpinnedUses catches quoted-key and whitespace-variant uses forms', () => {
  // The YAML spec allows the key to be quoted and whitespace around the colon.
  const variants = [
    '  - "uses": actions/checkout@v6\n',
    "  - 'uses': someone/thing@main\n",
    '  - "uses": "actions/checkout@v6"\n',
    '  - uses : actions/checkout@v6\n',
    '  - uses  :  someone/thing@main\n',
  ];
  for (const variant of variants) {
    const violations = findUnpinnedUses(variant);
    assert.equal(violations.length, 1, `expected one violation for: ${variant.trim()}`);
  }
  // Pinned refs in these forms still pass.
  assert.deepEqual(
    findUnpinnedUses('  - "uses": actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n'),
    [],
  );
  assert.deepEqual(
    findUnpinnedUses('  - uses : actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n'),
    [],
  );
});

test('findUnpinnedUses conservatively flags every non-block-style uses (fail-closed)', () => {
  // The check is conservatively fail-closed: any uses: token it cannot
  // positively confirm as a clean block-style pinned/local ref is flagged.
  // This catches flow style, anchors, multi-entry sequences, and any other
  // form a regex cannot fully parse — pinning a 40-hex SHA inside these
  // forms does NOT make them pass, because the validator refuses to trust a
  // ref it cannot reliably extract.
  const suspiciousForms = [
    '  - {uses: actions/checkout@v6}\n',                                    // flow seq item
    '  - {uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10}\n', // flow, pinned — still flagged
    '  - {"uses": actions/checkout@v6}\n',                                  // quoted flow key
    "  - {'uses': someone/thing@main}\n",                                   // single-quote flow key
    'release: {uses: octo-org/repo/.github/workflows/release.yml@main}\n',  // map-value flow
    'steps: [{uses: owner/action@main}]\n',                                 // flow sequence
    'steps: [{name: setup}, {uses: owner/action@main}]\n',                  // multi-entry flow seq
    '  - uses: &checkout actions/checkout@v6\n',                            // YAML anchor
    'key: "x # y"; {uses: owner/action@main}\n',                            // hash-in-quote then flow
  ];
  for (const form of suspiciousForms) {
    const violations = findUnpinnedUses(form);
    assert.equal(violations.length, 1, `expected one violation for: ${form.trim()}`);
    assert.match(violations[0].ref, /non-block-style|unparseable/i);
  }
  // Mixed document: block-style pinned line passes, suspicious line flags.
  const mixed = 'steps:\n  - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n  - {uses: someone/thing@main}\n';
  const mixedViolations = findUnpinnedUses(mixed);
  assert.equal(mixedViolations.length, 1);
  assert.equal(mixedViolations[0].line, 3);
});

test('findUnpinnedUses does not false-positive on uses in run strings or comments', () => {
  // A run:/entrypoint:/shell: line's value is a string scalar; uses: or
  // {uses:} inside it is script text, not a YAML key. Comment lines too.
  const safeTexts = [
    'run: echo "{uses: foo@bar}"\n',
    'run: echo uses: something\n',
    '# this {uses: something} is a comment\n',
    'entrypoint: /bin/sh -c "uses: noop"\n',
  ];
  for (const text of safeTexts) {
    assert.deepEqual(findUnpinnedUses(text), [],
      `expected no violation for non-YAML-key text: ${text.trim()}`);
  }
});

test('findUnpinnedUses skips block-scalar bodies (run: | and shell: >)', () => {
  // A block scalar (run: |, shell: >) continues on subsequent more-indented
  // lines as raw string content — {uses:...} in the body is script text, not a
  // YAML key. The scanner must track the scalar's indentation and skip body
  // lines until indentation drops back.
  // Body lines are indented DEEPER than the header's key column (6, vs. the
  // "- run:" key at column 4) — a body at the SAME column as the key is an
  // EMPTY scalar whose next line is a sibling key, not body (YAML semantics;
  // see "flags a sibling uses key after an empty block scalar" below), so
  // these fixtures must genuinely out-indent the key to exercise body-skip.
  const blockLiteral = 'steps:\n  - run: |\n      echo "{uses: foo@bar}"\n      echo done\n  - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n';
  assert.deepEqual(findUnpinnedUses(blockLiteral), [],
    'block-literal body with {uses:...} must not false-positive');
  const foldedScalar = '  shell: >-\n    printf "{uses: foo@bar}"\n  - uses: ./local\n';
  assert.deepEqual(findUnpinnedUses(foldedScalar), [],
    'folded-scalar body with {uses:...} must not false-positive');
  // After the scalar ends (indentation drops), scanning resumes normally.
  const resume = '  - run: |\n      echo "{uses: x}"\n  - uses: someone/thing@main\n';
  const v = findUnpinnedUses(resume);
  assert.equal(v.length, 1, 'a real uses: after the scalar body IS caught');
  assert.equal(v[0].line, 3);
});

test('findUnpinnedUses handles block-scalar header variants (comment, indent indicator)', () => {
  // YAML allows a comment after the scalar indicator (run: | # cmt) and an
  // explicit indentation indicator (run: |2). Both must open a scalar whose
  // body is skipped — otherwise the body's {uses:...} false-positives. Body
  // lines are indented deeper than the key column for the same reason as
  // above (same-column is an empty scalar, not body).
  const withComment = '  - run: | # build\n      echo "{uses: foo@bar}"\n';
  assert.deepEqual(findUnpinnedUses(withComment), [],
    'scalar header with trailing comment must skip body');
  // |2 means "body indented 2 past the key column" (4 + 2 = column 6).
  const withIndent = '  - run: |2\n      echo "{uses: foo@bar}"\n';
  assert.deepEqual(findUnpinnedUses(withIndent), [],
    'scalar header with indent indicator must skip body');
  const withIndentChomp = '  - run: |2-\n      echo "{uses: foo@bar}"\n';
  assert.deepEqual(findUnpinnedUses(withIndentChomp), [],
    'scalar header with indent+chomp indicator must skip body');
  // YAML allows an anchor on the scalar value (key: &name |).
  const withAnchor = 'name: &message |\n  hello {uses: world}\n';
  assert.deepEqual(findUnpinnedUses(withAnchor), [],
    'scalar header with anchor indicator must skip body');
});

test('findUnpinnedUses flags a sibling uses key after an empty block scalar', () => {
  // A block-scalar header (`name: |`) immediately followed by an equally or
  // less indented non-blank line is an EMPTY scalar in YAML: the header key
  // parses to an empty string and the following line is a SIBLING key, not
  // body content. A sibling `uses:` is a real action reference and must be
  // scanned — the pending-state must not swallow it as scalar body.
  const seqSibling = 'steps:\n  - name: |\n    uses: owner/action@main\n';
  const seqV = findUnpinnedUses(seqSibling);
  assert.equal(seqV.length, 1, 'sibling uses after an empty |-scalar must be flagged');
  assert.equal(seqV[0].line, 3);
  const foldedSibling = 'steps:\n  - name: >\n    uses: owner/action@main\n';
  const foldedV = findUnpinnedUses(foldedSibling);
  assert.equal(foldedV.length, 1, 'sibling uses after an empty >-scalar must be flagged');
  assert.equal(foldedV[0].line, 3);
  const mapSibling = 'name: |\nuses: owner/action@main\n';
  const mapV = findUnpinnedUses(mapSibling);
  assert.equal(mapV.length, 1, 'sibling uses at a shallower indent must be flagged');
  assert.equal(mapV[0].line, 2);
  // A genuine scalar body (more indented than the header key) is still body:
  // `uses:` text inside it must NOT be flagged.
  const realBody = 'name: |\n  echo uses: not-a-key\n';
  assert.deepEqual(findUnpinnedUses(realBody), [],
    'a deeper-indented line is real scalar body and must not be flagged');
});

test('findUnpinnedUses flags sibling uses after a multi-space sequence dash', () => {
  // YAML permits any amount of whitespace after the sequence `-` marker
  // (`-  name:` or `-   name:`), so the effective mapping-key column is the
  // END of the actual dash prefix, not a constant indent+2. An empty block
  // scalar header with a multi-space dash must still treat an equally-indented
  // following line as a sibling key, not scalar body — otherwise an unpinned
  // sibling `uses:` evades the fail-closed scan.
  const twoSpace = 'steps:\n  -  name: |\n     uses: owner/action@main\n';
  const twoSpaceV = findUnpinnedUses(twoSpace);
  assert.equal(twoSpaceV.length, 1, 'sibling uses after a 2-space-dash empty scalar must be flagged');
  assert.equal(twoSpaceV[0].line, 3);
  const threeSpace = 'steps:\n  -   name: |\n      uses: owner/action@main\n';
  const threeSpaceV = findUnpinnedUses(threeSpace);
  assert.equal(threeSpaceV.length, 1, 'sibling uses after a 3-space-dash empty scalar must be flagged');
  assert.equal(threeSpaceV[0].line, 3);
  // A genuine deeper body line (past the true key column) is still scalar body.
  const realBody = 'steps:\n  -  name: |\n        echo uses: not-a-key\n';
  assert.deepEqual(findUnpinnedUses(realBody), [],
    'a deeper-indented line is real scalar body and must not be flagged');
});

test('findUnpinnedUses does not false-positive on a valid deeper block-scalar body (Qodo #10)', () => {
  // The empty-scalar sibling detection compares the first body line's column
  // against the header's KEY column (the END of any dash prefix), measured in
  // the same units as the line's leading-whitespace indent. A genuine scalar
  // body is strictly more indented than the key column, so it is correctly
  // treated as body content — even when the body text contains a token that
  // SUSPICIOUS_USES would otherwise flag. The body token `{uses: owner/action@main}`
  // is chosen deliberately: it matches SUSPICIOUS_USES in isolation, so this
  // test proves scalar-body tracking actively suppresses it (a `uses:`-like
  // script fragment would be a false positive without tracking).
  // (A line at the key column itself is an empty scalar + sibling key, which
  // IS scanned — see the sibling-uses tests above.)
  assert.deepEqual(findUnpinnedUses('steps:\n  - run: |\n      {uses: owner/action@main}\n'), [],
    'a deeper-indented body line matching SUSPICIOUS_USES is script text, not a key');
  assert.deepEqual(findUnpinnedUses('  -  run: |\n        {uses: owner/action@main}\n'), [],
    'a deeper-indented body under a multi-space dash is script text');
  assert.deepEqual(findUnpinnedUses('jobs:\n  b:\n    steps:\n      - run: |\n          echo "uses: x"\n'), [],
    'a realistic nested run block-scalar body is not flagged');
});

test('findUnpinnedUses exempts a uses token inside a quoted scalar value (Qodo #14)', () => {
  // A `{uses: ...}` or `uses:` appearing inside a quoted scalar value is
  // string text, not a YAML key, and must not be flagged. This is the quoted-
  // scalar case the finding names; an unquoted value-level flow `uses:`
  // (e.g. `env: {uses: production}`) is a documented accepted limitation of
  // the conservative fail-closed regex design — see the inline note in
  // workflow_checks.js.
  assert.deepEqual(findUnpinnedUses('name: "{uses: foo@bar}"\n'), [],
    'a {uses:...} inside a double-quoted value is string text');
  assert.deepEqual(findUnpinnedUses('description: "uses: foo@bar inline"\n'), [],
    'a uses: inside a double-quoted value is string text');
  // Real flow-style action references are still caught.
  assert.equal(findUnpinnedUses('  - {uses: owner/action@main}\n').length, 1,
    'a flow-style action uses: is still flagged');
});

test('findUnpinnedUses flags a tagged/anchored uses key that YAML resolves to a property (Codex P2, CodeRabbit)', () => {
  // A YAML tag or anchor applied to the key — `- !!str uses:` / `- &step uses:`
  // / `- &step !!str uses:` / `- !!str &step uses:` — parses (verified with
  // js-yaml) to an ordinary unpinned `{uses: "owner/action@main"}` mapping.
  // Neither USES_LINE (blocked by the `!!str `/`&step ` prefix) nor the old
  // SUSPICIOUS_USES (no tag/anchor allowance) saw these, so an unpinned remote
  // action could bypass the pinning check. The scanner now treats any tag
  // (`!!str`, `!`, `!<...>`) or anchor (`&name`) indicator before the key, in
  // either order and combination, as fail-closed suspicious: it cannot confirm
  // the ref is safe, so it flags for manual review rather than silently passing.
  const flagged = (ref) => findUnpinnedUses(ref).length === 1;
  // Tag-only forms.
  assert.equal(flagged('steps:\n  - !!str uses: owner/action@main\n'), true,
    '!!str uses: resolves to a real unpinned uses and must be flagged');
  assert.equal(flagged('steps:\n  - ! uses: owner/action@main\n'), true,
    'a bare non-specific tag ! on uses: must be flagged');
  assert.equal(flagged('steps:\n  - !<tag:yaml.org,2002:str> uses: owner/action@main\n'), true,
    'an angle-bracket tag on uses: must be flagged');
  assert.equal(flagged('steps:\n  - !!str "uses": owner/action@main\n'), true,
    'a tag on a quoted uses: key must be flagged');
  // Anchor-before-key forms (CodeRabbit): the anchor alone, or combined with
  // a tag in either order, all resolve to {uses: ...} via js-yaml.
  assert.equal(flagged('steps:\n  - &step uses: owner/action@main\n'), true,
    '&step uses: (anchor on the key) resolves to a real unpinned uses and must be flagged');
  assert.equal(flagged('steps:\n  - &step !!str uses: owner/action@main\n'), true,
    '&step !!str uses: (anchor then tag) must be flagged');
  assert.equal(flagged('steps:\n  - !!str &step uses: owner/action@main\n'), true,
    '!!str &step uses: (tag then anchor) must be flagged');
  // A tag/anchor is vanishingly rare on real workflow keys, but a clean
  // PINNED uses: (the overwhelmingly common form) must never regress.
  assert.deepEqual(findUnpinnedUses('steps:\n  - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n'), [],
    'a clean pinned uses: is unaffected by the tag/anchor handling');
});

test('findUnpinnedUses flags an escape-obfuscated quoted uses key (Codex #14)', () => {
  // A YAML double-quoted key spelled with a unicode escape that resolves to
  // `uses` — `- "u\u0073es": owner/action@main` — parses (verified with
  // js-yaml) to an ordinary unpinned `{uses: "owner/action@main"}`. Neither
  // USES_LINE nor SUSPICIOUS_USES match the literal `uses` token (the key is
  // `u\u0073es`), so the bypass slips through. The scanner now decodes
  // \uXXXX/\UXXXXXXXX/\xXX escapes in a double-quoted key and flags it
  // fail-closed when the decoded value is `uses`. (Single-quoted keys are
  // excluded: YAML single-quoted scalars have no escape processing, so an
  // escape there stays literal and cannot spell `uses` obliquely.)
  assert.equal(findUnpinnedUses('steps:\n  - "u\\u0073es": owner/action@main\n').length, 1,
    '"u\\u0073es": resolves to a uses: key and must be flagged');
  assert.equal(findUnpinnedUses('steps:\n  - "\\x75ses": owner/action@main\n').length, 1,
    'a \\xXX hex escape spelling uses must be flagged');
  assert.equal(findUnpinnedUses('"\\u0075\\u0073\\u0065\\u0073": owner/action@main\n').length, 1,
    'a fully-escaped uses key must be flagged');
  // A plain quoted uses: is already caught by USES_LINE (no regression); a
  // quoted key that does NOT resolve to uses must not be flagged here.
  assert.equal(findUnpinnedUses('steps:\n  - "user": not-uses\n').length, 0,
    'a quoted key that does not resolve to uses is not flagged');
  assert.equal(findUnpinnedUses("steps:\n  - 'u\\u0073es': owner/action@main\n").length, 0,
    'single-quoted escapes are literal in YAML and must not be flagged');
  // The flow-mapping variant: an escape-obfuscated quoted uses key INSIDE a
  // flow mapping/sequence — `steps: [{"u\u0073es": ref}]` (js-yaml verified to
  // resolve to {uses: ...}). QUOTED_USES_KEY is anchored to a block line start
  // and misses this; the FLOW_QUOTED_USES_KEY variant decodes at the flow
  // boundary and flags it fail-closed.
  assert.equal(findUnpinnedUses('steps: [{"u\\u0073es": owner/action@main}]\n').length, 1,
    'an escape-obfuscated quoted uses: inside a flow mapping must be flagged');
  assert.equal(findUnpinnedUses('jobs: [{name: a}, {"u\\u0073es": owner/action@main}]\n').length, 1,
    'an escape-obfuscated uses: after a comma in a flow sequence must be flagged');
  // A non-resolving quoted key in flow context must not be flagged here.
  assert.equal(findUnpinnedUses('steps: [{"user": not-uses}]\n').length, 0,
    'a flow-mapping quoted key that does not resolve to uses is not flagged');
  // A SECOND quoted key in the same flow mapping after another key
  // (CodeRabbit 3745322365): `[{"name": setup, "u\u0073es": ref}]` — the
  // escape key is not the first quoted key, so a single .exec missed it.
  // The scanner now iterates every flow quoted key.
  assert.equal(findUnpinnedUses('steps: [{"name": setup, "u\\u0073es": owner/action@main}]\n').length, 1,
    'an escape-obfuscated uses: that is the second quoted key in a flow mapping must be flagged');
});

test('findUnpinnedUses flags an explicit ? uses mapping key (Codex #20)', () => {
  // YAML's explicit mapping-key form — `- ? uses` followed by `: ref` on the
  // next line — parses (verified with js-yaml) to `{uses: "owner/action@main"}`.
  // The line-oriented scanner cannot re-associate the value line, but the
  // `? uses` marker alone proves a `uses` key exists whose ref this regex
  // cannot pin-check, so it is flagged fail-closed.
  assert.equal(findUnpinnedUses('steps:\n  - ? uses\n    : owner/action@main\n').length, 1,
    'an explicit ? uses mapping key must be flagged');
  assert.equal(findUnpinnedUses('jobs:\n  b:\n    steps:\n      ? uses\n      : owner/action@main\n').length, 1,
    'an explicit ? uses key without a dash must be flagged');
  assert.equal(findUnpinnedUses('steps:\n  - ? "uses"\n    : owner/action@main\n').length, 1,
    'an explicit ? "uses" quoted key must be flagged');
  // The escape-obfuscated variant: `- ? "u\u0073es"` (js-yaml verified to
  // resolve to {uses: ...}). EXPLICIT_USES_KEY matches only the literal
  // spelling; the decode check catches the escape form fail-closed.
  assert.equal(findUnpinnedUses('steps:\n  - ? "u\\u0073es"\n    : owner/action@main\n').length, 1,
    'an escape-obfuscated explicit ? "u\\u0073es" key must be flagged');
  // A `? name` explicit key for a NON-uses property must not be flagged.
  assert.equal(findUnpinnedUses('steps:\n  - ? name\n    : build\n').length, 0,
    'an explicit ? key for a non-uses property is not flagged');
  // An alias-backed explicit key (Codex 3745332784): `name: &action_key uses`
  // then `- ? *action_key` resolves (js-yaml verified) to {uses: ...}. The
  // scanner cannot resolve aliases, so any alias in explicit-key position is
  // flagged fail-closed.
  const aliasExplicit = findUnpinnedUses('name: &action_key uses\nsteps:\n  - ? *action_key\n    : owner/action@main\n');
  assert.equal(aliasExplicit.length, 1,
    'an alias-backed explicit ? *alias key must be flagged (alias may resolve to uses)');
  assert.equal(aliasExplicit[0].line, 3,
    'the violation reports the alias explicit-key line');
  assert.match(aliasExplicit[0].ref, /\(explicit \? \*alias mapping key/,
    'the violation reports the alias explicit-key reason');
  // A trailing YAML comment must not defeat detection (Qodo 3745372289): all
  // three explicit-key regexes allow an optional `# comment` after the key.
  assert.equal(findUnpinnedUses('steps:\n  - ? uses # comment\n    : owner/action@main\n').length, 1,
    'an explicit ? uses key with a trailing comment must be flagged');
  assert.equal(findUnpinnedUses('name: &k uses\nsteps:\n  - ? *k # comment\n    : owner/action@main\n').length, 1,
    'an alias explicit key with a trailing comment must be flagged');
  // An alias as an IMPLICIT block-style mapping key (Codex 3745389802):
  // `name: &action_key uses` then `- *action_key : ref` resolves (js-yaml
  // verified) to {uses: ref}. The scanner cannot resolve aliases, so any alias
  // in implicit-key position is flagged fail-closed. An alias that is a VALUE
  // (`key: *alias`) must NOT be flagged.
  const aliasImplicit = findUnpinnedUses('name: &action_key uses\nsteps:\n  - *action_key : owner/action@main\n');
  assert.equal(aliasImplicit.length, 1,
    'an alias used as an implicit mapping key must be flagged');
  assert.equal(aliasImplicit[0].line, 3,
    'the violation reports the alias implicit-key line');
  assert.match(aliasImplicit[0].ref, /\(\*alias: implicit mapping key/,
    'the violation reports the alias implicit-key reason');
  assert.equal(findUnpinnedUses('env:\n  url: *checkout\n').length, 0,
    'an alias used as a value for a non-uses key is not flagged here');
});

test('findUnpinnedUses flags a tag or anchor placed AFTER the explicit-key ? marker (chatgpt-codex-connector PR7 #6Yb1dJ)', () => {
  // A tag or anchor attaches to the key NODE itself and can legally sit on
  // either side of `?` -- js-yaml verified: `- ? !!str uses` and
  // `- ? &anchorx uses` both resolve the key to the literal string "uses"
  // (the tag/anchor is metadata, not part of the value), same as the
  // already-covered before-`?` form. Only allowing it before `?` let either
  // after-`?` form bypass pin enforcement entirely.
  assert.equal(findUnpinnedUses('steps:\n  - ? !!str uses\n    : owner/action@main\n').length, 1,
    'a tag placed after the ? marker must still be flagged');
  assert.equal(findUnpinnedUses('steps:\n  - ? &anchorx uses\n    : owner/action@main\n').length, 1,
    'an anchor placed after the ? marker must still be flagged');
  // The quoted, escape-obfuscated variant with a tag after ?: js-yaml
  // verified `- ? !!str "uses"` also resolves to {uses: ...}.
  assert.equal(findUnpinnedUses('steps:\n  - ? !!str "u\\u0073es"\n    : owner/action@main\n').length, 1,
    'a quoted, escape-obfuscated key with a tag after the ? marker must still be flagged');
  // The block-scalar explicit-key form with a tag after ?: js-yaml verified
  // `? !!str |` is valid and still opens a block-scalar key body.
  assert.equal(findUnpinnedUses('steps:\n  - ? !!str |\n      uses\n    : owner/action@main\n').length, 1,
    'a block-scalar explicit key with a tag after the ? marker must still be flagged');
  // Sanity: a tag after ? for a genuinely non-uses key must not be flagged.
  assert.equal(findUnpinnedUses('steps:\n  - ? !!str name\n    : build\n').length, 0,
    'a tag after the ? marker for a non-uses property is not flagged');
});
// Regression coverage for inline-value, flow, and continued-key explicit
// bypasses (CodeRabbit PR7 threads 6X7tKr / 6X72Zm / 6X942y / 6X9422 / 6XsD7p).
test('findUnpinnedUses flags inline-value explicit-key uses forms (CodeRabbit #6X7tKr)', () => {
  const inlineLiteral = findUnpinnedUses('steps:\n  - ? uses : owner/action@main\n');
  assert.equal(inlineLiteral.length, 1);
  assert.equal(inlineLiteral[0].line, 2);
  assert.match(inlineLiteral[0].ref, /\(explicit \? uses mapping key/);
  const inlineQuoted = findUnpinnedUses('steps:\n  - ? "uses" : owner/action@main\n');
  assert.equal(inlineQuoted.length, 1);
  assert.equal(inlineQuoted[0].line, 2);
  assert.match(inlineQuoted[0].ref, /\(explicit \? uses mapping key/);
  const inlineAlias = findUnpinnedUses('name: &k uses\nsteps:\n  - ? *k : owner/action@main\n');
  assert.equal(inlineAlias.length, 1);
  assert.equal(inlineAlias[0].line, 3);
  assert.match(inlineAlias[0].ref, /\(explicit \? \*alias mapping key/);
});
test('findUnpinnedUses flags flow-mapping escape-obfuscated uses keys with explicit-key marker (CodeRabbit #6X72Zm)', () => {
  const r = findUnpinnedUses('steps: [{? "u\\u0073es": owner/action@main}]\n');
  assert.equal(r.length, 1);
  assert.equal(r[0].line, 1);
  assert.match(r[0].ref, /quoted uses: key resolves to uses via escape sequences/);
});
test('findUnpinnedUses flags alias keys inside flow mappings (CodeRabbit #6X942y)', () => {
  const r = findUnpinnedUses('name: &action_key uses\nsteps: [{*action_key: owner/action@main}]\n');
  assert.equal(r.length, 1);
  assert.equal(r[0].line, 2);
  assert.match(r[0].ref, /\(\*alias: flow mapping key/);
});
test('findUnpinnedUses scans every suspicious uses token on a flow line (CodeRabbit #6X9422)', () => {
  // Companion negative assertion (CodeRabbit #6YEr9k): the quoted token alone
  // yields NO violation. Without this, the test would pass even if the quote
  // walker were broken and reported the quoted token instead of the real one.
  assert.equal(findUnpinnedUses('steps: [{with: {x: ok}, name: "foo, uses: fake"}]\n').length, 0,
    'a uses: token inside a quoted flow value alone is not flagged');
  const r = findUnpinnedUses('steps: [{with: {x: ok}, name: "foo, uses: fake", uses: owner/action@main}]\n');
  assert.equal(r.length, 1);
  assert.equal(r[0].line, 1);
  assert.match(r[0].ref, /uses: in non-block-style or unparseable form/);
});
test('findUnpinnedUses checks quote context at the key candidate, not the match start or the bare uses word (CodeRabbit #6YYcNX)', () => {
  // The `[{[][^}]*?` branch of SUSPICIOUS_USES starts its OVERALL match at
  // the `{`/`[` boundary, well before the actual uses: text. Checking quote
  // context at that early match-start position (rather than at the key
  // candidate itself) reported this SAFE workflow — no real `uses:` key,
  // js-yaml verified: only a `name` key whose value happens to contain the
  // text "uses:" — as a violation.
  assert.deepEqual(findUnpinnedUses('steps: [{name: "documentation, uses: owner/action@main"}]\n'), [],
    'uses: text entirely inside an unrelated quoted value must not be flagged');
  // Sanity: a real unpinned uses: key still gets flagged when quoted content
  // precedes it on the same flow line.
  assert.equal(findUnpinnedUses('steps: [{name: "documentation", uses: owner/action@main}]\n').length, 1,
    'a real uses: key after quoted content is still flagged');
  // The opposite mistake — checking at the bare `uses` word, skipping an
  // optional LEADING quote the regex itself should attribute to the key
  // candidate — is equally wrong: a quoted `uses` KEY (not a `uses:` token
  // buried inside someone else's string) must still be flagged. Proves the
  // fix doesn't just move the false negative from one shape to another.
  assert.equal(findUnpinnedUses('- {"uses": actions/checkout@v6}\n').length, 1,
    'a quoted uses key must still be flagged, not misread as "inside a string"');
});
test('findUnpinnedUses flags explicit alias keys in flow mappings (CodeRabbit #6YEoRA)', () => {
  // `name: &action_key uses` then `steps: [{? *action_key: ref}]` resolves
  // (Ruby Psych) to {uses: ref}. FLOW_ALIAS_KEY now permits the `?`
  // explicit-key marker inside flow context, mirroring FLOW_QUOTED_USES_KEY.
  const r = findUnpinnedUses('name: &action_key uses\nsteps: [{? *action_key: owner/action@main}]\n');
  assert.equal(r.length, 1);
  assert.equal(r[0].line, 2);
  assert.match(r[0].ref, /\(\*alias: flow mapping key/);
});
test('findUnpinnedUses suppresses flow-key matches inside quoted scalars (CodeRabbit #6YEr9a)', () => {
  // An alias-shaped or quoted-uses-shaped token inside a quoted scalar value
  // is string content, not a YAML key. The quote-context walker is now applied
  // to FLOW_QUOTED_USES_KEY and FLOW_ALIAS_KEY matches, so neither false-positives.
  assert.equal(findUnpinnedUses('steps: [{name: "a, *k: b"}]\n').length, 0,
    'an alias-shaped token inside a quoted value is not flagged');
  assert.equal(findUnpinnedUses('steps: [{name: "x, {\\"u\\\\u0073es\\": y}"}]\n').length, 0,
    'a quoted-uses-shaped token inside a quoted value is not flagged');
});
test('findUnpinnedUses fails closed on continuation cap overflow (CodeRabbit #6YEr9d)', () => {
  // A `? "u\\<NL>...ses"` key spread over more than 16 continuation lines
  // cannot be parsed (the partial line ends inside an unterminated quote).
  // The cap records the overflow and reports it as a violation rather than
  // letting the unpinned-action bypass pass silently.
  const overflow = '- ? "u\\\n' + Array(18).fill('  more\\').join('\n') + '\n  ses"\n  : owner/action@main\n';
  const r = findUnpinnedUses(overflow);
  assert.equal(r.length, 1);
  assert.equal(r[0].line, 1);
  assert.match(r[0].ref, /exceeded the 16-line continuation cap/);
});
test('findUnpinnedUses rejects continued quoted explicit uses keys (CodeRabbit #6XsD7p)', () => {
  const r = findUnpinnedUses('- ? "u\\\n  ses"\n  : owner/action@main\n');
  assert.equal(r.length, 1);
  assert.equal(r[0].line, 1);
  assert.match(r[0].ref, /\(explicit \? uses mapping key/);
});
test('findUnpinnedUses does not let a plain-scalar apostrophe hide a later flow key (CodeRabbit #6YSoOn)', () => {
  // A bare apostrophe in an UNQUOTED plain scalar (`don't`) is ordinary scalar
  // content, not a quote delimiter — YAML plain scalars may contain `'`
  // anywhere except as the first character. The quote-context walker
  // previously treated every `'` as toggling single-quote state, so this
  // apostrophe opened a phantom quoted string that swallowed the real,
  // escape-obfuscated flow uses key that followed, suppressing the violation
  // (a fail-OPEN bypass). Both the escape-obfuscated-quoted-key and
  // alias-key scanners share the fix (isInsideQuotedScalar).
  const escaped = findUnpinnedUses('steps: [{name: don\'t, "u\\u0073es": owner/action@main}]\n');
  assert.equal(escaped.length, 1, 'an apostrophe before an escaped flow key must not hide it');
  assert.match(escaped[0].ref, /quoted uses: key resolves to uses/);
  const alias = findUnpinnedUses('steps: [{name: don\'t, *action_key: owner/action@main}]\n');
  assert.equal(alias.length, 1, 'an apostrophe before an alias flow key must not hide it');
  assert.match(alias[0].ref, /\(\*alias: flow mapping key/);
  // The literal-uses SUSPICIOUS_USES scanner (previously a duplicated, now
  // shared, walker) has the identical failure mode: confirm it too.
  const literal = findUnpinnedUses('steps: [{name: don\'t, uses: owner/action@main}]\n');
  assert.equal(literal.length, 1, 'an apostrophe before a literal uses: key must not hide it');
  // A real single-quoted scalar must still suppress a uses-shaped token
  // inside it — the fix must not turn every apostrophe into a non-quote.
  assert.equal(findUnpinnedUses("name: 'a {uses: fake}'\n").length, 0,
    'a uses-shaped token inside a real single-quoted scalar is still suppressed');
});
test('findUnpinnedUses does not let a plain-scalar double-quote hide a later flow key (CodeRabbit #6YW1O6)', () => {
  // The #6YSoOn fix gated ONLY the single-quote branch on "did this quote
  // char immediately follow a real quote-open context (line start, :, -, {,
  // [, ,, ?)". The double-quote branch still opened unconditionally on any
  // `"`, so a plain scalar containing a bare double quote (`a"b`, valid
  // unquoted YAML — `"` is not special mid-scalar) had the identical
  // fail-OPEN failure mode: it opened a phantom quoted string that swallowed
  // a real, later flow uses key. Both quote types now share the same gate.
  const literal = findUnpinnedUses('steps: [{name: a"b, uses: owner/action@main}]\n');
  assert.equal(literal.length, 1, 'a plain-scalar double-quote before a literal uses: key must not hide it');
  const escaped = findUnpinnedUses('steps: [{name: a"b, "u\\u0073es": owner/action@main}]\n');
  assert.equal(escaped.length, 1, 'a plain-scalar double-quote before an escaped flow key must not hide it');
  assert.match(escaped[0].ref, /quoted uses: key resolves to uses/);
  const alias = findUnpinnedUses('steps: [{name: 5" nail, *action_key: owner/action@main}]\n');
  assert.equal(alias.length, 1, 'a plain-scalar double-quote before an alias flow key must not hide it');
  assert.match(alias[0].ref, /\(\*alias: flow mapping key/);
  // A real double-quoted scalar must still suppress a real uses: that follows
  // it on the same line — the fix must not turn every `"` into a non-quote.
  const realQuoted = findUnpinnedUses('steps: [{name: "a b", uses: owner/action@main}]\n');
  assert.equal(realQuoted.length, 1, 'the real uses: after a properly double-quoted name is still flagged (not suppressed twice-over)');
});
test('findUnpinnedUses does not let a plain-scalar question mark extend quote-open context (Qodo #1)', () => {
  // `?` only belongs in the quote-open context when it is ITSELF validly
  // positioned (immediately after start-of-line, :, -, {, [, or ,) — e.g. the
  // explicit-key marker in `{? "uses": ref}`. A bare `?` as ordinary
  // plain-scalar content (`ok? "x` — preceded by `k`, not a boundary) must
  // NOT re-open quote context for what follows: doing so would misclassify
  // the flow boundary before a later real `uses:` key as "inside a string",
  // suppressing the violation (fail-OPEN bypass).
  const bypassAttempt = findUnpinnedUses('steps: [{name: ok? "x", uses: owner/action@main}]\n');
  assert.equal(bypassAttempt.length, 1, 'a plain-scalar ? must not extend quote-open context to a later real uses: key');
  // Sanity: a genuinely valid explicit-key ? (right after a flow boundary)
  // must still open context for the quote it introduces.
  const legitExplicitKey = findUnpinnedUses('steps: [{? "u\\u0073es": owner/action@main}]\n');
  assert.equal(legitExplicitKey.length, 1, 'a validly-positioned explicit-key ? still opens context for its quote');
  assert.match(legitExplicitKey[0].ref, /quoted uses: key resolves to uses/);
});
test('findUnpinnedUses does not let a plain-scalar hyphen extend quote-open context (CodeRabbit #6YXkRo)', () => {
  // Same transitivity requirement as `?` above, for `-`: a hyphen only
  // belongs in quote-open context when it is ITSELF validly positioned (a
  // genuine sequence-entry dash, `- 'value'`). `name: abc-'def` (js-yaml
  // verified: a valid plain scalar equal to the literal string "abc-'def")
  // has the hyphen mid-word, preceded by `c` — it must not re-open context
  // for the apostrophe after it, or the walker misclassifies the flow
  // boundary before a later real `uses:` key as "inside a string".
  const bypassAttempt = findUnpinnedUses("steps: [{name: abc-'def, with: {}, uses: owner/action@main}]\n");
  assert.equal(bypassAttempt.length, 1, 'a plain-scalar hyphen must not extend quote-open context to a later real uses: key');
  // Sanity: a genuine sequence-entry dash at line start still opens context
  // for the quote that follows it — proven by a fixture whose result
  // actually DEPENDS on that (CodeRabbit #6YXkRy): if the dash failed to
  // open context, the quote would never open and the uses: text inside it
  // would be scanned as real YAML and flagged; only a correctly-opened
  // quoted scalar suppresses it.
  assert.deepEqual(findUnpinnedUses("- 'name, uses: owner/action@main'\n"), [],
    'a genuine sequence dash opens context, so the quoted scalar suppresses its uses: text');
});
test('findUnpinnedUses does not let a content-only colon extend quote-open context (CodeRabbit/Qodo colon bypass)', () => {
  // `:` was a flat QUOTE_OPEN_CONTEXT member, granting quote-open context
  // after ANY colon regardless of what followed it. YAML only treats `:` as
  // a real key/value separator when it is followed by whitespace or EOL;
  // `a:"b` (js-yaml verified: a valid plain scalar equal to the literal
  // string 'a:"b') has a colon immediately followed by `"` — ordinary
  // content, not a boundary. That content-only colon must not grant quote-
  // open context to the `"` right after it, or the walker misclassifies the
  // flow boundary before a later real `uses:` key as "inside a string".
  const bypassAttempt = findUnpinnedUses('steps: [{name: a:"b, uses: owner/action@main}]\n');
  assert.equal(bypassAttempt.length, 1, 'a content-only colon must not extend quote-open context to a later real uses: key');
  // Sanity: a genuine key-separator colon (followed by whitespace) still
  // opens context for the quote it introduces — proven by a fixture whose
  // result DEPENDS on that: if the separator colon failed to grant context,
  // the quote around "a, uses: fake" would never open and that fake inner
  // uses: text would ALSO be scanned as real YAML.
  //
  // The combined fixture alone can't prove that: the real `uses:` key
  // produces length === 1 regardless of whether the quoted `uses: fake`
  // text was suppressed or counted, since the scan loop stops after the
  // first violation either way. The negative half below isolates the
  // quoted fragment alone and asserts it yields zero violations, so the
  // pair together can actually fail on the regression it documents
  // (CodeRabbit PR7 #6YZkoM).
  assert.deepEqual(findUnpinnedUses('steps: [{name: "a, uses: fake"}]\n'), [],
    'the quoted fake uses: text alone is suppressed by the key-separator colon context');
  assert.equal(findUnpinnedUses('steps: [{name: "a, uses: fake", uses: owner/action@main}]\n').length, 1,
    'a validly-positioned key-separator colon still opens context, suppressing the quoted fake uses: text');
});
test('findUnpinnedUses rejects an explicit key spelled as a block scalar (CodeRabbit #6YW9UB)', () => {
  // `- ? |-` opens a literal block scalar whose resolved content becomes the
  // mapping KEY (not a value) — `- ? |-` / `    uses` / `  : owner/action@main`
  // resolves (js-yaml verified) to {uses: "owner/action@main"}. Neither
  // BLOCK_SCALAR_HEADER (requires a preceding `:`, targets `key: |` VALUES)
  // nor any explicit-key scanner recognized this form.
  const literal = findUnpinnedUses('steps:\n  - ? |-\n    uses\n  : owner/action@main\n');
  assert.equal(literal.length, 1);
  assert.equal(literal[0].line, 2);
  assert.match(literal[0].ref, /\(explicit \? block-scalar mapping key/);
  const folded = findUnpinnedUses('steps:\n  - ? >\n    uses\n  : owner/action@main\n');
  assert.equal(folded.length, 1);
  assert.equal(folded[0].line, 2);
  // A genuine `run: |` block-scalar VALUE (not an explicit key) must still
  // be tracked and skipped normally — this fix must not touch that path.
  assert.deepEqual(findUnpinnedUses('steps:\n  - run: |\n      echo "{uses: foo@bar}"\n'), [],
    'an ordinary block-scalar value is unaffected');
});
test('findUnpinnedUses folds continued explicit keys inside flow mappings (CodeRabbit #6YSx9t)', () => {
  // The block-style pre-fold only recognized an explicit-key marker at
  // absolute line start; a flow-embedded one (`steps: [{? "u\<NL>ses": ref}]`,
  // js-yaml verified to resolve identically to the block form) was never
  // folded, so its resolved `uses` key slipped past every downstream scanner.
  // Once folded to `{? "uses": ref}`, the literal (non-escaped) quoted key
  // falls through FLOW_QUOTED_USES_KEY (which only flags escape-obfuscated
  // keys) to the general SUSPICIOUS_USES scanner, same as any other clean
  // flow-style `uses:` — still flagged, just via the generic message.
  const r = findUnpinnedUses('steps: [{? "u\\\n  ses": owner/action@main}]\n');
  assert.equal(r.length, 1);
  assert.equal(r[0].line, 1);
  assert.match(r[0].ref, /uses: in non-block-style or unparseable form/);
});
test('findUnpinnedUses strips trailing YAML comments before SUSPICIOUS_USES (CodeRabbit #6X7tKy)', () => {
  assert.equal(findUnpinnedUses('name: build # see {uses: owner/action@main}\n').length, 0,
    'a {uses:} token inside a trailing comment is not flagged');
  assert.equal(findUnpinnedUses("name: build # don't use {uses: owner/action@main}\n").length, 0,
    'a {uses:} token inside a trailing comment with an apostrophe is not flagged');
  assert.equal(findUnpinnedUses('steps: [{uses: owner/action@main}]\n').length, 1,
    'a real flow uses: outside any comment is still flagged');
});
test('findUnpinnedUses keeps a plain-scalar apostrophe BEFORE the # from hiding the comment start (chatgpt-codex-connector PR7 #6Yap8e)', () => {
  // Distinct from the #6X7tKy case above: there the apostrophe sits INSIDE
  // the comment (after #), so a naive walker already reaches the real # while
  // still un-quoted. Here the apostrophe sits in the PLAIN SCALAR CONTENT
  // BEFORE the #, so a walker that treats every quote char as toggling state
  // unconditionally (stripTrailingYamlComment's original bug — the position-
  // aware fix already applied to isInsideQuotedScalar under #6YSoOn/#6YW1O6
  // had never been ported to this function) wrongly opens a single-quoted
  // string at "don't" and is still "inside" it when it reaches #, so the
  // comment is never recognized — the unstripped comment text then reaches
  // SUSPICIOUS_USES and gets flagged as a fake key.
  assert.equal(findUnpinnedUses("name: don't # {uses: owner/action@main}\n").length, 0,
    'a plain-scalar apostrophe before the # must not hide the trailing comment');
  assert.equal(findUnpinnedUses('name: say "hi" # {uses: owner/action@main}\n').length, 0,
    'a plain-scalar double-quote before the # must not hide the trailing comment either');
});
test('findUnpinnedUses handles mirrored single-quote cases in flow values (CodeRabbit #6X7tLA)', () => {
  assert.equal(findUnpinnedUses('steps: [{name: \'say "hi"\'}, {uses: owner/action@main}]\n').length, 1,
    'a double quote inside a single-quoted value must not suppress a later flow uses');
  assert.equal(findUnpinnedUses("steps: [{name: 'it''s'}, {uses: owner/action@main}]\n").length, 1,
    "a doubled '' escape inside a single-quoted value must not suppress a later flow uses");
});

test('findUnpinnedUses accepts uppercase and mixed-case hex commit pins (Codex #1652)', () => {
  // Git object IDs are case-insensitive hexadecimal; a SHA may contain A-F.
  // The lowercase-only PINNED_REF falsely flagged valid immutable pins like
  // actions/checkout@DF4CB1C... as unpinned. The match is now case-insensitive.
  assert.deepEqual(findUnpinnedUses('steps:\n  - uses: actions/checkout@DF4CB1C069E1874EDD31B4311F1884172CEC0E10\n'), [],
    'an uppercase-hex 40-char SHA is a valid pin');
  assert.deepEqual(findUnpinnedUses('steps:\n  - uses: actions/checkout@Df4Cb1C069e1874edD31b4311f1884172ceC0e10\n'), [],
    'a mixed-case-hex 40-char SHA is a valid pin');
  // A non-SHA ref (tag/branch) is still correctly flagged unpinned.
  assert.equal(findUnpinnedUses('steps:\n  - uses: actions/checkout@v6\n').length, 1,
    'a tag ref is still flagged unpinned');
  // A too-short hex string (not 40 chars) is still flagged.
  assert.equal(findUnpinnedUses('steps:\n  - uses: actions/checkout@ABCDEF\n').length, 1,
    'a short hex string is not a valid pin');
});

test('findUnpinnedUses flags flow uses after an apostrophe in a quoted value (Codex #1657)', () => {
  // The quote-context check previously COUNTED each ' and " char before the
  // match position. An apostrophe inside a double-quoted value — `name: "can't"`
  // — inflated the single-quote count to odd, falsely marking a later
  // `{uses: ...}` as "inside a quoted string" and suppressing the violation.
  // The scanner now walks the prefix tracking the active quote context, so a
  // quote char inside the OTHER type's string is ignored.
  assert.equal(findUnpinnedUses('steps: [{name: "can\'t"}, {uses: owner/action@main}]\n').length, 1,
    'an apostrophe inside a double-quoted value must not suppress a later flow uses');
  assert.equal(findUnpinnedUses('steps: [{name: "a\\"b"}, {uses: owner/action@main}]\n').length, 1,
    'an escaped double-quote inside a double-quoted value must not suppress a later flow uses');
  // A uses genuinely inside a quoted value is still correctly suppressed.
  assert.equal(findUnpinnedUses('name: "steps: [{uses: owner/action@main}]"\n').length, 0,
    'a uses inside a complete double-quoted value is still not flagged');
});

test('findUnpinnedUses tracks a quoted scalar across physical lines (chatgpt-codex-connector PR7 #6YaZ5F)', () => {
  // A double-quoted flow value can legally span physical lines (YAML folds
  // the embedded newline to a space) with no trailing backslash needed. Each
  // line was previously scanned with quote state reset fresh, so the scalar's
  // CLOSING quote on a later line was mistaken for a NEW opener, hiding a
  // real uses: key right after it on that same line (js-yaml verified:
  // resolves to {name: "foo bar ", uses: "owner/action@main"}).
  assert.equal(findUnpinnedUses('steps: [{name: "foo\n  bar\n  ", uses: owner/action@main}]\n').length, 1,
    'a uses: key right after a multiline double-quoted scalar closes must still be flagged');
  // Single-quoted scalars fold the same way and must be tracked identically.
  assert.equal(findUnpinnedUses("steps: [{name: 'foo\n  bar\n  ', uses: owner/action@main}]\n").length, 1,
    'a uses: key right after a multiline single-quoted scalar closes must still be flagged');
  // Sanity, both directions at once: a uses:-shaped SUSPICIOUS_USES candidate
  // (after a `,` flow boundary) on the MIDDLE continuation line, genuinely
  // inside the still-open multiline string, must be suppressed by the
  // carryover — while the REAL uses: key once the string actually closes on
  // the next line must still be caught (js-yaml verified: resolves to
  // {name: "foo x, uses: bar baz", uses: "owner/action@main"} — one real
  // uses: key, not two).
  assert.deepEqual(
    findUnpinnedUses('steps: [{name: "foo\n  x, uses: bar\n  baz", uses: owner/action@main}]\n'),
    [{ line: 3, ref: '(uses: in non-block-style or unparseable form — rewrite in clean block style or review manually)' }],
    'a uses:-shaped fragment still inside the open string is suppressed; the real uses: key after it closes is still caught',
  );
});

test('findUnpinnedUses requires trailing separation for a dash/question-mark quote-open marker (chatgpt-codex-connector PR7 #6Yap8Z)', () => {
  // A real YAML sequence dash or explicit-key marker requires whitespace (or
  // EOL) right after it to introduce the next token. `-"def`/`?"def` (no
  // space) is ordinary plain-scalar CONTENT, not a marker — js-yaml verified:
  // both resolve to the literal plain scalar (e.g. `-"def`), and the quote
  // character is part of that scalar's text, not a real quote-open.
  assert.equal(findUnpinnedUses('steps: [{name: -"def, uses: owner/action@main}]\n').length, 1,
    'a dash immediately followed by a quote (no space) must not open a phantom quoted scalar');
  assert.equal(findUnpinnedUses('steps: [{name: ?"def, uses: owner/action@main}]\n').length, 1,
    'a question mark immediately followed by a quote (no space) must not open a phantom quoted scalar');
  // Sanity: a genuine sequence dash / explicit-key marker (WITH separation)
  // still correctly preserves quote-open context.
  assert.equal(findUnpinnedUses('steps:\n  - "foo, uses: owner/action@main"\n').length, 0,
    'a real sequence dash followed by whitespace still opens a genuine quoted scalar');
});

test('findUnpinnedUses strips a trailing comment before testing BLOCK_SCALAR_HEADER (chatgpt-codex-connector PR7 #6Yap8d)', () => {
  // BLOCK_SCALAR_HEADER's own `\S.*:` prefix is greedy and, on a line whose
  // trailing COMMENT itself contains a `key: |`-shaped fragment, can swallow
  // past the real comment-start `#` and match the comment's own colon plus
  // chomping indicator as if it were a genuine block-scalar header — falsely
  // treating the line as opening a scalar and silently skipping its real
  // (more-indented) body, which can contain a genuine unpinned uses:.
  const doc = 'jobs: # bogus: |\n  build:\n    steps:\n      - uses: owner/action@main\n';
  assert.deepEqual(findUnpinnedUses(doc), [{ line: 4, ref: 'owner/action@main' }],
    'a block-scalar-shaped fragment inside a trailing comment must not hide the real, more-indented uses: below it');
  // Sanity: a genuine block scalar header (no comment involved) still works.
  const genuine = 'with:\n  script: |\n    const x = {uses: owner/action@main};\n';
  assert.deepEqual(findUnpinnedUses(genuine), [], 'a real block-scalar header is unaffected');
});

test('findUnpinnedUses does not let a quote inside a trailing comment corrupt carryover to the next line (CodeRabbit #6YbIQU / chatgpt-codex-connector PR7 #6YbKFc)', () => {
  // quoteCarryover was previously computed from the RAW line, including its
  // own trailing comment text. An unclosed quote inside that comment (a
  // single or double quote with no matching close before end-of-line) was
  // wrongly treated as opening a real scalar that carries into the NEXT
  // line, suppressing that line's genuine unpinned flow-style uses: (fail-
  // open). js-yaml verified: both documents resolve to a real, unpinned
  // `uses: owner/action@main` on line 2 — the comment's stray quote has no
  // bearing on line 2's own YAML structure at all.
  assert.equal(findUnpinnedUses("name: build # ok, 'quoted\nsteps: [{uses: owner/action@main}]\n").length, 1,
    'an unmatched single quote inside a trailing comment must not suppress the next line\'s real uses:');
  assert.equal(findUnpinnedUses('name: build # ok, "quoted\nsteps: [{uses: owner/action@main}]\n').length, 1,
    'an unmatched double quote inside a trailing comment must not suppress the next line\'s real uses:');
  // Sanity: a GENUINE open scalar (no comment involved) must still carry
  // over correctly — this fix must not blind the carryover to real cases.
  assert.equal(findUnpinnedUses('steps: [{name: "a # b\n  c", uses: owner/action@main}]\n').length, 1,
    'a real multiline quoted scalar (unrelated to a comment) must still carry over and still catch the real uses: after it closes');
});

test('findUnpinnedUses does not treat a block-style uses:-shaped continuation of a carried-open scalar as a real key (chatgpt-codex-connector PR7 #6YbMwS)', () => {
  // js-yaml verified: `name: "foo\n  uses: owner/action@main\n  bar"` resolves
  // to one folded scalar value ("foo uses: owner/action@main bar"), not a
  // real `uses` key — USES_LINE's block-style match previously ignored
  // lineStartQuoteState entirely and flagged line 2 as an unpinned action.
  assert.deepEqual(findUnpinnedUses('name: "foo\n  uses: owner/action@main\n  bar"\nsteps: []\n'), [],
    'a uses:-shaped line that is scalar CONTENT of a carried-open quote must not be treated as a real key');
  // Sanity: an actual top-level block-style uses: (not inside any scalar)
  // must still be caught.
  assert.deepEqual(findUnpinnedUses('steps:\n  - uses: owner/action@main\n'), [{ line: 2, ref: 'owner/action@main' }],
    'a genuine, unquoted block-style uses: line must still be flagged');
});

test('findUnpinnedUses updates carried quote state on a comment-shaped line that actually closes an open scalar (chatgpt-codex-connector PR7 #6YbMwW)', () => {
  // js-yaml verified: `name: "foo\n  # bar"` resolves to the scalar
  // "foo # bar" — the `#` on line 2 is INSIDE the still-open double-quoted
  // scalar from line 1, not a real YAML comment. The old unconditional
  // `COMMENT_LINE.test(text)` early return treated line 2 as a pure comment
  // and skipped updating quoteCarryover entirely, so the scalar looked
  // permanently open and the real uses: on line 3 was wrongly suppressed.
  assert.deepEqual(
    findUnpinnedUses('name: "foo\n  # bar"\nsteps: [{uses: owner/action@main}]\n'),
    [{ line: 3, ref: '(uses: in non-block-style or unparseable form — rewrite in clean block style or review manually)' }],
    'a comment-shaped line that actually closes a carried-open scalar must still let the next real uses: be caught',
  );
  // Sanity: a genuine standalone comment line (no open scalar at all) is
  // still skipped and does not itself produce a violation.
  assert.deepEqual(findUnpinnedUses('# just a comment: uses: owner/action@main\nsteps: []\n'), [],
    'a real standalone comment line must still be ignored entirely');
});

test('findUnpinnedUses does not open block-scalar tracking from a key:-shaped line inside a carried-open scalar (CodeRabbit PR7 #6Yb1dD)', () => {
  // js-yaml verified: `name: "foo\n  run: |\n    text"\nsteps: [{uses: owner/action@main}]`
  // resolves to {name: "foo run: | text", steps: [{uses: "owner/action@main"}]}
  // -- line 2's "run: |" is scalar CONTENT, not a real block-scalar header.
  // BLOCK_SCALAR_HEADER was previously tested against every line
  // unconditionally, so it wrongly started tracking a scalar body on line 2,
  // which then swallowed line 3 (where the carried quote actually closes)
  // as fake scalar content and hid the real unpinned uses: on line 4.
  assert.deepEqual(
    findUnpinnedUses('name: "foo\n  run: |\n    text"\nsteps: [{uses: owner/action@main}]\n'),
    [{ line: 4, ref: '(uses: in non-block-style or unparseable form — rewrite in clean block style or review manually)' }],
    'a key:-shaped line inside a carried-open scalar must not open fake block-scalar tracking that hides a later real uses:',
  );
  // Sanity: a genuine block-scalar header (not inside any carried-open
  // scalar) must still correctly start body tracking.
  assert.deepEqual(findUnpinnedUses('with:\n  script: |\n    const x = {uses: owner/action@main};\n'), [],
    'a real block-scalar header outside any carried quote must still be recognized');
});

test('hasTopLevelPermissions requires a column-zero permissions block', () => {
  assert.equal(hasTopLevelPermissions('name: x\npermissions:\n  contents: read\n'), true);
  assert.equal(hasTopLevelPermissions('name: x\npermissions: {}\n'), true);
  assert.equal(hasTopLevelPermissions('jobs:\n  a:\n    permissions:\n      contents: read\n'), false);
  assert.equal(hasTopLevelPermissions('name: x\n'), false);
  // A quoted top-level key ("permissions" or 'permissions') is valid YAML and
  // must be recognized identically to the bare form.
  assert.equal(hasTopLevelPermissions('"permissions": {contents: read}\n'), true);
  assert.equal(hasTopLevelPermissions("'permissions': {contents: read}\n"), true);
  // Whitespace before the colon (permissions :) is valid YAML — consistent
  // with the whitespace tolerance USES_LINE already applies to uses: keys.
  assert.equal(hasTopLevelPermissions('permissions :\n  contents: read\n'), true);
  // A UTF-8 BOM at file start must not defeat column-zero detection
  // (CodeRabbit #6X72Z8). Without the BOM strip, the regex anchors fail.
  assert.equal(hasTopLevelPermissions("\uFEFFpermissions:\n  contents: read\n"), true,
    'a BOM-prefixed permissions block is detected');
});

test('hasTopLevelPermissions does not mistake column-zero scalar content for a real key (chatgpt-codex-connector PR7 #6YblGF)', () => {
  // js-yaml verified: a multiline double-quoted scalar can fold a physical
  // line that LOOKS like a column-zero `permissions:` key into its plain
  // string content -- `name: "foo\n  permissions:\n  bar"` resolves to
  // {name: "foo permissions: bar"}, with no real permissions key anywhere.
  // The reviewer's own literal example (`name: "foo\npermissions:\nbar"`,
  // with the continuation lines at column 0) is not valid YAML at all --
  // js-yaml rejects it with "deficient indentation" -- because YAML
  // requires a folded scalar's continuation lines to be indented past
  // their parent's own indentation; a properly-indented equivalent is used
  // here since that is the form that actually parses.
  assert.equal(
    hasTopLevelPermissions('name: "foo\n  permissions:\n  bar"\n'),
    false,
    'a permissions:-shaped line inside a still-open multiline scalar must not count as a real top-level key',
  );
  // Sanity: a genuine top-level permissions: key on the line immediately
  // after a completed (closed) multiline scalar must still be detected.
  assert.equal(
    hasTopLevelPermissions('name: "foo\n  bar"\npermissions:\n  contents: read\n'),
    true,
    'a real top-level permissions: key after a scalar closes must still be found',
  );
});

test('hasTopLevelPermissions splits on \\r\\n and lone \\r, not only \\n (CodeRabbit PR7 #6Yb1dF)', () => {
  // Splitting on '\n' alone left every physical line of a CR-only
  // (old-Mac-style line ending) file joined into a single string, so a
  // real top-level permissions: key later in the file was never reached
  // on its own line and went undetected.
  assert.equal(hasTopLevelPermissions('name: x\rpermissions:\r  contents: read\r'), true,
    'a CR-only workflow with a real top-level permissions: key must be detected');
  assert.equal(hasTopLevelPermissions('name: x\r\npermissions:\r\n  contents: read\r\n'), true,
    'a CRLF workflow with a real top-level permissions: key must be detected');
  assert.equal(hasTopLevelPermissions('name: x\r'), false,
    'a CR-only workflow with no permissions: key must still report false');
});

test('the real validator passes on this repository (integration)', () => {
  const result = spawnSync(process.execPath, [path.join(__dirname, 'validate_repository.js')], { encoding: 'utf8' });
  assert.equal(result.status, 0, `validator failed:\n${result.stderr}`);
  assert.match(result.stdout, /"status":"PASS"/);
});
