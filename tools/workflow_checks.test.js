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
  const blockLiteral = 'steps:\n  - run: |\n    echo "{uses: foo@bar}"\n    echo done\n  - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n';
  assert.deepEqual(findUnpinnedUses(blockLiteral), [],
    'block-literal body with {uses:...} must not false-positive');
  const foldedScalar = '  shell: >-\n    printf "{uses: foo@bar}"\n  - uses: ./local\n';
  assert.deepEqual(findUnpinnedUses(foldedScalar), [],
    'folded-scalar body with {uses:...} must not false-positive');
  // After the scalar ends (indentation drops), scanning resumes normally.
  const resume = '  - run: |\n    echo "{uses: x}"\n  - uses: someone/thing@main\n';
  const v = findUnpinnedUses(resume);
  assert.equal(v.length, 1, 'a real uses: after the scalar body IS caught');
  assert.equal(v[0].line, 3);
});

test('findUnpinnedUses handles block-scalar header variants (comment, indent indicator)', () => {
  // YAML allows a comment after the scalar indicator (run: | # cmt) and an
  // explicit indentation indicator (run: |2). Both must open a scalar whose
  // body is skipped — otherwise the body's {uses:...} false-positives.
  const withComment = '  - run: | # build\n    echo "{uses: foo@bar}"\n';
  assert.deepEqual(findUnpinnedUses(withComment), [],
    'scalar header with trailing comment must skip body');
  const withIndent = '  - run: |2\n    echo "{uses: foo@bar}"\n';
  assert.deepEqual(findUnpinnedUses(withIndent), [],
    'scalar header with indent indicator must skip body');
  const withIndentChomp = '  - run: |2-\n    echo "{uses: foo@bar}"\n';
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
});

test('the real validator passes on this repository (integration)', () => {
  const result = spawnSync(process.execPath, [path.join(__dirname, 'validate_repository.js')], { encoding: 'utf8' });
  assert.equal(result.status, 0, `validator failed:\n${result.stderr}`);
  assert.match(result.stdout, /"status":"PASS"/);
});
