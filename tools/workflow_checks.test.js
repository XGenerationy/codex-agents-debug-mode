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
  // treated as body content — even when the body text begins with `uses:`.
  // (A line at the key column itself is an empty scalar + sibling key, which
  // IS scanned — see the sibling-uses tests above.)
  assert.deepEqual(findUnpinnedUses('steps:\n  - run: |\n      uses: not-a-key\n'), [],
    'a deeper-indented body line beginning with uses: is script text, not a key');
  assert.deepEqual(findUnpinnedUses('  -  run: |\n        uses: not-a-key\n'), [],
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
