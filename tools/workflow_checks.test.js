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

test('hasTopLevelPermissions requires a column-zero permissions block', () => {
  assert.equal(hasTopLevelPermissions('name: x\npermissions:\n  contents: read\n'), true);
  assert.equal(hasTopLevelPermissions('name: x\npermissions: {}\n'), true);
  assert.equal(hasTopLevelPermissions('jobs:\n  a:\n    permissions:\n      contents: read\n'), false);
  assert.equal(hasTopLevelPermissions('name: x\n'), false);
});

test('the real validator passes on this repository (integration)', () => {
  const result = spawnSync(process.execPath, [path.join(__dirname, 'validate_repository.js')], { encoding: 'utf8' });
  assert.equal(result.status, 0, `validator failed:\n${result.stderr}`);
  assert.match(result.stdout, /"status":"PASS"/);
});
