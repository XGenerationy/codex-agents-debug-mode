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

test('findUnpinnedUses catches quoted-key uses forms (YAML allows "uses": and uses:\'ref\')', () => {
  // The YAML spec allows the key itself to be quoted; GitHub interprets
  // "uses" / 'uses' as the `uses` key, so the validator must not skip it.
  const doubleQuotedKey = '  - "uses": actions/checkout@v6\n';
  const singleQuotedKey = "  - 'uses': someone/thing@main\n";
  const quotedKeyAndValue = '  - "uses": "actions/checkout@v6"\n';
  for (const variant of [doubleQuotedKey, singleQuotedKey, quotedKeyAndValue]) {
    const violations = findUnpinnedUses(variant);
    assert.equal(violations.length, 1, `expected one violation for: ${variant.trim()}`);
    assert.ok(violations[0].ref.includes('@'));
  }
  // A quoted-key PINNED ref still passes.
  assert.deepEqual(
    findUnpinnedUses('  - "uses": actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n'),
    [],
  );
});

test('findUnpinnedUses catches whitespace-variant uses keys (YAML allows spaces around the colon)', () => {
  // The YAML spec permits `uses : ref` (spaces around the colon); GitHub
  // interprets it as the `uses` key, so the validator must not skip it.
  const before = '  - uses : actions/checkout@v6\n';
  const both = '  - uses  :  someone/thing@main\n';
  for (const variant of [before, both]) {
    const violations = findUnpinnedUses(variant);
    assert.equal(violations.length, 1, `expected one violation for: ${variant.trim()}`);
    assert.ok(violations[0].ref.includes('@'));
  }
  // A whitespace-variant PINNED ref still passes (the colon tolerance must
  // not start false-flagging valid 40-hex pins).
  assert.deepEqual(
    findUnpinnedUses('  - uses : actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n'),
    [],
  );
});

test('findUnpinnedUses rejects flow-style uses mappings fail-closed (no bypass)', () => {
  // Flow-style `uses:` cannot be parsed without a YAML parser, so the check
  // fails closed rather than letting the entry through unchecked — pinning a
  // 40-hex SHA inside the flow mapping does NOT make it pass, because the
  // validator refuses to trust a ref it cannot reliably extract.
  const flowUnpinned = '  - {uses: actions/checkout@v6}\n';
  const flowPinned = '  - {uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10}\n';
  const flowQuoted = "  - {name: x, uses: 'actions/checkout@v6'}\n";
  // A quoted uses KEY inside a flow mapping (e.g. {"uses": ...}) is valid YAML
  // and must not bypass the check — FLOW_USES tolerates an optional quote.
  const flowQuotedKeyDouble = '  - {"uses": actions/checkout@v6}\n';
  const flowQuotedKeySingle = "  - {'uses': someone/thing@main}\n";
  for (const flow of [flowUnpinned, flowPinned, flowQuoted, flowQuotedKeyDouble, flowQuotedKeySingle]) {
    const violations = findUnpinnedUses(flow);
    assert.equal(violations.length, 1, `expected one flow-style violation for: ${flow.trim()}`);
    assert.match(violations[0].ref, /flow-style uses/);
    assert.equal(violations[0].line, 1);
  }
  // Mixed document: block-style pinned line passes, flow-style line flags.
  const mixed = 'steps:\n  - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10\n  - {uses: someone/thing@main}\n';
  const mixedViolations = findUnpinnedUses(mixed);
  assert.equal(mixedViolations.length, 1);
  assert.equal(mixedViolations[0].line, 3);
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
