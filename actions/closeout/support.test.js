'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  decideExit,
  escapeActionText,
  parseLastJsonLine,
  resolveBaseRef,
  validateActionInputs,
} = require('./support');

test('validateActionInputs applies defaults and rejects unknown values fail-closed', () => {
  const defaults = validateActionInputs({});
  assert.deepEqual(defaults, { run: 'plan', mode: 'strict', prComment: false });

  const explicit = validateActionInputs({ run: 'full', mode: 'engine', prComment: 'true' });
  assert.deepEqual(explicit, { run: 'full', mode: 'engine', prComment: true });

  assert.throws(() => validateActionInputs({ run: 'preview' }), /Unknown run input value: preview/);
  assert.throws(() => validateActionInputs({ mode: 'lenient' }), /Unknown mode input value: lenient/);
  assert.throws(() => validateActionInputs({ prComment: 'yes' }), /Unknown pr-comment input value: yes/);
  // Casing is not forgiven: the gate CLI is case-sensitive and the action
  // must never widen what the CLI accepts.
  assert.throws(() => validateActionInputs({ mode: 'Engine' }), /Unknown mode input value: Engine/);
});

test('resolveBaseRef walks the ladder: input, GITHUB_BASE_REF, event payload, then null', () => {
  assert.equal(resolveBaseRef({ inputBaseRef: 'origin/dev', env: {}, event: {} }), 'origin/dev');
  assert.equal(resolveBaseRef({ inputBaseRef: '', env: { GITHUB_BASE_REF: 'main' }, event: {} }), 'origin/main');
  assert.equal(
    resolveBaseRef({ inputBaseRef: '', env: {}, event: { pull_request: { base: { ref: 'release' } } } }),
    'origin/release',
  );
  assert.equal(resolveBaseRef({ inputBaseRef: '', env: {}, event: {} }), null);
  // The env branch wins over the event branch when both exist.
  assert.equal(
    resolveBaseRef({ inputBaseRef: '', env: { GITHUB_BASE_REF: 'main' }, event: { pull_request: { base: { ref: 'other' } } } }),
    'origin/main',
  );
});

test('parseLastJsonLine returns the last parseable JSON object line, else null', () => {
  assert.deepEqual(parseLastJsonLine('{"a":1}\n'), { a: 1 });
  assert.deepEqual(parseLastJsonLine('noise\n{"a":1}\n{"b":2}\n'), { b: 2 });
  assert.equal(parseLastJsonLine('no json here\n'), null);
  assert.equal(parseLastJsonLine(''), null);
  // A JSON scalar line is not a record.
  assert.equal(parseLastJsonLine('42\n'), null);
  // A record with an own __proto__ key can only be hostile or garbled — the
  // gate never emits one. Rejected structurally so no later consumer can be
  // prototype-tricked by an Object.assign-style copy (review decision).
  assert.equal(parseLastJsonLine('{"__proto__":{"planStatus":"PASS"}}\n'), null);
});

test('decideExit implements the spec exit decision table exactly', () => {
  const plan = { planStatus: 'FAIL', mode: 'strict' };
  // Plan tier: success iff a real plan (string planStatus) was captured,
  // regardless of exit code or planStatus value.
  assert.deepEqual(decideExit({ run: 'plan', cliExitCode: 2, parsed: plan }), { success: true, exitCode: 0, reason: 'plan captured (planStatus=FAIL)' });
  assert.deepEqual(decideExit({ run: 'plan', cliExitCode: 0, parsed: { planStatus: 'PASS' } }), { success: true, exitCode: 0, reason: 'plan captured (planStatus=PASS)' });
  const broken = decideExit({ run: 'plan', cliExitCode: 3, parsed: { status: 'BLOCKED', error: 'bad repo' } });
  assert.equal(broken.success, false);
  assert.equal(broken.exitCode, 3);
  assert.match(broken.reason, /no plan JSON/i);
  const silent = decideExit({ run: 'plan', cliExitCode: 0, parsed: null });
  assert.equal(silent.success, false);
  assert.equal(silent.exitCode, 3);
  // Full tier: the CLI's exit code propagates verbatim.
  assert.deepEqual(decideExit({ run: 'full', cliExitCode: 0, parsed: { status: 'PASS' } }), { success: true, exitCode: 0, reason: 'gate PASS' });
  const fail = decideExit({ run: 'full', cliExitCode: 2, parsed: { status: 'FAIL' } });
  assert.deepEqual([fail.success, fail.exitCode], [false, 2]);
  const blocked = decideExit({ run: 'full', cliExitCode: 3, parsed: { status: 'BLOCKED' } });
  assert.deepEqual([blocked.success, blocked.exitCode], [false, 3]);
  // Unknown tier fails CLOSED (review decision, Task 1 round): an
  // unvalidated run value must never fall into the more permissive plan
  // branch and report success for a failing full gate.
  const mixedCase = decideExit({ run: 'FULL', cliExitCode: 0, parsed: { planStatus: 'PASS' } });
  assert.deepEqual([mixedCase.success, mixedCase.exitCode], [false, 3]);
  assert.match(mixedCase.reason, /unknown run tier/i);
  const missingTier = decideExit({ run: undefined, cliExitCode: 2, parsed: { planStatus: 'PASS' } });
  assert.deepEqual([missingTier.success, missingTier.exitCode], [false, 3]);
});

test('escapeActionText is the gate safeText allowlist: everything non-allowlisted becomes a numeric entity', () => {
  assert.equal(escapeActionText('plain text 123 file.name_ok-1'), 'plain text 123 file.name_ok-1');
  assert.equal(escapeActionText('a & b'), 'a &#38; b');
  assert.equal(escapeActionText('<img>'), '&#60;img&#62;');
  assert.equal(escapeActionText('x | y'), 'x &#124; y');
  assert.equal(escapeActionText('# heading'), '&#35; heading');
  assert.equal(escapeActionText('~~FAILED~~ ~~~js'), '&#126;&#126;FAILED&#126;&#126; &#126;&#126;&#126;js');
  assert.equal(escapeActionText('https://evil.example/x'), 'https&#58;&#47;&#47;evil.example&#47;x');
  assert.equal(
    escapeActionText('> quote **bold** `c` [l](u)'),
    '&#62; quote &#42;&#42;bold&#42;&#42; &#96;c&#96; &#91;l&#93;&#40;u&#41;',
  );
  assert.equal(escapeActionText('line1\nline2\r\nline3'), 'line1 \u23CE line2 \u23CE line3');
  const hostile = `bad${String.fromCharCode(27)}[31mansi${String.fromCharCode(0)}nul`;
  const escaped = escapeActionText(hostile);
  assert.match(escaped, /&#27;/);
  assert.match(escaped, /&#0;/);
  for (let index = 0; index < escaped.length; index += 1) {
    const code = escaped.charCodeAt(index);
    assert.ok(code >= 32 && code !== 127, `control byte survived at ${index}`);
  }
  assert.equal(escapeActionText(undefined), '');
  assert.equal(escapeActionText(42), '42');
});
