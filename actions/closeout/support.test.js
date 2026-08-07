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
});

test('escapeActionText neutralizes markdown-active and control characters', () => {
  assert.equal(escapeActionText('plain text 123'), 'plain text 123');
  assert.equal(escapeActionText('a & b'), 'a &amp; b');
  assert.equal(escapeActionText('<img>'), '&lt;img&#62;');
  assert.equal(escapeActionText('x | y'), 'x &#124; y');
  assert.equal(escapeActionText('# heading'), '&#35; heading');
  assert.equal(escapeActionText('> quote **bold** _u_ `c` [l](u)'),
    '&#62; quote &#42;&#42;bold&#42;&#42; &#95;u&#95; &#96;c&#96; &#91;l&#93;(u)');
  assert.equal(escapeActionText('line1\nline2\r\nline3'), 'line1 \u23CE line2 \u23CE line3');
  const hostile = `bad${String.fromCharCode(27)}[31mansi${String.fromCharCode(0)}nul`;
  const escaped = escapeActionText(hostile);
  for (let index = 0; index < escaped.length; index += 1) {
    const code = escaped.charCodeAt(index);
    assert.ok(code >= 32 && code !== 127, `control byte survived at ${index}`);
  }
  assert.equal(escapeActionText(undefined), '');
  assert.equal(escapeActionText(42), '42');
});
