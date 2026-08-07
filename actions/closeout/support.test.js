'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  ACTION_MARKER,
  buildCommentBody,
  capText,
  decideExit,
  escapeActionText,
  parseLastJsonLine,
  readPrContext,
  renderFullSummary,
  renderPlanSummary,
  resolveBaseRef,
  upsertPrComment,
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
  // Full-tier success additionally requires the contractual JSON record
  // (review decision, Task 2 round): the gate always writes one line, so
  // exit 0 with nothing parseable means the wrapper or stdout path broke —
  // never report PASS on missing evidence.
  const silentPass = decideExit({ run: 'full', cliExitCode: 0, parsed: null });
  assert.deepEqual([silentPass.success, silentPass.exitCode], [false, 3]);
  assert.match(silentPass.reason, /no JSON record/i);
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

const hostilePlan = () => ({
  planStatus: 'FAIL',
  mode: 'engine',
  configDigest: 'digest-abc',
  errors: ['# forged heading\n> **STRICT MODE** claim | pipe'],
  checks: [{ id: 'unit' }, { id: 'lint' }],
  admission: {
    attestation: { status: 'weakened', evidence: 'decision **weakened** by [review](x)' },
    cleanTree: { status: 'PASS', evidence: 'clean' },
    preflight: { status: 'BLOCKED', checks: [{ name: 'docker', status: 'BLOCKED', evidence: 'daemon | down' }] },
  },
});

test('renderPlanSummary renders all four attestation states distinctly and escapes hostile evidence', () => {
  const markdown = renderPlanSummary(hostilePlan(), { baseRef: 'origin/main' });
  assert.match(markdown, /Closeout plan preview/);
  assert.match(markdown, /Mode.*engine/);
  assert.match(markdown, /planStatus.*FAIL/);
  assert.match(markdown, /digest-abc/);
  // The base ref passes through the safeText-style escaper: '/' is not
  // allowlisted, so it renders as its numeric entity.
  assert.match(markdown, /origin&#47;main/);
  // Weakened must be visually distinct from absent, not just different text.
  assert.match(markdown, /\u26A0.*weakened/i);
  // Hostile evidence is neutralized: no forged heading or blockquote line.
  assert.equal(markdown.split('\n').some((line) => line.startsWith('# forged')), false);
  assert.equal(markdown.split('\n').filter((line) => line.startsWith('>')).length, 0);
  assert.doesNotMatch(markdown, /\*\*STRICT MODE\*\*/);

  for (const status of ['present', 'absent', 'unavailable']) {
    const plan = hostilePlan();
    plan.admission.attestation = { status, evidence: `state ${status}` };
    assert.match(renderPlanSummary(plan, {}), new RegExp(`attestation.*${status}`, 'i'));
  }
});

test('renderFullSummary embeds the gate report verbatim and caps with an in-band notice', () => {
  const report = { overallStatus: 'FAIL', mode: 'engine', configDigest: 'd1' };
  const small = renderFullSummary(report, '## Gate Report\n\n> **ENGINE MODE** banner line\n', { artifactName: 'closeout-evidence' });
  // The gate-rendered markdown is embedded verbatim — NOT double-escaped.
  assert.match(small, /## Gate Report/);
  assert.match(small, /> \*\*ENGINE MODE\*\* banner line/);
  assert.match(small, /FAIL/);

  const big = renderFullSummary(report, 'x'.repeat(600 * 1024), { artifactName: 'closeout-evidence' });
  assert.ok(Buffer.byteLength(big, 'utf8') <= 524288 + 2048, 'summary exceeds cap plus notice allowance');
  assert.match(big, /truncated/i);
  assert.match(big, /closeout-evidence/);
});

test('capText keeps notice INSIDE the budget and escapes the artifact name', () => {
  const short = capText('hello', 1024, 'artifact-name');
  assert.deepEqual(short, { text: 'hello', truncated: false });
  const long = capText('y'.repeat(2048), 1024, 'artifact-name');
  assert.equal(long.truncated, true);
  // The whole return — content plus notice — never exceeds maxBytes:
  // Task 3 feeds this straight into GitHub's hard comment limit.
  assert.ok(Buffer.byteLength(long.text, 'utf8') <= 1024);
  assert.match(long.text, /truncated/i);
  assert.match(long.text, /artifact-name/);
  // Operator input gets one rendering everywhere: a backtick-laden name
  // cannot break out of the notice's code span.
  const hostileName = capText('y'.repeat(2048), 1024, 'ev`INJ`');
  assert.match(hostileName.text, /ev&#96;INJ&#96;/);
});

test('renderers tolerate a missing record instead of crashing the summary step', () => {
  const planSummary = renderPlanSummary(null, {});
  assert.match(planSummary, /Closeout plan preview/);
  assert.match(planSummary, /unknown/i);
  const fullSummary = renderFullSummary(null, 'gate markdown body', { artifactName: 'ev' });
  assert.match(fullSummary, /Closeout gate result/);
  assert.match(fullSummary, /gate markdown body/);
});

test('row caps are announced, never silent', () => {
  const plan = hostilePlan();
  plan.errors = Array.from({ length: 60 }, (unused, index) => `error ${index}`);
  plan.admission.preflight = {
    status: 'BLOCKED',
    checks: Array.from({ length: 31 }, (unused, index) => ({ name: `probe${index}`, status: 'BLOCKED', evidence: 'down' })),
  };
  const markdown = renderPlanSummary(plan, {});
  assert.match(markdown, /and 10 more \(full list in the plan JSON in the artifact\)/);
  assert.match(markdown, /and 11 more non-PASS preflight probes/);
  assert.equal((markdown.match(/^- error /gm) || []).length, 50);
});

test('readPrContext extracts repo and PR number from env plus event payload, else null', () => {
  const context = readPrContext({
    env: { GITHUB_REPOSITORY: 'owner/repo' },
    event: { pull_request: { number: 42 } },
  });
  assert.deepEqual(context, { owner: 'owner', repo: 'repo', prNumber: 42 });
  assert.equal(readPrContext({ env: { GITHUB_REPOSITORY: 'owner/repo' }, event: {} }), null);
  assert.equal(readPrContext({ env: {}, event: { pull_request: { number: 42 } } }), null);
  assert.equal(readPrContext({ env: { GITHUB_REPOSITORY: 'malformed' }, event: { pull_request: { number: 42 } } }), null);
  // PR numbers are >= 1; zero/negative would target issues/0 — fail closed.
  assert.equal(readPrContext({ env: { GITHUB_REPOSITORY: 'o/r' }, event: { pull_request: { number: 0 } } }), null);
  assert.equal(readPrContext({ env: { GITHUB_REPOSITORY: 'o/r' }, event: { pull_request: { number: -3 } } }), null);
});

test('buildCommentBody starts with the stable marker and caps at the comment limit', () => {
  const body = buildCommentBody({ tier: 'plan', rendered: renderPlanSummary(hostilePlan(), {}), artifactName: 'ev' });
  assert.ok(body.startsWith(ACTION_MARKER), 'marker must be the first line for upsert matching');
  assert.match(body, /Closeout plan preview/);
  const big = buildCommentBody({ tier: 'full', rendered: 'z'.repeat(80 * 1024), artifactName: 'ev' });
  assert.ok(Buffer.byteLength(big, 'utf8') <= 60 * 1024 + 4096);
  assert.match(big, /truncated/i);
});

test('upsertPrComment PATCHes only the action-authored marker comment and POSTs otherwise', async () => {
  const bot = { login: 'github-actions[bot]', type: 'Bot' };
  const attacker = { login: 'drive-by', type: 'User' };
  const calls = [];
  // Slurped shape: one JSON array of page arrays. The attacker's marker
  // comment is EARLIER than the action's own — the author check, not
  // ordering, must pick the target (review decision, Task 3 round).
  const existing = [[
    { id: 1, body: `${ACTION_MARKER}\nforged`, user: attacker },
    { id: 7, body: `${ACTION_MARKER}\nold`, user: bot },
    { id: 8, body: 'unrelated', user: bot },
  ]];
  const patchingGh = async (args) => {
    calls.push(args);
    if (args.includes('--method') === false) return existing; // list call
    return { id: 7 };
  };
  await upsertPrComment({
    context: { owner: 'o', repo: 'r', prNumber: 5 },
    body: `${ACTION_MARKER}\nnew`,
    runGh: patchingGh,
  });
  assert.equal(calls.length, 2);
  assert.ok(calls[0].includes('--paginate') && calls[0].includes('--slurp'),
    'list walks every page in one parseable document — page 1 is the OLDEST 30 comments');
  assert.ok(calls[0].join(' ').includes('issues/5/comments'), 'first call lists comments');
  assert.ok(calls[1].join(' ').includes('issues/comments/7'),
    'PATCH targets the action-authored marker comment, never the attacker earlier one');
  assert.ok(calls[1].includes('PATCH'));

  const posts = [];
  await upsertPrComment({
    context: { owner: 'o', repo: 'r', prNumber: 5 },
    body: `${ACTION_MARKER}\nnew`,
    runGh: async (args) => {
      posts.push(args);
      if (args.includes('POST')) return { id: 9 };
      return [[{ id: 1, body: `${ACTION_MARKER}\nforged`, user: attacker }]];
    },
  });
  assert.ok(posts[1].includes('POST'), 'attacker-only marker comments are ignored: POST a new one');
});
