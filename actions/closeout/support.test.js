'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { mkdtempSync, readFileSync: readFs, symlinkSync, writeFileSync: writeFs } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');

const {
  ACTION_MARKER,
  assertOutputOutsideWorkspace,
  buildCommentBody,
  capText,
  commentSubcommand,
  decideExit,
  escapeActionText,
  finishSubcommand,
  parseLastJsonLine,
  readPrContext,
  renderFullSummary,
  renderPlanSummary,
  resolveBaseRef,
  runSubcommand,
  upsertPrComment,
  validateActionInputs,
  writeOutputs,
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

test('upsertPrComment PATCHes the NEWEST marker comment when duplicates exist', async () => {
  // Regression for the oldest-vs-newest selection bug: with two action-
  // authored marker comments (from rerun races, prior duplication, or a
  // drive-by bot comment), the upsert must PATCH the newest (largest id) so
  // it converges on one current comment rather than pinning the oldest
  // stale one forever. GitHub comment ids are globally monotonic.
  const bot = { login: 'github-actions[bot]', type: 'Bot' };
  const calls = [];
  const existing = [[
    { id: 7, body: `${ACTION_MARKER}\nold`, user: bot },
    { id: 42, body: `${ACTION_MARKER}\nstale duplicate`, user: bot },
  ]];
  await upsertPrComment({
    context: { owner: 'o', repo: 'r', prNumber: 5 },
    body: `${ACTION_MARKER}\nnew`,
    runGh: async (args) => { calls.push(args); return args.includes('--method') ? { id: 42 } : existing; },
  });
  assert.equal(calls.length, 2);
  assert.ok(calls[1].join(' ').includes('issues/comments/42'),
    'PATCH targets the NEWEST (largest id) marker comment, not the oldest');
  assert.ok(!calls[1].join(' ').includes('issues/comments/7'),
    'the older duplicate is not the PATCH target');
});

const makeTempDir = () => mkdtempSync(path.join(tmpdir(), 'closeout-action-'));

test('writeOutputs appends sanitized single-line name=value pairs', () => {
  const dir = makeTempDir();
  const outputFile = path.join(dir, 'gh-output');
  writeFs(outputFile, 'existing=1\n');
  writeOutputs(outputFile, { status: 'FAIL', mode: 'engine', attestation: 'absent', 'report-path': 'C:\\x\\report.json' });
  writeOutputs(outputFile, { extra: 'line1\nline2' });
  const content = readFs(outputFile, 'utf8');
  assert.match(content, /^existing=1$/m);
  assert.match(content, /^status=FAIL$/m);
  assert.match(content, /^mode=engine$/m);
  assert.match(content, /^attestation=absent$/m);
  assert.match(content, /^extra=line1 line2$/m);
  assert.equal(content.split('\n').every((line) => !line.includes('\r')), true);
});

test('runSubcommand end-to-end (plan tier): spawns the CLI, writes summary, outputs, and state', async () => {
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const summaryFile = path.join(dir, 'summary');
  const outputFile = path.join(dir, 'output');
  const plan = { planStatus: 'FAIL', mode: 'strict', configDigest: 'd', errors: [], checks: [],
    admission: { attestation: { status: 'absent', evidence: 'none yet' }, cleanTree: { status: 'PASS', evidence: 'clean' }, preflight: { status: 'PASS' } } };
  let spawnedArgs;
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: summaryFile },
    event: {},
    spawnCli: (args) => { spawnedArgs = args; return { status: 2, stdout: `${JSON.stringify(plan)}\n`, stderr: '' }; },
  });
  assert.equal(exit, 0, 'run never fails the job for gate outcomes; finish decides');
  assert.ok(spawnedArgs.includes('--plan'));
  assert.ok(spawnedArgs.includes('--mode'));
  assert.deepEqual(spawnedArgs.slice(spawnedArgs.indexOf('--base-ref'), spawnedArgs.indexOf('--base-ref') + 2), ['--base-ref', 'origin/main']);
  const summary = readFs(summaryFile, 'utf8');
  assert.match(summary, /Closeout plan preview/);
  assert.match(summary, /absent/);
  const outputs = readFs(outputFile, 'utf8');
  assert.match(outputs, /^status=FAIL$/m);
  assert.match(outputs, /^attestation=absent$/m);
  const state = JSON.parse(readFs(path.join(outputDir, 'action-state.json'), 'utf8'));
  assert.equal(state.tier, 'plan');
  assert.equal(state.decision.success, true);
});

test('runSubcommand end-to-end (full tier): reads report.json/report.md and records the failing decision', async () => {
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const summaryFile = path.join(dir, 'summary');
  const outputFile = path.join(dir, 'output');
  const reportDir = makeTempDir();
  const reportJson = path.join(reportDir, 'report.json');
  const reportMd = path.join(reportDir, 'report.md');
  writeFs(reportJson, JSON.stringify({ overallStatus: 'FAIL', mode: 'engine', configDigest: 'd9', matrixSource: { checkCount: 1 } }));
  writeFs(reportMd, '# PR Closeout Evidence\n\n> **ENGINE MODE** banner\n');
  const exit = await runSubcommand({
    inputs: { run: 'full', mode: 'engine', prComment: 'false' },
    inputBaseRef: 'origin/main', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: summaryFile },
    event: {},
    spawnCli: () => ({ status: 2, stdout: `${JSON.stringify({ status: 'FAIL', headSha: 'h', report: { json: reportJson, markdown: reportMd } })}\n`, stderr: '' }),
  });
  assert.equal(exit, 0);
  const summary = readFs(summaryFile, 'utf8');
  assert.match(summary, /Closeout gate result/);
  assert.match(summary, /> \*\*ENGINE MODE\*\* banner/);
  const outputs = readFs(outputFile, 'utf8');
  assert.match(outputs, /^status=FAIL$/m);
  assert.match(outputs, /^mode=engine$/m);
  const state = JSON.parse(readFs(path.join(outputDir, 'action-state.json'), 'utf8'));
  assert.deepEqual([state.decision.success, state.decision.exitCode], [false, 2]);
  // Spec: full-tier COMMENTS carry key fields + an artifact pointer, never
  // the embedded report.md — the summary keeps the embed, the comment
  // rendering must not.
  assert.match(state.renderedSummary, /> \*\*ENGINE MODE\*\* banner/);
  assert.doesNotMatch(state.renderedComment, /> \*\*ENGINE MODE\*\* banner/);
  assert.match(state.renderedComment, /See report\.md in the evidence artifact/);
  assert.match(state.renderedComment, /Closeout gate result/);
});

test('runSubcommand (full tier) fails closed when report.json is missing despite a success record', async () => {
  // Integrity guard: a full tier that exited 0 (claimed success) but whose
  // report.json is missing/malformed cannot be trusted. The exit decision
  // must fail closed so finish fails the job — the rendered summary already
  // shows BLOCKED; the exit code must not contradict it by passing.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  // Point at a report.json that does NOT exist; JSON.parse/readFileSync throw.
  const bogusReport = path.join(dir, 'no-such-report.json');
  const exit = await runSubcommand({
    inputs: { run: 'full', mode: 'strict', prComment: 'false' },
    inputBaseRef: 'origin/main', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    // CLI claims success (exit 0) with a status PASS record pointing at a
    // nonexistent report.json — the wrapper must not propagate exit 0.
    spawnCli: () => ({ status: 0, stdout: `${JSON.stringify({ status: 'PASS', headSha: 'h', report: { json: bogusReport, markdown: 'report.md' } })}\n`, stderr: '' }),
  });
  assert.equal(exit, 0, 'run never fails the job; finish decides');
  const state = JSON.parse(readFs(path.join(outputDir, 'action-state.json'), 'utf8'));
  assert.equal(state.decision.success, false, 'an unverifiable success record must not PASS');
  assert.equal(state.decision.exitCode, 3);
  assert.match(state.decision.reason, /report\.json was missing, malformed, or schema-invalid/);
  // The status output must read BLOCKED, not PASS: the CLI record claimed
  // PASS but the report is unreadable, so the rendered status must agree with
  // the failing exit decision rather than contradicting it.
  const outputs = readFs(path.join(dir, 'o'), 'utf8');
  assert.match(outputs, /^status=BLOCKED$/m, 'status output must be BLOCKED when the report is unreadable');
});

test('runSubcommand (full tier) fails closed when report.json parses but is schema-invalid {}', async () => {
  // A schema-invalid report (parses as JSON but has no overallStatus, e.g. {})
  // must be treated as unreadable: JSON.parse succeeds so the earlier read/
  // parse guard does not fire, but the record is not valid gate evidence, and
  // an exit-0 PASS record must still fail closed rather than propagate success.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const reportDir = makeTempDir();
  const bogusReport = path.join(reportDir, 'report.json');
  writeFs(bogusReport, '{}'); // parses, but no overallStatus
  const exit = await runSubcommand({
    inputs: { run: 'full', mode: 'strict', prComment: 'false' },
    inputBaseRef: 'origin/main', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 0, stdout: `${JSON.stringify({ status: 'PASS', headSha: 'h', report: { json: bogusReport, markdown: 'report.md' } })}\n`, stderr: '' }),
  });
  assert.equal(exit, 0, 'run never fails the job; finish decides');
  const state = JSON.parse(readFs(path.join(outputDir, 'action-state.json'), 'utf8'));
  assert.equal(state.decision.success, false, 'a schema-invalid report must not PASS');
  assert.equal(state.decision.exitCode, 3);
  assert.match(state.decision.reason, /schema-invalid/);
});

test('the comment step sends the comment rendering, not the summary embed', async () => {
  const dir = makeTempDir();
  writeFs(path.join(dir, 'action-state.json'), JSON.stringify({
    tier: 'full', artifactName: 'ev',
    renderedSummary: '## Closeout gate result\nfields\n\n---\n\nHUGE EMBEDDED REPORT BODY',
    renderedComment: '## Closeout gate result\nfields\n\nSee report.md in the evidence artifact named above.',
    decision: { success: false, exitCode: 2 },
  }));
  const calls = [];
  await commentSubcommand({
    outputDir: dir,
    env: { GITHUB_REPOSITORY: 'o/r' },
    event: { pull_request: { number: 3 } },
    runGh: async (args) => { calls.push(args); return args.includes('POST') ? { id: 1 } : [[]]; },
  });
  const bodyArg = calls[1].find((argument) => argument.startsWith('body='));
  assert.match(bodyArg, /Closeout gate result/);
  assert.doesNotMatch(bodyArg, /HUGE EMBEDDED REPORT BODY/);
});

test('a broken preview comments only a pointer — gate error text stays in summary and artifact', async () => {
  // The CLI's top-level catch does NOT redact (its audience was a
  // terminal): raw stderr and the init-failure error can carry an embedded
  // token. The Step Summary is run-log-equivalent and keeps it; the
  // permanent, subscriber-notifying COMMENT never carries it.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: 'origin/main', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({
      status: 3,
      stdout: `${JSON.stringify({ status: 'BLOCKED', error: 'git ls-remote https://x-access-token:SECRETTOKEN@github.example failed' })}\n`,
      stderr: 'fatal: SECRETTOKEN in remote',
    }),
  });
  assert.match(readFs(path.join(dir, 's'), 'utf8'), /SECRETTOKEN/);
  const state = JSON.parse(readFs(path.join(outputDir, 'action-state.json'), 'utf8'));
  assert.doesNotMatch(state.renderedComment, /SECRETTOKEN/);
  assert.match(state.renderedComment, /preview itself failed/i);
  assert.match(state.renderedComment, /Step Summary and run log/);
});

test('a degraded engine run never labels itself strict', async () => {
  // report.json unreadable: the renderer fallback would claim strict, but
  // the action KNOWS the tier it invoked (same rule as sub-project A's
  // matrixSource tell). Machine `mode` output stays report-sourced.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  await runSubcommand({
    inputs: { run: 'full', mode: 'engine', prComment: 'false' },
    inputBaseRef: 'origin/main', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({
      status: 2,
      stdout: `${JSON.stringify({ status: 'FAIL', headSha: 'h', report: { json: path.join(dir, 'missing', 'report.json'), markdown: path.join(dir, 'missing', 'report.md') } })}\n`,
      stderr: '',
    }),
  });
  const summary = readFs(path.join(dir, 's'), 'utf8');
  assert.match(summary, /- Mode: engine/);
  assert.doesNotMatch(summary, /- Mode: strict/);
  const state = JSON.parse(readFs(path.join(outputDir, 'action-state.json'), 'utf8'));
  assert.match(state.renderedComment, /- Mode: engine/);
});

test('a spawn failure is named in the summary, not just "no JSON"', async () => {
  const dir = makeTempDir();
  await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: 'origin/main', config: '', outputDir: path.join(dir, 'e'), artifactName: 'ev',
    env: { GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: null, stdout: '', stderr: '', error: new Error('spawn node ENOENT') }),
  });
  assert.match(readFs(path.join(dir, 's'), 'utf8'), /spawn node ENOENT/);
});

test('finishSubcommand exits with the recorded decision', () => {
  const dir = makeTempDir();
  writeFs(path.join(dir, 'action-state.json'), JSON.stringify({ decision: { success: false, exitCode: 2, reason: 'gate FAIL (exit 2)' } }));
  assert.equal(finishSubcommand({ outputDir: dir }), 2);
  writeFs(path.join(dir, 'action-state.json'), JSON.stringify({ decision: { success: true, exitCode: 0, reason: 'ok' } }));
  assert.equal(finishSubcommand({ outputDir: dir }), 0);
  // Missing state means run never completed: fail closed.
  assert.equal(finishSubcommand({ outputDir: makeTempDir() }), 3);
});

test('assertOutputOutsideWorkspace rejects inside-workspace paths before any write', () => {
  const workspace = makeTempDir();
  // A path inside the workspace root (including the workspace itself) is rejected.
  assert.throws(
    () => assertOutputOutsideWorkspace({ outputDir: path.join(workspace, 'evidence'), workspace }),
    /must be outside the repository workspace/,
  );
  assert.throws(
    () => assertOutputOutsideWorkspace({ outputDir: workspace, workspace }),
    /must be outside the repository workspace/,
  );
  // A relative path resolved against the workspace root is rejected when it
  // lands inside it. `output-dir: .` in action.yml resolves under the cwd,
  // which is GITHUB_WORKSPACE on the runner.
  assert.throws(
    () => assertOutputOutsideWorkspace({ outputDir: '.', workspace }),
    /must be outside the repository workspace/,
  );
  // An escape attempt via `..` from inside the workspace is rejected too.
  assert.throws(
    () => assertOutputOutsideWorkspace({ outputDir: path.join(workspace, 'sub', '..', 'ev'), workspace }),
    /must be outside the repository workspace/,
  );
  // A genuinely outside path (a sibling temp dir) is accepted.
  const outside = makeTempDir();
  assert.doesNotThrow(() => assertOutputOutsideWorkspace({ outputDir: outside, workspace }));
  // A not-yet-existing outside path is accepted: the CLI mkdirs it later,
  // and the ancestor realpath check confirms it stays outside the workspace.
  assert.doesNotThrow(
    () => assertOutputOutsideWorkspace({ outputDir: path.join(outside, 'new-evidence'), workspace }),
  );
});

test('assertOutputOutsideWorkspace rejects an inside path reached through a symlinked workspace root', () => {
  // Regression for the symlinked-workspace bypass: when GITHUB_WORKSPACE is a
  // symlink, the physical containment check must compare the realpathed
  // output against the realpathed ROOT, not the logical root. Without that,
  // /linked-workspace/evidence (logical) maps to /real/repo/evidence
  // (physical) but the old logical root /linked-workspace hides the
  // containment. Creating a symlink requires elevated privileges on some
  // Windows hosts; skip honestly rather than fail when the platform forbids it.
  const realWorkspace = makeTempDir();
  const linkedWorkspace = path.join(tmpdir(), `closeout-link-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  try {
    symlinkSync(realWorkspace, linkedWorkspace, 'dir');
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EEXIST' || error.code === 'EACCES') {
      // Platform forbids symlink creation without developer mode/admin — the
      // regression is covered by the realpath-pair logic; skip the live test.
      return;
    }
    throw error;
  }
  // An output dir physically inside the real workspace, addressed via the
  // symlinked workspace root, must be rejected by the physical check.
  const outputDir = path.join(linkedWorkspace, 'evidence');
  assert.throws(
    () => assertOutputOutsideWorkspace({ outputDir, workspace: linkedWorkspace }),
    /must be outside the repository workspace/,
  );
});

test('runSubcommand rejects an inside-workspace output dir before mkdir or any spawn', async () => {
  const workspace = makeTempDir();
  let spawned = false;
  await assert.rejects(
    () => runSubcommand({
      inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
      inputBaseRef: '', config: '', outputDir: path.join(workspace, 'evidence'), artifactName: 'ev',
      env: { GITHUB_WORKSPACE: workspace },
      event: {},
      spawnCli: () => { spawned = true; return { status: 0, stdout: '', stderr: '' }; },
    }),
    /must be outside the repository workspace/,
  );
  assert.equal(spawned, false, 'the CLI must never be spawned for an inside-workspace output dir');
});

test('commentSubcommand upserts in PR context and skips with a notice otherwise', async () => {
  const dir = makeTempDir();
  writeFs(path.join(dir, 'action-state.json'), JSON.stringify({
    tier: 'plan', artifactName: 'ev', renderedSummary: '## Closeout plan preview\nbody', decision: { success: true, exitCode: 0 },
  }));
  const calls = [];
  const code = await commentSubcommand({
    outputDir: dir,
    env: { GITHUB_REPOSITORY: 'o/r' },
    event: { pull_request: { number: 3 } },
    runGh: async (args) => { calls.push(args); return args.includes('POST') ? { id: 1 } : []; },
  });
  assert.equal(code, 0);
  assert.equal(calls.length, 2);

  const skipped = await commentSubcommand({ outputDir: dir, env: {}, event: {}, runGh: async () => { throw new Error('must not be called'); } });
  assert.equal(skipped, 0, 'outside PR context the comment step skips, never fails');
});

test('full tier with lost stdout fails closed and still renders a summary', async () => {
  // decideExit (Task 2 round) refuses success on exit 0 with no JSON
  // record; the run step must still surface a summary, and finish applies
  // the failure — never a TypeError in a composite step.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  await runSubcommand({
    inputs: { run: 'full', mode: 'strict', prComment: 'false' },
    inputBaseRef: 'origin/main', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 0, stdout: '', stderr: '' }),
  });
  const state = JSON.parse(readFs(path.join(outputDir, 'action-state.json'), 'utf8'));
  assert.deepEqual([state.decision.success, state.decision.exitCode], [false, 3]);
  assert.match(state.decision.reason, /no JSON record/i);
  assert.match(readFs(path.join(dir, 's'), 'utf8'), /BLOCKED/);
});

test('a hostile base-ref stays one argv element — never a shell string', async () => {
  // resolveBaseRef returns input verbatim; that is safe ONLY because the CLI
  // is spawned with an argv array. Pin it (quality-review note, Task 1).
  const dir = makeTempDir();
  let spawnedArgs;
  await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: 'main --mode engine', config: '', outputDir: path.join(dir, 'e'), artifactName: 'ev',
    env: { GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: (args) => { spawnedArgs = args; return { status: 3, stdout: '{"status":"BLOCKED","error":"x"}\n', stderr: '' }; },
  });
  const at = spawnedArgs.indexOf('--base-ref');
  assert.equal(spawnedArgs[at + 1], 'main --mode engine', 'the hostile value is exactly one argv element');
  assert.equal(spawnedArgs.filter((a) => a === '--mode').length, 1, 'no injected second --mode flag');
});

test('a comment API failure propagates — the consumer opted in, silence would lie', async () => {
  const dir = makeTempDir();
  writeFs(path.join(dir, 'action-state.json'), JSON.stringify({
    tier: 'plan', artifactName: 'ev', renderedSummary: 'body', decision: { success: true, exitCode: 0 },
  }));
  await assert.rejects(
    commentSubcommand({
      outputDir: dir,
      env: { GITHUB_REPOSITORY: 'o/r' },
      event: { pull_request: { number: 3 } },
      runGh: async () => { throw new Error('gh: HTTP 403 Resource not accessible'); },
    }),
    /HTTP 403/,
  );
});
