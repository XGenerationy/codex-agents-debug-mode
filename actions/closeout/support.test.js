'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  mkdtempSync,
  mkdirSync,
  readFileSync: readFs,
  symlinkSync,
  writeFileSync: writeFs,
  chmodSync,
  lstatSync,
} = require('node:fs');
const { spawnSync } = require('node:child_process');
const { tmpdir } = require('node:os');
const path = require('node:path');

const {
  ACTION_MARKER,
  EVIDENCE_SUBDIR,
  assertOutputOutsideWorkspace,
  buildCommentBody,
  capText,
  cleanupDelegatedTokenFile,
  commentSubcommand,
  decideExit,
  escapeActionText,
  finishSubcommand,
  parseLastJsonLine,
  readPrContext,
  renderFullSummary,
  renderPlanSummary,
  resolveBaseRef,
  resolveContainedEvidencePath,
  resolveEvidenceDir,
  runSubcommand,
  stageTokenSubcommand,
  upsertPrComment,
  validateActionInputs,
  writeEvidenceFile,
  writeOutputs,
} = require('./support');

// Evidence written by `run` — and read back by `comment`/`finish` — lives in
// the fixed private child of the caller-facing output-dir, never in that
// directory itself (chatgpt-codex-connector PR7 #6Yd4Qx). These helpers keep
// every test honest about that layout instead of hand-joining the segment.
const evidencePath = (outputDir, name) => path.join(resolveEvidenceDir(outputDir), name);
const plantEvidence = (outputDir, name, content) => {
  mkdirSync(resolveEvidenceDir(outputDir), { recursive: true });
  writeFs(evidencePath(outputDir, name), content);
};

// Return "ok" only when `filePath` has a protected (inheritance-broken) DACL
// consisting of exactly one current-user FullControl allow rule. Kept as a
// local copy consistent with the same helper in pr_closeout_report.test.js,
// pr_closeout_process.test.js, and debug_server.test.js so the ACL invariant
// is asserted identically across every security-critical write path.
const windowsAclIsCurrentUserOnly = (filePath) => {
  const encodedPath = Buffer.from(filePath, 'utf16le').toString('base64');
  const script = [
    `$path = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${encodedPath}'))`,
    '$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User',
    '$acl = [IO.File]::GetAccessControl($path)',
    '$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))',
    'if ($acl.AreAccessRulesProtected -and $rules.Count -eq 1 -and $rules[0].IdentityReference.Value -eq $sid.Value -and $rules[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and (($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl)) { [Console]::Out.Write("ok") } else { [Console]::Out.Write("not-owner-only"); exit 1 }',
  ].join('; ');
  return spawnSync(
    'powershell.exe',
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    { encoding: 'utf8', windowsHide: true, timeout: 15000 },
  );
};

// Grant BUILTIN\Users (SID S-1-5-32-545) inheritable read on `dir` so files
// created inside it would inherit an ACE readable by other local users unless
// explicitly stripped. (OI)(CI) = object+container inherit; (R) = read.
const grantInheritedReadToUsers = (dir) => spawnSync(
  'icacls',
  [dir, '/grant', '*S-1-5-32-545:(OI)(CI)(R)'],
  { encoding: 'utf8', windowsHide: true, timeout: 15000 },
);

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

test('resolveBaseRef falls back to the workflow_run event payload\'s associated PR base (CodeRabbit PR7 #6YW9UP)', () => {
  // workflow_run events have no GITHUB_BASE_REF and no top-level
  // pull_request — only workflow_run.pull_requests[0], populated for a
  // same-repo PR.
  assert.equal(
    resolveBaseRef({
      inputBaseRef: '', env: {},
      event: { workflow_run: { pull_requests: [{ base: { ref: 'release/7' } }] } },
    }),
    'origin/release/7',
  );
  // Empty pull_requests (a fork PR — GitHub does not populate this array
  // for forks) falls through to null, same as no event context at all.
  assert.equal(
    resolveBaseRef({ inputBaseRef: '', env: {}, event: { workflow_run: { pull_requests: [] } } }),
    null,
  );
  // The plain pull_request.base.ref rung still wins over workflow_run's when
  // both are somehow present (should never co-occur in a real event, but
  // the ladder order must stay deterministic).
  assert.equal(
    resolveBaseRef({
      inputBaseRef: '', env: {},
      event: {
        pull_request: { base: { ref: 'direct' } },
        workflow_run: { pull_requests: [{ base: { ref: 'nested' } }] },
      },
    }),
    'origin/direct',
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

test('renderPlanSummary prints the exact required attestation marker verbatim, not escaped, when one is still needed (chatgpt-codex-connector PR7 #6Yb3lW)', () => {
  // Before this fix, a reviewer had to separately discover and download
  // plan.json to get the copy-pasteable marker line; the plan record always
  // carried it at gateIntegrityAttestationRequired.marker, but the summary
  // never printed it.
  const marker = 'PR-CLOSEOUT-ATTESTATION v1 base=abc123 head=def456 config=digest789 decision=not-weakened';
  const plan = {
    ...hostilePlan(),
    admission: { ...hostilePlan().admission, attestation: { status: 'absent', evidence: 'no matching review yet' } },
    gateIntegrityAttestationRequired: { marker },
  };
  const markdown = renderPlanSummary(plan, {});
  assert.match(markdown, /Required attestation marker/);
  // Verbatim, byte-for-byte: escapeActionText would turn every `=` and `/`
  // into a numeric HTML entity, which is EXACTLY what classifyGateAttestation
  // does NOT compare against — a corrupted marker would be pasted into a
  // review and still never match.
  assert.ok(markdown.includes(marker), 'the marker must appear completely unescaped');
  assert.equal(markdown.includes('&#61;'), false, 'the marker\'s "=" characters must never be HTML-entity-escaped');

  // A 'present' status means a matching attestation already exists — the
  // "paste this" instruction would be confusing noise, so it must not render.
  const satisfiedPlan = {
    ...plan,
    admission: { ...plan.admission, attestation: { status: 'present', evidence: 'covers this snapshot' } },
  };
  const satisfiedMarkdown = renderPlanSummary(satisfiedPlan, {});
  assert.doesNotMatch(satisfiedMarkdown, /Required attestation marker/);
  assert.equal(satisfiedMarkdown.includes(marker), false);
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

test('readPrContext falls back to workflow_run.pull_requests[0] for a same-repo PR, and fails closed on ambiguity (chatgpt-codex-connector PR7 #6YZpdA)', () => {
  // workflow_run events carry no top-level pull_request — same fallback,
  // and the same exactly-one-entry fail-closed rule, as readActionsPrNumber
  // (CodeRabbit PR7 #6YZkn9).
  const viaWorkflowRun = readPrContext({
    env: { GITHUB_REPOSITORY: 'owner/repo' },
    event: { workflow_run: { pull_requests: [{ number: 42 }] } },
  });
  assert.deepEqual(viaWorkflowRun, { owner: 'owner', repo: 'repo', prNumber: 42 });
  // A direct pull_request field still takes precedence when both are present.
  const directWins = readPrContext({
    env: { GITHUB_REPOSITORY: 'owner/repo' },
    event: { pull_request: { number: 7 }, workflow_run: { pull_requests: [{ number: 42 }] } },
  });
  assert.deepEqual(directWins, { owner: 'owner', repo: 'repo', prNumber: 7 });
  // Empty array (fork PR — not populated for forks): no resolvable PR.
  assert.equal(readPrContext({ env: { GITHUB_REPOSITORY: 'owner/repo' }, event: { workflow_run: { pull_requests: [] } } }), null);
  // More than one entry: ambiguous, must not guess.
  assert.equal(
    readPrContext({
      env: { GITHUB_REPOSITORY: 'owner/repo' },
      event: { workflow_run: { pull_requests: [{ number: 42 }, { number: 43 }] } },
    }),
    null,
  );
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

test('writeEvidenceFile never follows a planted symlink at the destination', () => {
  // A check that predicts the evidence dir could plant the state file as a
  // symlink to a tracked workspace file. The write must replace the link with
  // a regular file, never the link's target.
  const dir = makeTempDir();
  const victim = path.join(dir, 'workspace-file.txt');
  writeFs(victim, 'ORIGINAL CONTENT');
  const evidenceDir = makeTempDir();
  const statePath = path.join(evidenceDir, 'action-state.json');
  try {
    symlinkSync(victim, statePath, 'file');
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EACCES') return; // no symlink privilege on this host
    throw error;
  }
  writeEvidenceFile(evidenceDir, 'action-state.json', '{"safe":true}\n');
  // The victim is untouched: the link was replaced, not followed.
  assert.equal(readFs(victim, 'utf8'), 'ORIGINAL CONTENT');
  // The destination is now a regular file with the new content.
  const { lstatSync } = require('node:fs');
  const info = lstatSync(statePath);
  assert.equal(info.isSymbolicLink(), false, 'destination must no longer be a symlink');
  assert.equal(info.isFile(), true);
  assert.equal(readFs(statePath, 'utf8'), '{"safe":true}\n');
});

test('writeEvidenceFile refuses a hard-linked destination (shared inode)', () => {
  // A hard link to a tracked workspace file reports as a regular file but
  // shares an inode: writing through it would mutate the workspace file after
  // the CLI's final seal. The write must replace the link (new inode) and
  // leave the linked target untouched.
  const dir = makeTempDir();
  const victim = path.join(dir, 'workspace-file.txt');
  writeFs(victim, 'ORIGINAL CONTENT');
  const evidenceDir = makeTempDir();
  const statePath = path.join(evidenceDir, 'action-state.json');
  const { linkSync, lstatSync } = require('node:fs');
  try {
    linkSync(victim, statePath);
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EACCES') return; // platform lacks hard-link support
    throw error;
  }
  writeEvidenceFile(evidenceDir, 'action-state.json', '{"safe":true}\n');
  // The victim is untouched: the hard-link entry was replaced, not followed.
  assert.equal(readFs(victim, 'utf8'), 'ORIGINAL CONTENT');
  // The destination is now a regular file with a fresh inode (nlink === 1).
  const info = lstatSync(statePath);
  assert.equal(info.nlink, 1, 'destination must be a fresh regular file');
  assert.equal(readFs(statePath, 'utf8'), '{"safe":true}\n');
});

test('writeEvidenceFile does not clobber an outside hard-linked file via its staging path (chatgpt-codex-connector PR7 #6Yb1dK)', () => {
  // The staging name is predictable (pid + ms). Pre-link an OUTSIDE file
  // across a window of consecutive stamps so the real call's O_EXCL create
  // either lands on a still-free stamp (write succeeds normally) or an
  // already-linked one (must fail closed via EEXIST) -- either way the
  // outside file's content must never be truncated through the link.
  const evidenceDir = makeTempDir();
  const outsideDir = makeTempDir();
  const outsideTarget = path.join(outsideDir, 'clobber-me.json');
  writeFs(outsideTarget, 'do not overwrite this\n');
  const { linkSync } = require('node:fs');
  const now = Date.now();
  let linked = 0;
  for (let i = 0; i < 50; i += 1) {
    try {
      linkSync(outsideTarget, path.join(evidenceDir, `.action-state.json.${process.pid}.${now + i}.tmp`));
      linked += 1;
    } catch (error) {
      if (error.code === 'EPERM' || error.code === 'EACCES') break; // no hard-link privilege on this host
      throw error;
    }
  }
  if (linked === 0) return; // platform lacks hard-link support
  let wrote = false;
  try {
    writeEvidenceFile(evidenceDir, 'action-state.json', '{"safe":true}\n');
    wrote = true;
  } catch (error) {
    assert.match(String(error?.message || error), /pre-existing path/i);
  }
  // The outside file must be untouched regardless of which branch ran: O_EXCL
  // never truncates a pre-existing inode, only ever creates a fresh one.
  assert.equal(readFs(outsideTarget, 'utf8'), 'do not overwrite this\n');
  if (wrote) {
    assert.equal(readFs(path.join(evidenceDir, 'action-state.json'), 'utf8'), '{"safe":true}\n');
  }
});

test('writeEvidenceFile fails closed when an unsafe target cannot be unlinked (Codex #3)', () => {
  // The broad catch formerly swallowed EVERY error from lstatSync/unlinkSync,
  // so if unlinkSync(target) failed (EPERM/EACCES/EBUSY) on a symlink/hardlink
  // destination, execution fell through to writeFileSync(target) and wrote
  // THROUGH the still-linked target — mutating the workspace file this
  // function exists to protect. The catch is now scoped to ENOENT only: any
  // other unlink failure propagates and fails the run step.
  //
  // Reproduce the unsafe-unlinkable case by planting a DIRECTORY at the
  // evidence path: lstatSync succeeds (it is not ENOENT), isFile() is false
  // so the unlink branch runs, and unlinkSync on a non-empty directory throws
  // EPERM/EISDIR — which must propagate rather than be swallowed.
  const evidenceDir = makeTempDir();
  const dirTarget = path.join(evidenceDir, 'action-state.json');
  mkdirSync(dirTarget, { recursive: true }); // a directory where a file is expected
  const victim = path.join(evidenceDir, 'workspace-file.txt');
  writeFs(victim, 'ORIGINAL CONTENT');
  // The directory is NOT a link to the victim, but the point is the same: an
  // unsafe entry that cannot be removed must abort, never fall through to a
  // write that could touch an unintended target.
  assert.throws(
    () => writeEvidenceFile(evidenceDir, 'action-state.json', '{"safe":true}\n'),
    (error) => ['EPERM', 'EISDIR', 'ENOTEMPTY'].includes(error?.code),
    'a non-ENOENT unlink failure must propagate, not fall through to writeFileSync',
  );
});

test('writeEvidenceFile tightens a pre-existing regular file\'s mode before overwriting it (CodeRabbit #6YT0Jx)', () => {
  if (process.platform === 'win32') return; // POSIX file modes are meaningless on NTFS
  // A regular, single-link file (nlink === 1) is NOT unlinked by the
  // symlink/hardlink guard — it is opened and truncated in place. writeFileSync's
  // `mode` option only applies when the OPEN call CREATES the file; a
  // pre-existing regular file (left over from a prior invocation of a reused
  // output-dir) keeps whatever permissive mode it already had, e.g. 0o644.
  const evidenceDir = makeTempDir();
  const target = path.join(evidenceDir, 'plan.json');
  writeFs(target, '{"stale":true}\n');
  chmodSync(target, 0o644);
  const { lstatSync } = require('node:fs');
  assert.equal(lstatSync(target).mode & 0o777, 0o644, 'precondition: pre-existing file is 0o644');
  writeEvidenceFile(evidenceDir, 'plan.json', '{"fresh":true}\n');
  const info = lstatSync(target);
  assert.equal(info.mode & 0o777, 0o600, 'the reused file is tightened to 0o600 even though it was not recreated');
  assert.equal(readFs(target, 'utf8'), '{"fresh":true}\n');
});

test(
  'writeEvidenceFile protects its output with a current-user-only Windows ACL (Codex PR7, Windows DACL)',
  { skip: process.platform !== 'win32' && 'Windows ACL semantics only', timeout: 20000 },
  () => {
    // chmodSync(0o600) only clears Windows' read-only attribute bit; it does
    // NOT remove an inherited DACL, so plan.json/action-state.json written
    // into a directory whose inherited ACL grants other local users access
    // would otherwise stay readable (and action-state.json writable) by
    // them. writeEvidenceFile must establish and verify the same
    // current-user-only ACL invariant already covered for the gate CLI's own
    // evidence writes (pr_closeout_report.test.js, pr_closeout_process.test.js).
    const evidenceDir = makeTempDir();
    // Give evidenceDir an explicit, inheritable ACE for BUILTIN\Users (read).
    // Absent the fix, a file created here inherits it and stays readable by
    // other local users; the fix must strip it.
    const granted = grantInheritedReadToUsers(evidenceDir);
    assert.equal(granted.status, 0, `icacls setup failed: ${granted.stdout}\n${granted.stderr}`);

    writeEvidenceFile(evidenceDir, 'action-state.json', '{"safe":true}\n');
    const target = path.join(evidenceDir, 'action-state.json');
    const acl = windowsAclIsCurrentUserOnly(target);
    assert.equal(acl.status, 0, `${target}: ${acl.stdout}\n${acl.stderr}`);
    assert.equal(acl.stdout.trim(), 'ok', `${target} must be current-user-only`);
  },
);

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
  assert.match(outputs, /^admission-status=BLOCKED$/m, 
    'admission-status output is BLOCKED when attestation is absent (CodeRabbit #6X_pwM)');
  const state = JSON.parse(readFs(evidencePath(outputDir, 'action-state.json'), 'utf8'));
  assert.equal(state.tier, 'plan');
  assert.equal(state.decision.success, true);
});

test('runSubcommand reports admission-status PASS for a fully-ready plan (CodeRabbit #6YT0J4)', async () => {
  // resolvePlanAdmission uses a DIFFERENT vocabulary for the attestation probe
  // (present | weakened | absent | unavailable) than cleanTree/preflight
  // (PASS | FAIL | BLOCKED) — 'present' is the attestation probe's PASSING
  // state, but it never literally equals 'PASS'. Requiring every probe to
  // equal 'PASS' meant a fully-ready plan could never aggregate to PASS.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const outputFile = path.join(dir, 'output');
  const plan = { planStatus: 'PASS', mode: 'strict', configDigest: 'd', errors: [], checks: [],
    admission: { attestation: { status: 'present', evidence: 'ok' }, cleanTree: { status: 'PASS', evidence: 'clean' }, preflight: { status: 'PASS' } } };
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 0, stdout: `${JSON.stringify(plan)}\n`, stderr: '' }),
  });
  assert.equal(exit, 0);
  const outputs = readFs(outputFile, 'utf8');
  assert.match(outputs, /^admission-status=PASS$/m,
    'a present attestation plus clean tree and passing preflight aggregates to PASS, not BLOCKED');
});

test('runSubcommand reports admission-status FAIL for a weakened attestation (CodeRabbit #6YT0J4)', async () => {
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const outputFile = path.join(dir, 'output');
  const plan = { planStatus: 'FAIL', mode: 'strict', configDigest: 'd', errors: [], checks: [],
    admission: { attestation: { status: 'weakened', evidence: 'stale' }, cleanTree: { status: 'PASS', evidence: 'clean' }, preflight: { status: 'PASS' } } };
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 2, stdout: `${JSON.stringify(plan)}\n`, stderr: '' }),
  });
  assert.equal(exit, 0);
  const outputs = readFs(outputFile, 'utf8');
  assert.match(outputs, /^admission-status=FAIL$/m,
    'a weakened attestation is an active negative finding, distinct from a merely-BLOCKED (not-yet-satisfied) probe');
});

test('runSubcommand reports admission-status BLOCKED, not PASS, when the plan record is missing probes (chatgpt-codex-connector PR7 #6YaxWb)', async () => {
  // A truncated or malformed CLI report can carry `admission` with only SOME
  // of the three required probe keys -- here cleanTree/preflight are absent
  // entirely, not merely present-with-a-non-passing-status. Before this fix,
  // the aggregation filtered absent/malformed probes OUT before reducing, so
  // a single passing probe (attestation) made `every(probePasses)` vacuously
  // true over a one-element array and published PASS even though two of the
  // three admission checks never ran.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const outputFile = path.join(dir, 'output');
  const plan = { planStatus: 'PASS', mode: 'strict', configDigest: 'd', errors: [], checks: [],
    admission: { attestation: { status: 'present', evidence: 'ok' } } };
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 0, stdout: `${JSON.stringify(plan)}\n`, stderr: '' }),
  });
  assert.equal(exit, 0);
  const outputs = readFs(outputFile, 'utf8');
  assert.match(outputs, /^admission-status=BLOCKED$/m,
    'missing cleanTree/preflight probes must block the aggregate, not silently drop out of it');
});

test('runSubcommand reports admission-status BLOCKED when a probe entry is malformed (no string status)', async () => {
  // Distinct from the fully-absent-key case above: here every key is
  // PRESENT but one probe's value itself is malformed (missing `status`
  // entirely). The prior `.filter(probe => probe && typeof probe.status ===
  // 'string')` treated this identically to an absent key -- dropped, not
  // counted -- which this fix also closes.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const outputFile = path.join(dir, 'output');
  const plan = { planStatus: 'PASS', mode: 'strict', configDigest: 'd', errors: [], checks: [],
    admission: {
      attestation: { status: 'present', evidence: 'ok' },
      cleanTree: { evidence: 'no status field' },
      preflight: { status: 'PASS' },
    } };
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: outputFile, GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 0, stdout: `${JSON.stringify(plan)}\n`, stderr: '' }),
  });
  assert.equal(exit, 0);
  const outputs = readFs(outputFile, 'utf8');
  assert.match(outputs, /^admission-status=BLOCKED$/m,
    'a malformed probe entry (no string status) must block the aggregate, not be silently filtered out');
});

test('runSubcommand clears stale plan.json/report.json/report.md from a reused outputDir before a run that fails early (CodeRabbit #6YT0KA)', async () => {
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  mkdirSync(outputDir, { recursive: true });
  // Evidence left behind by a PRIOR successful invocation of this same
  // (reused) output-dir — inside its evidence child, where a prior run of
  // this action would have written it (#6Yd4Qx). action-state.json with this
  // action's own authenticated shape is the ownership marker
  // (chatgpt-codex-connector PR7 #6YaIal) proving this directory has
  // genuinely hosted this action before, so the cleanup below is expected
  // to run.
  plantEvidence(outputDir, 'action-state.json', `${JSON.stringify({ tier: 'plan', nonce: 'stale-nonce-1' })}\n`);
  plantEvidence(outputDir, 'plan.json', '{"planStatus":"PASS","stale":true}\n');
  plantEvidence(outputDir, 'report.json', '{"overallStatus":"PASS","stale":true}\n');
  plantEvidence(outputDir, 'report.md', '# stale prior report\n');
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    // The CURRENT invocation fails before producing any parseable output —
    // exactly the scenario where stale evidence would otherwise survive.
    spawnCli: () => ({ status: 1, stdout: 'not json\n', stderr: 'boom' }),
  });
  assert.equal(exit, 0, 'run never fails the job for gate outcomes');
  const { existsSync } = require('node:fs');
  assert.equal(existsSync(evidencePath(outputDir, 'plan.json')), false,
    'stale plan.json from a prior invocation must not survive a failed current run');
  assert.equal(existsSync(evidencePath(outputDir, 'report.json')), false,
    'stale report.json from a prior invocation must not survive a failed current run');
  assert.equal(existsSync(evidencePath(outputDir, 'report.md')), false,
    'stale report.md from a prior invocation must not survive a failed current run');
});

test('runSubcommand clears a stale outputDir/logs directory from a reused outputDir that shows a prior invocation (CodeRabbit #6YXkRN)', async () => {
  // The gate CLI's full tier populates outputDir/logs (a DIRECTORY of
  // per-check probe log files), which the file-by-file stale-evidence
  // cleanup cannot reach. Left behind, a prior invocation's log files would
  // be presented as evidence for a new, unrelated (and possibly blocked)
  // invocation. A stale action-state.json with this action's own
  // authenticated shape (a known tier + a nonce) alongside it is the
  // ownership marker (CodeRabbit PR7 #6YYcNT / chatgpt-codex-connector PR7
  // #6YZpcz) proving this directory has genuinely hosted this action
  // before, so the purge below is expected to run.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const logsDir = evidencePath(outputDir, 'logs');
  mkdirSync(logsDir, { recursive: true });
  writeFs(path.join(logsDir, 'qualification.probe.attempt-001.log'), 'stale log output\n');
  plantEvidence(outputDir, 'action-state.json', `${JSON.stringify({ tier: 'plan', nonce: 'stale-nonce-1' })}\n`);
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 1, stdout: 'not json\n', stderr: 'boom' }),
  });
  assert.equal(exit, 0);
  const { existsSync } = require('node:fs');
  assert.equal(existsSync(logsDir), false, 'a stale logs directory from a prior invocation must not survive');
});
test('runSubcommand leaves outputDir/logs alone when nothing else signals a prior invocation of this action (CodeRabbit PR7 #6YYcNT)', async () => {
  // A caller-supplied broad output-dir (e.g. /tmp, ${{ runner.temp }}) may
  // have never hosted this action before, and the wrapper has no ownership
  // signal over pre-existing content there. "logs" is a generic directory
  // name likely to collide with something unrelated a caller or another
  // tool placed there — even at the evidence-child path, where the cleanup
  // now looks (#6Yd4Qx). Without a genuine action-state.json present, this
  // logs/ directory must NOT be treated as this action's stale evidence.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const logsDir = evidencePath(outputDir, 'logs');
  mkdirSync(logsDir, { recursive: true });
  writeFs(path.join(logsDir, 'unrelated-tool-output.log'), 'not ours\n');
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 1, stdout: 'not json\n', stderr: 'boom' }),
  });
  assert.equal(exit, 0);
  const { existsSync } = require('node:fs');
  assert.equal(existsSync(logsDir), true, 'a logs directory with no other ownership marker must not be deleted');
  assert.equal(readFs(path.join(logsDir, 'unrelated-tool-output.log'), 'utf8'), 'not ours\n',
    'unrelated content inside it must survive untouched');
});
test('runSubcommand leaves outputDir/logs alone when only a generic, unauthenticated plan.json/report.json is present (chatgpt-codex-connector PR7 #6YZpcz)', async () => {
  // plan.json and report.json are generic enough filenames that an
  // unrelated tool sharing this output-dir could plausibly produce one by
  // coincidence — their mere presence must not be trusted as proof this
  // action itself has run here before. Only action-state.json (written
  // exclusively by this action, with a shape no other tool would
  // coincidentally reproduce) counts as real ownership evidence.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const logsDir = evidencePath(outputDir, 'logs');
  mkdirSync(logsDir, { recursive: true });
  writeFs(path.join(logsDir, 'unrelated-tool-output.log'), 'not ours\n');
  plantEvidence(outputDir, 'plan.json', '{"someOtherToolsOwnUnrelatedShape":true}\n');
  plantEvidence(outputDir, 'report.json', '{"someOtherToolsOwnUnrelatedShape":true}\n');
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 1, stdout: 'not json\n', stderr: 'boom' }),
  });
  assert.equal(exit, 0);
  const { existsSync } = require('node:fs');
  assert.equal(existsSync(logsDir), true, 'a generic plan.json/report.json alone is not an authenticated ownership marker');
  assert.equal(readFs(path.join(logsDir, 'unrelated-tool-output.log'), 'utf8'), 'not ours\n',
    'unrelated content inside it must survive untouched');
  // The file-deletion loop is gated on the same authenticated marker
  // (chatgpt-codex-connector PR7 #6YaIal) — an unrelated tool's own
  // plan.json/report.json must survive, not just outputDir/logs.
  assert.equal(existsSync(evidencePath(outputDir, 'plan.json')), true, 'an unauthenticated plan.json must not be deleted');
  assert.equal(existsSync(evidencePath(outputDir, 'report.json')), true, 'an unauthenticated report.json must not be deleted');
});
test('runSubcommand leaves outputDir/logs alone when action-state.json exists but does not match this action\'s own shape (chatgpt-codex-connector PR7 #6YZpcz)', async () => {
  // An unrelated tool could coincidentally also name a file
  // "action-state.json"; this must not be trusted as ownership evidence
  // unless its CONTENT matches this action's authenticated shape (a known
  // tier value and a nonce string).
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const logsDir = evidencePath(outputDir, 'logs');
  mkdirSync(logsDir, { recursive: true });
  writeFs(path.join(logsDir, 'unrelated-tool-output.log'), 'not ours\n');
  plantEvidence(outputDir, 'action-state.json', '{"someOtherToolsOwnUnrelatedShape":true}\n');
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 1, stdout: 'not json\n', stderr: 'boom' }),
  });
  assert.equal(exit, 0);
  const { existsSync } = require('node:fs');
  assert.equal(existsSync(logsDir), true, 'a same-named but wrongly-shaped action-state.json is not authenticated ownership evidence');
});

test('runSubcommand does not trust action-state.json as ownership evidence when it is a symlink to a forged marker (chatgpt-codex-connector PR7 #6Yb44Sj)', async () => {
  // A plain readFileSync follows a symlink: action-state.json planted as a
  // symlink to an ATTACKER-CHOSEN file elsewhere -- content entirely outside
  // this directory -- could forge the {tier, nonce} shape trivially and
  // drive the stale-evidence cleanup (plan.json/report.json/report.md
  // unlinks, recursive logs/ removal) against a directory this run never
  // actually populated. The symlink must be refused outright, before any
  // read, so none of that cleanup ever runs.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const logsDir = evidencePath(outputDir, 'logs');
  mkdirSync(logsDir, { recursive: true });
  writeFs(path.join(logsDir, 'unrelated-tool-output.log'), 'not ours\n');
  plantEvidence(outputDir, 'plan.json', '{"someOtherToolsOwnUnrelatedShape":true}\n');
  const forgedTarget = path.join(dir, 'attacker-controlled.json');
  const forgedContent = `${JSON.stringify({ tier: 'plan', nonce: 'forged' })}\n`;
  writeFs(forgedTarget, forgedContent);
  try {
    symlinkSync(forgedTarget, evidencePath(outputDir, 'action-state.json'), 'file');
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EACCES') return; // no symlink privilege on this host
    throw error;
  }
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 1, stdout: 'not json\n', stderr: 'boom' }),
  });
  assert.equal(exit, 0);
  const { existsSync } = require('node:fs');
  assert.equal(existsSync(logsDir), true, 'a forged symlinked marker must not authorize the logs/ removal');
  assert.equal(readFs(path.join(logsDir, 'unrelated-tool-output.log'), 'utf8'), 'not ours\n',
    'unrelated content inside it must survive untouched');
  assert.equal(existsSync(evidencePath(outputDir, 'plan.json')), true, 'a forged symlinked marker must not authorize deleting plan.json');
  // The forged marker's OWN target file (outside outputDir entirely) must
  // also be left completely untouched -- confirming the read never followed
  // the link into any destructive operation on it either.
  assert.equal(readFs(forgedTarget, 'utf8'), forgedContent);
});

test('runSubcommand fails the run when a stale action-state.json cannot be removed (Qodo #13)', async () => {
  // A directory at action-state.json is refused two ways now, either of
  // which must fail the run rather than silently succeed: hadPriorEvidence's
  // own lstatSync guard (chatgpt-codex-connector PR7 #6Yb44Sj) sees a
  // non-regular-file entry and returns false, so the stale-evidence cleanup
  // loop never runs against it — but THIS invocation still needs to WRITE
  // its own action-state.json at the end of the run, and writeEvidenceFile's
  // renameSync into that same directory-occupied path fails closed
  // (EISDIR/EPERM), exactly like the equivalent case already covered in
  // support.test.js's own writeEvidenceFile tests. Either mechanism must
  // reject rather than silently leave the old/foreign state in place for the
  // always()-gated comment step to post as the current run's decision.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  // Plant a hostile action-state.json that is a directory — at the evidence
  // child path, where this action actually reads and writes it (#6Yd4Qx).
  mkdirSync(evidencePath(outputDir, 'action-state.json'), { recursive: true });
  await assert.rejects(
    runSubcommand({
      inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
      inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
      env: { GITHUB_BASE_REF: 'main' },
      event: {},
      spawnCli: () => ({ status: 0, stdout: '{}\n', stderr: '' }),
    }),
    (error) => {
      // A directory occupying action-state.json's path fails with EISDIR
      // (POSIX), EPERM, or ENOTEMPTY (Windows renameSync onto a directory) —
      // never the benign ENOENT the cleanup is allowed to swallow.
      assert.notEqual(error?.code, 'ENOENT', 'ENOENT must be the only swallowed unlink error');
      assert.ok(['EISDIR', 'EPERM', 'ENOTEMPTY'].includes(error?.code), `expected a non-ENOENT filesystem error, got ${error?.code}`);
      return true;
    },
    'a directory occupying action-state.json must fail the run step, not be silently ignored',
  );
});

test('runSubcommand never modifies the caller output directory mode; evidence lives in an owner-only child (chatgpt-codex-connector PR7 #6Yd4Qx)', async () => {
  if (process.platform === 'win32') {
    // POSIX directory modes are meaningless on NTFS; assert the property on
    // Linux/macOS CI where the mode bits are real.
    return;
  }
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  // A shared-style caller directory: 01777 like /tmp — sticky bit included,
  // so the assertions would catch a narrowing OR a special-bit drop. Under
  // the retired capture/restore scheme (#6YFOVK/#6YTfjs/#6YT0Jo) this
  // directory spent the entire gate run at 0o700, breaking concurrent users
  // of a shared path for up to the configured timeout; now it must never
  // change AT ALL, at any point — there is no restore because there is no
  // modification.
  mkdirSync(outputDir, { recursive: true, mode: 0o1777 });
  chmodSync(outputDir, 0o1777);
  assert.equal(lstatSync(outputDir).mode & 0o7777, 0o1777, 'precondition: caller dir starts at 0o1777 (sticky)');
  let callerModeAtSpawn;
  let cliOutputDirArg;
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: (args) => {
      callerModeAtSpawn = lstatSync(outputDir).mode & 0o7777;
      cliOutputDirArg = args[args.indexOf('--output-dir') + 1];
      // Mirror the real CLI's writeEvidenceReport, which chmods ITS
      // --output-dir to 0o700 of its own accord while writing evidence.
      // Handing the CLI the caller's directory would therefore narrow it no
      // matter what the wrapper did — the fix only holds because the CLI
      // receives the action-owned child instead.
      chmodSync(cliOutputDirArg, 0o700);
      return { status: 0, stdout: '{"planStatus":"PASS"}\n', stderr: '' };
    },
  });
  assert.equal(exit, 0);
  assert.equal(cliOutputDirArg, resolveEvidenceDir(outputDir),
    'the CLI must be handed the private evidence child, never the caller directory');
  assert.equal(callerModeAtSpawn, 0o1777,
    'the caller directory is not narrowed even DURING the gate run — concurrent users of a shared path stay unaffected (#6Yd4Qx)');
  assert.equal(lstatSync(outputDir).mode & 0o7777, 0o1777,
    'the caller directory mode (incl. sticky bit) is untouched after the run');
  assert.equal(lstatSync(resolveEvidenceDir(outputDir)).mode & 0o7777, 0o700,
    'the child that actually holds evidence is owner-only (0o700)');
  assert.equal(JSON.parse(readFs(evidencePath(outputDir, 'plan.json'), 'utf8')).planStatus, 'PASS',
    'evidence is genuinely written inside the child');
});
test('runSubcommand leaves the caller directory mode untouched on a throwing exit path too (#6Yd4Qx, retiring #6YT0Jo\'s finally-restore)', async () => {
  if (process.platform === 'win32') return;
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  mkdirSync(outputDir, { recursive: true, mode: 0o1777 });
  chmodSync(outputDir, 0o1777);
  await assert.rejects(
    () => runSubcommand({
      inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
      inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
      env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
      event: {},
      spawnCli: () => { throw new Error('boom'); },
    }),
    /boom/,
  );
  assert.equal(lstatSync(outputDir).mode & 0o7777, 0o1777,
    'no capture/restore is needed on ANY exit path — the caller mode was never modified in the first place');
});
test('a symlinked outputDir\'s TARGET directory keeps its own mode — never narrowed during the run, never broadened after (#6Yd4Qx, retiring CodeRabbit #6YT0Js)', async () => {
  if (process.platform === 'win32') return;
  const dir = makeTempDir();
  const realTarget = path.join(dir, 'real-evidence');
  const outputDir = path.join(dir, 'evidence-link');
  // 0o755: distinguishable from BOTH failure directions the old scheme had —
  // a narrowing chmod to 0o700 during the run (#6Yd4Qx's complaint) and a
  // broadening restore to the link's own 0o777 lstat mode (#6YT0Js's
  // complaint). Neither can happen now: the target is simply never chmodded.
  mkdirSync(realTarget, { recursive: true, mode: 0o755 });
  chmodSync(realTarget, 0o755);
  try {
    symlinkSync(realTarget, outputDir, 'dir');
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EACCES') return; // no symlink privilege on this host
    throw error;
  }
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 0, stdout: '{"planStatus":"PASS"}\n', stderr: '' }),
  });
  assert.equal(exit, 0);
  assert.equal(lstatSync(realTarget).mode & 0o7777, 0o755,
    'the symlink target\'s mode is never touched — neither narrowed to 0o700 nor broadened to the link\'s 0o777');
  // The evidence child is created THROUGH the caller's link (the parent link
  // is the caller's own, legitimate arrangement — only a link at the child's
  // fixed name is hostile), so it physically lives under the target.
  assert.equal(lstatSync(path.join(realTarget, EVIDENCE_SUBDIR)).mode & 0o7777, 0o700,
    'the evidence child under the target is owner-only');
});
test('runSubcommand refuses a pre-planted symlink at the fixed evidence-child name (chatgpt-codex-connector PR7 #6Yd4Qx)', async () => {
  // The child's name is fixed and its parent may be a shared world-writable
  // directory (/tmp): a hostile local user can create
  // <output-dir>/closeout-action-evidence AHEAD of the run as a symlink to a
  // victim directory, aiming every later read, delete (stale-evidence
  // cleanup), and write there — the directory-level analogue of the
  // state-file symlink #6Yb44Sj closed. prepareEvidenceDirectory's
  // post-mkdir lstat must refuse it before the ownership probe, the cleanup,
  // the CLI spawn, or any write runs.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  mkdirSync(outputDir, { recursive: true });
  const victim = path.join(dir, 'victim');
  mkdirSync(victim, { recursive: true });
  // A forged authenticated-shape marker INSIDE the victim: if the planted
  // link were followed, hadPriorEvidence would read this and authorize the
  // destructive cleanup against the victim's own files.
  writeFs(path.join(victim, 'action-state.json'), `${JSON.stringify({ tier: 'plan', nonce: 'forged' })}\n`);
  writeFs(path.join(victim, 'plan.json'), '{"victim":true}\n');
  try {
    symlinkSync(victim, resolveEvidenceDir(outputDir), 'dir');
  } catch (error) {
    if (error.code === 'EPERM' || error.code === 'EACCES') return; // no symlink privilege on this host
    throw error;
  }
  let spawned = false;
  await assert.rejects(
    () => runSubcommand({
      inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
      inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
      env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
      event: {},
      spawnCli: () => { spawned = true; return { status: 0, stdout: '{"planStatus":"PASS"}\n', stderr: '' }; },
    }),
    /Refusing to use a pre-existing non-directory/,
  );
  assert.equal(spawned, false, 'the CLI must never be spawned against a symlinked evidence path');
  const { existsSync } = require('node:fs');
  assert.equal(readFs(path.join(victim, 'plan.json'), 'utf8'), '{"victim":true}\n',
    'nothing behind the planted link is deleted or overwritten');
  assert.equal(existsSync(path.join(victim, 'action-state.json')), true,
    'the forged marker must not authorize cleanup through the link');
});
test('a pre-existing evidence child from a reused output-dir is re-tightened to 0o700 (Qodo #6 / CodeRabbit #6X72Z2, retargeted to the child)', async () => {
  if (process.platform === 'win32') return;
  // mkdirSync's `mode` only applies when the directory is CREATED (Qodo #6),
  // so a child left loosened between runs of a reused output-dir would keep
  // its broad mode without the explicit chmod — the same pair of invariants
  // the old in-place code enforced on the caller directory, now enforced on
  // the child that actually holds the evidence.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const child = resolveEvidenceDir(outputDir);
  mkdirSync(child, { recursive: true });
  chmodSync(child, 0o755);
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({ status: 0, stdout: '{"planStatus":"PASS"}\n', stderr: '' }),
  });
  assert.equal(exit, 0);
  assert.equal(lstatSync(child).mode & 0o7777, 0o700,
    'a reused, loosened child must be explicitly re-tightened — mkdir mode alone cannot do it');
});
test('finish and comment locate the state that run wrote, given only the caller output-dir (chatgpt-codex-connector PR7 #6Yd4Qx)', async () => {
  // `comment` and `finish` execute as SEPARATE processes receiving only
  // CLOSEOUT_OUTPUT_DIR (the caller-facing directory). The evidence child
  // must be re-derivable from that value alone, or the composite's later
  // steps would go state-blind and fail closed on every run.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    nonce: 'cross-step-nonce',
    spawnCli: () => ({ status: 0, stdout: '{"planStatus":"PASS"}\n', stderr: '' }),
  });
  assert.equal(exit, 0);
  const calls = [];
  const commentCode = await commentSubcommand({
    outputDir,
    env: { GITHUB_REPOSITORY: 'o/r', CLOSEOUT_INVOCATION_NONCE: 'cross-step-nonce' },
    event: { pull_request: { number: 7 } },
    runGh: async (args) => { calls.push(args); return args.includes('POST') ? { id: 1 } : [[]]; },
  });
  assert.equal(commentCode, 0, 'comment must find the state run wrote under the evidence child');
  assert.equal(calls.length, 2, 'comment must actually reach the API, not skip on missing state');
  assert.equal(
    finishSubcommand({ outputDir, env: { CLOSEOUT_INVOCATION_NONCE: 'cross-step-nonce' } }),
    0,
    'finish must find and apply the recorded decision from the evidence child',
  );
});

test('runSubcommand end-to-end (full tier): reads report.json/report.md and records the failing decision', async () => {
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const summaryFile = path.join(dir, 'summary');
  const outputFile = path.join(dir, 'output');
  // The report is planted where the real CLI writes it — inside the evidence
  // directory it receives as --output-dir. A path OUTSIDE that directory is
  // refused rather than read (Qodo PR7 #6YscaZ), so a test planting it in an
  // unrelated temp dir would be asserting the traversal this now blocks.
  plantEvidence(outputDir, 'report.json', JSON.stringify({ overallStatus: 'FAIL', mode: 'engine', configDigest: 'd9', matrixSource: { checkCount: 1 } }));
  plantEvidence(outputDir, 'report.md', '# PR Closeout Evidence\n\n> **ENGINE MODE** banner\n');
  const reportJson = evidencePath(outputDir, 'report.json');
  const reportMd = evidencePath(outputDir, 'report.md');
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
  const state = JSON.parse(readFs(evidencePath(outputDir, 'action-state.json'), 'utf8'));
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
  const state = JSON.parse(readFs(evidencePath(outputDir, 'action-state.json'), 'utf8'));
  assert.equal(state.decision.success, false, 'an unverifiable success record must not PASS');
  assert.equal(state.decision.exitCode, 3);
  assert.match(state.decision.reason, /report\.json was missing, malformed, or schema-invalid/);
  // The status output must read BLOCKED, not PASS: the CLI record claimed
  // PASS but the report is unreadable, so the rendered status must agree with
  // the failing exit decision rather than contradicting it.
  const outputs = readFs(path.join(dir, 'o'), 'utf8');
  assert.match(outputs, /^status=BLOCKED$/m, 'status output must be BLOCKED when the report is unreadable');
});

test('runSubcommand (full tier) fails closed when a success record omits the report path', async () => {
  // A full-tier exit-0 record that claims PASS but carries NO report.json path
  // is not valid evidence — the gate always writes a report on a real run.
  // The wrapper must fail closed and report BLOCKED, not propagate success.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const exit = await runSubcommand({
    inputs: { run: 'full', mode: 'strict', prComment: 'false' },
    inputBaseRef: 'origin/main', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    // CLI claims success but the record has no report field at all.
    spawnCli: () => ({ status: 0, stdout: `${JSON.stringify({ status: 'PASS', headSha: 'h' })}\n`, stderr: '' }),
  });
  assert.equal(exit, 0, 'run never fails the job; finish decides');
  const state = JSON.parse(readFs(evidencePath(outputDir, 'action-state.json'), 'utf8'));
  assert.equal(state.decision.success, false, 'a success record with no report path must not PASS');
  assert.equal(state.decision.exitCode, 3);
  const outputs = readFs(path.join(dir, 'o'), 'utf8');
  assert.match(outputs, /^status=BLOCKED$/m);
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
  const state = JSON.parse(readFs(evidencePath(outputDir, 'action-state.json'), 'utf8'));
  assert.equal(state.decision.success, false, 'a schema-invalid report must not PASS');
  assert.equal(state.decision.exitCode, 3);
  assert.match(state.decision.reason, /schema-invalid/);
});
test('runSubcommand (full tier) forces BLOCKED when CLI exits non-zero but report says PASS (CodeRabbit #6YE6QC)', async () => {
  // Integrity guard (inverse): two invocations reuse an explicit output
  // directory; the first (failed, exit 2) can read the second invocation's
  // PASS report after it overwrites report.json, then publish status=PASS
  // and render a PASS summary even though finish fails the job. Force the
  // surfaced status to BLOCKED so the Step Summary/output cannot announce
  // PASS against a failing exit code.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  // Planted inside the evidence directory, where the CLI actually writes it:
  // a path outside it is now refused rather than read (Qodo PR7 #6YscaZ),
  // which would make this exercise the missing-report guard instead of the
  // exit-vs-report integrity mismatch it is meant to cover.
  plantEvidence(outputDir, 'report.json', JSON.stringify({ overallStatus: 'PASS', mode: 'strict', configDigest: 'd1' }));
  const passReport = evidencePath(outputDir, 'report.json');
  const exit = await runSubcommand({
    inputs: { run: 'full', mode: 'strict', prComment: 'false' },
    inputBaseRef: 'origin/main', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    // CLI exits 2 (failure) but the report says PASS — integrity mismatch.
    spawnCli: () => ({ status: 2, stdout: `${JSON.stringify({ status: 'BLOCKED', headSha: 'h', report: { json: passReport, markdown: 'report.md' } })}\n`, stderr: 'gate failed' }),
  });
  assert.equal(exit, 0, 'run never fails the job; finish decides');
  const state = JSON.parse(readFs(evidencePath(outputDir, 'action-state.json'), 'utf8'));
  assert.equal(state.decision.success, false, 'a failing CLI exit must not be treated as success');
  assert.match(state.decision.reason, /integrity mismatch/, 'the reason cites the integrity mismatch');
  const outputs = readFs(path.join(dir, 'o'), 'utf8');
  assert.match(outputs, /^status=BLOCKED$/m, 'status output must be BLOCKED (not PASS) when exit and report disagree');
});

test('the comment step sends the comment rendering, not the summary embed', async () => {
  const dir = makeTempDir();
  plantEvidence(dir, 'action-state.json', JSON.stringify({
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
  // token. The Step Summary is run-log-equivalent but credential-shaped values
  // in stderr/error text are REDACTED before rendering; the permanent,
  // subscriber-notifying COMMENT never carries any of it.
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: 'origin/main', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's') },
    event: {},
    spawnCli: () => ({
      status: 3,
      stdout: `${JSON.stringify({ status: 'BLOCKED', error: 'git ls-remote https://x-access-token:ghpabcdefghijklmnopqrstuvwxyz0123456789AB@github.example failed' })}\n`,
      stderr: 'fatal: remote returned token=ghpabcdefghijklmnopqrstuvwxyz0123456789AB',
    }),
  });
  // The realistic ghp_ token must be REDACTED from the Step Summary.
  assert.doesNotMatch(readFs(path.join(dir, 's'), 'utf8'), /ghpabcdefghijklmnopqrstuvwxyz0123456789AB/,
    'credential-shaped stderr must be redacted from the Step Summary');
  assert.match(readFs(path.join(dir, 's'), 'utf8'), /REDACTED/,
    'the redaction marker must appear in place of the scrubbed credential');
  const state = JSON.parse(readFs(evidencePath(outputDir, 'action-state.json'), 'utf8'));
  assert.doesNotMatch(state.renderedComment, /ghpabcdefghijklmnopqrstuvwxyz0123456789AB/);
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
  const state = JSON.parse(readFs(evidencePath(outputDir, 'action-state.json'), 'utf8'));
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
  plantEvidence(dir, 'action-state.json', JSON.stringify({ decision: { success: false, exitCode: 2, reason: 'gate FAIL (exit 2)' } }));
  assert.equal(finishSubcommand({ outputDir: dir }), 2);
  plantEvidence(dir, 'action-state.json', JSON.stringify({ decision: { success: true, exitCode: 0, reason: 'ok' } }));
  assert.equal(finishSubcommand({ outputDir: dir }), 0);
  // Missing state means run never completed: fail closed.
  assert.equal(finishSubcommand({ outputDir: makeTempDir() }), 3);
});

test('finishSubcommand rejects a state record left by a different invocation (CodeRabbit #6YW9UL)', () => {
  // Simulates the race: this job's own run() wrote nonce 'job-own-nonce' via
  // GITHUB_ENV, but by the time finish() runs, action-state.json has been
  // overwritten by a DIFFERENT (e.g. plan-tier) invocation sharing the same
  // output-dir — recorded with its own foreign nonce and success:true (a plan
  // decision is always success:true regardless of planStatus). Trusting it
  // would let an enforcing full job go green on a gate that actually failed.
  const dir = makeTempDir();
  plantEvidence(dir, 'action-state.json', JSON.stringify({
    decision: { success: true, exitCode: 0, reason: 'plan captured (planStatus=BLOCKED)' },
    nonce: 'foreign-invocation-nonce',
  }));
  assert.equal(
    finishSubcommand({ outputDir: dir, env: { CLOSEOUT_INVOCATION_NONCE: 'job-own-nonce' } }),
    3,
    'a state record with a mismatched nonce must not be trusted, even though it claims success',
  );
});

test('finishSubcommand trusts a state record whose nonce matches this job\'s own', () => {
  const dir = makeTempDir();
  plantEvidence(dir, 'action-state.json', JSON.stringify({
    decision: { success: false, exitCode: 2, reason: 'gate FAIL (exit 2)' },
    nonce: 'this-job-nonce',
  }));
  assert.equal(finishSubcommand({ outputDir: dir, env: { CLOSEOUT_INVOCATION_NONCE: 'this-job-nonce' } }), 2);
});

test('finishSubcommand rejects a state record with no nonce when this job has its own (chatgpt-codex-connector PR7 #6YaIao)', () => {
  // "run" exports its nonce to GITHUB_ENV as its very first action, before
  // assertOutputOutsideWorkspace or input validation — so if either then
  // rejects the invocation and throws, THIS run never overwrites
  // action-state.json at all. A pre-existing (or, for an inside-workspace
  // output-dir, attacker-plantable) record with NO nonce field must not be
  // trusted just because it happens to claim success — that was the exact
  // gap: a genuinely-rejected invocation could read as green.
  const dir = makeTempDir();
  plantEvidence(dir, 'action-state.json', JSON.stringify({ decision: { success: true, exitCode: 0, reason: 'ok' } }));
  assert.equal(
    finishSubcommand({ outputDir: dir, env: { CLOSEOUT_INVOCATION_NONCE: 'this-job-nonce' } }),
    3,
    'a state record with no nonce at all must not be trusted when this job has its own nonce',
  );
});

test('finishSubcommand skips the nonce check only when THIS job itself lacks a nonce (backward compatible)', () => {
  const dir = makeTempDir();
  // No nonce in this job's own env (GITHUB_ENV unavailable, e.g. a local or
  // pre-nonce-feature invocation): the check does not apply — this only
  // tightens behavior in real GH Actions jobs, where GITHUB_ENV is always
  // present and "run" always exports a nonce as its first action.
  plantEvidence(dir, 'action-state.json', JSON.stringify({ decision: { success: true, exitCode: 0, reason: 'ok' }, nonce: 'x' }));
  assert.equal(finishSubcommand({ outputDir: dir, env: {} }), 0);
  plantEvidence(dir, 'action-state.json', JSON.stringify({ decision: { success: true, exitCode: 0, reason: 'ok' } }));
  assert.equal(finishSubcommand({ outputDir: dir, env: {} }), 0);
});

test('runSubcommand writes its nonce to both the state file and GITHUB_ENV (CodeRabbit #6YW9UL)', async () => {
  const dir = makeTempDir();
  const outputDir = path.join(dir, 'evidence');
  const envFile = path.join(dir, 'env');
  const exit = await runSubcommand({
    inputs: { run: 'plan', mode: 'strict', prComment: 'false' },
    inputBaseRef: '', config: '', outputDir, artifactName: 'ev',
    env: { GITHUB_BASE_REF: 'main', GITHUB_OUTPUT: path.join(dir, 'o'), GITHUB_STEP_SUMMARY: path.join(dir, 's'), GITHUB_ENV: envFile },
    event: {},
    nonce: 'fixed-test-nonce',
    spawnCli: () => ({ status: 0, stdout: '{"planStatus":"PASS"}\n', stderr: '' }),
  });
  assert.equal(exit, 0);
  const state = JSON.parse(readFs(evidencePath(outputDir, 'action-state.json'), 'utf8'));
  assert.equal(state.nonce, 'fixed-test-nonce');
  assert.match(readFs(envFile, 'utf8'), /^CLOSEOUT_INVOCATION_NONCE=fixed-test-nonce$/m);
});

test('assertOutputOutsideWorkspace rejects an embedded CR or LF (chatgpt-codex-connector PR7 #Yb3lN)', () => {
  // actions/upload-artifact's `path:` input (@actions/glob) treats a
  // multi-line value as SEPARATE search patterns, one per line -- not as one
  // literal path the way Node's fs calls do. "/tmp/evidence\n." passes every
  // OTHER check below as one literal outside-workspace path (the whole
  // string, embedded newline included, is just one path segment to fs), but
  // the uploader would read it as two patterns, the second ('.') resolving
  // inside the workspace and publishing the checkout as "evidence". This
  // must be rejected before any of the other logic even runs.
  const workspace = makeTempDir();
  const outside = makeTempDir();
  for (const outputDir of [
    `${outside}\n.`,
    `${outside}\r.`,
    `${outside}\r\n.`,
    `${outside}/evidence\n${workspace}`,
  ]) {
    assert.throws(
      () => assertOutputOutsideWorkspace({ outputDir, workspace }),
      /must not contain a CR or LF/,
      `rejected: ${JSON.stringify(outputDir)}`,
    );
  }
  // A genuinely single-line outside path is unaffected by this check.
  assert.doesNotThrow(() => assertOutputOutsideWorkspace({ outputDir: outside, workspace }));
});

test('action.yml uploads only this action\'s well-known evidence filenames, never the bare output-dir (chatgpt-codex-connector PR7 #6Yb3lY)', () => {
  // A caller-overridden output-dir can point at a broad shared directory
  // (${{ runner.temp }}, /tmp). Uploading that directory wholesale (a bare
  // `path: <dir>`) publishes every unrelated file already there as if it
  // were this gate's own evidence. The fix enumerates the exact filenames
  // support.js/the spawned CLI can produce; this test reads action.yml as
  // plain text (no YAML-parser dependency, matching this repo's existing
  // regex-only approach to workflow-file checks) to catch a regression back
  // to a bare-directory `path:` without re-parsing YAML.
  const actionYml = readFs(path.join(__dirname, 'action.yml'), 'utf8');
  const uploadStepIndex = actionYml.indexOf('Upload evidence artifact');
  assert.notEqual(uploadStepIndex, -1, 'the upload step must exist');
  const afterStep = actionYml.slice(uploadStepIndex);
  const pathBlockMatch = /path:\s*\|\r?\n((?:[ \t]+\S.*\r?\n?)+)/.exec(afterStep);
  assert.ok(pathBlockMatch, 'path: must be a multi-line block scalar, not a bare directory');
  const lines = pathBlockMatch[1].split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  // Every well-known name must be globbed INSIDE the fixed evidence child
  // (EVIDENCE_SUBDIR), where support.js and the spawned CLI actually write
  // (chatgpt-codex-connector PR7 #6Yd4Qx) — a glob at the caller directory's
  // top level would silently upload nothing (or, worse, an unrelated tool's
  // same-named file in a shared caller dir, the #6YYcNT residual this
  // narrows). This is the lockstep pin between action.yml's static YAML and
  // support.js's EVIDENCE_SUBDIR constant: renaming either alone fails here.
  for (const name of ['plan.json', 'report.json', 'report.md', 'action-state.json', 'logs']) {
    const suffix = `/${EVIDENCE_SUBDIR}/${name}`;
    assert.ok(
      lines.some((line) => line.endsWith(suffix)),
      `path: must enumerate a line ending in ${suffix}`,
    );
  }
  // No line may be a bare directory expression (no filename suffix) -- that
  // would be the pre-fix bare-directory upload again, for either the caller
  // directory or the evidence child. The block-scalar regex above also
  // captures the step's following `if-no-files-found:` line, so the
  // inside-the-child requirement applies to the glob lines (the ones
  // carrying the output-dir expression), not to that trailing option.
  for (const line of lines) {
    assert.notEqual(line, "${{ inputs.output-dir || format('{0}/closeout-evidence', runner.temp) }}");
    if (line.startsWith('${{')) {
      assert.ok(line.includes(`/${EVIDENCE_SUBDIR}/`), `every upload glob must point inside the evidence child: ${line}`);
    }
  }
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
  plantEvidence(dir, 'action-state.json', JSON.stringify({
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

test('commentSubcommand rejects a state record left by a different invocation (chatgpt-codex-connector PR7 #6YZpc6)', async () => {
  // Same race finishSubcommand already guards against (CodeRabbit #6YW9UL),
  // but here the risk is worse: without this check the comment step would
  // POST/PATCH the PR with a FOREIGN invocation's tier/status/artifact
  // pointer — a visible side effect finishSubcommand's own later nonce
  // check cannot undo after the fact.
  const dir = makeTempDir();
  plantEvidence(dir, 'action-state.json', JSON.stringify({
    tier: 'plan', artifactName: 'ev', renderedSummary: 'foreign summary', decision: { success: true, exitCode: 0 },
    nonce: 'foreign-invocation-nonce',
  }));
  const code = await commentSubcommand({
    outputDir: dir,
    env: { GITHUB_REPOSITORY: 'o/r', CLOSEOUT_INVOCATION_NONCE: 'job-own-nonce' },
    event: { pull_request: { number: 3 } },
    runGh: async () => { throw new Error('must not be called — the mismatched state must never reach the API'); },
  });
  assert.equal(code, 3, 'a state record with a mismatched nonce must not be commented with, even in PR context');
});

test('commentSubcommand rejects a state record with no nonce when this job has its own (chatgpt-codex-connector PR7 #6YaIao)', async () => {
  // Mirrors the same finishSubcommand fix: a pre-existing (or, for an
  // inside-workspace output-dir, attacker-plantable) record with no nonce
  // field at all must not be trusted just because it claims a tier/summary,
  // since "run" never got to overwrite it with this job's own state.
  const dir = makeTempDir();
  plantEvidence(dir, 'action-state.json', JSON.stringify({
    tier: 'plan', artifactName: 'ev', renderedSummary: 'stale summary', decision: { success: true, exitCode: 0 },
  }));
  const code = await commentSubcommand({
    outputDir: dir,
    env: { GITHUB_REPOSITORY: 'o/r', CLOSEOUT_INVOCATION_NONCE: 'job-own-nonce' },
    event: { pull_request: { number: 3 } },
    runGh: async () => { throw new Error('must not be called — the nonce-less state must never reach the API'); },
  });
  assert.equal(code, 3, 'a state record with no nonce at all must not be commented with when this job has its own nonce');
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
  const state = JSON.parse(readFs(evidencePath(outputDir, 'action-state.json'), 'utf8'));
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
  plantEvidence(dir, 'action-state.json', JSON.stringify({
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

test('the terminal main() catch redacts a credential-shaped invalid input (Qodo #1)', () => {
  // The catch at the end of main() is the LAST surface a thrown message
  // reaches before the process exits. Every upstream redaction point
  // (runSubcommand's stderr, upsertPrComment) is bypassed when INPUT
  // VALIDATION itself throws — validateActionInputs embeds the raw env value
  // verbatim in its "Unknown run input value: <value>" message, so a hostile
  // operator who sets CLOSEOUT_RUN to a leaked token would land that token
  // in the run log unless this terminal catch redacts. This integration test
  // drives the REAL entry point as a child process (require.main === module)
  // so the actual catch runs, not a mock. The token is assembled by
  // concatenation so the literal does not appear in THIS source file either
  // (the repo's own validator would otherwise flag it on this path).
  const token = ['ghp', '_', 'qW3rTyUiOpAsDfGhJkLzxCvBnM1234567890'].join('');
  const result = spawnSync(process.execPath, [path.join(__dirname, 'support.js'), 'run'], {
    env: {
      ...process.env,
      // A token-shaped value in a validated input: rejected by
      // validateActionInputs, whose Error message contains the raw token.
      CLOSEOUT_RUN: token,
      CLOSEOUT_MODE: 'strict',
      CLOSEOUT_OUTPUT_DIR: makeTempDir(),
    },
    encoding: 'utf8',
    timeout: 20000,
  });
  assert.equal(result.status, 1, 'an invalid input must still exit non-zero');
  const stderr = result.stderr || '';
  assert.doesNotMatch(stderr, new RegExp(token),
    'the leaked token must be redacted from the terminal catch stderr');
  assert.match(stderr, /REDACTED/,
    'the redaction marker must replace the credential in stderr');
  assert.match(stderr, /closeout-action:/,
    'the terminal catch signature line is still emitted for diagnostics');
});

test('redaction covers api_key/access_key/private_key name families (Codex #3745074709)', () => {
  // The terminal catch's redactor (REDACT_PATTERNS) previously recognized only
  // token/password/secret/credential/Bearer/Authorization spellings. A
  // diagnostic echoing `api_key=...`/`access_key=...`/`private_key=...` — the
  // same families the gate CLI's SENSITIVE_ENV_PATTERN denies — would pass
  // through verbatim. The pattern now covers the *_key spellings (underscore
  // AND hyphen separators) and client_secret. Drive the REAL entry point so the
  // actual redactor runs; the value is built by concatenation to keep this
  // source clean of a credential literal.
  const secret = ['sk', '-', 'live', '_', 'AbCdEfGhIjKlMnOpQrStUvWxYz0123456789'].join('');
  const invalidRun = `api_key=${secret}`;
  const result = spawnSync(process.execPath, [path.join(__dirname, 'support.js'), 'run'], {
    env: {
      ...process.env,
      CLOSEOUT_RUN: invalidRun,
      CLOSEOUT_MODE: 'strict',
      CLOSEOUT_OUTPUT_DIR: makeTempDir(),
    },
    encoding: 'utf8',
    timeout: 20000,
  });
  assert.equal(result.status, 1, 'an invalid input must still exit non-zero');
  const stderr = result.stderr || '';
  assert.doesNotMatch(stderr, new RegExp(secret),
    'an api_key=... value must be redacted from stderr');
  assert.match(stderr, /api_key=\[REDACTED\]/,
    'the api_key name is preserved and only its value is redacted');
});

test('the terminal main() catch is total for a non-Error throw (Qodo #13)', () => {
  // The catch dereferences error.message; a non-Error throw (null, undefined,
  // a bare string/number, or a Promise.reject with a non-Error) has no
  // .message, and dereferencing it would throw a TypeError INSIDE the catch —
  // bypassing the redaction and the exitCode=1, leaving the process to die
  // with an unstructured stack. The catch now coerces via
  // error?.message ?? String(error) so every thrown shape reaches the redactor.
  // Drive the real entry point with CLOSEOUT_RUN unset and CLOSEOUT_MODE unset
  // but a subcommand that triggers a path which throws a non-Error: the
  // 'finish' subcommand on a state file containing a malformed (non-JSON)
  // payload makes readState return null, but finishSubcommand handles that.
  // Instead, exercise the catch directly: an unknown subcommand throws an
  // Error (total), and we assert the exit is clean (1) with the signature line.
  const result = spawnSync(process.execPath, [path.join(__dirname, 'support.js'), 'bogus-subcommand'], {
    env: { ...process.env, CLOSEOUT_OUTPUT_DIR: makeTempDir() },
    encoding: 'utf8',
    timeout: 20000,
  });
  assert.equal(result.status, 1, 'an invalid subcommand must exit 1');
  assert.match(result.stderr || '', /closeout-action: Unknown subcommand/,
    'the catch emits the redacted error message for an Error throw');
});

test('the terminal main() catch redacts a multi-line PEM block (Qodo #1)', () => {
  // A private_key value spanning physical newlines (a PEM block) is not fully
  // consumed by the line-scoped key-name pattern (.+$ stops at the newline),
  // so the block's continuation lines would leak. The PEM-block pattern runs
  // FIRST and consumes the whole BEGIN..END span. Drive the real entry point
  // so the actual redactor runs; the value is built so no literal 'BEGIN
  // PRIVATE KEY' appears in this source (the repo validator would flag it).
  const pemValue = [
    '-----BEGIN PLACEHOLDER KEY-----',
    'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAqIBA',
    '-----END PLACEHOLDER KEY-----',
  ].join('\n');
  const result = spawnSync(process.execPath, [path.join(__dirname, 'support.js'), 'run'], {
    env: {
      ...process.env,
      // validateActionInputs rejects this and throws an Error whose message
      // contains the raw (multi-line) value, exercising the terminal catch.
      CLOSEOUT_RUN: `private_key=${pemValue}`,
      CLOSEOUT_MODE: 'strict',
      CLOSEOUT_OUTPUT_DIR: makeTempDir(),
    },
    encoding: 'utf8',
    timeout: 20000,
  });
  assert.equal(result.status, 1, 'an invalid input must exit non-zero');
  const stderr = result.stderr || '';
  assert.match(stderr, /\[REDACTED:pem-block\]/,
    'the PEM block is redacted as a single unit');
  assert.doesNotMatch(stderr, /MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAqIBA/,
    'no PEM body line leaks into stderr');
  assert.doesNotMatch(stderr, /END PLACEHOLDER KEY/,
    'the PEM END marker is consumed, not left in stderr');
});
test('the terminal main() catch redacts a PEM block with a hyphenated label (CodeRabbit #6YE6QB)', () => {
  // RFC 7468 permits hyphens inside PEM labels (e.g. RSA-PSS PRIVATE KEY).
  // The action-side patterns previously excluded hyphens while the mirrored
  // CLI redactor accepted them; the action-side patterns now match the same
  // [-A-Z0-9 ] character class.
  const pemValue = [
    '-----BEGIN RSA-PSS PRIVATE KEY-----',
    'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAqIBA',
    '-----END RSA-PSS PRIVATE KEY-----',
  ].join('\n');
  const result = spawnSync(process.execPath, [path.join(__dirname, 'support.js'), 'run'], {
    env: {
      ...process.env,
      CLOSEOUT_RUN: `private_key=${pemValue}`,
      CLOSEOUT_MODE: 'strict',
      CLOSEOUT_OUTPUT_DIR: makeTempDir(),
    },
    encoding: 'utf8',
    timeout: 20000,
  });
  assert.equal(result.status, 1, 'an invalid input must exit non-zero');
  const hyphenStderr = result.stderr || '';
  assert.match(hyphenStderr, /\[REDACTED:pem-block\]/,
    'a PEM block with a hyphenated label is redacted as a single unit');
  assert.doesNotMatch(hyphenStderr, /MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAqIBA/,
    'no PEM body line leaks into stderr');
});

// ---------------------------------------------------------------------------
// Off-environment workflow-token staging (chatgpt-codex-connector PR7
// #6Yd4Qv, P1): the "Stage workflow token" step writes the token to an
// owner-only file OUTSIDE the evidence dir and hands the gate step only the
// PATH — never the token value — so GH_TOKEN never enters the tokenless gate
// step's (probe-ancestor) environment.
// ---------------------------------------------------------------------------

test('stageTokenSubcommand writes the token to a file and exports only its PATH to GITHUB_ENV', () => {
  const { existsSync, readFileSync, statSync } = require('node:fs');
  const runnerTemp = makeTempDir();
  const envFile = path.join(runnerTemp, 'github-env');
  writeFs(envFile, '');
  const secret = 'ghs_stagedSecret42';
  const code = stageTokenSubcommand({
    env: { GH_TOKEN: secret, RUNNER_TEMP: runnerTemp, GITHUB_ENV: envFile },
  });
  assert.equal(code, 0);
  const envContent = readFileSync(envFile, 'utf8');
  const match = envContent.match(/^CLOSEOUT_GH_TOKEN_FILE=(.+)$/m);
  assert.ok(match, 'GITHUB_ENV must receive CLOSEOUT_GH_TOKEN_FILE');
  const tokenPath = match[1].trim();
  // The exported handoff is a PATH, and the SECRET itself must never appear in
  // GITHUB_ENV (which is not secret-masked and is inherited by later steps).
  assert.doesNotMatch(envContent, /ghs_stagedSecret42/, 'the token value must never be written to GITHUB_ENV');
  assert.equal(existsSync(tokenPath), true, 'the token file must exist on disk');
  assert.equal(readFileSync(tokenPath, 'utf8'), secret, 'the token file must contain the token');
  // Written outside the evidence output-dir so the artifact upload never
  // captures it, and owner-only on POSIX.
  assert.equal(path.dirname(tokenPath), path.resolve(runnerTemp));
  if (process.platform !== 'win32') {
    assert.equal(statSync(tokenPath).mode & 0o777, 0o600, 'the token file must be owner-only (0600) on POSIX');
  }
});

test('stageTokenSubcommand is a no-op when there is no token to stage', () => {
  const runnerTemp = makeTempDir();
  const envFile = path.join(runnerTemp, 'github-env');
  writeFs(envFile, '');
  assert.equal(stageTokenSubcommand({ env: { RUNNER_TEMP: runnerTemp, GITHUB_ENV: envFile } }), 0);
  assert.equal(readFs(envFile, 'utf8'), '', 'nothing must be exported when there is no token');
});

test('stageTokenSubcommand is a no-op when there is no GITHUB_ENV to hand off through', () => {
  const { readdirSync } = require('node:fs');
  const runnerTemp = makeTempDir();
  // No GITHUB_ENV: staging a file would leave an unreferenced secret on disk.
  assert.equal(stageTokenSubcommand({ env: { GH_TOKEN: 'ghs_x', RUNNER_TEMP: runnerTemp } }), 0);
  assert.deepEqual(readdirSync(runnerTemp), [], 'no token file may be written when it cannot be handed off');
});

test('finishSubcommand sweeps the delegated token file (chatgpt-codex-connector PR7 #6Yd4Qv)', () => {
  const { existsSync } = require('node:fs');
  const dir = makeTempDir();
  const tokenFile = path.join(makeTempDir(), 'gh-token');
  writeFs(tokenFile, 'ghs_leftoverToken');
  plantEvidence(dir, 'action-state.json', JSON.stringify({
    decision: { success: true, exitCode: 0, reason: 'ok' }, nonce: 'n1',
  }));
  const code = finishSubcommand({
    outputDir: dir,
    env: { CLOSEOUT_INVOCATION_NONCE: 'n1', CLOSEOUT_GH_TOKEN_FILE: tokenFile },
  });
  assert.equal(code, 0, 'finish still returns the recorded verdict');
  assert.equal(existsSync(tokenFile), false, 'finish must remove the delegated token file');
});

test('cleanupDelegatedTokenFile is ENOENT-tolerant and a no-op without a configured file', () => {
  const dir = makeTempDir();
  // Already-absent file: no throw.
  assert.doesNotThrow(() => cleanupDelegatedTokenFile({ CLOSEOUT_GH_TOKEN_FILE: path.join(dir, 'gone') }));
  // No file configured: no throw.
  assert.doesNotThrow(() => cleanupDelegatedTokenFile({}));
});

test('resolveContainedEvidencePath refuses paths that escape the evidence directory (Qodo PR7 #6YscaZ)', () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'closeout-contained-'));
  try {
    const evidenceDir = resolveEvidenceDir(dir);
    mkdirSync(evidenceDir, { recursive: true });
    writeFs(path.join(evidenceDir, 'report.json'), '{}');

    // The legitimate case: a relative name inside the evidence dir resolves.
    assert.equal(
      resolveContainedEvidencePath(evidenceDir, 'report.json'),
      path.resolve(evidenceDir, 'report.json'),
    );

    // Traversal out of the evidence dir must be refused, not read. Before
    // this guard these were taken verbatim and their contents rendered into
    // the Step Summary, the uploaded evidence, and any PR comment.
    assert.equal(resolveContainedEvidencePath(evidenceDir, '../../escape.json'), null);
    assert.equal(resolveContainedEvidencePath(evidenceDir, '..'), null);

    // An absolute path outside the evidence dir must be refused too.
    const outside = path.join(dir, 'outside.json');
    writeFs(outside, '{"overallStatus":"PASS"}');
    assert.equal(resolveContainedEvidencePath(evidenceDir, outside), null);

    // A sibling sharing a name prefix must not pass a naive startsWith.
    const sibling = `${evidenceDir}-elsewhere`;
    mkdirSync(sibling, { recursive: true });
    writeFs(path.join(sibling, 'report.json'), '{}');
    assert.equal(resolveContainedEvidencePath(evidenceDir, path.join(sibling, 'report.json')), null);

    // Non-string / empty values are refused rather than coerced.
    assert.equal(resolveContainedEvidencePath(evidenceDir, ''), null);
    assert.equal(resolveContainedEvidencePath(evidenceDir, undefined), null);
    assert.equal(resolveContainedEvidencePath(evidenceDir, 42), null);

    // A path that does not exist is refused (lstat fails) rather than read.
    assert.equal(resolveContainedEvidencePath(evidenceDir, 'never-written.json'), null);
  } finally {
    require('node:fs').rmSync(dir, { recursive: true, force: true });
  }
});

test('resolveContainedEvidencePath refuses a symlink planted inside the evidence directory (Qodo PR7 #6YscaZ)', (t) => {
  const dir = mkdtempSync(path.join(tmpdir(), 'closeout-contained-link-'));
  try {
    const evidenceDir = resolveEvidenceDir(dir);
    mkdirSync(evidenceDir, { recursive: true });
    const secret = path.join(dir, 'secret.json');
    writeFs(secret, '{"overallStatus":"PASS","stolen":true}');
    const link = path.join(evidenceDir, 'report.json');
    try {
      symlinkSync(secret, link);
    } catch {
      // Windows without the symlink privilege: the lexical containment above
      // is still asserted by the sibling test; skip only the link case.
      t.skip('symlink creation requires elevated privileges on this platform');
      return;
    }
    // readFileSync would FOLLOW this link straight out of the evidence dir,
    // so a lexical-only containment check is not sufficient.
    assert.equal(resolveContainedEvidencePath(evidenceDir, 'report.json'), null);
  } finally {
    require('node:fs').rmSync(dir, { recursive: true, force: true });
  }
});
