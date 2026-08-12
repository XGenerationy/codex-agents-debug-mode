const assert = require('node:assert/strict');
const test = require('node:test');

const { mkdtempSync, writeFileSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { join } = require('node:path');

const {
  buildGhArgs,
  classifyGateAttestation,
  classifyLivePrState,
  detectCrossWorkflowSelfExclusionCollision,
  gateAttestationMarker,
  readLiveGateAttestation,
  readLivePrState,
  readReviewerPermissions,
  resolveCurrentJobDisplayName,
  resolveWorkflowRunPath,
} = require('./pr_closeout_github');

const cleanAttestation = (extra = {}) => ({
  provider: 'github-pull-request-review',
  status: 'PASS',
  baseSha: 'base123',
  headSha: 'head123',
  configDigest: 'cfg123',
  decision: 'not-weakened',
  reviewer: 'reviewer',
  evidence: 'https://github.example/reviews/7',
  ...extra,
});

const approvedReview = (extra = {}) => ({
  id: 7,
  html_url: 'https://github.example/reviews/7',
  state: 'APPROVED',
  commit_id: 'head123',
  body: gateAttestationMarker({ baseSha: 'base123', headSha: 'head123', configDigest: 'cfg123' }),
  submitted_at: '2026-07-14T00:00:00Z',
  author_association: 'OWNER',
  user: { login: 'reviewer' },
  ...extra,
});

const cleanPr = () => ({
  number: 42,
  url: 'https://github.example/pull/42',
  state: 'OPEN',
  isDraft: false,
  mergeable: 'MERGEABLE',
  mergeStateStatus: 'CLEAN',
  reviewDecision: 'APPROVED',
  headRefOid: 'head123',
  baseRefOid: 'base123',
  statusCheckRollup: [
    { name: 'ci', status: 'COMPLETED', conclusion: 'SUCCESS', workflowName: 'CI' },
  ],
  latestReviews: [{ author: { login: 'reviewer' }, state: 'APPROVED', submittedAt: '2026-07-14T00:00:00Z' }],
  author: { login: 'author' },
});

const classifyPr = (pr) => classifyLivePrState({
  repository: 'owner/repo',
  pr,
  unresolvedThreads: [],
  expectedHeadSha: 'head123',
  expectedBaseSha: 'base123',
  gateAttestation: cleanAttestation(),
});

const ghEnvKeys = ['GITHUB_ACTIONS', 'GITHUB_REF_NAME', 'GITHUB_REPOSITORY', 'GITHUB_EVENT_PATH', 'GITHUB_RUN_ID', 'RUNNER_NAME'];
const ghEnvSaved = {};
test.beforeEach(() => {
  for (const key of ghEnvKeys) { ghEnvSaved[key] = process.env[key]; }
  // GITHUB_RUN_ID/RUNNER_NAME are ambient when this suite runs inside this
  // repo's own GitHub Actions CI, which would otherwise make
  // resolveCurrentJobDisplayName's extra Jobs API call fire nondeterministically
  // in tests whose runGh mock doesn't expect it. Clear them by default; tests
  // that specifically exercise that path set them explicitly.
  delete process.env.GITHUB_RUN_ID;
  delete process.env.RUNNER_NAME;
});
test.afterEach(() => { for (const key of ghEnvKeys) { if (ghEnvSaved[key] === undefined) { delete process.env[key]; } else { process.env[key] = ghEnvSaved[key]; } } });

test('accepts only an independent exact GitHub review attestation marker', () => {
  const expected = { expectedBaseSha: 'base123', expectedHeadSha: 'head123', expectedConfigDigest: 'cfg123', prAuthor: 'author' };
  assert.equal(classifyGateAttestation({ reviews: [approvedReview()], ...expected }).status, 'PASS');
  assert.equal(classifyGateAttestation({ reviews: [approvedReview({ state: 'COMMENTED' })], ...expected }).status, 'BLOCKED');
  assert.equal(classifyGateAttestation({ reviews: [approvedReview({ user: { login: 'author' } })], ...expected }).status, 'BLOCKED');
  assert.equal(classifyGateAttestation({ reviews: [approvedReview({ commit_id: 'old-head' })], ...expected }).status, 'BLOCKED');
  const marker = approvedReview().body;
  assert.equal(classifyGateAttestation({ reviews: [approvedReview({ body: `${marker}\n${marker}` })], ...expected }).status, 'BLOCKED');
  assert.equal(classifyGateAttestation({ reviews: [approvedReview({ body: `${marker}-suffix` })], ...expected }).status, 'BLOCKED');
});

test('honors each reviewer latest decision on the attested head', () => {
  // Codex #4780351874: an older APPROVED+marker must not admit after the same
  // reviewer later submits CHANGES_REQUESTED (or a marker-less re-review) on
  // the same head. Collapse per-reviewer history to the latest submission.
  const expected = { expectedBaseSha: 'base123', expectedHeadSha: 'head123', expectedConfigDigest: 'cfg123', prAuthor: 'author' };
  const earlierApproval = approvedReview({
    id: 10,
    submitted_at: '2026-07-14T00:00:00Z',
  });
  const laterChangesRequested = approvedReview({
    id: 11,
    state: 'CHANGES_REQUESTED',
    body: 'Please fix the gate bypass.',
    submitted_at: '2026-07-14T01:00:00Z',
  });
  assert.equal(
    classifyGateAttestation({ reviews: [earlierApproval, laterChangesRequested], ...expected }).status,
    'BLOCKED',
  );

  const laterMarkerlessApproval = approvedReview({
    id: 12,
    body: 'LGTM without the marker.',
    submitted_at: '2026-07-14T02:00:00Z',
  });
  assert.equal(
    classifyGateAttestation({ reviews: [earlierApproval, laterMarkerlessApproval], ...expected }).status,
    'BLOCKED',
  );

  // A second authorized reviewer whose latest decision is still APPROVED+marker
  // remains admissible even if a different reviewer later requested changes.
  const otherReviewerApproval = approvedReview({
    id: 13,
    user: { login: 'other-owner' },
    submitted_at: '2026-07-14T00:30:00Z',
  });
  const stillPass = classifyGateAttestation({
    reviews: [earlierApproval, laterChangesRequested, otherReviewerApproval],
    ...expected,
  });
  assert.equal(stillPass.status, 'PASS');
  assert.equal(stillPass.reviewer, 'other-owner');

  // Same submitted_at: higher review id wins (withdrawal after marker).
  const sameTsApproval = approvedReview({
    id: 20,
    submitted_at: '2026-07-14T03:00:00Z',
  });
  const sameTsChanges = approvedReview({
    id: 21,
    state: 'CHANGES_REQUESTED',
    body: 'Withdrawn.',
    submitted_at: '2026-07-14T03:00:00Z',
  });
  assert.equal(
    classifyGateAttestation({ reviews: [sameTsApproval, sameTsChanges], ...expected }).status,
    'BLOCKED',
  );
});

test('requires the marker reviewer itself to have authoritative repository access', () => {
  const expected = { expectedBaseSha: 'base123', expectedHeadSha: 'head123', expectedConfigDigest: 'cfg123', prAuthor: 'author' };
  const unrelatedTrustedApproval = approvedReview({
    id: 8,
    body: 'Looks good.',
    author_association: 'MEMBER',
    user: { login: 'trusted-reviewer' },
  });
  const outsiderMarker = approvedReview({
    id: 9,
    author_association: 'CONTRIBUTOR',
    user: { login: 'outsider' },
  });

  const result = classifyGateAttestation({
    reviews: [unrelatedTrustedApproval, outsiderMarker],
    ...expected,
  });
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /authorized independent/i);
});

test('blocks attestation when GitHub does not prove the PR author identity', () => {
  const result = classifyGateAttestation({
    reviews: [approvedReview()],
    expectedBaseSha: 'base123',
    expectedHeadSha: 'head123',
    expectedConfigDigest: 'cfg123',
  });
  assert.equal(result.status, 'BLOCKED');
});

test('accepts a marker reviewer only when the repository permission lookup proves write access', async () => {
  const readResult = await readLiveGateAttestation({
    repo: 'C:/repo',
    expectedBaseSha: 'base123',
    expectedHeadSha: 'head123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return cleanPr();
      if (args[1]?.endsWith('/permission')) return { permission: 'read' };
      return [[approvedReview({ author_association: 'CONTRIBUTOR' })]];
    },
  });
  assert.equal(readResult.status, 'BLOCKED');

  const writeResult = await readLiveGateAttestation({
    repo: 'C:/repo',
    expectedBaseSha: 'base123',
    expectedHeadSha: 'head123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return cleanPr();
      if (args[1]?.endsWith('/permission')) return { permission: 'write' };
      return [[approvedReview({ author_association: 'CONTRIBUTOR' })]];
    },
  });
  assert.equal(writeResult.status, 'PASS');
});

test('requires repository write permission for MEMBER attestors instead of trusting org membership', () => {
  const expected = { expectedBaseSha: 'base123', expectedHeadSha: 'head123', expectedConfigDigest: 'cfg123', prAuthor: 'author' };
  // A MEMBER with no permission record must NOT be treated as authoritative.
  const memberWithoutPermission = classifyGateAttestation({
    reviews: [approvedReview({ author_association: 'MEMBER' })],
    ...expected,
  });
  assert.equal(memberWithoutPermission.status, 'BLOCKED');

  // A MEMBER whose permission lookup returns write access is accepted.
  const memberWithWrite = classifyGateAttestation({
    reviews: [approvedReview({ author_association: 'MEMBER' })],
    reviewerPermissions: new Map([['reviewer', { permission: 'write' }]]),
    ...expected,
  });
  assert.equal(memberWithWrite.status, 'PASS');

  // A MEMBER whose permission lookup returns only read access is rejected.
  const memberWithRead = classifyGateAttestation({
    reviews: [approvedReview({ author_association: 'MEMBER' })],
    reviewerPermissions: new Map([['reviewer', { permission: 'read' }]]),
    ...expected,
  });
  assert.equal(memberWithRead.status, 'BLOCKED');
});

test('requires repository write permission for COLLABORATOR attestors instead of trusting the association', () => {
  const expected = { expectedBaseSha: 'base123', expectedHeadSha: 'head123', expectedConfigDigest: 'cfg123', prAuthor: 'author' };
  const collaboratorWithoutPermission = classifyGateAttestation({
    reviews: [approvedReview({ author_association: 'COLLABORATOR' })],
    ...expected,
  });
  assert.equal(collaboratorWithoutPermission.status, 'BLOCKED');

  const collaboratorWithWrite = classifyGateAttestation({
    reviews: [approvedReview({ author_association: 'COLLABORATOR' })],
    reviewerPermissions: new Map([['reviewer', { permission: 'write' }]]),
    ...expected,
  });
  assert.equal(collaboratorWithWrite.status, 'PASS');

  const collaboratorWithRead = classifyGateAttestation({
    reviews: [approvedReview({ author_association: 'COLLABORATOR' })],
    reviewerPermissions: new Map([['reviewer', { permission: 'read' }]]),
    ...expected,
  });
  assert.equal(collaboratorWithRead.status, 'BLOCKED');
});

test('accepts only a clean live PR bound to the expected base and head', () => {
  const result = classifyLivePrState({
    repository: 'owner/repo',
    pr: cleanPr(),
    unresolvedThreads: [],
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    gateAttestation: cleanAttestation(),
  });
  assert.equal(result.status, 'PASS');
  assert.equal(result.checks[0].name, 'ci');
});

test('classifies failed checks as FAIL and skipped checks as BLOCKED', () => {
  // FAILURE is a functional fail; SKIPPED is missing evidence (run it or mark
  // blocked), not a functional regression — see pr-closeout-validation.md.
  const failed = classifyLivePrState({
    repository: 'owner/repo',
    pr: {
      ...cleanPr(),
      statusCheckRollup: [
        { name: 'failed', status: 'COMPLETED', conclusion: 'FAILURE' },
      ],
    },
    unresolvedThreads: [],
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    gateAttestation: cleanAttestation(),
  });
  assert.equal(failed.status, 'FAIL');
  assert.equal(failed.checks[0].classification, 'FAIL');

  const skipped = classifyLivePrState({
    repository: 'owner/repo',
    pr: {
      ...cleanPr(),
      statusCheckRollup: [
        { name: 'ci', status: 'COMPLETED', conclusion: 'SUCCESS' },
        { name: 'path-filtered', status: 'COMPLETED', conclusion: 'SKIPPED' },
      ],
    },
    unresolvedThreads: [],
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    gateAttestation: cleanAttestation(),
  });
  assert.equal(skipped.status, 'BLOCKED');
  assert.equal(
    skipped.checks.find((check) => check.name === 'path-filtered').classification,
    'BLOCKED',
  );
  assert.match(skipped.evidence, /path-filtered/i);
  assert.doesNotMatch(skipped.evidence, /concluded SKIPPED/i);

  const pending = classifyLivePrState({
    repository: 'owner/repo',
    pr: { ...cleanPr(), statusCheckRollup: [{ name: 'ci', status: 'IN_PROGRESS', conclusion: null }] },
    unresolvedThreads: [{ path: 'src/a.ts', line: 4, url: 'https://github.example/comment/1' }],
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    gateAttestation: cleanAttestation(),
  });
  assert.equal(pending.status, 'BLOCKED');
  assert.match(pending.evidence, /unresolved review thread/i);
});

test('excludes every self-workflow check from the rollup, including a prior completed run (CodeRabbit #6X_pwH, broadened by chatgpt-codex-connector PR7 #6YaIaU)', () => {
  // At the moment classifyLivePrState runs INSIDE the Closeout gate job, its
  // own check is IN_PROGRESS and cannot see its own result. The exclusion omits
  // EVERY check matching (workflowName AND name) — not only the currently
  // non-COMPLETED one; SIBLING jobs in the same workflow are still classified
  // (#6X_pwH refined by #6YSx9w).
  //
  // #6X_pwH originally kept a prior COMPLETED run of this same job classified
  // (a stale FAILURE "kept blocking"), written before the workflow_run retry
  // trigger existed (#6YW9UP). That trigger specifically re-runs the gate
  // after a run that correctly BLOCKED on a still-pending sibling check (an
  // entirely routine outcome that GitHub Actions can only record as a job
  // "failure" conclusion). Keeping that stale entry classified would make
  // every retry re-derive FAIL from its own earlier blocked attempt forever —
  // defeating the one scenario the retry exists to recover from — so a prior
  // completed run of THIS SAME job is now excluded too (#6YaIaU).
  const savedWorkflow = process.env.GITHUB_WORKFLOW;
  const savedJob = process.env.GITHUB_JOB;
  try {
    process.env.GITHUB_WORKFLOW = 'Closeout gate';
    process.env.GITHUB_JOB = 'gate';
    // Running self (IN_PROGRESS) + a prior self FAILURE from an earlier
    // BLOCKED attempt at this same head + legitimate external CI.
    const priorFailure = classifyLivePrState({
      repository: 'owner/repo',
      pr: {
        ...cleanPr(),
        statusCheckRollup: [
          { name: 'gate', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate' },
          { name: 'gate', status: 'COMPLETED', conclusion: 'FAILURE', workflowName: 'Closeout gate' },
          { name: 'ci', status: 'COMPLETED', conclusion: 'SUCCESS', workflowName: 'CI' },
        ],
      },
      unresolvedThreads: [],
      expectedHeadSha: 'head123',
      expectedBaseSha: 'base123',
      gateAttestation: cleanAttestation(),
    });
    // Neither self instance blocks a retry from reaching PASS on its own
    // merits — every other signal (mergeability, review decision, unresolved
    // threads, gate attestation, and this legitimate external CI check) is
    // independently re-derived from live state and still fully classified.
    assert.equal(priorFailure.status, 'PASS', 'a prior FAILED self-workflow run at this head no longer sticks — a retry can recover');
    assert.equal(
      priorFailure.checks.filter((c) => c.workflowName === 'Closeout gate').length,
      0,
      'both the IN_PROGRESS and the prior COMPLETED self-workflow checks are omitted',
    );
    assert.equal(priorFailure.checks.filter((c) => c.name === 'ci').length, 1, 'a genuinely unrelated check is still classified');

    // Now verify the pure running-self case (no prior failure): PASS is reachable.
    const clean = classifyLivePrState({
      repository: 'owner/repo',
      pr: {
        ...cleanPr(),
        statusCheckRollup: [
          { name: 'gate', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate' },
          { name: 'ci', status: 'COMPLETED', conclusion: 'SUCCESS', workflowName: 'CI' },
        ],
      },
      unresolvedThreads: [],
      expectedHeadSha: 'head123',
      expectedBaseSha: 'base123',
      gateAttestation: cleanAttestation(),
    });
    assert.equal(clean.status, 'PASS', 'with only the running self-check omitted, PASS is reachable');
    assert.equal(
      clean.checks.filter((c) => c.workflowName === 'Closeout gate').length,
      0,
      'the running self-check is omitted from the returned rollup',
    );

    // #6YSx9w: a SIBLING job in the same workflow must NOT be excluded. If the
    // workflow runs gate + preview, and preview is still IN_PROGRESS, the gate
    // must see preview as a blocker (not omit it). Only the gate's OWN
    // IN_PROGRESS check (name === GITHUB_JOB) is omitted.
    const sibling = classifyLivePrState({
      repository: 'owner/repo',
      pr: {
        ...cleanPr(),
        statusCheckRollup: [
          { name: 'gate', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate' },
          { name: 'preview', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate' },
          { name: 'ci', status: 'COMPLETED', conclusion: 'SUCCESS', workflowName: 'CI' },
        ],
      },
      unresolvedThreads: [],
      expectedHeadSha: 'head123',
      expectedBaseSha: 'base123',
      gateAttestation: cleanAttestation(),
    });
    assert.equal(sibling.status, 'BLOCKED', 'sibling preview IN_PROGRESS still BLOCKS (not excluded by #6YSx9w)');
    const siblingPreview = sibling.checks.find((c) => c.name === 'preview' && c.workflowName === 'Closeout gate');
    assert.ok(siblingPreview, 'the sibling preview check is RETAINED in the rollup');
    assert.equal(sibling.checks.filter((c) => c.name === 'gate' && c.status === 'IN_PROGRESS').length, 0,
      'only the gate OWN IN_PROGRESS check is omitted');
  } finally {
    if (savedWorkflow === undefined) delete process.env.GITHUB_WORKFLOW;
    else process.env.GITHUB_WORKFLOW = savedWorkflow;
    if (savedJob === undefined) delete process.env.GITHUB_JOB;
    else process.env.GITHUB_JOB = savedJob;
  }
});

test('a rollup that legitimately contains only this job\'s own check can still reach PASS (chatgpt-codex-connector PR7 #6Yb3lX)', () => {
  // A consumer that installs ONLY this gate as their CI (no separate lint/
  // test/build workflow) has a rollup that, at the moment this job classifies
  // itself, contains nothing but this job's own (always in-progress, always
  // self-excluded) check. Before the fix, `!checks.length` read the
  // POST-exclusion array, so this case was indistinguishable from GitHub
  // genuinely returning no check data at all -- the gate could never PASS
  // standalone, forever blocked on "No live GitHub check results were
  // returned." even though every other signal was clean.
  const savedWorkflow = process.env.GITHUB_WORKFLOW;
  const savedJob = process.env.GITHUB_JOB;
  try {
    process.env.GITHUB_WORKFLOW = 'Closeout gate';
    process.env.GITHUB_JOB = 'gate';
    const standalone = classifyLivePrState({
      repository: 'owner/repo',
      pr: {
        ...cleanPr(),
        statusCheckRollup: [
          { name: 'gate', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate' },
        ],
      },
      unresolvedThreads: [],
      expectedHeadSha: 'head123',
      expectedBaseSha: 'base123',
      gateAttestation: cleanAttestation(),
    });
    assert.equal(standalone.status, 'PASS', 'a self-only rollup must not permanently block a standalone installation');
    assert.equal(standalone.checks.length, 0, 'the self check is still excluded from the returned rollup');

    // A genuinely empty/malformed rollup must still fail-closed: this is NOT
    // the same case, and the fix must not have widened it.
    const genuinelyEmpty = classifyLivePrState({
      repository: 'owner/repo',
      pr: { ...cleanPr(), statusCheckRollup: [] },
      unresolvedThreads: [],
      expectedHeadSha: 'head123',
      expectedBaseSha: 'base123',
      gateAttestation: cleanAttestation(),
    });
    assert.equal(genuinelyEmpty.status, 'BLOCKED');
    assert.match(genuinelyEmpty.evidence, /No live GitHub check results were returned/);

    const malformed = classifyLivePrState({
      repository: 'owner/repo',
      pr: { ...cleanPr(), statusCheckRollup: null },
      unresolvedThreads: [],
      expectedHeadSha: 'head123',
      expectedBaseSha: 'base123',
      gateAttestation: cleanAttestation(),
    });
    assert.equal(malformed.status, 'BLOCKED');
    assert.match(malformed.evidence, /No live GitHub check results were returned/);
  } finally {
    if (savedWorkflow === undefined) delete process.env.GITHUB_WORKFLOW;
    else process.env.GITHUB_WORKFLOW = savedWorkflow;
    if (savedJob === undefined) delete process.env.GITHUB_JOB;
    else process.env.GITHUB_JOB = savedJob;
  }
});

test('selfJobDisplayName excludes a matrixed/named job that GITHUB_JOB alone could never match (CodeRabbit PR7 #6YXkRF)', () => {
  // GITHUB_JOB is the YAML job id ("gate"); a consumer that runs the job in
  // a matrix gets a DISPLAYED check name like "gate (ubuntu-latest, 20)",
  // which never equals GITHUB_JOB. Without a resolved selfJobDisplayName,
  // self-exclusion silently no-ops and the gate can never see its own
  // in-progress check as excluded. Passing the caller-resolved true
  // displayed name closes that gap.
  const savedWorkflow = process.env.GITHUB_WORKFLOW;
  const savedJob = process.env.GITHUB_JOB;
  try {
    process.env.GITHUB_WORKFLOW = 'Closeout gate';
    process.env.GITHUB_JOB = 'gate';
    const withoutResolvedName = classifyLivePrState({
      repository: 'owner/repo',
      pr: {
        ...cleanPr(),
        statusCheckRollup: [
          { name: 'gate (ubuntu-latest, 20)', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate' },
          { name: 'ci', status: 'COMPLETED', conclusion: 'SUCCESS', workflowName: 'CI' },
        ],
      },
      unresolvedThreads: [], expectedHeadSha: 'head123', expectedBaseSha: 'base123', gateAttestation: cleanAttestation(),
    });
    assert.equal(withoutResolvedName.status, 'BLOCKED',
      'GITHUB_JOB alone never matches a matrix-suffixed displayed name, so self-exclusion silently no-ops');

    const withResolvedName = classifyLivePrState({
      repository: 'owner/repo',
      pr: {
        ...cleanPr(),
        statusCheckRollup: [
          { name: 'gate (ubuntu-latest, 20)', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate' },
          { name: 'ci', status: 'COMPLETED', conclusion: 'SUCCESS', workflowName: 'CI' },
        ],
      },
      unresolvedThreads: [], expectedHeadSha: 'head123', expectedBaseSha: 'base123', gateAttestation: cleanAttestation(),
      selfJobDisplayName: 'gate (ubuntu-latest, 20)',
    });
    assert.equal(withResolvedName.status, 'PASS', 'the resolved true displayed name correctly excludes the running self-check');

    // #6YSx9w must still hold with a resolved name: a sibling job is never excluded.
    const siblingStillBlocks = classifyLivePrState({
      repository: 'owner/repo',
      pr: {
        ...cleanPr(),
        statusCheckRollup: [
          { name: 'gate (ubuntu-latest, 20)', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate' },
          { name: 'preview (ubuntu-latest, 20)', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate' },
        ],
      },
      unresolvedThreads: [], expectedHeadSha: 'head123', expectedBaseSha: 'base123', gateAttestation: cleanAttestation(),
      selfJobDisplayName: 'gate (ubuntu-latest, 20)',
    });
    assert.equal(siblingStillBlocks.status, 'BLOCKED', 'a sibling job with a similarly-shaped name is still not excluded');
  } finally {
    if (savedWorkflow === undefined) delete process.env.GITHUB_WORKFLOW;
    else process.env.GITHUB_WORKFLOW = savedWorkflow;
    if (savedJob === undefined) delete process.env.GITHUB_JOB;
    else process.env.GITHUB_JOB = savedJob;
  }
});

test('selfJobDisplayName === false disables self-exclusion entirely instead of falling back to GITHUB_JOB (chatgpt-codex-connector PR7 #6YbMwM)', () => {
  // This job has NO name: override, so GITHUB_JOB ('gate') literally equals
  // its own displayed check name — the exact scenario the finding describes.
  // A sibling job independently ALSO displays as 'gate' (its own name:
  // override) and has FAILED. Before this fix, resolveCurrentJobDisplayName
  // detecting that collision returned null, classifyLivePrState fell back to
  // `selfJobDisplayName || GITHUB_JOB || null` = 'gate', and the filter
  // `check.name === 'gate'` matched and excluded BOTH checks — this job's own
  // in-progress one AND the sibling's genuine failure — letting an otherwise
  // clean PR wrongly reach PASS.
  const savedWorkflow = process.env.GITHUB_WORKFLOW;
  const savedJob = process.env.GITHUB_JOB;
  try {
    process.env.GITHUB_WORKFLOW = 'Closeout gate';
    process.env.GITHUB_JOB = 'gate';
    const result = classifyLivePrState({
      repository: 'owner/repo',
      pr: {
        ...cleanPr(),
        statusCheckRollup: [
          { name: 'gate', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate' },
          { name: 'gate', status: 'COMPLETED', conclusion: 'FAILURE', workflowName: 'Closeout gate' },
        ],
      },
      unresolvedThreads: [], expectedHeadSha: 'head123', expectedBaseSha: 'base123', gateAttestation: cleanAttestation(),
      selfJobDisplayName: false,
    });
    assert.equal(result.status, 'FAIL', 'the sibling FAILURE sharing this job\'s own name must stay visible, not be excluded alongside it');
    assert.equal(result.checks.filter((c) => c.name === 'gate').length, 2,
      'false must skip self-exclusion entirely — BOTH same-named checks remain in the rollup');
  } finally {
    if (savedWorkflow === undefined) delete process.env.GITHUB_WORKFLOW;
    else process.env.GITHUB_WORKFLOW = savedWorkflow;
    if (savedJob === undefined) delete process.env.GITHUB_JOB;
    else process.env.GITHUB_JOB = savedJob;
  }
});

test('resolveCurrentJobDisplayName resolves the current job\'s true displayed name by matching RUNNER_NAME (CodeRabbit PR7 #6YXkRF)', async () => {
  // --slurp wraps every page into one outer array, even when there is only
  // one page (gh api --help: "wrap all pages ... into an outer JSON
  // array") — the mock mirrors that shape, not a bare {jobs: [...]} object.
  const jobsResponse = [{ jobs: [
    { name: 'preview', runner_name: 'other-runner-1' },
    { name: 'gate (ubuntu-latest, 20)', runner_name: 'this-runner' },
  ] }];
  let capturedArgs;
  const runGh = async (args) => { capturedArgs = args; return jobsResponse; };
  const resolved = await resolveCurrentJobDisplayName({
    repository: 'owner/repo',
    runGh,
    env: { GITHUB_RUN_ID: '12345', RUNNER_NAME: 'this-runner' },
  });
  assert.equal(resolved, 'gate (ubuntu-latest, 20)', 'matches the job entry whose runner_name equals RUNNER_NAME');
  assert.deepEqual(capturedArgs, ['api', 'repos/owner/repo/actions/runs/12345/jobs', '--paginate', '--slurp'],
    'queries the Jobs API for this specific run, across all pages, wrapped so JSON.parse can handle it');
});

test('resolveCurrentJobDisplayName paginates so a runner match on a later API page is still found (CodeRabbit PR7 #6YZkoF, qodo PR7 pagination-unparsable follow-up)', async () => {
  let capturedArgs;
  const runGh = async (args) => {
    capturedArgs = args;
    // Simulates the real --paginate --slurp shape: an array of separate
    // page OBJECTS (gh api --help: "Each page is a separate JSON array or
    // object... --slurp to wrap all pages... into an outer JSON array") —
    // NOT one response object with an already-merged jobs array. The match
    // is deliberately on the second page, past the API's 30-per-page
    // default.
    const page1 = { jobs: Array.from({ length: 30 }, (_, i) => ({ name: `filler-${i}`, runner_name: `other-runner-${i}` })) };
    const page2 = { jobs: [{ name: 'gate (ubuntu-latest, 20)', runner_name: 'this-runner' }] };
    return [page1, page2];
  };
  const resolved = await resolveCurrentJobDisplayName({
    repository: 'owner/repo',
    runGh,
    env: { GITHUB_RUN_ID: '12345', RUNNER_NAME: 'this-runner' },
  });
  assert.ok(capturedArgs.includes('--paginate'), 'must request every page, not just the default 30-job first page');
  assert.ok(capturedArgs.includes('--slurp'), 'must wrap multi-page output so a single JSON.parse(stdout) can parse it (qodo PR7)');
  assert.equal(resolved, 'gate (ubuntu-latest, 20)', 'a match on the second page is still found once pages are flattened');
});

test('resolveCurrentJobDisplayName resolves uniquely when a reused self-hosted runner shares runner_name with an earlier completed job (CodeRabbit PR7 #6YZkoJ)', async () => {
  const runGh = async () => [{ jobs: [
    { name: 'earlier-job', runner_name: 'shared-runner', status: 'completed', conclusion: 'success' },
    { name: 'current-job', runner_name: 'shared-runner', status: 'in_progress', conclusion: null },
  ] }];
  const resolved = await resolveCurrentJobDisplayName({
    repository: 'owner/repo',
    runGh,
    env: { GITHUB_RUN_ID: '1', RUNNER_NAME: 'shared-runner' },
  });
  assert.equal(resolved, 'current-job', 'skips the earlier completed job sharing the same reused runner_name');
});

test('resolveCurrentJobDisplayName refuses to guess when multiple non-completed jobs share runner_name (CodeRabbit PR7 #6YZkoJ)', async () => {
  const runGh = async () => [{ jobs: [
    { name: 'queued-1', runner_name: 'shared-runner', status: 'in_progress', conclusion: null },
    { name: 'queued-2', runner_name: 'shared-runner', status: 'queued', conclusion: null },
  ] }];
  const resolved = await resolveCurrentJobDisplayName({
    repository: 'owner/repo',
    runGh,
    env: { GITHUB_RUN_ID: '1', RUNNER_NAME: 'shared-runner' },
  });
  assert.equal(resolved, null, 'an ambiguous non-completed match is not trustworthy — best-effort null, not a guess');
});

test('resolveCurrentJobDisplayName refuses a name shared with a genuinely different sibling job (chatgpt-codex-connector PR7 #6Yap8W / #6YbMwM)', async () => {
  // Two DIFFERENT jobs (different runner_name, so uniquely resolvable on
  // their own) happen to share the exact same displayed name. Returning
  // that name would make classifyLivePrState's name-based self-exclusion
  // ALSO exclude the sibling's own check entry, hiding a genuine sibling
  // failure. The collision is visible directly in this same Jobs API
  // response (both entries have name: 'gate').
  //
  // Resolves to `false`, NOT `null` (#6YbMwM): `null` tells the caller to
  // fall back to the legacy GITHUB_JOB matching, but that fallback is EQUALLY
  // unsafe whenever this job has no `name:` override (GITHUB_JOB then equals
  // the very 'gate' name just found ambiguous) — `false` instead tells the
  // caller to skip self-exclusion entirely, which classifyLivePrState's own
  // test below verifies.
  const runGh = async () => [{ jobs: [
    { name: 'gate', runner_name: 'this-runner', status: 'in_progress', conclusion: null },
    { name: 'gate', runner_name: 'other-runner', status: 'in_progress', conclusion: null },
  ] }];
  const resolved = await resolveCurrentJobDisplayName({
    repository: 'owner/repo',
    runGh,
    env: { GITHUB_RUN_ID: '1', RUNNER_NAME: 'this-runner' },
  });
  assert.equal(resolved, false, 'a name shared with a different job in this run must resolve to the no-exclusion sentinel, not null');
});

test('resolveCurrentJobDisplayName is best-effort: null on missing env, API failure, or no match (CodeRabbit PR7 #6YXkRF)', async () => {
  const alwaysCalled = { called: false };
  const failingRunGh = async () => { alwaysCalled.called = true; throw new Error('API rate limited'); };

  assert.equal(
    await resolveCurrentJobDisplayName({ repository: 'owner/repo', runGh: failingRunGh, env: {} }),
    null,
    'missing GITHUB_RUN_ID/RUNNER_NAME short-circuits to null without calling the API',
  );
  assert.equal(alwaysCalled.called, false, 'the API must not be called when required env vars are absent');

  assert.equal(
    await resolveCurrentJobDisplayName({
      repository: 'owner/repo', runGh: failingRunGh,
      env: { GITHUB_RUN_ID: '1', RUNNER_NAME: 'r' },
    }),
    null,
    'an API failure (rate limit, network) falls back to null, never throws',
  );

  const noMatchRunGh = async () => [{ jobs: [{ name: 'preview', runner_name: 'someone-else' }] }];
  assert.equal(
    await resolveCurrentJobDisplayName({
      repository: 'owner/repo', runGh: noMatchRunGh,
      env: { GITHUB_RUN_ID: '1', RUNNER_NAME: 'this-runner' },
    }),
    null,
    'no job entry matches this runner falls back to null',
  );

  // A bare (unwrapped) object, as if --slurp's outer array were missing —
  // the real gh --slurp output is always an array (per --help), so this is
  // the "malformed" shape here.
  const malformedRunGh = async () => ({ not: 'the expected shape' });
  assert.equal(
    await resolveCurrentJobDisplayName({
      repository: 'owner/repo', runGh: malformedRunGh,
      env: { GITHUB_RUN_ID: '1', RUNNER_NAME: 'this-runner' },
    }),
    null,
    'a malformed (non-array) response falls back to null rather than throwing',
  );

  // A well-formed page array whose page object has no `jobs` array.
  const missingJobsRunGh = async () => [{ not: 'the expected shape' }];
  assert.equal(
    await resolveCurrentJobDisplayName({
      repository: 'owner/repo', runGh: missingJobsRunGh,
      env: { GITHUB_RUN_ID: '1', RUNNER_NAME: 'this-runner' },
    }),
    null,
    'a page object with no jobs array falls back to null rather than throwing',
  );
});

test('resolveWorkflowRunPath resolves the workflow file path from the run endpoint (chatgpt-codex-connector PR7 #6Yb44Si)', async () => {
  const calls = [];
  const runGh = async (args) => {
    calls.push(args);
    return { path: '.github/workflows/closeout-gate.yml' };
  };
  const path = await resolveWorkflowRunPath({ repository: 'owner/repo', runGh, repo: 'C:/repo', runId: '123' });
  assert.equal(path, '.github/workflows/closeout-gate.yml');
  assert.deepEqual(calls, [['api', 'repos/owner/repo/actions/runs/123']]);
});

test('resolveWorkflowRunPath is best-effort: null on missing args, API failure, or a missing path field', async () => {
  assert.equal(await resolveWorkflowRunPath({ runGh: async () => ({ path: 'x' }), repo: 'C:/repo', runId: '1' }), null, 'missing repository short-circuits to null');
  assert.equal(await resolveWorkflowRunPath({ repository: 'owner/repo', repo: 'C:/repo', runId: '1' }), null, 'missing runGh short-circuits to null');
  assert.equal(await resolveWorkflowRunPath({ repository: 'owner/repo', runGh: async () => ({ path: 'x' }), repo: 'C:/repo' }), null, 'missing runId short-circuits to null');
  assert.equal(
    await resolveWorkflowRunPath({ repository: 'owner/repo', runGh: async () => { throw new Error('rate limited'); }, repo: 'C:/repo', runId: '1' }),
    null,
    'an API failure falls back to null, never throws',
  );
  assert.equal(
    await resolveWorkflowRunPath({ repository: 'owner/repo', runGh: async () => ({ not: 'the expected shape' }), repo: 'C:/repo', runId: '1' }),
    null,
    'a response with no path field falls back to null',
  );
});

test('detectCrossWorkflowSelfExclusionCollision returns no collision and no network calls when no other run id shares this displayed name (the common case)', async () => {
  let calls = 0;
  const runGh = async () => { calls += 1; return { path: 'irrelevant' }; };
  const pr = {
    statusCheckRollup: [
      { name: 'gate', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/999/job/1' },
      { name: 'ci', status: 'COMPLETED', conclusion: 'SUCCESS', workflowName: 'CI' },
    ],
  };
  const result = await detectCrossWorkflowSelfExclusionCollision({
    pr,
    selfWorkflowName: 'Closeout gate',
    selfJobName: 'gate',
    selfWorkflowPath: '.github/workflows/closeout-gate.yml',
    repository: 'owner/repo',
    runGh,
    repo: 'C:/repo',
    env: { GITHUB_RUN_ID: '999' },
  });
  assert.deepEqual(result, { collision: false, networkCallsMade: false });
  assert.equal(calls, 0, 'no extra API call is made when every same-named check belongs to this run');
});

test('detectCrossWorkflowSelfExclusionCollision reports a collision (with network calls made) when a same-named check belongs to a different workflow file (chatgpt-codex-connector PR7 #6Yb44Si)', async () => {
  const pr = {
    statusCheckRollup: [
      { name: 'gate', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/999/job/1' },
      { name: 'gate', status: 'COMPLETED', conclusion: 'FAILURE', workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/555/job/2' },
    ],
  };
  const runGh = async (args) => {
    if (args[1] === 'repos/owner/repo/actions/runs/555') return { path: '.github/workflows/some-other-gate.yml' };
    throw new Error(`unexpected call: ${args.join(' ')}`);
  };
  const result = await detectCrossWorkflowSelfExclusionCollision({
    pr,
    selfWorkflowName: 'Closeout gate',
    selfJobName: 'gate',
    selfWorkflowPath: '.github/workflows/closeout-gate.yml',
    repository: 'owner/repo',
    runGh,
    repo: 'C:/repo',
    env: { GITHUB_RUN_ID: '999' },
  });
  assert.deepEqual(result, { collision: true, networkCallsMade: true });
});

test('detectCrossWorkflowSelfExclusionCollision reports no collision (but network calls made) when the other run id genuinely resolves to the same workflow file', async () => {
  const pr = {
    statusCheckRollup: [
      { name: 'gate', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/999/job/1' },
      { name: 'gate', status: 'COMPLETED', conclusion: 'FAILURE', workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/555/job/2' },
    ],
  };
  const runGh = async () => ({ path: '.github/workflows/closeout-gate.yml' });
  const result = await detectCrossWorkflowSelfExclusionCollision({
    pr,
    selfWorkflowName: 'Closeout gate',
    selfJobName: 'gate',
    selfWorkflowPath: '.github/workflows/closeout-gate.yml',
    repository: 'owner/repo',
    runGh,
    repo: 'C:/repo',
    env: { GITHUB_RUN_ID: '999' },
  });
  assert.deepEqual(result, { collision: false, networkCallsMade: true });
});

test('detectCrossWorkflowSelfExclusionCollision fails safe (collision: true) when the other run\'s path cannot be resolved', async () => {
  const pr = {
    statusCheckRollup: [
      { name: 'gate', status: 'COMPLETED', conclusion: 'FAILURE', workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/555/job/2' },
    ],
  };
  const runGh = async () => { throw new Error('rate limited'); };
  const result = await detectCrossWorkflowSelfExclusionCollision({
    pr,
    selfWorkflowName: 'Closeout gate',
    selfJobName: 'gate',
    selfWorkflowPath: '.github/workflows/closeout-gate.yml',
    repository: 'owner/repo',
    runGh,
    repo: 'C:/repo',
    env: { GITHUB_RUN_ID: '999' },
  });
  assert.equal(result.collision, true, 'an unresolvable other-run path must not be treated as safe to exclude');
  assert.equal(result.networkCallsMade, true);
});

test('detectCrossWorkflowSelfExclusionCollision fails safe (collision: true, no network calls) when a name-matching check has no resolvable run id (CodeRabbit PR7 #6Yb44Sm)', async () => {
  let calls = 0;
  const pr = {
    statusCheckRollup: [
      // Matches selfWorkflowName/selfJobName but carries no detailsUrl at all
      // — cannot be proven to be this run's own check.
      { name: 'gate', status: 'COMPLETED', conclusion: 'FAILURE', workflowName: 'Closeout gate' },
    ],
  };
  const runGh = async () => { calls += 1; return { path: '.github/workflows/closeout-gate.yml' }; };
  const result = await detectCrossWorkflowSelfExclusionCollision({
    pr,
    selfWorkflowName: 'Closeout gate',
    selfJobName: 'gate',
    selfWorkflowPath: '.github/workflows/closeout-gate.yml',
    repository: 'owner/repo',
    runGh,
    repo: 'C:/repo',
    env: { GITHUB_RUN_ID: '999' },
  });
  assert.deepEqual(result, { collision: true, networkCallsMade: false }, 'an unidentifiable match fails safe immediately, without any request');
  assert.equal(calls, 0);
});

test('detectCrossWorkflowSelfExclusionCollision fails safe (collision: true, no network calls) when this run\'s own path could not be resolved (cubic P1, follow-up to #6Yb44Si)', async () => {
  let calls = 0;
  const pr = {
    statusCheckRollup: [
      { name: 'gate', status: 'COMPLETED', conclusion: 'FAILURE', workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/555/job/2' },
    ],
  };
  const runGh = async () => { calls += 1; return { path: 'whatever' }; };
  const result = await detectCrossWorkflowSelfExclusionCollision({
    pr,
    selfWorkflowName: 'Closeout gate',
    selfJobName: 'gate',
    selfWorkflowPath: null,
    repository: 'owner/repo',
    runGh,
    repo: 'C:/repo',
    env: { GITHUB_RUN_ID: '999' },
  });
  assert.deepEqual(result, { collision: true, networkCallsMade: false }, 'with no baseline to compare against, self-exclusion must not silently continue on the name match alone');
  assert.equal(calls, 0, 'no request is made — this is an immediate fail-safe short-circuit');
});

test('readLivePrState disables self-exclusion end-to-end when a same-named check belongs to a different workflow file, letting the sibling\'s FAILURE surface (chatgpt-codex-connector PR7 #6Yb44Si)', async () => {
  const savedWorkflow = process.env.GITHUB_WORKFLOW;
  const savedJob = process.env.GITHUB_JOB;
  const savedRunId = process.env.GITHUB_RUN_ID;
  const savedRunnerName = process.env.RUNNER_NAME;
  process.env.GITHUB_WORKFLOW = 'Closeout gate';
  process.env.GITHUB_JOB = 'gate';
  process.env.GITHUB_RUN_ID = '999';
  process.env.RUNNER_NAME = 'this-runner';
  try {
    const collidingPr = {
      ...cleanPr(),
      statusCheckRollup: [
        { name: 'gate', status: 'COMPLETED', conclusion: 'SUCCESS', workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/999/job/1' },
        // A DIFFERENT workflow file whose displayed workflow+job name happens
        // to collide with this one, and whose check is a genuine FAILURE.
        { name: 'gate', status: 'COMPLETED', conclusion: 'FAILURE', workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/555/job/2' },
      ],
    };
    const runGh = async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return collidingPr;
      if (args[0] === 'api' && args[1] === 'repos/owner/repo/actions/runs/999/jobs') {
        return [{ jobs: [{ name: 'gate', runner_name: 'this-runner' }] }];
      }
      if (args[0] === 'api' && args[1] === 'repos/owner/repo/actions/runs/999') return { path: '.github/workflows/closeout-gate.yml' };
      if (args[0] === 'api' && args[1] === 'repos/owner/repo/actions/runs/555') return { path: '.github/workflows/some-other-gate.yml' };
      if (args.includes('--paginate')) return [[approvedReview()]];
      return {
        data: { repository: { pullRequest: { reviewThreads: {
          nodes: [],
          pageInfo: { hasNextPage: false, endCursor: null },
        } } } },
      };
    };
    const result = await readLivePrState({
      repo: 'C:/repo',
      expectedHeadSha: 'head123',
      expectedBaseSha: 'base123',
      expectedConfigDigest: 'cfg123',
      runGh,
    });
    assert.equal(result.status, 'FAIL', 'the colliding workflow\'s genuine FAILURE must surface, not be silently excluded');
  } finally {
    if (savedWorkflow === undefined) delete process.env.GITHUB_WORKFLOW;
    else process.env.GITHUB_WORKFLOW = savedWorkflow;
    if (savedJob === undefined) delete process.env.GITHUB_JOB;
    else process.env.GITHUB_JOB = savedJob;
    if (savedRunId === undefined) delete process.env.GITHUB_RUN_ID;
    else process.env.GITHUB_RUN_ID = savedRunId;
    if (savedRunnerName === undefined) delete process.env.RUNNER_NAME;
    else process.env.RUNNER_NAME = savedRunnerName;
  }
});

test('readLivePrState blocks when PR state changes during the collision check\'s own verification window (CodeRabbit PR7 #6Yb44So)', async () => {
  const savedWorkflow = process.env.GITHUB_WORKFLOW;
  const savedJob = process.env.GITHUB_JOB;
  const savedRunId = process.env.GITHUB_RUN_ID;
  const savedRunnerName = process.env.RUNNER_NAME;
  process.env.GITHUB_WORKFLOW = 'Closeout gate';
  process.env.GITHUB_JOB = 'gate';
  process.env.GITHUB_RUN_ID = '999';
  process.env.RUNNER_NAME = 'this-runner';
  try {
    const collidingPr = {
      ...cleanPr(),
      statusCheckRollup: [
        { name: 'gate', status: 'COMPLETED', conclusion: 'SUCCESS', workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/999/job/1' },
        { name: 'gate', status: 'COMPLETED', conclusion: 'FAILURE', workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/555/job/2' },
      ],
    };
    // A same-shape PR whose merge state flips — simulating a live change that
    // lands specifically during detectCrossWorkflowSelfExclusionCollision's
    // own resolveWorkflowRunPath request, after every earlier snapshot in
    // this function already agreed and was found stable.
    const changedPr = { ...collidingPr, mergeStateStatus: 'DIRTY' };
    let prCalls = 0;
    const runGh = async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') { prCalls += 1; return prCalls <= 5 ? collidingPr : changedPr; }
      if (args[0] === 'api' && args[1] === 'repos/owner/repo/actions/runs/999/jobs') {
        return [{ jobs: [{ name: 'gate', runner_name: 'this-runner' }] }];
      }
      if (args[0] === 'api' && args[1] === 'repos/owner/repo/actions/runs/999') return { path: '.github/workflows/closeout-gate.yml' };
      if (args[0] === 'api' && args[1] === 'repos/owner/repo/actions/runs/555') return { path: '.github/workflows/some-other-gate.yml' };
      if (args.includes('--paginate')) return [[approvedReview()]];
      return {
        data: { repository: { pullRequest: { reviewThreads: {
          nodes: [],
          pageInfo: { hasNextPage: false, endCursor: null },
        } } } },
      };
    };
    const result = await readLivePrState({
      repo: 'C:/repo',
      expectedHeadSha: 'head123',
      expectedBaseSha: 'base123',
      expectedConfigDigest: 'cfg123',
      runGh,
    });
    assert.equal(result.status, 'BLOCKED');
    assert.match(result.evidence, /cross-workflow collision verification window/i);
    assert.equal(prCalls, 6, 'the collision check\'s own network call must trigger exactly one extra PR re-read');
  } finally {
    if (savedWorkflow === undefined) delete process.env.GITHUB_WORKFLOW;
    else process.env.GITHUB_WORKFLOW = savedWorkflow;
    if (savedJob === undefined) delete process.env.GITHUB_JOB;
    else process.env.GITHUB_JOB = savedJob;
    if (savedRunId === undefined) delete process.env.GITHUB_RUN_ID;
    else process.env.GITHUB_RUN_ID = savedRunId;
    if (savedRunnerName === undefined) delete process.env.RUNNER_NAME;
    else process.env.RUNNER_NAME = savedRunnerName;
  }
});

test('classifies legacy StatusContext checks from state only', () => {
  const outcomes = new Map([
    ['SUCCESS', 'PASS'],
    ['EXPECTED', 'BLOCKED'],
    ['PENDING', 'BLOCKED'],
    ['FAILURE', 'FAIL'],
    ['ERROR', 'FAIL'],
  ]);

  for (const [state, expected] of outcomes) {
    const result = classifyPr({
      ...cleanPr(),
      statusCheckRollup: [{ __typename: 'StatusContext', context: 'legacy-ci', state }],
    });
    assert.equal(result.status, expected, `StatusContext ${state}`);
  }
});

test('passes a CheckRun only when it is completed successfully', () => {
  const outcomes = [
    [{ status: 'COMPLETED', conclusion: 'SUCCESS' }, 'PASS'],
    [{ status: 'IN_PROGRESS', conclusion: 'SUCCESS' }, 'BLOCKED'],
    [{ status: 'COMPLETED', conclusion: 'EXPECTED' }, 'BLOCKED'],
    [{ status: 'COMPLETED', conclusion: null }, 'BLOCKED'],
  ];

  for (const [check, expected] of outcomes) {
    const result = classifyPr({
      ...cleanPr(),
      statusCheckRollup: [{ __typename: 'CheckRun', name: 'ci', ...check }],
    });
    assert.equal(result.status, expected, `CheckRun ${check.status}/${check.conclusion}`);
  }
});

test('classifies a STARTUP_FAILURE check conclusion as failure', () => {
  const result = classifyPr({
    ...cleanPr(),
    statusCheckRollup: [{ name: 'startup-failed', status: 'COMPLETED', conclusion: 'STARTUP_FAILURE' }],
  });
  assert.equal(result.status, 'FAIL');
});

test('blocks malformed check rollup entries without throwing', () => {
  assert.doesNotThrow(() => classifyPr({ ...cleanPr(), statusCheckRollup: [null] }));
  const result = classifyPr({ ...cleanPr(), statusCheckRollup: [null, {}, 'invalid'] });
  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.checks.length, 3);
});

test('blocks an empty check rollup', () => {
  const result = classifyPr({ ...cleanPr(), statusCheckRollup: [] });
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /no live GitHub check results/i);
});

test('requires GitHub to report an explicit non-draft PR', () => {
  for (const isDraft of [true, null, undefined]) {
    const result = classifyPr({ ...cleanPr(), isDraft });
    assert.equal(result.status, 'BLOCKED', `isDraft=${isDraft}`);
  }
  assert.equal(classifyPr({ ...cleanPr(), isDraft: false }).status, 'PASS');
});

test('requires both MERGEABLE and CLEAN merge state', () => {
  const blockers = [
    { mergeable: 'UNKNOWN', mergeStateStatus: 'CLEAN' },
    { mergeable: 'MERGEABLE', mergeStateStatus: 'UNSTABLE' },
    { mergeable: 'MERGEABLE', mergeStateStatus: 'BLOCKED' },
  ];

  for (const mergeState of blockers) {
    const result = classifyPr({ ...cleanPr(), ...mergeState });
    assert.equal(result.status, 'BLOCKED', `${mergeState.mergeable}/${mergeState.mergeStateStatus}`);
  }
  assert.equal(classifyPr(cleanPr()).status, 'PASS');
});

test('fails conflicting or dirty merge state', () => {
  const conflicting = classifyPr({ ...cleanPr(), mergeable: 'CONFLICTING' });
  const dirty = classifyPr({ ...cleanPr(), mergeStateStatus: 'DIRTY' });
  assert.equal(conflicting.status, 'FAIL');
  assert.equal(dirty.status, 'FAIL');
});

test('fails a changes-requested review decision', () => {
  const result = classifyPr({ ...cleanPr(), reviewDecision: 'CHANGES_REQUESTED' });
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /requests changes/i);
});

test('blocks when review-thread pagination repeats a cursor', async () => {
  const runGh = async (args) => {
    if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
    if (args[0] === 'pr') return cleanPr();
    if (args.includes('--paginate')) return [[approvedReview()]];
    return {
      data: { repository: { pullRequest: { reviewThreads: {
        nodes: [],
        pageInfo: { hasNextPage: true, endCursor: 'repeated' },
      } } } },
    };
  };

  const result = await readLivePrState({
    repo: 'C:/repo',
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    expectedConfigDigest: 'cfg123',
    runGh,
  });
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /pagination did not advance/i);
});

test('queries live PR metadata and paginates unresolved review threads', async () => {
  // GITHUB_RUN_ID/RUNNER_NAME are ambient ONLY when this test itself happens
  // to run inside a real GitHub Actions job (as it does in this repo's own
  // CI matrix) — present there, absent on a local dev machine. Left
  // uncontrolled, resolveCurrentJobDisplayName's conditional extra `api`
  // call would make the exact call-count assertion below pass locally and
  // fail in CI (or vice versa). Clear both so the call count is
  // deterministic regardless of where the test runs.
  const savedRunId = process.env.GITHUB_RUN_ID;
  const savedRunnerName = process.env.RUNNER_NAME;
  delete process.env.GITHUB_RUN_ID;
  delete process.env.RUNNER_NAME;
  try {
    const calls = [];
    const runGh = async (args) => {
      calls.push(args);
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return cleanPr();
      if (args.includes('--paginate')) return [[approvedReview()]];
      const cursorArgument = args.find((value) => String(value).startsWith('cursor='));
      if (!cursorArgument) {
        return {
          data: { repository: { pullRequest: { reviewThreads: {
            nodes: [{ isResolved: false, isOutdated: false, path: 'src/a.ts', line: 4, comments: { nodes: [{ url: 'https://github.example/comment/1' }] } }],
            pageInfo: { hasNextPage: true, endCursor: 'next-page' },
          } } } },
        };
      }
      return {
        data: { repository: { pullRequest: { reviewThreads: {
          nodes: [{ isResolved: true, path: 'src/b.ts', line: 2, comments: { nodes: [] } }],
          pageInfo: { hasNextPage: false, endCursor: null },
        } } } },
      };
    };
    const result = await readLivePrState({
      repo: 'C:/repo',
      expectedHeadSha: 'head123',
      expectedBaseSha: 'base123',
      expectedConfigDigest: 'cfg123',
      runGh,
    });
    assert.equal(result.status, 'BLOCKED');
    assert.equal(result.unresolvedThreads.length, 1);
    // Stable path: five gate-attestation snapshots (first, final, terminal,
    // post-thread, verified — the last re-checking PR/attestation stability
    // across the post-thread review-thread walk's own window, chatgpt-codex-
    // connector PR7 #Yb3lQ) + four review-thread walks (2 pages each with
    // this mock; the fourth re-checks threads across the verified snapshot's
    // own window, CodeRabbit PR7 #6Yb44Se) = 5 snapshots + 8 thread pages
    // → 13 api calls. Neither resolveCurrentJobDisplayName nor
    // resolveWorkflowRunPath (CodeRabbit PR7 #6Yb44Sk) makes an additional
    // call here: both short-circuit on the absent GITHUB_RUN_ID (cleared
    // above), and detectCrossWorkflowSelfExclusionCollision short-circuits in
    // turn on the resulting null selfWorkflowPath. A future change to any of
    // these three resolvers could affect this count.
    assert.equal(calls.filter(([command]) => command === 'api').length, 13);
  } finally {
    if (savedRunId === undefined) delete process.env.GITHUB_RUN_ID;
    else process.env.GITHUB_RUN_ID = savedRunId;
    if (savedRunnerName === undefined) delete process.env.RUNNER_NAME;
    else process.env.RUNNER_NAME = savedRunnerName;
  }
});

test('readLivePrState resolves the current job\'s displayed name via the Jobs API and reaches PASS for a matrixed self-check (CodeRabbit PR7 #6YXkRF)', async () => {
  const savedWorkflow = process.env.GITHUB_WORKFLOW;
  const savedJob = process.env.GITHUB_JOB;
  const savedRunId = process.env.GITHUB_RUN_ID;
  const savedRunnerName = process.env.RUNNER_NAME;
  process.env.GITHUB_WORKFLOW = 'Closeout gate';
  process.env.GITHUB_JOB = 'gate';
  process.env.GITHUB_RUN_ID = '999';
  process.env.RUNNER_NAME = 'this-runner';
  try {
    // Matrix-expanded displayed name — never equal to GITHUB_JOB ("gate")
    // alone, so PASS is reachable here ONLY if readLivePrState actually
    // resolved and threaded the true displayed name through.
    const matrixedPr = {
      ...cleanPr(),
      statusCheckRollup: [
        // detailsUrl identifies this as run 999's OWN check (#6Yb44Sm/#6Yb44Si)
        // -- without it, the unidentified-run-id fail-safe would disable
        // self-exclusion regardless of what this test actually exercises.
        { name: 'gate (ubuntu-latest, 20)', status: 'IN_PROGRESS', conclusion: null, workflowName: 'Closeout gate', detailsUrl: 'https://github.example/owner/repo/actions/runs/999/job/1' },
        { name: 'ci', status: 'COMPLETED', conclusion: 'SUCCESS', workflowName: 'CI' },
      ],
    };
    let jobsApiCalled = false;
    const callOrder = [];
    const runGh = async (args) => {
      if (args[0] === 'repo') { callOrder.push('repo'); return { nameWithOwner: 'owner/repo' }; }
      if (args[0] === 'pr') { callOrder.push('pr'); return matrixedPr; }
      if (args[0] === 'api' && args[1] === 'repos/owner/repo/actions/runs/999/jobs') {
        jobsApiCalled = true;
        callOrder.push('jobs');
        return [{ jobs: [{ name: 'gate (ubuntu-latest, 20)', runner_name: 'this-runner' }] }];
      }
      // resolveWorkflowRunPath's own endpoint (#6Yb44Si/#6Yb44Sr): distinct
      // from the Jobs API call above. Its own path resolving successfully
      // means the checked-in fail-safe (an unresolvable OWN path disables
      // self-exclusion entirely) does not fire, letting this test still
      // isolate what it actually means to test — the Jobs API name
      // resolution reaching PASS.
      if (args[0] === 'api' && args[1] === 'repos/owner/repo/actions/runs/999') {
        return { path: '.github/workflows/closeout-gate.yml' };
      }
      if (args.includes('--paginate')) { callOrder.push('reviews'); return [[approvedReview()]]; }
      callOrder.push('threads');
      return {
        data: { repository: { pullRequest: { reviewThreads: {
          nodes: [],
          pageInfo: { hasNextPage: false, endCursor: null },
        } } } },
      };
    };
    const result = await readLivePrState({
      repo: 'C:/repo',
      expectedHeadSha: 'head123',
      expectedBaseSha: 'base123',
      expectedConfigDigest: 'cfg123',
      runGh,
    });
    assert.equal(jobsApiCalled, true, 'the Jobs API must actually be queried');
    assert.equal(result.status, 'PASS', 'the resolved true displayed name lets the matrixed self-check be excluded, reaching PASS');
    // chatgpt-codex-connector PR7 #6YaIas: the Jobs API call must happen
    // BEFORE any PR snapshot is taken, so its own latency is covered by the
    // SAME stability-tuple re-verification chain that protects every other
    // network round-trip in readLivePrState — not after the terminal
    // snapshot sequence, where a change during this call would never be
    // rechecked.
    assert.equal(callOrder[0], 'repo', 'repo identity is resolved first');
    assert.equal(callOrder[1], 'jobs', 'the Jobs API is queried before any PR snapshot is taken');
    assert.ok(callOrder.slice(2).includes('pr'), 'a PR snapshot is still taken afterward');
  } finally {
    if (savedWorkflow === undefined) delete process.env.GITHUB_WORKFLOW;
    else process.env.GITHUB_WORKFLOW = savedWorkflow;
    if (savedJob === undefined) delete process.env.GITHUB_JOB;
    else process.env.GITHUB_JOB = savedJob;
    if (savedRunId === undefined) delete process.env.GITHUB_RUN_ID;
    else process.env.GITHUB_RUN_ID = savedRunId;
    if (savedRunnerName === undefined) delete process.env.RUNNER_NAME;
    else process.env.RUNNER_NAME = savedRunnerName;
  }
});

test('re-reads review threads after the terminal snapshot and requires stability', async () => {
  // Stable path does four review-thread reads: after PR/review stability,
  // after the terminal PR+attestation snapshot, after the post-thread
  // PR/gate re-fetch, and after the final verified PR/attestation snapshot
  // (CodeRabbit PR7 #6Yb44Se). All four must match.
  let threadReads = 0;
  const result = await readLivePrState({
    repo: 'C:/repo',
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return cleanPr();
      if (args.includes('--paginate')) return [[approvedReview()]];
      const cursorArgument = args.find((value) => String(value).startsWith('cursor='));
      if (!cursorArgument) {
        threadReads += 1;
        return {
          data: { repository: { pullRequest: { reviewThreads: {
            nodes: [{ isResolved: false, isOutdated: false, path: 'src/a.ts', line: 4, comments: { nodes: [{ url: 'https://github.example/comment/1' }] } }],
            pageInfo: { hasNextPage: false, endCursor: null },
          } } } },
        };
      }
      return {
        data: { repository: { pullRequest: { reviewThreads: {
          nodes: [],
          pageInfo: { hasNextPage: false, endCursor: null },
        } } } },
      };
    },
  });
  assert.equal(threadReads, 4, 'stable path must re-read review threads after terminal, post-thread, and verified snapshots');
  assert.equal(result.unresolvedThreads.length, 1);
});

test('blocks when review threads change during the post-thread verification window', async () => {
  let threadReads = 0;
  const openThread = {
    isResolved: false,
    isOutdated: false,
    path: 'src/a.ts',
    line: 4,
    comments: { nodes: [{ url: 'https://github.example/comment/1' }] },
  };
  const result = await readLivePrState({
    repo: 'C:/repo',
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return cleanPr();
      if (args.includes('--paginate')) return [[approvedReview()]];
      const cursorArgument = args.find((value) => String(value).startsWith('cursor='));
      if (!cursorArgument) {
        threadReads += 1;
        // First two walks agree (empty). Third (post-thread) surfaces a new
        // unresolved thread opened during the PR/gate re-fetch window.
        const nodes = threadReads >= 3 ? [openThread] : [];
        return {
          data: { repository: { pullRequest: { reviewThreads: {
            nodes,
            pageInfo: { hasNextPage: false, endCursor: null },
          } } } },
        };
      }
      return {
        data: { repository: { pullRequest: { reviewThreads: {
          nodes: [],
          pageInfo: { hasNextPage: false, endCursor: null },
        } } } },
      };
    },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /threads changed during post-thread/i);
  assert.equal(result.unresolvedThreads.length, 1);
  assert.equal(threadReads, 3);
});

test('blocks when review threads change during the final verified PR/attestation window (CodeRabbit PR7 #6Yb44Se)', async () => {
  // postThreadUnresolvedThreads (the third walk) was fetched BEFORE
  // verifiedPr/verifiedGateSnapshot -- a thread reopened during either of
  // those two requests must still be caught by a FOURTH walk, not
  // classified away using the now-stale third walk's empty result.
  let threadReads = 0;
  const openThread = {
    isResolved: false,
    isOutdated: false,
    path: 'src/a.ts',
    line: 4,
    comments: { nodes: [{ url: 'https://github.example/comment/1' }] },
  };
  const result = await readLivePrState({
    repo: 'C:/repo',
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return cleanPr();
      if (args.includes('--paginate')) return [[approvedReview()]];
      const cursorArgument = args.find((value) => String(value).startsWith('cursor='));
      if (!cursorArgument) {
        threadReads += 1;
        // First three walks agree (empty). Fourth (verified) surfaces a new
        // unresolved thread opened during the verifiedPr/verifiedGateSnapshot
        // window.
        const nodes = threadReads >= 4 ? [openThread] : [];
        return {
          data: { repository: { pullRequest: { reviewThreads: {
            nodes,
            pageInfo: { hasNextPage: false, endCursor: null },
          } } } },
        };
      }
      return {
        data: { repository: { pullRequest: { reviewThreads: {
          nodes: [],
          pageInfo: { hasNextPage: false, endCursor: null },
        } } } },
      };
    },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /threads changed during the final PR\/attestation/i);
  assert.equal(result.unresolvedThreads.length, 1);
  assert.equal(threadReads, 4);
});

test('blocks when the PR head changes during live verification', async () => {
  let prReads = 0;
  const result = await readLivePrState({
    repo: 'C:/repo',
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') {
        prReads += 1;
        return prReads === 1 ? cleanPr() : { ...cleanPr(), headRefOid: 'concurrent-head' };
      }
      if (args.includes('--paginate')) return [[approvedReview()]];
      return {
        data: { repository: { pullRequest: { reviewThreads: {
          nodes: [],
          pageInfo: { hasNextPage: false, endCursor: null },
        } } } },
      };
    },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /changed during verification/i);
  assert.equal(prReads, 2);
});

test('blocks when checks or review state change during live verification', async () => {
  for (const concurrentPr of [
    {
      ...cleanPr(),
      statusCheckRollup: [{ name: 'ci', status: 'IN_PROGRESS', conclusion: null, workflowName: 'CI' }],
    },
    {
      ...cleanPr(),
      reviewDecision: 'CHANGES_REQUESTED',
      latestReviews: [{ author: { login: 'reviewer' }, state: 'CHANGES_REQUESTED', submittedAt: '2026-07-14T00:01:00Z' }],
    },
  ]) {
    let prReads = 0;
    const result = await readLivePrState({
      repo: 'C:/repo',
      expectedHeadSha: 'head123',
      expectedBaseSha: 'base123',
      expectedConfigDigest: 'cfg123',
      runGh: async (args) => {
        if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
        if (args[0] === 'pr') {
          prReads += 1;
          return prReads === 1 ? cleanPr() : concurrentPr;
        }
        if (args.includes('--paginate')) return [[approvedReview()]];
        return {
          data: { repository: { pullRequest: { reviewThreads: {
            nodes: [],
            pageInfo: { hasNextPage: false, endCursor: null },
          } } } },
        };
      },
    });
    assert.equal(result.status, 'BLOCKED');
    assert.match(result.evidence, /changed during verification/i);
    assert.equal(prReads, 2);
  }
});

test('blocks when the full review list changes while the PR summary remains stable', async () => {
  let reviewReads = 0;
  const result = await readLivePrState({
    repo: 'C:/repo',
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return cleanPr();
      if (args.includes('--paginate')) {
        reviewReads += 1;
        return reviewReads === 1
          ? [[approvedReview()]]
          : [[approvedReview(), approvedReview({ id: 10, body: 'Concurrent review.', user: { login: 'other-reviewer' } })]];
      }
      return {
        data: { repository: { pullRequest: { reviewThreads: {
          nodes: [],
          pageInfo: { hasNextPage: false, endCursor: null },
        } } } },
      };
    },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /changed during verification/i);
  assert.equal(reviewReads, 2);
});

test('blocks when a reviewer permission downgrades from write to read between stability snapshots', async () => {
  // Regression guard for the reviewer-permission cache-sharing revert: the two
  // gate-attestation snapshots inside readLivePrState must each fetch
  // collaborator permissions independently. If a second snapshot ever reused
  // the first snapshot's permission map again, a reviewer whose write access
  // is revoked mid-run would still attest PASS instead of being caught by the
  // stability/race check.
  let permissionReads = 0;
  const result = await readLivePrState({
    repo: 'C:/repo',
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return cleanPr();
      if (args.includes('--paginate')) return [[approvedReview({ author_association: 'CONTRIBUTOR' })]];
      if (args[1]?.endsWith('/permission')) {
        permissionReads += 1;
        return { permission: permissionReads === 1 ? 'write' : 'read' };
      }
      return {
        data: { repository: { pullRequest: { reviewThreads: {
          nodes: [],
          pageInfo: { hasNextPage: false, endCursor: null },
        } } } },
      };
    },
  });
  assert.equal(permissionReads, 2, 'permissions must be re-fetched independently for each stability snapshot, never cached across them');
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /changed during verification/i);
});

test('blocks when a reviewer permission is revoked during the final post-thread request window (chatgpt-codex-connector PR7 #Yb3lQ)', async () => {
  // The first four gate-attestation snapshots (first, final, terminal, post-
  // thread) all agree — only the fifth (verified, taken after the LAST
  // paginated thread request) sees the revoked permission. This isolates the
  // new round added for this finding: without it, nothing re-checks
  // attestation stability across postThreadUnresolvedThreads's own network
  // window, so a revocation timed to land exactly there would attest a stale
  // PASS forever (no workflow event exists to ever invalidate it).
  let permissionReads = 0;
  const result = await readLivePrState({
    repo: 'C:/repo',
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return cleanPr();
      if (args.includes('--paginate')) return [[approvedReview({ author_association: 'CONTRIBUTOR' })]];
      if (args[1]?.endsWith('/permission')) {
        permissionReads += 1;
        return { permission: permissionReads <= 4 ? 'write' : 'read' };
      }
      return {
        data: { repository: { pullRequest: { reviewThreads: {
          nodes: [],
          pageInfo: { hasNextPage: false, endCursor: null },
        } } } },
      };
    },
  });
  assert.equal(permissionReads, 5, 'all five gate-attestation snapshots must fetch permissions independently');
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /final thread-request verification window/i);
});

test('reads the independent attestation from paginated GitHub review data', async () => {
  const result = await readLiveGateAttestation({
    repo: 'C:/repo',
    expectedBaseSha: 'base123',
    expectedHeadSha: 'head123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return cleanPr();
      return [[approvedReview()]];
    },
  });
  assert.equal(result.status, 'PASS');
  assert.equal(result.reviewer, 'reviewer');
});

test('readLiveGateAttestation blocks when the PR head changes while reading reviews and reviewer permissions (chatgpt-codex-connector PR7 #6Yb44Ss)', async () => {
  let prCalls = 0;
  const result = await readLiveGateAttestation({
    repo: 'C:/repo',
    expectedBaseSha: 'base123',
    expectedHeadSha: 'head123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') {
        prCalls += 1;
        // First call (the head/base admission check) sees the expected head;
        // the SECOND call (the new post-attestation revalidation) simulates a
        // push landing while the paginated reviews/permissions requests were
        // in flight.
        return prCalls === 1 ? cleanPr() : { ...cleanPr(), headRefOid: 'head456' };
      }
      return [[approvedReview()]];
    },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /no longer current/i);
  assert.equal(prCalls, 2, 'the revalidation must be a real second PR read, not reuse of the first');
});

test('returns BLOCKED instead of inventing live evidence when GitHub is unavailable', async () => {
  const result = await readLivePrState({
    repo: 'C:/repo',
    expectedHeadSha: 'head123',
    expectedBaseSha: 'base123',
    runGh: async () => { throw new Error('authentication required'); },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.match(result.evidence, /authentication required/i);
});

test('readLiveGateAttestation tags its internal catch path with a machine-readable unavailable reason', async () => {
  const result = await readLiveGateAttestation({
    repo: 'C:/repo',
    expectedBaseSha: 'base123',
    expectedHeadSha: 'head123',
    expectedConfigDigest: 'cfg123',
    runGh: async () => { throw new Error('gh: command not found'); },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.reason, 'unavailable');
  assert.match(result.evidence, /gh: command not found/);
});

test('snapshot-mismatch BLOCKED attestations carry no unavailable reason', async () => {
  const result = await readLiveGateAttestation({
    repo: 'C:/repo',
    expectedBaseSha: 'base123',
    expectedHeadSha: 'head123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      if (args[0] === 'repo') return { nameWithOwner: 'owner/repo' };
      if (args[0] === 'pr') return { number: 7, author: { login: 'a' }, headRefOid: 'movedhead', baseRefOid: 'base123' };
      return [[]];
    },
  });
  assert.equal(result.status, 'BLOCKED');
  assert.equal(result.reason, undefined);
});

test('buildGhArgs injects PR number and --repo for pr view under GITHUB_ACTIONS', () => {
  process.env.GITHUB_ACTIONS = 'true';
  process.env.GITHUB_REF_NAME = '7/merge';
  process.env.GITHUB_REPOSITORY = 'XGenerationy/codex-agents-debug-mode';
  const args = ['pr', 'view', '--json', 'number'];
  const result = buildGhArgs(args);
  assert.deepStrictEqual(result, ['pr', 'view', '7', '--json', 'number', '--repo', 'XGenerationy/codex-agents-debug-mode']);
});

test('buildGhArgs passes through when GITHUB_ACTIONS is not set', () => {
  delete process.env.GITHUB_ACTIONS;
  const args = ['pr', 'view', '--json', 'number'];
  const result = buildGhArgs(args);
  assert.strictEqual(result, args);
});

test('buildGhArgs passes through when GITHUB_REPOSITORY is missing', () => {
  process.env.GITHUB_ACTIONS = 'true';
  delete process.env.GITHUB_REPOSITORY;
  const args = ['pr', 'view', '--json', 'number'];
  const result = buildGhArgs(args);
  assert.strictEqual(result, args);
});

test('buildGhArgs passes through when --repo is already present', () => {
  process.env.GITHUB_ACTIONS = 'true';
  process.env.GITHUB_REPOSITORY = 'XGenerationy/codex-agents-debug-mode';
  const args = ['pr', 'view', '--repo', 'foo/bar'];
  const result = buildGhArgs(args);
  assert.strictEqual(result, args);
});

test('buildGhArgs injects repository positionally for repo view under GITHUB_ACTIONS', () => {
  process.env.GITHUB_ACTIONS = 'true';
  process.env.GITHUB_REPOSITORY = 'XGenerationy/codex-agents-debug-mode';
  const args = ['repo', 'view'];
  const result = buildGhArgs(args);
  assert.deepStrictEqual(result, ['repo', 'view', 'XGenerationy/codex-agents-debug-mode']);
});

test('buildGhArgs injects repository positionally before flags for repo view --json', () => {
  process.env.GITHUB_ACTIONS = 'true';
  process.env.GITHUB_REPOSITORY = 'XGenerationy/codex-agents-debug-mode';
  const args = ['repo', 'view', '--json', 'nameWithOwner'];
  const result = buildGhArgs(args);
  assert.deepStrictEqual(result, ['repo', 'view', 'XGenerationy/codex-agents-debug-mode', '--json', 'nameWithOwner']);
});

test('buildGhArgs pr view passes through when PR number is unresolvable', () => {
  process.env.GITHUB_ACTIONS = 'true';
  process.env.GITHUB_REF_NAME = 'feat/closeout-action';
  process.env.GITHUB_REPOSITORY = 'XGenerationy/codex-agents-debug-mode';
  delete process.env.GITHUB_EVENT_PATH;
  const args = ['pr', 'view', '--json', 'number'];
  const result = buildGhArgs(args);
  assert.strictEqual(result, args);
});

test('buildGhArgs pr view falls back to GITHUB_EVENT_PATH for PR number', () => {
  process.env.GITHUB_ACTIONS = 'true';
  process.env.GITHUB_REPOSITORY = 'XGenerationy/codex-agents-debug-mode';
  delete process.env.GITHUB_REF_NAME;
  const dir = mkdtempSync(join(tmpdir(), 'pr7-gh-'));
  try {
    writeFileSync(join(dir, 'event.json'), JSON.stringify({ pull_request: { number: 42 } }));
    process.env.GITHUB_EVENT_PATH = join(dir, 'event.json');
    const args = ['pr', 'view', '--json', 'number'];
    const result = buildGhArgs(args);
    assert.deepStrictEqual(result, ['pr', 'view', '42', '--json', 'number', '--repo', 'XGenerationy/codex-agents-debug-mode']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('buildGhArgs pr view falls back to workflow_run.pull_requests[0].number for a same-repo PR (CodeRabbit PR7 #6YW9UP)', () => {
  const savedActions = process.env.GITHUB_ACTIONS;
  const savedRepository = process.env.GITHUB_REPOSITORY;
  const savedRefName = process.env.GITHUB_REF_NAME;
  const savedEventPath = process.env.GITHUB_EVENT_PATH;
  process.env.GITHUB_ACTIONS = 'true';
  process.env.GITHUB_REPOSITORY = 'XGenerationy/codex-agents-debug-mode';
  delete process.env.GITHUB_REF_NAME;
  const dir = mkdtempSync(join(tmpdir(), 'pr7-gh-workflow-run-'));
  try {
    // workflow_run events carry no top-level pull_request — only
    // workflow_run.pull_requests[0], populated for a same-repo PR.
    writeFileSync(join(dir, 'event.json'), JSON.stringify({ workflow_run: { pull_requests: [{ number: 42 }] } }));
    process.env.GITHUB_EVENT_PATH = join(dir, 'event.json');
    const result = buildGhArgs(['pr', 'view', '--json', 'number']);
    assert.deepStrictEqual(result, ['pr', 'view', '42', '--json', 'number', '--repo', 'XGenerationy/codex-agents-debug-mode']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    if (savedActions === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = savedActions;
    if (savedRepository === undefined) delete process.env.GITHUB_REPOSITORY; else process.env.GITHUB_REPOSITORY = savedRepository;
    if (savedRefName === undefined) delete process.env.GITHUB_REF_NAME; else process.env.GITHUB_REF_NAME = savedRefName;
    if (savedEventPath === undefined) delete process.env.GITHUB_EVENT_PATH; else process.env.GITHUB_EVENT_PATH = savedEventPath;
  }
});

test('buildGhArgs pr view has no PR number for a fork PR via workflow_run (empty pull_requests array)', () => {
  const savedActions = process.env.GITHUB_ACTIONS;
  const savedRepository = process.env.GITHUB_REPOSITORY;
  const savedRefName = process.env.GITHUB_REF_NAME;
  const savedEventPath = process.env.GITHUB_EVENT_PATH;
  process.env.GITHUB_ACTIONS = 'true';
  process.env.GITHUB_REPOSITORY = 'XGenerationy/codex-agents-debug-mode';
  delete process.env.GITHUB_REF_NAME;
  const dir = mkdtempSync(join(tmpdir(), 'pr7-gh-workflow-run-fork-'));
  try {
    // GitHub does not populate workflow_run.pull_requests for fork PRs.
    writeFileSync(join(dir, 'event.json'), JSON.stringify({ workflow_run: { pull_requests: [] } }));
    process.env.GITHUB_EVENT_PATH = join(dir, 'event.json');
    const args = ['pr', 'view', '--json', 'number'];
    // No PR number resolvable: buildGhArgs passes the args through unchanged.
    assert.deepStrictEqual(buildGhArgs(args), args);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    if (savedActions === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = savedActions;
    if (savedRepository === undefined) delete process.env.GITHUB_REPOSITORY; else process.env.GITHUB_REPOSITORY = savedRepository;
    if (savedRefName === undefined) delete process.env.GITHUB_REF_NAME; else process.env.GITHUB_REF_NAME = savedRefName;
    if (savedEventPath === undefined) delete process.env.GITHUB_EVENT_PATH; else process.env.GITHUB_EVENT_PATH = savedEventPath;
  }
});

test('buildGhArgs pr view fails closed when workflow_run reports more than one associated PR (CodeRabbit PR7 #6YZkn9)', () => {
  const savedActions = process.env.GITHUB_ACTIONS;
  const savedRepository = process.env.GITHUB_REPOSITORY;
  const savedRefName = process.env.GITHUB_REF_NAME;
  const savedEventPath = process.env.GITHUB_EVENT_PATH;
  process.env.GITHUB_ACTIONS = 'true';
  process.env.GITHUB_REPOSITORY = 'XGenerationy/codex-agents-debug-mode';
  delete process.env.GITHUB_REF_NAME;
  const dir = mkdtempSync(join(tmpdir(), 'pr7-gh-workflow-run-multi-'));
  try {
    // GitHub documents workflow_run.pull_requests as an array that can carry
    // more than one entry. Picking [0] unconditionally risks validating the
    // wrong PR, so this must fail closed to no resolvable number rather than
    // guess (CodeRabbit PR7 #6YZkn9).
    writeFileSync(join(dir, 'event.json'), JSON.stringify({ workflow_run: { pull_requests: [{ number: 42 }, { number: 43 }] } }));
    process.env.GITHUB_EVENT_PATH = join(dir, 'event.json');
    const args = ['pr', 'view', '--json', 'number'];
    assert.deepStrictEqual(buildGhArgs(args), args, 'an ambiguous multi-PR payload must not be trusted for either number');
  } finally {
    rmSync(dir, { recursive: true, force: true });
    if (savedActions === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = savedActions;
    if (savedRepository === undefined) delete process.env.GITHUB_REPOSITORY; else process.env.GITHUB_REPOSITORY = savedRepository;
    if (savedRefName === undefined) delete process.env.GITHUB_REF_NAME; else process.env.GITHUB_REF_NAME = savedRefName;
    if (savedEventPath === undefined) delete process.env.GITHUB_EVENT_PATH; else process.env.GITHUB_EVENT_PATH = savedEventPath;
  }
});

test('buildGhArgs pr view falls back to a workflow_dispatch pr-number input (chatgpt-codex-connector PR7 #6Yd4Qs)', () => {
  const savedActions = process.env.GITHUB_ACTIONS;
  const savedRepository = process.env.GITHUB_REPOSITORY;
  const savedRefName = process.env.GITHUB_REF_NAME;
  const savedEventPath = process.env.GITHUB_EVENT_PATH;
  process.env.GITHUB_ACTIONS = 'true';
  process.env.GITHUB_REPOSITORY = 'XGenerationy/codex-agents-debug-mode';
  delete process.env.GITHUB_REF_NAME;
  const dir = mkdtempSync(join(tmpdir(), 'pr7-gh-dispatch-pr-number-'));
  try {
    // workflow_dispatch carries neither pull_request nor workflow_run — only
    // the declared inputs, keyed by their hyphenated YAML name.
    writeFileSync(join(dir, 'event.json'), JSON.stringify({ inputs: { 'pr-number': '99' } }));
    process.env.GITHUB_EVENT_PATH = join(dir, 'event.json');
    const result = buildGhArgs(['pr', 'view', '--json', 'number']);
    assert.deepStrictEqual(result, ['pr', 'view', '99', '--json', 'number', '--repo', 'XGenerationy/codex-agents-debug-mode']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    if (savedActions === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = savedActions;
    if (savedRepository === undefined) delete process.env.GITHUB_REPOSITORY; else process.env.GITHUB_REPOSITORY = savedRepository;
    if (savedRefName === undefined) delete process.env.GITHUB_REF_NAME; else process.env.GITHUB_REF_NAME = savedRefName;
    if (savedEventPath === undefined) delete process.env.GITHUB_EVENT_PATH; else process.env.GITHUB_EVENT_PATH = savedEventPath;
  }
});

test('buildGhArgs pr view ignores an empty/absent workflow_dispatch pr-number input', () => {
  const savedActions = process.env.GITHUB_ACTIONS;
  const savedRepository = process.env.GITHUB_REPOSITORY;
  const savedRefName = process.env.GITHUB_REF_NAME;
  const savedEventPath = process.env.GITHUB_EVENT_PATH;
  process.env.GITHUB_ACTIONS = 'true';
  process.env.GITHUB_REPOSITORY = 'XGenerationy/codex-agents-debug-mode';
  delete process.env.GITHUB_REF_NAME;
  const dir = mkdtempSync(join(tmpdir(), 'pr7-gh-dispatch-pr-number-empty-'));
  try {
    // The workflow declares pr-number with default: "" — an operator who
    // leaves it blank must not accidentally resolve to PR "0" or similar.
    writeFileSync(join(dir, 'event.json'), JSON.stringify({ inputs: { 'pr-number': '' } }));
    process.env.GITHUB_EVENT_PATH = join(dir, 'event.json');
    const args = ['pr', 'view', '--json', 'number'];
    assert.deepStrictEqual(buildGhArgs(args), args);
  } finally {
    rmSync(dir, { recursive: true, force: true });
    if (savedActions === undefined) delete process.env.GITHUB_ACTIONS; else process.env.GITHUB_ACTIONS = savedActions;
    if (savedRepository === undefined) delete process.env.GITHUB_REPOSITORY; else process.env.GITHUB_REPOSITORY = savedRepository;
    if (savedRefName === undefined) delete process.env.GITHUB_REF_NAME; else process.env.GITHUB_REF_NAME = savedRefName;
    if (savedEventPath === undefined) delete process.env.GITHUB_EVENT_PATH; else process.env.GITHUB_EVENT_PATH = savedEventPath;
  }
});

test('readReviewerPermissions resolves unique reviewers with bounded concurrency and dedup', async () => {
  // GitHub's collaborators/permission endpoint is per-user, so the prior loop
  // awaited one gh api call per reviewer sequentially (N+1). The lookup now
  // resolves the unique reviewer set with bounded concurrency. This injects a
  // runGh that records every call and tracks the maximum number in flight, then
  // asserts: every distinct non-authoritative reviewer is queried exactly once
  // (dedup), authoritative associations are skipped, and concurrency is capped.
  const marker = gateAttestationMarker({ baseSha: 'base123', headSha: 'head123', configDigest: 'cfg123' });
  const reviews = [
    approvedReview({ user: { login: 'alice' }, author_association: 'CONTRIBUTOR', body: marker }),
    // duplicate reviewer — must be queried once, not twice
    approvedReview({ user: { login: 'alice' }, author_association: 'CONTRIBUTOR', body: marker }),
    approvedReview({ user: { login: 'bob' }, author_association: 'CONTRIBUTOR', body: marker }),
    approvedReview({ user: { login: 'carol' }, author_association: 'CONTRIBUTOR', body: marker }),
    approvedReview({ user: { login: 'dave' }, author_association: 'CONTRIBUTOR', body: marker }),
    approvedReview({ user: { login: 'eve' }, author_association: 'CONTRIBUTOR', body: marker }),
    // OWNER association is authoritative — no permission lookup needed
    approvedReview({ user: { login: 'frank' }, author_association: 'OWNER', body: marker }),
  ];
  const calls = [];
  let inFlight = 0;
  let maxInFlight = 0;
  const permissions = await readReviewerPermissions({
    repo: 'repo',
    repository: 'owner/repo',
    reviews,
    prAuthor: 'pr-author',
    expectedBaseSha: 'base123',
    expectedHeadSha: 'head123',
    expectedConfigDigest: 'cfg123',
    runGh: async (args) => {
      const reviewer = args[1].split('/').slice(-2)[0];
      calls.push(reviewer);
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((resolve) => setImmediate(resolve));
      inFlight -= 1;
      return { permission: 'write', user: { login: reviewer } };
    },
  });
  // Each distinct non-authoritative reviewer queried exactly once (dedup).
  assert.deepEqual([...calls].sort(), ['alice', 'bob', 'carol', 'dave', 'eve']);
  // Authoritative (OWNER) frank was skipped.
  assert.equal(permissions.has('frank'), false);
  // Concurrency reached the configured batch cap (4): with 5 distinct eligible
  // reviewers and a yielding runGh stub, a sequential loop (maxInFlight === 1)
  // would reintroduce the N+1 — so assert the cap is actually exercised.
  assert.equal(maxInFlight, 4, `lookups must run in batches of four (got maxInFlight=${maxInFlight})`);
  // Each resolved permission is recorded.
  assert.equal(permissions.get('alice').permission, 'write');
});
