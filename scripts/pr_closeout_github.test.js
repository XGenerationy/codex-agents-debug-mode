const assert = require('node:assert/strict');
const test = require('node:test');

const {
  classifyGateAttestation,
  classifyLivePrState,
  gateAttestationMarker,
  readLiveGateAttestation,
  readLivePrState,
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
  // Stable path: four gate-attestation snapshots (first, final, terminal,
  // post-thread) + three review-thread walks (2 pages each with this mock) =
  // 4 snapshots (mix of paginate + graphql) + 6 thread pages → 10 api calls.
  assert.equal(calls.filter(([command]) => command === 'api').length, 10);
});

test('re-reads review threads after the terminal snapshot and requires stability', async () => {
  // Stable path does three review-thread reads: after PR/review stability,
  // after the terminal PR+attestation snapshot, and after the post-thread
  // PR/gate re-fetch. All three must match.
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
  assert.equal(threadReads, 3, 'stable path must re-read review threads after terminal and post-thread snapshots');
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
