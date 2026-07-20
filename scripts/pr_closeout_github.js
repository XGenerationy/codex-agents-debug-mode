const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);

const FAILURE_CONCLUSIONS = new Set([
  'ACTION_REQUIRED',
  'CANCELLED',
  'ERROR',
  'FAILURE',
  'NEUTRAL',
  'SKIPPED',
  'STARTUP_FAILURE',
  'STALE',
  'TIMED_OUT',
]);
const PENDING_STATES = new Set(['EXPECTED', 'IN_PROGRESS', 'PENDING', 'QUEUED', 'REQUESTED', 'WAITING']);
// OWNER (repo owner) is authoritative by association. MEMBER only proves
// organization membership and COLLABORATOR only proves an invitation to
// collaborate; neither guarantees repository write access, so both must be
// verified through the permission endpoint in reviewerAuthorization below.
const AUTHORITATIVE_ASSOCIATIONS = new Set(['OWNER']);
const WRITE_PERMISSIONS = new Set(['ADMIN', 'MAINTAIN', 'PUSH', 'WRITE']);
const MAX_REVIEW_THREAD_PAGES = 100;

const gateAttestationMarker = ({ baseSha, headSha, configDigest }) => (
  `PR-CLOSEOUT-ATTESTATION v1 base=${baseSha} head=${headSha} config=${configDigest} decision=not-weakened`
);

const permissionRecordFor = (reviewerPermissions, reviewer) => {
  if (reviewerPermissions instanceof Map) {
    return reviewerPermissions.get(reviewer.toLowerCase());
  }
  if (reviewerPermissions && typeof reviewerPermissions === 'object') {
    return reviewerPermissions[reviewer.toLowerCase()] || reviewerPermissions[reviewer];
  }
  return undefined;
};

const reviewerAuthorization = (review, reviewerPermissions) => {
  const association = String(review?.author_association || review?.authorAssociation || '').toUpperCase();
  if (AUTHORITATIVE_ASSOCIATIONS.has(association)) {
    return { authorized: true, association, permission: null };
  }
  const reviewer = String(review?.user?.login || '');
  const permissionRecord = permissionRecordFor(reviewerPermissions, reviewer);
  const permission = String(permissionRecord?.permission || '').toUpperCase();
  const flags = permissionRecord?.user?.permissions || permissionRecord?.permissions || {};
  const authorized = WRITE_PERMISSIONS.has(permission)
    || flags.admin === true
    || flags.maintain === true
    || flags.push === true;
  return { authorized, association: association || null, permission: permission || null };
};

const classifyGateAttestation = ({
  reviews = [],
  prAuthor,
  expectedBaseSha,
  expectedHeadSha,
  expectedConfigDigest,
  reviewerPermissions = new Map(),
} = {}) => {
  const marker = gateAttestationMarker({
    baseSha: expectedBaseSha,
    headSha: expectedHeadSha,
    configDigest: expectedConfigDigest,
  });
  const candidates = reviews.filter((review) => {
    const exactLines = String(review?.body || '').split(/\r?\n/).filter((line) => line === marker);
    const reviewer = review?.user?.login;
    return String(review?.state || '').toUpperCase() === 'APPROVED'
      && review?.commit_id === expectedHeadSha
      && exactLines.length === 1
      && typeof reviewer === 'string'
      && reviewer.trim()
      && typeof prAuthor === 'string'
      && prAuthor.trim()
      && reviewer.toLowerCase() !== String(prAuthor || '').toLowerCase()
      && reviewerAuthorization(review, reviewerPermissions).authorized;
  }).sort((left, right) => String(right.submitted_at || '').localeCompare(String(left.submitted_at || '')));
  const review = candidates[0];
  if (!review) {
    return {
      provider: 'github-pull-request-review',
      status: 'BLOCKED',
      baseSha: expectedBaseSha,
      headSha: expectedHeadSha,
      configDigest: expectedConfigDigest,
      decision: 'not-weakened',
      marker,
      evidence: 'No authorized independent current-head APPROVED GitHub review contains the exact gate attestation marker.',
    };
  }
  const authorization = reviewerAuthorization(review, reviewerPermissions);
  return {
    provider: 'github-pull-request-review',
    status: 'PASS',
    baseSha: expectedBaseSha,
    headSha: expectedHeadSha,
    configDigest: expectedConfigDigest,
    decision: 'not-weakened',
    marker,
    reviewer: review.user.login,
    reviewId: review.id,
    reviewUrl: review.html_url,
    submittedAt: review.submitted_at,
    commitId: review.commit_id,
    reviewerAssociation: authorization.association,
    reviewerPermission: authorization.permission,
    evidence: review.html_url || `GitHub review ${review.id}`,
  };
};

const defaultRunGh = async (args, { repo } = {}) => {
  const { stdout } = await execFileAsync('gh', args, {
    cwd: repo,
    encoding: 'utf8',
    maxBuffer: 20_000_000,
    timeout: 60_000,
    windowsHide: true,
  });
  return JSON.parse(stdout);
};

const normalizeCheck = (value) => {
  const check = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
  const name = check.name || check.context || check.workflowName || 'unnamed-check';
  const legacy = check.__typename === 'StatusContext'
    || (!check.__typename && Object.hasOwn(check, 'state') && !Object.hasOwn(check, 'status'));
  const status = String(legacy ? check.state : check.status || '').toUpperCase();
  const conclusion = String(legacy ? check.state : check.conclusion || '').toUpperCase();
  let classification = 'BLOCKED';
  if (FAILURE_CONCLUSIONS.has(conclusion)) classification = 'FAIL';
  else if (legacy && status === 'SUCCESS') classification = 'PASS';
  else if (!legacy && status === 'COMPLETED' && conclusion === 'SUCCESS') classification = 'PASS';
  else if (PENDING_STATES.has(status) || PENDING_STATES.has(conclusion) || !status || !conclusion) classification = 'BLOCKED';
  return {
    name,
    status: status || null,
    conclusion: conclusion || null,
    workflowName: check.workflowName || null,
    classification,
  };
};

const classifyLivePrState = ({
  repository,
  pr = {},
  unresolvedThreads = [],
  expectedHeadSha,
  expectedBaseSha,
  gateAttestation,
} = {}) => {
  const checks = Array.isArray(pr.statusCheckRollup) ? pr.statusCheckRollup.map(normalizeCheck) : [];
  const threads = Array.isArray(unresolvedThreads) ? unresolvedThreads : [];
  const failures = [];
  const blockers = [];
  if (pr.state !== 'OPEN') failures.push(`PR state is ${pr.state || 'unknown'}, not OPEN.`);
  if (pr.isDraft === true) blockers.push('PR is still a draft.');
  else if (pr.isDraft !== false) blockers.push('GitHub did not return an explicit non-draft state.');
  if (pr.headRefOid !== expectedHeadSha) blockers.push(`Live PR head ${pr.headRefOid || 'unknown'} does not match ${expectedHeadSha}.`);
  if (pr.baseRefOid !== expectedBaseSha) blockers.push(`Live PR base ${pr.baseRefOid || 'unknown'} does not match ${expectedBaseSha}.`);
  if (['CONFLICTING', 'DIRTY'].includes(pr.mergeable) || pr.mergeStateStatus === 'DIRTY') {
    failures.push('Live PR has merge conflicts.');
  } else if (pr.mergeable !== 'MERGEABLE' || pr.mergeStateStatus !== 'CLEAN') {
    blockers.push(`Mergeability is ${pr.mergeable || 'unknown'}/${pr.mergeStateStatus || 'unknown'}; MERGEABLE/CLEAN is required.`);
  }
  if (pr.reviewDecision === 'CHANGES_REQUESTED') failures.push('Latest review decision requests changes.');
  else if (pr.reviewDecision !== 'APPROVED') blockers.push(`Review decision is ${pr.reviewDecision || 'not approved'}.`);
  if (!checks.length) blockers.push('No live GitHub check results were returned.');
  for (const check of checks) {
    if (check.classification === 'FAIL') failures.push(`Check ${check.name} concluded ${check.conclusion || check.status}.`);
    else if (check.classification !== 'PASS') blockers.push(`Check ${check.name} is ${check.status || check.conclusion || 'unresolved'}.`);
  }
  if (!Array.isArray(unresolvedThreads)) blockers.push('GitHub returned malformed unresolved review-thread data.');
  if (threads.length) {
    blockers.push(`${threads.length} unresolved review thread${threads.length === 1 ? '' : 's'} remain.`);
  }
  if (gateAttestation?.status === 'FAIL') failures.push(gateAttestation.evidence || 'Gate attestation failed.');
  else if (gateAttestation?.status !== 'PASS') blockers.push(gateAttestation?.evidence || 'Independent gate attestation is unavailable.');
  const status = failures.length ? 'FAIL' : (blockers.length ? 'BLOCKED' : 'PASS');
  const evidence = [...failures, ...blockers].join(' ') || 'Live PR head, base, reviews, merge state, threads, and checks are clean.';
  return {
    status,
    evidence,
    repository,
    number: pr.number,
    url: pr.url,
    state: pr.state,
    isDraft: pr.isDraft,
    mergeable: pr.mergeable,
    mergeStateStatus: pr.mergeStateStatus,
    reviewDecision: pr.reviewDecision,
    headRefOid: pr.headRefOid,
    baseRefOid: pr.baseRefOid,
    latestReviews: Array.isArray(pr.latestReviews) ? pr.latestReviews : [],
    checks,
    unresolvedThreads: threads,
    externalServices: checks.filter(({ workflowName }) => !workflowName),
    gateAttestation,
  };
};

const flattenReviewPages = (value) => {
  if (!Array.isArray(value)) throw new Error('GitHub returned malformed review data.');
  return value.flatMap((page) => (Array.isArray(page) ? page : [page]));
};

const reviewMatchesAttestationShape = ({
  review,
  prAuthor,
  expectedHeadSha,
  marker,
}) => {
  const reviewer = review?.user?.login;
  const exactLines = String(review?.body || '').split(/\r?\n/).filter((line) => line === marker);
  return String(review?.state || '').toUpperCase() === 'APPROVED'
    && review?.commit_id === expectedHeadSha
    && exactLines.length === 1
    && typeof reviewer === 'string'
    && reviewer.trim()
    && reviewer.toLowerCase() !== String(prAuthor || '').toLowerCase();
};

const readReviewerPermissions = async ({
  repo,
  repository,
  reviews,
  prAuthor,
  expectedBaseSha,
  expectedHeadSha,
  expectedConfigDigest,
  runGh,
}) => {
  const marker = gateAttestationMarker({
    baseSha: expectedBaseSha,
    headSha: expectedHeadSha,
    configDigest: expectedConfigDigest,
  });
  const reviewerPermissions = new Map();
  for (const review of reviews) {
    if (!reviewMatchesAttestationShape({ review, prAuthor, expectedHeadSha, marker })) continue;
    const reviewer = review.user.login;
    const association = String(review.author_association || review.authorAssociation || '').toUpperCase();
    if (AUTHORITATIVE_ASSOCIATIONS.has(association) || reviewerPermissions.has(reviewer.toLowerCase())) continue;
    try {
      const permission = await runGh([
        'api',
        `repos/${repository}/collaborators/${encodeURIComponent(reviewer)}/permission`,
      ], { repo });
      reviewerPermissions.set(reviewer.toLowerCase(), permission);
    } catch {
      reviewerPermissions.set(reviewer.toLowerCase(), null);
    }
  }
  return reviewerPermissions;
};

const captureReviewStabilityTuple = (reviews, reviewerPermissions) => reviews.map((review) => {
  const reviewer = String(review?.user?.login || '');
  const authorization = reviewerAuthorization(review, reviewerPermissions);
  return {
    id: review?.id ?? null,
    state: review?.state ?? null,
    commitId: review?.commit_id ?? null,
    body: review?.body ?? null,
    submittedAt: review?.submitted_at ?? null,
    reviewer: reviewer || null,
    association: authorization.association,
    permission: authorization.permission,
    authorized: authorization.authorized,
  };
}).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)));

const readGateAttestationSnapshotForPr = async ({
  repo,
  repository,
  pr,
  expectedBaseSha,
  expectedHeadSha,
  expectedConfigDigest,
  runGh,
}) => {
  const reviews = flattenReviewPages(await runGh([
    'api',
    '--paginate',
    '--slurp',
    `repos/${repository}/pulls/${pr.number}/reviews`,
  ], { repo }));
  const reviewerPermissions = await readReviewerPermissions({
    repo,
    repository,
    reviews,
    prAuthor: pr.author?.login,
    expectedBaseSha,
    expectedHeadSha,
    expectedConfigDigest,
    runGh,
  });
  return {
    attestation: classifyGateAttestation({
      reviews,
      prAuthor: pr.author?.login,
      expectedBaseSha,
      expectedHeadSha,
      expectedConfigDigest,
      reviewerPermissions,
    }),
    stabilityTuple: captureReviewStabilityTuple(reviews, reviewerPermissions),
  };
};

const readGateAttestationForPr = async (options) => {
  const snapshot = await readGateAttestationSnapshotForPr(options);
  return snapshot.attestation;
};

const readLiveGateAttestation = async ({
  repo,
  expectedBaseSha,
  expectedHeadSha,
  expectedConfigDigest,
  runGh = defaultRunGh,
} = {}) => {
  try {
    const repositoryResult = await runGh(['repo', 'view', '--json', 'nameWithOwner'], { repo });
    const repository = repositoryResult.nameWithOwner;
    if (!repository || !repository.includes('/')) throw new Error('GitHub repository identity was not returned.');
    const pr = await runGh(['pr', 'view', '--json', 'author,number'], { repo });
    if (!Number.isInteger(pr.number)) throw new Error('GitHub did not return an open pull request number.');
    if (typeof pr.author?.login !== 'string' || !pr.author.login.trim()) {
      throw new Error('GitHub did not return the pull request author identity.');
    }
    return await readGateAttestationForPr({
      repo,
      repository,
      pr,
      expectedBaseSha,
      expectedHeadSha,
      expectedConfigDigest,
      runGh,
    });
  } catch (error) {
    return {
      provider: 'github-pull-request-review',
      status: 'BLOCKED',
      baseSha: expectedBaseSha,
      headSha: expectedHeadSha,
      configDigest: expectedConfigDigest,
      decision: 'not-weakened',
      marker: gateAttestationMarker({ baseSha: expectedBaseSha, headSha: expectedHeadSha, configDigest: expectedConfigDigest }),
      evidence: `Live GitHub gate attestation was unavailable: ${error.message}`,
    };
  }
};

const REVIEW_THREADS_QUERY = `
query($owner: String!, $name: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $name) {
    pullRequest(number: $number) {
      reviewThreads(first: 100, after: $cursor) {
        nodes {
          isResolved
          isOutdated
          path
          line
          comments(last: 1) { nodes { url } }
        }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}`;

const readUnresolvedReviewThreads = async ({ repo, owner, name, number, runGh }) => {
  const unresolvedThreads = [];
  const seenCursors = new Set();
  let cursor;
  for (let page = 0; page < MAX_REVIEW_THREAD_PAGES; page += 1) {
    const args = [
      'api',
      'graphql',
      '-f', `query=${REVIEW_THREADS_QUERY}`,
      '-F', `owner=${owner}`,
      '-F', `name=${name}`,
      '-F', `number=${number}`,
    ];
    if (cursor) args.push('-F', `cursor=${cursor}`);
    const response = await runGh(args, { repo });
    const threads = response?.data?.repository?.pullRequest?.reviewThreads;
    if (!threads || !Array.isArray(threads.nodes) || !threads.pageInfo) {
      throw new Error('GitHub returned malformed review-thread data.');
    }
    for (const thread of threads.nodes) {
      if (!thread.isResolved) {
        unresolvedThreads.push({
          path: thread.path || null,
          line: thread.line || null,
          isOutdated: Boolean(thread.isOutdated),
          url: thread.comments?.nodes?.at(-1)?.url || null,
        });
      }
    }
    if (!threads.pageInfo.hasNextPage) break;
    const next = threads.pageInfo.endCursor;
    if (!next || seenCursors.has(next)) throw new Error('GitHub review-thread pagination did not advance.');
    seenCursors.add(next);
    cursor = next;
    if (page === MAX_REVIEW_THREAD_PAGES - 1) {
      throw new Error(`GitHub review-thread pagination exceeded ${MAX_REVIEW_THREAD_PAGES} pages.`);
    }
  }
  return unresolvedThreads;
};

const PR_VIEW_FIELDS = 'author,baseRefOid,headRefOid,isDraft,latestReviews,mergeable,mergeStateStatus,number,reviewDecision,state,statusCheckRollup,url';

const capturePrStabilityTuple = (pr) => {
  const checks = Array.isArray(pr?.statusCheckRollup)
    ? pr.statusCheckRollup.map(normalizeCheck).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)))
    : { malformed: true, value: pr?.statusCheckRollup ?? null };
  const latestReviews = Array.isArray(pr?.latestReviews)
    ? pr.latestReviews.map((review) => ({
      reviewer: review?.author?.login || review?.user?.login || null,
      state: review?.state ?? null,
      submittedAt: review?.submittedAt || review?.submitted_at || null,
      commitId: review?.commitId || review?.commit_id || null,
    })).sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right)))
    : { malformed: true, value: pr?.latestReviews ?? null };
  return {
    number: pr?.number ?? null,
    author: pr?.author?.login ?? null,
    state: pr?.state ?? null,
    baseRefOid: pr?.baseRefOid ?? null,
    headRefOid: pr?.headRefOid ?? null,
    isDraft: pr?.isDraft ?? null,
    mergeable: pr?.mergeable ?? null,
    mergeStateStatus: pr?.mergeStateStatus ?? null,
    reviewDecision: pr?.reviewDecision ?? null,
    checks,
    latestReviews,
  };
};

const stabilityTuplesMatch = (left, right) => JSON.stringify(left) === JSON.stringify(right);

const readLivePrState = async ({ repo, expectedHeadSha, expectedBaseSha, expectedConfigDigest, runGh = defaultRunGh } = {}) => {
  try {
    const repositoryResult = await runGh(['repo', 'view', '--json', 'nameWithOwner'], { repo });
    const repository = repositoryResult.nameWithOwner;
    if (!repository || !repository.includes('/')) throw new Error('GitHub repository identity was not returned.');
    const pr = await runGh([
      'pr',
      'view',
      '--json',
      PR_VIEW_FIELDS,
    ], { repo });
    if (!Number.isInteger(pr.number)) throw new Error('GitHub did not return an open pull request number.');
    if (typeof pr.author?.login !== 'string' || !pr.author.login.trim()) {
      throw new Error('GitHub did not return the pull request author identity.');
    }
    const [owner, name] = repository.split('/');
    const unresolvedThreads = await readUnresolvedReviewThreads({ repo, owner, name, number: pr.number, runGh });
    const firstGateSnapshot = await readGateAttestationSnapshotForPr({
      repo,
      repository,
      pr,
      expectedBaseSha,
      expectedHeadSha,
      expectedConfigDigest,
      runGh,
    });
    const finalGateSnapshot = await readGateAttestationSnapshotForPr({
      repo,
      repository,
      pr,
      expectedBaseSha,
      expectedHeadSha,
      expectedConfigDigest,
      runGh,
    });
    const finalPr = await runGh([
      'pr',
      'view',
      '--json',
      PR_VIEW_FIELDS,
    ], { repo });
    if (!Number.isInteger(finalPr.number)) throw new Error('GitHub did not return a stable pull request number.');
    if (typeof finalPr.author?.login !== 'string' || !finalPr.author.login.trim()) {
      throw new Error('GitHub did not return a stable pull request author identity.');
    }
    const prStable = stabilityTuplesMatch(capturePrStabilityTuple(pr), capturePrStabilityTuple(finalPr));
    const reviewsStable = stabilityTuplesMatch(firstGateSnapshot.stabilityTuple, finalGateSnapshot.stabilityTuple);
    if (!prStable || !reviewsStable) {
      return {
        status: 'BLOCKED',
        evidence: 'Live GitHub PR, check, or review state changed during verification; rerun against a stable remote snapshot.',
        repository,
        number: finalPr.number,
        checks: [],
        unresolvedThreads,
        externalServices: [],
        gateAttestation: finalGateSnapshot.attestation,
      };
    }
    const finalUnresolvedThreads = await readUnresolvedReviewThreads({ repo, owner, name, number: pr.number, runGh });
    return classifyLivePrState({
      repository,
      pr: finalPr,
      unresolvedThreads: finalUnresolvedThreads,
      expectedHeadSha,
      expectedBaseSha,
      gateAttestation: finalGateSnapshot.attestation,
    });
  } catch (error) {
    return {
      status: 'BLOCKED',
      evidence: `Live GitHub PR verification was unavailable: ${error.message}`,
      checks: [],
      unresolvedThreads: [],
      externalServices: [],
    };
  }
};

module.exports = {
  classifyGateAttestation,
  classifyLivePrState,
  gateAttestationMarker,
  readLiveGateAttestation,
  readLivePrState,
};
