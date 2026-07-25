const { execFile } = require('node:child_process');
const { promisify } = require('node:util');

const execFileAsync = promisify(execFile);

// True functional/infra failures. SKIPPED is intentionally absent: docs say a
// skipped applicable check is not PASS and must be run or marked BLOCKED, not
// reported as a functional FAIL (see references/pr-closeout-validation.md).
const FAILURE_CONCLUSIONS = new Set([
  'ACTION_REQUIRED',
  'CANCELLED',
  'ERROR',
  'FAILURE',
  'NEUTRAL',
  'STARTUP_FAILURE',
  'STALE',
  'TIMED_OUT',
]);
// Check conclusions that block closeout without claiming a functional failure.
const BLOCKED_CONCLUSIONS = new Set([
  'SKIPPED',
]);
const PENDING_STATES = new Set(['EXPECTED', 'IN_PROGRESS', 'PENDING', 'QUEUED', 'REQUESTED', 'WAITING']);
// OWNER (repo owner) is authoritative by association. MEMBER only proves
// organization membership and COLLABORATOR only proves an invitation to
// collaborate; neither guarantees repository write access, so both must be
// verified through the permission endpoint in reviewerAuthorization below.
const AUTHORITATIVE_ASSOCIATIONS = new Set(['OWNER']);
const WRITE_PERMISSIONS = new Set(['ADMIN', 'MAINTAIN', 'PUSH', 'WRITE']);
const MAX_REVIEW_THREAD_PAGES = 100;

/**
 * Build the exact-match line an independent reviewer's APPROVED review body
 * must contain, verbatim, to count as the gate attestation. Binding the
 * marker to `baseSha`/`headSha`/`configDigest` means a review approving one
 * commit or config cannot be replayed to attest a different one.
 * @param {{baseSha: string, headSha: string, configDigest: string}} shas
 * @returns {string}
 */
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

/**
 * Find the newest APPROVED review that independently attests this exact
 * gate: authored by someone other than the PR author, submitted against
 * `expectedHeadSha`, whose body contains the gateAttestationMarker line
 * exactly once (not as a substring/prefix and not duplicated), and whose
 * author is authorized (repository OWNER by association, or proven WRITE+
 * permission via `reviewerPermissions` — see reviewerAuthorization). Returns
 * `{status: 'PASS', ...}` with the winning review's identity, or
 * `{status: 'BLOCKED', evidence}` if no candidate qualifies.
 * @param {object} options
 * @param {object[]} [options.reviews]
 * @param {string} options.prAuthor
 * @param {string} options.expectedBaseSha
 * @param {string} options.expectedHeadSha
 * @param {string} options.expectedConfigDigest
 * @param {Map|object} [options.reviewerPermissions] - reviewer login (lowercased) -> GitHub collaborator-permission API response.
 * @returns {object} the attestation result.
 */
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
  else if (BLOCKED_CONCLUSIONS.has(conclusion)) classification = 'BLOCKED';
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

/**
 * Reduce one already-fetched snapshot of live GitHub PR state (metadata,
 * status checks, unresolved review threads, gate attestation) to a single
 * PASS/BLOCKED/FAIL verdict plus the evidence lines that justify it. A
 * definite functional problem (PR closed, merge conflicts, changes
 * requested, a FAILed check, a failed gate attestation) is FAIL; anything
 * merely unresolved, pending, or unproven (draft, not-yet-mergeable,
 * in-progress check, unresolved thread, unavailable attestation) is
 * BLOCKED — SKIPPED is deliberately absent from the failure set (see
 * FAILURE_CONCLUSIONS) so a skipped-but-applicable check blocks rather than
 * silently passing. `expectedHeadSha`/`expectedBaseSha` are only used to
 * annotate the returned snapshot, not to re-validate here — callers that
 * need the "did the PR move" check should compare snapshots themselves (see
 * readLivePrState).
 * @param {object} options
 * @param {string} [options.repository]
 * @param {object} [options.pr] - a GitHub `pr view` JSON object.
 * @param {object[]} [options.unresolvedThreads]
 * @param {string} [options.expectedHeadSha]
 * @param {string} [options.expectedBaseSha]
 * @param {object} [options.gateAttestation] - result of classifyGateAttestation.
 * @returns {object} `{status, evidence, ...}` plus the normalized checks/threads/gateAttestation.
 */
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

/**
 * Fetch the current PR from GitHub (via `gh`) and classify its gate
 * attestation, but only against the exact snapshot the caller expects: if
 * the live head or base OID does not match `expectedHeadSha`/
 * `expectedBaseSha`, this returns BLOCKED immediately rather than evaluating
 * reviews against a PR that has already moved — an approval attesting an
 * older head must never be read as attesting the current one. Any GitHub
 * error (auth, network, malformed response) is caught and returned as
 * BLOCKED with the error message as evidence; this never throws or invents
 * a PASS.
 * @param {object} options
 * @param {string} options.repo - path passed as `--repo`/cwd to the `gh` invocations.
 * @param {string} options.expectedBaseSha
 * @param {string} options.expectedHeadSha
 * @param {string} options.expectedConfigDigest
 * @param {Function} [options.runGh] - defaults to shelling out to the real `gh` CLI; overridable for tests.
 * @returns {Promise<object>} the attestation result.
 */
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
    // Include headRefOid/baseRefOid in the admission query so the attestation
    // cannot admit a stale local snapshot against an old approved review that
    // still carries the local expectedHeadSha marker. Validation must never
    // run against a PR head that has already moved on the remote.
    const pr = await runGh(['pr', 'view', '--json', 'author,number,baseRefOid,headRefOid'], { repo });
    if (!Number.isInteger(pr.number)) throw new Error('GitHub did not return an open pull request number.');
    if (typeof pr.author?.login !== 'string' || !pr.author.login.trim()) {
      throw new Error('GitHub did not return the pull request author identity.');
    }
    if (typeof pr.headRefOid !== 'string' || !pr.headRefOid) {
      throw new Error('GitHub did not return the pull request head OID.');
    }
    if (pr.headRefOid !== expectedHeadSha) {
      return {
        provider: 'github-pull-request-review',
        status: 'BLOCKED',
        baseSha: expectedBaseSha,
        headSha: expectedHeadSha,
        configDigest: expectedConfigDigest,
        evidence: `Live PR head ${pr.headRefOid.substring(0, 7)} does not match expected head ${expectedHeadSha?.substring(0, 7)}; admission attestation is bound to the wrong snapshot.`,
      };
    }
    if (typeof pr.baseRefOid !== 'string' || !pr.baseRefOid) {
      throw new Error('GitHub did not return the pull request base OID.');
    }
    if (pr.baseRefOid !== expectedBaseSha) {
      return {
        provider: 'github-pull-request-review',
        status: 'BLOCKED',
        baseSha: expectedBaseSha,
        headSha: expectedHeadSha,
        configDigest: expectedConfigDigest,
        evidence: `Live PR base ${pr.baseRefOid.substring(0, 7)} does not match expected base ${expectedBaseSha?.substring(0, 7)}; admission attestation is bound to the wrong snapshot.`,
      };
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

/**
 * Verify live GitHub PR state is stable and clean enough to close out on,
 * guarding against state changing mid-verification (a reviewer's access
 * being revoked, a new push, a check flipping) rather than trusting a single
 * point-in-time read.
 *
 * Takes two independent gate-attestation snapshots (`firstGateSnapshot`,
 * `finalGateSnapshot`) around a single PR-metadata read pair. Each snapshot
 * re-fetches reviewer collaborator permissions from scratch — a snapshot
 * must never reuse the other's permission map, or a write-to-read
 * permission downgrade (or a transient permission-API failure) between the
 * two reads would go unnoticed and the two "independent" snapshots would no
 * longer be independent. If the PR-metadata tuple or either gate-attestation
 * stability tuple differs between the two reads, this returns BLOCKED
 * ("changed during verification") without trusting either snapshot's
 * classification.
 *
 * On the stable path, unresolved review threads are read exactly once (the
 * final read) so the common case pays for one paginated thread walk instead
 * of two; the unstable path pays for a second, separate read since it needs
 * current evidence for the BLOCKED result.
 *
 * Never throws: GitHub/parse errors are caught and returned as BLOCKED with
 * the error message as evidence.
 * @param {object} options
 * @param {string} options.repo - path passed as `--repo`/cwd to the `gh` invocations.
 * @param {string} options.expectedHeadSha
 * @param {string} options.expectedBaseSha
 * @param {string} options.expectedConfigDigest
 * @param {Function} [options.runGh] - defaults to shelling out to the real `gh` CLI; overridable for tests.
 * @returns {Promise<object>} the classified live PR state (see classifyLivePrState), or a BLOCKED stub on instability/error.
 */
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
      // The second snapshot must fetch reviewer permissions independently:
      // reusing the first snapshot's permission map would mask permission
      // changes (and make transient permission-API failures sticky) across the
      // stability window, defeating the two-independent-snapshots race check.
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
      // Defer the unstable-state review-thread read into this branch so the
      // common stable path only pays for one thread read (the final one
      // below) instead of two full paginated round-trips.
      const unstableThreads = await readUnresolvedReviewThreads({ repo, owner, name, number: pr.number, runGh });
      return {
        status: 'BLOCKED',
        evidence: 'Live GitHub PR, check, or review state changed during verification; rerun against a stable remote snapshot.',
        repository,
        number: finalPr.number,
        checks: [],
        unresolvedThreads: unstableThreads,
        externalServices: [],
        gateAttestation: finalGateSnapshot.attestation,
      };
    }
    const finalUnresolvedThreads = await readUnresolvedReviewThreads({ repo, owner, name, number: pr.number, runGh });
    // Revalidate after the (often long) paginated thread walk: a push, check
    // flip, review edit, or permission change during that window would leave
    // finalPr / finalGateSnapshot stale while threads look current. Take a
    // terminal PR + attestation snapshot and require the full stability
    // tuple to still match before classifying PASS.
    const terminalPr = await runGh([
      'pr',
      'view',
      '--json',
      PR_VIEW_FIELDS,
    ], { repo });
    if (!Number.isInteger(terminalPr.number)) throw new Error('GitHub did not return a terminal pull request number.');
    if (typeof terminalPr.author?.login !== 'string' || !terminalPr.author.login.trim()) {
      throw new Error('GitHub did not return a terminal pull request author identity.');
    }
    const terminalGateSnapshot = await readGateAttestationSnapshotForPr({
      repo,
      repository,
      pr: terminalPr,
      expectedBaseSha,
      expectedHeadSha,
      expectedConfigDigest,
      runGh,
    });
    const terminalPrStable = stabilityTuplesMatch(
      capturePrStabilityTuple(finalPr),
      capturePrStabilityTuple(terminalPr),
    );
    const terminalReviewsStable = stabilityTuplesMatch(
      finalGateSnapshot.stabilityTuple,
      terminalGateSnapshot.stabilityTuple,
    );
    // Thread state is not in PR/review stability tuples. Re-read threads after
    // the terminal snapshot and require an identical unresolved set so a
    // reopen during the terminal window cannot PASS with a stale empty list.
    const terminalUnresolvedThreads = await readUnresolvedReviewThreads({
      repo, owner, name, number: terminalPr.number, runGh,
    });
    const threadTuple = (threads) => JSON.stringify(
      [...(threads || [])]
        .map((thread) => ({
          path: thread?.path ?? null,
          line: thread?.line ?? null,
          url: thread?.url ?? null,
        }))
        .sort((a, b) => JSON.stringify(a).localeCompare(JSON.stringify(b))),
    );
    const threadsStable = threadTuple(finalUnresolvedThreads) === threadTuple(terminalUnresolvedThreads);
    if (!terminalPrStable || !terminalReviewsStable || !threadsStable) {
      return {
        status: 'BLOCKED',
        evidence: 'Live GitHub PR, check, or review state changed during verification; rerun against a stable remote snapshot.',
        repository,
        number: terminalPr.number,
        checks: [],
        unresolvedThreads: terminalUnresolvedThreads,
        externalServices: [],
        gateAttestation: terminalGateSnapshot.attestation,
      };
    }
    // The thread walk above is the longest remaining read. Re-capture PR +
    // gate attestation once more so a check flip / push during that walk
    // cannot be classified against the pre-walk snapshot.
    const postThreadPr = await runGh([
      'pr',
      'view',
      '--json',
      PR_VIEW_FIELDS,
    ], { repo });
    if (!Number.isInteger(postThreadPr.number)) {
      throw new Error('GitHub did not return a post-thread pull request number.');
    }
    const postThreadGateSnapshot = await readGateAttestationSnapshotForPr({
      repo,
      repository,
      pr: postThreadPr,
      expectedBaseSha,
      expectedHeadSha,
      expectedConfigDigest,
      runGh,
    });
    const postThreadPrStable = stabilityTuplesMatch(
      capturePrStabilityTuple(terminalPr),
      capturePrStabilityTuple(postThreadPr),
    );
    const postThreadReviewsStable = stabilityTuplesMatch(
      terminalGateSnapshot.stabilityTuple,
      postThreadGateSnapshot.stabilityTuple,
    );
    if (!postThreadPrStable || !postThreadReviewsStable) {
      return {
        status: 'BLOCKED',
        evidence: 'Live GitHub PR, check, or review state changed during the terminal thread walk; rerun against a stable remote snapshot.',
        repository,
        number: postThreadPr.number,
        checks: [],
        unresolvedThreads: terminalUnresolvedThreads,
        externalServices: [],
        gateAttestation: postThreadGateSnapshot.attestation,
      };
    }
    // The post-thread PR/gate re-fetch itself is another network window. A
    // new unresolved review thread opened in that window would leave
    // terminalUnresolvedThreads stale (often empty) while PR/checks still
    // look stable — re-read threads and require an identical set before PASS.
    const postThreadUnresolvedThreads = await readUnresolvedReviewThreads({
      repo, owner, name, number: postThreadPr.number, runGh,
    });
    if (threadTuple(terminalUnresolvedThreads) !== threadTuple(postThreadUnresolvedThreads)) {
      return {
        status: 'BLOCKED',
        evidence: 'Live GitHub review threads changed during post-thread verification; rerun against a stable remote snapshot.',
        repository,
        number: postThreadPr.number,
        checks: [],
        unresolvedThreads: postThreadUnresolvedThreads,
        externalServices: [],
        gateAttestation: postThreadGateSnapshot.attestation,
      };
    }
    return classifyLivePrState({
      repository,
      pr: postThreadPr,
      unresolvedThreads: postThreadUnresolvedThreads,
      expectedHeadSha,
      expectedBaseSha,
      gateAttestation: postThreadGateSnapshot.attestation,
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
