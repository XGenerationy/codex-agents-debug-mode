const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const {
  closeSync, constants: fsConstants, fstatSync, lstatSync, readFileSync, unlinkSync,
} = require('node:fs');
const { openNoFollowSync } = require('./pr_closeout_fs');

const execFileAsync = promisify(execFile);

// Off-environment workflow-token delegation (chatgpt-codex-connector PR7
// #6Yd4Qv, P1). Background: on a Linux/self-hosted runner whose procfs ptrace
// policy permits same-UID reads, a repository-controlled plan-preflight probe
// can walk its process ancestry and read GH_TOKEN out of any ancestor's
// /proc/<pid>/environ. `/proc/<pid>/environ` is the environment block CAPTURED
// AT THAT PROCESS'S OWN execve(2) and is NOT updated by later in-process
// setenv()/putenv() (verified empirically on Linux: a variable present in a
// process's exec-time env appears in its own /proc/self/environ and is
// readable by a scrubbed-env child through /proc/<ppid>/environ, while a
// variable added by an in-process assignment after exec never appears there;
// and against proc(5): "environ — the initial environment set when the program
// was started via execve(2)"). Filtering the probe's OWN spawn env therefore
// does nothing about the token still sitting in an ancestor's exec-time
// environ. The action.yml wiring now keeps GH_TOKEN out of the env of every
// process that is an ancestor of the probe (the gate step no longer sets it),
// and instead a separate, earlier step stages the token into an owner-only
// FILE named by CLOSEOUT_GH_TOKEN_FILE. This module reads that file only when
// it actually needs to authenticate a `gh` call, and hands the token to the
// `gh` LEAF process via that child's OWN spawn env — the leaf has no
// descendants, so it never becomes a probe ancestor. The token thus lives only
// in (a) an owner-only file that resolvePlanAdmission REVOKES before any
// untrusted probe runs, (b) the short-lived `gh` leaf's environ, and (c) this
// process's JS heap — never in any probe-ancestor's exec-time environ.
//
// GUARANTEED: for the plan tier, no process in the untrusted preflight probe's
// ancestry (the runner step shell, this Node CLI, or its children) has ever
// held GH_TOKEN in its exec-time environment, and the delegated-token file is
// deleted before the probe is spawned — closing the /proc/<pid>/environ
// exfiltration vector for the pre-attestation preview.
// NOT GUARANTEED: this does not create an OS-level process/UID boundary. A
// same-UID process could still read this CLI's heap via a ptrace attach where
// the runner's ptrace_scope permits attaching to an ancestor (scope 0), and in
// the FULL (attested) tier the delegated-token file necessarily persists across
// the run because authenticated reads follow the preflight probe — so a
// full-tier probe (which only runs after a WRITE-access reviewer has attested
// this exact snapshot) can still read the token file by path. Those residuals
// are the same class the #6YaZ5K KNOWN LIMITATION documents and are out of
// scope for a targeted change; the token remains bounded by the consuming
// workflow's own `permissions:` grant regardless.

// A workflow token is a compact opaque string; 64 KiB is orders of magnitude
// beyond any legitimate one and bounds a hostile/oversized file read.
const DELEGATED_TOKEN_MAX_BYTES = 64 * 1024;

/**
 * Reads the delegated workflow token from the owner-only file named by
 * CLOSEOUT_GH_TOKEN_FILE, or returns null when the caller should fall back to
 * the ambient `gh` behavior (a token already present in the process
 * environment, or no delegation file configured). Returning null — never
 * throwing — keeps a delegation misconfiguration from turning every gh call
 * into a hard crash; the gh call then simply runs unauthenticated and the
 * attestation reader reports its own honest "unavailable" state.
 *
 * The file is opened no-follow after an lstat regular-file gate (mirroring the
 * symlink discipline used for every other sensitive read in this codebase) so
 * a symlink planted at the path cannot redirect the read, and is size-bounded
 * before any byte is consumed. The value is trimmed of surrounding whitespace
 * so a trailing newline written by the stager does not corrupt the token.
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string|null}
 */
const acquireDelegatedGhToken = (env = process.env) => {
  // An explicit token already in the environment wins — this preserves the
  // pre-existing behavior for direct CLI users and any caller that still sets
  // GH_TOKEN/GITHUB_TOKEN itself. Delegation is only for the hardened action
  // path where the gate step deliberately carries no token env.
  if (env.GH_TOKEN || env.GITHUB_TOKEN) return null;
  const file = env.CLOSEOUT_GH_TOKEN_FILE;
  if (!file) return null;
  let info;
  try {
    info = lstatSync(file);
  } catch {
    return null;
  }
  if (!info.isFile()) return null;
  let fd;
  try {
    fd = openNoFollowSync(file, fsConstants.O_RDONLY, 0o666, true);
  } catch {
    return null;
  }
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.size > DELEGATED_TOKEN_MAX_BYTES) return null;
    const token = readFileSync(fd, 'utf8').trim();
    return token || null;
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
};

/**
 * Deletes the delegated-token file so no untrusted process spawned afterwards
 * can read it by path. Called by resolvePlanAdmission immediately before the
 * plan-preflight probe (the first and only point in the plan tier where
 * repository-controlled code executes). Throws on any failure OTHER than the
 * file already being absent (ENOENT): a token file that could not be proven
 * gone must fail the caller closed — a preview that BLOCKS is strictly better
 * than one that runs an untrusted probe while the token file still exists. A
 * no-op when delegation is not in use (no CLOSEOUT_GH_TOKEN_FILE, or a token
 * was supplied through the ambient environment instead).
 * @param {NodeJS.ProcessEnv} [env]
 */
const revokeDelegatedGhToken = (env = process.env) => {
  const file = env.CLOSEOUT_GH_TOKEN_FILE;
  if (!file) return;
  try {
    unlinkSync(file);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
};

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

/**
 * Look up a collaborator-permission record by reviewer login (case-insensitive).
 * @param {Map|object|undefined} reviewerPermissions
 * @param {string} reviewer
 * @returns {object|undefined}
 */
const permissionRecordFor = (reviewerPermissions, reviewer) => {
  if (reviewerPermissions instanceof Map) {
    return reviewerPermissions.get(reviewer.toLowerCase());
  }
  if (reviewerPermissions && typeof reviewerPermissions === 'object') {
    return reviewerPermissions[reviewer.toLowerCase()] || reviewerPermissions[reviewer];
  }
  return undefined;
};

/**
 * Decide whether a review author may attest the gate: OWNER/MEMBER/COLLABORATOR
 * association, or a proven WRITE+ collaborator permission record.
 * @param {object} review
 * @param {Map|object} [reviewerPermissions]
 * @returns {{authorized: boolean, association: string|null, permission: string|null}}
 */
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
  // Collapse each reviewer's history on this head to their latest submission
  // before admitting APPROVED+marker. Otherwise an older APPROVED with the
  // marker still admits after the same reviewer later posts CHANGES_REQUESTED
  // (or a marker-less re-review) on the same head (Codex #4780351874).
  const latestByReviewer = new Map();
  const isLaterReview = (candidate, previous) => {
    const candidateAt = String(candidate.submitted_at || '');
    const previousAt = String(previous.submitted_at || '');
    if (candidateAt !== previousAt) return candidateAt > previousAt;
    // Deterministic tie-break when submitted_at collides: GitHub review ids
    // are monotonic, so the higher id is the later decision (Codex open
    // finding on same-timestamp CHANGES_REQUESTED after APPROVED+marker).
    return Number(candidate.id || 0) > Number(previous.id || 0);
  };
  for (const review of reviews) {
    const reviewer = review?.user?.login;
    if (typeof reviewer !== 'string' || !reviewer.trim()) continue;
    if (review?.commit_id !== expectedHeadSha) continue;
    const key = reviewer.toLowerCase();
    const previous = latestByReviewer.get(key);
    if (!previous || isLaterReview(review, previous)) {
      latestByReviewer.set(key, review);
    }
  }
  const candidates = [...latestByReviewer.values()].filter((review) => {
    const exactLines = String(review?.body || '').split(/\r?\n/).filter((line) => line === marker);
    const reviewer = review?.user?.login;
    return String(review?.state || '').toUpperCase() === 'APPROVED'
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

const readActionsPrNumber = ({ env }) => {
  const refName = env.GITHUB_REF_NAME || '';
  const refMatch = refName.match(/^(\d+)\/merge$/);
  if (refMatch) return Number(refMatch[1]);
  if (env.GITHUB_EVENT_PATH) {
    try {
      const event = JSON.parse(readFileSync(env.GITHUB_EVENT_PATH, 'utf8'));
      const direct = Number(event?.pull_request?.number);
      if (Number.isFinite(direct) && direct > 0) return direct;
      // workflow_run events carry no top-level pull_request; a same-repo
      // PR's number instead lives at workflow_run.pull_requests[]. GitHub
      // documents this as an array (theoretically >1 entries), and it is
      // empty for a fork PR (not populated for forks). Only trust it when
      // it names exactly one PR — with more than one we cannot tell which
      // PR this run belongs to, so fail closed to null rather than guess
      // (CodeRabbit PR7 #6YZkn9); empty likewise falls through to null.
      const workflowRunPrs = event?.workflow_run?.pull_requests;
      if (Array.isArray(workflowRunPrs) && workflowRunPrs.length === 1) {
        const viaWorkflowRun = Number(workflowRunPrs[0]?.number);
        if (Number.isFinite(viaWorkflowRun) && viaWorkflowRun > 0) return viaWorkflowRun;
      }
      // workflow_dispatch carries neither pull_request nor workflow_run —
      // `gh pr view` (bare) falls back to "the PR for the current branch",
      // which is wrong (or fails outright) for a fork PR — not selectable in
      // the dispatch UI's branch dropdown at all — or a dispatch launched
      // from the default branch (chatgpt-codex-connector PR7 #6Yd4Qs). The
      // workflow's `pr-number` dispatch input (see closeout-gate.yml) is the
      // explicit escape hatch: GitHub places declared workflow_dispatch
      // inputs verbatim under event.inputs, keyed by their declared
      // (hyphenated) name, same as base-ref is already read at the YAML
      // level elsewhere in this workflow.
      const viaDispatchInput = Number(event?.inputs?.['pr-number']);
      if (Number.isFinite(viaDispatchInput) && viaDispatchInput > 0) return viaDispatchInput;
    } catch {
      /* fall through */
    }
  }
  return null;
};

const buildGhArgs = (args, { repo } = {}) => {
  if (!Array.isArray(args) || args.length < 2) return args;
  if (process.env.GITHUB_ACTIONS !== 'true') return args;
  const repository = process.env.GITHUB_REPOSITORY || '';
  if (!repository.includes('/')) return args;
  if (args.includes('--repo')) return args;

  const [sub, action] = args;
  if (sub === 'pr' && action === 'view') {
    const number = readActionsPrNumber({ env: process.env });
    if (!number) return args;
    return ['pr', 'view', String(number), ...args.slice(2), '--repo', repository];
  }
  if (sub === 'repo' && action === 'view') {
    // gh repo view takes the repository positionally; --repo is not a valid flag
    return ['repo', 'view', repository, ...args.slice(2)];
  }
  return args;
};
const defaultRunGh = async (args, { repo } = {}) => {
  const finalArgs = buildGhArgs(args, { repo });
  // Hand the delegated workflow token (when one is configured off-environment,
  // chatgpt-codex-connector PR7 #6Yd4Qv) to the `gh` LEAF process through its
  // OWN spawn env, so authentication works without this CLI — a probe ancestor
  // — ever carrying GH_TOKEN in its exec-time environ. When no delegated token
  // is in use (a token already in process.env, or no delegation file),
  // acquireDelegatedGhToken returns null and gh inherits the ambient
  // environment exactly as before. `gh` reads GH_TOKEN ahead of GITHUB_TOKEN,
  // so setting GH_TOKEN alone is sufficient.
  const delegatedToken = acquireDelegatedGhToken();
  const childEnv = delegatedToken ? { ...process.env, GH_TOKEN: delegatedToken } : undefined;
  const { stdout } = await execFileAsync('gh', finalArgs, {
    cwd: repo,
    encoding: 'utf8',
    maxBuffer: 20_000_000,
    timeout: 60_000,
    windowsHide: true,
    ...(childEnv ? { env: childEnv } : {}),
  });
  // A handful of `gh api` endpoints (e.g. POST .../rerun) return 204 No
  // Content on success — empty stdout, not empty JSON. Every existing
  // caller of this function only ever reads endpoints that return a real
  // body, so this branch was previously unreachable; JSON.parse('') would
  // throw SyntaxError and a genuinely successful call would be misreported
  // as failed. Return null rather than guessing a shape — callers that
  // expect a body already destructure defensively (`response?.field`).
  if (!stdout.trim()) return null;
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
 * Resolve the CURRENT job's true displayed check name — the value that
 * shows up in `statusCheckRollup[].name` — rather than assuming it equals
 * `GITHUB_JOB` (the YAML job id). The two diverge whenever the consuming
 * workflow gives the job a `name:` override or runs it in a
 * `strategy.matrix` (the displayed name then carries a `(value, value)`
 * suffix); `classifyLivePrState`'s self-exclusion match on `GITHUB_JOB`
 * alone silently no-ops in either configuration (CodeRabbit PR7 #6YXkRF).
 *
 * `RUNNER_NAME` uniquely identifies the runner executing THIS job within
 * the current workflow run (GitHub Actions provisions a distinct runner
 * instance per job), so matching the Jobs API's `runner_name` field against
 * it — rather than trying to match on job id/name, which is exactly the
 * ambiguous data this function exists to resolve — reliably finds this
 * job's own entry and its true `name`.
 *
 * Deliberately best-effort: returns `null` on any missing env var, API
 * failure, malformed response, or no matching job found, so the caller can
 * fall back to the existing `GITHUB_JOB` behavior exactly as before this
 * function existed. A transient API failure or rate limit here must never
 * turn into a hard failure of the whole live-state read — self-exclusion is
 * an optimization (avoid the gate blocking on its own in-progress check),
 * not a correctness requirement of live-state classification itself.
 *
 * Returns `false` — NOT `null` — specifically when a genuine name collision
 * is detected (another job in this run shares this job's resolved displayed
 * name): `null` means "could not determine a name, use the legacy
 * `GITHUB_JOB` fallback", but that fallback is exactly as unsafe as the
 * collision itself whenever this job has no `name:` override, since
 * `GITHUB_JOB` (the YAML job id) then equals the very displayed name found
 * to be ambiguous, and `classifyLivePrState` would recreate the identical
 * false match `GITHUB_JOB` was meant to disambiguate (chatgpt-codex-
 * connector PR7 #6YbMwM). `false` tells the caller to skip self-exclusion
 * entirely rather than fall back — a failed sibling sharing this job's name
 * must stay visible in the rollup rather than be silently excluded alongside
 * this job's own in-progress check.
 * @param {object} options
 * @param {string} options.repository - "owner/name".
 * @param {Function} options.runGh - injectable `gh` invoker, same contract as elsewhere in this file.
 * @param {string} [options.repo] - repo checkout path, forwarded to runGh like every other call site.
 * @param {object} [options.env] - defaults to process.env.
 * @returns {Promise<string|false|null>}
 */
const resolveCurrentJobDisplayName = async ({ repository, runGh, repo, env = process.env } = {}) => {
  const runId = env.GITHUB_RUN_ID;
  const runnerName = env.RUNNER_NAME;
  if (!repository || typeof runGh !== 'function' || !runId || !runnerName) return null;
  try {
    // --paginate: the Jobs API returns 30 jobs per page by default, and a
    // matrix or multi-job workflow can easily exceed that (CodeRabbit PR7
    // #6YZkoF). --paginate ALONE does not merge pages into one JSON
    // document — gh's own help text is explicit: "Each page is a separate
    // JSON array or object. Pass --slurp to wrap all pages ... into an
    // outer JSON array." Without --slurp, multiple pages print as multiple
    // concatenated JSON documents, which runGh's single JSON.parse(stdout)
    // cannot parse — the call would throw and this resolver would silently
    // fall back to null on any run with more than one page of jobs, the
    // opposite of what --paginate was added for (qodo PR7, "Jobs api
    // pagination unparsable"). --slurp (already the established pattern
    // for a paginated `gh api` call elsewhere in this file) wraps every
    // page into one outer array; each element here is a whole page OBJECT
    // (`{jobs: [...], total_count}`, not a bare array like the reviews
    // endpoint), so each page's own `.jobs` is extracted and concatenated.
    const pages = await runGh(['api', `repos/${repository}/actions/runs/${runId}/jobs`, '--paginate', '--slurp'], { repo });
    const list = (Array.isArray(pages) ? pages : []).flatMap((page) => (Array.isArray(page?.jobs) ? page.jobs : []));
    // A reused self-hosted runner can carry the same runner_name across
    // sequential jobs within one run, so the first match by name alone
    // could be an earlier, already-COMPLETED job rather than this one
    // (CodeRabbit PR7 #6YZkoJ). Only trust a non-COMPLETED match, and only
    // when it is unique — an ambiguous or absent match resolves to null,
    // same as any other best-effort failure of this resolver.
    const activeMatches = list.filter(
      (job) => job && job.runner_name === runnerName && String(job.status || '').toUpperCase() !== 'COMPLETED',
    );
    const ownJob = activeMatches.length === 1 ? activeMatches[0] : null;
    const ownName = typeof ownJob?.name === 'string' && ownJob.name ? ownJob.name : null;
    if (!ownName) return null;
    // classifyLivePrState's self-exclusion matches purely on displayed name
    // (workflowName + name), since that is all statusCheckRollup exposes —
    // it has no notion of "the exact same job instance" versus "a different
    // job that happens to render an identical name". If a consumer's
    // workflow has TWO DIFFERENT jobs sharing this exact displayed name
    // (e.g. both given the same `name:` override), returning this name would
    // make self-exclusion ALSO exclude the sibling's check entirely — a
    // genuinely failed sibling could then go undetected and the gate could
    // wrongly reach PASS (chatgpt-codex-connector PR7 #6Yap8W). This SAME
    // Jobs API response already reveals such a collision directly: if more
    // than one job in this run carries this name, resolving to it is unsafe.
    //
    // Return `false` here, NOT `null` (chatgpt-codex-connector PR7 #6YbMwM):
    // `null` means "use the legacy GITHUB_JOB fallback", but when this job
    // has no `name:` override, GITHUB_JOB literally EQUALS `ownName` — the
    // very name just found to be ambiguous — so falling back would recreate
    // the identical collision `classifyLivePrState` matches on, excluding
    // the sibling's genuinely-failed check right alongside this job's own.
    // `false` is a distinct sentinel the caller must treat as "do not
    // self-exclude at all", not as "resolution failed, try the old way".
    const sameNameJobCount = list.filter((job) => job?.name === ownName).length;
    if (sameNameJobCount > 1) return false;
    return ownName;
  } catch {
    return null;
  }
};

/**
 * Resolve the workflow FILE path (e.g. `.github/workflows/closeout-gate.yml`)
 * that produced a given run id, via `repos/{repo}/actions/runs/{runId}` — a
 * distinct endpoint/field from resolveCurrentJobDisplayName's Jobs API call.
 * Best-effort: any failure (bad runId, API error, missing field) resolves to
 * null, exactly like resolveCurrentJobDisplayName's own failure contract.
 * @param {object} options
 * @param {string} [options.repository]
 * @param {Function} [options.runGh]
 * @param {string} [options.repo]
 * @param {string} [options.runId]
 * @returns {Promise<string|null>}
 */
const resolveWorkflowRunPath = async ({ repository, runGh, repo, runId } = {}) => {
  if (!repository || typeof runGh !== 'function' || !runId) return null;
  try {
    const run = await runGh(['api', `repos/${repository}/actions/runs/${runId}`], { repo });
    return typeof run?.path === 'string' && run.path ? run.path : null;
  } catch {
    return null;
  }
};

/**
 * Close the cross-workflow self-exclusion collision documented as a KNOWN
 * LIMITATION inside classifyLivePrState (chatgpt-codex-connector PR7
 * #6Yb44Si): that function's self-exclusion filter matches purely on
 * DISPLAYED workflow name + job name, so a second, unrelated workflow FILE
 * that happens to render the identical display names would have its checks
 * — including a genuine failure — silently excluded too.
 *
 * This runs entirely in the caller (readLivePrState), which already has
 * `runGh`/`repo` access, rather than making classifyLivePrState itself async
 * — the complete fix scoped in that function's own comment, implemented here
 * to avoid the signature change rippling through every call site/test there.
 *
 * Cheap in the common case: GitHub's statusCheckRollup normally carries at
 * most ONE entry per distinct check name at a time (a rerun supersedes the
 * prior entry in place), so finding a SECOND, distinct run id sharing this
 * job's exact displayed name is itself already an unusual signal — the loop
 * below only makes extra `gh api` calls when that signal is present, zero
 * otherwise. When it fires, this fails SAFE: an unresolvable run identity or
 * mismatched path disables self-exclusion (`collision: true`, which maps to
 * the existing tested `false` sentinel by the caller), which can only make
 * the gate MORE conservative (BLOCKED on a check that turns out to be this
 * run's own), never less — it can never turn a real failure into a false
 * PASS.
 *
 * Returns `networkCallsMade` alongside the verdict (CodeRabbit PR7 #6Yb44So)
 * so the caller knows whether it must re-verify PR/attestation/thread
 * stability afterward: a live `resolveWorkflowRunPath` request reopens the
 * same kind of unverified window every other network call in readLivePrState
 * is already re-checked for. `networkCallsMade` is `false` whenever the
 * verdict was reached WITHOUT any request — the common zero-collision case,
 * and the unidentified-run-id fail-safe path, which returns immediately
 * without calling `resolveWorkflowRunPath` at all.
 *
 * An unresolvable `selfWorkflowPath` (this run's OWN path, not another
 * run's) also fails safe to `collision: true` (cubic P1, following up on
 * #6Yb44Si): without a baseline to compare against, whether a name-matching
 * check belongs to a different workflow simply cannot be determined, so
 * self-exclusion must not be allowed to silently continue on the strength of
 * the name match alone — that is precisely the collision this function
 * exists to catch. In real GitHub Actions runs GITHUB_RUN_ID (this call's
 * only precondition, alongside the name/job values) is always present, so
 * this path is reached only on a genuine transient failure of the
 * `repos/{repo}/actions/runs/{runId}` request itself — rare, and no worse
 * than the pre-#6YXkRF self-exclusion gap this whole feature improves on:
 * worst case the gate BLOCKS on its own pending check for one evaluation,
 * never a false PASS.
 * @param {object} options
 * @param {object} [options.pr] - a `gh pr view` JSON object with statusCheckRollup.
 * @param {string|null} [options.selfWorkflowName]
 * @param {string|null} [options.selfJobName]
 * @param {string|null} [options.selfWorkflowPath]
 * @param {string} [options.repository]
 * @param {Function} [options.runGh]
 * @param {string} [options.repo]
 * @param {object} [options.env]
 * @returns {Promise<{collision: boolean, networkCallsMade: boolean}>}
 */
const detectCrossWorkflowSelfExclusionCollision = async ({
  pr,
  selfWorkflowName,
  selfJobName,
  selfWorkflowPath,
  repository,
  runGh,
  repo,
  env = process.env,
} = {}) => {
  if (!selfWorkflowName || !selfJobName) return { collision: false, networkCallsMade: false };
  if (!selfWorkflowPath) return { collision: true, networkCallsMade: false };
  const rollup = Array.isArray(pr?.statusCheckRollup) ? pr.statusCheckRollup : [];
  const selfRunId = env.GITHUB_RUN_ID ? String(env.GITHUB_RUN_ID) : null;
  const otherRunIds = new Set();
  for (const entry of rollup) {
    const normalized = normalizeCheck(entry);
    if (normalized.workflowName !== selfWorkflowName || normalized.name !== selfJobName) continue;
    const detailsUrl = typeof entry?.detailsUrl === 'string' ? entry.detailsUrl : '';
    const match = detailsUrl.match(/\/actions\/runs\/(\d+)\//);
    const runId = match ? match[1] : null;
    // A name-matching entry whose run id cannot be extracted (missing,
    // empty, or unexpectedly shaped detailsUrl) cannot be PROVEN to be this
    // run's own check either — treat it the same as an unresolvable path
    // below (CodeRabbit PR7 #6Yb44Sm): fail safe rather than silently let
    // classifyLivePrState exclude an unverified check. No request is made to
    // reach this verdict, so networkCallsMade stays false.
    if (!runId) return { collision: true, networkCallsMade: false };
    if (runId !== selfRunId) otherRunIds.add(runId);
  }
  if (!otherRunIds.size) return { collision: false, networkCallsMade: false };
  for (const runId of otherRunIds) {
    const otherPath = await resolveWorkflowRunPath({ repository, runGh, repo, runId });
    if (!otherPath || otherPath !== selfWorkflowPath) return { collision: true, networkCallsMade: true };
  }
  return { collision: false, networkCallsMade: true };
};

/**
 * Resolve the self job's DISPLAYED name to match against `statusCheckRollup`
 * entries, from resolveCurrentJobDisplayName's result. `selfJobDisplayName
 * === false` is a DISTINCT sentinel from `null`/absent (chatgpt-codex-
 * connector PR7 #6YbMwM): the resolver returns it specifically when it
 * detected another job sharing this job's own displayed name, and in that
 * exact scenario GITHUB_JOB can itself equal that same ambiguous name —
 * falling back to it would recreate the very collision the resolver just
 * rejected. Resolves to `null` in that case so self-exclusion is skipped
 * entirely, rather than silently falling back to an equally-unsafe match.
 * Shared by classifyLivePrState's own self-exclusion filter and
 * readLivePrState's cross-workflow collision pre-check so the two copies of
 * this sentinel rule cannot independently drift (CodeRabbit PR7 #6Yb44Sn).
 * @param {string|false|null|undefined} selfJobDisplayName
 * @param {object} [env]
 * @returns {string|null}
 */
const resolveSelfJobName = (selfJobDisplayName, env = process.env) => (
  selfJobDisplayName === false
    ? null
    : (selfJobDisplayName || env.GITHUB_JOB || null)
);

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
  selfJobDisplayName,
} = {}) => {
  // Exclude the gate JOB's OWN checks from the rollup classification
  // (CodeRabbit #6X_pwH, refined by #6YSx9w and — for retries — by
  // chatgpt-codex-connector PR7 #6YaIaU): at the moment the gate classifies
  // live state, its own check is IN_PROGRESS and cannot see its own result, so
  // counting it would always block PASS. The exclusion is scoped to the SINGLE
  // current job — NOT the whole workflow. Earlier versions matched on
  // workflowName alone, which incorrectly excluded sibling jobs in the same
  // workflow (e.g. a preview job) and could let the gate PASS before a sibling
  // finished (#6YSx9w). The match requires BOTH:
  //   - workflowName === GITHUB_WORKFLOW (this workflow)
  //   - check.name === the current job's DISPLAYED name
  // A sibling job's check (different name) is never excluded, still matching
  // #6YSx9w.
  //
  // ALL checks matching both — completed or not — are now excluded, not only
  // the currently-in-progress one. #6X_pwH/#6YSx9w originally kept a prior
  // COMPLETED run of this same job classified ("a prior FAILURE keeps
  // blocking"), written before the workflow_run retry trigger existed
  // (#6YW9UP): back then, every gate invocation was triggered by a
  // meaningfully new PR/review event, so a leftover FAILURE from an earlier
  // run at the same head was a plausible still-relevant signal. The retry
  // trigger broke that assumption — it exists specifically to re-run the
  // gate after a run that correctly BLOCKED on a still-pending sibling check
  // (an entirely routine, non-error outcome, but one GitHub Actions can only
  // record as a job "failure" conclusion, since jobs have no native
  // "blocked" state). Keeping that stale FAILURE classified would make the
  // retry re-derive FAIL from its own earlier blocked attempt on every
  // re-run, forever, for the one scenario the retry exists to recover from.
  // This is safe to remove: every OTHER failure/blocker signal below
  // (mergeability, review decision, unresolved threads, gate attestation,
  // and every check that is NOT this job) is independently re-derived from
  // LIVE state on each call — nothing here depends on trusting a past
  // verdict from this same job, so a stale self check-run is redundant
  // information, not additional protection.
  //
  // `check.name` is the check's DISPLAYED name, which is NOT always
  // `GITHUB_JOB` (the YAML job id): a consumer that gives the job a `name:`
  // override or runs it in a `strategy.matrix` gets a displayed name that
  // diverges from the id, and the equality below would then never match,
  // silently defeating self-exclusion (CodeRabbit PR7 #6YXkRF). The caller
  // (readLivePrState) resolves the TRUE displayed name via the Jobs API
  // (resolveCurrentJobDisplayName) and passes it as selfJobDisplayName when
  // available; fall back to GITHUB_JOB — the exact prior behavior — when it
  // is not (API unavailable, older/local invocation, or dispatch without a
  // resolvable run id).
  //
  // The `selfJobDisplayName === false` sentinel (a detected in-run name
  // collision) is resolved via the shared resolveSelfJobName helper — see
  // its own doc comment above for why it must not fall back to GITHUB_JOB.
  const selfWorkflowName = process.env.GITHUB_WORKFLOW || null;
  const selfJobName = resolveSelfJobName(selfJobDisplayName);
  const checks = Array.isArray(pr.statusCheckRollup) ? pr.statusCheckRollup.map(normalizeCheck) : [];
  // Recorded BEFORE self-exclusion so a rollup that legitimately contained
  // ONLY this job's own check (chatgpt-codex-connector PR7 #6Yb3lX, P2) can be
  // told apart from GitHub genuinely returning no live check data at all — see
  // the `!liveCheckCount` guard below, which reads this instead of the
  // post-exclusion `checks.length`.
  const liveCheckCount = checks.length;
  if (selfWorkflowName && selfJobName) {
    // This match is on the DISPLAYED workflow name and job name only — the
    // same two strings GITHUB_WORKFLOW/the resolved display name always
    // were. In isolation, a repository with a SECOND, unrelated workflow
    // FILE whose top-level `name:` happens to equal GITHUB_WORKFLOW and
    // whose job happens to resolve to the identical displayed name would
    // have every check that OTHER workflow ever produces — including a
    // genuine completed FAILURE — also match and be silently excluded here.
    //
    // Closed by the caller, not by widening this filter (chatgpt-codex-
    // connector PR7 #6Yb44Si, complete fix): readLivePrState resolves this
    // run's own workflow FILE path (`repos/{repo}/actions/runs/{runId}`'s
    // `path` field — a different endpoint/field from the Jobs API call
    // resolveCurrentJobDisplayName makes) and, via
    // detectCrossWorkflowSelfExclusionCollision, checks whether any OTHER
    // run id sharing this exact displayed name resolves to a different
    // path. On a confirmed or unresolvable mismatch it passes
    // `selfJobDisplayName: false` into this function — the same tested
    // sentinel `resolveCurrentJobDisplayName` already returns for an
    // in-run collision — disabling self-exclusion entirely for that call.
    // This filter itself stays purely name-based and synchronous; a caller
    // that skips the collision check (a direct unit test, or a future
    // caller) still has the raw limitation described above.
    //
    // Practical bound on the actual risk in the meantime: creating that
    // colliding workflow file requires the SAME same-repo write-level trust
    // this gate already extensively documents and accepts elsewhere (see
    // `KNOWN LIMITATION #6YaxWT` above `uses: ./actions/closeout` in
    // closeout-gate.yml) — an untrusted fork PR cannot introduce a new
    // workflow file that runs without maintainer approval first, and a
    // repository that already has two identically-displayed-named gate
    // workflows is a pre-existing, self-inflicted configuration choice, not
    // something this finding alone lets a PR create from nothing.
    const filtered = checks.filter((check) => !(
      check.workflowName === selfWorkflowName
      && check.name === selfJobName
    ));
    checks.length = 0;
    checks.push(...filtered);
  }
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
  // liveCheckCount (pre-self-exclusion), not checks.length: a consumer that
  // installs ONLY this gate as their CI has a rollup that legitimately
  // contains nothing but this job's own (always in-progress, always
  // excluded) check — checks.length would then be 0 forever and this
  // BLOCKED reason could never clear, even though GitHub genuinely returned
  // live data (chatgpt-codex-connector PR7 #6Yb3lX). This still blocks
  // fail-closed on a truly empty/malformed rollup: liveCheckCount is 0 in
  // that case too, since it is captured before self-exclusion ever runs.
  if (!liveCheckCount) blockers.push('No live GitHub check results were returned.');
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
  // Collect the unique set of non-authoritative reviewers who left an
  // attestation-shaped review, BEFORE issuing any network call. GitHub's
  // collaborators/permission endpoint is per-user (no batch API), so the prior
  // sequential await loop was an N+1: one gh api call per reviewer, one after
  // another. Issue them with bounded concurrency instead — each distinct
  // reviewer is still queried exactly once (dedup is resolved upfront), and a
  // hard cap keeps the request fan-out small even on a PR with many reviews.
  const reviewerPermissions = new Map();
  const seen = new Set();
  const pending = [];
  for (const review of reviews) {
    if (!reviewMatchesAttestationShape({ review, prAuthor, expectedHeadSha, marker })) continue;
    const reviewer = review.user.login;
    const association = String(review.author_association || review.authorAssociation || '').toUpperCase();
    if (AUTHORITATIVE_ASSOCIATIONS.has(association)) continue;
    const key = reviewer.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    pending.push(reviewer);
  }
  const PERMISSION_CONCURRENCY = 4;
  const lookupPermission = async (reviewer) => {
    try {
      const permission = await runGh([
        'api',
        `repos/${repository}/collaborators/${encodeURIComponent(reviewer)}/permission`,
      ], { repo });
      reviewerPermissions.set(reviewer.toLowerCase(), permission);
    } catch {
      reviewerPermissions.set(reviewer.toLowerCase(), null);
    }
  };
  for (let i = 0; i < pending.length; i += PERMISSION_CONCURRENCY) {
    await Promise.all(pending.slice(i, i + PERMISSION_CONCURRENCY).map(lookupPermission));
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
    const attestation = await readGateAttestationForPr({
      repo,
      repository,
      pr,
      expectedBaseSha,
      expectedHeadSha,
      expectedConfigDigest,
      runGh,
    });
    // readGateAttestationForPr's own reviews + reviewer-permission requests
    // (paginated, potentially several round-trips) run AFTER the head/base
    // check above, with no recheck afterward — a push, force-push, or rebase
    // landing while those requests are in flight would leave `attestation`
    // computed from the now-stale `pr` snapshot, and this function would
    // still return it as current (chatgpt-codex-connector PR7 #6Yb44Ss).
    // Unlike readLivePrState's live-state path, this function's callers
    // (plan-mode admission, and the full run's early pre-check) treat this
    // result as authoritative on its own within their own scope, so the
    // same re-verification discipline applies here too. Re-read only the
    // cheap head/base identity, not the full review/permission set again —
    // an attestation computed against a snapshot that has since moved is
    // unsafe regardless of what it concluded.
    const revalidated = await runGh(['pr', 'view', '--json', 'headRefOid,baseRefOid'], { repo });
    if (revalidated.headRefOid !== pr.headRefOid || revalidated.baseRefOid !== pr.baseRefOid) {
      return {
        provider: 'github-pull-request-review',
        status: 'BLOCKED',
        baseSha: expectedBaseSha,
        headSha: expectedHeadSha,
        configDigest: expectedConfigDigest,
        evidence: 'Live GitHub PR head or base changed while reading reviews and reviewer permissions; admission attestation is bound to a snapshot that is no longer current.',
      };
    }
    return attestation;
  } catch (error) {
    return {
      provider: 'github-pull-request-review',
      status: 'BLOCKED',
      // Machine-readable discriminator for the plan-mode admission mapping
      // (spec: "Plan-mode admission readiness"): this is the ONLY path that
      // means the read itself could not complete (gh missing, unauthenticated,
      // network failure) rather than a clean snapshot-reasoned BLOCKED (no
      // matching review, or the PR head/base moved) — additive field, every
      // other return path in this function carries no `reason`.
      reason: 'unavailable',
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
    // Resolved here, BEFORE any PR/review/thread snapshot is taken — not
    // right before the final classifyLivePrState call (chatgpt-codex-
    // connector PR7 #6YaIas). This call has its own network latency (up to
    // the gh timeout) and depends only on `repository`, not on any PR
    // state, so placing it before every stability-tuple round below means
    // its latency is already covered by the SAME re-verification chain that
    // protects every other network round-trip in this function — a PR/
    // review/thread/check change during this call is caught exactly like a
    // change during the thread walk or any other read. Placed after it
    // (the original position, right before classifyLivePrState), its
    // latency opened the one window in this function with NO subsequent
    // stability recheck: `postThreadPr` could go stale while this call was
    // in flight and still be classified as current.
    const selfJobDisplayName = await resolveCurrentJobDisplayName({ repository, runGh, repo });
    // Resolved here too (best-effort, alongside selfJobDisplayName) so its
    // own network latency is likewise covered by the stability re-checks
    // below rather than opening a fresh unverified window right before
    // classification — see detectCrossWorkflowSelfExclusionCollision.
    const selfWorkflowPath = await resolveWorkflowRunPath({
      repository, runGh, repo, runId: process.env.GITHUB_RUN_ID,
    });
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
    // Mirror the author-identity guard used for pr/finalPr/terminalPr so a
    // response without author.login cannot reach classifyLivePrState (where
    // self-approval exclusion depends on a real author identity).
    if (typeof postThreadPr.author?.login !== 'string' || !postThreadPr.author.login.trim()) {
      throw new Error('GitHub did not return a post-thread pull request author identity.');
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
    // postThreadUnresolvedThreads is itself another paginated network window
    // (chatgpt-codex-connector PR7 #Yb3lQ, review 4912448810). Everything
    // above re-verifies PR/review/attestation stability across every window
    // BEFORE this final thread request, but nothing yet re-checks them across
    // this request's OWN window — an attesting reviewer's repository
    // permission revoked while it was in flight would leave postThreadGateSnapshot
    // (captured before it started) still holding the earlier authoritative
    // permission, with no event here to ever invalidate that stale PASS. Take
    // one more PR + attestation snapshot and require it to match
    // postThreadGateSnapshot before publishing the verdict.
    const verifiedPr = await runGh([
      'pr',
      'view',
      '--json',
      PR_VIEW_FIELDS,
    ], { repo });
    if (!Number.isInteger(verifiedPr.number)) throw new Error('GitHub did not return a verified pull request number.');
    if (typeof verifiedPr.author?.login !== 'string' || !verifiedPr.author.login.trim()) {
      throw new Error('GitHub did not return a verified pull request author identity.');
    }
    const verifiedGateSnapshot = await readGateAttestationSnapshotForPr({
      repo,
      repository,
      pr: verifiedPr,
      expectedBaseSha,
      expectedHeadSha,
      expectedConfigDigest,
      runGh,
    });
    const verifiedPrStable = stabilityTuplesMatch(
      capturePrStabilityTuple(postThreadPr),
      capturePrStabilityTuple(verifiedPr),
    );
    const verifiedReviewsStable = stabilityTuplesMatch(
      postThreadGateSnapshot.stabilityTuple,
      verifiedGateSnapshot.stabilityTuple,
    );
    if (!verifiedPrStable || !verifiedReviewsStable) {
      return {
        status: 'BLOCKED',
        evidence: 'Live GitHub PR or review/attestation state changed during the final thread-request verification window; rerun against a stable remote snapshot.',
        repository,
        number: verifiedPr.number,
        checks: [],
        unresolvedThreads: postThreadUnresolvedThreads,
        externalServices: [],
        gateAttestation: verifiedGateSnapshot.attestation,
      };
    }
    // postThreadUnresolvedThreads was fetched BEFORE verifiedPr and
    // verifiedGateSnapshot (CodeRabbit PR7 #6Yb44Se): a thread reopened
    // during either of those two requests would leave classification below
    // using a stale, already-resolved-looking thread list, letting a PASS
    // publish even though a genuinely unresolved thread now exists. Re-read
    // threads once more and require an identical set before publishing.
    const verifiedUnresolvedThreads = await readUnresolvedReviewThreads({
      repo, owner, name, number: verifiedPr.number, runGh,
    });
    if (threadTuple(postThreadUnresolvedThreads) !== threadTuple(verifiedUnresolvedThreads)) {
      return {
        status: 'BLOCKED',
        evidence: 'Live GitHub review threads changed during the final PR/attestation verification window; rerun against a stable remote snapshot.',
        repository,
        number: verifiedPr.number,
        checks: [],
        unresolvedThreads: verifiedUnresolvedThreads,
        externalServices: [],
        gateAttestation: verifiedGateSnapshot.attestation,
      };
    }
    // selfJobDisplayName was resolved near the top of this function (see the
    // comment there) — best-effort: resolves to null (falling back to
    // GITHUB_JOB inside classifyLivePrState, the exact prior behavior) on
    // any failure. Checked once more, right here against the final verified
    // rollup, for a genuine cross-workflow collision (#6Yb44Si) — a second
    // workflow file rendering this job's exact displayed name. Detecting one
    // overrides to `false`, the existing tested sentinel that disables
    // self-exclusion entirely inside classifyLivePrState, without changing
    // that function at all.
    const { collision: selfExclusionCollision, networkCallsMade: collisionCheckMadeNetworkCalls } = (
      await detectCrossWorkflowSelfExclusionCollision({
        pr: verifiedPr,
        selfWorkflowName: process.env.GITHUB_WORKFLOW || null,
        selfJobName: resolveSelfJobName(selfJobDisplayName),
        selfWorkflowPath,
        repository,
        runGh,
        repo,
      })
    );
    let classifiedPr = verifiedPr;
    let classifiedGateSnapshot = verifiedGateSnapshot;
    let classifiedUnresolvedThreads = verifiedUnresolvedThreads;
    if (collisionCheckMadeNetworkCalls) {
      // detectCrossWorkflowSelfExclusionCollision's own resolveWorkflowRunPath
      // request(s) are live `gh api` calls made AFTER verifiedPr/
      // verifiedGateSnapshot/verifiedUnresolvedThreads were captured, with no
      // subsequent stability recheck — the same class of window every other
      // network round-trip in this function is already re-verified for
      // (CodeRabbit PR7 #6Yb44So). Only paid for when it actually fired
      // (networkCallsMade), which is rare — see detectCrossWorkflowSelfExclusionCollision's
      // own doc comment on why the common case makes zero requests.
      const postCollisionCheckPr = await runGh(['pr', 'view', '--json', PR_VIEW_FIELDS], { repo });
      const postCollisionCheckGateSnapshot = await readGateAttestationSnapshotForPr({
        repo,
        repository,
        pr: postCollisionCheckPr,
        expectedBaseSha,
        expectedHeadSha,
        expectedConfigDigest,
        runGh,
      });
      const postCollisionCheckStable = stabilityTuplesMatch(
        capturePrStabilityTuple(verifiedPr),
        capturePrStabilityTuple(postCollisionCheckPr),
      ) && stabilityTuplesMatch(
        verifiedGateSnapshot.stabilityTuple,
        postCollisionCheckGateSnapshot.stabilityTuple,
      );
      if (!postCollisionCheckStable) {
        return {
          status: 'BLOCKED',
          evidence: 'Live GitHub PR or review/attestation state changed during the cross-workflow collision verification window; rerun against a stable remote snapshot.',
          repository,
          number: postCollisionCheckPr.number,
          checks: [],
          unresolvedThreads: verifiedUnresolvedThreads,
          externalServices: [],
          gateAttestation: postCollisionCheckGateSnapshot.attestation,
        };
      }
      const postCollisionCheckUnresolvedThreads = await readUnresolvedReviewThreads({
        repo, owner, name, number: postCollisionCheckPr.number, runGh,
      });
      if (threadTuple(verifiedUnresolvedThreads) !== threadTuple(postCollisionCheckUnresolvedThreads)) {
        return {
          status: 'BLOCKED',
          evidence: 'Live GitHub review threads changed during the cross-workflow collision verification window; rerun against a stable remote snapshot.',
          repository,
          number: postCollisionCheckPr.number,
          checks: [],
          unresolvedThreads: postCollisionCheckUnresolvedThreads,
          externalServices: [],
          gateAttestation: postCollisionCheckGateSnapshot.attestation,
        };
      }
      classifiedPr = postCollisionCheckPr;
      classifiedGateSnapshot = postCollisionCheckGateSnapshot;
      classifiedUnresolvedThreads = postCollisionCheckUnresolvedThreads;
    }
    return classifyLivePrState({
      repository,
      pr: classifiedPr,
      unresolvedThreads: classifiedUnresolvedThreads,
      expectedHeadSha,
      expectedBaseSha,
      gateAttestation: classifiedGateSnapshot.attestation,
      selfJobDisplayName: selfExclusionCollision ? false : selfJobDisplayName,
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
  acquireDelegatedGhToken,
  buildGhArgs,
  classifyGateAttestation,
  classifyLivePrState,
  defaultRunGh,
  revokeDelegatedGhToken,
  detectCrossWorkflowSelfExclusionCollision,
  gateAttestationMarker,
  readActionsPrNumber,
  readLiveGateAttestation,
  readLivePrState,
  readReviewerPermissions,
  resolveCurrentJobDisplayName,
  resolveWorkflowRunPath,
};
