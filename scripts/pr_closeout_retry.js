const { defaultRunGh } = require('./pr_closeout_github');

// The gate workflow's own file PATH, not its displayed name — matching by
// path (like resolveWorkflowRunPath/detectCrossWorkflowSelfExclusionCollision
// elsewhere in this action) avoids the exact class of display-name-collision
// bug this session repeatedly found and fixed in scripts/pr_closeout_github.js.
const GATE_WORKFLOW_PATH = '.github/workflows/closeout-gate.yml';

/**
 * Find the most recent Actions run of the closeout gate workflow at a given
 * commit SHA. Used to locate the run whose SHA-association is correct (it
 * was triggered by a real `pull_request`/`pull_request_review` event on that
 * exact head) so it can be asked to re-run, rather than relying on a NEW
 * `workflow_run`-triggered run whose own implicit check-run would attach to
 * the wrong commit (chatgpt-codex-connector PR7 #6YaxWe).
 *
 * Filters on the run's `path` field (the workflow FILE), not its displayed
 * `name` — a repository could in principle have a second workflow whose
 * `name:` happens to render identically; the file path is what actually
 * identifies "the same workflow definition".
 * @param {object} options
 * @param {string} [options.repository] - `owner/repo`.
 * @param {string} [options.headSha]
 * @param {Function} [options.runGh]
 * @param {string} [options.repo] - path passed as `--repo`/cwd to `gh`.
 * @param {string} [options.workflowPath]
 * @returns {Promise<object|null>} the most recent matching run, or null.
 */
const findMostRecentGateRun = async ({
  repository,
  headSha,
  runGh = defaultRunGh,
  repo,
  workflowPath = GATE_WORKFLOW_PATH,
} = {}) => {
  if (!repository || !headSha || typeof runGh !== 'function') return null;
  const response = await runGh(['api', `repos/${repository}/actions/runs?head_sha=${headSha}&per_page=50`], { repo });
  const runs = Array.isArray(response?.workflow_runs) ? response.workflow_runs : [];
  const matching = runs.filter((run) => run?.path === workflowPath);
  if (!matching.length) return null;
  // Highest run_number is the most recent — GitHub assigns these
  // monotonically per workflow, unlike `id` (global, not workflow-scoped,
  // but also monotonic in practice; run_number is the documented ordering
  // field for "which run of THIS workflow came later").
  matching.sort((left, right) => (right?.run_number ?? 0) - (left?.run_number ?? 0));
  return matching[0];
};

/**
 * Ask GitHub to re-run an already-completed Actions run. The re-run executes
 * as a new ATTEMPT of the SAME run, under the run's ORIGINAL trigger event
 * context (e.g. `pull_request_review`) — so its implicit check-run is
 * correctly SHA-associated with the PR head by GitHub itself, unlike a fresh
 * `workflow_run`-triggered execution of the gate job (which is bound to
 * `workflow_run`'s own trigger context, not the sibling's PR head).
 *
 * The GitHub API returns 204 No Content on success (defaultRunGh returns
 * `null` for that; see its own comment). Never throws: a failed rerun
 * request is reported in the return value, not raised, so a caller looping
 * over multiple PRs (readMostRecentGateRun's caller in the base-branch-drift
 * path) can continue past one failure instead of aborting the whole batch.
 * @param {object} options
 * @param {string} [options.repository]
 * @param {number|string} [options.runId]
 * @param {Function} [options.runGh]
 * @param {string} [options.repo]
 * @returns {Promise<{ok: boolean, error?: string}>}
 */
const rerunGateRun = async ({ repository, runId, runGh = defaultRunGh, repo } = {}) => {
  if (!repository || !runId || typeof runGh !== 'function') {
    return { ok: false, error: 'Missing repository, run id, or GitHub client.' };
  }
  try {
    await runGh(['api', '--method', 'POST', `repos/${repository}/actions/runs/${runId}/rerun`], { repo });
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error.message };
  }
};

/**
 * Find and, if eligible, re-run the closeout gate's most recent run at a PR
 * head — the "retry forwarder" (chatgpt-codex-connector PR7 #6YaxWe). Never
 * throws: every branch (missing input, no prior run, run still in flight,
 * already succeeded, rerun request failure) resolves to a described
 * `{action, reason}` result rather than raising, so a caller processing many
 * PRs (the base-branch-drift path) can log and continue.
 *
 * Eligibility, in order:
 *   - No prior gate run at this head at all → skip (a normal `pull_request`
 *     trigger will run the gate naturally once there is real PR activity).
 *   - Most recent run not yet `completed` → skip (rerunning is invalid via
 *     the API while a run is in flight, and it will produce a correctly-
 *     associated result on its own once it finishes).
 *   - Most recent run's conclusion is already `success` → skip (nothing to
 *     recover).
 *   - Otherwise → rerun it.
 * @param {object} options
 * @param {string} [options.repository]
 * @param {string} [options.headSha]
 * @param {Function} [options.runGh]
 * @param {string} [options.repo]
 * @param {string} [options.workflowPath]
 * @returns {Promise<{action: 'rerun-triggered'|'skipped', reason: string, runId?: number}>}
 */
const forwardGateRetry = async ({
  repository,
  headSha,
  runGh = defaultRunGh,
  repo,
  workflowPath = GATE_WORKFLOW_PATH,
} = {}) => {
  if (!repository || !headSha || typeof runGh !== 'function') {
    return { action: 'skipped', reason: 'Missing repository, head SHA, or GitHub client.' };
  }
  let run;
  try {
    run = await findMostRecentGateRun({ repository, headSha, runGh, repo, workflowPath });
  } catch (error) {
    return { action: 'skipped', reason: `Could not list Actions runs: ${error.message}` };
  }
  if (!run) {
    return { action: 'skipped', reason: `No prior ${workflowPath} run found at head ${headSha}.` };
  }
  if (run.status !== 'completed') {
    return {
      action: 'skipped',
      reason: `Most recent gate run (#${run.run_number}, id ${run.id}) is still "${run.status}"; letting it finish naturally.`,
      runId: run.id,
    };
  }
  if (run.conclusion === 'success') {
    return {
      action: 'skipped',
      reason: `Most recent gate run (#${run.run_number}, id ${run.id}) already succeeded.`,
      runId: run.id,
    };
  }
  const rerun = await rerunGateRun({ repository, runId: run.id, runGh, repo });
  if (!rerun.ok) {
    return {
      action: 'skipped',
      reason: `Rerun request for run #${run.run_number} (id ${run.id}) failed: ${rerun.error}`,
      runId: run.id,
    };
  }
  return {
    action: 'rerun-triggered',
    reason: `Reran gate run #${run.run_number} (id ${run.id}), previously concluded "${run.conclusion}".`,
    runId: run.id,
  };
};

/**
 * List every OPEN pull request targeting a given base branch. Used by the
 * base-branch-drift path (chatgpt-codex-connector PR7 #6YbMwY): nothing in
 * this repository's triggers fires from a push to the base branch alone, so
 * this discovers the affected PRs a `push` event's own payload never names.
 * @param {object} options
 * @param {string} [options.repository]
 * @param {string} [options.baseRef] - branch name (no `refs/heads/` prefix).
 * @param {Function} [options.runGh]
 * @param {string} [options.repo]
 * @returns {Promise<Array<{number: number, headRefOid: string}>>}
 */
const discoverOpenPullRequests = async ({ repository, baseRef, runGh = defaultRunGh, repo } = {}) => {
  if (!repository || !baseRef || typeof runGh !== 'function') return [];
  const response = await runGh([
    'pr', 'list',
    '--repo', repository,
    '--base', baseRef,
    '--state', 'open',
    '--json', 'number,headRefOid',
    '--limit', '100',
  ], { repo });
  return Array.isArray(response)
    ? response.filter((pr) => Number.isInteger(pr?.number) && typeof pr?.headRefOid === 'string' && pr.headRefOid)
    : [];
};

/**
 * Re-verify the gate for every open PR targeting `baseRef` after a push to
 * that branch — one job classifying every affected PR, per the repository
 * owner's chosen design (restructure into a single job rather than one
 * `workflow_dispatch` per PR). Processes PRs SEQUENTIALLY, not in parallel:
 * this runs against every open PR on every push to a shared base branch, and
 * each iteration is already a real Actions API write (a rerun dispatch) —
 * bounding concurrency here bounds the worst-case API load on a repository
 * with many open PRs against one branch, at the cost of wall-clock time this
 * job (which does no PR-code execution itself) can afford to spend. A single
 * PR's failure (a transient API error, a PR that closed between listing and
 * processing) does not stop the batch — every result is collected, not
 * thrown.
 * @param {object} options
 * @param {string} [options.repository]
 * @param {string} [options.baseRef]
 * @param {Function} [options.runGh]
 * @param {string} [options.repo]
 * @param {string} [options.workflowPath]
 * @returns {Promise<Array<{number: number, headRefOid: string, action: string, reason: string, runId?: number}>>}
 */
const forwardGateRetriesForBase = async ({
  repository,
  baseRef,
  runGh = defaultRunGh,
  repo,
  workflowPath = GATE_WORKFLOW_PATH,
} = {}) => {
  if (!repository || !baseRef || typeof runGh !== 'function') return [];
  let pullRequests;
  try {
    pullRequests = await discoverOpenPullRequests({ repository, baseRef, runGh, repo });
  } catch (error) {
    return [{ number: null, headRefOid: null, action: 'skipped', reason: `Could not list open pull requests targeting ${baseRef}: ${error.message}` }];
  }
  const results = [];
  for (const pr of pullRequests) {
    let outcome;
    try {
      outcome = await forwardGateRetry({ repository, headSha: pr.headRefOid, runGh, repo, workflowPath });
    } catch (error) {
      outcome = { action: 'skipped', reason: `Unexpected error: ${error.message}` };
    }
    results.push({ number: pr.number, headRefOid: pr.headRefOid, ...outcome });
  }
  return results;
};

module.exports = {
  GATE_WORKFLOW_PATH,
  discoverOpenPullRequests,
  findMostRecentGateRun,
  forwardGateRetriesForBase,
  forwardGateRetry,
  rerunGateRun,
};
