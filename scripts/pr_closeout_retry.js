const { defaultRunGh } = require('./pr_closeout_github');
const { redactSecrets } = require('./pr_closeout_process');

/**
 * Renders a caught error's message for inclusion in a returned result.
 *
 * Every `reason`/`error` string this module produces is JSON-serialized to
 * stdout by scripts/gate_retry_cli.js, i.e. straight into the workflow log,
 * which is world-readable for a public repository. A `gh` failure message is
 * not a controlled string: it can echo the request URL (a token-bearing
 * remote, a credential-embedded proxy URL) or a raw API error body. Passing
 * it through the gate's own redactor before it can reach a log closes that
 * path (CodeRabbit PR7 #6YjkMb) — the same discipline
 * scripts/pr_closeout_process.js already applies to every command's captured
 * output, reused here rather than reinvented.
 *
 * Also normalizes a non-Error throw (a rejected string, a thrown object) to
 * a useful string instead of `undefined`, which is what reading `.message`
 * off a non-Error would otherwise produce.
 *
 * This function must NEVER throw, because every caller is on a path whose
 * whole contract is "report the failure, do not raise" — a throw here would
 * turn a described `skipped` result back into a rejected promise and abort a
 * multi-PR batch (CodeRabbit PR7 #6Ys0fU). Both remaining hazards are handled
 * explicitly: `JSON.stringify` throws on a circular object, and `String()`
 * throws on a Symbol while `JSON.stringify` returns undefined for a BigInt.
 * Each falls back to a fixed, non-informative label rather than propagating.
 * @param {unknown} error
 * @returns {string}
 */
const describeError = (error) => {
  let message;
  try {
    if (error instanceof Error) message = error.message;
    else if (typeof error === 'string') message = error;
    else message = JSON.stringify(error) ?? String(error);
  } catch {
    // Circular structure, a BigInt, a Symbol, or a throwing toString/toJSON.
    message = '(unserializable error value)';
  }
  try {
    return redactSecrets(String(message ?? ''));
  } catch {
    return '(unserializable error value)';
  }
};

// The gate workflow's own file PATH, not its displayed name — matching by
// path (like resolveWorkflowRunPath/detectCrossWorkflowSelfExclusionCollision
// elsewhere in this action) avoids the exact class of display-name-collision
// bug this session repeatedly found and fixed in scripts/pr_closeout_github.js.
const GATE_WORKFLOW_PATH = '.github/workflows/closeout-gate.yml';

/**
 * True when an Actions run's reported `path` names this workflow file.
 *
 * A run's `path` is normally the bare in-repo file path, but GitHub also
 * reports the `<path>@<ref>` form (the shape used for a workflow referenced
 * at a specific ref) — a strict `===` misses those runs entirely and the
 * caller then reports "no prior run" and skips a retry that existed
 * (CodeRabbit PR7 #6YjkMO). Matching the bare path OR the `path@ref` prefix
 * covers both without loosening into a substring match: the `@` boundary is
 * required, so `.github/workflows/closeout-gate.yml.bak` and
 * `other/closeout-gate.yml` still do not match.
 *
 * Honest scope note: this is defensive normalization. The `@ref` form is
 * documented for referenced/reusable workflows; whether the plain
 * `GET /repos/{repo}/actions/runs` listing this module uses ever emits it
 * for a repository's own workflow could not be confirmed from here. The
 * handling is strictly more permissive along one exact axis, so it cannot
 * break the bare-path case that is known to work.
 * @param {unknown} runPath
 * @param {string} workflowPath
 * @returns {boolean}
 */
const matchesWorkflowPath = (runPath, workflowPath) => {
  if (typeof runPath !== 'string' || !workflowPath) return false;
  return runPath === workflowPath || runPath.startsWith(`${workflowPath}@`);
};

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
  // --paginate follows Link headers to the end rather than silently stopping
  // at the first page (CodeRabbit PR7 #6YjkMG): a busy PR head can carry more
  // than one page of runs across all workflows, and the gate's own run is not
  // guaranteed to be among the newest — a truncated list would make this
  // return null and skip a retry that was in fact available. `gh api
  // --paginate --slurp` returns an ARRAY of page objects, so the pages are
  // flattened back into one run list here.
  const response = await runGh([
    'api', '--paginate', '--slurp',
    `repos/${repository}/actions/runs?head_sha=${encodeURIComponent(headSha)}&per_page=100`,
  ], { repo });
  const pages = Array.isArray(response) ? response : [response];
  const runs = pages.flatMap((page) => (Array.isArray(page?.workflow_runs) ? page.workflow_runs : []));
  const matching = runs.filter((run) => matchesWorkflowPath(run?.path, workflowPath));
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
    return { ok: false, error: describeError(error) };
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
    return { action: 'skipped', reason: `Could not list Actions runs: ${describeError(error)}` };
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
 *
 * `gh pr list` caps at `--limit` and pages internally up to it, exposing no
 * total — so a cap silently TRUNCATES on a busy base branch, and the PRs
 * dropped are exactly the ones that would go un-re-verified, the failure this
 * whole mechanism exists to prevent (CodeRabbit PR7 #6YjkMG). The limit is
 * therefore raised well past any plausible open-PR count against one branch,
 * and — because a silent cap is the actual hazard — hitting it is REPORTED by
 * the caller rather than passing unnoticed (see forwardGateRetriesForBase),
 * per this repo's "no silent truncation" rule.
 * @param {object} options
 * @param {string} [options.repository]
 * @param {string} [options.baseRef] - branch name (no `refs/heads/` prefix).
 * @param {Function} [options.runGh]
 * @param {string} [options.repo]
 * @param {number} [options.limit]
 * @returns {Promise<Array<{number: number, headRefOid: string}>>}
 */
const PR_DISCOVERY_LIMIT = 1000;

const discoverOpenPullRequests = async ({
  repository, baseRef, runGh = defaultRunGh, repo, limit = PR_DISCOVERY_LIMIT,
} = {}) => {
  if (!repository || !baseRef || typeof runGh !== 'function') return [];
  const response = await runGh([
    'pr', 'list',
    '--repo', repository,
    '--base', baseRef,
    '--state', 'open',
    '--json', 'number,headRefOid',
    '--limit', String(limit),
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
    return [{ number: null, headRefOid: null, action: 'skipped', reason: `Could not list open pull requests targeting ${baseRef}: ${describeError(error)}` }];
  }
  const results = [];
  // A full page means discovery may have TRUNCATED, and the PRs it dropped
  // are precisely the ones that would silently go un-re-verified. Surface it
  // as a result entry rather than letting a capped list read as "these are
  // all the affected PRs" (CodeRabbit PR7 #6YjkMG).
  if (pullRequests.length >= PR_DISCOVERY_LIMIT) {
    results.push({
      number: null,
      headRefOid: null,
      action: 'skipped',
      reason: `Open-PR discovery for ${baseRef} returned the full limit of ${PR_DISCOVERY_LIMIT}; some open PRs targeting this branch may not have been re-verified.`,
    });
  }
  for (const pr of pullRequests) {
    let outcome;
    try {
      outcome = await forwardGateRetry({ repository, headSha: pr.headRefOid, runGh, repo, workflowPath });
    } catch (error) {
      outcome = { action: 'skipped', reason: `Unexpected error: ${describeError(error)}` };
    }
    results.push({ number: pr.number, headRefOid: pr.headRefOid, ...outcome });
  }
  return results;
};

module.exports = {
  GATE_WORKFLOW_PATH,
  PR_DISCOVERY_LIMIT,
  describeError,
  discoverOpenPullRequests,
  findMostRecentGateRun,
  forwardGateRetriesForBase,
  forwardGateRetry,
  matchesWorkflowPath,
  rerunGateRun,
};
