const assert = require('node:assert/strict');
const test = require('node:test');

const {
  GATE_WORKFLOW_PATH,
  PR_DISCOVERY_LIMIT,
  describeError,
  discoverOpenPullRequests,
  findMostRecentGateRun,
  forwardGateRetriesForBase,
  forwardGateRetry,
  matchesWorkflowPath,
  rerunGateRun,
} = require('./pr_closeout_retry');

const gateRun = (extra = {}) => ({
  id: 111,
  run_number: 5,
  path: GATE_WORKFLOW_PATH,
  status: 'completed',
  conclusion: 'failure',
  ...extra,
});

test('findMostRecentGateRun returns null on missing inputs without calling runGh', async () => {
  let calls = 0;
  const runGh = async () => { calls += 1; return {}; };
  assert.equal(await findMostRecentGateRun({ headSha: 'abc', runGh, repo: 'C:/repo' }), null, 'missing repository');
  assert.equal(await findMostRecentGateRun({ repository: 'o/r', runGh, repo: 'C:/repo' }), null, 'missing headSha');
  assert.equal(await findMostRecentGateRun({ repository: 'o/r', headSha: 'abc', runGh: null, repo: 'C:/repo' }), null, 'missing runGh');
  assert.equal(calls, 0);
});

test('findMostRecentGateRun filters by workflow path and picks the highest run_number', async () => {
  const calls = [];
  const runGh = async (args) => {
    calls.push(args);
    return [{
      workflow_runs: [
        gateRun({ id: 1, run_number: 3 }),
        { id: 2, run_number: 9, path: '.github/workflows/validate.yml', status: 'completed', conclusion: 'success' },
        gateRun({ id: 3, run_number: 7 }),
      ],
    }];
  };
  const run = await findMostRecentGateRun({ repository: 'owner/repo', headSha: 'abc123', runGh, repo: 'C:/repo' });
  assert.equal(run.id, 3);
  assert.equal(run.run_number, 7);
  assert.deepEqual(calls, [[
    'api', '--paginate', '--slurp', 'repos/owner/repo/actions/runs?head_sha=abc123&per_page=100',
  ]], 'discovery must paginate rather than silently stop at one page (CodeRabbit PR7 #6YjkMG)');
});

test('findMostRecentGateRun flattens every page, not just the first (CodeRabbit PR7 #6YjkMG)', async () => {
  // `gh api --paginate --slurp` returns an ARRAY of page objects. A run on a
  // later page must still be found — truncating here would report "no prior
  // run" and skip a retry that existed.
  const runGh = async () => ([
    { workflow_runs: [{ id: 1, run_number: 2, path: '.github/workflows/validate.yml', status: 'completed', conclusion: 'success' }] },
    { workflow_runs: [gateRun({ id: 42, run_number: 11 })] },
  ]);
  const run = await findMostRecentGateRun({ repository: 'owner/repo', headSha: 'abc123', runGh, repo: 'C:/repo' });
  assert.equal(run.id, 42, 'a gate run on the second page must still be found');
});

test('findMostRecentGateRun matches the API-shaped path@ref form (CodeRabbit PR7 #6YjkMO)', async () => {
  const runGh = async () => ([{ workflow_runs: [gateRun({ id: 7, path: `${GATE_WORKFLOW_PATH}@refs/heads/main` })] }]);
  const run = await findMostRecentGateRun({ repository: 'owner/repo', headSha: 'abc', runGh, repo: 'C:/repo' });
  assert.equal(run?.id, 7, 'a `<path>@<ref>` run path must not be missed by a strict equality match');
});

test('matchesWorkflowPath accepts the bare path and path@ref, and nothing looser', () => {
  assert.equal(matchesWorkflowPath(GATE_WORKFLOW_PATH, GATE_WORKFLOW_PATH), true);
  assert.equal(matchesWorkflowPath(`${GATE_WORKFLOW_PATH}@main`, GATE_WORKFLOW_PATH), true);
  assert.equal(matchesWorkflowPath(`${GATE_WORKFLOW_PATH}@refs/heads/x`, GATE_WORKFLOW_PATH), true);
  // The `@` boundary is required, so these near-misses must NOT match.
  assert.equal(matchesWorkflowPath(`${GATE_WORKFLOW_PATH}.bak`, GATE_WORKFLOW_PATH), false);
  assert.equal(matchesWorkflowPath(`other/${GATE_WORKFLOW_PATH}`, GATE_WORKFLOW_PATH), false);
  assert.equal(matchesWorkflowPath('.github/workflows/validate.yml', GATE_WORKFLOW_PATH), false);
  assert.equal(matchesWorkflowPath(undefined, GATE_WORKFLOW_PATH), false);
  assert.equal(matchesWorkflowPath(GATE_WORKFLOW_PATH, ''), false);
});

test('describeError redacts secret values out of a caught diagnostic (CodeRabbit PR7 #6YjkMb)', () => {
  // gate_retry_cli.js JSON-serializes these strings to stdout, i.e. into the
  // workflow log, so a gh diagnostic echoing a token-bearing URL must not
  // survive verbatim.
  const priorToken = process.env.GH_TOKEN;
  process.env.GH_TOKEN = 'SENTINEL-NOT-A-REAL-TOKEN';
  try {
    const redacted = describeError(new Error('HTTP 401 for https://x-access-token:SENTINEL-NOT-A-REAL-TOKEN@github.com/o/r'));
    assert.equal(redacted.includes('SENTINEL-NOT-A-REAL-TOKEN'), false, 'the secret must not survive into a logged reason');
    assert.equal(redacted.includes('[REDACTED]'), true);
  } finally {
    if (priorToken === undefined) delete process.env.GH_TOKEN; else process.env.GH_TOKEN = priorToken;
  }
});

test('describeError normalizes a non-Error throw instead of yielding undefined', () => {
  assert.equal(describeError('plain string failure'), 'plain string failure');
  assert.equal(typeof describeError({ code: 'ENOENT' }), 'string');
  assert.notEqual(describeError({ code: 'ENOENT' }), 'undefined');
});

test('describeError never throws on a non-serializable thrown value (CodeRabbit PR7 #6Ys0fU)', () => {
  // Every caller is on a "report the failure, never raise" path, so a throw
  // here would turn a described skipped result back into a rejected promise
  // and abort a whole multi-PR batch.
  const circular = { code: 'ELOOP' };
  circular.self = circular;
  const throwingToJson = { toJSON() { throw new Error('nope'); } };
  const throwingToString = { toString() { throw new Error('nope'); }, toJSON() { throw new Error('nope'); } };
  for (const value of [circular, 1n, Symbol('boom'), throwingToJson, throwingToString]) {
    let described;
    assert.doesNotThrow(() => { described = describeError(value); }, `describeError must not throw for ${String(typeof value)}`);
    assert.equal(typeof described, 'string');
  }
});

test('forwardGateRetry still returns a skipped result when the thrown value is non-serializable (CodeRabbit PR7 #6Ys0fU)', async () => {
  const circular = { code: 'ELOOP' };
  circular.self = circular;
  const runGh = async () => { throw circular; };
  const result = await forwardGateRetry({ repository: 'owner/repo', headSha: 'abc123', runGh, repo: 'C:/repo' });
  assert.equal(result.action, 'skipped', 'a non-serializable throw must not reject out of forwardGateRetry');
  assert.match(result.reason, /Could not list Actions runs:/);
});

test('findMostRecentGateRun returns null when no run matches the workflow path', async () => {
  const runGh = async () => ({ workflow_runs: [{ id: 1, path: '.github/workflows/validate.yml', status: 'completed', conclusion: 'success' }] });
  assert.equal(await findMostRecentGateRun({ repository: 'owner/repo', headSha: 'abc', runGh, repo: 'C:/repo' }), null);
});

test('findMostRecentGateRun tolerates a malformed (non-array) response', async () => {
  const runGh = async () => ({ not: 'the expected shape' });
  assert.equal(await findMostRecentGateRun({ repository: 'owner/repo', headSha: 'abc', runGh, repo: 'C:/repo' }), null);
});

test('rerunGateRun returns ok:false on missing inputs without calling runGh', async () => {
  let calls = 0;
  const runGh = async () => { calls += 1; };
  assert.deepEqual(await rerunGateRun({ runId: 1, runGh, repo: 'C:/repo' }), { ok: false, error: 'Missing repository, run id, or GitHub client.' });
  assert.deepEqual(await rerunGateRun({ repository: 'o/r', runGh, repo: 'C:/repo' }), { ok: false, error: 'Missing repository, run id, or GitHub client.' });
  assert.equal(calls, 0);
});

test('rerunGateRun posts to the correct rerun endpoint and returns ok:true (tolerating a 204 empty response)', async () => {
  const calls = [];
  const runGh = async (args) => { calls.push(args); return null; };
  const result = await rerunGateRun({ repository: 'owner/repo', runId: 456, runGh, repo: 'C:/repo' });
  assert.deepEqual(result, { ok: true });
  assert.deepEqual(calls, [['api', '--method', 'POST', 'repos/owner/repo/actions/runs/456/rerun']]);
});

test('rerunGateRun reports failure without throwing when the API call rejects', async () => {
  const runGh = async () => { throw new Error('403: Resource not accessible'); };
  const result = await rerunGateRun({ repository: 'owner/repo', runId: 456, runGh, repo: 'C:/repo' });
  assert.deepEqual(result, { ok: false, error: '403: Resource not accessible' });
});

test('forwardGateRetry skips when no prior gate run exists at this head', async () => {
  const runGh = async () => ({ workflow_runs: [] });
  const result = await forwardGateRetry({ repository: 'owner/repo', headSha: 'abc123', runGh, repo: 'C:/repo' });
  assert.equal(result.action, 'skipped');
  assert.match(result.reason, /No prior .* run found/);
});

test('forwardGateRetry skips (does not rerun) when the most recent gate run is still in flight', async () => {
  const runGh = async () => ({ workflow_runs: [gateRun({ status: 'in_progress', conclusion: null })] });
  const result = await forwardGateRetry({ repository: 'owner/repo', headSha: 'abc123', runGh, repo: 'C:/repo' });
  assert.equal(result.action, 'skipped');
  assert.match(result.reason, /still "in_progress"/);
  assert.equal(result.runId, 111);
});

test('forwardGateRetry skips when the most recent gate run already succeeded', async () => {
  const runGh = async () => ({ workflow_runs: [gateRun({ conclusion: 'success' })] });
  const result = await forwardGateRetry({ repository: 'owner/repo', headSha: 'abc123', runGh, repo: 'C:/repo' });
  assert.equal(result.action, 'skipped');
  assert.match(result.reason, /already succeeded/);
});

test('forwardGateRetry triggers a rerun when the most recent completed run did not succeed', async () => {
  const calls = [];
  const runGh = async (args) => {
    calls.push(args);
    if (args[0] === 'api' && args.includes('--method')) return null;
    return { workflow_runs: [gateRun({ conclusion: 'failure' })] };
  };
  const result = await forwardGateRetry({ repository: 'owner/repo', headSha: 'abc123', runGh, repo: 'C:/repo' });
  assert.equal(result.action, 'rerun-triggered');
  assert.equal(result.runId, 111);
  assert.match(result.reason, /Reran gate run #5.*"failure"/);
  assert.deepEqual(calls[1], ['api', '--method', 'POST', 'repos/owner/repo/actions/runs/111/rerun']);
});

test('forwardGateRetry reports (does not throw) when the rerun request itself fails', async () => {
  const runGh = async (args) => {
    if (args[0] === 'api' && args.includes('--method')) throw new Error('rate limited');
    return { workflow_runs: [gateRun({ conclusion: 'failure' })] };
  };
  const result = await forwardGateRetry({ repository: 'owner/repo', headSha: 'abc123', runGh, repo: 'C:/repo' });
  assert.equal(result.action, 'skipped');
  assert.match(result.reason, /Rerun request .* failed: rate limited/);
  assert.equal(result.runId, 111);
});

test('forwardGateRetry reports (does not throw) when listing Actions runs itself fails', async () => {
  const runGh = async () => { throw new Error('gh: not logged in'); };
  const result = await forwardGateRetry({ repository: 'owner/repo', headSha: 'abc123', runGh, repo: 'C:/repo' });
  assert.equal(result.action, 'skipped');
  assert.match(result.reason, /Could not list Actions runs: gh: not logged in/);
});

test('forwardGateRetry skips on missing inputs without calling runGh', async () => {
  let calls = 0;
  const runGh = async () => { calls += 1; };
  const result = await forwardGateRetry({ repository: 'owner/repo', runGh, repo: 'C:/repo' });
  assert.equal(result.action, 'skipped');
  assert.equal(calls, 0);
});

test('discoverOpenPullRequests calls gh pr list with the expected arguments and filters malformed entries', async () => {
  const calls = [];
  const runGh = async (args) => {
    calls.push(args);
    return [
      { number: 12, headRefOid: 'abc' },
      { number: null, headRefOid: 'def' }, // malformed: no number
      { number: 34, headRefOid: '' }, // malformed: empty headRefOid
      { number: 56, headRefOid: 'ghi' },
    ];
  };
  const result = await discoverOpenPullRequests({ repository: 'owner/repo', baseRef: 'main', runGh, repo: 'C:/repo' });
  assert.deepEqual(result, [{ number: 12, headRefOid: 'abc' }, { number: 56, headRefOid: 'ghi' }]);
  assert.deepEqual(calls, [[
    'pr', 'list', '--repo', 'owner/repo', '--base', 'main', '--state', 'open', '--json', 'number,headRefOid',
    '--limit', String(PR_DISCOVERY_LIMIT),
  ]]);
});

test('forwardGateRetriesForBase reports a full-limit discovery instead of silently truncating (CodeRabbit PR7 #6YjkMG)', async () => {
  // gh pr list exposes no total, so a result at exactly the limit may have
  // dropped PRs — and the dropped ones are precisely those left
  // un-re-verified. That must surface, not read as "all PRs handled".
  const full = Array.from({ length: PR_DISCOVERY_LIMIT }, (unused, index) => ({ number: index + 1, headRefOid: `head-${index + 1}` }));
  const runGh = async (args) => {
    if (args[0] === 'pr' && args[1] === 'list') return full;
    if (args[0] === 'api') return [{ workflow_runs: [] }];
    throw new Error(`unexpected call: ${args.join(' ')}`);
  };
  const results = await forwardGateRetriesForBase({ repository: 'owner/repo', baseRef: 'main', runGh, repo: 'C:/repo' });
  const truncation = results.find((entry) => entry.number === null);
  assert.ok(truncation, 'a full-limit discovery must emit a truncation-warning entry');
  assert.match(truncation.reason, /full limit of 1000/);
  assert.match(truncation.reason, /may not have been re-verified/);
});

test('discoverOpenPullRequests returns [] on missing inputs or a malformed response', async () => {
  assert.deepEqual(await discoverOpenPullRequests({ baseRef: 'main', runGh: async () => [], repo: 'C:/repo' }), []);
  assert.deepEqual(await discoverOpenPullRequests({ repository: 'owner/repo', runGh: async () => [], repo: 'C:/repo' }), []);
  assert.deepEqual(await discoverOpenPullRequests({ repository: 'owner/repo', baseRef: 'main', runGh: null, repo: 'C:/repo' }), []);
  assert.deepEqual(await discoverOpenPullRequests({ repository: 'owner/repo', baseRef: 'main', runGh: async () => ({ not: 'an array' }), repo: 'C:/repo' }), []);
});

test('forwardGateRetriesForBase processes every discovered PR and aggregates results, one failure does not stop the batch', async () => {
  const runGh = async (args) => {
    if (args[0] === 'pr' && args[1] === 'list') {
      return [{ number: 1, headRefOid: 'head-1' }, { number: 2, headRefOid: 'head-2' }, { number: 3, headRefOid: 'head-3' }];
    }
    const endpoint = args.find((arg) => typeof arg === 'string' && arg.startsWith('repos/owner/repo/actions/runs?'));
    if (args[0] === 'api' && endpoint) {
      if (endpoint.includes('head-1')) return [{ workflow_runs: [gateRun({ id: 1, conclusion: 'failure' })] }];
      if (endpoint.includes('head-2')) throw new Error('transient list failure');
      if (endpoint.includes('head-3')) return [{ workflow_runs: [gateRun({ id: 3, conclusion: 'success' })] }];
    }
    if (args[0] === 'api' && args.includes('--method')) return null;
    throw new Error(`unexpected call: ${args.join(' ')}`);
  };
  const results = await forwardGateRetriesForBase({ repository: 'owner/repo', baseRef: 'main', runGh, repo: 'C:/repo' });
  assert.equal(results.length, 3);
  assert.deepEqual(
    results.map((r) => ({ number: r.number, action: r.action })),
    [{ number: 1, action: 'rerun-triggered' }, { number: 2, action: 'skipped' }, { number: 3, action: 'skipped' }],
  );
  assert.match(results[1].reason, /Could not list Actions runs: transient list failure/);
  assert.match(results[2].reason, /already succeeded/);
});

test('forwardGateRetriesForBase returns a single skipped entry when discovery itself fails, rather than throwing', async () => {
  const runGh = async (args) => {
    if (args[0] === 'pr' && args[1] === 'list') throw new Error('gh: not logged in');
    throw new Error(`unexpected call: ${args.join(' ')}`);
  };
  const results = await forwardGateRetriesForBase({ repository: 'owner/repo', baseRef: 'main', runGh, repo: 'C:/repo' });
  assert.equal(results.length, 1);
  assert.equal(results[0].action, 'skipped');
  assert.match(results[0].reason, /Could not list open pull requests targeting main: gh: not logged in/);
});

test('forwardGateRetriesForBase returns [] on missing inputs without calling runGh', async () => {
  let calls = 0;
  const runGh = async () => { calls += 1; };
  assert.deepEqual(await forwardGateRetriesForBase({ baseRef: 'main', runGh, repo: 'C:/repo' }), []);
  assert.deepEqual(await forwardGateRetriesForBase({ repository: 'owner/repo', runGh, repo: 'C:/repo' }), []);
  assert.deepEqual(await forwardGateRetriesForBase({ repository: 'owner/repo', baseRef: 'main', runGh: null, repo: 'C:/repo' }), []);
  assert.equal(calls, 0);
});
