const assert = require('node:assert/strict');
const { mkdtemp, readFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { MANDATORY_CHECKS } = require('./pr_closeout_core');
const { writeEvidenceReport } = require('./pr_closeout_report');
const { runValidationPhases, statusFrom } = require('./pr_closeout_runner');

// CI failure diagnostics: when a status assertion fails, print the executor's
// evidence so the remote runner log carries the root cause.
const statusDiag = (result) =>
  `evidence: ${result?.evidence || ''} | terminationEvidence: ${result?.terminationEvidence || ''}`;


test('reports FAIL when failures and blockers are both present', () => {
  assert.equal(statusFrom([{ status: 'BLOCKED' }, { status: 'FAIL' }]), 'FAIL');
  assert.equal(statusFrom([{ status: 'BASELINE' }, { status: 'PASS' }]), 'BLOCKED');
});

test('rolls an empty result list up to BLOCKED instead of a vacuous PASS', () => {
  // Array.prototype.every on an empty array is true, so without an explicit
  // empty-list check a no-work rollup would silently satisfy the gate.
  assert.equal(statusFrom([]), 'BLOCKED');
});

test('an empty overall checks plan rolls up to BLOCKED, not a vacuous PASS', async () => {
  let executions = 0;
  const result = await runValidationPhases({
    checks: [],
    execute: async () => {
      executions += 1;
      return { status: 'PASS' };
    },
  });
  assert.equal(executions, 0);
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.deepEqual(result.qualification, []);
  assert.deepEqual(result.confirmation, []);
});

test('an empty qualificationSafe subset is not treated as a qualification failure', async () => {
  // No check opts into the fast qualification pass; every check goes
  // straight to confirmation. This must behave identically to a normal
  // clean run, not get short-circuited by the empty-list-is-BLOCKED rule
  // that statusFrom now applies (that rule is for the overall rollup, not
  // for a subset that is intentionally allowed to be empty).
  const checks = ['first', 'second'].map((id) => ({ id, command: `run ${id}` }));
  let confirmationRuns = 0;
  const result = await runValidationPhases({
    checks,
    execute: async (check, phase) => {
      if (phase === 'confirmation') confirmationRuns += 1;
      return { id: check.id, phase, status: 'PASS', exitCode: 0 };
    },
  });
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.deepEqual(result.qualification, []);
  assert.equal(confirmationRuns, checks.length);
  assert.equal(result.confirmation.length, checks.length);
});

test('parallelizes safe qualification then confirms all checks sequentially', async () => {
  const checks = MANDATORY_CHECKS.map((check) => ({ ...check, command: check.command || `run ${check.id}`, status: undefined }));
  const events = [];
  let active = 0;
  let maxQualificationConcurrency = 0;
  const execute = async (check, phase) => {
    events.push(`start:${phase}:${check.id}`);
    active += 1;
    if (phase === 'qualification') maxQualificationConcurrency = Math.max(maxQualificationConcurrency, active);
    if (phase === 'confirmation') assert.equal(active, 1);
    await new Promise((resolve) => setTimeout(resolve, 4));
    active -= 1;
    events.push(`end:${phase}:${check.id}`);
    return { id: check.id, phase, status: 'PASS', exitCode: 0 };
  };

  const result = await runValidationPhases({ checks, execute, parallelism: 3 });
  assert.ok(maxQualificationConcurrency > 1);
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.deepEqual(result.confirmation.map(({ id }) => id), MANDATORY_CHECKS.map(({ id }) => id));
  const lastQualification = Math.max(...events.map((event, index) => event.startsWith('end:qualification:') ? index : -1));
  const firstConfirmation = events.findIndex((event) => event.startsWith('start:confirmation:'));
  assert.ok(firstConfirmation > lastQualification);
});

test('does not start confirmation when qualification is not clean', async () => {
  const checks = MANDATORY_CHECKS.map((check) => ({
    ...check,
    command: check.command || `run ${check.id}`,
    qualificationSafe: check.id === 'typecheck' || check.qualificationSafe,
  }));
  let confirmationRuns = 0;
  const result = await runValidationPhases({
    checks,
    parallelism: 2,
    execute: async (check, phase) => {
      if (phase === 'confirmation') confirmationRuns += 1;
      return { id: check.id, phase, status: check.id === 'typecheck' ? 'FAIL' : 'PASS', exitCode: check.id === 'typecheck' ? 1 : 0 };
    },
  });
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.equal(confirmationRuns, 0);
  assert.equal(result.confirmation.length, MANDATORY_CHECKS.length);
  assert.ok(result.confirmation.every(({ phase, status, evidence }) => (
    phase === 'confirmation'
      && status === 'BLOCKED'
      && /qualification/i.test(evidence)
  )));
});

test('serializes qualification checks that share a resource group', async () => {
  const checks = ['first', 'second', 'third'].map((id, index) => ({
    id,
    command: `run ${id}`,
    qualificationSafe: true,
    resourceGroup: index < 2 ? 'database' : 'browser',
  }));
  let databaseActive = 0;
  let maxDatabaseActive = 0;
  const result = await runValidationPhases({
    checks,
    parallelism: 3,
    execute: async (check, phase) => {
      if (phase === 'qualification' && check.resourceGroup === 'database') {
        databaseActive += 1;
        maxDatabaseActive = Math.max(maxDatabaseActive, databaseActive);
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
      if (phase === 'qualification' && check.resourceGroup === 'database') databaseActive -= 1;
      return { ...check, phase, status: 'PASS', exitCode: 0 };
    },
  });
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.equal(maxDatabaseActive, 1);
});

test('contains a thrown executor error to a single BLOCKED qualification row', async () => {
  const checks = ['survivor', 'thrower', 'survivor2'].map((id) => ({
    id,
    command: `run ${id}`,
    qualificationSafe: true,
  }));
  const result = await runValidationPhases({
    checks,
    parallelism: 2,
    execute: async (check) => {
      if (check.id === 'thrower') throw new Error('boom');
      return { ...check, phase: 'qualification', status: 'PASS', exitCode: 0 };
    },
  });
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  const failed = result.qualification.find(({ id }) => id === 'thrower');
  assert.equal(failed.status, 'BLOCKED');
  assert.match(failed.evidence, /boom/);
  // The thrown error must not abort the pool: every other row still ran.
  assert.equal(result.qualification.length, checks.length);
  assert.ok(result.qualification.every(({ id }) => id));
});

test('materializes all mandatory confirmation rows when the plan is unresolved', async () => {
  const checks = MANDATORY_CHECKS.map((check) => ({
    ...check,
    command: check.id === 'producer-tests' ? undefined : (check.command || `run ${check.id}`),
    status: check.id === 'producer-tests' ? 'BLOCKED' : undefined,
    evidence: check.id === 'producer-tests' ? 'No authoritative producer test command resolved.' : undefined,
  }));
  let executions = 0;
  const result = await runValidationPhases({
    checks,
    execute: async () => {
      executions += 1;
      return { status: 'PASS' };
    },
  });

  assert.equal(executions, 0);
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.equal(result.confirmation.length, MANDATORY_CHECKS.length);
  assert.deepEqual(result.confirmation.map(({ id }) => id), MANDATORY_CHECKS.map(({ id }) => id));
  assert.ok(result.confirmation.every(({ phase, status }) => phase === 'confirmation' && status === 'BLOCKED'));
  assert.equal(
    result.confirmation.find(({ id }) => id === 'producer-tests').evidence,
    'No authoritative producer test command resolved.',
  );
});

test('writes JSON and Markdown evidence with head SHA and non-pass truth', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-report-'));
  const report = {
    schemaVersion: 1,
    repository: 'C:/repo',
    headSha: 'deadbeef',
    baseSha: 'cafebabe',
    configDigest: 'config123',
    overallStatus: 'BLOCKED',
    preflight: { checks: [{ name: 'redis', status: 'BLOCKED', evidence: 'unavailable' }] },
    qualificationChecks: [{ id: 'git-diff-check', command: 'git diff --check', status: 'PASS', exitCode: 0, evidence: 'clean' }],
    headConsistency: { status: 'PASS', evidence: 'same head' },
    livePrState: {
      status: 'BLOCKED',
      evidence: 'One unresolved review thread.',
      number: 42,
      url: 'https://github.example/pulls/42',
      state: 'OPEN',
      isDraft: false,
      mergeStateStatus: 'BLOCKED',
      reviewDecision: 'REVIEW_REQUIRED',
      unresolvedThreads: [{ path: 'src/a.ts', line: 4, url: 'https://github.example/comment/1' }],
      checks: [{ name: 'ci', status: 'COMPLETED', conclusion: 'SUCCESS' }],
      externalServices: [],
    },
    toolVersions: { node: 'v24' },
    checks: [
      { id: 'redis-integration', phase: 'confirmation', command: 'pnpm test:redis', status: 'BLOCKED', exitCode: null, durationMs: 12, evidence: 'Redis unavailable' },
    ],
    suppressionFindings: [],
  };

  const paths = await writeEvidenceReport({ outputDir, report });
  const stored = JSON.parse(await readFile(paths.json, 'utf8'));
  const markdown = await readFile(paths.markdown, 'utf8');
  assert.equal(stored.headSha, 'deadbeef');
  assert.match(markdown, /Overall status: \*\*BLOCKED\*\*/);
  assert.match(markdown, /redis-integration/);
  assert.match(markdown, /Redis unavailable/);
  assert.match(markdown, /Configuration digest: config123/);
  assert.match(markdown, /Qualification checks/);
  assert.match(markdown, /Head consistency/);
  assert.match(markdown, /node: v24/);
  assert.match(markdown, /Live GitHub PR state/);
  assert.match(markdown, /One unresolved review thread/);
  assert.match(markdown, /Fix and rerun record/);
  assert.match(markdown, /Baseline comparison/);
});
