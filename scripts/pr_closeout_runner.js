const statusFrom = (results) => {
  if (results.every(({ status }) => status === 'PASS')) return 'PASS';
  if (results.some(({ status }) => status === 'FAIL')) return 'FAIL';
  if (results.some(({ status }) => ['BLOCKED', 'BASELINE'].includes(status))) return 'BLOCKED';
  return 'FAIL';
};

const runPool = async (items, limit, execute) => {
  const results = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      try {
        results[index] = await execute(items[index]);
      } catch (error) {
        // Contain executor failures to this single item so one thrown error
        // cannot abort the whole pool and prevent the workflow from writing a
        // structured evidence report. Mirror the executor's own BLOCKED shape
        // so downstream classification still treats the row as non-passing.
        const item = items[index] || {};
        results[index] = {
          ...item,
          status: 'BLOCKED',
          exitCode: null,
          evidence: `Executor threw while running ${item.id || item.label || 'check'}: ${error?.message || error}.`,
        };
      }
    }
  };
  const count = Math.max(1, Math.min(Number(limit) || 1, items.length || 1));
  await Promise.all(Array.from({ length: count }, worker));
  return results;
};

const blockedConfirmationRows = (checks, evidence, priorResults = []) => {
  const priorById = new Map(priorResults.map((result) => [result.id, result]));
  return checks.map((check) => ({
    ...check,
    phase: 'confirmation',
    status: 'BLOCKED',
    exitCode: null,
    evidence: check.evidence || priorById.get(check.id)?.evidence || evidence,
  }));
};

const resourceAwareExecutor = (execute) => {
  const locks = new Map();
  return async (check, phase) => {
    if (!check.resourceGroup) return execute(check, phase);
    const previous = locks.get(check.resourceGroup) || Promise.resolve();
    let release;
    const current = new Promise((resolve) => { release = resolve; });
    locks.set(check.resourceGroup, current);
    await previous;
    try {
      return await execute(check, phase);
    } finally {
      release();
      if (locks.get(check.resourceGroup) === current) locks.delete(check.resourceGroup);
    }
  };
};

const runValidationPhases = async ({ checks, execute, parallelism = 4 } = {}) => {
  const unresolved = checks.filter(({ status, command }) => status === 'BLOCKED' || !command);
  if (unresolved.length) {
    return {
      status: 'BLOCKED',
      qualification: unresolved,
      confirmation: blockedConfirmationRows(checks, 'Confirmation did not run because the validation plan is unresolved.'),
    };
  }
  const qualificationChecks = checks.filter(({ qualificationSafe }) => qualificationSafe);
  const executeQualification = resourceAwareExecutor(execute);
  const qualification = await runPool(
    qualificationChecks,
    parallelism,
    (check) => executeQualification(check, 'qualification'),
  );
  const qualificationStatus = statusFrom(qualification);
  if (qualificationStatus !== 'PASS') {
    return {
      status: qualificationStatus,
      qualification,
      confirmation: blockedConfirmationRows(
        checks,
        'Confirmation did not run because qualification was not clean.',
        qualification,
      ),
    };
  }
  const confirmation = [];
  for (const check of checks) {
    // Contain confirmation executor errors the same way runPool contains
    // qualification errors: a single thrown error (verifyBaseline worktree
    // failure, log/proof filesystem error, etc.) must not bubble out of
    // runValidationPhases and prevent the workflow from writing a structured
    // evidence report. Record a BLOCKED row and continue with the next check.
    try {
      confirmation.push(await execute(check, 'confirmation'));
    } catch (error) {
      confirmation.push({
        ...check,
        phase: 'confirmation',
        status: 'BLOCKED',
        exitCode: null,
        evidence: `Executor threw while running ${check.id || check.label || 'check'}: ${error?.message || error}.`,
      });
    }
  }
  return { status: statusFrom(confirmation), qualification, confirmation };
};

module.exports = { blockedConfirmationRows, runValidationPhases, statusFrom };
