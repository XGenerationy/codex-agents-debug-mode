/**
 * Rolls a list of check results up into one overall status. An empty list
 * rolls up to BLOCKED rather than the vacuous PASS `Array.prototype.every`
 * would produce, so a no-work rollup can never silently satisfy the gate;
 * callers with a legitimately empty subset (e.g. runValidationPhases'
 * qualification phase, which is optional by design) must special-case that
 * themselves rather than routing it through this function. Otherwise: PASS
 * only when every result is PASS; a single FAIL outranks any
 * BLOCKED/BASELINE so a real failure is never masked by a merely-blocked
 * check; BLOCKED/BASELINE with no FAIL present rolls up to BLOCKED; any
 * other/unrecognized status combination fails closed to FAIL rather than
 * defaulting to PASS.
 * @param {{status: string}[]} results
 * @returns {'PASS'|'FAIL'|'BLOCKED'}
 */
const statusFrom = (results) => {
  if (results.length === 0) return 'BLOCKED';
  if (results.every(({ status }) => status === 'PASS')) return 'PASS';
  if (results.some(({ status }) => status === 'FAIL')) return 'FAIL';
  if (results.some(({ status }) => ['BLOCKED', 'BASELINE'].includes(status))) return 'BLOCKED';
  return 'FAIL';
};

/**
 * Runs `execute` over `items` with at most `limit` concurrent workers,
 * preserving each result at its original index regardless of completion
 * order. A thrown error from `execute` is caught and converted into a
 * BLOCKED row for that single item (see inline comment below) so one bad
 * executor can never abort the pool or the rest of the results.
 * @param {Array} items
 * @param {number} limit max concurrent workers (clamped to at least 1 and at most items.length).
 * @param {(item: *) => Promise<object>} execute
 * @returns {Promise<object[]>} one result per item, in the same order as `items`.
 */
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

/**
 * Synthesizes BLOCKED confirmation-phase rows for every check when
 * confirmation cannot run at all (an unresolved plan, or a qualification
 * phase that was not clean). Evidence prefers, in order: the check's own
 * evidence (e.g. why its command never resolved), then the matching
 * `priorResults` row's evidence (e.g. why it failed in qualification), and
 * only falls back to the generic `evidence` message if neither is present.
 * @param {object[]} checks
 * @param {string} evidence fallback evidence text.
 * @param {object[]} [priorResults] results from an earlier phase, matched to `checks` by `id`.
 * @returns {object[]} one BLOCKED confirmation row per check.
 */
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

/**
 * Wraps `execute` so calls that share a `check.resourceGroup` (e.g. a
 * database or browser fixture that cannot be exercised concurrently) run
 * strictly one at a time, chained in call order, while checks with no
 * resourceGroup (or a different one) run unrestricted. Implemented as a
 * per-group promise chain: each call waits on the previous holder before
 * running, then releases and clears its group's lock entry only if it is
 * still the current holder, so a later call is never clobbered.
 * @param {(check: object, phase: string) => Promise<object>} execute
 * @returns {(check: object, phase: string) => Promise<object>} a serialized version of `execute`.
 */
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

/**
 * Runs the two-phase closeout validation gate: a fast, resource-aware
 * `qualification` pass over only the `qualificationSafe` subset of checks
 * (bounded to `parallelism` concurrent workers) as an early fail-fast smoke
 * test, followed — only if qualification is entirely clean — by a full,
 * one-at-a-time `confirmation` pass over every check for an authoritative
 * result. If the plan itself is unresolved (a check is already BLOCKED or
 * has no command) or qualification is not clean, confirmation never runs
 * and every check gets a synthesized BLOCKED confirmation row instead (via
 * blockedConfirmationRows), so the report always has a confirmation row per
 * check. A thrown confirmation executor error is caught per-check so it
 * cannot abort the remaining confirmation checks or the report.
 * @param {{checks: object[], execute: (check: object, phase: string) => Promise<object>, parallelism?: number}} options
 * @returns {Promise<{status: string, qualification: object[], confirmation: object[]}>}
 */
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
  // An empty qualification subset (no check marked qualificationSafe) is not
  // a no-work failure: it is a legitimate configuration where every check
  // skips straight to the authoritative one-at-a-time confirmation pass
  // below. Only route a non-empty qualification result through statusFrom's
  // fail-closed rollup.
  const qualificationStatus = qualification.length ? statusFrom(qualification) : 'PASS';
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
