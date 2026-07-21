const assert = require('node:assert/strict');
const test = require('node:test');

// Mirrors createCommandExecutor timeout resolution for baseline comparison ids.
const resolveTimeout = (check, timeoutsMs, timeoutMs) => {
  if (timeoutsMs[check.id]) return timeoutsMs[check.id];
  if (check.associatedCheckId && timeoutsMs[check.associatedCheckId]) {
    return timeoutsMs[check.associatedCheckId];
  }
  if (typeof check.id === 'string' && check.id.endsWith('-baseline-comparison')) {
    const parent = check.id.slice(0, -'-baseline-comparison'.length);
    if (timeoutsMs[parent]) return timeoutsMs[parent];
  }
  return timeoutMs;
};

test('baseline-comparison ids inherit parent check timeout from timeoutsMs', () => {
  const timeoutsMs = { 'make-pr-check': 12345 };
  assert.equal(
    resolveTimeout({ id: 'make-pr-check-baseline-comparison' }, timeoutsMs, 1000),
    12345,
  );
  assert.equal(
    resolveTimeout({ id: 'other-baseline-comparison', associatedCheckId: 'make-pr-check' }, timeoutsMs, 1000),
    12345,
  );
  assert.equal(resolveTimeout({ id: 'unknown' }, timeoutsMs, 1000), 1000);
});
