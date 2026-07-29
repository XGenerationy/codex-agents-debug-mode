const assert = require('node:assert/strict');
const test = require('node:test');

const { resolveCheckTimeout } = require('./pr_closeout_process');

test('baseline-comparison ids inherit parent check timeout from timeoutsMs', () => {
  const timeoutsMs = { 'make-pr-check': 12345 };
  assert.equal(
    resolveCheckTimeout({ id: 'make-pr-check-baseline-comparison' }, timeoutsMs, 1000),
    12345,
  );
  assert.equal(
    resolveCheckTimeout({ id: 'other-baseline-comparison', associatedCheckId: 'make-pr-check' }, timeoutsMs, 1000),
    12345,
  );
  assert.equal(resolveCheckTimeout({ id: 'unknown' }, timeoutsMs, 1000), 1000);
  assert.equal(
    resolveCheckTimeout({ id: 'make-pr-check' }, timeoutsMs, 1000),
    12345,
  );
});
