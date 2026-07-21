const assert = require('node:assert/strict');
const test = require('node:test');
const { withNoTextconv } = require('./pr_closeout_repo');

test('withNoTextconv injects flag only for diff without existing textconv options', () => {
  assert.deepEqual(withNoTextconv(['status']), ['status']);
  assert.deepEqual(withNoTextconv(['diff', '--name-only']), ['diff', '--no-textconv', '--name-only']);
  assert.deepEqual(withNoTextconv(['diff', '--no-textconv', 'HEAD']), ['diff', '--no-textconv', 'HEAD']);
  assert.deepEqual(withNoTextconv(['diff', '--textconv', 'HEAD']), ['diff', '--textconv', 'HEAD']);
});
