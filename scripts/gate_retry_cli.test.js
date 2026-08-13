const assert = require('node:assert/strict');
const test = require('node:test');

const { parseArgs } = require('./gate_retry_cli');

test('parseArgs accepts a well-formed single-mode invocation', () => {
  const options = parseArgs(['single', '--repository', 'owner/repo', '--head-sha', 'abc123', '--repo', 'C:/repo']);
  assert.deepEqual(options, { mode: 'single', repository: 'owner/repo', headSha: 'abc123', repo: 'C:/repo' });
});

test('parseArgs accepts a well-formed base-mode invocation and defaults repo to cwd', () => {
  const options = parseArgs(['base', '--repository', 'owner/repo', '--base-ref', 'main']);
  assert.equal(options.mode, 'base');
  assert.equal(options.repository, 'owner/repo');
  assert.equal(options.baseRef, 'main');
  assert.equal(options.repo, process.cwd());
});

test('parseArgs shows help without requiring other flags', () => {
  assert.deepEqual(parseArgs(['-h']), { help: true });
  assert.deepEqual(parseArgs(['--help']), { help: true });
});

test('parseArgs rejects an unknown mode', () => {
  assert.throws(() => parseArgs(['bogus', '--repository', 'o/r']), /Unknown mode "bogus"/);
  assert.throws(() => parseArgs([]), /Unknown mode ""/);
});

test('parseArgs rejects an unrecognized flag', () => {
  assert.throws(() => parseArgs(['single', '--repository', 'o/r', '--head-sha', 'abc', '--bogus', 'x']), /Unrecognized argument: --bogus/);
});

test('parseArgs rejects a flag missing its value', () => {
  assert.throws(() => parseArgs(['single', '--repository']), /--repository requires a value/);
});

test('parseArgs rejects a value that is itself a flag, so a dropped value cannot silently swallow the next flag', () => {
  assert.throws(() => parseArgs(['single', '--repository', '--head-sha', 'abc']), /--repository requires a value/);
});

test('parseArgs requires --repository', () => {
  assert.throws(() => parseArgs(['single', '--head-sha', 'abc']), /--repository is required/);
});

test('parseArgs requires --head-sha for single mode', () => {
  assert.throws(() => parseArgs(['single', '--repository', 'o/r']), /--head-sha is required for "single" mode/);
});

test('parseArgs requires --base-ref for base mode', () => {
  assert.throws(() => parseArgs(['base', '--repository', 'o/r']), /--base-ref is required for "base" mode/);
});
