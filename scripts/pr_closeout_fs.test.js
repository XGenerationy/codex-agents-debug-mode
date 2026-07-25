const assert = require('node:assert/strict');
const { constants } = require('node:fs');
const { mkdtemp, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { assertNotSymlink, openNoFollow } = require('./pr_closeout_fs');

test('openNoFollow defaults to O_RDONLY when flags are omitted', async () => {
  // Suppression/gate scanners call openNoFollow(path) with no flags. After the
  // shared helper was extracted, rejecting missing flags would crash closeout
  // reads; default to O_RDONLY so one-argument callers stay valid while string
  // flags still throw.
  const dir = await mkdtemp(path.join(tmpdir(), 'closeout-fs-'));
  const file = path.join(dir, 'sample.txt');
  try {
    await writeFile(file, 'hello-open-nofollow\n', 'utf8');
    const handle = await openNoFollow(file);
    try {
      const buf = Buffer.alloc(32);
      const { bytesRead } = await handle.read(buf, 0, buf.length, 0);
      assert.equal(buf.subarray(0, bytesRead).toString('utf8'), 'hello-open-nofollow\n');
    } finally {
      await handle.close();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('openNoFollow rejects non-integer flags', async () => {
  await assert.rejects(
    () => openNoFollow('/tmp/unused', 'r'),
    /numeric fs\.constants flags/i,
  );
  await assert.rejects(
    () => openNoFollow('/tmp/unused', 'a'),
    TypeError,
  );
});

test('openNoFollow accepts explicit numeric write flags', async () => {
  const dir = await mkdtemp(path.join(tmpdir(), 'closeout-fs-w-'));
  const file = path.join(dir, 'out.txt');
  try {
    const handle = await openNoFollow(
      file,
      constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC,
      0o666,
    );
    try {
      await handle.writeFile('written\n', 'utf8');
    } finally {
      await handle.close();
    }
    const again = await openNoFollow(file);
    try {
      const buf = Buffer.alloc(16);
      const { bytesRead } = await again.read(buf, 0, buf.length, 0);
      assert.equal(buf.subarray(0, bytesRead).toString('utf8'), 'written\n');
    } finally {
      await again.close();
    }
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('assertNotSymlink tolerates ENOENT', async () => {
  await assertNotSymlink(path.join(tmpdir(), 'no-such-closeout-fs-path'), 'should not throw');
});
