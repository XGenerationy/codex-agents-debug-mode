const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const { mkdtemp, readFile, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { MANDATORY_CHECKS } = require('./pr_closeout_core');

const script = path.join(__dirname, 'pr_closeout.js');
const git = (repo, ...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' });

test('prints help without touching a repository', () => {
  const result = spawnSync(process.execPath, [script, '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /^Usage: pr_closeout\.js/);
  assert.match(result.stdout, /--plan/);
});

test('plan mode resolves all 19 checks without executing them', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-cli-'));
  try {
    git(repo, 'init', '--quiet');
    git(repo, 'config', 'user.name', 'Closeout Test');
    git(repo, 'config', 'user.email', 'closeout@example.invalid');
    git(repo, 'config', 'commit.gpgSign', 'false');
    await writeFile(path.join(repo, 'package.json'), '{}');
    // The fixed make-smoke/make-sbom/make-audit/make-pr-check checks require
    // a captured, non-neutralizing recipe before they resolve (Codex UsPVX):
    // an absent entry fails closed exactly like an unresolved makeCandidates
    // recipe. Provide a real Makefile with clean recipes so this plan-mode
    // smoke test exercises the intended "trusted, inspected recipe" path.
    await writeFile(
      path.join(repo, 'Makefile'),
      'smoke:\n\tnode scripts/smoke.js\n\nsbom:\n\tnode scripts/sbom.js\n\naudit:\n\tnode scripts/audit.js\n\npr-check:\n\tnpm test\n',
    );
    git(repo, 'add', '.');
    git(repo, 'commit', '--quiet', '-m', 'base');
    const commands = Object.fromEntries(
      MANDATORY_CHECKS.filter(({ fixed }) => !fixed).map(({ id }) => [id, `printf clean-${id}`]),
    );
    const configPath = path.join(repo, 'closeout.json');
    await writeFile(configPath, JSON.stringify({
      baseRef: 'HEAD',
      commands,
      services: {
        redis: { host: '127.0.0.1', port: 6379 },
        grafana: { url: 'http://127.0.0.1:3000/api/health' },
      },
      proofs: {
        'grafana-render': { type: 'artifact', path: 'artifacts/grafana.json' },
        'make-sbom': { type: 'artifact', path: 'artifacts/sbom.json' },
        'grafana-live-render': {
          type: 'artifact',
          path: 'artifacts/grafana-live.json',
          semantic: 'grafana-live-result',
          grafanaOrigin: 'http://127.0.0.1:3000',
        },
        'hunter-build': {
          type: 'command',
          command: 'docker compose ps --format json hunter',
          expectedPattern: 'semantic:docker-compose-running-healthy',
        },
      },
    }));
    const result = spawnSync(process.execPath, [script, '--repo', repo, '--config', configPath, '--plan'], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const plan = JSON.parse(result.stdout);
    assert.equal(plan.checks.length, 19);
    assert.ok(plan.checks.every(({ command }) => command));
    assert.equal(plan.execution, 'not-started');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('example config uses the enforced semantic proof policies', async () => {
  const examplePath = path.join(__dirname, '..', 'assets', 'pr-closeout.config.example.json');
  const config = JSON.parse(await readFile(examplePath, 'utf8'));
  assert.deepEqual(config.safeEnv, []);
  assert.equal(config.proofs['grafana-live-render'].semantic, 'grafana-live-result');
  assert.equal(
    config.proofs['hunter-build'].expectedPattern,
    'semantic:docker-compose-running-healthy',
  );
});

test('rejects unknown arguments as a usage error', () => {
  const result = spawnSync(process.execPath, [script, '--weaken-gate'], { encoding: 'utf8' });
  assert.equal(result.status, 3);
  assert.match(result.stderr, /Unknown argument/);
});

test('readCloseoutConfig parses a bounded regular config file', async () => {
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-cli-config-'));
  try {
    const configPath = path.join(repo, 'closeout.json');
    await writeFile(configPath, JSON.stringify({ baseRef: 'HEAD' }));
    assert.deepEqual(await readCloseoutConfig(configPath), { baseRef: 'HEAD' });
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('rejects a --config that exceeds the regular-file size cap', async () => {
  // Codex #UDDQK: the descriptor-verified cap rejects before JSON.parse, and
  // the CLI surfaces it as a config error (exit 3 + BLOCKED record).
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-cli-config-cap-'));
  try {
    const configPath = path.join(repo, 'closeout.json');
    await writeFile(configPath, `{"padding":"${'x'.repeat(1_100_000)}"}`);
    await assert.rejects(readCloseoutConfig(configPath), /regular file/);
    const result = spawnSync(process.execPath, [script, '--repo', repo, '--config', configPath, '--plan'], { encoding: 'utf8' });
    assert.equal(result.status, 3);
    assert.match(result.stderr, /regular file/);
    const record = JSON.parse(result.stdout);
    assert.equal(record.status, 'BLOCKED');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('rejects a non-regular --config target through the descriptor guard', async () => {
  // Codex #UDDQK: a FIFO/device behind the config path must be rejected from
  // the opened descriptor, never read. Windows cannot create FIFOs without
  // admin, so the opener is injected — the same seam openNoFollow provides.
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const fakeHandle = {
    stat: async () => ({ isFile: () => false, size: 12 }),
    read: async () => { throw new Error('read must not be reached for a non-regular config'); },
    close: async () => {},
  };
  await assert.rejects(
    readCloseoutConfig('closeout-fifo.json', { openFile: async () => fakeHandle }),
    /regular file/,
  );
});

test('rejects a symlinked --config without following it', async () => {
  // Codex #UDDQK: no real symlink (Windows needs admin); the injected opener
  // rejects with ELOOP exactly as openNoFollow does where O_NOFOLLOW exists.
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const eloop = Object.assign(new Error('ELOOP: too many symbolic links encountered'), { code: 'ELOOP' });
  await assert.rejects(
    readCloseoutConfig('closeout-link.json', { openFile: async () => { throw eloop; } }),
    /must not be a symlink/,
  );
});

test('rejects a symlinked --config even when NOFOLLOW is unavailable and the opener silently follows it', async () => {
  // Codex review (pr_closeout.js:78): on platforms where O_NOFOLLOW is not
  // enforced (Windows, some filesystems), openNoFollow's attempt ladder can
  // fall back to a plain open that follows the symlink instead of throwing
  // ELOOP. Simulate that fallback with an injected opener that ignores
  // no-follow semantics entirely, and an injected lstat reporting the target
  // is a symlink (no real symlink needed, so this runs on Windows CI too).
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const targetContent = JSON.stringify({ baseRef: 'HEAD' });
  const fakeHandle = {
    stat: async () => ({ isFile: () => true, size: targetContent.length, dev: 1, ino: 999 }),
    read: async (buffer, offset) => {
      const chunk = Buffer.from(targetContent, 'utf8');
      chunk.copy(buffer, offset);
      return { bytesRead: chunk.length };
    },
    close: async () => {},
  };
  await assert.rejects(
    readCloseoutConfig('closeout-link.json', {
      lstatFn: async () => ({ isSymbolicLink: () => true, dev: 1, ino: 42 }),
      openFile: async () => fakeHandle,
    }),
    /must not be a symlink/,
  );
});

test('rejects a --config swapped for a symlink between lstat and open (TOCTOU)', async () => {
  // Codex review (pr_closeout.js:78): even when the pre-open lstat sees a
  // regular file, a symlink could be swapped in before the open completes.
  // The opened descriptor's dev/ino must still be compared back against the
  // pre-open lstat to close that gap.
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const fakeHandle = {
    stat: async () => ({ isFile: () => true, size: 2, dev: 1, ino: 999 }),
    read: async () => { throw new Error('read must not be reached once identity mismatches'); },
    close: async () => {},
  };
  await assert.rejects(
    readCloseoutConfig('closeout-race.json', {
      lstatFn: async () => ({ isSymbolicLink: () => false, dev: 1, ino: 42 }),
      openFile: async () => fakeHandle,
    }),
    /must not be a symlink/,
  );
});

test('accepts a regular --config whose pre-open lstat identity matches the opened descriptor', async () => {
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const targetContent = JSON.stringify({ baseRef: 'HEAD' });
  const fakeHandle = {
    stat: async () => ({ isFile: () => true, size: targetContent.length, dev: 7, ino: 55 }),
    read: async (buffer, offset) => {
      const chunk = Buffer.from(targetContent, 'utf8');
      chunk.copy(buffer, offset);
      return { bytesRead: chunk.length };
    },
    close: async () => {},
  };
  const config = await readCloseoutConfig('closeout-ok.json', {
    lstatFn: async () => ({ isSymbolicLink: () => false, dev: 7, ino: 55 }),
    openFile: async () => fakeHandle,
  });
  assert.deepEqual(config, { baseRef: 'HEAD' });
});

test('readCloseoutConfig tolerates a missing config path at the lstat pre-check', async () => {
  // ENOENT at lstat must fall through to openFile, which surfaces its own
  // (existing, well-tested) ENOENT error rather than a symlink rejection.
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-cli-missing-'));
  try {
    const configPath = path.join(repo, 'does-not-exist.json');
    await assert.rejects(readCloseoutConfig(configPath), /ENOENT/);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('rejects a --config identity check when the filesystem never assigns real inodes (ino === 0)', async () => {
  // CodeRabbit review (pr_closeout.js:110): a dev/ino comparison where both
  // sides report ino 0 (some FAT/network mounts never assign real inodes) is
  // vacuously true and provides zero protection precisely on the platforms
  // where openNoFollow's own O_NOFOLLOW fallback also degrades.
  //
  // CodeRabbit review (pr_closeout.js:128, Codex UfmJr): this must NOT be the
  // generic "must not be a symlink" message -- an operator on a filesystem
  // that never assigns real inodes has no symlink to fix, and that message
  // points them at the wrong problem. The zero-ino case gets its own,
  // actionable message instead.
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const fakeHandle = {
    stat: async () => ({ isFile: () => true, size: 2, dev: 1, ino: 0 }),
    read: async () => { throw new Error('read must not be reached once ino reporting is untrusted'); },
    close: async () => {},
  };
  await assert.rejects(
    readCloseoutConfig('closeout-zero-ino.json', {
      lstatFn: async () => ({ isSymbolicLink: () => false, dev: 1, ino: 0 }),
      openFile: async () => fakeHandle,
    }),
    /does not report a usable file identity/,
  );
});

test('rejects a --config identity check when only the pre-open lstat reports ino 0', async () => {
  // Same zero-ino message must fire when the untrusted side is the pre-open
  // lstat rather than the opened descriptor's stat -- both sides carry no
  // verified identity to compare either way.
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const fakeHandle = {
    stat: async () => ({ isFile: () => true, size: 2, dev: 1, ino: 9 }),
    read: async () => { throw new Error('read must not be reached once ino reporting is untrusted'); },
    close: async () => {},
  };
  await assert.rejects(
    readCloseoutConfig('closeout-zero-ino-pre.json', {
      lstatFn: async () => ({ isSymbolicLink: () => false, dev: 1, ino: 0 }),
      openFile: async () => fakeHandle,
    }),
    /does not report a usable file identity/,
  );
});

test('rejects a --config truncated after handle.stat() but before the read finishes', async () => {
  // Codex review (pr_closeout.js:149, P2): if the config is truncated in
  // place after handle.stat() captures its size, the read loop hits EOF
  // early (bytesRead === 0) and used to break out silently, parsing whatever
  // shorter document remained (even a trivial `{}`) instead of rejecting the
  // raced read. The stat reports a size the underlying content no longer
  // has; read returns fewer bytes than that size and then EOF.
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const targetContent = JSON.stringify({ baseRef: 'HEAD' });
  const truncatedContent = '{}';
  const fakeHandle = {
    stat: async () => ({ isFile: () => true, size: targetContent.length, dev: 7, ino: 55, mtimeMs: 1000 }),
    read: async (buffer, offset) => {
      if (offset > 0) return { bytesRead: 0 };
      const chunk = Buffer.from(truncatedContent, 'utf8');
      chunk.copy(buffer, offset);
      return { bytesRead: chunk.length };
    },
    close: async () => {},
  };
  await assert.rejects(
    readCloseoutConfig('closeout-truncated.json', {
      lstatFn: async () => ({ isSymbolicLink: () => false, dev: 7, ino: 55 }),
      openFile: async () => fakeHandle,
    }),
    /truncated while it was being read/,
  );
});

test('rejects a --config rewritten in place between the pre-read and post-read stat (TOCTOU)', async () => {
  // Codex review (pr_closeout.js:149, P2): a full read (offset === info.size)
  // can still have raced an in-place rewrite that completed entirely between
  // the pre-read stat and the read itself -- same byte count, different
  // content. Re-stating the same open descriptor after the read must catch
  // the identity/metadata change instead of trusting the bytes just read.
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const targetContent = JSON.stringify({ baseRef: 'HEAD' });
  let statCalls = 0;
  const fakeHandle = {
    stat: async () => {
      statCalls += 1;
      // First call: the pre-read stat. Second call: the post-read re-stat,
      // reporting a different mtimeMs as if the file had been rewritten in
      // place (same dev/ino/size) during the read.
      return {
        isFile: () => true,
        size: targetContent.length,
        dev: 7,
        ino: 55,
        mtimeMs: statCalls === 1 ? 1000 : 2000,
      };
    },
    read: async (buffer, offset) => {
      const chunk = Buffer.from(targetContent, 'utf8');
      chunk.copy(buffer, offset);
      return { bytesRead: chunk.length };
    },
    close: async () => {},
  };
  await assert.rejects(
    readCloseoutConfig('closeout-rewritten.json', {
      lstatFn: async () => ({ isSymbolicLink: () => false, dev: 7, ino: 55 }),
      openFile: async () => fakeHandle,
    }),
    /changed while it was being read/,
  );
});

test('rejects a --config opened after an ENOENT lstat pre-check finds nothing to compare against', async () => {
  // Codex review (pr_closeout.js:95): when the pre-open lstat sees ENOENT,
  // preInfo is null and there is nothing to compare the opened descriptor's
  // identity against. A symlink created in that exact gap (the config path
  // did not exist yet, then a racer swapped one in before openFile ran) must
  // not be silently accepted just because there was no earlier identity to
  // contradict it.
  const { readCloseoutConfig } = require('./pr_closeout.js');
  const targetContent = JSON.stringify({ baseRef: 'HEAD' });
  const fakeHandle = {
    stat: async () => ({ isFile: () => true, size: targetContent.length, dev: 1, ino: 1 }),
    read: async (buffer, offset) => {
      const chunk = Buffer.from(targetContent, 'utf8');
      chunk.copy(buffer, offset);
      return { bytesRead: chunk.length };
    },
    close: async () => {},
  };
  const enoent = Object.assign(new Error('ENOENT: no such file or directory'), { code: 'ENOENT' });
  await assert.rejects(
    readCloseoutConfig('closeout-race.json', {
      lstatFn: async () => { throw enoent; },
      openFile: async () => fakeHandle,
    }),
    /must not be a symlink/,
  );
});
