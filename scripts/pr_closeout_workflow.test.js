const assert = require('node:assert/strict');
const test = require('node:test');

const { MANDATORY_CHECKS } = require('./pr_closeout_core');
const { digestValidationConfig } = require('./pr_closeout_git');
const {
  acquireOutputDirLock,
  defaultOutputDir,
  evaluateOverallStatus,
  normalizePersistedPaths,
  prepareOutputDirectory,
  runCloseoutWorkflow,
} = require('./pr_closeout_workflow');

const configuredCommands = Object.fromEntries(
  MANDATORY_CHECKS.filter(({ fixed }) => !fixed).map(({ id }) => [id, `run ${id}`]),
);
const reviewedConfig = (extra = {}) => ({
  commands: configuredCommands,
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
  ...extra,
});

const gateAttestation = (status = 'PASS', extra = {}) => ({
  provider: 'github-pull-request-review',
  status,
  baseSha: 'base123',
  headSha: 'head123',
  configDigest: '__TEST_DIGEST__',
  decision: 'not-weakened',
  reviewer: 'independent-reviewer',
  evidence: 'https://github.example/reviews/7',
  ...extra,
});

const passingExecution = (check, phase) => ({
  ...check,
  phase,
  status: 'PASS',
  exitCode: 0,
  stdout: 'clean',
  stderr: '',
  startedAt: '2026-07-14T00:00:00.000Z',
  finishedAt: '2026-07-14T00:00:00.001Z',
  durationMs: 1,
  evidence: 'clean',
});

const makeDependencies = ({
  finalFindings = [],
  finalHead = 'head123',
  finalBase = 'base123',
  sealHead = finalHead,
  sealBase = finalBase,
  lateSealHead,
  livePrStatus = 'PASS',
  admissionAttestationStatus = 'PASS',
  finalAttestationStatus = 'PASS',
} = {}) => {
  let stateReads = 0;
  let scanReads = 0;
  let currentSealHead = sealHead;
  const executions = [];
  const written = [];
  const events = [];
  return {
    executions,
    written,
    events,
    dependencies: {
      resolveRepositoryState: async () => {
        stateReads += 1;
        events.push(`repository-state:${stateReads}`);
        return {
          repo: 'C:/repo',
          baseRef: 'origin/main',
          baseSha: stateReads === 1 ? 'base123' : (stateReads === 2 ? finalBase : sealBase),
          headSha: stateReads === 1 ? 'head123' : (stateReads === 2 ? finalHead : currentSealHead),
          touchedFiles: ['src/a.ts'],
        };
      },
      readProjectMetadata: async () => ({ packageScripts: {}, makeTargets: [] }),
      prepareOutputDirectory: async ({ outputDir }) => outputDir,
      readGateChanges: async () => {
        events.push('gate-changes');
        return { changedFiles: [], addedLines: [] };
      },
      scanTouchedSuppressions: async () => {
        scanReads += 1;
        events.push(`suppression-scan:${scanReads}`);
        if (scanReads > 1 && lateSealHead) currentSealHead = lateSealHead;
        return scanReads === 1 ? [] : finalFindings;
      },
      runPreflight: async () => {
        events.push('preflight');
        return { status: 'PASS', checks: [], toolVersions: { node: 'v24' } };
      },
      digestValidationConfig: () => '__TEST_DIGEST__',
      workingTreeFingerprint: async () => {
        events.push('fingerprint');
        return 'stable-tree';
      },
      cleanTreeStatus: async () => {
        events.push('clean-tree');
        return { status: 'PASS', evidence: 'clean' };
      },
      readLiveGateAttestation: async () => {
        events.push('gate-attestation');
        return gateAttestation(admissionAttestationStatus);
      },
      readLivePrState: async () => ({
        status: livePrStatus,
        evidence: livePrStatus === 'PASS' ? 'Live PR surfaces are clean.' : 'Live PR surface is not clean.',
        number: 42,
        checks: [],
        unresolvedThreads: [],
        externalServices: [],
        gateAttestation: gateAttestation(finalAttestationStatus),
      }),
      execute: async (check, phase) => {
        executions.push(`${phase}:${check.id}`);
        return passingExecution(check, phase);
      },
      verifyBaseline: async ({ headResult }) => headResult,
      writeEvidenceReport: async ({ report }) => {
        events.push(`report-write:${written.length + 1}`);
        written.push(structuredClone(report));
        return { json: 'report.json', markdown: 'report.md' };
      },
    },
  };
};

test('normalizes differently cased path aliases before persisting evidence', () => {
  const normalized = normalizePersistedPaths(
    {
      repository: 'c:\\REPO',
      evidence: 'C:/REPO/logs and c:\\EVIDENCE\\report.json',
    },
    'C:\\Repo',
    'C:\\Evidence',
  );

  assert.deepEqual(normalized, {
    repository: '<repo>',
    evidence: '<repo>/logs and <evidence>\\report.json',
  });
});

test('runs two generator passes, rescans last, and reports the final head', async () => {
  const fixture = makeDependencies();
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig({ parallelism: 3 }),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.overallStatus, 'PASS');
  assert.equal(result.report.headSha, 'head123');
  assert.equal(result.report.reproducibility.status, 'PASS');
  assert.equal(fixture.executions.filter((event) => event.includes('generator-') && event.endsWith(':prisma-generate')).length, 2);
  assert.equal(fixture.written.length, 2);
  assert.equal(fixture.written[0].overallStatus, 'BLOCKED');
  assert.equal(fixture.written[1].overallStatus, 'PASS');
  assert.equal(fixture.written[1].repositorySeal.evidenceWrite.status, 'PASS');
  assert.deepEqual(result.paths, { json: 'report.json', markdown: 'report.md' });
});

test('admits the exact GitHub attestation before preflight or repository validation inspection', async () => {
  const fixture = makeDependencies();
  await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });

  const admission = fixture.events.indexOf('gate-attestation');
  assert.ok(admission >= 0);
  for (const event of ['preflight', 'gate-changes', 'suppression-scan:1', 'clean-tree']) {
    assert.ok(fixture.events.indexOf(event) > admission, `${event} ran before attestation admission`);
  }
});

test('runs no executable preflight or repository validation command when attestation admission is blocked', async () => {
  const fixture = makeDependencies({ admissionAttestationStatus: 'BLOCKED' });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });

  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.equal(fixture.executions.length, 0);
  assert.equal(fixture.events.includes('preflight'), false);
  assert.equal(fixture.events.includes('gate-changes'), false);
  assert.equal(fixture.events.some((event) => event.startsWith('suppression-scan:')), false);
  assert.equal(fixture.events.includes('clean-tree'), false);
});

test('passes only essential and explicitly configured environment variables to child commands', async () => {
  const requiredName = 'PR_CLOSEOUT_REQUIRED_TEST';
  const safeName = 'PR_CLOSEOUT_SAFE_TEST';
  const ambientName = 'PR_CLOSEOUT_AMBIENT_SECRET_TEST';
  const previous = Object.fromEntries(
    [requiredName, safeName, ambientName].map((name) => [name, process.env[name]]),
  );
  process.env[requiredName] = 'required-value';
  process.env[safeName] = 'safe-value';
  process.env[ambientName] = 'must-not-pass';
  try {
    const fixture = makeDependencies();
    let executorEnvironment;
    let preflightEnvironment;
    delete fixture.dependencies.execute;
    fixture.dependencies.createCommandExecutor = ({ env }) => {
      executorEnvironment = env;
      return async (check, phase) => passingExecution(check, phase);
    };
    fixture.dependencies.runPreflight = async ({ env }) => {
      preflightEnvironment = env;
      return { status: 'BLOCKED', checks: [], toolVersions: {} };
    };

    await runCloseoutWorkflow({
      repo: 'C:/repo',
      baseRef: 'origin/main',
      config: reviewedConfig({
        requiredEnv: [requiredName],
        safeEnv: [safeName],
      }),
      outputDir: 'C:/evidence',
      dependencies: fixture.dependencies,
    });

    for (const environment of [executorEnvironment, preflightEnvironment]) {
      assert.equal(environment[requiredName], 'required-value');
      assert.equal(environment[safeName], 'safe-value');
      assert.equal(environment[ambientName], undefined);
      assert.ok(environment.PATH || environment.Path);
    }
  } finally {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
});

test('default evidence directories include process uniqueness for concurrent same-ms starts', () => {
  // Codex #4780351874: timestamp-only names collide when two closeout
  // processes for the same repo+head start in the same millisecond.
  const a = defaultOutputDir('/tmp/my-repo', 'abcdef0123456789');
  const b = defaultOutputDir('/tmp/my-repo', 'abcdef0123456789');
  assert.notEqual(a, b);
  assert.match(a, /codex-pr-closeout/);
  assert.match(a, new RegExp(`${process.pid}-[0-9a-f]{8}`));
  assert.match(b, new RegExp(`${process.pid}-[0-9a-f]{8}`));
  assert.match(a, /abcdef012345/);
});

test('exclusive output-dir lock rejects a second concurrent holder', async () => {
  // Codex #4781560042: explicit --output-dir must not be shared.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-lock-'));
  try {
    const first = await acquireOutputDirLock(tmp);
    await assert.rejects(
      acquireOutputDirLock(tmp),
      /already locked by (this closeout process|closeout pid)/i,
    );
    // release() alone must free the directory (CodeRabbit #4781622077).
    await first.release();
    const second = await acquireOutputDirLock(tmp);
    await second.release();
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('exclusive output-dir lock reclaims a stale lock from a dead PID', async () => {
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-stale-lock-'));
  try {
    // Seed a lock naming a PID that cannot be alive on this host.
    await fs.writeFile(nodePath.join(tmp, '.closeout.lock'), '2147483646\nstale-nonce\n', 'utf8');
    const lock = await acquireOutputDirLock(tmp);
    assert.ok(lock.nonce);
    await lock.release();
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('exclusive output-dir lock does not reclaim a freshly created incomplete holder record', async () => {
  // `O_EXCL` exposes the path before writeFile(payload) resolves. A concurrent
  // contender must treat that short empty/partial window as owned, not unlink
  // the first process's active lock. Once the record is old, stale recovery
  // remains available for a creator that crashed before writing its payload.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-initializing-lock-'));
  const lockPath = nodePath.join(tmp, '.closeout.lock');
  try {
    await fs.writeFile(lockPath, '', 'utf8');
    await assert.rejects(acquireOutputDirLock(tmp), /still initializing/i);
    // A rejecting contender must leave the possibly live creator's record
    // alone; otherwise the rejection itself would break exclusivity.
    await fs.stat(lockPath);

    const old = new Date(Date.now() - 10_000);
    await fs.utimes(lockPath, old, old);
    const lock = await acquireOutputDirLock(tmp);
    assert.ok(lock.nonce);
    await lock.release();
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('exclusive output-dir lock revalidates a stale holder before reclaiming it', async () => {
  // A contender can only use the stale record it actually observed. This
  // simulates a newer holder appearing between the initial recovery read and
  // the reclaim step; the newer record must survive untouched.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-revalidate-lock-'));
  const lockPath = nodePath.join(tmp, '.closeout.lock');
  const successor = `${process.pid}\nsuccessor-nonce\n`;
  let reads = 0;
  try {
    await fs.writeFile(lockPath, successor, 'utf8');
    await assert.rejects(
      acquireOutputDirLock(tmp, {
        readLockFile: async () => {
          reads += 1;
          return reads === 1 ? '2147483646\nstale-nonce\n' : successor;
        },
      }),
      /already locked by this closeout process/i,
    );
    assert.equal(await fs.readFile(lockPath, 'utf8'), successor);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('exclusive output-dir lock lets only one concurrent stale reclaimer take over', async () => {
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-concurrent-reclaim-'));
  try {
    await fs.writeFile(nodePath.join(tmp, '.closeout.lock'), '2147483646\nstale-nonce\n', 'utf8');
    const attempts = await Promise.allSettled([
      acquireOutputDirLock(tmp),
      acquireOutputDirLock(tmp),
    ]);
    const acquired = attempts.filter(({ status }) => status === 'fulfilled').map(({ value }) => value);
    assert.equal(acquired.length, 1);
    assert.ok(acquired[0].nonce);
    await acquired[0].release();
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('exclusive output-dir lock release refuses a symlinked successor', async () => {
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-release-symlink-'));
  try {
    const lock = await acquireOutputDirLock(tmp);
    const replacement = nodePath.join(tmp, 'replacement-lock');
    await fs.unlink(lock.path);
    await fs.writeFile(replacement, `${process.pid}\n${lock.nonce}\n`, 'utf8');
    try {
      await fs.symlink(replacement, lock.path, 'file');
    } catch (error) {
      if (['EACCES', 'EPERM', 'ENOSYS'].includes(error?.code)) return;
      throw error;
    }
    await lock.release();
    // Node 20 on hosted Windows can report EPERM for lstat on a symlink it
    // just created. Resolving the successor still proves the relevant
    // contract: release did not unlink or replace the untrusted lock path.
    assert.equal(await fs.realpath(lock.path), await fs.realpath(replacement));
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('exclusive output-dir lock treats a special-file lock as corrupt and reclaims it', async () => {
  // Codex #UDDQC: a FIFO/symlinked .closeout.lock must never be followed or
  // block the recovery read; a guard failure takes the corrupt-lock path.
  // Windows cannot create FIFOs/symlinks without admin, so the special file
  // is simulated by injecting the guarded reader's rejection — the same
  // rejection readOutputDirLockFile raises for a non-regular descriptor.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-special-lock-'));
  try {
    // Seed content naming this process: if the guard were bypassed and the
    // raw file parsed, acquisition would throw "already locked" instead of
    // reclaiming — so this test fails unless the injected rejection ran.
    await fs.writeFile(nodePath.join(tmp, '.closeout.lock'), `${process.pid}\nforeign-nonce\n`, 'utf8');
    let guardCalls = 0;
    const lock = await acquireOutputDirLock(tmp, {
      readLockFile: async () => {
        guardCalls += 1;
        throw new Error('Evidence lock is not a size-bounded regular file.');
      },
    });
    assert.ok(guardCalls >= 1, 'recovery read must go through the guarded reader');
    assert.ok(lock.nonce);
    await lock.release();
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('exclusive output-dir lock rejects an oversized lock as not size-bounded', async () => {
  // Codex #UDDQC: the descriptor-verified cap rejects before the PID line is
  // parsed. The payload names this process, so a bypass of the size guard
  // would parse it and throw "already locked" instead of reclaiming.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-oversized-lock-'));
  try {
    await fs.writeFile(
      nodePath.join(tmp, '.closeout.lock'),
      `${process.pid}\n${'x'.repeat(8192)}\n`,
      'utf8',
    );
    const lock = await acquireOutputDirLock(tmp);
    assert.ok(lock.nonce);
    await lock.release();
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('release() unregisters the abrupt-exit listener across repeated runs', async () => {
  // Codex discussion_r3652957330 / CodeRabbit discussion_r3652923142: a
  // long-lived process running closeout repeatedly must not accumulate exit
  // listeners (the eleventh unreleased run would emit
  // MaxListenersExceededWarning).
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-exit-listeners-'));
  const warnings = [];
  const onWarning = (warning) => warnings.push(warning);
  process.on('warning', onWarning);
  const baseline = process.listenerCount('exit');
  try {
    for (let i = 0; i < 12; i += 1) {
      const lock = await acquireOutputDirLock(tmp);
      assert.equal(process.listenerCount('exit'), baseline + 1);
      await lock.release();
      assert.equal(process.listenerCount('exit'), baseline);
      await assert.rejects(fs.stat(nodePath.join(tmp, '.closeout.lock')));
    }
    assert.equal(process.listenerCount('exit'), baseline);
    assert.deepEqual(
      warnings.filter(({ name }) => name === 'MaxListenersExceededWarning'),
      [],
    );
  } finally {
    process.removeListener('warning', onWarning);
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('rejects a lexically external output whose physical target is inside the repository', async () => {
  const physical = new Map([
    ['C:/repo', 'C:/physical/repo'],
    ['C:/outside-link', 'C:/physical/repo/evidence'],
  ]);
  await assert.rejects(
    prepareOutputDirectory({
      repo: 'C:/repo',
      outputDir: 'C:/outside-link',
      mkdirPath: async () => {},
      realpathPath: async (target) => physical.get(target),
    }),
    /outside the repository/i,
  );
});

test('rejects an output-dir traversing a symlink into the repo before creating anything', async () => {
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'codex-pr-closeout-symlink-'));
  try {
    const repoRoot = nodePath.join(tmp, 'repo');
    const linkDir = nodePath.join(tmp, 'link-to-repo');
    const outputDir = nodePath.join(linkDir, 'evidence');
    await fs.mkdir(repoRoot, { recursive: true });
    try {
      await fs.symlink(repoRoot, linkDir, 'dir');
    } catch (error) {
      if (error && (error.code === 'EPERM' || error.code === 'EACCES' || error.code === 'ENOSYS')) {
        return;
      }
      throw error;
    }
    await assert.rejects(
      prepareOutputDirectory({ repo: repoRoot, outputDir }),
      /outside the repository/i,
    );
    await assert.rejects(
      fs.access(nodePath.join(repoRoot, 'evidence')),
      (error) => error && error.code === 'ENOENT',
    );
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('requires a clean initial tree before executing validation commands', async () => {
  const fixture = makeDependencies();
  let cleanReads = 0;
  fixture.dependencies.cleanTreeStatus = async () => {
    cleanReads += 1;
    return cleanReads === 1
      ? { status: 'FAIL', evidence: 'dirty before validation' }
      : { status: 'PASS', evidence: 'restored after validation' };
  };

  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });

  assert.equal(result.report.overallStatus, 'FAIL');
  assert.equal(result.report.initialTree.status, 'FAIL');
  assert.equal(fixture.executions.length, 0);
  // A dirty tree must also gate executable PREFLIGHT probes (Codex M6UFnGb):
  // they may run repository-local binaries or contact services, so they must
  // not launch against an unclean snapshot that admission will reject.
  assert.equal(fixture.events.includes('preflight'), false);
  assert.match(result.report.preflight.evidence, /initial working tree was not clean/i);
  assert.match(result.report.gateIntegrity.evidence, /initial working tree was not clean/i);
});

test('gives baseline setup and comparison executions unique parent and attempt identities', async () => {
  const fixture = makeDependencies();
  const baselineCalls = [];
  fixture.dependencies.execute = async (check, phase) => {
    fixture.executions.push(`${phase}:${check.id}`);
    const result = passingExecution(check, phase);
    if (phase === 'qualification' && check.id === 'git-diff-check') {
      return { ...result, status: 'FAIL', exitCode: 1, evidence: 'head failure' };
    }
    return result;
  };
  fixture.dependencies.verifyBaseline = async ({
    check,
    headResult,
    execute,
    setup,
  }) => {
    baselineCalls.push(await setup('C:/baseline'));
    baselineCalls.push(await execute(check, 'C:/baseline'));
    return headResult;
  };

  await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });

  assert.equal(baselineCalls.length, 2);
  assert.equal(baselineCalls[0].associatedCheckId, 'git-diff-check');
  assert.equal(baselineCalls[1].associatedCheckId, 'git-diff-check');
  assert.notEqual(baselineCalls[0].attemptId, baselineCalls[1].attemptId);
  assert.match(baselineCalls[0].id, /git-diff-check/);
  assert.match(baselineCalls[1].id, /git-diff-check/);
});

test('writes a blocked provisional report, seals after that write, then writes normalized final evidence', async () => {
  const fixture = makeDependencies();
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });

  assert.equal(fixture.written.length, 2);
  assert.equal(fixture.written[0].overallStatus, 'BLOCKED');
  assert.match(fixture.written[0].repositorySeal.evidence, /pending|provisional/i);
  assert.equal(fixture.written[1].repositorySeal.evidenceWrite.status, 'PASS');
  assert.equal(fixture.written[1].repository, '<repo>');
  assert.doesNotMatch(JSON.stringify(fixture.written[1]), /C:[/\\](?:repo|evidence)/i);
  assert.equal(result.report.repositorySeal.evidenceWrite.status, 'PASS');

  const firstWrite = fixture.events.indexOf('report-write:1');
  const secondWrite = fixture.events.indexOf('report-write:2');
  assert.ok(firstWrite >= 0 && secondWrite > firstWrite);
  assert.ok(
    fixture.events.slice(firstWrite + 1, secondWrite).some((event) => event.startsWith('repository-state:')),
    'repository identity was not re-read between provisional and final report writes',
  );
});

test('fails closeout when the final suppression rescan finds a marker', async () => {
  const fixture = makeDependencies({
    finalFindings: [{ file: 'src/a.ts', line: 4, category: 'marker', match: 'forbidden' }],
  });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.overallStatus, 'FAIL');
  assert.equal(result.report.suppressionFindings.length, 1);
});

test('blocks evidence when HEAD changes during validation', async () => {
  const fixture = makeDependencies({ finalHead: 'different-head' });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.match(result.report.headConsistency.evidence, /changed during validation/i);
});

test('blocks evidence when the live base moves during validation', async () => {
  const fixture = makeDependencies({ finalBase: 'different-base' });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.match(result.report.headConsistency.evidence, /base changed during validation/i);
});

test('seals repository identity again after live PR verification', async () => {
  const fixture = makeDependencies({ sealHead: 'post-github-drift' });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.equal(result.report.repositorySeal.status, 'BLOCKED');
  assert.match(result.report.repositorySeal.evidence, /post-github-drift/);
});

test('blocks evidence when the base moves after live PR verification', async () => {
  const fixture = makeDependencies({ sealBase: 'post-github-base-drift' });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.match(result.report.repositorySeal.evidence, /post-github-base-drift/);
});

test('re-reads repository identity after final scans to catch late commits', async () => {
  const fixture = makeDependencies({ lateSealHead: 'late-head-during-scan' });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.match(result.report.repositorySeal.evidence, /late-head-during-scan/);
});

test('rejects evidence output inside the repository before validation starts', async () => {
  const fixture = makeDependencies();
  await assert.rejects(
    runCloseoutWorkflow({
      repo: 'C:/repo',
      baseRef: 'origin/main',
      config: reviewedConfig(),
      outputDir: 'C:/repo/evidence',
      dependencies: fixture.dependencies,
    }),
    /outside the repository/i,
  );
  assert.equal(fixture.executions.length, 0);
});

test('binds every validation-affecting config field into the review digest', async () => {
  const baseConfig = reviewedConfig({
    requiredEnv: ['TOKEN'],
    timeoutMs: 1000,
    timeoutsMs: { typecheck: 2000 },
    minFreeDiskGb: 3,
    ports: [3000],
    reproducibilityPaths: ['generated/client'],
    parallelism: 2,
  });
  const planDigest = async (config) => {
    const fixture = makeDependencies();
    fixture.dependencies.digestValidationConfig = digestValidationConfig;
    const result = await runCloseoutWorkflow({
      repo: 'C:/repo',
      baseRef: 'origin/main',
      config,
      planOnly: true,
      dependencies: fixture.dependencies,
    });
    return result.configDigest;
  };
  const original = await planDigest(baseConfig);
  const variants = [
    { ...baseConfig, requiredEnv: ['TOKEN', 'SECOND_TOKEN'] },
    { ...baseConfig, timeoutMs: 1001 },
    { ...baseConfig, timeoutsMs: { typecheck: 2001 } },
    { ...baseConfig, minFreeDiskGb: 4 },
    { ...baseConfig, ports: [3001] },
    { ...baseConfig, reproducibilityPaths: ['generated/other'] },
    { ...baseConfig, parallelism: 3 },
    { ...baseConfig, services: { ...baseConfig.services, redis: { host: '127.0.0.2', port: 6379 } } },
  ];
  for (const variant of variants) assert.notEqual(await planDigest(variant), original);
});

test('plan emits a live GitHub attestation marker and rejects legacy self-attestation', async () => {
  const fixture = makeDependencies();
  const plan = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    planOnly: true,
    dependencies: fixture.dependencies,
  });
  assert.equal(plan.gateIntegrityAttestationRequired.provider, 'github-pull-request-review');
  assert.match(plan.gateIntegrityAttestationRequired.marker, /PR-CLOSEOUT-ATTESTATION v1/);

  const legacy = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig({ gateIntegrityReview: { decision: 'not-weakened' } }),
    planOnly: true,
    dependencies: fixture.dependencies,
  });
  assert.equal(legacy.planStatus, 'FAIL');
  assert.match(legacy.errors.join(' '), /self-attestation|gateIntegrityReview/i);
});

test('does not execute validation without independent live gate attestation', async () => {
  const fixture = makeDependencies({ admissionAttestationStatus: 'BLOCKED' });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.equal(fixture.executions.length, 0);
});

test('blocks final evidence when the GitHub attestation is no longer valid', async () => {
  const fixture = makeDependencies({ finalAttestationStatus: 'BLOCKED' });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(fixture.executions.length > 0, true);
  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.equal(result.report.gateIntegrity.status, 'BLOCKED');
});

test('preserves exact plan blocker evidence in final mandatory rows', async () => {
  const fixture = makeDependencies();
  const commands = { ...configuredCommands };
  delete commands['producer-tests'];
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig({ commands }),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.match(
    result.report.checks.find(({ id }) => id === 'producer-tests').evidence,
    /No authoritative command resolved for Focused producer tests/i,
  );
});

test('blocks completion when final live GitHub PR state is not clean', async () => {
  const fixture = makeDependencies({ livePrStatus: 'BLOCKED' });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.equal(result.report.livePrState.status, 'BLOCKED');
});

test('overall status never treats baseline, residual findings, or dirty output as clean', () => {
  const base = {
    planStatus: 'PASS',
    preflight: { status: 'PASS' },
    gateIntegrity: { status: 'PASS' },
    phases: { status: 'PASS' },
    reproducibility: { status: 'PASS' },
    preGithubCleanTree: { status: 'PASS' },
    cleanTree: { status: 'PASS' },
    headConsistency: { status: 'PASS' },
    repositorySeal: { status: 'PASS' },
    livePrState: { status: 'PASS' },
    suppressionFindings: [],
  };
  assert.equal(evaluateOverallStatus(base), 'PASS');
  assert.equal(evaluateOverallStatus({ ...base, phases: { status: 'BASELINE' } }), 'BLOCKED');
  assert.equal(evaluateOverallStatus({ ...base, suppressionFindings: [{}] }), 'FAIL');
  assert.equal(evaluateOverallStatus({ ...base, cleanTree: { status: 'FAIL' } }), 'FAIL');
  // Pre-GitHub dirt is first-class: even when the final tree is clean, a dirty
  // pre-GitHub probe must still fail (or block) overall status.
  assert.equal(evaluateOverallStatus({ ...base, preGithubCleanTree: { status: 'FAIL' } }), 'FAIL');
  assert.equal(evaluateOverallStatus({ ...base, preGithubCleanTree: { status: 'BLOCKED' } }), 'BLOCKED');
});

test('writes exactly 19 final mandatory rows when admission is blocked', async () => {
  const fixture = makeDependencies();
  fixture.dependencies.runPreflight = async () => ({
    status: 'BLOCKED',
    checks: [{ name: 'redis', status: 'BLOCKED', evidence: 'unavailable' }],
    toolVersions: {},
  });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });

  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.equal(result.report.checks.length, MANDATORY_CHECKS.length);
  assert.deepEqual(result.report.checks.map(({ id }) => id), MANDATORY_CHECKS.map(({ id }) => id));
  assert.ok(result.report.checks.every(({ phase, status }) => phase === 'confirmation' && status === 'BLOCKED'));
  assert.deepEqual(result.report.qualificationChecks, []);
});

test('preserves the Unix shell override in the workflow environment', async () => {
  const previous = process.env.OMO_CODEX_SHELL_PATH;
  process.env.OMO_CODEX_SHELL_PATH = '/opt/custom/bin/bash';
  try {
    const fixture = makeDependencies();
    let executorEnvironment;
    let preflightEnvironment;
    delete fixture.dependencies.execute;
    fixture.dependencies.createCommandExecutor = ({ env }) => {
      executorEnvironment = env;
      return async (check, phase) => passingExecution(check, phase);
    };
    fixture.dependencies.runPreflight = async ({ env }) => {
      preflightEnvironment = env;
      return { status: 'BLOCKED', checks: [], toolVersions: {} };
    };

    await runCloseoutWorkflow({
      repo: 'C:/repo',
      baseRef: 'origin/main',
      config: reviewedConfig(),
      outputDir: 'C:/evidence',
      dependencies: fixture.dependencies,
    });

    assert.equal(executorEnvironment.OMO_CODEX_SHELL_PATH, '/opt/custom/bin/bash');
    assert.equal(preflightEnvironment.OMO_CODEX_SHELL_PATH, '/opt/custom/bin/bash');
  } finally {
    if (previous === undefined) delete process.env.OMO_CODEX_SHELL_PATH;
    else process.env.OMO_CODEX_SHELL_PATH = previous;
  }
});

test('preserves failed generator execution details in the row and baseline signature', async () => {
  // A generator run that fails is returned by verifyGeneratorReproducibility
  // as the top-level result rather than under first/second; the final row and
  // the head-side baseline comparison must keep the real exit code, output,
  // and timing so an identical failure at base can match.
  const fixture = makeDependencies();
  let baselineHeadResult;
  fixture.dependencies.execute = async (check, phase) => {
    fixture.executions.push(`${phase}:${check.id}`);
    const result = passingExecution(check, phase);
    if (check.id === 'prisma-generate' && phase === 'confirmation-generator-1') {
      return {
        ...result,
        status: 'FAIL',
        exitCode: 17,
        stdout: 'generator exploded',
        stderr: 'boom',
        evidence: 'generator failed',
      };
    }
    return result;
  };
  fixture.dependencies.verifyBaseline = async ({ headResult }) => {
    baselineHeadResult = headResult;
    return headResult;
  };

  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });

  const row = result.report.checks.find(({ id }) => id === 'prisma-generate');
  assert.equal(row.status, 'FAIL');
  assert.equal(row.exitCode, 17);
  assert.equal(row.stdout, 'generator exploded');
  assert.equal(row.stderr, 'boom');
  assert.equal(row.startedAt, '2026-07-14T00:00:00.000Z');
  assert.equal(row.durationMs, 1);
  assert.equal(baselineHeadResult.exitCode, 17);
  assert.equal(baselineHeadResult.stdout, 'generator exploded');
});

test('seals ignored generated output paths after all checks', async () => {
  // Generated outputs under ignored paths are invisible to cleanTreeStatus
  // and the tracked-diff hash. A mutation landing after live GitHub
  // verification must trip the repository seal, so every post-validation and
  // evidence-write fingerprint is bound to the reproducibility paths.
  const fixture = makeDependencies();
  const fingerprintCalls = [];
  fixture.dependencies.workingTreeFingerprint = async (repo, extraPaths = []) => {
    fingerprintCalls.push(extraPaths);
    return extraPaths.length && fingerprintCalls.length > 4 ? 'generated-mutated' : 'stable-tree';
  };

  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig({ reproducibilityPaths: ['generated/client'] }),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });

  assert.equal(result.report.repositorySeal.status, 'BLOCKED');
  assert.match(result.report.repositorySeal.evidence, /fingerprint changed after live GitHub verification/i);
  assert.equal(result.report.overallStatus, 'BLOCKED');
  assert.ok(fingerprintCalls.length >= 4);
  for (const extraPaths of fingerprintCalls) {
    assert.deepEqual(extraPaths, ['node_modules/.prisma', 'node_modules/@prisma/client', 'generated/client']);
  }
});
