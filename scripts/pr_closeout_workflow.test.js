const assert = require('node:assert/strict');
const test = require('node:test');

const { MANDATORY_CHECKS } = require('./pr_closeout_core');
const { digestValidationConfig } = require('./pr_closeout_git');
const {
  acquireOutputDirLock,
  assertOutputDirLockIdentity,
  defaultOutputDir,
  evaluateOverallStatus,
  isSameLockIdentity,
  mergeEngineTimeouts,
  normalizePersistedPaths,
  prepareOutputDirectory,
  resolvePlanAdmission,
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
      readProjectMetadata: async () => ({
        packageScripts: {},
        makeTargets: ['smoke', 'sbom', 'audit', 'pr-check'],
        // The fixed make-smoke/make-sbom/make-audit/make-pr-check checks
        // require a captured, non-neutralizing recipe before they resolve
        // (Codex UsPVX) -- an absent entry fails closed exactly like an
        // unresolved makeCandidates recipe. Supply clean stand-ins so this
        // fixture exercises the intended "trusted, inspected recipe" path
        // rather than incidentally proving the fail-closed path instead.
        makeRecipes: {
          smoke: 'node scripts/smoke.js',
          sbom: 'node scripts/sbom.js',
          audit: 'node scripts/audit.js',
          'pr-check': 'npm test',
        },
      }),
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

test('production DEFAULTS wires a real prepareOutputDirectory for non-plan runs (no dependency override)', async () => {
  // Every other full-workflow test above stubs prepareOutputDirectory in the
  // shared fixture, so none of them would notice if DEFAULTS.prepareOutputDirectory
  // were ever removed or misassigned (Qodo #4790675668's "d.prepareOutputDirectory
  // is not a function" concern). Omit the override here so runCloseoutWorkflow
  // falls back to the real DEFAULTS implementation and prove it actually runs by
  // observing its real filesystem side effect: the output directory getting created.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-real-prepare-'));
  const repoRoot = nodePath.join(tmp, 'repo');
  const outputDir = nodePath.join(tmp, 'evidence');
  await fs.mkdir(repoRoot, { recursive: true });
  try {
    const fixture = makeDependencies();
    // resolveRepositoryState (not the repo argument below) is what actually
    // feeds prepareOutputDirectory's realpath check; point it at the real
    // temp repo so the real implementation has something to resolve.
    const resolveState = fixture.dependencies.resolveRepositoryState;
    fixture.dependencies.resolveRepositoryState = async (...args) => ({
      ...(await resolveState(...args)),
      repo: repoRoot,
    });
    delete fixture.dependencies.prepareOutputDirectory;
    const result = await runCloseoutWorkflow({
      repo: repoRoot,
      baseRef: 'origin/main',
      config: reviewedConfig(),
      outputDir,
      dependencies: fixture.dependencies,
    });
    assert.equal(result.report.overallStatus, 'PASS');
    // A stubbed prepareOutputDirectory never touches the filesystem, so this
    // only succeeds if the real DEFAULTS implementation actually ran.
    assert.ok((await fs.stat(outputDir)).isDirectory());
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
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

test('exclusive output-dir lock does not delete a successor lock after a guard-failure read', async () => {
  // Codex Uert4: when the guarded recovery read itself throws (FIFO/symlink/
  // oversized lock), staleSnapshot stays null and the byte-for-byte
  // revalidation used for parsed records is unavailable. An unconditional
  // rename in that case would quarantine whatever now occupies the path --
  // including a legitimate successor lock a peer created after reclaiming
  // the same guard failure first. Simulate that race: the very first guarded
  // read swaps the lock file out from under this contender (as if a peer had
  // already quarantined it and created its own fresh lock) before throwing
  // the guard error, so the independently-captured staleIdentity must be the
  // thing that stops the rename, not the content comparison.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-guard-failure-race-'));
  const lockPath = nodePath.join(tmp, '.closeout.lock');
  const successor = `${process.pid}\nsuccessor-nonce\n`;
  let reads = 0;
  try {
    await fs.writeFile(lockPath, '2147483646\nstale-nonce\n', 'utf8');
    await assert.rejects(
      acquireOutputDirLock(tmp, {
        readLockFile: async () => {
          reads += 1;
          if (reads === 1) {
            await fs.unlink(lockPath);
            await fs.writeFile(lockPath, successor, 'utf8');
            throw new Error('Evidence lock is not a size-bounded regular file.');
          }
          return successor;
        },
      }),
      /already locked by this closeout process/i,
    );
    // Do not assert an exact read count here. Two paths are both correct
    // product behavior: the identity-mismatch-only path (2 reads) and, when a
    // same-millisecond reused-inode collision defeats the dev/ino/ctimeMs
    // guard, the collision-recovery path (quarantine -> re-read -> restore,
    // which spends a 3rd guarded read before restoring the successor). Assert
    // only the externally-visible invariants that hold for both: the successor
    // survives (below) and the reclaim is rejected (assert.rejects above).
    assert.equal(await fs.readFile(lockPath, 'utf8'), successor);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('restores a live successor lock when a guard-failure identity match is later proven wrong', async () => {
  // Codex UgisL/UguCX/Uert4/UikNw: dev/ino/ctimeMs identity alone has only
  // filesystem/clock resolution, so it cannot fully rule out a
  // same-millisecond reused-inode collision between the true stale entry
  // and a peer's freshly created live successor. Model that gap directly:
  // the guard read fails against the real, untouched stale file (so the
  // dev/ino/ctimeMs identity captured before and after the throw
  // legitimately/correctly match -- nothing has changed on disk), which is
  // exactly the situation an unavoidable collision would also produce.
  // The post-quarantine re-read is mocked to report a parseable live
  // successor record, and the fix must restore the quarantined entry to
  // its original pathname rather than deleting it.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-guard-collision-'));
  const lockPath = nodePath.join(tmp, '.closeout.lock');
  const staleContent = '2147483646\nstale-nonce\n';
  const successor = `${process.pid}\nsuccessor-nonce\n`;
  let reads = 0;
  try {
    await fs.writeFile(lockPath, staleContent, 'utf8');
    await assert.rejects(
      acquireOutputDirLock(tmp, {
        readLockFile: async () => {
          reads += 1;
          if (reads === 1) throw new Error('Evidence lock is not a size-bounded regular file.');
          // Every subsequent read (the post-quarantine re-verification, and
          // the next attempt's guard read once the entry is restored)
          // reports the live successor's real content.
          return successor;
        },
      }),
      /already locked by this closeout process/i,
    );
    assert.equal(
      reads,
      3,
      'must re-verify the quarantined entry once, restore it, then re-discover it as the live holder on retry',
    );
    assert.equal(
      await fs.readFile(lockPath, 'utf8'),
      staleContent,
      'the quarantined entry must be restored to its original pathname, not deleted',
    );
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('restores a live successor lock created between the byte-for-byte check and quarantine rename', async () => {
  // Codex Ukpki: the byte-for-byte verification read (just before the
  // quarantine rename) is not atomic with that rename, so a concurrent
  // reclaimer that read the same stale content can create its own live lock
  // at lockPath in the gap between the two -- and an unconditional rename
  // would then quarantine that live successor instead of the stale entry.
  // Model the gap directly: the verification read reports the stale content
  // still matched (so the rename proceeds) but, as a side effect of that
  // same read, a peer's live lock actually lands on disk at lockPath first.
  // The post-quarantine re-verification must catch the mismatch and restore
  // the successor rather than deleting it.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-byte-for-byte-race-'));
  const lockPath = nodePath.join(tmp, '.closeout.lock');
  const staleContent = '2147483646\nstale-nonce\n';
  const successor = `${process.pid}\nsuccessor-nonce\n`;
  let reads = 0;
  try {
    await fs.writeFile(lockPath, staleContent, 'utf8');
    await assert.rejects(
      acquireOutputDirLock(tmp, {
        readLockFile: async (p) => {
          reads += 1;
          if (reads === 1) return staleContent;
          if (reads === 2) {
            // A peer's live lock lands on disk here, right after this
            // contender's verification read reported the stale content
            // still matched.
            await fs.writeFile(lockPath, successor, 'utf8');
            return staleContent;
          }
          return fs.readFile(p, 'utf8');
        },
      }),
      /already locked by this closeout process/i,
    );
    assert.equal(
      reads,
      4,
      'must verify byte-for-byte, quarantine, re-verify post-quarantine, then re-discover the restored successor on retry',
    );
    assert.equal(
      await fs.readFile(lockPath, 'utf8'),
      successor,
      'the live successor must be restored, not deleted as if it were the stale entry',
    );
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('restores an initializing successor whose quarantined payload is byte-different from the stale snapshot but does not parse', async () => {
  // CodeRabbit UnT4B / qodo UnB_K: the post-quarantine content check must
  // restore on *byte-difference from the authorized stale snapshot*, not on
  // whether the quarantined payload parses. A peer can create its successor
  // via O_EXCL and be quarantined before it has awaited its payload write --
  // an empty/partial record that is neither byte-identical to staleSnapshot
  // nor yet parseable. Deleting it (the pre-fix behavior, which restored only
  // when outputDirLockHolder parsed a holder) frees the pathname while the
  // peer still owns an open descriptor, letting both processes believe they
  // hold the lock. Model the gap directly: the byte-for-byte verification read
  // reports the stale content still matched (so the rename proceeds) but, as a
  // side effect of that same read, a peer's still-initializing (empty)
  // successor lands on disk at lockPath. Post-quarantine that unparseable,
  // byte-different payload must be restored, not deleted.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-initializing-successor-'));
  const lockPath = nodePath.join(tmp, '.closeout.lock');
  const staleContent = '2147483646\nstale-nonce\n';
  // Empty payload: a peer created the lock via O_EXCL but has not yet written
  // its pid/nonce. It is byte-different from staleContent and does not parse.
  const initializingSuccessor = '';
  let reads = 0;
  try {
    await fs.writeFile(lockPath, staleContent, 'utf8');
    await assert.rejects(
      acquireOutputDirLock(tmp, {
        readLockFile: async (p) => {
          reads += 1;
          if (reads === 1) return staleContent;
          if (reads === 2) {
            // Right after this contender's verification read reports the
            // stale content still matched, a peer's initializing (empty)
            // successor lands on disk at lockPath.
            await fs.writeFile(lockPath, initializingSuccessor, 'utf8');
            return staleContent;
          }
          return fs.readFile(p, 'utf8');
        },
      }),
      // Whichever legitimate reason it rejects for, it must not return a lock:
      // restoring the initializing successor and re-discovering it on retry
      // yields "still initializing"; it must never delete the successor and
      // acquire the freed pathname.
      /still initializing|already locked/i,
    );
    assert.equal(
      await fs.readFile(lockPath, 'utf8'),
      initializingSuccessor,
      'the byte-different, unparseable initializing successor must be restored, not deleted',
    );
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('isSameLockIdentity does not treat a reused inode as the same file', () => {
  // Codex Uert4 follow-up: CI on Linux (tmpfs /tmp) showed that unlinking a
  // stale lock and immediately writing a successor can hand the successor
  // the exact same dev/ino the stale snapshot recorded -- a plain
  // unlink()+create() is free to reuse a just-freed inode number. A pure
  // dev/ino/nlink comparison would then wrongly call the successor "the same
  // file" and let a guard-failure reclaim quarantine it. ctimeMs must also
  // match: a freshly created file (even on a reused inode) always gets a new
  // change time the original snapshot cannot share.
  const stale = { ino: 42, dev: 1, nlink: 1, ctimeMs: 1000 };
  const reusedInodeSuccessor = { ino: 42, dev: 1, nlink: 1, ctimeMs: 2000 };
  const untouchedSameFile = { ino: 42, dev: 1, nlink: 1, ctimeMs: 1000 };
  assert.equal(isSameLockIdentity(stale, reusedInodeSuccessor), false);
  assert.equal(isSameLockIdentity(stale, untouchedSameFile), true);
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

test('exclusive output-dir lock release refuses an unverified successor', async () => {
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-release-unverified-'));
  try {
    // The guarded reader is the same no-follow, bounded descriptor reader
    // used for actual symlink/FIFO successors. Inject its rejection so this
    // release test exercises the fail-closed path on every supported Node,
    // including Node 20 Windows where reparse-point metadata is unavailable.
    const lock = await acquireOutputDirLock(tmp, {
      readLockFile: async () => {
        throw new Error('Evidence lock is not a size-bounded regular file.');
      },
    });
    await lock.release();
    const retained = await fs.readFile(lock.path, 'utf8');
    assert.match(retained, new RegExp(`\\n${lock.nonce.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')}\\n`));
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('release() keeps the abrupt-exit safety net registered when it cannot confirm the lock was cleared', async () => {
  // CodeRabbit review (pr_closeout_workflow.js:365): the release() path used
  // to mark the lock "released" and unregister the exit-time safety net
  // unconditionally, even when the read/unlink that verifies this process
  // still owns the on-disk record failed. If the lock file was in fact still
  // there naming this process's own live PID, that left the output directory
  // permanently blocked for the rest of this long-lived process's life, with
  // no exit-time fallback left to clean it up either. The listener must stay
  // registered until removal is actually confirmed.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-release-listener-'));
  const baseline = process.listeners('exit');
  let added = [];
  try {
    const lock = await acquireOutputDirLock(tmp, {
      readLockFile: async () => {
        throw new Error('Evidence lock is not a size-bounded regular file.');
      },
    });
    added = process.listeners('exit').filter((fn) => !baseline.includes(fn));
    assert.equal(added.length, 1);
    await lock.release();
    // The unverifiable release above must not have unregistered the safety
    // net: the lock file (still naming this process) is confirmed retained
    // by the sibling test above, so the exit listener must still be armed to
    // clean it up if this process exits abruptly.
    assert.deepEqual(process.listeners('exit').filter((fn) => !baseline.includes(fn)), added);
  } finally {
    added.forEach((fn) => process.removeListener('exit', fn));
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

test('prepareOutputDirectory rejects when the locked output directory was swapped for a new one at the same path', async () => {
  // Codex: "Bind the evidence lock to the output directory inode." Without
  // verifyLock, a same-user removal + recreation of the locked evidence
  // directory between two prepareOutputDirectory calls in one closeout run
  // goes unnoticed — the lock file's own name-based checks are satisfied
  // again by the replacement directory, but it is not the directory the
  // exclusive lock was actually acquired against.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-dir-swap-'));
  const repoRoot = nodePath.join(tmp, 'repo');
  const outputDir = nodePath.join(tmp, 'evidence');
  await fs.mkdir(repoRoot, { recursive: true });
  await fs.mkdir(outputDir, { recursive: true });
  const lock = await acquireOutputDirLock(outputDir);
  await lock.release();
  try {
    // Not yet swapped: the lock's recorded identity still matches.
    await prepareOutputDirectory({ repo: repoRoot, outputDir, verifyLock: lock });

    // Rename the original out of the way (keeping its inode allocated)
    // instead of removing it, then mkdir a fresh directory at outputDir.
    // Deleting-then-recreating at the same path is not a reliable way to
    // force a new inode number: on filesystems like ext4, a freshly freed
    // inode can be handed straight back to the very next mkdir when nothing
    // else was allocated in between, which is exactly what happened in a
    // tight temp directory on Linux CI and made this test flake. Keeping the
    // original directory alive elsewhere guarantees the replacement gets a
    // genuinely unused inode, and it doubles as a more realistic model of a
    // same-user swap (rename/mount the real thing out, put a decoy in).
    await fs.rename(outputDir, nodePath.join(tmp, 'evidence-displaced'));
    await fs.mkdir(outputDir, { recursive: true });

    await assert.rejects(
      prepareOutputDirectory({ repo: repoRoot, outputDir, verifyLock: lock }),
      /changed identity/i,
    );
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('acquireOutputDirLock refuses to record a directory identity the filesystem reports as dev/ino 0', async () => {
  // Some Windows filesystems report dev/ino as 0 for every path. Recording
  // that as the lock's dirIdentity would make every later swap-detection
  // comparison pass vacuously (0 === 0) for a same-path replacement, so
  // acquisition itself must fail closed instead.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-zero-identity-'));
  try {
    await assert.rejects(
      acquireOutputDirLock(tmp, { statPath: async () => ({ dev: 0, ino: 0 }) }),
      /usable directory identity/i,
    );
    // The lock file created before the identity check must not be left
    // behind, or every subsequent acquisition attempt would see it as a
    // pre-existing (and never-reclaimable, since no process holds it) lock.
    const lockStillExists = await fs.stat(nodePath.join(tmp, '.closeout.lock')).then(() => true, () => false);
    assert.equal(lockStillExists, false);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('acquireOutputDirLock cleans up the lock file when statPath rejects outright', async () => {
  // CodeRabbit review (pr_closeout_workflow.js:333): the ino===0 branch above
  // closes the handle and unlinks the lock, but a rejecting statPath call
  // (EACCES/ENOENT/EIO) previously escaped with none of that cleanup: the
  // lock file stayed on disk naming this process's live PID, with no exit
  // listener registered, permanently blocking the output directory for every
  // subsequent run.
  const fs = require('node:fs/promises');
  const os = require('node:os');
  const nodePath = require('node:path');
  const tmp = await fs.mkdtemp(nodePath.join(os.tmpdir(), 'closeout-statpath-reject-'));
  try {
    await assert.rejects(
      acquireOutputDirLock(tmp, {
        statPath: async () => { throw Object.assign(new Error('denied'), { code: 'EACCES' }); },
      }),
      /denied/,
    );
    const lockStillExists = await fs.stat(nodePath.join(tmp, '.closeout.lock')).then(() => true, () => false);
    assert.equal(lockStillExists, false);
  } finally {
    await fs.rm(tmp, { recursive: true, force: true });
  }
});

test('assertOutputDirLockIdentity rejects a zero/zero identity even though dev and ino both compare equal', async () => {
  // The only way the dev/ino comparison can pass vacuously for a genuine
  // swap is when both stats report the *same* values despite naming
  // different underlying directories — which on a filesystem that always
  // reports ino 0 means dev/ino both read 0/0 on both sides. A mismatched
  // ino (e.g. 42 vs 0) is already caught by the plain inequality check and
  // is not the case this guard exists for.
  const fakeLock = { dirIdentity: { dev: 0, ino: 0 } };
  await assert.rejects(
    assertOutputDirLockIdentity(fakeLock, 'C:/evidence', {
      statPath: async () => ({ dev: 0, ino: 0 }),
    }),
    /changed identity/i,
  );
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
  // Fail control for the BASELINE reclassification companion test below: with a
  // passthrough verifyBaseline the head FAIL is not reclassified, so it must
  // propagate into the shared reproducibility status (which evaluateOverallStatus
  // reads independently of the row) and into the overall verdict. Without this,
  // nothing pins reproducibility.status/overallStatus for the un-reclassified
  // generator-failure case, so a regression that stopped propagating the
  // failure could slip through green.
  assert.equal(result.report.reproducibility.status, 'FAIL');
  assert.equal(result.report.overallStatus, 'FAIL');
});

test('propagates a generator baseline reclassification into the shared reproducibility status', async () => {
  // Codex UeruN: verifyBaseline can reclassify a generator confirmation row
  // away from its head FAIL (e.g. to BASELINE, when the failure reproduces
  // exactly at the base commit). evaluateOverallStatus reads `reproducibility`
  // as an input separate from the row itself, and FAIL outranks
  // BASELINE/BLOCKED there, so a stale reproducibility.status would still
  // report the whole run as FAIL even though the row was resolved to BASELINE.
  const fixture = makeDependencies();
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
  // Only reclassify a row that actually failed at head, matching the real
  // verifyBaseline contract (mirror FAIL -> BASELINE when it reproduces at
  // base; pass any non-FAIL row through untouched). This keeps a future change
  // that started routing passing rows through verifyBaseline from silently
  // holding the BASELINE/BLOCKED assertions below green.
  fixture.dependencies.verifyBaseline = async ({ headResult }) =>
    headResult.status === 'FAIL'
      ? {
        ...headResult,
        status: 'BASELINE',
        blocking: true,
        evidence: 'Failure reproduced exactly at base commit; not a regression.',
      }
      : headResult;

  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });

  const row = result.report.checks.find(({ id }) => id === 'prisma-generate');
  assert.equal(row.status, 'BASELINE');
  assert.equal(result.report.reproducibility.status, 'BASELINE');
  assert.equal(result.report.overallStatus, 'BLOCKED');
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

test('config.mode is rejected before any repository work — mode comes only from the invocation', async () => {
  await assert.rejects(
    () => runCloseoutWorkflow({
      repo: process.cwd(),
      baseRef: 'origin/main',
      config: { mode: 'engine' },
      planOnly: true,
      dependencies: {
        resolveRepositoryState: async () => { throw new Error('must not be called'); },
      },
    }),
    /mode cannot be set from config/,
  );
});

const planDeps = (digests) => ({
  resolveRepositoryState: async ({ repo, baseRef }) => ({
    repo, baseRef, baseSha: 'basesha000', headSha: 'headsha000', mergeBaseSha: 'mergebase000', touchedFiles: [],
  }),
  readProjectMetadata: async () => ({ packageScripts: {}, makeTargets: [], makeRecipes: {} }),
  digestValidationConfig: (value) => {
    digests.push(value);
    return `digest-${digests.length}`;
  },
  // Task 5's admission block now runs unconditionally in plan mode; fake
  // these three so this digest-focused test doesn't pay for a real `gh`
  // round trip (and its 60s execFile timeout) on every invocation.
  readLiveGateAttestation: async () => ({ status: 'BLOCKED', evidence: 'no matching attestation' }),
  cleanTreeStatus: async () => ({ status: 'PASS', evidence: 'clean' }),
  runPreflight: async () => ({ status: 'PASS', checks: [], toolVersions: {} }),
});

test('the validation-config digest binds the mode (schemaVersion 3)', async () => {
  const digests = [];
  await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, config: {},
    dependencies: planDeps(digests),
  });
  await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, mode: 'engine',
    config: { engineChecks: [{ id: 'unit', command: 'cargo test' }] },
    dependencies: planDeps(digests),
  });
  assert.equal(digests[0].schemaVersion, 3);
  assert.equal(digests[0].mode, 'strict');
  assert.equal(digests[1].mode, 'engine');
});

test('strict and engine digests differ even for identical config bytes, and a matrix edit changes the engine digest', async () => {
  const { digestValidationConfig } = require('./pr_closeout_git');
  const realDeps = () => ({
    resolveRepositoryState: async ({ repo, baseRef }) => ({
      repo, baseRef, baseSha: 'basesha000', headSha: 'headsha000', mergeBaseSha: 'mergebase000', touchedFiles: [],
    }),
    readProjectMetadata: async () => ({ packageScripts: {}, makeTargets: [], makeRecipes: {} }),
    digestValidationConfig,
    // Same reasoning as planDeps above: avoid a real `gh` round trip per
    // invocation now that plan mode resolves admission unconditionally.
    readLiveGateAttestation: async () => ({ status: 'BLOCKED', evidence: 'no matching attestation' }),
    cleanTreeStatus: async () => ({ status: 'PASS', evidence: 'clean' }),
    runPreflight: async () => ({ status: 'PASS', checks: [], toolVersions: {} }),
  });
  const strictPlan = await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, config: {}, dependencies: realDeps(),
  });
  const enginePlan = await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, mode: 'engine',
    config: { engineChecks: [{ id: 'unit', command: 'cargo test' }] }, dependencies: realDeps(),
  });
  const editedPlan = await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, mode: 'engine',
    config: { engineChecks: [{ id: 'unit', command: 'cargo test --all' }] }, dependencies: realDeps(),
  });
  assert.notEqual(strictPlan.configDigest, enginePlan.configDigest);
  assert.notEqual(enginePlan.configDigest, editedPlan.configDigest);
  assert.equal(strictPlan.mode, 'strict');
  assert.equal(enginePlan.mode, 'engine');
});

test('mergeEngineTimeouts lets inline engine timeouts win over config.timeoutsMs', () => {
  assert.deepEqual(
    mergeEngineTimeouts({ unit: 5000, lint: 7000 }, [
      { id: 'unit', timeoutMs: 9000 },
      { id: 'style' },
    ]),
    { unit: 9000, lint: 7000 },
  );
  assert.deepEqual(mergeEngineTimeouts(undefined, [{ id: 'a', timeoutMs: 100 }]), { a: 100 });
  assert.deepEqual(mergeEngineTimeouts({ a: 1 }, []), { a: 1 });
});

test('resolvePlanAdmission reports present, absent, and unavailable attestation states plus tree and preflight readiness', async () => {
  const base = {
    repo: '/r', baseSha: 'b1', headSha: 'h1', configDigest: 'd1',
    d: {
      readLiveGateAttestation: async () => ({ status: 'PASS', evidence: 'attested by reviewer' }),
      cleanTreeStatus: async () => ({ status: 'PASS', evidence: 'clean' }),
      runPreflight: async () => ({ status: 'PASS', checks: [], toolVersions: { git: '2.45' } }),
    },
  };
  const present = await resolvePlanAdmission(base);
  assert.equal(present.attestation.status, 'present');
  assert.equal(present.cleanTree.status, 'PASS');
  assert.equal(present.preflight.status, 'PASS');

  const absent = await resolvePlanAdmission({
    ...base,
    d: { ...base.d, readLiveGateAttestation: async () => ({ status: 'BLOCKED', evidence: 'no matching attestation' }) },
  });
  assert.equal(absent.attestation.status, 'absent');
  assert.match(absent.attestation.evidence, /no matching attestation/);

  const unavailable = await resolvePlanAdmission({
    ...base,
    d: {
      ...base.d,
      readLiveGateAttestation: async () => { throw new Error('gh: not logged in'); },
      runPreflight: async () => { throw new Error('probe crashed'); },
      cleanTreeStatus: async () => { throw new Error('git unavailable'); },
    },
  });
  assert.equal(unavailable.attestation.status, 'unavailable');
  assert.match(unavailable.attestation.evidence, /gh: not logged in/);
  assert.equal(unavailable.preflight.status, 'BLOCKED');
  assert.match(unavailable.preflight.evidence, /probe crashed/);
  assert.equal(unavailable.cleanTree.status, 'BLOCKED');
  assert.match(unavailable.cleanTree.evidence, /git unavailable/);
});

test('planOnly output carries the admission block', async () => {
  const plan = await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, config: {},
    dependencies: {
      resolveRepositoryState: async ({ repo, baseRef }) => ({
        repo, baseRef, baseSha: 'basesha000', headSha: 'headsha000', mergeBaseSha: 'mergebase000', touchedFiles: [],
      }),
      readProjectMetadata: async () => ({ packageScripts: {}, makeTargets: [], makeRecipes: {} }),
      digestValidationConfig: () => 'digest-a',
      readLiveGateAttestation: async () => ({ status: 'BLOCKED', evidence: 'no matching attestation' }),
      cleanTreeStatus: async () => ({ status: 'PASS', evidence: 'clean' }),
      runPreflight: async () => ({ status: 'PASS', checks: [], toolVersions: {} }),
    },
  });
  assert.equal(plan.admission.attestation.status, 'absent');
  assert.equal(plan.admission.cleanTree.status, 'PASS');
  assert.equal(plan.admission.preflight.status, 'PASS');
});

test('resolvePlanAdmission distinguishes weakened and unavailable from absent', async () => {
  const base = {
    repo: '/r', baseSha: 'b1', headSha: 'h1', configDigest: 'd1',
    d: {
      readLiveGateAttestation: async () => ({ status: 'FAIL', evidence: 'decision recorded as weakened' }),
      cleanTreeStatus: async () => ({ status: 'PASS', evidence: 'clean' }),
      runPreflight: async () => ({ status: 'PASS', checks: [], toolVersions: {} }),
    },
  };
  const weakened = await resolvePlanAdmission(base);
  assert.equal(weakened.attestation.status, 'weakened');
  assert.match(weakened.attestation.evidence, /weakened/);

  const unavailable = await resolvePlanAdmission({
    ...base,
    d: {
      ...base.d,
      readLiveGateAttestation: async () => ({
        status: 'BLOCKED',
        reason: 'unavailable',
        evidence: 'Live GitHub gate attestation was unavailable: gh: command not found',
      }),
    },
  });
  assert.equal(unavailable.attestation.status, 'unavailable');
  assert.match(unavailable.attestation.evidence, /unavailable/);
});

test('engine-mode preflight probes exactly git, node, and declared requiredTools', async () => {
  // Reuse this branch's planDeps-style fixture; only runPreflight differs.
  let captured = 'not-called';
  const plan = await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, mode: 'engine',
    config: { engineChecks: [{ id: 'lint', command: 'echo lint' }], requiredTools: ['make'] },
    dependencies: {
      resolveRepositoryState: async ({ repo, baseRef }) => ({
        repo, baseRef, baseSha: 'basesha000', headSha: 'headsha000', mergeBaseSha: 'mergebase000', touchedFiles: [],
      }),
      readProjectMetadata: async () => ({ packageScripts: {}, makeTargets: [], makeRecipes: {} }),
      digestValidationConfig: () => 'digest-engine-tools',
      readLiveGateAttestation: async () => ({ status: 'BLOCKED', evidence: 'no matching attestation' }),
      cleanTreeStatus: async () => ({ status: 'PASS', evidence: 'clean' }),
      runPreflight: async (options) => { captured = options.toolProbes; return { status: 'PASS', checks: [], toolVersions: {} }; },
    },
  });
  assert.notEqual(plan.planStatus, 'FAIL');
  assert.deepEqual(captured.map(([name]) => name), ['git', 'node', 'make']);
  assert.ok(captured.every(([, command]) => typeof command === 'string' && command.length > 0));
});

test('engine mode without requiredTools probes only git and node', async () => {
  let captured = 'not-called';
  await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, mode: 'engine',
    config: { engineChecks: [{ id: 'lint', command: 'echo lint' }] },
    dependencies: {
      resolveRepositoryState: async ({ repo, baseRef }) => ({
        repo, baseRef, baseSha: 'basesha000', headSha: 'headsha000', mergeBaseSha: 'mergebase000', touchedFiles: [],
      }),
      readProjectMetadata: async () => ({ packageScripts: {}, makeTargets: [], makeRecipes: {} }),
      digestValidationConfig: () => 'digest-engine-default',
      readLiveGateAttestation: async () => ({ status: 'BLOCKED', evidence: 'no matching attestation' }),
      cleanTreeStatus: async () => ({ status: 'PASS', evidence: 'clean' }),
      runPreflight: async (options) => { captured = options.toolProbes; return { status: 'PASS', checks: [], toolVersions: {} }; },
    },
  });
  assert.deepEqual(captured.map(([name]) => name), ['git', 'node']);
});

test('strict mode passes no toolProbes filter to preflight', async () => {
  let captured = 'sentinel';
  await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, config: {},
    dependencies: {
      resolveRepositoryState: async ({ repo, baseRef }) => ({
        repo, baseRef, baseSha: 'basesha000', headSha: 'headsha000', mergeBaseSha: 'mergebase000', touchedFiles: [],
      }),
      readProjectMetadata: async () => ({ packageScripts: {}, makeTargets: [], makeRecipes: {} }),
      digestValidationConfig: () => 'digest-strict-tools',
      readLiveGateAttestation: async () => ({ status: 'BLOCKED', evidence: 'no matching attestation' }),
      cleanTreeStatus: async () => ({ status: 'PASS', evidence: 'clean' }),
      runPreflight: async (options) => { captured = options.toolProbes; return { status: 'PASS', checks: [], toolVersions: {} }; },
    },
  });
  assert.equal(captured, undefined);
});

test('unknown requiredTools names are a named config error and the plan fails closed', async () => {
  const plan = await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, mode: 'engine',
    config: { engineChecks: [{ id: 'lint', command: 'echo lint' }], requiredTools: ['blender'] },
    dependencies: {
      resolveRepositoryState: async ({ repo, baseRef }) => ({
        repo, baseRef, baseSha: 'basesha000', headSha: 'headsha000', mergeBaseSha: 'mergebase000', touchedFiles: [],
      }),
      readProjectMetadata: async () => ({ packageScripts: {}, makeTargets: [], makeRecipes: {} }),
      digestValidationConfig: () => 'digest-engine-unknown-tool',
      readLiveGateAttestation: async () => ({ status: 'BLOCKED', evidence: 'no matching attestation' }),
      cleanTreeStatus: async () => ({ status: 'PASS', evidence: 'clean' }),
      runPreflight: async () => ({ status: 'PASS', checks: [], toolVersions: {} }),
    },
  });
  assert.equal(plan.planStatus, 'FAIL');
  assert.match(
    plan.errors.join('\n'),
    /requiredTools\[0\] names unknown preflight probe "blender"/,
  );
  assert.match(plan.errors.join('\n'), /Known probes:/);
});

test('a strict full run labels its report mode strict with no matrix source', async () => {
  const fixture = makeDependencies();
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    config: reviewedConfig(),
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.mode, 'strict');
  assert.equal(result.report.matrixSource, null);
  // The provisional (first) write must already name its tier — a crashed
  // run's on-disk report can never masquerade as the other mode.
  assert.equal(fixture.written[0].mode, 'strict');
  assert.equal(fixture.written[0].matrixSource, null);
});

test('engine mode full run: a suppression finding auto-FAILs even an all-green custom matrix, and the report names its tier', async () => {
  // Spec test-group 3: suppression auto-FAIL must override an otherwise
  // all-green repo-defined matrix, and the report must still say which tier
  // (engine, not strict) produced it. Reuse makeDependencies' full set of
  // admission/attestation/execute fakes wholesale (mode-agnostic — the
  // workflow calls readLiveGateAttestation, cleanTreeStatus, runPreflight,
  // readGateChanges, scanTouchedSuppressions, and execute the same way
  // regardless of mode) and inject one finding via the already-supported
  // finalFindings hook, which lands as the post-attestation rescan result.
  const fixture = makeDependencies({
    finalFindings: [{
      file: 'src/a.ts',
      line: 12,
      category: 'suppression',
      match: '// eslint-disable-next-line',
    }],
  });
  const result = await runCloseoutWorkflow({
    repo: 'C:/repo',
    baseRef: 'origin/main',
    mode: 'engine',
    config: { engineChecks: [{ id: 'unit', command: 'echo ok' }] },
    outputDir: 'C:/evidence',
    dependencies: fixture.dependencies,
  });
  assert.equal(result.report.overallStatus, 'FAIL');
  assert.equal(result.report.mode, 'engine');
  // Spec test-group 4 read strictly: the engine RUN's report.json carries the
  // exact matrixSource provenance block, and the provisional (first) write
  // already carries both labeling fields by construction.
  assert.deepEqual(result.report.matrixSource, {
    source: 'config.engineChecks',
    digest: '__TEST_DIGEST__',
    checkCount: 1,
  });
  assert.equal(fixture.written[0].mode, 'engine');
  assert.deepEqual(fixture.written[0].matrixSource, result.report.matrixSource);
});
