const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { linkSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } = require('node:fs');
const { lstat, mkdir, mkdtemp, readdir, readFile, readlink, rm, symlink, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { normalizeReportPaths, renderMarkdown, writeEvidenceReport } = require('./pr_closeout_report');

// Return "ok" only when `filePath` has a protected (inheritance-broken) DACL
// consisting of exactly one current-user FullControl allow rule. Kept as a
// local copy consistent with the same helper in pr_closeout_process.test.js
// and debug_server.test.js so the ACL invariant is asserted identically across
// every security-critical write path.
const windowsAclIsCurrentUserOnly = (filePath) => {
  const encodedPath = Buffer.from(filePath, 'utf16le').toString('base64');
  const script = [
    `$path = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${encodedPath}'))`,
    '$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User',
    '$acl = [IO.File]::GetAccessControl($path)',
    '$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))',
    'if ($acl.AreAccessRulesProtected -and $rules.Count -eq 1 -and $rules[0].IdentityReference.Value -eq $sid.Value -and $rules[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and (($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl)) { [Console]::Out.Write("ok") } else { [Console]::Out.Write("not-owner-only"); exit 1 }',
  ].join('; ');
  return spawnSync(
    'powershell.exe',
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    { encoding: 'utf8', windowsHide: true, timeout: 15000 },
  );
};

// Grant BUILTIN\Users (SID S-1-5-32-545) inheritable read on `dir` so files
// created inside it would inherit an ACE readable by other local users unless
// explicitly stripped. (OI)(CI) = object+container inherit; (R) = read.
const grantInheritedReadToUsers = (dir) => spawnSync(
  'icacls',
  [dir, '/grant', '*S-1-5-32-545:(OI)(CI)(R)'],
  { encoding: 'utf8', windowsHide: true, timeout: 15000 },
);

const hostile = '<script>alert(1)</script>\n# Injected\n[click](javascript:alert(1)) | extra';

const hostileReport = () => ({
  overallStatus: hostile,
  repository: hostile,
  baseSha: hostile,
  headSha: hostile,
  configDigest: hostile,
  startedAt: hostile,
  finishedAt: hostile,
  preflight: {
    checks: [{ name: hostile, status: hostile, evidence: hostile }],
  },
  qualificationChecks: [{
    id: hostile,
    command: hostile,
    status: hostile,
    exitCode: hostile,
    evidence: hostile,
  }],
  checks: [{
    phase: hostile,
    id: hostile,
    command: hostile,
    status: hostile,
    exitCode: hostile,
    durationMs: hostile,
    attempts: [{ status: hostile }],
    fixRecord: hostile,
    baseline: { status: hostile },
    evidence: hostile,
  }],
  livePrState: {
    status: hostile,
    evidence: hostile,
    url: hostile,
    state: hostile,
    isDraft: hostile,
    mergeStateStatus: hostile,
    reviewDecision: hostile,
    unresolvedThreads: [],
    checks: [{
      name: hostile,
      status: hostile,
      conclusion: hostile,
      workflowName: hostile,
    }],
    gateAttestation: {
      provider: hostile,
      status: hostile,
      reviewer: hostile,
      reviewUrl: hostile,
      evidence: hostile,
      baseSha: hostile,
      headSha: hostile,
      configDigest: hostile,
      decision: hostile,
    },
  },
  gateIntegrity: {
    status: hostile,
    evidence: hostile,
  },
  reproducibility: { status: hostile, evidence: hostile },
  headConsistency: { status: hostile, evidence: hostile },
  repositorySeal: {
    status: hostile,
    evidence: hostile,
    beforeFingerprint: hostile,
    afterFingerprint: hostile,
  },
  cleanTree: { status: hostile, evidence: hostile },
  suppressionFindings: [{
    file: hostile,
    line: hostile,
    category: hostile,
    match: hostile,
  }],
  toolVersions: { [hostile]: hostile },
});

test('renders every dynamic value as inert Markdown text', () => {
  const markdown = renderMarkdown(hostileReport());

  assert.doesNotMatch(markdown, /<script>/i);
  assert.doesNotMatch(markdown, /\n# Injected/);
  assert.doesNotMatch(markdown, /\[click\]\(javascript:alert\(1\)\)/);
  assert.doesNotMatch(markdown, /\| extra/);
  assert.match(markdown, /&#60;script&#62;alert&#40;1&#41;&#60;&#47;script&#62;/);
  assert.match(markdown, / ⏎ &#35; Injected ⏎ /);
  assert.match(markdown, /&#91;click&#93;&#40;javascript&#58;alert&#40;1&#41;&#41;/);
  assert.match(markdown, /&#124; extra/);
});

test('renders repository sealing and independent gate-attestation evidence', () => {
  const report = hostileReport();
  report.repositorySeal = {
    status: 'PASS',
    evidence: 'Identity remained stable.',
    beforeFingerprint: 'before123',
    afterFingerprint: 'after123',
  };
  report.livePrState.gateAttestation = {
    provider: 'github-pull-request-review',
    status: 'PASS',
    reviewer: 'reviewer-one',
    reviewUrl: 'https://github.example/review/7',
    evidence: 'Exact tuple approved.',
    baseSha: 'base123',
    headSha: 'head123',
    configDigest: 'config123',
    decision: 'not-weakened',
  };

  const markdown = renderMarkdown(report);

  assert.match(markdown, /## Repository seal/);
  assert.match(markdown, /Identity remained stable\./);
  assert.match(markdown, /before123/);
  assert.match(markdown, /after123/);
  assert.match(markdown, /## Independent gate attestation/);
  assert.match(markdown, /github-pull-request-review/);
  assert.match(markdown, /reviewer-one/);
  assert.match(markdown, /Exact tuple approved\./);
  assert.match(markdown, /base123/);
  assert.match(markdown, /head123/);
  assert.match(markdown, /config123/);
  assert.match(markdown, /not-weakened/);
});

test('renders distinct qualification, confirmation, baseline, rerun, and fix evidence', () => {
  const report = hostileReport();
  report.qualificationChecks = [{
    id: 'typecheck',
    command: 'pnpm typecheck',
    status: 'PASS',
    exitCode: 0,
    attemptId: 'typecheck:qualification:1',
    evidence: 'qualification clean',
  }];
  report.checks = [{
    phase: 'confirmation',
    id: 'typecheck',
    command: 'pnpm typecheck',
    status: 'PASS',
    exitCode: 0,
    durationMs: 5,
    attemptId: 'typecheck:confirmation:1',
    attempts: [
      { attemptId: 'typecheck:confirmation:1', status: 'FAIL' },
      { attemptId: 'typecheck:confirmation:2', status: 'PASS' },
    ],
    baselineSetup: {
      attemptId: 'typecheck:baseline-setup:1',
      status: 'PASS',
    },
    baseline: {
      attemptId: 'typecheck:baseline:1',
      status: 'FAIL',
    },
    fixRecord: 'Corrected the invalid return type.',
    evidence: 'clean rerun',
  }];

  const markdown = renderMarkdown(report);

  assert.match(markdown, /typecheck&#58;qualification&#58;1/);
  assert.match(markdown, /typecheck&#58;confirmation&#58;1/);
  assert.match(markdown, /typecheck&#58;confirmation&#58;2/);
  assert.match(markdown, /typecheck&#58;baseline-setup&#58;1/);
  assert.match(markdown, /typecheck&#58;baseline&#58;1/);
  assert.match(markdown, /Corrected the invalid return type\./);
  assert.match(markdown, /Reruns observed&#58; 1/);
});

test('does not invent a fix or a single attempt when no execution evidence exists', () => {
  const report = hostileReport();
  report.qualificationChecks = [];
  report.checks = [{
    phase: 'confirmation',
    id: 'worker-tests',
    command: 'pnpm test worker',
    status: 'BLOCKED',
    exitCode: null,
    evidence: 'admission blocked',
  }];

  const markdown = renderMarkdown(report);

  assert.match(markdown, /No fix record was supplied&#59; the runner does not perform or infer repairs\./);
  assert.match(markdown, /Confirmation attempts&#58; 0/);
  assert.match(markdown, /Reruns observed&#58; 0/);
  assert.doesNotMatch(markdown, /No automatic fix recorded/);
});

test('normalizes repository and evidence paths before persistence', () => {
  const report = {
    repository: 'C:\\repo',
    checks: [{
      logPath: 'C:\\evidence\\logs\\confirmation.typecheck.log',
      evidence: 'cwd C:/repo and log C:/evidence/logs/confirmation.typecheck.log',
    }],
  };

  const normalized = normalizeReportPaths(report, {
    repoRoot: 'C:\\repo',
    outputRoot: 'C:\\evidence',
  });

  assert.equal(normalized.repository, '<repo>');
  assert.equal(normalized.checks[0].logPath, '<evidence>\\logs\\confirmation.typecheck.log');
  assert.equal(
    normalized.checks[0].evidence,
    'cwd <repo> and log <evidence>/logs/confirmation.typecheck.log',
  );
  assert.doesNotMatch(JSON.stringify(normalized), /C:[/\\](?:repo|evidence)/i);
});

test('renders initial-tree and evidence-write sealing evidence', () => {
  const report = hostileReport();
  report.initialTree = {
    status: 'PASS',
    evidence: 'Initial tree clean.',
    fingerprint: 'initial123',
  };
  report.preGithubCleanTree = {
    status: 'PASS',
    evidence: 'Pre-GitHub working tree was clean.',
  };
  report.cleanTree = {
    status: 'PASS',
    evidence: 'Final working tree was clean.',
  };
  report.repositorySeal = {
    status: 'PASS',
    evidence: 'Stable through report persistence.',
    initialFingerprint: 'initial123',
    beforeFingerprint: 'before123',
    afterFingerprint: 'after123',
    evidenceWrite: {
      status: 'PASS',
      evidence: 'A blocked provisional report was written before the post-write seal.',
      fingerprint: 'postwrite123',
    },
  };

  const markdown = renderMarkdown(report);

  assert.match(markdown, /## Initial working tree/);
  assert.match(markdown, /Initial tree clean\./);
  assert.match(markdown, /initial123/);
  assert.match(markdown, /## Pre-GitHub clean tree/);
  assert.match(markdown, /Pre-GitHub working tree was clean\./);
  assert.match(markdown, /## Final clean tree/);
  assert.match(markdown, /Final working tree was clean\./);
  assert.match(markdown, /Evidence write seal/);
  assert.match(markdown, /postwrite123/);
  assert.match(markdown, /blocked provisional report/i);
});

const minimalReport = () => ({
  overallStatus: 'PASS',
  repository: '/repo',
  baseSha: 'base123',
  headSha: 'head123',
  configDigest: 'cfg123',
});

test('writeEvidenceReport writes report.json and report.md into outputDir', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-'));
  try {
    const { json, markdown } = await writeEvidenceReport({ outputDir, report: minimalReport() });
    assert.equal(json, path.join(outputDir, 'report.json'));
    assert.equal(markdown, path.join(outputDir, 'report.md'));

    const jsonContents = JSON.parse(await readFile(json, 'utf8'));
    assert.equal(jsonContents.overallStatus, 'PASS');
    const markdownContents = await readFile(markdown, 'utf8');
    assert.match(markdownContents, /Overall status: \*\*PASS\*\*/);
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('writeEvidenceReport does not clobber hard-linked outside files via staging paths', async () => {
  // Staging names are pid+ms; pre-create hard links across a stamp window so
  // O_EXCL either picks a free stamp or fails closed — never O_TRUNC on the
  // shared outside inode.
  const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-hl-'));
  const outsideDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-hl-out-'));
  const outsideTarget = path.join(outsideDir, 'clobber-me.json');
  await writeFile(outsideTarget, 'do not overwrite this\n', 'utf8');
  try {
    const now = Date.now();
    for (let i = 0; i < 50; i += 1) {
      linkSync(outsideTarget, path.join(outputDir, `.report.json.${process.pid}.${now + i}.tmp`));
      linkSync(outsideTarget, path.join(outputDir, `.report.md.${process.pid}.${now + i}.tmp`));
    }
    let wrote = false;
    try {
      await writeEvidenceReport({ outputDir, report: minimalReport() });
      wrote = true;
    } catch (error) {
      assert.match(String(error?.message || error), /pre-existing path/i);
    }
    assert.equal(await readFile(outsideTarget, 'utf8'), 'do not overwrite this\n');
    if (wrote) {
      assert.ok((await readdir(outputDir)).includes('report.json'));
    }
  } finally {
    await rm(outputDir, { recursive: true, force: true });
    await rm(outsideDir, { recursive: true, force: true });
  }
});

// One-time, synchronous capability probe (same shape as the bashAvailable/
// pwshAvailable probes in debug_server.test.js): can this process actually
// create a FILE symlink? Windows requires SeCreateSymbolicLinkPrivilege
// (Developer Mode, or an elevated process), so process.platform alone cannot
// answer this. The three tests below used to attempt the real symlink and
// fall back to `t.diagnostic(...); return;` on failure -- but returning early
// after a diagnostic still reports as a PASS in node:test's own summary, not
// a SKIP, silently hiding the fact that nothing was actually verified. Probe
// once at module load and cache the result so these tests can use the
// declarative `{ skip }` form instead, which reports honestly either way.
const canCreateFileSymlinks = (() => {
  let probeDir;
  try {
    probeDir = mkdtempSync(path.join(tmpdir(), 'pr-closeout-report-symlink-probe-'));
    const target = path.join(probeDir, 'target');
    writeFileSync(target, '');
    symlinkSync(target, path.join(probeDir, 'link'));
    return true;
  } catch {
    return false;
  } finally {
    if (probeDir) rmSync(probeDir, { recursive: true, force: true });
  }
})();

test(
  'writeEvidenceReport refuses to write through a pre-existing symlinked report.json',
  { skip: !canCreateFileSymlinks && 'file symlinks unavailable in this environment' },
  async () => {
    const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-'));
    const outsideDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-outside-'));
    const outsideTarget = path.join(outsideDir, 'clobber-me.json');
    await writeFile(outsideTarget, 'do not overwrite this\n', 'utf8');
    try {
      // A prior run, a reused temp directory, or repo-controlled content could
      // leave report.json as a symlink pointing outside outputDir. writeFile
      // would silently follow it and overwrite whatever it points to; the
      // no-follow open must instead fail closed before any bytes are written.
      await symlink(outsideTarget, path.join(outputDir, 'report.json'));

      await assert.rejects(
        () => writeEvidenceReport({ outputDir, report: minimalReport() }),
        /symlink/i,
      );

      const untouched = await readFile(outsideTarget, 'utf8');
      assert.equal(untouched, 'do not overwrite this\n', 'the symlink target must not be modified');
      const linkTarget = await readlink(path.join(outputDir, 'report.json'));
      assert.equal(linkTarget, outsideTarget, 'the symlink itself must not be replaced');
    } finally {
      await rm(outputDir, { recursive: true, force: true });
      await rm(outsideDir, { recursive: true, force: true });
    }
  },
);

test(
  'writeEvidenceReport refuses to write through a pre-existing symlinked report.md',
  { skip: !canCreateFileSymlinks && 'file symlinks unavailable in this environment' },
  async () => {
    const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-'));
    const outsideDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-outside-'));
    const outsideTarget = path.join(outsideDir, 'clobber-me.md');
    await writeFile(outsideTarget, 'do not overwrite this\n', 'utf8');
    try {
      await symlink(outsideTarget, path.join(outputDir, 'report.md'));

      await assert.rejects(
        () => writeEvidenceReport({ outputDir, report: minimalReport() }),
        /symlink/i,
      );

      const untouched = await readFile(outsideTarget, 'utf8');
      assert.equal(untouched, 'do not overwrite this\n', 'the symlink target must not be modified');
      const linkTarget = await readlink(path.join(outputDir, 'report.md'));
      assert.equal(linkTarget, outsideTarget, 'the symlink itself must not be replaced');
    } finally {
      await rm(outputDir, { recursive: true, force: true });
      await rm(outsideDir, { recursive: true, force: true });
    }
  },
);

test(
  'writeEvidenceReport never writes report.json when report.md is the rejected symlink',
  { skip: !canCreateFileSymlinks && 'file symlinks unavailable in this environment' },
  async () => {
    // Both targets are validated up front, before either write happens: a
    // symlink at report.md must not leave a real report.json sitting next to
    // an untouched, attacker-controlled report.md symlink (an inconsistent
    // evidence pair for what is meant to be a trustworthy compliance
    // artifact).
    const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-'));
    const outsideDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-outside-'));
    const outsideTarget = path.join(outsideDir, 'clobber-me.md');
    await writeFile(outsideTarget, 'do not overwrite this\n', 'utf8');
    try {
      await symlink(outsideTarget, path.join(outputDir, 'report.md'));

      await assert.rejects(
        () => writeEvidenceReport({ outputDir, report: minimalReport() }),
        /symlink/i,
      );

      await assert.rejects(
        () => readFile(path.join(outputDir, 'report.json'), 'utf8'),
        { code: 'ENOENT' },
        'report.json must not be written when report.md fails validation',
      );
    } finally {
      await rm(outputDir, { recursive: true, force: true });
      await rm(outsideDir, { recursive: true, force: true });
    }
  },
);

test('writeEvidenceReport commits report.json and report.md as a pair (no leftover temps)', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-pair-'));
  try {
    await writeEvidenceReport({ outputDir, report: minimalReport() });
    const entries = require('node:fs').readdirSync(outputDir).sort();
    assert.deepEqual(entries, ['report.json', 'report.md']);
    const json = JSON.parse(await readFile(path.join(outputDir, 'report.json'), 'utf8'));
    const md = await readFile(path.join(outputDir, 'report.md'), 'utf8');
    assert.equal(json.overallStatus, 'PASS');
    assert.match(md, /\*\*PASS\*\*/);
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('writeEvidenceReport removes report.json when the report.md rename fails', async () => {
  // Force the second rename to fail by pre-creating report.md as a directory
  // (rename onto an existing non-empty directory fails). The already-committed
  // report.json must be removed so consumers never see a contradictory pair.
  const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-mdfail-'));
  try {
    await mkdir(path.join(outputDir, 'report.md'));
    await writeFile(path.join(outputDir, 'report.md', 'blocker'), 'x', 'utf8');
    await assert.rejects(
      () => writeEvidenceReport({ outputDir, report: minimalReport() }),
      /./,
    );
    await assert.rejects(
      () => readFile(path.join(outputDir, 'report.json'), 'utf8'),
      { code: 'ENOENT' },
      'report.json must be removed when report.md commit fails',
    );
    const leftovers = require('node:fs').readdirSync(outputDir).filter((name) => name.includes('.tmp'));
    assert.deepEqual(leftovers, [], `no temp report files may remain: ${leftovers.join(',')}`);
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test(
  'writeEvidenceReport protects report.json and report.md with a current-user-only Windows ACL',
  { skip: process.platform !== 'win32' && 'Windows ACL semantics only', timeout: 20000 },
  async () => {
    // chmod(0600) at report-write time is a no-op against Windows' inherited
    // DACL, so report.json/report.md written into a directory whose inherited
    // ACL grants other local users access would otherwise stay readable by
    // them (Codex UguCe/UkXzo/UiXEu/UkAe3). writeNoFollow must establish and
    // verify the same current-user-only ACL invariant already covered for the
    // evidence-log write path (pr_closeout_process.test.js).
    const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-acl-'));
    try {
      // Give outputDir an explicit, inheritable ACE for BUILTIN\Users (read).
      // Absent the fix, files created here inherit it and stay readable by
      // other local users; the fix must strip it from both report files.
      const granted = grantInheritedReadToUsers(outputDir);
      assert.equal(granted.status, 0, `icacls setup failed: ${granted.stdout}\n${granted.stderr}`);

      const { json, markdown } = await writeEvidenceReport({ outputDir, report: minimalReport() });

      for (const target of [json, markdown]) {
        const acl = windowsAclIsCurrentUserOnly(target);
        assert.equal(acl.status, 0, `${target}: ${acl.stdout}\n${acl.stderr}`);
        assert.equal(acl.stdout.trim(), 'ok', `${target} must be current-user-only`);
      }
    } finally {
      await rm(outputDir, { recursive: true, force: true });
    }
  },
);

test('writeEvidenceReport refuses to rename a staged report.json whose identity changed before commit', async () => {
  // Staging names are pid+ms and writeNoFollow closes its descriptor well
  // before the rename below, so a concurrent writer with access to
  // outputDir could swap jsonTmp for a symlink or a different regular file
  // in that gap; only the final report.json/report.md paths were validated
  // up front (assertNotSymlink), not the staged temp paths themselves. A
  // fake lstatFn deterministically reproduces the post-swap disk state
  // (mismatched dev/ino, mirroring the fake lstatFn technique in
  // pr_closeout_repo.test.js) for the pre-rename identity check instead of
  // racing a real concurrent process (Codex UnYbv).
  const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-swap-json-'));
  try {
    const lstatFn = async (target) => {
      const info = await lstat(target);
      if (path.basename(target).startsWith('.report.json.')) {
        return { ...info, dev: info.dev + 1, ino: info.ino + 4096 };
      }
      return info;
    };

    await assert.rejects(
      () => writeEvidenceReport({ outputDir, report: minimalReport(), lstatFn }),
      /staged path swapped before rename/i,
    );

    await assert.rejects(
      () => readFile(path.join(outputDir, 'report.json'), 'utf8'),
      { code: 'ENOENT' },
      'report.json must not be committed when its staged identity changed',
    );
    await assert.rejects(
      () => readFile(path.join(outputDir, 'report.md'), 'utf8'),
      { code: 'ENOENT' },
      'report.md must be rolled back when report.json fails its pre-rename identity check',
    );
    const leftovers = require('node:fs').readdirSync(outputDir).filter((name) => name.includes('.tmp'));
    assert.deepEqual(leftovers, [], `no temp report files may remain: ${leftovers.join(',')}`);
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('writeEvidenceReport refuses to rename a staged report.md whose identity changed before commit', async () => {
  // Same TOCTOU window as above, but on the first rename: markdownTmp is
  // swapped before its own pre-rename identity check runs, so neither final
  // report file may ever be written (Codex UnYbv).
  const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-swap-md-'));
  try {
    const lstatFn = async (target) => {
      const info = await lstat(target);
      if (path.basename(target).startsWith('.report.md.')) {
        return { ...info, dev: info.dev + 1, ino: info.ino + 4096 };
      }
      return info;
    };

    await assert.rejects(
      () => writeEvidenceReport({ outputDir, report: minimalReport(), lstatFn }),
      /staged path swapped before rename/i,
    );

    await assert.rejects(
      () => readFile(path.join(outputDir, 'report.md'), 'utf8'),
      { code: 'ENOENT' },
      'report.md must not be committed when its staged identity changed',
    );
    await assert.rejects(
      () => readFile(path.join(outputDir, 'report.json'), 'utf8'),
      { code: 'ENOENT' },
      'report.json must never be committed when report.md fails its pre-rename identity check',
    );
    const leftovers = require('node:fs').readdirSync(outputDir).filter((name) => name.includes('.tmp'));
    assert.deepEqual(leftovers, [], `no temp report files may remain: ${leftovers.join(',')}`);
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('writeEvidenceReport removes a committed report.md whose identity changed during its rename into place', async () => {
  // Unlike the staged-identity tests above (which perturb the *.tmp staging
  // name and are caught by assertStagedIdentity before rename() ever runs),
  // this perturbs only the bare final "report.md" name: the pre-rename
  // identity check sees the real, matching identity and lets the rename
  // proceed, so only the new post-rename re-check on the committed
  // destination catches the swap (Qodo UplSr). Against the pre-fix code,
  // which never re-verified after rename(), this scenario would be silently
  // trusted and committed as the final report.
  const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-postswap-md-'));
  try {
    const lstatFn = async (target) => {
      const info = await lstat(target);
      if (path.basename(target) === 'report.md') {
        return { ...info, dev: info.dev + 1, ino: info.ino + 4096 };
      }
      return info;
    };

    await assert.rejects(
      () => writeEvidenceReport({ outputDir, report: minimalReport(), lstatFn }),
      /swapped during its rename into place/i,
    );

    await assert.rejects(
      () => readFile(path.join(outputDir, 'report.md'), 'utf8'),
      { code: 'ENOENT' },
      'a report.md whose post-rename identity does not match must be removed, not trusted',
    );
    await assert.rejects(
      () => readFile(path.join(outputDir, 'report.json'), 'utf8'),
      { code: 'ENOENT' },
      'report.json must never be committed when report.md fails its post-rename identity check',
    );
    const leftovers = require('node:fs').readdirSync(outputDir).filter((name) => name.includes('.tmp'));
    assert.deepEqual(leftovers, [], `no temp report files may remain: ${leftovers.join(',')}`);
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('writeEvidenceReport removes a committed report.json whose identity changed during its rename into place, and rolls back report.md', async () => {
  // Same class of swap as above, but on the second rename: report.md commits
  // and passes its own post-rename check normally, then report.json's
  // post-rename check catches the swap. The already-committed report.md must
  // be rolled back too so the pair is never left inconsistent (Qodo UplSr).
  const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-postswap-json-'));
  try {
    const lstatFn = async (target) => {
      const info = await lstat(target);
      if (path.basename(target) === 'report.json') {
        return { ...info, dev: info.dev + 1, ino: info.ino + 4096 };
      }
      return info;
    };

    await assert.rejects(
      () => writeEvidenceReport({ outputDir, report: minimalReport(), lstatFn }),
      /swapped during its rename into place/i,
    );

    await assert.rejects(
      () => readFile(path.join(outputDir, 'report.json'), 'utf8'),
      { code: 'ENOENT' },
      'a report.json whose post-rename identity does not match must be removed, not trusted',
    );
    await assert.rejects(
      () => readFile(path.join(outputDir, 'report.md'), 'utf8'),
      { code: 'ENOENT' },
      'report.md must be rolled back when report.json fails its post-rename identity check',
    );
    const leftovers = require('node:fs').readdirSync(outputDir).filter((name) => name.includes('.tmp'));
    assert.deepEqual(leftovers, [], `no temp report files may remain: ${leftovers.join(',')}`);
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('writeEvidenceReport leaves a pre-existing valid report pair untouched when the staged Markdown identity check fails', async () => {
  // CodeRabbit UptWV: the two staged-identity-swap tests above both start
  // from a fresh outputDir, so neither can catch an ordering defect where a
  // valid prior report.json is deleted even though the staged report.md
  // identity check that runs first is what actually fails. Establish a
  // genuine prior pair with a real (unperturbed) run first, then fail the
  // second run's pre-rename assertStagedIdentity(markdownTmp) check, and
  // confirm neither prior file was touched.
  const outputDir = await mkdtemp(path.join(tmpdir(), 'pr-closeout-report-preexisting-'));
  try {
    await writeEvidenceReport({ outputDir, report: minimalReport() });
    const priorJson = await readFile(path.join(outputDir, 'report.json'), 'utf8');
    const priorMarkdown = await readFile(path.join(outputDir, 'report.md'), 'utf8');

    const lstatFn = async (target) => {
      const info = await lstat(target);
      if (path.basename(target).startsWith('.report.md.')) {
        return { ...info, dev: info.dev + 1, ino: info.ino + 4096 };
      }
      return info;
    };

    await assert.rejects(
      () => writeEvidenceReport({
        outputDir,
        report: { ...minimalReport(), overallStatus: 'FAIL' },
        lstatFn,
      }),
      /staged path swapped before rename/i,
    );

    assert.equal(
      await readFile(path.join(outputDir, 'report.json'), 'utf8'),
      priorJson,
      'a failed pre-rename identity check on report.md must not destroy the pre-existing valid report.json',
    );
    assert.equal(
      await readFile(path.join(outputDir, 'report.md'), 'utf8'),
      priorMarkdown,
      'a failed pre-rename identity check on report.md must not touch the pre-existing valid report.md',
    );
    const leftovers = require('node:fs').readdirSync(outputDir).filter((name) => name.includes('.tmp'));
    assert.deepEqual(leftovers, [], `no temp report files may remain: ${leftovers.join(',')}`);
  } finally {
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('markdown renders the mode line in both modes and the engine banner only in engine mode', () => {
  const strictReport = hostileReport();
  strictReport.mode = 'strict';
  strictReport.matrixSource = null;
  const strictMarkdown = renderMarkdown(strictReport);
  assert.match(strictMarkdown, /- Mode: strict/);
  assert.doesNotMatch(strictMarkdown, /ENGINE MODE/);

  const engineReport = hostileReport();
  engineReport.mode = 'engine';
  engineReport.matrixSource = { source: 'config.engineChecks', digest: 'engine-digest-1', checkCount: 3 };
  const engineMarkdown = renderMarkdown(engineReport);
  assert.match(engineMarkdown, /- Mode: engine/);
  assert.match(engineMarkdown, /ENGINE MODE/);
  assert.match(engineMarkdown, /repo-defined check matrix/);
  assert.match(engineMarkdown, /different, weaker guarantee than the strict 19-check gate/);
  assert.match(engineMarkdown, /engine-digest-1/);
  assert.match(engineMarkdown, /3 checks/);
});

test('markdown banner cannot be dodged by mode casing or a stripped mode field', () => {
  // Casing: any spelling of engine must carry the weaker-guarantee banner —
  // an engine label without its warning is the failure mode being pinned.
  const cased = hostileReport();
  cased.mode = 'ENGINE';
  cased.matrixSource = { source: 'config.engineChecks', digest: 'd1', checkCount: 1 };
  assert.match(renderMarkdown(cased), /ENGINE MODE/);

  // Stripped mode: matrixSource is non-null only on engine runs, so deleting
  // the mode field from an engine report must not upgrade it to a strict claim.
  const stripped = hostileReport();
  stripped.matrixSource = { source: 'config.engineChecks', digest: 'd1', checkCount: 1 };
  const strippedMarkdown = renderMarkdown(stripped);
  assert.match(strippedMarkdown, /- Mode: engine/);
  assert.match(strippedMarkdown, /ENGINE MODE/);

  // True legacy report (neither field): predates engine mode, really strict.
  const legacy = hostileReport();
  const legacyMarkdown = renderMarkdown(legacy);
  assert.match(legacyMarkdown, /- Mode: strict/);
  assert.doesNotMatch(legacyMarkdown, /ENGINE MODE/);
});
