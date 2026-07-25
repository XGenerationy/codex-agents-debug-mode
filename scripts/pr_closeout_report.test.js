const assert = require('node:assert/strict');
const { mkdtemp, readFile, readlink, rm, symlink, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { normalizeReportPaths, renderMarkdown, writeEvidenceReport } = require('./pr_closeout_report');

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

test('writeEvidenceReport refuses to write through a pre-existing symlinked report.json', async () => {
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
});

test('writeEvidenceReport refuses to write through a pre-existing symlinked report.md', async () => {
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
  } finally {
    await rm(outputDir, { recursive: true, force: true });
    await rm(outsideDir, { recursive: true, force: true });
  }
});
