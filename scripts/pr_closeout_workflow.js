const { tmpdir } = require('node:os');
const { mkdir, realpath } = require('node:fs/promises');
const path = require('node:path');

const { buildCheckPlan } = require('./pr_closeout_core');
const {
  classifyGateIntegrity,
  digestValidationConfig,
  verifyBaseline,
  verifyGeneratorReproducibility,
} = require('./pr_closeout_git');
const { gateAttestationMarker, readLiveGateAttestation, readLivePrState } = require('./pr_closeout_github');
const { createCommandExecutor, redactStructure, runPreflight } = require('./pr_closeout_process');
const { writeEvidenceReport } = require('./pr_closeout_report');
const {
  cleanTreeStatus,
  readGateChanges,
  readProjectMetadata,
  resolveRepositoryState,
  scanTouchedSuppressions,
  workingTreeFingerprint,
} = require('./pr_closeout_repo');
const { blockedConfirmationRows, runValidationPhases } = require('./pr_closeout_runner');

const DEFAULTS = {
  cleanTreeStatus,
  createCommandExecutor,
  digestValidationConfig,
  readGateChanges,
  readLiveGateAttestation,
  readLivePrState,
  readProjectMetadata,
  resolveRepositoryState,
  runPreflight,
  scanTouchedSuppressions,
  verifyBaseline,
  workingTreeFingerprint,
  writeEvidenceReport,
};

const evaluateOverallStatus = ({
  planStatus,
  preflight,
  gateIntegrity,
  phases,
  reproducibility,
  cleanTree,
  headConsistency,
  repositorySeal,
  livePrState,
  suppressionFindings = [],
}) => {
  if (suppressionFindings.length) return 'FAIL';
  const statuses = [
    planStatus,
    preflight?.status,
    gateIntegrity?.status,
    phases?.status,
    reproducibility?.status,
    cleanTree?.status,
    headConsistency?.status,
    repositorySeal?.status,
    livePrState?.status,
  ];
  if (statuses.includes('FAIL')) return 'FAIL';
  if (statuses.some((status) => ['BLOCKED', 'BASELINE'].includes(status))) return 'BLOCKED';
  return statuses.every((status) => status === 'PASS') ? 'PASS' : 'BLOCKED';
};

const planStatusFor = (plan) => {
  if (plan.errors.length) return 'FAIL';
  return plan.checks.every(({ command, status }) => command && status !== 'BLOCKED') ? 'PASS' : 'BLOCKED';
};

const defaultOutputDir = (repo, headSha) => {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const name = path.basename(repo).replace(/[^a-z0-9_-]/gi, '-');
  return path.join(tmpdir(), 'codex-pr-closeout', `${name}-${headSha.slice(0, 12)}-${stamp}`);
};

const assertOutputOutsideRepository = (repo, outputDir) => {
  const relative = path.relative(path.resolve(repo), path.resolve(outputDir));
  const inside = relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
  if (inside) throw new Error(`Evidence output must be outside the repository: ${outputDir}`);
};

const resolvePhysicalTarget = async (target, realpathPath) => {
  const missing = [];
  let current = target;
  while (true) {
    try {
      const resolved = await realpathPath(current);
      return missing.length ? path.join(resolved, ...missing.reverse()) : resolved;
    } catch (error) {
      if (error && error.code !== 'ENOENT') throw error;
      const parent = path.dirname(current);
      if (parent === current) return target;
      missing.push(path.basename(current));
      current = parent;
    }
  }
};

const prepareOutputDirectory = async ({
  repo,
  outputDir,
  mkdirPath = mkdir,
  realpathPath = realpath,
}) => {
  const resolvedRepo = path.resolve(repo);
  const resolvedOutput = path.resolve(outputDir);
  assertOutputOutsideRepository(resolvedRepo, resolvedOutput);
  const [physicalRepo, physicalAncestor] = await Promise.all([
    realpathPath(repo),
    resolvePhysicalTarget(outputDir, realpathPath),
  ]);
  assertOutputOutsideRepository(physicalRepo, physicalAncestor);
  await mkdirPath(resolvedOutput, { recursive: true });
  const physicalOutput = await realpathPath(outputDir);
  assertOutputOutsideRepository(physicalRepo, physicalOutput);
  return resolvedOutput;
};

DEFAULTS.prepareOutputDirectory = prepareOutputDirectory;

const ESSENTIAL_ENV = new Set([
  'PATH',
  'PATHEXT',
  'SYSTEMROOT',
  'COMSPEC',
  'TEMP',
  'TMP',
  'TMPDIR',
  'HOME',
  'USERPROFILE',
  'LOCALAPPDATA',
  'APPDATA',
  'PROGRAMFILES',
  'PROGRAMFILES(X86)',
  'PROGRAMDATA',
  'WINDIR',
  'CI',
  'NO_COLOR',
  'TERM',
  'OMO_CODEX_GIT_BASH_PATH',
]);

const buildWorkflowEnvironment = (env, config) => {
  const explicit = new Set([
    ...(config.requiredEnv || []),
    ...(config.safeEnv || []),
  ].map((name) => String(name).toUpperCase()));
  return Object.fromEntries(Object.entries(env).filter(([name]) => (
    ESSENTIAL_ENV.has(name.toUpperCase()) || explicit.has(name.toUpperCase())
  )));
};

const normalizePersistedPaths = (value, repo, outputDir, seen = new WeakSet()) => {
  const replacements = [
    [repo, '<repo>'],
    [repo?.replaceAll('\\', '/'), '<repo>'],
    [repo?.replaceAll('/', '\\'), '<repo>'],
    [outputDir, '<evidence>'],
    [outputDir?.replaceAll('\\', '/'), '<evidence>'],
    [outputDir?.replaceAll('/', '\\'), '<evidence>'],
  ].filter(([candidate]) => candidate);
  const normalize = (text) => {
    let result = String(text);
    for (const [candidate, replacement] of replacements) {
      const escaped = candidate.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const flags = /^[A-Za-z]:[\\/]/.test(candidate) ? 'gi' : 'g';
      result = result.replace(
        new RegExp(`${escaped}(?=$|[\\\\/]|[^A-Za-z0-9._-])`, flags),
        replacement,
      );
    }
    return result;
  };
  if (typeof value === 'string') return normalize(value);
  if (!value || typeof value !== 'object') return value;
  if (seen.has(value)) return '[Circular]';
  seen.add(value);
  if (Array.isArray(value)) return value.map((entry) => normalizePersistedPaths(entry, repo, outputDir, seen));
  return Object.fromEntries(Object.entries(value).map(([key, entry]) => [
    normalize(key),
    normalizePersistedPaths(entry, repo, outputDir, seen),
  ]));
};

const sameList = (left = [], right = []) => (
  left.length === right.length && left.every((value, index) => value === right[index])
);

const sealRepository = ({
  validatedState,
  observedState,
  sealedState,
  initialFingerprint,
  beforeFingerprint,
  afterFingerprint,
}) => {
  const problems = [];
  const compareState = (candidate, phase) => {
    for (const field of ['baseSha', 'mergeBaseSha', 'headSha']) {
      if ((validatedState[field] || null) !== (candidate[field] || null)) {
        problems.push(`${field} changed ${phase}: ${validatedState[field] || '<missing>'} -> ${candidate[field] || '<missing>'}.`);
      }
    }
    if (!sameList(validatedState.touchedFiles, candidate.touchedFiles)) problems.push(`Touched files changed ${phase}.`);
  };
  compareState(observedState, 'after live GitHub verification');
  compareState(sealedState, 'during the final repository seal');
  if (beforeFingerprint !== afterFingerprint) {
    problems.push(`Working-tree fingerprint changed after live GitHub verification: ${beforeFingerprint} -> ${afterFingerprint}.`);
  }
  if (initialFingerprint && initialFingerprint !== afterFingerprint) {
    problems.push(`Working-tree fingerprint differs from clean admission: ${initialFingerprint} -> ${afterFingerprint}.`);
  }
  return problems.length
    ? { status: 'BLOCKED', evidence: problems.join(' '), beforeFingerprint, afterFingerprint }
    : {
      status: 'PASS',
      evidence: `Post-GitHub repository seal matches base ${sealedState.baseSha}, head ${sealedState.headSha}, and working-tree fingerprint ${afterFingerprint}.`,
      initialFingerprint,
      beforeFingerprint,
      afterFingerprint,
    };
};

const admissionStatus = ({ planStatus, preflight, gateIntegrity, initialTree, initialSuppressions }) => {
  if (planStatus === 'FAIL' || preflight.status === 'FAIL' || gateIntegrity.status === 'FAIL'
    || initialTree.status === 'FAIL' || initialSuppressions.length) return 'FAIL';
  if (planStatus !== 'PASS' || preflight.status !== 'PASS' || gateIntegrity.status !== 'PASS'
    || initialTree.status !== 'PASS') return 'BLOCKED';
  return 'PASS';
};

const runCloseoutWorkflow = async ({
  repo,
  baseRef,
  config = {},
  outputDir,
  planOnly = false,
  dependencies = {},
} = {}) => {
  const d = { ...DEFAULTS, ...dependencies };
  const startedAt = new Date().toISOString();
  const initial = await d.resolveRepositoryState({ repo, baseRef });
  const metadata = await d.readProjectMetadata(initial.repo);
  const plan = buildCheckPlan({ config, ...metadata, touchedFiles: initial.touchedFiles });
  const planStatus = planStatusFor(plan);
  const baselineSetupCommand = config.baselineSetupCommand || 'pnpm install --frozen-lockfile --ignore-scripts';
  const { gateIntegrityReview: _gateIntegrityReview, ...validationConfig } = config;
  const configDigest = d.digestValidationConfig({
    schemaVersion: 2,
    config: validationConfig,
    resolved: {
      baselineSetupCommand,
      checks: plan.checks.map((check) => ({
        id: check.id,
        command: check.command,
        resolution: check.resolution,
        qualificationSafe: check.qualificationSafe,
        resourceGroup: check.resourceGroup,
        baselineSafe: check.baselineSafe,
        generator: check.generator,
        proof: check.proof,
      })),
    },
  });
  const configuredCommands = [
    `baseline-dependency-setup:${baselineSetupCommand}`,
    ...plan.checks.filter(({ command }) => command).map(({ id, resolution, command }) => `${id}:${resolution}:${command}`),
    ...plan.checks
      .filter(({ proof }) => proof?.type === 'command' && proof.command)
      .map(({ id, proof }) => `${id}:postcondition:${proof.command}`),
  ];
  if (planOnly) {
    return redactStructure({
      execution: 'not-started',
      repository: initial.repo,
      baseRef: initial.baseRef,
      baseSha: initial.baseSha,
      headSha: initial.headSha,
      configDigest,
      gateIntegrityAttestationRequired: {
        provider: 'github-pull-request-review',
        baseSha: initial.baseSha,
        headSha: initial.headSha,
        configDigest,
        decision: 'not-weakened',
        marker: gateAttestationMarker({ baseSha: initial.baseSha, headSha: initial.headSha, configDigest }),
      },
      touchedFiles: initial.touchedFiles,
      planStatus,
      errors: plan.errors,
      checks: plan.checks.map(({ id, label, command, resolution, status, evidence }) => ({
        id, label, command, resolution, status, evidence,
      })),
    }, process.env, config.requiredEnv || []);
  }

  const requestedOutput = path.resolve(outputDir || defaultOutputDir(initial.repo, initial.headSha));
  assertOutputOutsideRepository(initial.repo, requestedOutput);
  const resolvedOutput = await d.prepareOutputDirectory({ repo: initial.repo, outputDir: requestedOutput });
  const childEnv = buildWorkflowEnvironment(process.env, config);
  const execute = d.execute || d.createCommandExecutor({
    repo: initial.repo,
    outputDir: resolvedOutput,
    env: childEnv,
    secretNames: config.requiredEnv || [],
    timeoutMs: config.timeoutMs,
    timeoutsMs: config.timeoutsMs,
  });
  const initialAttestation = await d.readLiveGateAttestation({
    repo: initial.repo,
    expectedBaseSha: initial.baseSha,
    expectedHeadSha: initial.headSha,
    expectedConfigDigest: configDigest,
  });
  let preflight = {
    status: 'BLOCKED',
    checks: [],
    toolVersions: {},
    evidence: 'Preflight did not run because independent attestation admission was not clean.',
  };
  let initialSuppressions = [];
  let initialTree = {
    status: 'BLOCKED',
    evidence: 'Initial working tree was not inspected because attestation admission was not clean.',
  };
  let initialFingerprint = null;
  let gateIntegrity = {
    status: initialAttestation.status === 'FAIL' ? 'FAIL' : 'BLOCKED',
    evidence: initialAttestation.evidence || 'Independent live GitHub attestation was not clean.',
  };
  const attestationAdmitted = initialAttestation.status === 'PASS';
  if (attestationAdmitted) {
    const [observedPreflight, initialGateChanges, observedSuppressions, observedTree] = await Promise.all([
      d.runPreflight({ repo: initial.repo, config, env: childEnv }),
      d.readGateChanges(initial.repo, initial.mergeBaseSha || initial.baseSha),
      d.scanTouchedSuppressions(initial.repo, initial.touchedFiles),
      d.cleanTreeStatus(initial.repo),
    ]);
    preflight = observedPreflight;
    initialSuppressions = observedSuppressions;
    initialTree = observedTree;
    if (initialTree.status === 'PASS') initialFingerprint = await d.workingTreeFingerprint(initial.repo, []);
    gateIntegrity = classifyGateIntegrity({
      ...initialGateChanges,
      configuredCommands,
      baseSha: initial.baseSha,
      headSha: initial.headSha,
      configDigest,
      attestation: initialAttestation,
    });
  }
  const admitted = admissionStatus({
    planStatus,
    preflight,
    gateIntegrity,
    initialTree,
    initialSuppressions,
  });
  let reproducibility = {
    status: admitted === 'PASS' ? 'BLOCKED' : admitted,
    evidence: admitted === 'PASS' ? 'Generator confirmation has not run.' : 'Admission gate was not clean.',
  };
  let phases = {
    status: admitted,
    qualification: [],
    confirmation: admitted === 'PASS'
      ? []
      : blockedConfirmationRows(plan.checks, 'Confirmation did not run because admission was not clean.'),
  };

  if (admitted === 'PASS') {
    const reproducibilityPaths = [...new Set([
      'node_modules/.prisma',
      'node_modules/@prisma/client',
      ...(config.reproducibilityPaths || []),
    ])];
    let baselineChain = Promise.resolve();
    let baselineAttempt = 0;
    const serializeBaseline = (operation) => {
      const pending = baselineChain.then(operation, operation);
      baselineChain = pending.catch(() => undefined);
      return pending;
    };
    const executeChecked = async (check, phase) => {
      let result;
      if (check.generator && phase === 'confirmation') {
        reproducibility = await verifyGeneratorReproducibility({
          executeGenerator: (run) => execute(check, `confirmation-generator-${run}`),
          fingerprint: () => d.workingTreeFingerprint(initial.repo, reproducibilityPaths),
        });
        reproducibility.paths = reproducibilityPaths;
        const terminal = reproducibility.second || reproducibility.first || {};
        result = {
          ...check,
          phase,
          status: reproducibility.status,
          exitCode: terminal.exitCode ?? null,
          startedAt: reproducibility.first?.startedAt,
          finishedAt: terminal.finishedAt,
          durationMs: (reproducibility.first?.durationMs || 0) + (reproducibility.second?.durationMs || 0),
          stdout: terminal.stdout || '',
          stderr: terminal.stderr || '',
          evidence: reproducibility.evidence,
        };
      } else {
        result = await execute(check, phase);
      }
      if (result.status === 'PASS') return result;
      return serializeBaseline(() => d.verifyBaseline({
        repo: initial.repo,
        baseSha: initial.baseSha,
        check,
        headResult: result,
        execute: (baselineCheck, cwd) => execute({
          ...baselineCheck,
          id: `${check.id}-baseline-comparison`,
          associatedCheckId: check.id,
          attemptId: `${check.id}:baseline:${++baselineAttempt}`,
        }, 'baseline', cwd),
        setup: (cwd) => execute({
          id: `${check.id}-baseline-dependency-setup`,
          associatedCheckId: check.id,
          attemptId: `${check.id}:baseline-setup:${++baselineAttempt}`,
          command: baselineSetupCommand,
          baselineSafe: false,
        }, 'baseline-setup', cwd),
        toolVersions: preflight.toolVersions,
        captureVersions: async (cwd) => (await d.runPreflight({
          repo: cwd,
          config: { minFreeDiskGb: 0 },
          // Pass the sanitized childEnv so the disposable base worktree's
          // version probes use the same isolated environment as admission
          // preflight and command execution, instead of falling back to
          // process.env and leaking ambient CI credentials into the baseline
          // comparison.
          env: childEnv,
        })).toolVersions,
      }));
    };
    phases = await runValidationPhases({
      checks: plan.checks,
      execute: executeChecked,
      parallelism: Math.max(1, Math.min(Number(config.parallelism) || 4, 8)),
    });
  }

  const finalState = await d.resolveRepositoryState({ repo: initial.repo, baseRef });
  const consistencyProblems = [];
  if (finalState.headSha !== initial.headSha) {
    consistencyProblems.push(`HEAD changed during validation: ${initial.headSha} -> ${finalState.headSha}.`);
  }
  if (finalState.baseSha !== initial.baseSha) {
    consistencyProblems.push(`Live base changed during validation: ${initial.baseSha} -> ${finalState.baseSha}.`);
  }
  const headConsistency = consistencyProblems.length
    ? { status: 'BLOCKED', evidence: consistencyProblems.join(' ') }
    : { status: 'PASS', evidence: `Evidence belongs to final base ${finalState.baseSha} and head ${finalState.headSha}.` };
  const beforeGithubFingerprint = attestationAdmitted
    ? await d.workingTreeFingerprint(finalState.repo, [])
    : null;
  const livePrState = await d.readLivePrState({
    repo: finalState.repo,
    expectedHeadSha: finalState.headSha,
    expectedBaseSha: finalState.baseSha,
    expectedConfigDigest: configDigest,
  });
  const observedState = await d.resolveRepositoryState({ repo: finalState.repo, baseRef });
  let finalSuppressions = [];
  let cleanTree = { status: 'BLOCKED', evidence: 'Final tree inspection did not run because attestation admission was not clean.' };
  let finalGateChanges = { changedFiles: [], addedLines: [] };
  if (attestationAdmitted) {
    [finalSuppressions, cleanTree, finalGateChanges] = await Promise.all([
      d.scanTouchedSuppressions(observedState.repo, observedState.touchedFiles),
      d.cleanTreeStatus(observedState.repo),
      d.readGateChanges(observedState.repo, observedState.mergeBaseSha || observedState.baseSha),
    ]);
  }
  const afterGithubFingerprint = attestationAdmitted
    ? await d.workingTreeFingerprint(observedState.repo, [])
    : null;
  const sealedState = await d.resolveRepositoryState({ repo: observedState.repo, baseRef });
  let repositorySeal = attestationAdmitted
    ? sealRepository({
      validatedState: finalState,
      observedState,
      sealedState,
      initialFingerprint,
      beforeFingerprint: beforeGithubFingerprint,
      afterFingerprint: afterGithubFingerprint,
    })
    : {
      status: 'BLOCKED',
      evidence: 'Repository seal did not run because attestation admission was not clean.',
      initialFingerprint,
      beforeFingerprint: null,
      afterFingerprint: null,
    };
  if (attestationAdmitted) {
    gateIntegrity = classifyGateIntegrity({
      ...finalGateChanges,
      configuredCommands,
      baseSha: sealedState.baseSha,
      headSha: sealedState.headSha,
      configDigest,
      attestation: livePrState.gateAttestation,
    });
  }
  let report = normalizePersistedPaths(redactStructure({
    schemaVersion: 2,
    repository: sealedState.repo,
    baseRef: sealedState.baseRef,
    baseSha: sealedState.baseSha,
    mergeBaseSha: sealedState.mergeBaseSha,
    headSha: sealedState.headSha,
    configDigest,
    startedAt,
    finishedAt: new Date().toISOString(),
    toolVersions: preflight.toolVersions,
    preflight,
    planErrors: plan.errors,
    planStatus,
    gateIntegrity,
    reproducibility,
    headConsistency,
    repositorySeal,
    initialTree: { ...initialTree, fingerprint: initialFingerprint },
    cleanTree,
    livePrState,
    touchedFiles: sealedState.touchedFiles,
    suppressionFindings: finalSuppressions,
    qualificationChecks: phases.qualification,
    checks: phases.confirmation,
  }, process.env, config.requiredEnv || []), sealedState.repo, resolvedOutput);
  report.overallStatus = evaluateOverallStatus({
    planStatus,
    preflight,
    gateIntegrity,
    phases,
    reproducibility,
    cleanTree,
    headConsistency,
    repositorySeal,
    livePrState,
    suppressionFindings: finalSuppressions,
  });
  const provisional = {
    ...report,
    overallStatus: 'BLOCKED',
    repositorySeal: {
      ...report.repositorySeal,
      status: 'BLOCKED',
      evidence: 'Provisional evidence was written; the evidence-write repository seal is pending.',
      evidenceWrite: {
        status: 'BLOCKED',
        evidence: 'Pending verification after the provisional evidence write.',
        fingerprint: null,
      },
    },
  };
  await d.prepareOutputDirectory({ repo: initial.repo, outputDir: resolvedOutput });
  await d.writeEvidenceReport({ outputDir: resolvedOutput, report: provisional });
  const evidenceState = await d.resolveRepositoryState({ repo: sealedState.repo, baseRef });
  const evidenceFingerprint = attestationAdmitted
    ? await d.workingTreeFingerprint(evidenceState.repo, [])
    : null;
  const evidenceSeal = attestationAdmitted
    ? sealRepository({
      validatedState: sealedState,
      observedState: evidenceState,
      sealedState: evidenceState,
      beforeFingerprint: afterGithubFingerprint,
      afterFingerprint: evidenceFingerprint,
    })
    : {
      status: 'BLOCKED',
      evidence: 'Evidence-write seal did not run because attestation admission was not clean.',
    };
  repositorySeal = {
    ...repositorySeal,
    status: repositorySeal.status === 'PASS' && evidenceSeal.status === 'PASS'
      ? 'PASS'
      : (repositorySeal.status === 'FAIL' || evidenceSeal.status === 'FAIL' ? 'FAIL' : 'BLOCKED'),
    evidenceWrite: {
      status: evidenceSeal.status,
      evidence: evidenceSeal.evidence,
      fingerprint: evidenceFingerprint,
    },
  };
  report = {
    ...report,
    repositorySeal: normalizePersistedPaths(repositorySeal, sealedState.repo, resolvedOutput),
  };
  report.overallStatus = evaluateOverallStatus({
    planStatus,
    preflight,
    gateIntegrity,
    phases,
    reproducibility,
    cleanTree,
    headConsistency,
    repositorySeal,
    livePrState,
    suppressionFindings: finalSuppressions,
  });
  await d.prepareOutputDirectory({ repo: initial.repo, outputDir: resolvedOutput });
  const paths = await d.writeEvidenceReport({ outputDir: resolvedOutput, report });
  return { report, paths };
};

module.exports = {
  evaluateOverallStatus,
  normalizePersistedPaths,
  prepareOutputDirectory,
  runCloseoutWorkflow,
  sealRepository,
};
