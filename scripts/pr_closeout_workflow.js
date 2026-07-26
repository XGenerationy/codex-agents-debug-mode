const { randomBytes } = require('node:crypto');
const { constants: fsConstants } = require('node:fs');
const { tmpdir } = require('node:os');
const { mkdir, open: openFile, readFile, realpath, unlink } = require('node:fs/promises');
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

/**
 * Reduces every sub-check's status to one final verdict. Any suppression
 * marker found in touched files is an automatic FAIL regardless of what else
 * passed — the Zero-Suppression policy overrides everything. Otherwise: any
 * component FAIL wins; a BASELINE result (head failure reproduced exactly at
 * base — pre-existing, not introduced by this PR) is treated the same as
 * BLOCKED rather than silently passed; and PASS requires every tracked
 * status to be exactly 'PASS', with any other combination falling back to
 * BLOCKED rather than defaulting optimistically to PASS.
 * @returns {'PASS'|'FAIL'|'BLOCKED'}
 */
const evaluateOverallStatus = ({
  planStatus,
  preflight,
  gateIntegrity,
  phases,
  reproducibility,
  preGithubCleanTree,
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
    // Pre-GitHub dirty-tree probes are first-class status inputs so a
    // transient dirt that later cleans up cannot be ignored even if the
    // fold-into-cleanTree path is skipped or mis-wired.
    preGithubCleanTree?.status,
    cleanTree?.status,
    headConsistency?.status,
    repositorySeal?.status,
    livePrState?.status,
  ];
  if (statuses.includes('FAIL')) return 'FAIL';
  if (statuses.some((status) => ['BLOCKED', 'BASELINE'].includes(status))) return 'BLOCKED';
  return statuses.every((status) => status === 'PASS') ? 'PASS' : 'BLOCKED';
};

/**
 * A check plan is only PASS if every configured check both resolved to a
 * runnable `command` and isn't itself already BLOCKED (e.g. an unresolved
 * dependency); a plan-building error is a hard FAIL, and any other gap
 * (missing command, pre-blocked check) falls back to BLOCKED rather than
 * silently passing.
 * @param {{errors: unknown[], checks: {command?: string, status?: string}[]}} plan
 * @returns {'PASS'|'FAIL'|'BLOCKED'}
 */
const planStatusFor = (plan) => {
  if (plan.errors.length) return 'FAIL';
  return plan.checks.every(({ command, status }) => command && status !== 'BLOCKED') ? 'PASS' : 'BLOCKED';
};

/**
 * Default evidence output directory when the caller doesn't supply one:
 * under the OS tmpdir, namespaced by a filesystem-safe repo basename, the
 * short head SHA, a filesystem-safe timestamp, and a process-unique suffix
 * (pid + random), so concurrent runs against the same repo/head never share
 * an evidence directory even when they start in the same millisecond
 * (Codex #4780351874). Without the unique suffix, independently numbered
 * attempt logs and final reports can truncate/interleave and one run may
 * return PASS while its on-disk evidence belongs partly to the other.
 * @param {string} repo
 * @param {string} headSha
 * @returns {string}
 */
const defaultOutputDir = (repo, headSha) => {
  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const name = path.basename(repo).replace(/[^a-z0-9_-]/gi, '-');
  const unique = `${process.pid}-${randomBytes(4).toString('hex')}`;
  return path.join(tmpdir(), 'codex-pr-closeout', `${name}-${headSha.slice(0, 12)}-${stamp}-${unique}`);
};

/**
 * Throws unless `outputDir` resolves outside `repo`. Evidence must never be
 * written inside the repository it is validating: it would then be
 * (un)tracked content the working-tree/suppression scans have to reason
 * about, and a later run could pick up a previous run's evidence as part of
 * the very tree it is fingerprinting. Called against both logical and
 * realpath'd (symlink-resolved) path pairs by `prepareOutputDirectory`.
 * @param {string} repo
 * @param {string} outputDir
 */
const assertOutputOutsideRepository = (repo, outputDir) => {
  const relative = path.relative(path.resolve(repo), path.resolve(outputDir));
  const inside = relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
  if (inside) throw new Error(`Evidence output must be outside the repository: ${outputDir}`);
};

/**
 * Resolves the realpath `target` would have once created, even though it
 * (and possibly several trailing segments) doesn't exist yet: `realpath`
 * throws ENOENT on a nonexistent path, so this walks up to the nearest
 * ancestor that does exist, resolves that ancestor through symlinks, and
 * rejoins the missing trailing segments on top. Falls back to the original
 * `target` if no ancestor exists at all (e.g. root). Lets
 * `prepareOutputDirectory` check the *physical* output location against the
 * repository before `mkdir` ever runs, so a symlinked ancestor can't make an
 * outside-looking path actually land inside the repo.
 * @param {string} target
 * @param {(path: string) => Promise<string>} realpathPath
 * @returns {Promise<string>}
 */
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

/**
 * Creates the evidence output directory, defending against symlink TOCTOU:
 * checks `outputDir` against `repo` three times — the plain resolved paths,
 * the physical (symlink-resolved) paths before `mkdir` runs (via
 * `resolvePhysicalTarget`, since the directory doesn't exist yet), and the
 * physical paths again after `mkdir` actually creates it. A symlink planted
 * as the repo root or anywhere along the output path — even one that only
 * becomes resolvable once the directory exists — cannot smuggle the evidence
 * write inside the repository it describes. `mkdirPath`/`realpathPath` are
 * injectable for tests; callers use the real `fs/promises` implementations.
 * Invoked again later in the workflow immediately before each evidence
 * write, not just once at startup.
 * @returns {Promise<string>} the resolved output directory path.
 */
/**
 * Acquire an exclusive run lock under an explicit --output-dir so two closeout
 * processes cannot share report.json / command logs (Codex #4781560042).
 * Default (process-unique) dirs do not need this; stale locks from dead PIDs
 * are reclaimed.
 * @param {string} outputDir
 * @returns {Promise<import('node:fs/promises').FileHandle>}
 */
const acquireOutputDirLock = async (outputDir) => {
  const lockPath = path.join(outputDir, '.closeout.lock');
  const payload = `${process.pid}\n${new Date().toISOString()}\n`;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const handle = await openFile(
        lockPath,
        fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL,
        0o600,
      );
      try {
        await handle.writeFile(payload, 'utf8');
      } catch (error) {
        await handle.close().catch(() => {});
        throw error;
      }
      return handle;
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error;
      let holderPid = null;
      try {
        const text = await readFile(lockPath, 'utf8');
        holderPid = Number(String(text).split(/\r?\n/, 1)[0].trim());
      } catch {
        holderPid = null;
      }
      // Same-process re-entry: the lock file still names us while we hold the
      // FD. Unlink+recreate would not provide exclusion (Unix allows O_EXCL on
      // a new inode after unlink of an open file).
      if (holderPid === process.pid) {
        throw new Error(
          `Evidence output directory is already locked by this closeout process: ${outputDir}`,
        );
      }
      let holderAlive = false;
      if (Number.isInteger(holderPid) && holderPid > 0) {
        try {
          process.kill(holderPid, 0);
          holderAlive = true;
        } catch (probeError) {
          holderAlive = probeError?.code !== 'ESRCH';
        }
      }
      if (holderAlive) {
        throw new Error(
          `Evidence output directory is already locked by closeout pid ${holderPid}: ${outputDir}`,
        );
      }
      try {
        await unlink(lockPath);
      } catch (unlinkError) {
        if (unlinkError?.code !== 'ENOENT') {
          throw new Error(`Failed to reclaim stale evidence lock in ${outputDir}: ${unlinkError.message}`);
        }
      }
    }
  }
  throw new Error(`Failed to acquire exclusive evidence lock in ${outputDir}`);
};

const prepareOutputDirectory = async ({
  repo,
  outputDir,
  mkdirPath = mkdir,
  realpathPath = realpath,
  exclusive = false,
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
  if (exclusive) {
    // Hold the lock handle on the process; closeout is a short-lived CLI so
    // process exit releases the FD. Stale reclaim handles crashed peers.
    const lockHandle = await acquireOutputDirLock(resolvedOutput);
    // Keep a ref so GC does not close the lock FD mid-run.
    prepareOutputDirectory._heldLocks = prepareOutputDirectory._heldLocks || new Set();
    prepareOutputDirectory._heldLocks.add(lockHandle);
  }
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
  // Shell overrides honored by resolveCommandShell: Windows Git Bash and the
  // Unix OMO_CODEX_SHELL_PATH override must survive environment filtering or
  // preflight probes and executors fall back to a shell that is not on PATH.
  'OMO_CODEX_GIT_BASH_PATH',
  'OMO_CODEX_SHELL_PATH',
]);

/**
 * Builds the environment handed to every executed check: an allowlist, not a
 * denylist — only names in `ESSENTIAL_ENV` (PATH, shell/tmp/home basics, the
 * shell-override escape hatches) or explicitly named in `config.requiredEnv`
 * / `config.safeEnv` survive. Everything else in the ambient `env` (CI
 * secrets, unrelated tokens, etc.) is dropped by default rather than passed
 * through and relied on to be redacted after the fact.
 * @param {NodeJS.ProcessEnv} env
 * @param {{requiredEnv?: string[], safeEnv?: string[]}} config
 * @returns {NodeJS.ProcessEnv}
 */
const buildWorkflowEnvironment = (env, config) => {
  const explicit = new Set([
    ...(config.requiredEnv || []),
    ...(config.safeEnv || []),
  ].map((name) => String(name).toUpperCase()));
  return Object.fromEntries(Object.entries(env).filter(([name]) => (
    ESSENTIAL_ENV.has(name.toUpperCase()) || explicit.has(name.toUpperCase())
  )));
};

/**
 * Redacts absolute local paths from a persisted evidence value: recursively
 * replaces every occurrence of `repo`/`outputDir` (and their forward- and
 * backslash-normalized forms, case-insensitively for drive-letter paths)
 * with `<repo>`/`<evidence>` placeholders, in both string values and object
 * keys, so evidence written to disk is portable across machines and doesn't
 * leak the local filesystem layout. A lookahead boundary keeps a match from
 * firing inside a longer unrelated path segment. Walks objects/arrays with a
 * clone cache: a value reachable via more than one reference stays a single
 * shared reference after normalization (same contract as `redactStructure`),
 * and only a genuine cycle collapses to the string `'[Circular]'`.
 * @param {unknown} value
 * @param {string} repo
 * @param {string} outputDir
 * @returns {unknown} a new value with paths/keys normalized; non-string primitives pass through unchanged.
 */
const normalizePersistedPaths = (value, repo, outputDir, clones = new WeakMap(), stack = new WeakSet()) => {
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
  // Stack first (true cycle while building); clones second (shared refs done).
  if (stack.has(value)) return '[Circular]';
  if (clones.has(value)) return clones.get(value);
  stack.add(value);
  try {
    if (Array.isArray(value)) {
      const out = [];
      clones.set(value, out);
      for (const entry of value) out.push(normalizePersistedPaths(entry, repo, outputDir, clones, stack));
      return out;
    }
    const out = {};
    clones.set(value, out);
    for (const [key, entry] of Object.entries(value)) {
      out[normalize(key)] = normalizePersistedPaths(entry, repo, outputDir, clones, stack);
    }
    return out;
  } finally {
    stack.delete(value);
  }
};

/**
 * Order-sensitive list equality (not set equality) — used to detect whether
 * `touchedFiles` changed between two repository-state snapshots, where a
 * reordering is as meaningful a change as an addition or removal.
 * @param {unknown[]} left
 * @param {unknown[]} right
 * @returns {boolean}
 */
const sameList = (left = [], right = []) => (
  left.length === right.length && left.every((value, index) => value === right[index])
);

/**
 * The "did the repository move under us" integrity check, run at multiple
 * checkpoints during a closeout (once comparing validation-time state
 * through the post-GitHub-verification and final-seal states, and again
 * later comparing post-GitHub state through the post-evidence-write state).
 * Compares base/merge-base/head SHAs and the ordered touched-files list
 * across `validatedState` -> `observedState` -> `sealedState`, and compares
 * working-tree fingerprints to catch content-level drift (untracked/ignored
 * changes) that SHA/file-list comparisons alone would miss. Any mismatch —
 * including the optional `initialFingerprint` differing from
 * `afterFingerprint` — is accumulated and returned as BLOCKED with every
 * reason concatenated; a clean comparison returns PASS.
 * @returns {{status: 'PASS'|'BLOCKED', evidence: string, initialFingerprint?: string|null, beforeFingerprint: string|null, afterFingerprint: string|null}}
 */
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

/**
 * Gates whether `runCloseoutWorkflow` is allowed to actually execute the
 * configured checks: any FAIL among the plan/preflight/gate-integrity/
 * initial-tree statuses, or any pre-existing suppression finding, is a hard
 * FAIL; anything short of all four being exactly PASS is BLOCKED. Only a
 * PASS here lets validation phases run — an incomplete or dirty admission
 * never silently proceeds to executing checks.
 * @returns {'PASS'|'FAIL'|'BLOCKED'}
 */
const admissionStatus = ({ planStatus, preflight, gateIntegrity, initialTree, initialSuppressions }) => {
  if (planStatus === 'FAIL' || preflight.status === 'FAIL' || gateIntegrity.status === 'FAIL'
    || initialTree.status === 'FAIL' || initialSuppressions.length) return 'FAIL';
  if (planStatus !== 'PASS' || preflight.status !== 'PASS' || gateIntegrity.status !== 'PASS'
    || initialTree.status !== 'PASS') return 'BLOCKED';
  return 'PASS';
};

/**
 * Orchestrates a full PR closeout run end to end: resolve repo state, build
 * and admit the check plan, run validation, independently verify GitHub's
 * live gate/PR state, seal the repository against drift, and persist
 * evidence. `planOnly` short-circuits after building the plan and returns a
 * redacted preview without touching disk or running anything.
 *
 * Admission is gated on an independent live GitHub gate attestation
 * (`readLiveGateAttestation`) matching this exact base/head/configDigest —
 * only then do preflight, the initial suppression scan, and the initial
 * clean-tree fingerprint run, and only a clean admission (`admissionStatus`)
 * lets the configured checks actually execute. Each check runs through
 * `executeChecked`, which re-runs generator checks twice to prove
 * reproducibility and falls back to a serialized baseline comparison
 * (`verifyBaseline`, one at a time — they share a disposable git worktree)
 * when a check fails, to distinguish a pre-existing failure from one this PR
 * introduced.
 *
 * The tail of the run enforces ordering deliberately: the tree is
 * fingerprinted before and after the live-GitHub round trip
 * (`beforeGithubFingerprint`/`afterGithubFingerprint`) so a mutation that
 * happens purely around that network call is caught by `sealRepository`;
 * gate integrity is then re-classified against the *final* observed gate
 * changes and live attestation, not the initial local view. Evidence is
 * written twice: a PROVISIONAL report (forced BLOCKED, with its
 * evidence-write seal marked pending — that sub-seal cannot be computed
 * before something is actually on disk to compare against) is written
 * first, so a crash mid-run still leaves an unambiguously-incomplete report
 * on disk rather than a false PASS; only after that write is the tree
 * fingerprinted once more, the evidence-write seal computed by comparing
 * pre- and post-write state, and the final report (true `overallStatus`,
 * completed seal) written over it.
 * @param {{repo: string, baseRef: string, config?: object, outputDir?: string, planOnly?: boolean, dependencies?: object}} options `dependencies` overrides any of `DEFAULTS` (repo-state/git/GitHub/process/report I/O) for tests.
 * @returns {Promise<{report: object, paths: object}|object>} the full evidence report and its written paths; a redacted plan preview when `planOnly` is true.
 */
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
  const plan = buildCheckPlan({
    config,
    ...metadata,
    touchedFiles: initial.touchedFiles,
    // Expand fixed range checks (git-diff-check) from the live merge-base,
    // not a hard-coded origin/main, so non-main PR bases are correct.
    mergeBaseSha: initial.mergeBaseSha || initial.baseSha,
  });
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
    }, process.env, [...(config.requiredEnv || []), ...(config.safeEnv || [])]);
  }

  // Explicit --output-dir is shared-name; take an exclusive lock. Default dirs
  // already include pid+random uniqueness (Codex #4781560042).
  const explicitOutputDir = Boolean(outputDir);
  const requestedOutput = path.resolve(outputDir || defaultOutputDir(initial.repo, initial.headSha));
  assertOutputOutsideRepository(initial.repo, requestedOutput);
  const resolvedOutput = await d.prepareOutputDirectory({
    repo: initial.repo,
    outputDir: requestedOutput,
    exclusive: explicitOutputDir,
  });
  const childEnv = buildWorkflowEnvironment(process.env, config);
  const execute = d.execute || d.createCommandExecutor({
    repo: initial.repo,
    outputDir: resolvedOutput,
    env: childEnv,
    secretNames: [...(config.requiredEnv || []), ...(config.safeEnv || [])],
    timeoutMs: config.timeoutMs,
    timeoutsMs: config.timeoutsMs,
    grafanaServiceUrl: config.services?.grafana?.url || null,
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
  // Ignored generator outputs are invisible to cleanTreeStatus and the
  // tracked-diff hash, so fingerprint them at every seal point (admission,
  // post-validation, post-GitHub, post-evidence-write); a validation or
  // confirmation step mutating them after the generator reproducibility
  // check must break a seal instead of passing unnoticed.
  const reproducibilityPaths = [...new Set([
    'node_modules/.prisma',
    'node_modules/@prisma/client',
    ...(config.reproducibilityPaths || []),
  ])];
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
    if (initialTree.status === 'PASS') initialFingerprint = await d.workingTreeFingerprint(initial.repo, reproducibilityPaths);
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
        // A generator run that fails is returned as the top-level result
        // rather than under first/second; fall back to it so the row and the
        // head-side baseline signature keep the real exit code, output, and
        // timing instead of an empty terminal.
        const firstRun = reproducibility.first || reproducibility;
        const terminal = reproducibility.second || firstRun;
        // Preserve both generator attempts so renderMarkdown can count two
        // confirmation executions (Reruns observed / attempt IDs) instead of
        // treating the dual run as a single terminal-only row.
        const generatorAttempts = [reproducibility.first, reproducibility.second]
          .filter(Boolean);
        result = {
          ...check,
          phase,
          status: reproducibility.status,
          exitCode: terminal.exitCode ?? null,
          startedAt: firstRun.startedAt,
          finishedAt: terminal.finishedAt,
          durationMs: (firstRun.durationMs || 0) + (reproducibility.second?.durationMs || 0),
          stdout: terminal.stdout || '',
          stderr: terminal.stderr || '',
          evidence: reproducibility.evidence,
          first: reproducibility.first,
          second: reproducibility.second,
          attempts: generatorAttempts.length > 0 ? generatorAttempts : undefined,
        };
      } else {
        result = await execute(check, phase);
      }
      if (result.status === 'PASS') return result;
      // Baseline attribution is optional once head already failed. An
      // infrastructure throw from verifyBaseline (worktree create, filter
      // enumeration, etc.) must not replace a proven FAIL with BLOCKED.
      try {
        return await serializeBaseline(() => d.verifyBaseline({
          repo: initial.repo,
          baseSha: initial.baseSha,
          check,
          headResult: result,
          // Thread the sanitized childEnv into the disposable baseline worktree so
          // the internal git worktree add/remove runs with the filtered environment
          // (not ambient process.env/CI secrets), matching the command executor.
          env: childEnv,
          // Generator head failures use two-pass fingerprinting; baseline must
          // reproduce with the same two-run protocol, not a single generator exec.
          execute: async (baselineCheck, cwd) => {
            if (check.generator) {
              const repro = await verifyGeneratorReproducibility({
                executeGenerator: (run) => execute({
                  ...baselineCheck,
                  id: `${check.id}-baseline-comparison-gen-${run}`,
                  associatedCheckId: check.id,
                  attemptId: `${check.id}:baseline-gen-${run}:${++baselineAttempt}`,
                  generator: true,
                }, 'baseline', cwd),
                fingerprint: () => d.workingTreeFingerprint(cwd, reproducibilityPaths),
              });
              const firstRun = repro.first || repro;
              const terminal = repro.second || firstRun;
              return {
                ...baselineCheck,
                phase: 'baseline',
                status: repro.status,
                exitCode: terminal.exitCode ?? null,
                startedAt: firstRun.startedAt,
                finishedAt: terminal.finishedAt,
                durationMs: (firstRun.durationMs || 0) + (repro.second?.durationMs || 0),
                stdout: terminal.stdout || '',
                stderr: terminal.stderr || '',
                evidence: repro.evidence,
                first: repro.first,
                second: repro.second,
              };
            }
            return execute({
              ...baselineCheck,
              id: `${check.id}-baseline-comparison`,
              associatedCheckId: check.id,
              attemptId: `${check.id}:baseline:${++baselineAttempt}`,
            }, 'baseline', cwd);
          },
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
      } catch (error) {
        const note = error?.message || String(error);
        return {
          ...result,
          status: result.status === 'FAIL' ? 'FAIL' : 'BLOCKED',
          evidence: [
            result.evidence,
            `Baseline comparison unavailable (infrastructure error; head result preserved): ${note}`,
          ].filter(Boolean).join('\n'),
        };
      }
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
  // Cheap clean-tree probe before any fingerprint: a dirty tree already fails
  // closeout, so skip streaming multi-gigabyte untracked artifacts through
  // workingTreeFingerprint on the dirty path (before and after GitHub).
  const preGithubCleanTree = attestationAdmitted
    ? await d.cleanTreeStatus(finalState.repo)
    : { status: 'BLOCKED', evidence: 'Pre-GitHub tree inspection did not run because attestation admission was not clean.' };
  const beforeGithubFingerprint = (attestationAdmitted && preGithubCleanTree.status === 'PASS')
    ? await d.workingTreeFingerprint(finalState.repo, reproducibilityPaths)
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
    // Surface pre-GitHub dirt: a dirty probe that later cleans up must still
    // fail the clean-tree gate so the run cannot PASS after skipping the
    // before-GitHub fingerprint for performance.
    if (preGithubCleanTree.status !== 'PASS' && cleanTree.status === 'PASS') {
      cleanTree = {
        status: preGithubCleanTree.status === 'FAIL' ? 'FAIL' : 'BLOCKED',
        evidence: `Pre-GitHub working tree was not clean before live verification: ${preGithubCleanTree.evidence}`,
      };
    }
  }
  const afterGithubFingerprint = (attestationAdmitted && cleanTree.status === 'PASS')
    ? await d.workingTreeFingerprint(observedState.repo, reproducibilityPaths)
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
  // Include safeEnv alongside requiredEnv so custom secrets named only in
  // safeEnv (and embedded in configuredCommands / gateIntegrity) are redacted
  // from workflow-level reports — executors already redact both lists.
  const reportSecretNames = [...(config.requiredEnv || []), ...(config.safeEnv || [])];
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
    preGithubCleanTree,
    cleanTree,
    livePrState,
    touchedFiles: sealedState.touchedFiles,
    suppressionFindings: finalSuppressions,
    qualificationChecks: phases.qualification,
    checks: phases.confirmation,
  }, process.env, reportSecretNames), sealedState.repo, resolvedOutput);
  report.overallStatus = evaluateOverallStatus({
    planStatus,
    preflight,
    gateIntegrity,
    phases,
    reproducibility,
    preGithubCleanTree,
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
    ? await d.workingTreeFingerprint(evidenceState.repo, reproducibilityPaths)
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
    preGithubCleanTree,
    cleanTree,
    headConsistency,
    repositorySeal,
    livePrState,
    suppressionFindings: finalSuppressions,
  });
  await d.prepareOutputDirectory({ repo: initial.repo, outputDir: resolvedOutput });
  let paths = await d.writeEvidenceReport({ outputDir: resolvedOutput, report });
  // Post-write seal: a same-user swap of the output directory (or an ancestor)
  // after prepareOutputDirectory could redirect report.json/report.md into the
  // repository. Re-fingerprint and rewrite the report as non-PASS if the tree
  // moved after the evidence write.
  if (attestationAdmitted) {
    const postWriteState = await d.resolveRepositoryState({ repo: sealedState.repo, baseRef });
    const postWriteFingerprint = await d.workingTreeFingerprint(postWriteState.repo, reproducibilityPaths);
    const postWriteSeal = sealRepository({
      validatedState: evidenceState,
      observedState: postWriteState,
      sealedState: postWriteState,
      beforeFingerprint: evidenceFingerprint,
      afterFingerprint: postWriteFingerprint,
    });
    if (postWriteSeal.status !== 'PASS') {
      repositorySeal = {
        ...repositorySeal,
        status: repositorySeal.status === 'FAIL' || postWriteSeal.status === 'FAIL' ? 'FAIL' : 'BLOCKED',
        evidenceWrite: {
          status: postWriteSeal.status,
          evidence: `Post-write seal failed: ${postWriteSeal.evidence}`,
          fingerprint: postWriteFingerprint,
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
        preGithubCleanTree,
        cleanTree,
        headConsistency,
        repositorySeal,
        livePrState,
        suppressionFindings: finalSuppressions,
      });
      await d.prepareOutputDirectory({ repo: initial.repo, outputDir: resolvedOutput });
      paths = await d.writeEvidenceReport({ outputDir: resolvedOutput, report });
    }
  }
  return { report, paths };
};

module.exports = {
  acquireOutputDirLock,
  defaultOutputDir,
  evaluateOverallStatus,
  normalizePersistedPaths,
  prepareOutputDirectory,
  runCloseoutWorkflow,
  sealRepository,
};
