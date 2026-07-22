const { execFile } = require('node:child_process');
const { createHash } = require('node:crypto');
const { mkdir, mkdtemp, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { promisify } = require('node:util');

const { scanSuppressionText } = require('./pr_closeout_core');

const execFileAsync = promisify(execFile);

const stableValue = (value) => {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
};

const digestValidationConfig = (value) => createHash('sha256')
  .update(JSON.stringify(stableValue(value)))
  .digest('hex');

const normalizePath = (file) => String(file).replaceAll('\\', '/').replace(/^\.\//, '');

const isGateFile = (file) => {
  const normalized = normalizePath(file);
  const base = path.posix.basename(normalized).toLowerCase();
  return normalized.startsWith('.github/workflows/')
    || base === 'package.json'
    || /^\.(?:eslintrc|biomerc)(?:\..+)?$/.test(base)
    // Match all of GNU make's default filenames (GNUmakefile, makefile,
    // Makefile) so a weakening change to whichever one readProjectMetadata
    // actually discovers is treated as a gate change.
    || /^(?:gnu)?makefile(?:\..+)?$/.test(base)
    || /^(?:pnpm-lock\.yaml|package-lock\.json|npm-shrinkwrap\.json|biome(?:\..+)?\.jsonc?|tsconfig(?:\..+)?\.json)$/.test(base)
    || /^(?:vitest|vite|jest|playwright|cypress|eslint)(?:\.[^.]+)*\.config\.[a-z0-9]+$/.test(base)
    || /(?:^|\/)\.?pr-closeout(?:\.[^/]+)?\.json$/.test(normalized);
};

const WEAKENING_PATTERNS = [
  /\b(?:describe|it|test)\.(?:skip|only|todo)\b/i,
  /--(?:no-verify|force|passWithNoTests)\b/i,
  /(?:coverage|threshold)["']?\s*[:=]\s*(?:["']?0(?:\.0+)?["']?|false|null)(?![\w.])/i,
  // Intentionally NOT matching strategy.fail-fast: false / failFast: false.
  // In GitHub Actions that setting keeps the rest of the matrix running after
  // one leg fails (required for full Node/OS visibility). Flagging it as gate
  // weakening made any workflow adding the standard matrix line FAIL even with
  // an exact authorized review.
];

// A coverage threshold can also be zeroed in nested config form, with the
// coverage/threshold key and the zeroed metric on separate added lines
// (`coverageThreshold:` on one line, `statements: 0` on the next). The
// per-line patterns above never see both halves of that combination, so the
// joined added diff is scanned with these patterns as well.
const MULTILINE_WEAKENING_PATTERNS = [
  /(?:coverage|threshold)["']?\s*[:=][\s\S]{0,160}?\b(?:statements|branches|functions|lines)["']?\s*[:=]\s*["']?0(?:\.0+)?["']?(?![\w.])/i,
];

const classifyGateIntegrity = ({
  changedFiles = [], addedLines = [], deletedFiles = [], configuredCommands = [], baseSha, headSha, configDigest, attestation,
} = {}) => {
  const gateFiles = changedFiles.filter(isGateFile);
  const configured = [...new Set(configuredCommands)].sort();
  // A deleted gate file contributes no added lines to scan, so the weakening
  // checks below have nothing to evaluate for it. Removing an entire
  // validation surface must fail closed rather than PASS on attestation alone.
  const deletedGateFiles = deletedFiles.filter(isGateFile);
  if (deletedGateFiles.length) {
    return {
      status: 'FAIL',
      changedFiles: gateFiles,
      deletedFiles: deletedGateFiles,
      configuredCommands: configured,
      evidence: `Validation-defining gate files were deleted: ${deletedGateFiles.slice(0, 5).join(' | ')}`,
    };
  }
  const suppressionFindings = scanSuppressionText('__gate__.json', addedLines.join('\n'));
  const joinedAddedLines = addedLines.join('\n');
  const weakening = [
    ...addedLines.filter((line) => WEAKENING_PATTERNS.some((pattern) => pattern.test(line))),
    ...MULTILINE_WEAKENING_PATTERNS
      .map((pattern) => joinedAddedLines.match(pattern))
      .filter(Boolean)
      .map((match) => match[0].replace(/\s*\n\s*/g, ' ')),
    ...suppressionFindings.map((finding) => finding.match),
  ];
  if (weakening.length) {
    return {
      status: 'FAIL',
      changedFiles: gateFiles,
      configuredCommands: configured,
      evidence: `Potential gate weakening detected: ${weakening.slice(0, 5).join(' | ')}`,
    };
  }
  // A gate file that could not be fully decoded (tracked-diff maxBuffer
  // overflow, an oversized/missing/symlinked untracked gate file) leaves the
  // gate change set unscannable. Refuse to PASS on attestation alone in that
  // case — the closeout gate cannot prove no weakening was introduced when it
  // could not read the complete diff.
  const decodeErrors = addedLines.filter((line) => String(line).includes('__decode_error__'));
  if (decodeErrors.length) {
    return {
      status: 'FAIL',
      changedFiles: gateFiles,
      configuredCommands: configured,
      evidence: `Gate change could not be fully decoded; refusing to PASS without a complete scan: ${decodeErrors.slice(0, 3).join(' | ')}`,
    };
  }
  const reviewed = attestation
    && attestation.provider === 'github-pull-request-review'
    && attestation.status === 'PASS'
    && typeof baseSha === 'string'
    && baseSha.trim()
    && typeof configDigest === 'string'
    && configDigest.trim()
    && attestation.baseSha === baseSha
    && attestation.headSha === headSha
    && attestation.configDigest === configDigest
    && attestation.decision === 'not-weakened'
    && typeof attestation.reviewer === 'string'
    && attestation.reviewer.trim()
    && typeof attestation.evidence === 'string'
    && attestation.evidence.trim();
  if (reviewed) {
    return {
      status: 'PASS',
      changedFiles: gateFiles,
      configuredCommands: configured,
      attestation,
      evidence: `Independent exact-head GitHub gate review by ${attestation.reviewer}: ${attestation.evidence}`,
    };
  }
  return {
    status: 'BLOCKED',
    changedFiles: gateFiles,
    configuredCommands: configured,
    attestation,
    evidence: 'Every executable validation surface requires an independent live GitHub review bound to the exact base, head, and configuration digest.',
  };
};

const fingerprintEntries = (entries) => {
  const hash = createHash('sha256');
  for (const entry of [...entries].sort((left, right) => left.path.localeCompare(right.path))) {
    hash.update(`${normalizePath(entry.path)}\0${entry.hash}\0`);
  }
  return hash.digest('hex');
};

const verifyGeneratorReproducibility = async ({ executeGenerator, fingerprint }) => {
  const first = await executeGenerator(1);
  if (first.status !== 'PASS') {
    return { ...first, evidence: `First generator run was not clean. ${first.evidence || ''}`.trim() };
  }
  const afterFirst = await fingerprint();
  const second = await executeGenerator(2);
  if (second.status !== 'PASS') {
    return { ...second, evidence: `Second generator run was not clean. ${second.evidence || ''}`.trim() };
  }
  const afterSecond = await fingerprint();
  if (afterFirst !== afterSecond) {
    return {
      status: 'FAIL',
      evidence: 'The second generator run changed the tree; generated output is not reproducible.',
      first,
      second,
      afterFirst,
      afterSecond,
    };
  }
  return {
    status: 'PASS',
    evidence: 'Two generator runs produced the same working-tree fingerprint.',
    first,
    second,
    fingerprint: afterSecond,
  };
};

// Reduce a proof result to its stable fields for baseline failure signatures.
// proofResult carries volatile artifact-identity fields (path/realPath/realRoot
// are absolute paths resolved against the per-run command worktree, so they
// differ between the head repo and the disposable baseline worktree;
// dev/ino/mtimeMs/ctimeMs/size change every run because the proof artifact is
// regenerated, and logPath/durationMs vary per attempt). Without normalization,
// failureSignature() cannot match the same logical failure across head and
// baseline, so the baseline comparison always reports "did not reproduce" even
// for identical failures.
const STABLE_PROOF_KEYS = ['status', 'exists', 'digest', 'evidence', 'matched', 'matchPolicyValid', 'policyValid'];
const stableProofResult = (proofResult) => {
  if (!proofResult || typeof proofResult !== 'object') return null;
  return Object.fromEntries(STABLE_PROOF_KEYS.filter((key) => key in proofResult).map((key) => [key, proofResult[key]]));
};

const normalizeFailure = (result) => {
  if (result.outputDigest) {
    return `${result.status}\n${result.exitCode}\n${result.timedOut || false}\n${JSON.stringify(result.outputDigest)}\n${JSON.stringify(stableProofResult(result.proofResult))}`;
  }
  let output = `${result.status}\n${result.exitCode}\n${result.stdout || ''}\n${result.stderr || ''}`
    .replace(/\x1b\[[0-9;]*m/g, '')
    .replace(/\r\n/g, '\n');
  for (const root of [...new Set([
    result.cwd,
    result.cwd?.replaceAll('\\', '/'),
    result.cwd?.replaceAll('/', '\\'),
  ].filter(Boolean))]) output = output.replaceAll(root, '<repo>');
  return output.trim();
};

const failureSignature = (result) => createHash('sha256').update(normalizeFailure(result)).digest('hex');

const runGit = async (repo, args, options = {}) => {
  const result = await execFileAsync('git', args, { cwd: repo, encoding: 'utf8', maxBuffer: 20_000_000, ...options });
  return result.stdout;
};

const withDisposableWorktree = async ({ repo, baseSha }, callback) => {
  const parent = await mkdtemp(path.join(tmpdir(), 'codex-pr-baseline-'));
  const worktree = path.join(parent, 'worktree');
  const resolvedParent = path.resolve(parent);
  const relativeToTemp = path.relative(path.resolve(tmpdir()), resolvedParent);
  if (!relativeToTemp || relativeToTemp === '..' || relativeToTemp.startsWith(`..${path.sep}`) || path.isAbsolute(relativeToTemp)) {
    throw new Error('Refusing unsafe baseline path.');
  }
  let added = false;
  let primaryError;
  // Disable hooks AND the internal Git mechanisms that can execute attacker
  // code during an internal worktree create/remove, outside the command
  // executor's timeout/redaction/process-tree controls:
  //  - core.hooksPath: post-checkout/post-rewrite hooks on worktree add/remove.
  //  - core.fsmonitor / core.useBuiltinFSMonitor: the fsmonitor hook is invoked
  //    by `git worktree add` when configured (it inherits the repo's fsmonitor),
  //    so a validation command that sets core.fsmonitor gets code executed.
  //  - core.attributesFile: a global attributes file plus a per-driver smudge
  //    filter can run an external command during the worktree checkout; clearing
  //    the global attributes source neutralizes that vector for this checkout.
  //    (In-tree .gitattributes is reviewed/trusted; .git/info/attributes shares
  //    the same per-repo trust boundary as the hooks config neutralized above.)
  const noHooksDir = path.join(parent, 'no-hooks');
  await mkdir(noHooksDir, { recursive: true });
  const withInternalSafety = (args) => [
    '-c', `core.hooksPath=${noHooksDir}`,
    '-c', 'core.fsmonitor=',
    '-c', 'core.useBuiltinFSMonitor=false',
    '-c', 'core.attributesFile=',
    ...args,
  ];
  try {
    await runGit(repo, withInternalSafety(['worktree', 'add', '--detach', worktree, baseSha]));
    added = true;
    return await callback(worktree);
  } catch (error) {
    primaryError = error;
    throw error;
  } finally {
    try {
      if (added) {
        await runGit(repo, withInternalSafety(['worktree', 'remove', '--force', worktree]));
        await runGit(repo, withInternalSafety(['worktree', 'prune']));
      }
    } finally {
      try {
        await rm(parent, { recursive: true, force: true });
      } catch (cleanupError) {
        if (!primaryError) throw cleanupError;
      }
    }
  }
};

const verifyBaseline = async ({
  repo,
  baseSha,
  check,
  headResult,
  withWorktree = withDisposableWorktree,
  execute,
  toolVersions,
  captureVersions,
  setup,
} = {}) => {
  if (!check.baselineSafe) {
    return { ...headResult, evidence: `${headResult.evidence || ''} Check is not baseline-safe; no baseline claim was made.`.trim() };
  }
  const comparison = await withWorktree({ repo, baseSha }, async (worktree) => {
    const setupResult = setup ? await setup(worktree) : { status: 'PASS', evidence: 'No baseline setup configured.' };
    if (setupResult.status !== 'PASS') return { setupResult };
    return {
      setupResult,
      baseline: await execute(check, worktree),
      toolVersions: captureVersions ? await captureVersions(worktree) : toolVersions,
    };
  });
  if (!comparison.baseline) {
    return {
      ...headResult,
      status: 'BLOCKED',
      baselineSetup: comparison.setupResult,
      evidence: `Baseline dependency setup was not clean. ${comparison.setupResult?.evidence || ''}`.trim(),
    };
  }
  const baseline = comparison.baseline;
  const canonicalVersions = (versions) => JSON.stringify(
    Object.fromEntries(Object.entries(versions || {}).sort(([left], [right]) => left.localeCompare(right))),
  );
  if (toolVersions && canonicalVersions(toolVersions) !== canonicalVersions(comparison.toolVersions)) {
    return {
      ...headResult,
      baseline,
      baselineSetup: comparison.setupResult,
      baselineToolVersions: comparison.toolVersions,
      evidence: `${headResult.evidence || ''} Baseline tool versions differ; no baseline claim was made.`.trim(),
    };
  }
  const matches = baseline.status !== 'PASS' && failureSignature(baseline) === failureSignature(headResult);
  if (matches) {
    return {
      ...headResult,
      status: 'BASELINE',
      blocking: true,
      baseline,
      baselineSetup: comparison.setupResult,
      baselineToolVersions: comparison.toolVersions,
      evidence: `Failure reproduced exactly at base ${baseSha}; baseline remains blocking.`,
    };
  }
  return {
    ...headResult,
    baseline,
    baselineSetup: comparison.setupResult,
    baselineToolVersions: comparison.toolVersions,
    evidence: `${headResult.evidence || ''} Failure did not reproduce exactly at base ${baseSha}.`.trim(),
  };
};

module.exports = {
  classifyGateIntegrity,
  digestValidationConfig,
  failureSignature,
  fingerprintEntries,
  isGateFile,
  verifyBaseline,
  verifyGeneratorReproducibility,
  withDisposableWorktree,
};
