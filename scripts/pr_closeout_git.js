const { execFile } = require('node:child_process');
const { createHash } = require('node:crypto');
const { lstat, mkdir, mkdtemp, rename, rm } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const { promisify } = require('node:util');

const { scanSuppressionText } = require('./pr_closeout_core');

const execFileAsync = promisify(execFile);

/**
 * Recursively canonicalizes `value` by sorting object keys (array order is
 * left untouched) so JSON.stringify produces identical output regardless of
 * property insertion order. digestValidationConfig relies on this so two
 * configs that differ only in key order still hash identically.
 * @param {*} value
 * @returns {*} the same structure with every nested object's keys sorted.
 */
const stableValue = (value) => {
  if (Array.isArray(value)) return value.map(stableValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stableValue(value[key])]));
  }
  return value;
};

/**
 * SHA-256 digest of `value` after canonicalizing key order (see
 * stableValue), so semantically identical validation configs hash the same
 * regardless of how their keys were written. classifyGateIntegrity binds a
 * review attestation to this digest so an attestation cannot be replayed
 * against a configuration that was edited after the review.
 * @param {*} value
 * @returns {string} hex-encoded SHA-256 digest.
 */
const digestValidationConfig = (value) => createHash('sha256')
  .update(JSON.stringify(stableValue(value)))
  .digest('hex');

const normalizePath = (file) => String(file).replaceAll('\\', '/').replace(/^\.\//, '');

/**
 * True when `file` is one of the paths that define or configure validation
 * strength: CI workflows, package manifests/lockfiles, linter/formatter
 * configs, Makefiles (including GNU make's alternate default filenames),
 * test-runner configs, and the closeout tool's own config file. This is the
 * classifier classifyGateIntegrity uses to decide which changed files
 * require a live review attestation instead of passing on trust.
 * @param {string} file
 * @returns {boolean}
 */
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

/**
 * Decides whether changes to validation-defining "gate" files (CI configs,
 * lockfiles, linters, Makefiles, the closeout config itself, ...) preserve
 * or weaken enforcement. Deleted gate files, detected weakening patterns
 * (test `.only`/`.skip`, `--no-verify`, zeroed coverage thresholds,
 * suppression markers), or a gate diff that could not be fully decoded all
 * FAIL unconditionally — even with an attestation — because the gate must
 * fail closed whenever it cannot prove the change is safe. Otherwise, PASS
 * requires an independent live GitHub PR review `attestation` bound to the
 * exact baseSha/headSha/configDigest tuple with `decision: 'not-weakened'`;
 * a caller-supplied `review` object (self-attestation) is never sufficient.
 * Anything short of that is BLOCKED, pending human review.
 * @param {object} options destructured: changedFiles, addedLines,
 *   deletedFiles, configuredCommands, baseSha, headSha, configDigest,
 *   attestation.
 * @returns {{status: 'PASS'|'FAIL'|'BLOCKED', evidence: string}}
 */
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

/**
 * Hashes a set of `{path, hash}` entries into one order-independent
 * SHA-256 digest, so a working tree's contents can be fingerprinted and
 * compared for drift (e.g. across two generator runs) regardless of the
 * order entries were collected in.
 * @param {{path: string, hash: string}[]} entries
 * @returns {string} hex-encoded SHA-256 digest.
 */
const fingerprintEntries = (entries) => {
  const hash = createHash('sha256');
  for (const entry of [...entries].sort((left, right) => left.path.localeCompare(right.path))) {
    hash.update(`${normalizePath(entry.path)}\0${entry.hash}\0`);
  }
  return hash.digest('hex');
};

/**
 * Proves a code generator (e.g. `prisma generate`) is deterministic by
 * running it twice and comparing working-tree fingerprints in between. A
 * dirty first or second run short-circuits with that run's own status; a
 * clean pair whose fingerprints differ FAILs as non-reproducible generated
 * output — a generator that only matches the tree on some runs would let
 * committed generated code silently drift from its source of truth.
 * @param {{executeGenerator: (attempt: number) => Promise<object>, fingerprint: () => Promise<string>}} options
 * @returns {Promise<object>} a PASS/FAIL result with both attempts and both fingerprints attached.
 */
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

const STABLE_PROOF_KEYS = ['status', 'exists', 'digest', 'evidence', 'matched', 'matchPolicyValid', 'policyValid'];
/**
 * Reduces a captured proof result to the fields that identify a logical
 * failure, dropping volatile artifact-identity fields: path/realPath/realRoot
 * are absolute paths resolved against the per-run command worktree (so they
 * differ between the head repo and the disposable baseline worktree), and
 * dev/ino/mtimeMs/ctimeMs/size/logPath/durationMs vary every run because the
 * proof artifact is regenerated. Without this normalization, failureSignature
 * could never match the same logical failure across head and baseline, so
 * the baseline comparison would always report "did not reproduce" even for
 * identical failures.
 * @param {object|null} proofResult
 * @returns {object|null} only the stable subset of fields, or null if proofResult is absent.
 */
const stableProofResult = (proofResult) => {
  if (!proofResult || typeof proofResult !== 'object') return null;
  return Object.fromEntries(STABLE_PROOF_KEYS.filter((key) => key in proofResult).map((key) => [key, proofResult[key]]));
};

/**
 * Renders a check result into canonical text for hashing into a failure
 * signature. Prefers the pre-computed `outputDigest` (paired with the
 * stable proof fields) when present; otherwise falls back to raw
 * stdout/stderr with ANSI escapes stripped, CRLF normalized, and every
 * variant of the run's absolute `cwd` (forward- and back-slash) replaced
 * with `<repo>`, so the same logical failure hashes identically whether it
 * ran in the head repo or a disposable baseline worktree at a different path.
 * @param {object} result a check execution result.
 * @returns {string} canonical text ready for hashing.
 */
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

/**
 * SHA-256 digest of a check result's canonicalized failure text (see
 * normalizeFailure), used to compare a head failure against a baseline
 * failure for exact-match equality independent of volatile paths/formatting.
 * @param {object} result a check execution result.
 * @returns {string} hex digest identifying this logical failure.
 */
const failureSignature = (result) => createHash('sha256').update(normalizeFailure(result)).digest('hex');

/**
 * Runs `git` in `repo` and resolves to stdout only. Applies a large
 * maxBuffer and a bounded default timeout (see the inline comment below) so
 * a wedged internal git call cannot hang the closeout gate; `options` can
 * override either per call.
 * @param {string} repo working directory to run git in.
 * @param {string[]} args git subcommand and arguments.
 * @param {object} [options] overrides merged over the defaults (e.g. env, timeout).
 * @returns {Promise<string>} stdout.
 */
const runGit = async (repo, args, options = {}) => {
  const result = await execFileAsync('git', args, {
    cwd: repo,
    encoding: 'utf8',
    maxBuffer: 20_000_000,
    // Bound internal git calls so a wedged worktree/fsmonitor/filter cannot hang
    // the closeout gate indefinitely (overridable per call via options.timeout).
    timeout: 120_000,
    ...options,
  });
  return result.stdout;
};

/**
 * Checks out `baseSha` into a disposable, detached git worktree under a
 * fresh temp directory, runs `callback(worktreePath)`, and guarantees the
 * worktree and its temp directory are removed afterward (even if the
 * callback throws), so baseline comparisons never leak state into the real
 * repo or persist across runs. Refuses to proceed if the generated temp
 * path does not actually resolve inside the OS temp directory, so a hostile
 * or misconfigured temp root cannot trick cleanup into acting outside it.
 * Internal git calls that create/remove the worktree are hardened against
 * executing attacker-controlled config from the checked-out commit (hooks,
 * fsmonitor, attributes smudge filters — see the inline comments below)
 * and, when `env`/`timeoutMs` are supplied, run with the workflow's
 * sanitized environment and a bounded timeout so they cannot inherit
 * ambient CI secrets or hang the gate.
 * @param {{repo: string, baseSha: string, env?: object, timeoutMs?: number}} options
 * @param {(worktreePath: string) => Promise<*>} callback
 * @returns {Promise<*>} whatever `callback` resolves to.
 */
const withDisposableWorktree = async ({ repo, baseSha, env, timeoutMs } = {}, callback) => {
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
  //    filter can run an external command during the worktree checkout.
  //  - filter.<driver>.{smudge,clean,process,required}: repository-local
  //    filter drivers are a separate config surface from core.attributesFile.
  //    Clearing only the global attributes path still lets `.git/info/
  //    attributes` or in-tree `.gitattributes` assign a driver. Git prefers
  //    `filter.<driver>.process` (long-running filter protocol) over smudge/
  //    clean when present, so neutralizing only smudge/clean leaves an
  //    executable path open. Enumerate every local filter.* key, then for
  //    each driver name force smudge=/clean=/process= empty and
  //    required=false via -c overrides.
  //  - `.git/info/attributes`: temporarily rename away during the internal
  //    checkout so per-repo attributes cannot re-enable a filter driver even
  //    if config discovery misses a name.
  const noHooksDir = path.join(parent, 'no-hooks');
  await mkdir(noHooksDir, { recursive: true });
  const filterOverrides = [];
  try {
    // Match any filter.<driver>.<setting> key so process/required cannot hide
    // behind a non-smudge/clean suffix.
    const listed = await runGit(repo, ['config', '--local', '--get-regexp', '^filter\\.'], {
      ...(env ? { env } : {}),
      ...(timeoutMs ? { timeout: timeoutMs } : {}),
    });
    const drivers = new Set();
    for (const line of String(listed || '').split(/\r?\n/)) {
      const key = line.trim().split(/\s+/, 1)[0];
      if (!key || !key.startsWith('filter.')) continue;
      // filter.<driver>.<setting>: driver may contain dots (filter.a.b.process).
      const lastDot = key.lastIndexOf('.');
      if (lastDot <= 'filter.'.length) continue;
      const driver = key.slice('filter.'.length, lastDot);
      if (driver) drivers.add(driver);
    }
    for (const driver of drivers) {
      filterOverrides.push(
        '-c', `filter.${driver}.smudge=`,
        '-c', `filter.${driver}.clean=`,
        '-c', `filter.${driver}.process=`,
        '-c', `filter.${driver}.required=false`,
      );
    }
  } catch (error) {
    // git config --get-regexp exits 1 when there are no matches. Some Git
    // versions also exit 1 (not 128) when .git/config is unreadable or not a
    // regular file (e.g. replaced by a directory). Only treat exit 1 as
    // "no drivers" when the local config path is a readable regular file.
    const exitCode = error?.code;
    if (exitCode !== 1 && exitCode !== '1') {
      throw new Error(
        `Failed to enumerate local filter.* keys for baseline worktree safety: ${error?.message || error}`,
      );
    }
    let configPath;
    try {
      const gitPath = String(await runGit(repo, ['rev-parse', '--git-path', 'config'], {
        ...(env ? { env } : {}),
        ...(timeoutMs ? { timeout: timeoutMs } : {}),
      })).trim();
      configPath = path.isAbsolute(gitPath) ? gitPath : path.resolve(repo, gitPath);
      const info = await lstat(configPath);
      if (!info.isFile()) {
        throw new Error(`local config is not a regular file: ${configPath}`);
      }
    } catch (verifyError) {
      throw new Error(
        `Failed to enumerate local filter.* keys for baseline worktree safety: ${verifyError?.message || verifyError}`,
      );
    }
  }
  const withInternalSafety = (args) => [
    '-c', `core.hooksPath=${noHooksDir}`,
    '-c', 'core.fsmonitor=',
    '-c', 'core.useBuiltinFSMonitor=false',
    '-c', 'core.attributesFile=',
    ...filterOverrides,
    ...args,
  ];
  // Run internal baseline git with the workflow's sanitized environment (when
  // provided) and a bounded timeout so the baseline checkout does not inherit
  // ambient CI secrets via process.env and cannot hang the closeout gate.
  const gitOptions = {};
  if (env) gitOptions.env = env;
  if (timeoutMs) gitOptions.timeout = timeoutMs;

  // Resolve through git so linked worktrees (where .git is a file) still
  // locate the shared info/attributes path. path.join(repo, '.git', ...) is
  // ENOTDIR in that case and would block every baseline comparison.
  const infoAttributesRaw = String(await runGit(repo, ['rev-parse', '--git-path', 'info/attributes'], gitOptions)).trim();
  const infoAttributes = path.isAbsolute(infoAttributesRaw)
    ? infoAttributesRaw
    : path.resolve(repo, infoAttributesRaw);
  const infoAttributesBackup = `${infoAttributes}.closeout-disabled.${process.pid}`;
  let attributesMoved = false;
  try {
    try {
      await rename(infoAttributes, infoAttributesBackup);
      attributesMoved = true;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
    try {
      await runGit(repo, withInternalSafety(['worktree', 'add', '--detach', worktree, baseSha]), gitOptions);
      added = true;
      return await callback(worktree);
    } catch (error) {
      primaryError = error;
      throw error;
    } finally {
      try {
        if (added) {
          await runGit(repo, withInternalSafety(['worktree', 'remove', '--force', worktree]), gitOptions);
          await runGit(repo, withInternalSafety(['worktree', 'prune']), gitOptions);
        }
      } finally {
        try {
          await rm(parent, { recursive: true, force: true });
        } catch (cleanupError) {
          if (!primaryError) throw cleanupError;
        }
      }
    }
  } finally {
    if (attributesMoved) {
      try {
        await rename(infoAttributesBackup, infoAttributes);
      } catch (restoreError) {
        if (!primaryError) throw restoreError;
        // Primary path already failed; still surface that the repo was left
        // without its .git/info/attributes (orphaned closeout-disabled file).
        const detail = `Failed to restore ${infoAttributes}: ${restoreError?.message || restoreError}`;
        primaryError.restoreFailure = detail;
        try {
          process.stderr.write(`${detail}\n`);
        } catch {
          // stderr may be closed; property attachment above is enough.
        }
      }
    }
  }
};

/**
 * Determines whether a head failure for `check` also reproduces at
 * `baseSha`, so a pre-existing failure can be reported as inherited from
 * the base rather than misattributed to this PR. Skips the comparison
 * entirely when the check is not `baselineSafe` (some checks, like a Docker
 * build, are unsafe or too expensive to duplicate in a throwaway worktree).
 * Runs `setup` then `execute` inside a disposable worktree at the base
 * commit (via `withWorktree`); a failed setup BLOCKs rather than trusting
 * an incomplete baseline, and a `toolVersions` mismatch between head and
 * baseline environments refuses to make any baseline claim at all. Only an
 * exact `failureSignature` match against a non-PASS baseline result labels
 * the head result `status: 'BASELINE'` — note this is still `blocking:
 * true` (statusFrom rolls BASELINE into overall BLOCKED): a pre-existing
 * failure is not attributed to this PR, but it must not silently pass the
 * gate either. Any other outcome returns `headResult` with its original
 * status untouched, i.e. a failure that does not reproduce at the base is
 * treated as a regression introduced by this PR.
 * @param {object} options destructured: repo, baseSha, check, headResult,
 *   withWorktree, execute, toolVersions, captureVersions, setup, env,
 *   baselineGitTimeoutMs (see body for how each is used).
 * @returns {Promise<object>} headResult, possibly augmented with baseline
 *   evidence and/or reclassified to `status: 'BASELINE'`.
 */
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
  env,
  baselineGitTimeoutMs,
} = {}) => {
  if (!check.baselineSafe) {
    return { ...headResult, evidence: `${headResult.evidence || ''} Check is not baseline-safe; no baseline claim was made.`.trim() };
  }
  const comparison = await withWorktree({ repo, baseSha, env, timeoutMs: baselineGitTimeoutMs }, async (worktree) => {
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
