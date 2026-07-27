'use strict';

/**
 * CI gate: scan the PR (or push) touched-file set with scanTouchedSuppressions
 * and fail closed on any marker / config-silencing / test-weakening finding.
 * Also runs readGateChanges + classifyGateIntegrity and fails when the gate
 * status is FAIL (weakening, deleted gate files, decode errors) or when a
 * gate diff deletes validation-step lines (deletion-only weakening that
 * otherwise only yields BLOCKED without attestation).
 *
 * Resolves the comparison base from (in order):
 *   CLOSEOUT_BASE_SHA, GITHUB_BASE_SHA, GITHUB_EVENT_BEFORE (push preimage,
 *   only when the commit exists locally), merge-base with GITHUB_BASE_REF /
 *   origin/main / main, else the empty tree.
 *
 * Touched-file Git queries fail closed: any enumeration error aborts the
 * gate with a non-zero exit instead of treating the failure as an empty set.
 *
 * Diff form:
 * - commit bases use three-dot `base...HEAD` (PR-range / merge-base semantics)
 * - the empty-tree fallback uses two-dot `emptyTree HEAD` (symmetric range
 *   requires two commits and rejects a tree object)
 */

const { execFileSync } = require('node:child_process');
const path = require('node:path');
const { TextDecoder } = require('node:util');

const {
  VALIDATION_REMOVAL_PATTERNS,
  classifyGateIntegrity,
  isGateFile,
} = require('../scripts/pr_closeout_git');
const {
  readGateChanges,
  scanTouchedSuppressions,
} = require('../scripts/pr_closeout_repo');

const root = path.resolve(__dirname, '..');
// Large enough for a pathological multi-thousand-file PR; still bounded.
const GIT_MAX_BUFFER = 64 * 1024 * 1024;
const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';

// Mechanical lockfiles are pure generated dependency manifests: a routine
// dependency upgrade replaces hundreds of old records with new ones, so the
// fail-closed content-removal catch-all would flag every removed line as a
// validation weakening and fail CI even though no validation command or
// threshold changed. These files hold no validation steps, so exclude them
// from the content-removal scan; pattern-matched validation removals are
// still scanned separately and never match lockfile data (Codex M6UFnGM).
const LOCKFILE_PATTERNS = [
  /(^|[/\\])package-lock\.json$/i,
  /(^|[/\\])npm-shrinkwrap\.json$/i,
  /(^|[/\\])pnpm-lock\.yaml$/i,
  /(^|[/\\])yarn\.lock$/i,
  /(^|[/\\])bun\.lockb$/i,
  /(^|[/\\])bun\.lock$/i,
  /(^|[/\\])cargo\.lock$/i,
  /(^|[/\\])poetry\.lock$/i,
  /(^|[/\\])Pipfile\.lock$/i,
  /(^|[/\\])go\.sum$/i,
  /(^|[/\\])composer\.lock$/i,
  /(^|[/\\])gemfile\.lock$/i,
  /(^|[/\\])mix\.lock$/i,
  /(^|[/\\])podfile\.lock$/i,
  /(^|[/\\])pubspec\.lock$/i,
  /(^|[/\\])gradle\.lockfile$/i,
];
const isMechanicalLockfile = (filePath) => LOCKFILE_PATTERNS.some((pattern) => pattern.test(filePath));
// Fatal UTF-8: lossy decoding would replace invalid path bytes with U+FFFD
// and hand scanTouchedSuppressions a different pathname (ENOENT skip), so a
// touched non-UTF-8 path could evade the suppression gate entirely.
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });

/**
 * Run git in the repository root and return raw stdout as a Buffer
 * (undecoded). Path lists are NUL-delimited; callers that need text must
 * decode fatally (splitZ) or intentionally (gitScalar for ASCII SHAs).
 * @param {string[]} args
 * @param {object} [options]
 * @returns {Buffer}
 */
const gitBuffer = (args, options = {}) => {
  const { input, ...rest } = options;
  const stdout = execFileSync('git', args, {
    cwd: root,
    encoding: 'buffer',
    stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
    maxBuffer: GIT_MAX_BUFFER,
    input: input === undefined ? undefined : input,
    ...rest,
  });
  return Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout || '');
};

/**
 * Run git and return stdout decoded as UTF-8 (lossy only for non-path
 * content such as unified diffs). Prefer gitBuffer + splitZ for path lists.
 * @param {string[]} args
 * @param {object} [options]
 * @returns {string}
 */
const git = (args, options = {}) => gitBuffer(args, options).toString('utf8');

/** @param {string[]} args @param {object} [options] @returns {string} trimmed git stdout */
const gitScalar = (args, options = {}) => git(args, options).trim();

/**
 * Split a NUL-delimited git path list with a fatal UTF-8 decode per segment.
 * Preserves each nonempty segment (leading/trailing spaces are legal Git
 * path characters). Throws when any segment is not valid UTF-8 so the CI
 * gate fails closed instead of silently skipping a touched file.
 * @param {Buffer|string} data
 * @returns {string[]}
 */
const splitZ = (data) => {
  const buffer = Buffer.isBuffer(data)
    ? data
    : Buffer.from(String(data || ''), 'utf8');
  if (!buffer.length) return [];
  const paths = [];
  let start = 0;
  for (let i = 0; i <= buffer.length; i += 1) {
    if (i === buffer.length || buffer[i] === 0) {
      if (i > start) {
        const slice = buffer.subarray(start, i);
        let decoded;
        try {
          decoded = utf8Decoder.decode(slice);
        } catch {
          throw new Error(
            `Git path is not valid UTF-8 (fail closed): ${Buffer.from(slice).toString('hex').slice(0, 48)}`,
          );
        }
        if (decoded.length) paths.push(decoded);
      }
      start = i + 1;
    }
  }
  return paths;
};

/**
 * True when value is a usable commit/tree object ID (not empty, not the
 * all-zero push-create sentinel). Accepts abbreviated (7+) SHA-1 and full
 * SHA-256 object IDs.
 * @param {*} value
 * @returns {boolean}
 */
const isUsableSha = (value) => {
  const sha = String(value || '').trim();
  // GitHub push "before" is 40 zeros when the ref is newly created.
  // Accept both SHA-1 (≤40) and SHA-256 (64) object IDs.
  if (!sha || /^0+$/.test(sha)) return false;
  return /^[0-9a-f]{7,64}$/i.test(sha);
};

// Repository-specific empty tree (SHA-1 constant or SHA-256 hash-object result).
let cachedEmptyTreeSha = null;

/**
 * Resolve this repository's empty-tree object ID (SHA-1 well-known constant
 * or the SHA-256 hash-object result for an empty tree).
 * @param {string} [repoRoot] repository to query; defaults to the module root
 * @returns {string}
 */
const resolveEmptyTreeSha = (repoRoot = root) => {
  if (cachedEmptyTreeSha) return cachedEmptyTreeSha;
  try {
    cachedEmptyTreeSha = gitScalar(['hash-object', '-t', 'tree', '--stdin'], { input: '', cwd: repoRoot });
    if (cachedEmptyTreeSha) return cachedEmptyTreeSha;
  } catch {
    // fall through to the well-known SHA-1 empty tree
  }
  cachedEmptyTreeSha = EMPTY_TREE;
  return cachedEmptyTreeSha;
};

/**
 * True when `sha` denotes the empty tree. Comparison is case-insensitive and
 * accepts abbreviated empty-tree IDs (7+) so CLOSEOUT_BASE_SHA=4b825dc (or an
 * uppercase form) still selects the two-dot empty-tree diff path instead of a
 * three-dot commit range Git rejects.
 * @param {*} sha
 * @returns {boolean}
 */
const isEmptyTreeSha = (sha) => {
  const value = String(sha || '').trim().toLowerCase();
  if (!value || !/^[0-9a-f]{7,64}$/.test(value)) return false;
  const known = EMPTY_TREE.toLowerCase();
  const resolved = String(resolveEmptyTreeSha() || '').trim().toLowerCase();
  if (value === known || (resolved && value === resolved)) return true;
  if (known.startsWith(value)) return true;
  if (resolved && resolved.startsWith(value)) return true;
  return false;
};

/**
 * Comparison style for name-only / unified diffs against the resolved base.
 * - three-dot: PR / merge-base ranges (`base...HEAD`)
 * - two-dot: push preimage (`GITHUB_EVENT_BEFORE..HEAD`) so force-push
 *   removals against the actual previous tip are visible (Codex #4781637950)
 * - empty-tree: first-commit bootstrap
 * @type {'three-dot'|'two-dot'|'empty-tree'}
 */
let comparisonStyle = 'three-dot';

/**
 * Resolve the comparison base SHA for the CI suppression/gate scan from
 * env (CLOSEOUT_BASE_SHA / GITHUB_BASE_SHA / GITHUB_EVENT_BEFORE), then
 * merge-base with the PR base ref or main/master, else the empty tree.
 * @param {string} [repoRoot] repository the git queries run against; defaults
 *   to the module root. Test seam: unit tests point base resolution at a
 *   temporary repository; the CLI always uses the default.
 * @returns {string}
 */
const resolveBaseSha = (repoRoot = root) => {
  // Explicit operator override: default three-dot (PR-range semantics).
  if (isUsableSha(process.env.CLOSEOUT_BASE_SHA)) {
    comparisonStyle = 'three-dot';
    return process.env.CLOSEOUT_BASE_SHA.trim();
  }
  // PR base tip from Actions — three-dot against merge-base of this value.
  if (isUsableSha(process.env.GITHUB_BASE_SHA)) {
    comparisonStyle = 'three-dot';
    return process.env.GITHUB_BASE_SHA.trim();
  }
  // Push event preimage: compare against the actual previous tip (two-dot),
  // not merge-base, so a force-push cannot drop suppressions from the old
  // side without them appearing in the touched inventory / gate diff.
  if (isUsableSha(process.env.GITHUB_EVENT_BEFORE)) {
    // actions/checkout defaults to fetch-depth: 1, so a format-valid preimage
    // can name a commit that was never fetched. Returning it would make the
    // name-only diff die on an unknown revision before the gate evaluates, so
    // verify the object exists locally first; any error means "not available"
    // (CodeRabbit discussion_r3652923145).
    const beforeSha = process.env.GITHUB_EVENT_BEFORE.trim();
    try {
      gitBuffer(['cat-file', '-e', `${beforeSha}^{commit}`], { cwd: repoRoot });
      comparisonStyle = 'two-dot';
      return beforeSha;
    } catch {
      // Unfetched/unavailable preimage: fall through to GITHUB_BASE_REF /
      // origin/main / merge-base / empty-tree resolution instead of
      // selecting a base the diff cannot resolve.
    }
  }

  const baseRef = (process.env.GITHUB_BASE_REF || '').trim();
  if (baseRef) {
    // Actions provides GITHUB_BASE_REF as the bare branch name (e.g. main).
    const candidates = [
      `origin/${baseRef}`,
      `refs/remotes/origin/${baseRef}`,
      baseRef,
    ];
    for (const ref of candidates) {
      try {
        const mb = gitScalar(['merge-base', 'HEAD', ref], { cwd: repoRoot });
        if (isUsableSha(mb)) {
          comparisonStyle = 'three-dot';
          return mb;
        }
      } catch {
        // try next candidate
      }
    }
  }

  for (const ref of ['origin/main', 'main', 'origin/master', 'master']) {
    try {
      const head = gitScalar(['rev-parse', 'HEAD'], { cwd: repoRoot });
      const mb = gitScalar(['merge-base', 'HEAD', ref], { cwd: repoRoot });
      // On a push checkout, origin/main often equals HEAD; that yields an
      // empty range. Prefer a merge-base that is not HEAD.
      if (isUsableSha(mb) && mb !== head) {
        comparisonStyle = 'three-dot';
        return mb;
      }
    } catch {
      // try next
    }
  }

  // Last resort for a first commit on a new repo: the empty tree object
  // (SHA-1 well-known ID or the repository's SHA-256 empty tree).
  try {
    const empty = resolveEmptyTreeSha(repoRoot);
    if (isUsableSha(empty) || isEmptyTreeSha(empty)) {
      comparisonStyle = 'empty-tree';
      return empty;
    }
  } catch {
    // fall through
  }
  try {
    gitScalar(['cat-file', '-t', EMPTY_TREE], { cwd: repoRoot });
    comparisonStyle = 'empty-tree';
    return EMPTY_TREE;
  } catch {
    // fall through
  }

  throw new Error('Unable to resolve a comparison base SHA for the suppression scan');
};

/**
 * Name-only diff from base to HEAD. Commit bases use three-dot (PR range);
 * push preimages and the empty tree use two-dot.
 */
const diffNameOnly = (baseSha) => {
  if (isEmptyTreeSha(baseSha) || comparisonStyle === 'two-dot') {
    return splitZ(gitBuffer(['diff', '--name-only', '-z', baseSha, 'HEAD']));
  }
  return splitZ(gitBuffer(['diff', '--name-only', '-z', `${baseSha}...HEAD`]));
};

/**
 * Unified diff for gate files. Same three-dot vs two-dot rule as name-only.
 */
const diffUnified = (baseSha, files) => {
  if (!files.length) return '';
  // --no-textconv: a configured textconv filter must not rewrite deleted
  // validation lines before detectValidationRemovals scans the diff.
  if (isEmptyTreeSha(baseSha) || comparisonStyle === 'two-dot') {
    return git(['diff', '--unified=0', '--no-ext-diff', '--no-textconv', baseSha, 'HEAD', '--', ...files]);
  }
  // Three-dot: only PR-range changes (merge-base...HEAD), not base-branch-only
  // edits that would appear in a two-endpoint diff against a moved base tip.
  return git(['diff', '--unified=0', '--no-ext-diff', '--no-textconv', `${baseSha}...HEAD`, '--', ...files]);
};

/**
 * True when a unified-diff line is a file header (`--- a/path`, `--- /dev/null`)
 * rather than a removed source line such as `--coverage` → `---coverage`.
 * @param {string} line
 * @returns {boolean}
 */
const isUnifiedDiffFileHeader = (line) => /^--- (?:a\/|b\/|\/dev\/null)/.test(line);

/**
 * Build the complete touched-file set: PR/push range + unstaged + staged +
 * untracked. Fail closed: git errors propagate instead of becoming [].
 * @param {string} baseSha
 * @returns {string[]}
 */
const listTouchedFiles = (baseSha) => {
  const tracked = diffNameOnly(baseSha);
  const unstaged = splitZ(gitBuffer(['diff', '--name-only', '-z']));
  const staged = splitZ(gitBuffer(['diff', '--cached', '--name-only', '-z']));
  const untracked = splitZ(gitBuffer(['ls-files', '--others', '--exclude-standard', '-z']));
  return [...new Set([...tracked, ...unstaged, ...staged, ...untracked])].sort();
};

// Deletion of validation-bearing lines inside a still-present gate file does
// not produce a deletedFiles entry and may not match WEAKENING_PATTERNS on
// added lines, so classifyGateIntegrity alone can return BLOCKED. Treat these
// removals as FAIL in CI. Patterns are owned by pr_closeout_git.js
// (VALIDATION_REMOVAL_PATTERNS) so closeout and the CI scanner cannot drift.

/**
 * Scan gate-file diffs for removed validation-bearing lines (named security
 * actions, test/lint/audit commands). Deletion-only weakening often lacks
 * added-line markers, so this complements classifyGateIntegrity.
 * @param {string} baseSha
 * @param {string[]} gateFiles
 * @returns {string[]} truncated matching removed lines
 */
const detectValidationRemovals = (baseSha, gateFiles) => {
  if (!gateFiles.length) return [];
  let diff = '';
  try {
    diff = diffUnified(baseSha, gateFiles);
  } catch (error) {
    throw new Error(`Failed to read gate diff for validation-removal scan: ${error.message}`);
  }
  const findings = [];
  for (const line of diff.split(/\r?\n/)) {
    if (!line.startsWith('-') || isUnifiedDiffFileHeader(line)) continue;
    if (VALIDATION_REMOVAL_PATTERNS.some((pattern) => pattern.test(line))) {
      findings.push(line.slice(0, 200));
    }
  }
  return findings;
};

/**
 * Any substantive deleted content in gate files (not blank/comment-only).
 * Used by CI to fail-closed on replacements that neutralize smoke checks
 * without matching VALIDATION_REMOVAL_PATTERNS (Codex #4781495663).
 * @param {string} baseSha
 * @param {string[]} gateFiles
 * @returns {string[]} truncated removed lines
 */
const detectGateContentRemovals = (baseSha, gateFiles) => {
  if (!gateFiles.length) return [];
  let diff = '';
  try {
    diff = diffUnified(baseSha, gateFiles);
  } catch (error) {
    throw new Error(`Failed to read gate diff for content-removal scan: ${error.message}`);
  }
  const findings = [];
  for (const line of diff.split(/\r?\n/)) {
    // Keep `--coverage` / `--strict` removals: only skip real file headers.
    if (!line.startsWith('-') || isUnifiedDiffFileHeader(line)) continue;
    const body = line.slice(1).trim();
    if (!body || body.startsWith('#')) continue;
    findings.push(line.slice(0, 200));
  }
  return findings;
};

/**
 * CLI entry: resolve base/head, scan suppressions + gate integrity, exit
 * non-zero on FAIL findings or validation-step removals.
 * @returns {Promise<void>}
 */
const main = async () => {
  const baseSha = resolveBaseSha();
  const headSha = gitScalar(['rev-parse', 'HEAD']);
  const files = listTouchedFiles(baseSha);

  process.stdout.write(`suppression-scan base=${baseSha} head=${headSha} files=${files.length}\n`);

  const findings = await scanTouchedSuppressions(root, files);
  if (findings.length) {
    process.stderr.write(`FAIL: ${findings.length} suppression finding(s) in the touched-file set\n`);
    for (const finding of findings.slice(0, 50)) {
      process.stderr.write(
        `  ${finding.file}:${finding.line} [${finding.category}] ${finding.match}\n`,
      );
    }
    if (findings.length > 50) {
      process.stderr.write(`  ... and ${findings.length - 50} more\n`);
    }
    process.exitCode = 1;
  } else {
    process.stdout.write('suppression-scan: no marker/config-silencing/test-weakening findings\n');
  }

  // readGateChanges uses two-dot `git diff <base>` semantics. When baseSha is
  // the PR base *tip* (GITHUB_BASE_SHA), that can report base-only gate files
  // as deleted. Resolve merge-base(base, HEAD) for PR/three-dot bases so the
  // gate scan matches PR-range semantics. For push preimages (two-dot), keep
  // the actual previous tip so force-push removals stay visible.
  let gateBaseSha = baseSha;
  if (!isEmptyTreeSha(baseSha) && comparisonStyle !== 'two-dot') {
    try {
      const mb = gitScalar(['merge-base', baseSha, headSha]);
      if (isUsableSha(mb)) gateBaseSha = mb;
    } catch {
      // Keep baseSha if merge-base cannot be computed.
    }
  }
  const gate = await readGateChanges(root, gateBaseSha);
  const integrity = classifyGateIntegrity({
    changedFiles: gate.changedFiles,
    addedLines: gate.addedLines,
    deletedFiles: gate.deletedFiles,
    baseSha: gateBaseSha,
    headSha,
    configDigest: process.env.CLOSEOUT_CONFIG_DIGEST || 'ci-suppression-scan',
  });
  process.stdout.write(
    `gate-scan status=${integrity.status} changed=${gate.changedFiles.length} deleted=${gate.deletedFiles.length}\n`,
  );
  if (integrity.status === 'FAIL') {
    process.stderr.write(`FAIL: gate integrity ${integrity.evidence}\n`);
    process.exitCode = 1;
  } else if (integrity.status === 'BLOCKED') {
    // Additive gate changes still need live review for closeout, but CI must
    // not treat deletion/replacement weakening as success. Pattern-matched
    // validation removals fail first; any other substantive deleted gate
    // content also fails closed so a smoke block replaced by `echo passed`
    // cannot exit 0 when it evades VALIDATION_REMOVAL_PATTERNS (Codex
    // #4781495663). Pure additive BLOCKED remains a non-failing notice.
    const gateTargets = [...new Set([...gate.changedFiles, ...gate.deletedFiles])].filter(isGateFile);
    const removals = detectValidationRemovals(gateBaseSha, gateTargets);
    if (removals.length) {
      process.stderr.write(
        `FAIL: gate diff removes validation step(s) without a FAIL-class weakening match:\n`,
      );
      for (const line of removals.slice(0, 20)) {
        process.stderr.write(`  ${line}\n`);
      }
      process.exitCode = 1;
    } else {
      // Mechanical lockfiles (package-lock.json, pnpm-lock.yaml, Cargo.lock,
      // ...) are pure generated dependency manifests: a routine dependency
      // bump replaces old records with new ones, so their removed lines are
      // not validation weakening. Exclude them from the fail-closed
      // content-removal catch-all so legitimate dependency upgrades do not
      // fail CI; pattern-matched validation removals above still scan every
      // gate file and never match lockfile data (Codex M6UFnGM).
      const contentGateTargets = gateTargets.filter((file) => !isMechanicalLockfile(file));
      const contentRemovals = detectGateContentRemovals(gateBaseSha, contentGateTargets);
      if (contentRemovals.length) {
        process.stderr.write(
          `FAIL: gate diff removes content without a FAIL-class weakening match (fail-closed):\n`,
        );
        for (const line of contentRemovals.slice(0, 20)) {
          process.stderr.write(`  ${line}\n`);
        }
        process.exitCode = 1;
      } else {
        process.stdout.write(
          `gate-scan: BLOCKED (additive-only; no gate content removals): ${integrity.evidence}\n`,
        );
      }
    }
  } else {
    process.stdout.write(`gate-scan: ${integrity.status}\n`);
  }

  if (process.exitCode) {
    process.stderr.write('touched-file suppression/gate scan failed\n');
  }
};

/**
 * Comparison style chosen by the most recent resolveBaseSha call. Test seam
 * for asserting which base branch was selected; the CLI reads the module
 * binding directly.
 * @returns {'three-dot'|'two-dot'|'empty-tree'}
 */
const getComparisonStyle = () => comparisonStyle;

if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`suppression-scan error: ${error?.stack || error}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  getComparisonStyle,
  resolveBaseSha,
  detectGateContentRemovals,
  isMechanicalLockfile,
};
