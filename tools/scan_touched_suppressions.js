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
 *   CLOSEOUT_BASE_SHA, GITHUB_BASE_SHA, GITHUB_EVENT_BEFORE (push preimage),
 *   merge-base with GITHUB_BASE_REF / origin/main / main, else the empty tree.
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

const { classifyGateIntegrity, isGateFile } = require('../scripts/pr_closeout_git');
const {
  readGateChanges,
  scanTouchedSuppressions,
} = require('../scripts/pr_closeout_repo');

const root = path.resolve(__dirname, '..');
// Large enough for a pathological multi-thousand-file PR; still bounded.
const GIT_MAX_BUFFER = 64 * 1024 * 1024;
const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';

/**
 * Run git in the repository root and return raw stdout (not trimmed).
 * Path lists are NUL-delimited; individual entries may begin/end with
 * whitespace (legal Git paths). Callers that need a trimmed scalar SHA
 * still trim themselves via gitScalar.
 * @param {string[]} args
 * @param {object} [options]
 * @returns {string}
 */
const git = (args, options = {}) => {
  const { input, ...rest } = options;
  const stdout = execFileSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
    maxBuffer: GIT_MAX_BUFFER,
    input: input === undefined ? undefined : input,
    ...rest,
  });
  return String(stdout || '');
};

/** @param {string[]} args @param {object} [options] @returns {string} trimmed git stdout */
const gitScalar = (args, options = {}) => git(args, options).trim();

/**
 * Split a NUL-delimited path list, preserving each nonempty segment
 * byte-for-byte (leading/trailing spaces are part of a legal Git path).
 * @param {string} text
 * @returns {string[]}
 */
const splitZ = (text) => {
  const raw = String(text || '');
  if (!raw) return [];
  return raw.split('\0').filter((entry) => entry.length > 0);
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
 * @returns {string}
 */
const resolveEmptyTreeSha = () => {
  if (cachedEmptyTreeSha) return cachedEmptyTreeSha;
  try {
    cachedEmptyTreeSha = gitScalar(['hash-object', '-t', 'tree', '--stdin'], { input: '' });
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
 * Resolve the comparison base SHA for the CI suppression/gate scan from
 * env (CLOSEOUT_BASE_SHA / GITHUB_BASE_SHA / GITHUB_EVENT_BEFORE), then
 * merge-base with the PR base ref or main/master, else the empty tree.
 * @returns {string}
 */
const resolveBaseSha = () => {
  const explicit = [
    process.env.CLOSEOUT_BASE_SHA,
    process.env.GITHUB_BASE_SHA,
    process.env.GITHUB_EVENT_BEFORE,
  ];
  for (const candidate of explicit) {
    if (isUsableSha(candidate)) return candidate.trim();
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
        const mb = gitScalar(['merge-base', 'HEAD', ref]);
        if (isUsableSha(mb)) return mb;
      } catch {
        // try next candidate
      }
    }
  }

  for (const ref of ['origin/main', 'main', 'origin/master', 'master']) {
    try {
      const head = gitScalar(['rev-parse', 'HEAD']);
      const mb = gitScalar(['merge-base', 'HEAD', ref]);
      // On a push checkout, origin/main often equals HEAD; that yields an
      // empty range. Prefer a merge-base that is not HEAD.
      if (isUsableSha(mb) && mb !== head) return mb;
    } catch {
      // try next
    }
  }

  // Last resort for a first commit on a new repo: the empty tree object
  // (SHA-1 well-known ID or the repository's SHA-256 empty tree).
  try {
    const empty = resolveEmptyTreeSha();
    if (isUsableSha(empty) || isEmptyTreeSha(empty)) return empty;
  } catch {
    // fall through
  }
  try {
    gitScalar(['cat-file', '-t', EMPTY_TREE]);
    return EMPTY_TREE;
  } catch {
    // fall through
  }

  throw new Error('Unable to resolve a comparison base SHA for the suppression scan');
};

/**
 * Name-only diff from base to HEAD. Commit bases use three-dot (PR range);
 * the empty tree uses two-dot because `tree...commit` is rejected by Git.
 */
const diffNameOnly = (baseSha) => {
  if (isEmptyTreeSha(baseSha)) {
    return splitZ(git(['diff', '--name-only', '-z', baseSha, 'HEAD']));
  }
  return splitZ(git(['diff', '--name-only', '-z', `${baseSha}...HEAD`]));
};

/**
 * Unified diff for gate files. Same three-dot vs two-dot rule as name-only.
 */
const diffUnified = (baseSha, files) => {
  if (!files.length) return '';
  // --no-textconv: a configured textconv filter must not rewrite deleted
  // validation lines before detectValidationRemovals scans the diff.
  if (isEmptyTreeSha(baseSha)) {
    return git(['diff', '--unified=0', '--no-ext-diff', '--no-textconv', baseSha, 'HEAD', '--', ...files]);
  }
  // Three-dot: only PR-range changes (merge-base...HEAD), not base-branch-only
  // edits that would appear in a two-endpoint diff against a moved base tip.
  return git(['diff', '--unified=0', '--no-ext-diff', '--no-textconv', `${baseSha}...HEAD`, '--', ...files]);
};

/**
 * Build the complete touched-file set: PR/push range + unstaged + staged +
 * untracked. Fail closed: git errors propagate instead of becoming [].
 * @param {string} baseSha
 * @returns {string[]}
 */
const listTouchedFiles = (baseSha) => {
  const tracked = diffNameOnly(baseSha);
  const unstaged = splitZ(git(['diff', '--name-only', '-z']));
  const staged = splitZ(git(['diff', '--cached', '--name-only', '-z']));
  const untracked = splitZ(git(['ls-files', '--others', '--exclude-standard', '-z']));
  return [...new Set([...tracked, ...unstaged, ...staged, ...untracked])].sort();
};

// Deletion of validation-bearing lines inside a still-present gate file does
// not produce a deletedFiles entry and may not match WEAKENING_PATTERNS on
// added lines, so classifyGateIntegrity alone can return BLOCKED. Treat these
// removals as FAIL in CI. Include multi-language test runners that commonly
// appear inside `run: |` block steps (not only npm/pnpm/make).
const VALIDATION_REMOVAL_PATTERNS = [
  /^\-\s*run:\s*/i,
  /^\-\s*-\s*run:\s*/i,
  // Action-based validation steps (CodeQL, etc.): removed `uses:` lines.
  /^\-\s*uses:\s*\S+/i,
  /^\-\s*-\s*uses:\s*\S+/i,
  /^\-.*\buses:\s+(?:github\/codeql-action|aquasecurity\/trivy-action|securego\/gosec|golangci\/golangci-lint-action|github\/super-linter|oxsecurity\/megalinter|codecov\/codecov-action|sonarsource\/sonarcloud)\S*/i,
  /^\-.*\bnpm\s+(?:ci|test|run\b|audit\b)/i,
  /^\-.*\bpnpm\s+(?:test|run\b|audit\b)/i,
  /^\-.*\bscan:suppressions\b/i,
  /^\-.*\bnode\s+--test\b/i,
  /^\-.*\bmake\s+(?:pr-check|verify|test|audit)\b/i,
  // Word-boundary the keywords so values like `windows-latest` or
  // `attestation` do not match the bare `test` / `scan` substrings.
  /^\-\s*-\s*name:\s*.*\b(?:test|validate|audit|scan|lint|codeql|security|coverage)\b/i,
  // Common validation commands removed from block steps while `run: |` remains.
  /^\-.*\b(?:cargo\s+test|go\s+test|pytest|python\s+-m\s+pytest|dotnet\s+test|mvn\s+test|gradlew?\s+test|bun\s+test|yarn\s+test|vitest|jest|mocha|phpunit|rspec|ctest)\b/i,
  /^\-.*\b(?:npm|pnpm|yarn)\s+(?:run\s+)?(?:test|lint|typecheck|validate|audit|build)\b/i,
];

/**
 * Scan gate-file diffs for removed validation-bearing lines (run:/uses:/
 * test runners). Deletion-only weakening often lacks added-line markers, so
 * this complements classifyGateIntegrity.
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
    if (!line.startsWith('-') || line.startsWith('---')) continue;
    if (VALIDATION_REMOVAL_PATTERNS.some((pattern) => pattern.test(line))) {
      findings.push(line.slice(0, 200));
    }
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
  // as deleted. Resolve merge-base(base, HEAD) for commit bases so the gate
  // scan matches PR-range / three-dot semantics used by the touched-file list.
  let gateBaseSha = baseSha;
  if (!isEmptyTreeSha(baseSha)) {
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
    // not treat deletion-only weakening as success. Inspect removed lines.
    const removals = detectValidationRemovals(
      gateBaseSha,
      [...new Set([...gate.changedFiles, ...gate.deletedFiles])].filter(isGateFile),
    );
    if (removals.length) {
      process.stderr.write(
        `FAIL: gate diff removes validation step(s) without a FAIL-class weakening match:\n`,
      );
      for (const line of removals.slice(0, 20)) {
        process.stderr.write(`  ${line}\n`);
      }
      process.exitCode = 1;
    } else {
      process.stdout.write(
        `gate-scan: BLOCKED (no validation-step removals detected): ${integrity.evidence}\n`,
      );
    }
  } else {
    process.stdout.write(`gate-scan: ${integrity.status}\n`);
  }

  if (process.exitCode) {
    process.stderr.write('touched-file suppression/gate scan failed\n');
  }
};

main().catch((error) => {
  process.stderr.write(`suppression-scan error: ${error?.stack || error}\n`);
  process.exitCode = 1;
});
