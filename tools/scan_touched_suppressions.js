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
 *   merge-base with GITHUB_BASE_REF / origin/main / main, else the root commit.
 *
 * Touched-file Git queries fail closed: any enumeration error aborts the
 * gate with a non-zero exit instead of treating the failure as an empty set.
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

const git = (args, options = {}) => {
  const stdout = execFileSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: GIT_MAX_BUFFER,
    ...options,
  });
  return String(stdout || '').trim();
};

const splitZ = (text) => String(text || '')
  .split('\0')
  .map((entry) => entry.trim())
  .filter(Boolean);

const isUsableSha = (value) => {
  const sha = String(value || '').trim();
  // GitHub push "before" is 40 zeros when the ref is newly created.
  if (!sha || /^0+$/.test(sha)) return false;
  return /^[0-9a-f]{7,40}$/i.test(sha);
};

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
        const mb = git(['merge-base', 'HEAD', ref]);
        if (isUsableSha(mb) && mb !== git(['rev-parse', 'HEAD'])) return mb;
        if (isUsableSha(mb)) return mb;
      } catch {
        // try next candidate
      }
    }
  }

  for (const ref of ['origin/main', 'main', 'origin/master', 'master']) {
    try {
      const head = git(['rev-parse', 'HEAD']);
      const mb = git(['merge-base', 'HEAD', ref]);
      // On a push checkout, origin/main often equals HEAD; that yields an
      // empty range. Prefer the first-parent predecessor when available.
      if (isUsableSha(mb) && mb !== head) return mb;
    } catch {
      // try next
    }
  }

  // Last resort for a first commit on a new repo: scan the whole tree by
  // using the empty tree object so the range is well-defined.
  try {
    return git(['hash-object', '-t', 'tree', '/dev/null']);
  } catch {
    // Windows may not have /dev/null as a usable path for hash-object.
  }
  const emptyTree = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';
  try {
    git(['cat-file', '-t', emptyTree]);
    return emptyTree;
  } catch {
    // fall through
  }

  throw new Error('Unable to resolve a comparison base SHA for the suppression scan');
};

const listTouchedFiles = (baseSha) => {
  // Fail closed: do not swallow git errors into an empty touched set.
  const tracked = splitZ(git(['diff', '--name-only', '-z', `${baseSha}...HEAD`]));
  // Unstaged working-tree changes.
  const unstaged = splitZ(git(['diff', '--name-only', '-z']));
  // Index-only (staged) changes that are not yet in HEAD.
  const staged = splitZ(git(['diff', '--cached', '--name-only', '-z']));
  // Untracked files.
  const untracked = splitZ(git(['ls-files', '--others', '--exclude-standard', '-z']));
  return [...new Set([...tracked, ...unstaged, ...staged, ...untracked])].sort();
};

// Deletion of validation-bearing lines inside a still-present gate file does
// not produce a deletedFiles entry and may not match WEAKENING_PATTERNS on
// added lines, so classifyGateIntegrity alone can return BLOCKED. Treat these
// removals as FAIL in CI.
const VALIDATION_REMOVAL_PATTERNS = [
  /^\-\s*run:\s*/i,
  /^\-\s*-\s*run:\s*/i,
  /^\-.*\bnpm\s+(?:ci|test|run\b|audit\b)/i,
  /^\-.*\bpnpm\s+(?:test|run\b|audit\b)/i,
  /^\-.*\bscan:suppressions\b/i,
  /^\-.*\bnode\s+--test\b/i,
  /^\-.*\bmake\s+(?:pr-check|verify|test|audit)\b/i,
  /^\-\s*-\s*name:\s*.*(?:test|validate|audit|scan|lint)/i,
];

const detectValidationRemovals = (baseSha, gateFiles) => {
  if (!gateFiles.length) return [];
  let diff = '';
  try {
    diff = git(['diff', '--unified=0', '--no-ext-diff', baseSha, 'HEAD', '--', ...gateFiles]);
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

const main = async () => {
  const baseSha = resolveBaseSha();
  const headSha = git(['rev-parse', 'HEAD']);
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

  const gate = await readGateChanges(root, baseSha);
  const integrity = classifyGateIntegrity({
    changedFiles: gate.changedFiles,
    addedLines: gate.addedLines,
    deletedFiles: gate.deletedFiles,
    baseSha,
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
      baseSha,
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
