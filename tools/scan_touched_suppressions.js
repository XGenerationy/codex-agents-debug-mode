'use strict';

/**
 * CI gate: scan the PR (or push) touched-file set with scanTouchedSuppressions
 * and fail closed on any marker / config-silencing / test-weakening finding.
 * Also runs readGateChanges + classifyGateIntegrity and fails when the gate
 * status is FAIL (weakening, deleted gate files, decode errors). BLOCKED
 * (gate files changed but no weakening detected) is reported but does not
 * fail this check — independent review attestation is the closeout path.
 *
 * Resolves the comparison base from (in order):
 *   CLOSEOUT_BASE_SHA, GITHUB_BASE_SHA, merge-base with GITHUB_BASE_REF /
 *   origin/main / main, else the root commit.
 */

const { execFileSync } = require('node:child_process');
const path = require('node:path');

const { classifyGateIntegrity } = require('../scripts/pr_closeout_git');
const {
  readGateChanges,
  scanTouchedSuppressions,
} = require('../scripts/pr_closeout_repo');

const root = path.resolve(__dirname, '..');

const git = (args, options = {}) => {
  const stdout = execFileSync('git', args, {
    cwd: root,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  });
  return String(stdout || '').trim();
};

const tryGit = (args) => {
  try {
    return git(args);
  } catch {
    return '';
  }
};

const resolveBaseSha = () => {
  if (process.env.CLOSEOUT_BASE_SHA) return process.env.CLOSEOUT_BASE_SHA.trim();
  if (process.env.GITHUB_BASE_SHA) return process.env.GITHUB_BASE_SHA.trim();

  const baseRef = (process.env.GITHUB_BASE_REF || '').trim();
  if (baseRef) {
    // Actions provides GITHUB_BASE_REF as the bare branch name (e.g. main).
    const candidates = [
      `origin/${baseRef}`,
      `refs/remotes/origin/${baseRef}`,
      baseRef,
    ];
    for (const ref of candidates) {
      const mb = tryGit(['merge-base', 'HEAD', ref]);
      if (mb) return mb;
    }
  }

  for (const ref of ['origin/main', 'main', 'origin/master', 'master']) {
    const mb = tryGit(['merge-base', 'HEAD', ref]);
    if (mb) return mb;
  }

  const rootCommit = tryGit(['rev-list', '--max-parents=0', 'HEAD']).split(/\r?\n/).filter(Boolean)[0];
  if (rootCommit) return rootCommit;
  throw new Error('Unable to resolve a comparison base SHA for the suppression scan');
};

const listTouchedFiles = (baseSha) => {
  const tracked = tryGit(['diff', '--name-only', '-z', `${baseSha}...HEAD`])
    .split('\0')
    .map((entry) => entry.trim())
    .filter(Boolean);
  // Include uncommitted and untracked paths so a local/CI dirty tree cannot
  // hide a suppression that is not yet committed.
  const unstaged = tryGit(['diff', '--name-only', '-z'])
    .split('\0')
    .map((entry) => entry.trim())
    .filter(Boolean);
  const untracked = tryGit(['ls-files', '--others', '--exclude-standard', '-z'])
    .split('\0')
    .map((entry) => entry.trim())
    .filter(Boolean);
  return [...new Set([...tracked, ...unstaged, ...untracked])].sort();
};

const main = async () => {
  const baseSha = resolveBaseSha();
  const headSha = tryGit(['rev-parse', 'HEAD']) || 'HEAD';
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
    process.stdout.write(`gate-scan: BLOCKED (no weakening detected): ${integrity.evidence}\n`);
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
