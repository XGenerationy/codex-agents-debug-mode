const { constants } = require('node:fs');
const { mkdir, rename, unlink } = require('node:fs/promises');
const path = require('node:path');
const { assertNotSymlink: assertNotSymlinkShared, openNoFollow } = require('./pr_closeout_fs');

const safeText = (value) => String(value ?? '')
  .replace(/\r\n?|\n/g, ' ⏎ ')
  .replace(/[^A-Za-z0-9 ._⏎-]/gu, (character) => `&#${character.codePointAt(0)};`);

const cell = (value) => safeText(value);

const listFindings = (findings = []) => findings.length
  ? findings.map((finding) => `- ${safeText(finding.file)}: ${safeText(finding.line)} - ${safeText(finding.category)}: ${safeText(finding.match)}`).join('\n')
  : '- None';

const attemptCount = (check = {}) => {
  if (Array.isArray(check.attempts)) return check.attempts.length;
  return check.attemptId || check.startedAt || check.finishedAt || Number.isInteger(check.exitCode) ? 1 : 0;
};

const attemptIds = (check = {}) => {
  if (Array.isArray(check.attempts)) {
    return check.attempts.map(({ attemptId }) => attemptId).filter(Boolean);
  }
  return check.attemptId ? [check.attemptId] : [];
};

const attemptSummary = (check, qualification) => {
  const qualificationAttempts = attemptCount(qualification);
  const confirmationAttempts = attemptCount(check);
  const baselineSetupAttempts = attemptCount(check.baselineSetup);
  const baselineAttempts = attemptCount(check.baseline);
  const reruns = Math.max(qualificationAttempts - 1, 0) + Math.max(confirmationAttempts - 1, 0);
  const describe = (label, count, value) => {
    const ids = attemptIds(value);
    return `${label}: ${count}${ids.length ? ` [${ids.join(', ')}]` : ''}`;
  };
  return [
    describe('Qualification attempts', qualificationAttempts, qualification),
    describe('Confirmation attempts', confirmationAttempts, check),
    describe('Baseline setup attempts', baselineSetupAttempts, check.baselineSetup),
    describe('Baseline comparison attempts', baselineAttempts, check.baseline),
    `Reruns observed: ${reruns}`,
  ].join('; ');
};

const baselineComparison = (check) => {
  if (check.baseline) {
    return `Base result: ${check.baseline.status || 'unknown'}${check.baseline.attemptId ? ` (${check.baseline.attemptId})` : ''}`;
  }
  if (check.baselineSetup) {
    return `Baseline setup: ${check.baselineSetup.status || 'unknown'}${check.baselineSetup.attemptId ? ` (${check.baselineSetup.attemptId})` : ''}`;
  }
  return 'Not run; no baseline claim.';
};

const fixRecord = (check) => check.fixRecord
  || 'No fix record was supplied; the runner does not perform or infer repairs.';

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const replacePathRoot = (value, root, replacement) => {
  if (!root || root === replacement) return value;
  const variants = [...new Set([
    String(root),
    String(root).replaceAll('\\', '/'),
    String(root).replaceAll('/', '\\'),
  ])].sort((left, right) => right.length - left.length);
  let normalized = value;
  for (const variant of variants) {
    const flags = /^[A-Za-z]:[\\/]/.test(variant) ? 'gi' : 'g';
    normalized = normalized.replace(
      new RegExp(`${escapeRegex(variant)}(?=$|[\\\\/]|[^A-Za-z0-9._-])`, flags),
      replacement,
    );
  }
  return normalized;
};

/**
 * Recursively replace absolute repository/output-directory path prefixes
 * throughout a report value with the stable placeholders `<repo>` and
 * `<evidence>`, so persisted evidence is reproducible across machines/CI
 * runs and never leaks the local filesystem layout. Handles both path
 * separators (a Windows-style root also matches its forward-slash and
 * backslash variants) and de-duplicates object/array references via `seen`
 * so shared references survive the walk unchanged while true cycles
 * terminate instead of recursing forever.
 * @param {*} value - a report (sub)value; strings are rewritten, objects/arrays are walked.
 * @param {{repoRoot?: string, outputRoot?: string}} [roots]
 * @param {WeakMap} [seen] - internal cycle/shared-reference tracker; callers should not pass this.
 * @returns {*} the normalized value (same shape as `value`).
 */
const normalizeReportPaths = (value, {
  repoRoot,
  outputRoot,
} = {}, seen = new WeakMap()) => {
  if (typeof value === 'string') {
    return replacePathRoot(
      replacePathRoot(value, outputRoot, '<evidence>'),
      repoRoot,
      '<repo>',
    );
  }
  if (!value || typeof value !== 'object') return value;
  if (seen.has(value)) return seen.get(value);
  const normalized = Array.isArray(value) ? [] : {};
  seen.set(value, normalized);
  for (const [key, entry] of Object.entries(value)) {
    normalized[key] = normalizeReportPaths(entry, { repoRoot, outputRoot }, seen);
  }
  return normalized;
};

/**
 * Render the full human-readable evidence report (preflight, qualification
 * and final checks with rerun/baseline/fix-record evidence, live PR state,
 * gate attestation, repository sealing/fingerprints, suppression findings,
 * tool versions) as Markdown. Every dynamic value is routed through
 * `safeText`/`cell`, which strips everything but a small allow-listed
 * character set — this report is regularly rendered by GitHub and other
 * Markdown viewers, so a check's `evidence` string (which can contain
 * attacker- or repo-controlled text) must not be able to inject Markdown/
 * HTML/script content. This function is pure: it never touches the
 * filesystem (see writeEvidenceReport for persistence).
 * @param {object} report - a report object, ideally already passed through normalizeReportPaths.
 * @returns {string} the rendered Markdown document (no trailing newline).
 */
const renderMarkdown = (report) => {
  const lines = [
    '# PR Closeout Evidence',
    '',
    `Overall status: **${safeText(report.overallStatus)}**`,
    '',
    `- Repository: ${safeText(report.repository)}`,
    `- Base SHA: ${safeText(report.baseSha || 'unresolved')}`,
    `- Head SHA: ${safeText(report.headSha || 'unresolved')}`,
    `- Configuration digest: ${safeText(report.configDigest || 'unresolved')}`,
    `- Started: ${safeText(report.startedAt || 'unknown')}`,
    `- Finished: ${safeText(report.finishedAt || 'unknown')}`,
    '',
    '## Preflight',
    '',
    '| Probe | Status | Evidence |',
    '|---|---|---|',
  ];
  for (const check of report.preflight?.checks || []) {
    lines.push(`| ${cell(check.name)} | ${cell(check.status)} | ${cell(check.evidence)} |`);
  }
  lines.push(
    '',
    '## Qualification checks',
    '',
    '| Check | Command | Status | Exit | Evidence |',
    '|---|---|---|---:|---|',
  );
  for (const check of report.qualificationChecks || []) {
    const ids = attemptIds(check);
    const evidence = `${check.evidence || ''}${ids.length ? ` Attempt IDs: ${ids.join(', ')}.` : ''}`.trim();
    lines.push(`| ${cell(check.id)} | ${cell(check.command)} | ${cell(check.status)} | ${cell(check.exitCode)} | ${cell(evidence)} |`);
  }
  lines.push(
    '',
    '## Final validation checks',
    '',
    '| Phase | Check | Command | Status | Exit | Duration | Attempt evidence | Fix record | Baseline comparison | Evidence |',
    '|---|---|---|---|---:|---:|---|---|---|---|',
  );
  const qualificationById = new Map((report.qualificationChecks || []).map((check) => [check.id, check]));
  for (const check of report.checks || []) {
    lines.push(`| ${cell(check.phase)} | ${cell(check.id)} | ${cell(check.command)} | ${cell(check.status)} | ${cell(check.exitCode)} | ${cell(check.durationMs)} ms | ${cell(attemptSummary(check, qualificationById.get(check.id)))} | ${cell(fixRecord(check))} | ${cell(baselineComparison(check))} | ${cell(check.evidence)} |`);
  }
  lines.push(
    '',
    '## Fix and rerun record',
    '',
    'This runner records observed attempts and baseline evidence. It never invents a repair or marks an issue fixed without a clean rerun.',
    '',
    '## Live GitHub PR state',
    '',
    `- Status: ${safeText(report.livePrState?.status || 'unknown')}`,
    `- Evidence: ${safeText(report.livePrState?.evidence || 'not recorded')}`,
    `- PR: ${safeText(report.livePrState?.url || report.livePrState?.number || 'unresolved')}`,
    `- State: ${safeText(report.livePrState?.state || 'unknown')}`,
    `- Draft: ${safeText(report.livePrState?.isDraft ?? 'unknown')}`,
    `- Merge status: ${safeText(report.livePrState?.mergeStateStatus || report.livePrState?.mergeable || 'unknown')}`,
    `- Review decision: ${safeText(report.livePrState?.reviewDecision || 'unknown')}`,
    `- Unresolved review threads: ${safeText(report.livePrState?.unresolvedThreads?.length ?? 'unknown')}`,
    '',
    '| Live check | Status | Conclusion | Workflow / external service |',
    '|---|---|---|---|',
  );
  for (const check of report.livePrState?.checks || []) {
    lines.push(`| ${cell(check.name)} | ${cell(check.status)} | ${cell(check.conclusion)} | ${cell(check.workflowName || 'external service')} |`);
  }
  lines.push(
    '',
    '## Independent gate attestation',
    '',
    `- Provider: ${safeText(report.livePrState?.gateAttestation?.provider || 'unknown')}`,
    `- Status: ${safeText(report.livePrState?.gateAttestation?.status || 'unknown')}`,
    `- Reviewer: ${safeText(report.livePrState?.gateAttestation?.reviewer || 'unknown')}`,
    `- Review: ${safeText(report.livePrState?.gateAttestation?.reviewUrl || 'not recorded')}`,
    `- Evidence: ${safeText(report.livePrState?.gateAttestation?.evidence || 'not recorded')}`,
    `- Base SHA: ${safeText(report.livePrState?.gateAttestation?.baseSha || 'unresolved')}`,
    `- Head SHA: ${safeText(report.livePrState?.gateAttestation?.headSha || 'unresolved')}`,
    `- Configuration digest: ${safeText(report.livePrState?.gateAttestation?.configDigest || 'unresolved')}`,
    `- Decision: ${safeText(report.livePrState?.gateAttestation?.decision || 'unknown')}`,
    '',
    '## Gate integrity',
    '',
    `- Status: ${safeText(report.gateIntegrity?.status || 'unknown')}`,
    `- Evidence: ${safeText(report.gateIntegrity?.evidence || 'not recorded')}`,
    '',
    '## Generator reproducibility',
    '',
    `- Status: ${safeText(report.reproducibility?.status || 'unknown')}`,
    `- Evidence: ${safeText(report.reproducibility?.evidence || 'not recorded')}`,
    '',
    '## Head consistency',
    '',
    `- Status: ${safeText(report.headConsistency?.status || 'unknown')}`,
    `- Evidence: ${safeText(report.headConsistency?.evidence || 'not recorded')}`,
    '',
    '## Initial working tree',
    '',
    `- Status: ${safeText(report.initialTree?.status || 'unknown')}`,
    `- Evidence: ${safeText(report.initialTree?.evidence || 'not recorded')}`,
    `- Fingerprint: ${safeText(report.initialTree?.fingerprint || 'unresolved')}`,
    '',
    '## Repository seal',
    '',
    `- Status: ${safeText(report.repositorySeal?.status || 'unknown')}`,
    `- Evidence: ${safeText(report.repositorySeal?.evidence || 'not recorded')}`,
    `- Initial fingerprint: ${safeText(report.repositorySeal?.initialFingerprint || 'unresolved')}`,
    `- Before fingerprint: ${safeText(report.repositorySeal?.beforeFingerprint || 'unresolved')}`,
    `- After fingerprint: ${safeText(report.repositorySeal?.afterFingerprint || 'unresolved')}`,
    `- Evidence write seal: ${safeText(report.repositorySeal?.evidenceWrite?.status || 'unknown')}`,
    `- Evidence write evidence: ${safeText(report.repositorySeal?.evidenceWrite?.evidence || 'not recorded')}`,
    `- Evidence write fingerprint: ${safeText(report.repositorySeal?.evidenceWrite?.fingerprint || 'unresolved')}`,
    '',
    '## Final clean tree',
    '',
    `- Status: ${safeText(report.cleanTree?.status || 'unknown')}`,
    `- Evidence: ${safeText(report.cleanTree?.evidence || 'not recorded')}`,
    '',
    '## Suppression scan',
    '',
    listFindings(report.suppressionFindings),
    '',
    '## Tool versions',
    '',
    ...Object.entries(report.toolVersions || {}).map(([name, version]) => `- ${safeText(name)}: ${safeText(version)}`),
    '',
  );
  return lines.join('\n');
};

// Domain wrapper: shared assertNotSymlink with report-specific message.
const assertNotSymlink = async (target) => {
  await assertNotSymlinkShared(
    target,
    `Refusing to write evidence report through an existing symlink: ${target}`,
  );
};

// Write without following a symlinked final component. writeFile follows a
// symlink; if outputDir already contains report.json/report.md as a symlink
// (a reused temp directory or otherwise-populated output path), a
// path-based write would silently overwrite whatever the link points to
// instead of writing evidence there — and by this point the repository seal
// has already run, so it cannot catch the divergence. Fail closed instead.
// assertNotSymlink is the primary guard on platforms without O_NOFOLLOW
// (e.g. Windows); openNoFollow adds defense-in-depth on platforms that
// support it. Shared implementation lives in pr_closeout_fs.js.
const writeNoFollow = async (target, contents) => {
  await assertNotSymlink(target);
  let handle;
  try {
    handle = await openNoFollow(target, constants.O_WRONLY | constants.O_CREAT | constants.O_TRUNC, 0o666);
  } catch (error) {
    if (error?.code === 'ELOOP') {
      throw new Error(`Refusing to write evidence report through an existing symlink: ${target}`);
    }
    throw error;
  }
  try {
    await handle.writeFile(contents, 'utf8');
  } finally {
    await handle.close();
  }
};

/**
 * Persist the evidence report as `report.json` (normalized, machine-
 * readable) and `report.md` (rendered Markdown) under `outputDir`, creating
 * the directory if needed. Both final paths are validated up front, then
 * content is staged to sibling temp files and renamed into place so a
 * failure mid-commit cannot leave a final JSON claiming PASS beside an
 * older provisional Markdown (or vice versa).
 * @param {{outputDir: string, report: object}} options
 * @returns {Promise<{json: string, markdown: string}>} the absolute paths written.
 */
const writeEvidenceReport = async ({ outputDir, report }) => {
  await mkdir(outputDir, { recursive: true });
  const json = path.join(outputDir, 'report.json');
  const markdown = path.join(outputDir, 'report.md');
  // Validate both final targets before writing either temp or final path.
  await assertNotSymlink(json);
  await assertNotSymlink(markdown);
  const normalized = normalizeReportPaths(report, {
    repoRoot: report.repository,
    outputRoot: outputDir,
  });
  const stamp = `${process.pid}.${Date.now()}`;
  const jsonTmp = path.join(outputDir, `.report.json.${stamp}.tmp`);
  const markdownTmp = path.join(outputDir, `.report.md.${stamp}.tmp`);
  const cleanupTemps = async () => {
    await Promise.all([
      unlink(jsonTmp).catch(() => {}),
      unlink(markdownTmp).catch(() => {}),
    ]);
  };
  try {
    await writeNoFollow(jsonTmp, `${JSON.stringify(normalized, null, 2)}\n`);
    await writeNoFollow(markdownTmp, `${renderMarkdown(normalized)}\n`);
    // Commit as a pair: if the second rename fails, remove the first final so
    // consumers never observe contradictory report.json vs report.md.
    await rename(jsonTmp, json);
    try {
      await rename(markdownTmp, markdown);
    } catch (error) {
      await unlink(json).catch(() => {});
      throw error;
    }
  } catch (error) {
    await cleanupTemps();
    throw error;
  }
  return { json, markdown };
};

module.exports = { normalizeReportPaths, renderMarkdown, writeEvidenceReport };
