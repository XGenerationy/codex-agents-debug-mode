const { execFile } = require('node:child_process');
const { createHash } = require('node:crypto');
const { lstat, readFile, readdir, readlink } = require('node:fs/promises');
const path = require('node:path');
const { promisify, TextDecoder } = require('node:util');

const { scanSuppressionText } = require('./pr_closeout_core');
const { fingerprintEntries, isGateFile } = require('./pr_closeout_git');

const execFileAsync = promisify(execFile);
const normalize = (file) => String(file).replaceAll('\\', '/').replace(/^\.\//, '');
const utf8Decoder = new TextDecoder('utf-8', { fatal: true });
const utf16leDecoder = new TextDecoder('utf-16le', { fatal: true });
const utf16beDecoder = new TextDecoder('utf-16be', { fatal: true });

const decodeTouchedText = (bytes) => {
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return utf16leDecoder.decode(bytes.subarray(2));
  }
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    return utf16beDecoder.decode(bytes.subarray(2));
  }
  if (bytes.includes(0)) {
    throw new Error('Touched file contains NUL bytes in an unrecognized encoding.');
  }
  return utf8Decoder.decode(bytes);
};

const gitBuffer = async (repo, args) => {
  const result = await execFileAsync('git', args, { cwd: repo, encoding: 'buffer', maxBuffer: 50_000_000 });
  return result.stdout;
};

const gitText = async (repo, args) => (await gitBuffer(repo, args)).toString('utf8').trim();
const gitPaths = async (repo, args) => (await gitBuffer(repo, args))
  .toString('utf8')
  .split('\0')
  .filter(Boolean)
  .map(normalize);

const resolveRepositoryState = async ({ repo, baseRef }) => {
  if (!baseRef) throw new Error('A live PR base ref is required. Pass --base-ref or set baseRef in config.');
  const resolvedRepo = path.resolve(repo);
  const [headSha, baseSha, mergeBaseSha] = await Promise.all([
    gitText(resolvedRepo, ['rev-parse', 'HEAD']),
    gitText(resolvedRepo, ['rev-parse', baseRef]),
    gitText(resolvedRepo, ['merge-base', baseRef, 'HEAD']),
  ]);
  const groups = await Promise.all([
    gitPaths(resolvedRepo, ['diff', '--name-only', '-z', `${mergeBaseSha}...HEAD`]),
    gitPaths(resolvedRepo, ['diff', '--name-only', '-z']),
    gitPaths(resolvedRepo, ['diff', '--name-only', '--cached', '-z']),
    gitPaths(resolvedRepo, ['ls-files', '--others', '--exclude-standard', '-z']),
  ]);
  return {
    repo: resolvedRepo,
    baseRef,
    baseSha,
    mergeBaseSha,
    headSha,
    touchedFiles: [...new Set(groups.flat())].sort(),
  };
};

const readProjectMetadata = async (repo) => {
  let packageScripts = {};
  let makeTargets = [];
  try {
    const manifest = JSON.parse(await readFile(path.join(repo, 'package.json'), 'utf8'));
    packageScripts = manifest.scripts || {};
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  try {
    const makefile = await readFile(path.join(repo, 'Makefile'), 'utf8');
    makeTargets = [...new Set(makefile.split(/\r?\n/)
      .map((line) => line.match(/^([A-Za-z0-9_.-]+)\s*:(?![=])/))
      .filter(Boolean)
      .map((match) => match[1]))];
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return { packageScripts, makeTargets };
};

const scanTouchedSuppressions = async (repo, files) => {
  const findings = [];
  for (const file of files) {
    try {
      const bytes = await readFile(path.join(repo, file));
      findings.push(...scanSuppressionText(file, decodeTouchedText(bytes)));
    } catch (error) {
      if (error.code !== 'ENOENT') {
        findings.push({ file, line: 0, category: 'scan-error', match: error.message });
      }
    }
  }
  return findings;
};

const hashBytes = (value) => createHash('sha256').update(value).digest('hex');

const resolveExtraPath = (repo, requested) => {
  if (!requested || path.isAbsolute(requested)) throw new Error(`Reproducibility path must be repository-relative: ${requested}`);
  const absolute = path.resolve(repo, requested);
  const relative = path.relative(repo, absolute);
  const outside = relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative);
  const normalized = normalize(relative);
  if (!relative || outside || normalized === '.git' || normalized.startsWith('.git/')) {
    throw new Error(`Unsafe reproducibility path: ${requested}`);
  }
  return { absolute, relative: normalized };
};

const collectExtraEntries = async (repo, requested, entries) => {
  const root = resolveExtraPath(repo, requested);
  const visit = async ({ absolute, relative }) => {
    let info;
    try {
      info = await lstat(absolute);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      entries.push({ path: `__extra__/${relative}`, hash: hashBytes('missing') });
      return;
    }
    if (info.isSymbolicLink()) {
      entries.push({ path: `__extra__/${relative}`, hash: hashBytes(`symlink:${await readlink(absolute)}`) });
      return;
    }
    if (info.isDirectory()) {
      entries.push({ path: `__extra_dir__/${relative}`, hash: hashBytes('directory') });
      const children = (await readdir(absolute)).sort();
      for (const child of children) {
        await visit({ absolute: path.join(absolute, child), relative: normalize(path.join(relative, child)) });
      }
      return;
    }
    entries.push({ path: `__extra__/${relative}`, hash: hashBytes(await readFile(absolute)) });
  };
  await visit(root);
};

const workingTreeFingerprint = async (repo, extraPaths = []) => {
  const [diff, untracked] = await Promise.all([
    gitBuffer(repo, ['diff', '--binary', '--no-ext-diff', 'HEAD']),
    gitPaths(repo, ['ls-files', '--others', '--exclude-standard', '-z']),
  ]);
  const entries = [{ path: '__tracked_diff__', hash: hashBytes(diff) }];
  for (const file of untracked) {
    const bytes = await readFile(path.join(repo, file));
    entries.push({ path: file, hash: hashBytes(bytes) });
  }
  for (const extra of [...new Set(extraPaths)].sort()) await collectExtraEntries(repo, extra, entries);
  return fingerprintEntries(entries);
};

const cleanTreeStatus = async (repo) => {
  const raw = await gitText(repo, ['status', '--porcelain=v1']);
  return raw
    ? { status: 'FAIL', evidence: `Working tree is not clean: ${raw.split(/\r?\n/).slice(0, 20).join(' | ')}` }
    : { status: 'PASS', evidence: 'Working tree is clean.' };
};

const readGateChanges = async (repo, baseSha) => {
  const [changed, untracked] = await Promise.all([
    gitPaths(repo, ['diff', '--name-only', '-z', baseSha]),
    gitPaths(repo, ['ls-files', '--others', '--exclude-standard', '-z']),
  ]);
  const changedFiles = [...new Set([...changed, ...untracked].filter(isGateFile))].sort();
  if (!changedFiles.length) return { changedFiles, addedLines: [] };
  const tracked = changedFiles.filter((file) => !untracked.includes(file));
  const diff = tracked.length
    ? await gitText(repo, ['diff', '--unified=0', '--no-ext-diff', baseSha, '--', ...tracked])
    : '';
  const addedLines = diff.split(/\r?\n/).filter((line) => line.startsWith('+') && !line.startsWith('+++'));
  for (const file of changedFiles.filter((item) => untracked.includes(item))) {
    try {
      const text = decodeTouchedText(await readFile(path.join(repo, file)));
      addedLines.push(...text.split(/\r?\n/).map((line) => `+${line}`));
    } catch (error) {
      addedLines.push(`+__decode_error__:${file}:${error.message}`);
    }
  }
  return { changedFiles, addedLines };
};

module.exports = {
  cleanTreeStatus,
  readGateChanges,
  readProjectMetadata,
  resolveRepositoryState,
  scanTouchedSuppressions,
  workingTreeFingerprint,
};
