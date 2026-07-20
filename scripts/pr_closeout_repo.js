const { execFile, spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const { createReadStream } = require('node:fs');
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
  // Reject symlinked metadata before reading: a reviewed branch can make
  // root package.json or a default Makefile a symlink to /dev/zero or an
  // outside file, hanging or escaping the repository before any later check
  // can stop the read.
  const safeReadFile = async (relative) => {
    const absolute = path.join(repo, relative);
    let info;
    try {
      info = await lstat(absolute);
    } catch (error) {
      if (error.code === 'ENOENT') return undefined;
      throw error;
    }
    if (info.isSymbolicLink()) {
      throw new Error(`Refusing to read symlinked metadata: ${relative}`);
    }
    return readFile(absolute, 'utf8');
  };
  try {
    const manifestText = await safeReadFile('package.json');
    if (manifestText !== undefined) {
      const manifest = JSON.parse(manifestText);
      packageScripts = manifest.scripts || {};
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  // GNU make's documented default search order is GNUmakefile, makefile,
  // then Makefile (https://www.gnu.org/software/make/manual/html_node/Makefile-Names.html).
  // Read the first one that exists so repositories that use the lowercase
  // form still surface their named targets.
  const makeCandidates = ['GNUmakefile', 'makefile', 'Makefile'];
  for (const candidate of makeCandidates) {
    try {
      const makefile = await safeReadFile(candidate);
      if (makefile === undefined) continue;
      makeTargets = [...new Set(makefile.split(/\r?\n/)
        .map((line) => line.match(/^([A-Za-z0-9_.-]+)\s*:(?![=])/))
        .filter(Boolean)
        .map((match) => match[1]))];
      break;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return { packageScripts, makeTargets };
};

// Cap the suppression scanner so a single huge or binary touched file cannot
// spike memory or stall admission. Files larger than this are recorded as a
// scan-error; suppression markers are far smaller than this in practice.
const MAX_SUPPRESSION_SCAN_BYTES = 5 * 1024 * 1024;
// Sample the first N bytes for a NUL byte to detect binary files quickly
// without loading the whole file.
const BINARY_SAMPLE_BYTES = 4096;
const openForScan = (absolute) => new Promise((resolve, reject) => {
  require('node:fs').open(absolute, 'r', (err, fd) => {
    if (err) reject(err); else resolve(fd);
  });
});
const readScanHead = async (absolute, size) => {
  const fd = await openForScan(absolute);
  try {
    const buffer = Buffer.allocUnsafe(size);
    const { bytesRead } = await new Promise((resolve, reject) => {
      require('node:fs').read(fd, buffer, 0, size, 0, (error, n) => error ? reject(error) : resolve({ bytesRead: n }));
    });
    return buffer.subarray(0, bytesRead);
  } finally {
    require('node:fs').closeSync(fd);
  }
};

const scanTouchedSuppressions = async (repo, files) => {
  const findings = [];
  for (const file of files) {
    try {
      const absolute = path.join(repo, file);
      const stats = await lstat(absolute);
      if (stats.isSymbolicLink()) {
        findings.push({ file, line: 0, category: 'scan-error', match: 'Touched path is a symlink; refusing to follow.' });
        continue;
      }
      // Reject oversized files before reading them: a large untracked artifact
      // should not block admission with multi-MiB reads when the suppression
      // vocabulary is small.
      if (stats.size > MAX_SUPPRESSION_SCAN_BYTES) {
        findings.push({ file, line: 0, category: 'scan-error', match: `Touched file exceeds suppression scan limit (${stats.size} > ${MAX_SUPPRESSION_SCAN_BYTES} bytes).` });
        continue;
      }
      // Sample the first bytes for a NUL to detect binary files; scanning
      // them as text via decodeTouchedText already throws on NUL but we want
      // a clean scan-error finding instead of letting the throw bubble.
      // UTF-16 files start with a BOM (FF FE or FE FF) and contain NUL bytes
      // legitimately, so do not flag those as binary.
      if (stats.size > 0) {
        const head = await readScanHead(absolute, Math.min(BINARY_SAMPLE_BYTES, stats.size));
        const isUtf16Bom = head.length >= 2 && (
          (head[0] === 0xff && head[1] === 0xfe) || (head[0] === 0xfe && head[1] === 0xff)
        );
        if (!isUtf16Bom && head.includes(0)) {
          findings.push({ file, line: 0, category: 'scan-error', match: 'Touched file appears to be binary (NUL byte detected).' });
          continue;
        }
      }
      const bytes = await readFile(absolute);
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

// Stream the file through the hash instead of materializing the entire
// contents in memory. The fingerprint runs several times per closeout (initial
// tree, before/after GitHub verification, final seal), and a single large
// untracked artifact is enough to spike memory if readFile() is used.
const hashFile = async (absolute) => {
  const hash = createHash('sha256');
  const stream = createReadStream(absolute);
  for await (const chunk of stream) hash.update(chunk);
  return hash.digest('hex');
};

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
    entries.push({ path: `__extra__/${relative}`, hash: await hashFile(absolute) });
  };
  await visit(root);
};

// Stream git stdout through a hash instead of buffering it via execFile's
// maxBuffer. A sufficiently large tracked/staged diff can exceed the
// execFile maxBuffer and throw, which used to reject the closeout workflow
// before any evidence report was written. Streaming keeps memory bounded.
const hashGitOutput = (repo, args) => new Promise((resolve, reject) => {
  const hash = createHash('sha256');
  const child = spawn('git', args, { cwd: repo, stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '';
  child.stdout.on('data', (chunk) => hash.update(chunk));
  child.stderr.on('data', (chunk) => { stderr += chunk.toString('utf8'); });
  child.on('error', reject);
  child.on('close', (code) => {
    if (code !== 0) {
      reject(new Error(`git ${args.join(' ')} exited ${code}: ${stderr.trim()}`));
      return;
    }
    resolve(hash.digest('hex'));
  });
});

const workingTreeFingerprint = async (repo, extraPaths = []) => {
  const [diffHash, untracked] = await Promise.all([
    hashGitOutput(repo, ['diff', '--binary', '--no-ext-diff', 'HEAD']),
    gitPaths(repo, ['ls-files', '--others', '--exclude-standard', '-z']),
  ]);
  const entries = [{ path: '__tracked_diff__', hash: diffHash }];
  for (const file of untracked) {
    const absolute = path.join(repo, file);
    // Guard untracked symlinks before hashing: a validation command may leave
    // a link to /dev/zero or an outside file, and following it could hang or
    // read outside the repository before the final dirty-tree check can stop
    // the run. Treat untracked symlinks like collectExtraEntries does and
    // hash the link target string instead of dereferencing the link.
    let info;
    try {
      info = await lstat(absolute);
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      entries.push({ path: file, hash: hashBytes('missing') });
      continue;
    }
    if (info.isSymbolicLink()) {
      entries.push({ path: file, hash: hashBytes(`symlink:${await readlink(absolute)}`) });
      continue;
    }
    entries.push({ path: file, hash: await hashFile(absolute) });
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
      const absolute = path.join(repo, file);
      // Reject untracked gate symlinks before decoding: a PR can add
      // packages/web/package.json pointing at /dev/zero or an outside file,
      // and following the link would hang or read outside the repository
      // while readGateChanges runs in the admission/final scan.
      let info;
      try {
        info = await lstat(absolute);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        addedLines.push(`+__decode_error__:${file}:missing`);
        continue;
      }
      if (info.isSymbolicLink()) {
        addedLines.push(`+__decode_error__:${file}:symlink_not_allowed`);
        continue;
      }
      const text = decodeTouchedText(await readFile(absolute));
      for (const line of text.split(/\r?\n/)) {
        addedLines.push(`+${line}`);
      }
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
