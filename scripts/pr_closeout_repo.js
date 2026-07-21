const { execFile, spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const { constants, createReadStream } = require('node:fs');
const { lstat, open, readFile, readdir, readlink } = require('node:fs/promises');
const path = require('node:path');
const { promisify, TextDecoder } = require('node:util');

const { scanSuppressionText } = require('./pr_closeout_core');
const { fingerprintEntries, isGateFile } = require('./pr_closeout_git');

const execFileAsync = promisify(execFile);
// Preserve literal backslashes on POSIX: Git can report a filename that
// contains `\`, and converting every `\` to `/` would probe the wrong path and
// skip suppression scans (ENOENT). Only normalize Windows path separators when
// the path looks like a Windows absolute path or contains drive-style roots.
const normalize = (file) => {
  const raw = String(file);
  const stripped = raw.replace(/^\.\//, '');
  if (process.platform === 'win32' || /^[A-Za-z]:[\\/]/.test(stripped) || stripped.includes('\\')) {
    // On Windows, path separators are `\`; on POSIX a backslash is a literal
    // character in the filename — only map `\` → `/` on win32.
    if (process.platform === 'win32') return stripped.replaceAll('\\', '/');
  }
  return stripped;
};
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

// Always pass --no-textconv on internal diffs/fingerprints so a repo-local
// diff driver cannot run arbitrary converters during closeout validation.
const withNoTextconv = (args) => {
  if (!args.includes('diff')) return args;
  if (args.includes('--no-textconv') || args.includes('--textconv')) return args;
  const out = [...args];
  const diffAt = out.indexOf('diff');
  out.splice(diffAt + 1, 0, '--no-textconv');
  return out;
};

const gitBuffer = async (repo, args) => {
  const result = await execFileAsync('git', withNoTextconv(args), { cwd: repo, encoding: 'buffer', maxBuffer: 50_000_000 });
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
  // Reject symlinked and non-regular metadata before reading: a reviewed
  // branch can make root package.json or a default Makefile a symlink to
  // /dev/zero or an outside file, or replace it with a directory or FIFO
  // whose read throws EISDIR or blocks before any later check can stop the
  // read and before any structured evidence report exists.
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
    if (!info.isFile()) {
      throw new Error(`Refusing to read non-regular metadata: ${relative}`);
    }
    if (info.size > MAX_SUPPRESSION_SCAN_BYTES) {
      throw new Error(`Refusing to read oversized metadata (${info.size} > ${MAX_SUPPRESSION_SCAN_BYTES} bytes): ${relative}`);
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

// Open with O_NOFOLLOW (where the platform supports it) so a final-component
// symlink is rejected at open time, closing the lstat-then-readFile TOCTOU
// race: between a plain lstat and a subsequent path-based read, a concurrent
// replacement can redirect the read through a symlink. Reading through the
// returned file descriptor cannot be redirected. On platforms without
// O_NOFOLLOW (e.g. Windows), the caller's lstat symlink check still rejects
// static symlinks. Mirrors the existing openArtifact behavior.
const openNoFollow = async (absolute) => {
  const noFollow = constants.O_NOFOLLOW || 0;
  try {
    return await open(absolute, constants.O_RDONLY | noFollow);
  } catch (error) {
    if (!noFollow || !['EINVAL', 'ENOTSUP', 'EOPNOTSUPP'].includes(error?.code)) throw error;
    return open(absolute, constants.O_RDONLY);
  }
};

const readHeadFromHandle = async (handle, size) => {
  const buffer = Buffer.allocUnsafe(size);
  const { bytesRead } = await handle.read(buffer, 0, size, 0);
  return buffer.subarray(0, bytesRead);
};

const scanTouchedSuppressions = async (repo, files) => {
  const findings = [];
  for (const file of files) {
    let handle;
    try {
      const absolute = path.join(repo, file);
      let stats;
      try {
        stats = await lstat(absolute);
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        continue;
      }
      if (stats.isSymbolicLink()) {
        findings.push({ file, line: 0, category: 'scan-error', match: 'Touched path is a symlink; refusing to follow.' });
        continue;
      }
      // Reject non-regular files (FIFO, socket, device): a read-only FIFO on
      // POSIX blocks forever waiting for a writer, stalling the scan before
      // any dirty-tree result can stop the run.
      if (!stats.isFile()) {
        findings.push({ file, line: 0, category: 'scan-error', match: 'Touched path is not a regular file; refusing to read.' });
        continue;
      }
      // Reject oversized files before reading them: a large untracked artifact
      // should not block admission with multi-MiB reads when the suppression
      // vocabulary is small.
      if (stats.size > MAX_SUPPRESSION_SCAN_BYTES) {
        findings.push({ file, line: 0, category: 'scan-error', match: `Touched file exceeds suppression scan limit (${stats.size} > ${MAX_SUPPRESSION_SCAN_BYTES} bytes).` });
        continue;
      }
      // Open with O_NOFOLLOW (where supported) and read through the resulting
      // file descriptor so a concurrent replacement cannot redirect the read
      // through a symlink between the lstat above and the bytes we scan.
      try {
        handle = await openNoFollow(absolute);
      } catch (error) {
        if (error.code === 'ELOOP' || error.code === 'EMLINK') {
          findings.push({ file, line: 0, category: 'scan-error', match: 'Touched path is a symlink; refusing to follow.' });
          continue;
        }
        throw error;
      }
      // Sample the first bytes for a NUL to detect binary files; scanning
      // them as text via decodeTouchedText already throws on NUL but we want
      // a clean scan-error finding instead of letting the throw bubble.
      // UTF-16 files start with a BOM (FF FE or FE FF) and contain NUL bytes
      // legitimately, so do not flag those as binary.
      if (stats.size > 0) {
        const head = await readHeadFromHandle(handle, Math.min(BINARY_SAMPLE_BYTES, stats.size));
        const isUtf16Bom = head.length >= 2 && (
          (head[0] === 0xff && head[1] === 0xfe) || (head[0] === 0xfe && head[1] === 0xff)
        );
        if (!isUtf16Bom && head.includes(0)) {
          findings.push({ file, line: 0, category: 'scan-error', match: 'Touched file appears to be binary (NUL byte detected).' });
          continue;
        }
      }
      const bytes = await handle.readFile();
      findings.push(...scanSuppressionText(file, decodeTouchedText(bytes)));
    } catch (error) {
      if (error.code !== 'ENOENT') {
        findings.push({ file, line: 0, category: 'scan-error', match: error.message });
      }
    } finally {
      if (handle) await handle.close().catch(() => {});
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

// Shared filesystem-entry hasher used by both workingTreeFingerprint and
// collectExtraEntries.visit so the symlink/lstat/ENOENT/hashFile guard has
// one owner. Two independently-maintained copies of this safety-critical
// guard is the pattern that produced the earlier decodeTouchedText-bypass
// bug in this file.
const hashFsEntry = async (absolute) => {
  let info;
  try {
    info = await lstat(absolute);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    return hashBytes('missing');
  }
  if (info.isSymbolicLink()) {
    return hashBytes(`symlink:${await readlink(absolute)}`);
  }
  if (!info.isFile()) {
    // FIFO/socket/device: streaming would block or read non-file content.
    return hashBytes('non-regular');
  }
  try {
    return await hashFile(absolute);
  } catch (error) {
    // The file can disappear between lstat() and createReadStream(); treat
    // that the same as the lstat ENOENT case (a stable `missing` hash) so a
    // transiently-gone untracked entry cannot reject out of
    // workingTreeFingerprint and abort runCloseoutWorkflow before the
    // structured evidence report is written.
    if (error.code === 'ENOENT') return hashBytes('missing');
    throw error;
  }
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
    entries.push({ path: `__extra__/${relative}`, hash: await hashFsEntry(absolute) });
  };
  await visit(root);
};

// Stream git stdout through a hash instead of buffering it via execFile's
// maxBuffer. A sufficiently large tracked/staged diff can exceed the
// execFile maxBuffer and throw, which used to reject the closeout workflow
// before any evidence report was written. Streaming keeps memory bounded.
const hashGitOutput = (repo, args) => new Promise((resolve, reject) => {
  const hash = createHash('sha256');
  const child = spawn('git', withNoTextconv(args), { cwd: repo, stdio: ['ignore', 'pipe', 'pipe'] });
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
    hashGitOutput(repo, ['diff', '--binary', '--no-ext-diff', '--no-textconv', 'HEAD']),
    gitPaths(repo, ['ls-files', '--others', '--exclude-standard', '-z']),
  ]);
  const entries = [{ path: '__tracked_diff__', hash: diffHash }];
  // Seal Git exclude metadata via Git-resolved path so linked worktrees
  // (where `.git` is a file) still fingerprint the real gitdir exclude file.
  let excludePath;
  try {
    const gitPath = await gitText(repo, ['rev-parse', '--git-path', 'info/exclude']);
    excludePath = path.isAbsolute(gitPath) ? gitPath : path.join(repo, gitPath);
  } catch {
    excludePath = path.join(repo, '.git', 'info', 'exclude');
  }
  entries.push({ path: '__git_info_exclude__', hash: await hashFsEntry(excludePath) });
  // Seal core.excludesFile: --exclude-standard honors that path for untracked
  // discovery, so mutating it can hide files without changing info/exclude.
  try {
    const excludesFile = await gitText(repo, ['config', '--get', 'core.excludesFile']);
    const resolved = excludesFile
      ? (path.isAbsolute(excludesFile) ? excludesFile : path.resolve(repo, excludesFile))
      : '';
    entries.push({
      path: '__git_core_excludesFile__',
      hash: resolved
        ? hashBytes(`path:${resolved}\0${await hashFsEntry(resolved)}`)
        : hashBytes('unset'),
    });
  } catch {
    entries.push({ path: '__git_core_excludesFile__', hash: hashBytes('unset') });
  }
  for (const file of untracked) {
    // Delegate to the shared hashFsEntry helper so the symlink/lstat/ENOENT/
    // hashFile guard has one owner. A validation command may leave a link to
    // /dev/zero or an outside file; the helper hashes the link target string
    // instead of dereferencing the link, and surfaces a stable `missing`
    // marker when the file is gone.
    const absolute = path.join(repo, file);
    entries.push({ path: file, hash: await hashFsEntry(absolute) });
  }
  for (const extra of [...new Set(extraPaths)].sort()) await collectExtraEntries(repo, extra, entries);
  return fingerprintEntries(entries);
};

const cleanTreeStatus = async (repo) => {
  const raw = await gitText(repo, ['status', '--porcelain=v1']);
  if (raw) {
    return { status: 'FAIL', evidence: `Working tree is not clean: ${raw.split(/\r?\n/).slice(0, 20).join(' | ')}` };
  }
  // Also fail closed when .git/info/exclude was mutated during validation:
  // porcelain alone cannot see files newly ignored by that side channel.
  // Callers that need exclude sealing compare workingTreeFingerprint before/after.
  return { status: 'PASS', evidence: 'Working tree is clean.' };
};

const readGateChanges = async (repo, baseSha) => {
  // A deleted gate file contributes no added lines, so surface it on a
  // dedicated channel: classifyGateIntegrity must fail closed when a
  // validation-defining file (workflow, package.json, lockfile) is removed
  // rather than PASS on attestation alone.
  const [changed, deleted, untracked] = await Promise.all([
    gitPaths(repo, ['diff', '--name-only', '-z', baseSha]),
    gitPaths(repo, ['diff', '--name-only', '--diff-filter=D', '-z', baseSha]),
    gitPaths(repo, ['ls-files', '--others', '--exclude-standard', '-z']),
  ]);
  const changedFiles = [...new Set([...changed, ...untracked].filter(isGateFile))].sort();
  const deletedFiles = [...new Set(deleted.filter(isGateFile))].sort();
  if (!changedFiles.length) return { changedFiles, addedLines: [], deletedFiles };
  const tracked = changedFiles.filter((file) => !untracked.includes(file));
  // Contain a very large tracked gate-file diff (e.g. a regenerated
  // pnpm-lock.yaml or workspace manifest churn) that would exceed execFile's
  // maxBuffer and reject out of readGateChanges before the workflow can write a
  // structured evidence report. On overflow (or any git failure), record a
  // bounded decode-error marker for the tracked gate files and continue to the
  // untracked-file scan so the caller still receives a structured result.
  let diff = '';
  let trackedDiffError = null;
  if (tracked.length) {
    try {
      diff = await gitText(repo, ['diff', '--unified=0', '--no-ext-diff', baseSha, '--', ...tracked]);
    } catch (error) {
      trackedDiffError = error;
    }
  }
  const addedLines = trackedDiffError
    ? [`+__decode_error__:${tracked.join(',')}:diff_buffer_exceeded:${trackedDiffError?.code || trackedDiffError?.message || trackedDiffError}`]
    : diff.split(/\r?\n/).filter((line) => line.startsWith('+') && !line.startsWith('+++'));
  for (const file of changedFiles.filter((item) => untracked.includes(item))) {
    let handle;
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
      if (!info.isFile()) {
        addedLines.push(`+__decode_error__:${file}:non_regular_file`);
        continue;
      }
      // Bound reads of untracked gate files the same way scanTouchedSuppressions
      // bounds touched-file reads: a large untracked lockfile or generated
      // config must not exhaust memory before the dirty-tree result can stop
      // the run.
      if (info.size > MAX_SUPPRESSION_SCAN_BYTES) {
        addedLines.push(`+__decode_error__:${file}:exceeds_scan_limit`);
        continue;
      }
      // Open with O_NOFOLLOW (where supported) and read through the descriptor
      // so a concurrent replacement cannot redirect the read through a symlink
      // between the lstat above and the bytes we decode.
      try {
        handle = await openNoFollow(absolute);
      } catch (error) {
        if (error.code === 'ELOOP' || error.code === 'EMLINK') {
          addedLines.push(`+__decode_error__:${file}:symlink_not_allowed`);
          continue;
        }
        throw error;
      }
      const text = decodeTouchedText(await handle.readFile());
      for (const line of text.split(/\r?\n/)) {
        addedLines.push(`+${line}`);
      }
    } catch (error) {
      addedLines.push(`+__decode_error__:${file}:${error.message}`);
    } finally {
      if (handle) await handle.close().catch(() => {});
    }
  }
  return { changedFiles, addedLines, deletedFiles };
};

module.exports = {
  cleanTreeStatus,
  decodeTouchedText,
  normalize,
  readGateChanges,
  readProjectMetadata,
  resolveRepositoryState,
  scanTouchedSuppressions,
  withNoTextconv,
  workingTreeFingerprint,
};
