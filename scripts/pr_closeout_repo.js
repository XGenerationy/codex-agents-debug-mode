const { execFile, spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const { constants, createReadStream } = require('node:fs');
const { lstat, open, readFile, readdir, readlink } = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { promisify, TextDecoder } = require('node:util');

const { scanSuppressionText } = require('./pr_closeout_core');
const { fingerprintEntries, isGateFile } = require('./pr_closeout_git');

const execFileAsync = promisify(execFile);
/**
 * Normalize a raw git-reported path for consistent comparison and lookup:
 * strips a leading `./`, and — only when actually running on win32 —
 * converts `\` separators to `/`. On POSIX, backslashes are left intact even
 * if the path looks Windows-shaped, because Git can report a filename that
 * legitimately contains a literal `\`; rewriting it there would probe the
 * wrong path on disk and silently drop that file out of suppression scanning
 * (ENOENT).
 * @param {string} file - Raw path as reported by git (e.g. NUL-delimited `-z` output).
 * @returns {string} The normalized path.
 */
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

/**
 * Decode raw file bytes into text, auto-detecting a UTF-16 BOM (LE `FF FE`
 * or BE `FE FF`) before falling back to strict UTF-8. All three decoders run
 * with `fatal: true`, so malformed sequences throw instead of silently
 * producing replacement characters; a NUL byte with no recognized BOM is
 * rejected up front as an unrecognized/binary encoding rather than handed to
 * the UTF-8 decoder.
 * @param {Uint8Array} bytes - Raw file contents.
 * @returns {string} Decoded text.
 * @throws {Error} If the bytes contain a NUL byte outside a recognized BOM, or fail strict decoding.
 */
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

/**
 * Force `--no-textconv` onto any `git diff` invocation so a repo-local diff
 * driver (configured via `.gitattributes`/`textconv`) cannot run an
 * arbitrary converter during internal closeout diffing or fingerprinting. A
 * no-op for non-`diff` subcommands, and left untouched if the caller already
 * passed `--no-textconv` or `--textconv` explicitly.
 * @param {string[]} args - git argv (e.g. `['diff', '--name-only', ...]`).
 * @returns {string[]} `args` with `--no-textconv` inserted right after `diff` when needed.
 */
const withNoTextconv = (args) => {
  if (!args.includes('diff')) return args;
  if (args.includes('--no-textconv') || args.includes('--textconv')) return args;
  const out = [...args];
  const diffAt = out.indexOf('diff');
  out.splice(diffAt + 1, 0, '--no-textconv');
  return out;
};

/**
 * Wrap git argv with the config flags every internal (non-user-facing) git
 * call needs: disable fsmonitor/hooks so a repo- or user-configured local
 * hook can never run outside spawnCaptured's containment, force
 * `core.fileMode=true` so a validation command cannot flip
 * `core.fileMode=false` to hide a chmod change to a tracked file from the
 * status/diff seal, and apply withNoTextconv.
 * @param {string[]} args - git argv.
 * @returns {string[]} args prefixed with the safety `-c` flags.
 */
const withInternalGitSafety = (args) => ([
  '-c', 'core.fsmonitor=',
  '-c', 'core.useBuiltinFSMonitor=false',
  '-c', 'core.fileMode=true',
  ...withNoTextconv(args),
]);

// Git expands a leading `~/` (and `~\`) in pathname config values such as
// core.excludesFile against the user's home directory before resolving them
// (see git-config: pathname). Without that expansion a value like `~/gitignore`
// would be hashed as a repo-relative path (<repo>/~/gitignore) and a command
// could set excludesFile to hide untracked files without changing the seal.
/**
 * Resolve a Git pathname config value the way Git does: absolute paths are
 * kept as-is, a leading `~/` or `~\` is expanded against the home directory,
 * and any other value is resolved relative to `base` (the repo for local
 * config, the home dir for global config).
 * @param {string} value - Raw config value (e.g. `~/gitignore`, `/abs/path`).
 * @param {string} base - Base directory for non-absolute, non-tilde values.
 * @returns {string} The resolved absolute path, or '' for an empty value.
 */
const expandGitPathname = (value, base) => {
  if (!value) return '';
  if (path.isAbsolute(value)) return value;
  if (value.startsWith('~/')) return path.join(os.homedir(), value.slice(2));
  if (value.startsWith('~\\')) return path.join(os.homedir(), value.slice(2));
  return path.resolve(base, value);
};

// Enumerate every per-directory ignore file (tracked, untracked, and even a
// self-ignoring untracked .gitignore that lists itself). --exclude-standard
// omits ignored files, so a validation command can write an untracked
// .gitignore that hides an artifact directory and leave both cleanTreeStatus
// and the untracked fingerprint unchanged. The ignored query pathspec-bound to
// .gitignore surfaces the self-ignoring file without walking node_modules.
/**
 * Enumerate every per-directory ignore file under the repo: tracked, untracked,
 * and even a self-ignoring untracked `.gitignore` that lists itself. Uses two
 * pathspec-bound `git ls-files` queries (visible + ignored) so a validation
 * command cannot drop an untracked `.gitignore` that hides an artifact dir
 * without changing the fingerprint, without walking node_modules.
 * @param {string} repo - Absolute path to the repository working tree.
 * @returns {Promise<string[]>} Sorted list of repo-relative `.gitignore` paths.
 */
const listIgnoreFiles = async (repo) => {
  const pathspec = [':(glob)**/.gitignore', '.gitignore'];
  const visible = await gitPaths(repo, ['ls-files', '--cached', '--others', '--exclude-standard', '-z', '--', ...pathspec]);
  const ignored = await gitPaths(repo, ['ls-files', '--others', '--ignored', '--exclude-standard', '-z', '--', ...pathspec]);
  return [...new Set([...visible, ...ignored])].sort();
};

/**
 * Run git under withInternalGitSafety and return raw stdout as a Buffer
 * (undecoded), capped at 50MB via execFile's `maxBuffer`. Callers decode as
 * needed: gitText trims it to a UTF-8 string, gitPaths splits it on NUL and
 * normalizes each path.
 * @param {string} repo - Absolute repository path.
 * @param {string[]} args - git argv.
 * @returns {Promise<Buffer>} Raw stdout bytes.
 */
const gitBuffer = async (repo, args) => {
  const result = await execFileAsync('git', withInternalGitSafety(args), {
    cwd: repo,
    encoding: 'buffer',
    maxBuffer: 50_000_000,
  });
  return result.stdout;
};

const gitText = async (repo, args) => (await gitBuffer(repo, args)).toString('utf8').trim();
const gitPaths = async (repo, args) => (await gitBuffer(repo, args))
  .toString('utf8')
  .split('\0')
  .filter(Boolean)
  .map(normalize);

/**
 * Resolve the repository snapshot the rest of closeout operates on: HEAD,
 * `baseRef`, and their merge-base SHAs (resolved concurrently), plus the
 * full touched-file set. `touchedFiles` is the union of everything the PR
 * branch changed since the merge-base (three-dot diff) with whatever is
 * currently staged, unstaged, or untracked in the working tree — so it
 * reflects both committed branch history and any in-progress edits at scan
 * time.
 * @param {{repo: string, baseRef: string}} options - `repo` is resolved to an absolute path; `baseRef` is a required live PR base ref (branch or SHA).
 * @returns {Promise<{repo: string, baseRef: string, baseSha: string, mergeBaseSha: string, headSha: string, touchedFiles: string[]}>}
 * @throws {Error} If `baseRef` is not supplied.
 */
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

/**
 * Read the project metadata buildCheckPlan resolves checks against:
 * `package.json` scripts, and the target names defined in whichever
 * Makefile variant the repo uses. Makefile discovery follows GNU make's own
 * documented default search order — GNUmakefile, then makefile, then
 * Makefile — stopping at the first one present; target names are parsed from
 * lines shaped like `name:` while excluding variable assignments like
 * `name:=`. A missing file is silently treated as "no scripts" / "no
 * targets" (ENOENT is swallowed); every other read failure — including the
 * symlink/non-regular/oversized rejections from the nested safeReadFile
 * guard — propagates.
 * @param {string} repo - Absolute repository path.
 * @returns {Promise<{packageScripts: Record<string, string>, makeTargets: string[]}>}
 */
const readProjectMetadata = async (repo) => {
  let packageScripts = {};
  let makeTargets = [];
  /**
   * Reject symlinked and non-regular metadata before reading it: a reviewed
   * branch can make root `package.json` or a default Makefile a symlink to
   * `/dev/zero` or an outside file, or replace it with a directory or FIFO
   * whose read throws EISDIR or blocks — before any later check can stop the
   * read and before any structured evidence report exists. Also enforces the
   * shared MAX_SUPPRESSION_SCAN_BYTES cap.
   * @param {string} relative - Path relative to `repo`.
   * @returns {Promise<string|undefined>} File contents, or `undefined` if the path does not exist.
   * @throws {Error} If the path is a symlink, a non-regular file, or exceeds the size cap.
   */
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

/**
 * Open a file with `O_NOFOLLOW` (where the platform supports it) so a
 * final-component symlink is rejected at open time, closing the
 * lstat-then-readFile TOCTOU race: between a caller's plain `lstat` and a
 * later path-based read, a concurrent replacement could otherwise redirect
 * the read through a symlink. Reading through the returned file descriptor
 * cannot be redirected. Falls back to a plain open when the platform has no
 * `O_NOFOLLOW` (e.g. Windows) or rejects the flag as unsupported — the
 * caller's `lstat` symlink check still rejects a static symlink there.
 * Mirrors the existing `openArtifact` behavior.
 * @param {string} absolute - Absolute filesystem path.
 * @returns {Promise<import('node:fs/promises').FileHandle>} An open file handle.
 */
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

/**
 * Scan every touched file for suppression markers, config-level silencing,
 * and test-weakening (via scanSuppressionText), while defending the read
 * itself against a hostile or racing working tree. For each file: a missing
 * file (ENOENT) is skipped silently; a symlink, a non-regular file
 * (FIFO/socket/device), or a file over MAX_SUPPRESSION_SCAN_BYTES each
 * produce a `scan-error` finding instead of being read. Surviving files are
 * opened with `O_NOFOLLOW` (via openNoFollow) so a concurrent replacement
 * between the `lstat` check and the open cannot redirect the read through a
 * symlink — the same TOCTOU-closing pattern readGateChanges applies
 * independently to untracked gate files. The first sampled bytes are
 * checked for a NUL byte to reject binary content as a `scan-error`, except
 * a UTF-16 BOM prefix (which legitimately starts with a NUL-adjacent byte
 * pair); any other unexpected error becomes a `scan-error` finding rather
 * than aborting the whole scan.
 * @param {string} repo - Absolute repository path.
 * @param {string[]} files - Repo-relative touched file paths to scan.
 * @returns {Promise<Array<{file: string, line: number, category: string, match: string}>>} Combined findings across every file.
 */
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

/**
 * Stream a file's contents through a SHA-256 hash rather than materializing
 * it in memory. workingTreeFingerprint runs several times per closeout
 * (initial tree, before/after GitHub verification, final seal), and a single
 * large untracked artifact is enough to spike memory if `readFile()` were
 * used instead.
 * @param {string} absolute - Absolute filesystem path to a regular file.
 * @returns {Promise<string>} Hex-encoded SHA-256 digest of the file's contents.
 */
const hashFile = async (absolute) => {
  const hash = createHash('sha256');
  const stream = createReadStream(absolute);
  for await (const chunk of stream) hash.update(chunk);
  return hash.digest('hex');
};

/**
 * Shared filesystem-entry hasher used by both workingTreeFingerprint and
 * collectExtraEntries's `visit` so the symlink/lstat/ENOENT/hashFile guard
 * has exactly one owner — two independently-maintained copies of this
 * safety-critical guard is the pattern that produced the earlier
 * decodeTouchedText-bypass bug in this file. Produces a stable hash for
 * every entry kind: a missing path and a non-regular path (FIFO/socket/
 * device) each hash to a fixed marker, a symlink hashes its target text
 * without dereferencing it, and a regular file is streamed through
 * hashFile. A file that disappears between this function's `lstat` and the
 * streamed read (a benign race, not tampering) is treated the same as
 * already-missing rather than thrown.
 * @param {string} absolute - Absolute filesystem path.
 * @returns {Promise<string>} Hex-encoded SHA-256 digest identifying the entry's kind and content.
 */
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

/**
 * Validate and resolve a config-supplied "extra" reproducibility path before
 * it is folded into workingTreeFingerprint. Rejects an absolute `requested`
 * value outright, then rejects any path that resolves outside `repo` (`..`
 * traversal) or into `.git`/`.git/...` — config cannot use this mechanism to
 * fingerprint, or let a validation command tamper with, git internals.
 * @param {string} repo - Absolute repository path.
 * @param {string} requested - Repo-relative path from config (e.g. an `extraPaths` entry).
 * @returns {{absolute: string, relative: string}} The resolved absolute path and its normalized repo-relative form.
 * @throws {Error} If `requested` is absolute, empty, escapes the repo, or targets `.git`.
 */
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

/**
 * Resolve one config-supplied extra path (via resolveExtraPath) and
 * recursively fold it into the shared `entries` array that
 * workingTreeFingerprint later hashes. A missing path records a stable
 * "missing" marker, a symlink records its target text without following it,
 * a directory records a marker entry and then recurses into its children in
 * sorted order (so traversal order never affects the resulting fingerprint),
 * and a regular file delegates to hashFsEntry. Lets paths outside git's own
 * tracked/untracked accounting (e.g. generated output) be sealed into the
 * reproducibility fingerprint.
 * @param {string} repo - Absolute repository path.
 * @param {string} requested - Repo-relative extra path to fold in.
 * @param {{path: string, hash: string}[]} entries - Shared accumulator array, mutated in place.
 * @returns {Promise<void>}
 */
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

/**
 * Run git via `spawn` (not execFile) and stream stdout through a SHA-256
 * hash instead of buffering it against execFile's `maxBuffer` ceiling. A
 * sufficiently large tracked/staged diff can exceed that buffer and throw,
 * which used to reject the whole closeout workflow before any evidence
 * report was written; streaming keeps memory bounded regardless of diff
 * size.
 * @param {string} repo - Absolute repository path.
 * @param {string[]} args - git argv.
 * @returns {Promise<string>} Hex-encoded SHA-256 digest of stdout.
 * @throws {Error} If git exits non-zero, including captured stderr in the message.
 */
const hashGitOutput = (repo, args) => new Promise((resolve, reject) => {
  const hash = createHash('sha256');
  const child = spawn('git', withInternalGitSafety(args), { cwd: repo, stdio: ['ignore', 'pipe', 'pipe'] });
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

/**
 * Compute a single composite fingerprint of everything that can change the
 * meaning of "clean working tree" between two points in the closeout
 * workflow, so no individual channel git uses to hide or reveal a change can
 * be manipulated without moving the seal. Combines: the tracked diff against
 * HEAD (binary-safe, textconv disabled); `.git/info/exclude`, resolved via
 * `git rev-parse --git-path` so a linked worktree still seals its real
 * gitdir file; the local `core.excludesFile`; the global `core.excludesFile`
 * and the XDG default global gitignore (both of which `--exclude-standard`
 * also consults); every per-directory `.gitignore` in the repo, tracked or
 * untracked, including a self-ignoring one; every untracked file's identity
 * (via hashFsEntry); and any caller-supplied `extraPaths` (via
 * collectExtraEntries). All entries are handed to fingerprintEntries, which
 * sorts by path before hashing so entry-collection order never affects the
 * result.
 * @param {string} repo - Absolute repository path.
 * @param {string[]} [extraPaths] - Additional repo-relative paths (files or directories) to fold into the seal.
 * @returns {Promise<string>} Hex-encoded SHA-256 composite fingerprint.
 */
const workingTreeFingerprint = async (repo, extraPaths = []) => {
  const [diffHash, untracked] = await Promise.all([
    hashGitOutput(repo, ['diff', '--binary', '--no-ext-diff', '--no-textconv', '--ignore-submodules=none', 'HEAD']),
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
    const resolved = excludesFile ? expandGitPathname(excludesFile, repo) : '';
    entries.push({
      path: '__git_core_excludesFile__',
      hash: resolved
        ? hashBytes(`path:${resolved}\0${await hashFsEntry(resolved)}`)
        : hashBytes('unset'),
    });
  } catch {
    entries.push({ path: '__git_core_excludesFile__', hash: hashBytes('unset') });
  }
  // Seal Git's default global excludes too (`--exclude-standard` also reads
  // $XDG_CONFIG_HOME/git/ignore and the global core.excludesFile).
  const globalExcludeParts = [];
  try {
    const globalExcludes = await gitText(repo, ['config', '--global', '--get', 'core.excludesFile']);
    if (globalExcludes) {
      const resolved = expandGitPathname(globalExcludes, os.homedir());
      globalExcludeParts.push(`globalCore:${resolved}\0${await hashFsEntry(resolved)}`);
    } else {
      globalExcludeParts.push('globalCore:unset');
    }
  } catch {
    globalExcludeParts.push('globalCore:unset');
  }
  const xdgConfig = process.env.XDG_CONFIG_HOME
    ? process.env.XDG_CONFIG_HOME
    : path.join(os.homedir(), '.config');
  const xdgIgnore = path.join(xdgConfig, 'git', 'ignore');
  globalExcludeParts.push(`xdg:${xdgIgnore}\0${await hashFsEntry(xdgIgnore)}`);
  entries.push({
    path: '__git_global_excludes__',
    hash: hashBytes(globalExcludeParts.sort().join('\n')),
  });
  // Seal every per-directory .gitignore (tracked, untracked, and even a
  // self-ignoring one) so a validation command cannot drop an untracked
  // .gitignore that hides an artifact directory without changing the
  // fingerprint. --exclude-standard omits ignored files, so the ignored query
  // (pathspec-bound to .gitignore) surfaces a self-ignoring ignore file too.
  const ignoreFiles = await listIgnoreFiles(repo);
  const ignoreParts = [];
  for (const rel of ignoreFiles) {
    const absolute = path.isAbsolute(rel) ? rel : path.join(repo, rel);
    ignoreParts.push(`${rel}\0${await hashFsEntry(absolute)}`);
  }
  entries.push({ path: '__gitignore_files__', hash: hashBytes(ignoreParts.join('\n')) });
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

/**
 * Two-layer "is the working tree clean" check. First runs `git status`
 * forcing `--untracked-files=all` and `--ignore-submodules=none` so local or
 * global config that would normally hide untracked files or dirty
 * submodules cannot mask them here — any porcelain output FAILs with up to
 * 20 lines of evidence. Second, even with clean porcelain output, checks
 * `git ls-files -v` for assume-unchanged (lowercase tag) or skip-worktree
 * (`S` tag) index bits on tracked files — both make `git status`/`git diff`
 * blind to real edits on those files, so any tagged file also FAILs. Does
 * not by itself detect a mutated `.git/info/exclude`; a caller that needs
 * that sealed compares workingTreeFingerprint before/after instead.
 * @param {string} repo - Absolute repository path.
 * @returns {Promise<{status: 'PASS'|'FAIL', evidence: string}>}
 */
const cleanTreeStatus = async (repo) => {
  // Force untracked reporting even when status.showUntrackedFiles=no is set
  // locally/globally; otherwise porcelain omits untracked files and a dirty
  // tree can PASS while fingerprints still see the same stable untracked set.
  // --ignore-submodules=none overrides a local `submodule.<name>.ignore=all` so
  // a validation command cannot dirty a submodule and leave the seal clean.
  const raw = await gitText(repo, ['status', '--porcelain=v1', '--untracked-files=all', '--ignore-submodules=none']);
  if (raw) {
    return { status: 'FAIL', evidence: `Working tree is not clean: ${raw.split(/\r?\n/).slice(0, 20).join(' | ')}` };
  }
  // assume-unchanged / skip-worktree index bits hide working-tree modifications
  // from `git status` and `git diff`, so a validation command can edit a tracked
  // file after marking it and leave both the porcelain check and the diff
  // fingerprint unchanged. `git ls-files -v` tags assume-unchanged files with a
  // lowercase letter and skip-worktree files with 'S'; reject either before the
  // tree is declared clean.
  const tagged = await gitText(repo, ['ls-files', '-v']);
  const masked = tagged.split(/\r?\n/).filter((line) => {
    const tag = line[0];
    return tag && (tag === 'S' || (tag >= 'a' && tag <= 'z'));
  });
  if (masked.length) {
    return {
      status: 'FAIL',
      evidence: `Tracked file marked assume-unchanged/skip-worktree (hides modifications): ${masked.slice(0, 10).map((line) => line.slice(2)).join(', ')}`,
    };
  }
  // Also fail closed when .git/info/exclude was mutated during validation:
  // porcelain alone cannot see files newly ignored by that side channel.
  // Callers that need exclude sealing compare workingTreeFingerprint before/after.
  return { status: 'PASS', evidence: 'Working tree is clean.' };
};

/**
 * Extract what changed in "gate" files (isGateFile — CI workflows, package
 * manifests/lockfiles, linter/Makefile/test-runner configs, and this tool's
 * own config) between `baseSha` and the current working tree, so a caller
 * like classifyGateIntegrity can fail closed on weakened or deleted
 * validation. For tracked gate files, only added lines (`+...`, excluding
 * the `+++` file header) are collected from a unified=0 diff against
 * `baseSha` — the point is to see what new content entered the file, not
 * what left. For untracked gate files (new in this PR), the whole file is
 * read as "added" through the same symlink-safe, size-capped, `O_NOFOLLOW`
 * guarded path used by scanTouchedSuppressions, closing the same
 * lstat-then-read TOCTOU race. Any failure along either path — an oversized
 * tracked diff exceeding execFile's `maxBuffer`, or a per-file read guard
 * rejecting a file — degrades to a bounded `+__decode_error__:...` synthetic
 * line instead of throwing, so the closeout workflow still gets a structured
 * result to report against.
 * @param {string} repo - Absolute repository path.
 * @param {string} baseSha - Base commit SHA to diff gate files against.
 * @returns {Promise<{changedFiles: string[], addedLines: string[], deletedFiles: string[]}>}
 */
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
