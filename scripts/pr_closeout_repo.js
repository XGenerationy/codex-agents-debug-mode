const { execFile, spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const { lstat, readFile, readdir, readlink, realpath } = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { promisify, TextDecoder } = require('node:util');

const { scanSuppressionText } = require('./pr_closeout_core');
const { computeFilterSafetyOverrides, fingerprintEntries, isGateFile } = require('./pr_closeout_git');
const { isSameFileIdentity, openNoFollow } = require('./pr_closeout_fs');

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
 * status/diff seal, neutralize every configured `filter.<driver>.*` driver
 * (git invokes the `clean` filter to convert worktree content before
 * comparing it against the index during `diff` — confirmed by manual repro:
 * `git status` uses a cheaper stat/hash check and does NOT run the filter,
 * but `git diff`, used below by hashGitOutput/workingTreeFingerprint to seal
 * the tracked diff, does — so a touched `.gitattributes` selecting a
 * configured filter, or a validation command writing one to local config,
 * would otherwise run that driver outside spawnCaptured's sanitized
 * environment on every internal diff call), and apply withNoTextconv. Filter
 * drivers are re-enumerated on every call (not cached) because a validation
 * command can add one to local config between two internal git invocations.
 * @param {string} repo - Absolute repository path (used only to enumerate filter.* config).
 * @param {string[]} args - git argv.
 * @returns {Promise<string[]>} args prefixed with the safety `-c` flags.
 */
const withInternalGitSafety = async (repo, args) => ([
  '-c', 'core.fsmonitor=',
  '-c', 'core.useBuiltinFSMonitor=false',
  '-c', 'core.fileMode=true',
  ...(await computeFilterSafetyOverrides(repo, { env: gitChildEnv() })),
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
/**
 * Git env for internal closeout invocations: drop every inherited GIT_*
 * variable so caller-controlled routing (GIT_DIR / GIT_WORK_TREE), external
 * helpers (GIT_EXTERNAL_DIFF), and config overrides (GIT_CONFIG_*) cannot
 * redirect, execute, or reconfigure internal git work (CodeRabbit #4781498400).
 * Match case-insensitively: Windows env names are case-insensitive, so a
 * differently-cased key (git_dir / Git_Config_Count) is still observed by
 * Git as GIT_* (Qodo #4781532944).
 * @param {NodeJS.ProcessEnv} [source=process.env] - Env map to sanitize.
 * @returns {NodeJS.ProcessEnv}
 */
const gitChildEnv = (source = process.env) => {
  const env = { ...source };
  for (const key of Object.keys(env)) {
    if (key.toUpperCase().startsWith('GIT_')) delete env[key];
  }
  return env;
};

const gitBuffer = async (repo, args) => {
  const result = await execFileAsync('git', await withInternalGitSafety(repo, args), {
    cwd: repo,
    env: gitChildEnv(),
    encoding: 'buffer',
    maxBuffer: 50_000_000,
  });
  return result.stdout;
};

const gitText = async (repo, args) => (await gitBuffer(repo, args)).toString('utf8').trim();
/**
 * Split NUL-delimited git path output with a fatal UTF-8 decode per segment.
 * Lossy `toString('utf8')` would replace invalid bytes with U+FFFD and point
 * suppression/gate scans at the wrong path (ENOENT skip), so non-UTF-8 path
 * records fail closed instead of silently dropping a touched file.
 */
const gitPaths = async (repo, args) => {
  const buffer = await gitBuffer(repo, args);
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
        if (decoded.length) paths.push(normalize(decoded));
      }
      start = i + 1;
    }
  }
  return paths;
};

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
  // Prefer the physical directory Git and child processes report (pwd, cwd),
  // while still accepting a symlink path as input. Callers' path redaction
  // tables also include both spellings via buildPathReplacements.
  const resolvedRepo = path.resolve(repo);
  let physicalRepo = resolvedRepo;
  try {
    physicalRepo = await realpath(resolvedRepo);
  } catch (error) {
    // Only ENOENT falls back to path.resolve so a missing path still yields a
    // clearer downstream git error. ELOOP / EACCES / other failures must not
    // silently drop the physical-path guarantee used for containment checks.
    if (error?.code !== 'ENOENT') throw error;
  }
  const [headSha, baseSha, mergeBaseSha] = await Promise.all([
    gitText(physicalRepo, ['rev-parse', 'HEAD']),
    gitText(physicalRepo, ['rev-parse', baseRef]),
    gitText(physicalRepo, ['merge-base', baseRef, 'HEAD']),
  ]);
  const groups = await Promise.all([
    gitPaths(physicalRepo, ['diff', '--name-only', '-z', `${mergeBaseSha}...HEAD`]),
    gitPaths(physicalRepo, ['diff', '--name-only', '-z']),
    gitPaths(physicalRepo, ['diff', '--name-only', '--cached', '-z']),
    gitPaths(physicalRepo, ['ls-files', '--others', '--exclude-standard', '-z']),
  ]);
  return {
    repo: physicalRepo,
    baseRef,
    baseSha,
    mergeBaseSha,
    headSha,
    touchedFiles: [...new Set(groups.flat())].sort(),
  };
};

/**
 * Find the first `#` in a Makefile target/prerequisites tail that GNU make
 * would treat as a comment start, per make's backslash-escaping rule: a `#`
 * is literal only when preceded by an ODD number of consecutive backslashes
 * (each `\\` pair is one escaped literal backslash; a leftover single `\`
 * escapes the `#`). A single-backslash lookbehind (`/(?<!\\)#/`) gets this
 * wrong for an even count — e.g. `deps\\# comment` is one escaped backslash
 * followed by a real comment, but `(?<!\\)` sees the backslash immediately
 * before `#` and misclassifies it as escaped (Qodo UrI0h).
 * @param {string} text - Text to scan (the target line's tail after `:`).
 * @returns {number} Index of the first unescaped `#`, or -1 if none.
 */
const findUnescapedHashIndex = (text) => {
  for (let i = 0; i < text.length; i += 1) {
    if (text[i] !== '#') continue;
    let backslashes = 0;
    let j = i - 1;
    while (j >= 0 && text[j] === '\\') {
      backslashes += 1;
      j -= 1;
    }
    if (backslashes % 2 === 0) return i;
  }
  return -1;
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
 * @returns {Promise<{packageScripts: Record<string, string>, makeTargets: string[], makeRecipes: Record<string, string>}>}
 */
const readProjectMetadata = async (repo) => {
  let packageScripts = {};
  let makeTargets = [];
  const makeRecipes = {};
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
    // Open with O_NOFOLLOW and re-verify on the descriptor so a TOCTOU swap
    // to a symlink/FIFO between lstat and read cannot escape the repo or hang.
    let handle;
    try {
      handle = await openNoFollow(absolute);
    } catch (error) {
      if (error.code === 'ENOENT') return undefined;
      if (error.code === 'ELOOP' || error.code === 'EMLINK') {
        throw new Error(`Refusing to read symlinked metadata: ${relative}`);
      }
      throw error;
    }
    try {
      const opened = await handle.stat();
      if (!opened.isFile()) {
        throw new Error(`Refusing to read non-regular metadata: ${relative}`);
      }
      if (opened.size > MAX_SUPPRESSION_SCAN_BYTES) {
        throw new Error(`Refusing to read oversized metadata (${opened.size} > ${MAX_SUPPRESSION_SCAN_BYTES} bytes): ${relative}`);
      }
      // Read at most the verified size so a concurrent grow cannot force an
      // unbounded buffer despite the size check (Codex #4782132804).
      const bytes = Buffer.alloc(opened.size);
      let offset = 0;
      while (offset < opened.size) {
        const { bytesRead } = await handle.read(bytes, offset, opened.size - offset, offset);
        if (bytesRead === 0) break;
        offset += bytesRead;
      }
      if (offset !== opened.size) {
        throw new Error(`Metadata short-read during plan construction (${offset}/${opened.size} bytes): ${relative}`);
      }
      return bytes.toString('utf8');
    } finally {
      await handle.close().catch(() => {});
    }
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
      // Recipe lines are the tab-prefixed lines belonging to a target
      // (GNU make's default recipe-line convention), captured so a resolved
      // make target's body can be checked for failure-neutralizing patterns
      // the same way an auto-discovered package script is (Codex Ummss) — the
      // first definition's recipe wins for a repeated target name, mirroring
      // the Set dedup already applied to makeTargets below. Two gaps let a
      // neutralizing command hide from that check entirely: (1) GNU make also
      // accepts an inline recipe on the target line itself after a `;`
      // (`target: ; recipe` / `target: prereq ; recipe`), which a scan
      // starting on the NEXT line would never see (Qodo Uod13); (2) GNU make
      // does not end a recipe at a blank line or a make-level comment (a
      // non-tab-indented line whose first non-whitespace character is `#`) —
      // only a genuinely new construct does — so a neutralizer placed after
      // such a gap inside an otherwise-normal recipe was previously dropped by
      // stopping at the first non-tab-prefixed line (CodeRabbit Uohnu). Both
      // are closed here: the post-`;` text (if any) is captured as the first
      // recipe line, and the scan continues across blank/comment-only lines
      // instead of stopping at the first one.
      const lines = makefile.split(/\r?\n/);
      const targets = [];
      for (let i = 0; i < lines.length; i += 1) {
        const match = lines[i].match(/^([A-Za-z0-9_.-]+)\s*:(?![=])/);
        if (!match) continue;
        const target = match[1];
        targets.push(target);
        if (!Object.hasOwn(makeRecipes, target)) {
          const recipeLines = [];
          const afterColon = lines[i].slice(match[0].length);
          // GNU make strips a comment (an unescaped `#`) from a target/
          // prerequisites line before it looks for the `;` that introduces an
          // inline recipe, so a `#` in the tail can hide or fabricate a `;`
          // that is really commentary, e.g. `target: deps # note; echo hi`.
          // Search only the text before the first unescaped `#` so a comment
          // is never mistaken for (or scanned inside) a captured recipe
          // (CodeRabbit UptWQ; escape parity per Qodo UrI0h).
          const hashIndex = findUnescapedHashIndex(afterColon);
          const beforeComment = hashIndex === -1 ? afterColon : afterColon.slice(0, hashIndex);
          const semicolon = beforeComment.indexOf(';');
          if (semicolon !== -1) recipeLines.push(beforeComment.slice(semicolon + 1));
          let j = i + 1;
          while (j < lines.length) {
            const line = lines[j];
            if (/^\t/.test(line)) {
              recipeLines.push(line);
              j += 1;
              continue;
            }
            if (/^\s*$/.test(line) || /^\s*#/.test(line)) {
              j += 1;
              continue;
            }
            break;
          }
          if (recipeLines.length) makeRecipes[target] = recipeLines.join('\n');
        }
      }
      makeTargets = [...new Set(targets)];
      break;
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }
  return { packageScripts, makeTargets, makeRecipes };
};

// Cap the suppression scanner so a single huge or binary touched file cannot
// spike memory or stall admission. Files larger than this are recorded as a
// scan-error; suppression markers are far smaller than this in practice.
const MAX_SUPPRESSION_SCAN_BYTES = 5 * 1024 * 1024;
// Sample the first N bytes for a NUL byte to detect binary files quickly
// without loading the whole file.
const BINARY_SAMPLE_BYTES = 4096;

// openNoFollow is shared (pr_closeout_fs.js): defaults to O_RDONLY so
// openNoFollow(absolute) remains the read-side call shape used by
// suppression/gate scanners. Write-side callers pass explicit flags.

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
 * pair). The re-stat is additionally bound back to the pre-open lstat's
 * device/inode identity (via isSameFileIdentity) so a path — or a parent
 * directory — swapped between the lstat and the open (including through
 * openNoFollow's following-open fallback where O_NOFOLLOW is unavailable)
 * cannot redirect the scan to a different, clean file and silently miss a
 * real suppression; a mismatched or unusable (ino===0) identity is a
 * `scan-error`. Any other unexpected error becomes a `scan-error` finding
 * rather than aborting the whole scan.
 * @param {string} repo - Absolute repository path.
 * @param {string[]} files - Repo-relative touched file paths to scan.
 * @param {{lstatFn?: (target: string) => Promise<import('node:fs').Stats>}} [deps] - Injectable lstat for TOCTOU identity tests.
 * @returns {Promise<Array<{file: string, line: number, category: string, match: string}>>} Combined findings across every file.
 */
const scanTouchedSuppressions = async (repo, files, { lstatFn = lstat } = {}) => {
  const findings = [];
  for (const file of files) {
    let handle;
    try {
      const absolute = path.join(repo, file);
      let stats;
      try {
        stats = await lstatFn(absolute);
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
      // Re-stat the opened descriptor so a TOCTOU grow/replace after lstat
      // cannot push the read past MAX_SUPPRESSION_SCAN_BYTES.
      const opened = await handle.stat();
      // Bind the bytes we are about to scan to the exact file the pre-open
      // lstat classified. openNoFollow can fall back to a following open where
      // O_NOFOLLOW is unavailable (Windows / some filesystems), so a path — or
      // a parent directory — swapped between the lstat above and this open
      // could otherwise redirect the read to a different, clean file and
      // silently miss a real suppression. Reject a device/inode mismatch or an
      // unusable (ino===0) identity as a scan-error and skip, exactly as
      // readCloseoutConfig binds its config read (pr_closeout.js).
      if (!isSameFileIdentity(stats, opened)) {
        findings.push({
          file,
          line: 0,
          category: 'scan-error',
          match: 'Touched file identity changed between check and open; refusing to scan a possibly-swapped file.',
        });
        continue;
      }
      if (!opened.isFile()) {
        findings.push({ file, line: 0, category: 'scan-error', match: 'Touched path is not a regular file; refusing to read.' });
        continue;
      }
      if (opened.size > MAX_SUPPRESSION_SCAN_BYTES) {
        findings.push({
          file,
          line: 0,
          category: 'scan-error',
          match: `Touched file exceeds suppression scan limit (${opened.size} > ${MAX_SUPPRESSION_SCAN_BYTES} bytes).`,
        });
        continue;
      }
      // Sample the first bytes for a NUL to detect binary files; scanning
      // them as text via decodeTouchedText already throws on NUL but we want
      // a clean scan-error finding instead of letting the throw bubble.
      // UTF-16 files start with a BOM (FF FE or FE FF) and contain NUL bytes
      // legitimately, so do not flag those as binary.
      if (opened.size > 0) {
        const head = await readHeadFromHandle(handle, Math.min(BINARY_SAMPLE_BYTES, opened.size));
        const isUtf16Bom = head.length >= 2 && (
          (head[0] === 0xff && head[1] === 0xfe) || (head[0] === 0xfe && head[1] === 0xff)
        );
        if (!isUtf16Bom && head.includes(0)) {
          findings.push({ file, line: 0, category: 'scan-error', match: 'Touched file appears to be binary (NUL byte detected).' });
          continue;
        }
      }
      // Bound the read to the re-stated size so a concurrent grow during
      // readFile cannot force an unbounded buffer allocation. A short read
      // (file shrunk/replaced mid-loop) must fail closed as scan-error so a
      // concurrent writer cannot hide a marker in the unread tail (Codex
      // #4782132804).
      const bytes = Buffer.alloc(opened.size);
      let offset = 0;
      while (offset < opened.size) {
        const { bytesRead } = await handle.read(bytes, offset, opened.size - offset, offset);
        if (bytesRead === 0) break;
        offset += bytesRead;
      }
      if (offset !== opened.size) {
        findings.push({
          file,
          line: 0,
          category: 'scan-error',
          match: `Touched file short-read during suppression scan (${offset}/${opened.size} bytes).`,
        });
        continue;
      }
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
 *
 * Opens with openNoFollow and re-checks the descriptor is still a regular
 * file before streaming, so a TOCTOU replacement of the path with a symlink
 * or FIFO between lstat (in hashFsEntry) and open cannot redirect the read
 * outside the repository or hang on a non-file.
 * @param {string} absolute - Absolute filesystem path to a regular file.
 * @returns {Promise<string>} Hex-encoded SHA-256 digest of the file's contents.
 */
const hashFile = async (absolute) => {
  const handle = await openNoFollow(absolute);
  try {
    const stats = await handle.stat();
    if (!stats.isFile()) {
      throw new Error(`hashFile target is not a regular file after open: ${absolute}`);
    }
    const hash = createHash('sha256');
    const stream = handle.createReadStream();
    for await (const chunk of stream) hash.update(chunk);
    return hash.digest('hex');
  } finally {
    await handle.close().catch(() => {});
  }
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
    // Include permission bits so ignored generated artifacts cannot flip
    // executable/mode without breaking the repository seal fingerprint.
    const content = await hashFile(absolute);
    return hashBytes(`regular:mode=${info.mode & 0o777}:sha=${content}`);
  } catch (error) {
    // The file can disappear between lstat() and openNoFollow(); treat that
    // the same as the lstat ENOENT case (a stable `missing` hash) so a
    // transiently-gone untracked entry cannot reject out of
    // workingTreeFingerprint and abort runCloseoutWorkflow before the
    // structured evidence report is written. ELOOP means a symlink won the
    // race; treat it like a symlink entry rather than following.
    if (error.code === 'ENOENT') return hashBytes('missing');
    if (error.code === 'ELOOP' || error.code === 'EMLINK') {
      try {
        return hashBytes(`symlink:${await readlink(absolute)}`);
      } catch {
        return hashBytes('missing');
      }
    }
    throw error;
  }
};

/**
 * Hash a path Git consults as an excludes/ignore file. Unlike hashFsEntry
 * (which deliberately does not follow symlinks for untracked seals), Git
 * follows `core.excludesFile` / global excludes / XDG ignore paths and uses
 * the target file's contents. Seal both the link identity (if any) and the
 * followed regular-file material so rewriting the target cannot hide
 * untracked files without moving the repository seal fingerprint.
 * @param {string} absolute
 * @returns {Promise<string>}
 */
const hashGitExcludePath = async (absolute) => {
  let info;
  try {
    info = await lstat(absolute);
  } catch (error) {
    if (error.code === 'ENOENT') return hashBytes('missing');
    throw error;
  }
  if (info.isSymbolicLink()) {
    // TOCTOU: the symlink can vanish between lstat and readlink. Fail closed
    // with the same stable "missing" marker as a vanished path, not an
    // uncaught throw that aborts the whole fingerprint step.
    let target;
    try {
      target = await readlink(absolute);
    } catch (error) {
      if (error.code === 'ENOENT') return hashBytes('missing');
      throw error;
    }
    let followed = 'missing';
    try {
      // realpath follows the symlink chain to the final path Git would read.
      const resolved = await realpath(absolute);
      followed = await hashFsEntry(resolved);
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        // Broken link or non-file target: still seal the link text.
        followed = `unresolved:${error?.code || error?.message || error}`;
      }
    }
    return hashBytes(`symlink:${target}\0followed:${followed}`);
  }
  return hashFsEntry(absolute);
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

// Cap the node_modules structural walk so a pathological or maliciously huge
// vendor tree cannot make the seal unbounded. Realistic node_modules trees
// (even large monorepos with a pnpm store) fall well under this. A tree that
// exceeds the cap FAILS CLOSED (structuralDigest throws) rather than sealing a
// truncated prefix: a silently-truncated digest stays identical across
// checkpoints for an already-oversized tree, so a dependency added, removed, or
// modified past the deterministic cutoff would be invisible at every seal point
// while the next validation command still executes it (Codex UnKZ0 / Qodo
// UmhWL). Each entry costs one lstat (no content read), so the walk is cheap
// relative to content-hashing the tree.
const MAX_STRUCTURAL_DIGEST_ENTRIES = 200_000;

// Bound the discovery walk that locates every node_modules root (repo-root and
// nested workspace roots) so a pathologically deep source tree cannot make the
// discovery itself unbounded. The walk never descends INTO a node_modules tree
// (structuralDigest covers that subtree), so this only limits non-vendor depth.
const MAX_NODE_MODULES_DISCOVERY_DEPTH = 40;

/**
 * Compute a bounded STRUCTURAL digest of a directory tree (a vendor tree such
 * as node_modules, or a conventional generated/build output directory such as
 * dist — both findNodeModulesRoots and findGeneratedDirRoots below feed roots
 * through the same function) without reading any file contents. Recursively
 * walks `requested` in deterministic sorted order and folds each entry's
 * repo-relative path plus its kind and cheap metadata into a single SHA-256:
 * a regular file contributes its
 * size + mtimeMs + ctimeMs + permission bits, a symlink its (un-followed)
 * target text, and a directory or any non-regular entry a fixed marker.
 * ctimeMs (inode change time) is sealed alongside mtime because a same-length
 * in-place content rewrite that restores the original mtime (touch -r / cp -p)
 * leaves size + mtime + mode identical, yet both the write and the mtime
 * restoration bump ctime, which no user-facing API can reset (Codex UnKZx).
 * This catches any
 * mutation, addition, or removal under the tree — an edited file's size or
 * mtime moves, an added or removed file changes the listing — at the cost of
 * one lstat per entry instead of a full content hash of tens of thousands of
 * vendor files. cleanTreeStatus and the tracked-diff hash are both blind to
 * node_modules (git ignores it and the ignored-untracked listing pathspec-
 * excludes it), so this is the only channel that notices a dependency swapped
 * in for the next validation command to execute (finding UkNEm/UkTG5).
 *
 * Returns null when the root does not exist, so an absent node_modules
 * contributes no fingerprint entry at all; its later creation still moves the
 * seal by making the entry appear. The walk never follows a symlink and never
 * opens a file, so it cannot hang on a FIFO or read outside the repository. A
 * child that vanishes between readdir and lstat is skipped: a genuine
 * cross-checkpoint deletion is still caught because the earlier walk folded
 * that file's real metadata into the digest and the later walk no longer
 * lists it.
 * @param {string} repo - Absolute repository path.
 * @param {string} requested - Repo-relative tree root (e.g. 'node_modules' or 'dist').
 * @param {number} [maxEntries=MAX_STRUCTURAL_DIGEST_ENTRIES] - Entry cap; exceeding it fails closed (throws). Injectable so the truncation path is testable without a 200k-entry tree.
 * @returns {Promise<string|null>} Composite structural digest, or null if the root is absent.
 * @throws {Error} If the walk exceeds `maxEntries` (the tree cannot be fully sealed).
 */
const structuralDigest = async (repo, requested, maxEntries = MAX_STRUCTURAL_DIGEST_ENTRIES) => {
  const root = resolveExtraPath(repo, requested);
  let rootInfo;
  try {
    rootInfo = await lstat(root.absolute);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
  const hash = createHash('sha256');
  let count = 0;
  const record = (line) => hash.update(`${line}\n`);
  const visit = async ({ absolute, relative }, info) => {
    // Fail closed when the walk would exceed the cap. Silently returning a
    // truncated-prefix digest lets a dependency added, removed, or modified
    // past the deterministic cutoff stay invisible at every checkpoint while
    // producing an identical digest for an already-oversized tree, so the seal
    // cannot honestly attest the whole tree is unchanged (Codex UnKZ0 / Qodo
    // UmhWL). A blocking error is the only correct result when the tree is too
    // large to seal in full.
    if (count >= maxEntries) {
      throw new Error(
        `structural walk exceeded ${maxEntries} entries at '${root.relative}'; cannot fully seal this tree (fail closed).`,
      );
    }
    count += 1;
    if (info.isSymbolicLink()) {
      let target;
      try {
        target = await readlink(absolute);
      } catch {
        target = '__unreadable_link__';
      }
      record(`${relative}\0symlink:${target}`);
      return;
    }
    if (info.isDirectory()) {
      record(`${relative}\0dir`);
      let children;
      try {
        children = (await readdir(absolute)).sort();
      } catch (error) {
        // A directory that becomes unreadable mid-walk is fail-closed as a
        // marker rather than aborting the whole fingerprint step.
        record(`${relative}\0dir_unreadable:${error.code || error.message}`);
        return;
      }
      for (const child of children) {
        const childAbsolute = path.join(absolute, child);
        const childRelative = normalize(path.join(relative, child));
        let childInfo;
        try {
          childInfo = await lstat(childAbsolute);
        } catch (error) {
          if (error.code === 'ENOENT') continue;
          throw error;
        }
        await visit({ absolute: childAbsolute, relative: childRelative }, childInfo);
      }
      return;
    }
    if (info.isFile()) {
      record(`${relative}\0size=${info.size}\0mtime=${info.mtimeMs}\0ctime=${info.ctimeMs}\0mode=${info.mode & 0o777}`);
      return;
    }
    // FIFO/socket/device: record its kind without opening it.
    record(`${relative}\0non-regular`);
  };
  await visit({ absolute: root.absolute, relative: root.relative }, rootInfo);
  return hashBytes(`structural:count=${count}:${hash.digest('hex')}`);
};

/**
 * Discover every node_modules root under the repo — the repo-root tree AND
 * nested workspace roots such as `packages/api/node_modules` — so
 * workingTreeFingerprint can structurally seal each one. The ignored-untracked
 * listing pathspec-excludes every nested node_modules tree and a repo-root-only
 * structural digest never reaches a package-local dependency, so without
 * discovering nested roots a mutation under a workspace package is invisible to
 * the seal (Codex Ummso). The walk skips `.git` and conventional generated
 * build output (`dist`, `build`, `coverage`, `.next`, `.cache`): those
 * directories are separately discovered and structurally sealed IN FULL by
 * findGeneratedDirRoots below — which also covers any node_modules a build
 * leaves nested underneath one of them, since this walk would otherwise never
 * reach it either (Qodo UplSv) — so skipping them here avoids redundantly
 * re-walking bytes findGeneratedDirRoots already seals, rather than leaving
 * them unsealed (CodeRabbit UohnW's original "nothing to gain by descending"
 * rationale no longer holds now that a sibling mechanism seals this content
 * instead). The walk never follows a symlink (a symlinked directory is not
 * `isDirectory()` in a Dirent, so it is left for the un-followed symlink
 * handling elsewhere), and does NOT descend into a found node_modules
 * (structuralDigest already covers that subtree, including any node_modules
 * nested within it) — bounding cost to the non-vendor source tree.
 * @param {string} repo - Absolute repository path.
 * @returns {Promise<string[]>} Sorted repo-relative node_modules root paths (may be empty).
 */
// Directories that never contain a workspace's own node_modules root worth
// discovering here (either VCS internals, or conventional generated build
// output that findGeneratedDirRoots below discovers and structurally seals
// separately, in full) — skip descending into them so discovery cost stays
// proportional to the actual source tree and this walk never redundantly
// re-covers bytes the other one already seals.
const DISCOVERY_SKIP_DIRS = new Set(['.git', 'dist', 'build', 'coverage', '.next', '.cache']);

const findNodeModulesRoots = async (repo) => {
  const roots = [];
  const walk = async (absoluteDir, relativeDir, depth) => {
    if (depth > MAX_NODE_MODULES_DISCOVERY_DEPTH) return;
    let dirents;
    try {
      dirents = await readdir(absoluteDir, { withFileTypes: true });
    } catch {
      // An unreadable directory contributes no roots; a genuinely present
      // node_modules elsewhere is still discovered independently.
      return;
    }
    for (const dirent of dirents) {
      if (!dirent.isDirectory()) continue;
      if (DISCOVERY_SKIP_DIRS.has(dirent.name)) continue;
      const childRelative = relativeDir ? `${relativeDir}/${dirent.name}` : dirent.name;
      if (dirent.name === 'node_modules') {
        roots.push(childRelative);
        // Do not descend: structuralDigest walks the whole subtree, including
        // any node_modules nested inside this one.
        continue;
      }
      await walk(path.join(absoluteDir, dirent.name), childRelative, depth + 1);
    }
  };
  await walk(repo, '', 0);
  return roots.sort();
};

// Conventional generated/build output directory basenames. When one of these
// is gitignored (a near-universal convention), the ignoredBulkExcludes
// pathspec below pathspec-excludes its ENTIRE contents from the per-file
// ignored-untracked seal with no alternate digest, so a validation command can
// rewrite e.g. dist/result.js and leave every fingerprint identical unless the
// operator manually lists that directory in reproducibilityPaths (Codex
// Uonlg). Structurally sealing every occurrence of these directories the same
// bounded way a node_modules root is sealed also covers any executable
// node_modules tree a build leaves nested underneath one of them (a
// standalone bundle's own vendored copy, a coverage fixture's own install,
// ...), which findNodeModulesRoots above never finds since it does not
// descend into these directories either (Qodo UplSv). One digest over each
// root's whole subtree closes both gaps without a second, redundant walk into
// the same bytes.
const SEALED_GENERATED_DIR_NAMES = new Set(['dist', 'build', 'coverage', '.next', '.cache']);

/**
 * Discover every occurrence of a conventional generated/build output
 * directory (SEALED_GENERATED_DIR_NAMES) under the repo, the same way
 * findNodeModulesRoots discovers node_modules roots, so workingTreeFingerprint
 * can structurally seal each one in full (Codex Uonlg / Qodo UplSv). Skips
 * `.git`; never descends into `node_modules` (already fully, separately
 * sealed by findNodeModulesRoots/structuralDigest — redescending here would
 * only relabel the same bytes as an extra root for every "dist"/"build"
 * folder a vendored package happens to ship in its own published output); and
 * does not descend into an already-discovered generated-dir root
 * (structuralDigest walks that root's whole subtree, including anything
 * nested inside it, so recursing further during discovery would only find
 * redundant nested roots covered twice). Never follows a symlink, for the
 * same reason findNodeModulesRoots does not.
 * @param {string} repo - Absolute repository path.
 * @returns {Promise<string[]>} Sorted repo-relative generated-dir root paths (may be empty).
 */
const findGeneratedDirRoots = async (repo) => {
  const roots = [];
  const walk = async (absoluteDir, relativeDir, depth) => {
    if (depth > MAX_NODE_MODULES_DISCOVERY_DEPTH) return;
    let dirents;
    try {
      dirents = await readdir(absoluteDir, { withFileTypes: true });
    } catch {
      // An unreadable directory contributes no roots; a genuinely present
      // generated directory elsewhere is still discovered independently.
      return;
    }
    for (const dirent of dirents) {
      if (!dirent.isDirectory()) continue;
      if (dirent.name === '.git' || dirent.name === 'node_modules') continue;
      const childRelative = relativeDir ? `${relativeDir}/${dirent.name}` : dirent.name;
      if (SEALED_GENERATED_DIR_NAMES.has(dirent.name)) {
        roots.push(childRelative);
        // Do not descend: structuralDigest walks the whole subtree, including
        // any node_modules or nested generated directory inside this one.
        continue;
      }
      await walk(path.join(absoluteDir, dirent.name), childRelative, depth + 1);
    }
  };
  await walk(repo, '', 0);
  return roots.sort();
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
const hashGitOutput = async (repo, args) => {
  const safeArgs = await withInternalGitSafety(repo, args);
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const child = spawn('git', safeArgs, {
      cwd: repo,
      env: gitChildEnv(),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
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
};

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
 * (via hashFsEntry); a bounded STRUCTURAL digest of every node_modules root —
 * repo-root and nested workspace roots (path + size + mtime + ctime + mode, not
 * contents, via structuralDigest/findNodeModulesRoots) so a mutated, added, or
 * removed dependency the next validation command would execute cannot escape
 * the seal even though git ignores the vendor tree; the same STRUCTURAL digest
 * over every conventional generated/build directory anywhere in the tree (via
 * structuralDigest/findGeneratedDirRoots) so gitignoring dist/build/coverage/
 * .next/.cache — which pathspec-excludes their contents from the
 * ignored-untracked channel below — cannot hide a rewritten build artifact or
 * a node_modules nested underneath one of them either; and any caller-supplied
 * `extraPaths` (via collectExtraEntries). All entries are handed to
 * fingerprintEntries, which sorts by path before hashing so entry-collection
 * order never affects the result.
 * @param {string} repo - Absolute repository path.
 * @param {string[]} [extraPaths] - Additional repo-relative paths (files or directories) to fold into the seal.
 * @param {object} [overrides] - Test-only seam; defaults to the real `gitPaths` call.
 * @param {typeof gitPaths} [overrides.listIgnoredUntracked] - Overrides the ignored-untracked git listing.
 * @returns {Promise<string>} Hex-encoded SHA-256 composite fingerprint.
 */
const workingTreeFingerprint = async (
  repo,
  extraPaths = [],
  { listIgnoredUntracked = gitPaths, maxStructuralDigestEntries = MAX_STRUCTURAL_DIGEST_ENTRIES } = {},
) => {
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
  entries.push({ path: '__git_info_exclude__', hash: await hashGitExcludePath(excludePath) });
  // Seal core.excludesFile: --exclude-standard honors that path for untracked
  // discovery, so mutating it can hide files without changing info/exclude.
  // When the configured path is a symlink, Git follows it — hash both the
  // link identity and the followed contents (hashGitExcludePath).
  try {
    const excludesFile = await gitText(repo, ['config', '--get', 'core.excludesFile']);
    const resolved = excludesFile ? expandGitPathname(excludesFile, repo) : '';
    entries.push({
      path: '__git_core_excludesFile__',
      hash: resolved
        ? hashBytes(`path:${resolved}\0${await hashGitExcludePath(resolved)}`)
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
      globalExcludeParts.push(`globalCore:${resolved}\0${await hashGitExcludePath(resolved)}`);
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
  globalExcludeParts.push(`xdg:${xdgIgnore}\0${await hashGitExcludePath(xdgIgnore)}`);
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
  // Seal ignored untracked inputs (e.g. a gitignored `.env` created mid-run)
  // that `--exclude-standard` omits from the list above. Without this, a
  // validation command can create ignored inputs later checks consume while
  // initial/final fingerprints stay identical (Codex #4781560042). Bulk vendor
  // trees are pathspec-excluded so node_modules does not explode the seal.
  const ignoredBulkExcludes = [
    ':(exclude)node_modules',
    ':(exclude)**/node_modules/**',
    ':(exclude).git',
    ':(exclude)**/.git/**',
    ':(exclude)dist',
    ':(exclude)**/dist/**',
    ':(exclude)build',
    ':(exclude)**/build/**',
    ':(exclude)coverage',
    ':(exclude)**/coverage/**',
    ':(exclude).next',
    ':(exclude)**/.next/**',
    ':(exclude)**/.pnpm/**',
    ':(exclude)**/.cache/**',
  ];
  let ignoredUntracked;
  try {
    ignoredUntracked = await listIgnoredUntracked(repo, [
      'ls-files',
      '--others',
      '--ignored',
      '--exclude-standard',
      '-z',
      '--',
      '.',
      ...ignoredBulkExcludes,
    ]);
  } catch (error) {
    // A constant placeholder hash here would contribute the same value to
    // every fingerprint regardless of what actually changed, so a listing
    // that keeps failing the same way before and after a validation command
    // would hide a mid-run change to an ignored file completely -- the
    // opposite of failing closed (Codex Ukpkr). Fail the whole fingerprint
    // instead of masking the gap with a marker that never varies.
    throw new Error(`Failed to list ignored untracked files in ${repo}: ${error.message}`, { cause: error });
  }
  // Hoist once: spreading a Set per ignored file was O(n*m) allocations
  // (CodeRabbit #4781622077).
  const extraPrefixes = [...new Set(extraPaths.map((p) => String(p).replaceAll('\\', '/')))];
  for (const file of ignoredUntracked) {
    const normalized = String(file).replaceAll('\\', '/');
    // extraPaths (permitted generator outputs) are hashed via collectExtraEntries.
    if (extraPrefixes.some((extra) => normalized === extra || normalized.startsWith(`${extra}/`))) {
      continue;
    }
    const absolute = path.join(repo, file);
    entries.push({ path: `__ignored__/${normalized}`, hash: await hashFsEntry(absolute) });
  }
  // Structurally seal every node_modules root — the repo-root tree AND nested
  // workspace roots like packages/api/node_modules (a listing of path + size +
  // mtime + ctime + mode, NOT file contents) so a validation command that
  // mutates, adds, or removes a dependency between seal points moves the
  // fingerprint. git ignores node_modules and the ignored-untracked listing
  // above pathspec-excludes every nested node_modules tree, so without this
  // channel a swapped-in dependency the next validation step then executes
  // would leave every seal identical (findings UkNEm/UkTG5). A repo-root-only
  // digest would miss a package-local dependency mutation under a workspace
  // package (finding Ummso), so all roots are discovered and hashed.
  // Content-hashing the whole vendor tree would be far too slow; the structural
  // listing catches the same mutations at one lstat per entry. An absent
  // node_modules contributes no entry (structuralDigest returns null); its
  // later creation still moves the seal by making the entry appear.
  const nodeModulesRoots = await findNodeModulesRoots(repo);
  for (const nodeModulesRoot of nodeModulesRoots) {
    const digest = await structuralDigest(repo, nodeModulesRoot, maxStructuralDigestEntries);
    if (digest !== null) {
      entries.push({ path: `__node_modules_structural__/${nodeModulesRoot}`, hash: digest });
    }
  }
  // Structurally seal every conventional generated/build directory
  // (SEALED_GENERATED_DIR_NAMES) discovered anywhere in the tree, the same
  // bounded, content-free digest a node_modules root gets above. Gitignoring
  // one of these directories (dist/build/coverage/.next/.cache) pathspec-
  // excludes its entire contents from the ignored-untracked per-file seal
  // above with no alternate digest, so a validation command rewriting e.g.
  // dist/result.js would otherwise leave every fingerprint identical (Codex
  // Uonlg). This also covers any node_modules a build leaves nested
  // underneath one of these directories, which the node_modules discovery
  // above never finds since it does not descend into them either (Qodo
  // UplSv). An absent directory contributes no entry, exactly like an absent
  // node_modules; its later creation still moves the seal.
  const generatedDirRoots = await findGeneratedDirRoots(repo);
  for (const generatedDirRoot of generatedDirRoots) {
    const digest = await structuralDigest(repo, generatedDirRoot, maxStructuralDigestEntries);
    if (digest !== null) {
      entries.push({ path: `__generated_dir_structural__/${generatedDirRoot}`, hash: digest });
    }
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
 * @returns {Promise<{changedFiles: string[], addedLines: string[], removedLines: string[], deletedFiles: string[], proseAddedLines: string[]}>}
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
  if (!changedFiles.length) return { changedFiles, addedLines: [], removedLines: [], deletedFiles, proseAddedLines: [] };
  const tracked = changedFiles.filter((file) => !untracked.includes(file));
  // .codereview.yml/.codereview.yaml is this repo's declarative, non-executable
  // gate config: prose describing a check (e.g. "an existing target without
  // --force") can legitimately name a bypass flag without using it. Added
  // lines sourced from it are tagged separately so classifyGateIntegrity can
  // exempt them from the executable-invocation weakening scan while every
  // other gate file (workflows, package.json, lockfiles, ...) stays fully
  // scanned; see classifyGateIntegrity for how this is consumed.
  const isProseGateFile = (file) => /^\.codereview\.ya?ml$/i.test(path.posix.basename(normalize(file)));
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
      // --no-textconv: a configured textconv filter must not rewrite deleted
      // validation lines before classifyGateIntegrity scans removals.
      diff = await gitText(repo, ['diff', '--unified=0', '--no-ext-diff', '--no-textconv', baseSha, '--', ...tracked]);
    } catch (error) {
      trackedDiffError = error;
    }
  }
  const diffLines = trackedDiffError ? [] : diff.split(/\r?\n/);
  const addedLines = trackedDiffError
    ? [`+__decode_error__:${tracked.join(',')}:diff_buffer_exceeded:${trackedDiffError?.code || trackedDiffError?.message || trackedDiffError}`]
    : diffLines.filter((line) => line.startsWith('+') && !line.startsWith('+++'));
  // Removed lines from still-present gate files (in-place step deletion).
  const removedLines = trackedDiffError
    ? []
    // Diff file headers are `--- a/path` / `--- /dev/null`. A removed source
    // line such as `--coverage` becomes `---coverage` and must still scan
    // (CodeRabbit #4781622077).
    : diffLines.filter((line) => line.startsWith('-') && !/^--- (?:a\/|b\/|\/dev\/null)/.test(line));
  // Walk the same combined diff already fetched above (no second `git diff`)
  // to pull out just the added lines that belong to a prose gate file's
  // hunks. `+++ b/<path>` always precedes that file's content lines in a
  // multi-file unified diff and git diff paths always use `/`, so no
  // per-OS normalization is needed here the way `isProseGateFile` needs it
  // for untracked-file paths below.
  const proseAddedLines = [];
  if (!trackedDiffError) {
    let inProseGateFile = false;
    let inHunk = false;
    for (const line of diffLines) {
      // A `+++ b/<path>` file header always precedes the first `@@` hunk for
      // that file. Under --unified=0 an ADDED source line whose content is
      // literally `++ b/.codereview.yml` is emitted as `+++ b/.codereview.yml`
      // INSIDE the hunk; treating that as a header would flip inProseGateFile
      // on and wrongly exempt the rest of an unrelated (non-prose) gate file's
      // added lines from the weakening scan (CodeRabbit UmlJc). Track hunk
      // state — reset on each `diff --git`, enter on `@@` — and only accept a
      // `+++` header when outside a hunk.
      if (line.startsWith('diff --git ')) {
        inHunk = false;
        inProseGateFile = false;
        continue;
      }
      if (line.startsWith('@@')) {
        inHunk = true;
        continue;
      }
      const fileHeader = inHunk ? null : /^\+\+\+ b\/(.+)$/.exec(line);
      if (fileHeader) {
        inProseGateFile = /^\.codereview\.ya?ml$/i.test(path.posix.basename(fileHeader[1]));
        continue;
      }
      if (inProseGateFile && line.startsWith('+') && !line.startsWith('+++')) {
        proseAddedLines.push(line);
      }
    }
  }
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
      // Re-stat the opened descriptor and read at most that size so a
      // concurrent grow after the pre-open lstat cannot bypass the 5 MiB
      // cap via unbounded handle.readFile() (Codex #4781495663).
      const opened = await handle.stat();
      if (!opened.isFile()) {
        addedLines.push(`+__decode_error__:${file}:non_regular_file`);
        continue;
      }
      if (opened.size > MAX_SUPPRESSION_SCAN_BYTES) {
        addedLines.push(`+__decode_error__:${file}:exceeds_scan_limit`);
        continue;
      }
      const bytes = Buffer.alloc(opened.size);
      let offset = 0;
      while (offset < opened.size) {
        const { bytesRead } = await handle.read(bytes, offset, opened.size - offset, offset);
        if (bytesRead === 0) break;
        offset += bytesRead;
      }
      // Short reads (file shrunk between stat and read) must fail closed with
      // the same decode-error marker as other incomplete reads — a truncated
      // prefix would hide weakening past the cut (CodeRabbit #4781622077).
      if (offset < opened.size) {
        addedLines.push(`+__decode_error__:${file}:short_read:${offset}/${opened.size}`);
        continue;
      }
      const text = decodeTouchedText(bytes);
      const isProse = isProseGateFile(file);
      for (const line of text.split(/\r?\n/)) {
        const added = `+${line}`;
        addedLines.push(added);
        if (isProse) proseAddedLines.push(added);
      }
    } catch (error) {
      addedLines.push(`+__decode_error__:${file}:${error.message}`);
    } finally {
      if (handle) await handle.close().catch(() => {});
    }
  }
  return { changedFiles, addedLines, removedLines, deletedFiles, proseAddedLines };
};

module.exports = {
  cleanTreeStatus,
  decodeTouchedText,
  gitChildEnv,
  normalize,
  readGateChanges,
  readProjectMetadata,
  resolveRepositoryState,
  scanTouchedSuppressions,
  withNoTextconv,
  workingTreeFingerprint,
};
