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

// Package-manifest descriptive fields carry no validation semantics: a routine
// value edit (`"version": "1.2.3"` -> `"1.2.4"`, a reworded `"description"`,
// ...) removes the old line but weakens no gate, yet the fail-closed
// content-removal catch-all would flag every such removed line and fail CI.
// Treat a same-field value replacement as a safe modification. This is
// deliberately an ALLOWLIST (fail closed): any key NOT listed keeps failing
// exactly as before, so a lowered coverage threshold, a replaced smoke/verify
// step, a dependency edit, or any other non-metadata removal is never exempted.
const SAFE_METADATA_KEY = /^["']?(version|description|author|license|homepage|repository|bugs|funding|keywords|contributors|maintainers)["']?\s*[:=]/i;

// The same descriptive key name (e.g. `version`) can carry real validation
// semantics in a gate-POLICY file -- a `.codereview.yml` `version:` schema
// field -- even though it is purely cosmetic in an actual package manifest.
// isSafeMetadataReplacement must therefore know which file a hunk belongs to,
// not just the key, or a policy-file weakening disguised as a metadata bump
// slips through (Codex UnKZ7).
const PACKAGE_MANIFEST_BASENAMES = new Set(['package.json', 'pyproject.toml', 'cargo.toml', 'composer.json']);

/**
 * True when `filePath`'s basename is a recognized package-manifest file
 * (case-insensitive) -- one where SAFE_METADATA_KEY's descriptive fields are
 * known to carry no validation semantics.
 * @param {string} filePath
 * @returns {boolean}
 */
const isPackageManifestFile = (filePath) => PACKAGE_MANIFEST_BASENAMES.has(path.posix.basename(filePath || '').toLowerCase());

/**
 * Extract the leading allowlisted descriptive-metadata key from a trimmed diff
 * line body (`"version": "1.2.3",` -> `version`), or null when the line is not
 * a single-field descriptive edit.
 * @param {string} body diff line with the leading +/- stripped and trimmed
 * @returns {string|null}
 */
const metadataKey = (body) => {
  const match = SAFE_METADATA_KEY.exec(body);
  return match ? match[1].toLowerCase() : null;
};

/**
 * True when a removed gate line and its same-position replacement are a value-
 * only edit of the SAME descriptive-metadata field in an actual package
 * manifest (a benign modification, not a validation removal). Fails closed:
 * requires `currentFile` to be a recognized package manifest (Codex UnKZ7 --
 * without this check, the same key name in a gate-POLICY file such as
 * `.codereview.yml` would be wrongly treated as cosmetic), requires both
 * sides to resolve to the same allowlisted key, and reuses
 * VALIDATION_REMOVAL_PATTERNS so a descriptive value that smuggles a
 * validation command (`"description": "run npm test"`), or a replacement
 * that itself reads as a removed validation line, still fails. A pure
 * deletion (no replacement) is never routed here.
 * @param {string} removedLine unified-diff line starting with `-`
 * @param {string} addedLine unified-diff line starting with `+`
 * @param {string} currentFile repo-relative path the pair belongs to
 * @returns {boolean}
 */
const isSafeMetadataReplacement = (removedLine, addedLine, currentFile) => {
  if (!isPackageManifestFile(currentFile)) return false;
  const removedKey = metadataKey(removedLine.slice(1).trim());
  const addedKey = metadataKey(addedLine.slice(1).trim());
  if (!removedKey || removedKey !== addedKey) return false;
  // Re-anchor the added line as a removal so the `^\-`-anchored validation
  // patterns can test whether the replacement itself reads as validation.
  const addedAsRemoval = `-${addedLine.slice(1)}`;
  if (VALIDATION_REMOVAL_PATTERNS.some((pattern) => pattern.test(removedLine))) return false;
  if (VALIDATION_REMOVAL_PATTERNS.some((pattern) => pattern.test(addedAsRemoval))) return false;
  return true;
};

// Keys that name or imply a validation/security surface. A same-key value
// replacement is only ever admitted below when the key clears this check, so
// a script or dependency whose name itself suggests it validates something
// stays fail-closed even when its new value doesn't (yet) match
// VALIDATION_REMOVAL_PATTERNS. Word-boundary matching so e.g. `eslint` (a
// devDependency name) does not collide with the `lint` keyword.
const VALIDATION_KEY_HINT = /\b(?:test|lint|audit|validate|typecheck|coverage|verify|check|scan|smoke|health[-_]?check|doctor|build|security|codeql|ci)\b/i;

/**
 * Extract the quoted JSON key from a trimmed package.json diff line body
 * (`"lodash": "^4.17.20",` -> `lodash`), or null when the line is not a
 * single quoted `"key": value` field. Quotes are required (unlike
 * `metadataKey` above, which also accepts YAML's unquoted `key:` form)
 * because this is only ever invoked on package.json content, which is pure
 * JSON.
 * @param {string} body diff line with the leading +/- stripped and trimmed
 * @returns {string|null}
 */
const jsonFieldKey = (body) => {
  const match = /^"([^"]+)"\s*:/.exec(body);
  return match ? match[1].toLowerCase() : null;
};

// jsonFieldKey alone matches ANY `"key":` line regardless of nesting depth, so
// a nested validation-relevant leaf whose key name doesn't hint at validation
// (Jest's `coverageThreshold.global.lines`, `passWithNoTests`) could bypass
// VALIDATION_KEY_HINT purely because the key looked harmless. A real
// dependency/script/override entry is always a complete single-line JSON
// STRING value; it is never a bare number, boolean, null, or an object/array
// opener. Requiring the value itself to be a fully-quoted JSON string on one
// line rejects those nested non-string validation leaves regardless of what
// their key is named (Codex UnT4H).
const JSON_STRING_FIELD = /^"[^"]+"\s*:\s*"(?:[^"\\]|\\.)*"\s*,?\s*$/;

/**
 * True when a trimmed package.json diff line body is a complete single-line
 * `"key": "value"` field: a quoted key followed by a fully-quoted JSON string
 * value (optional trailing comma). False for numbers, booleans, null, and
 * object/array-opening lines.
 * @param {string} body diff line with the leading +/- stripped and trimmed
 * @returns {boolean}
 */
const isJsonStringField = (body) => JSON_STRING_FIELD.test(body);

/**
 * True when a removed/added pair is a same-key package.json value edit (a
 * dependency version bump, a non-validation script's command, ...) whose key
 * does not itself name a validation surface. Deliberately scoped to
 * `package.json` only: there the key IS the change's identity (`npm run
 * <key>` is what actually executes a script; a dependency's name is unique
 * per key), so a harmless-sounding key genuinely means a harmless change.
 * That does NOT generalize to e.g. a workflow step, where `run:`/`uses:` are
 * fixed keys shared by every step regardless of what it does -- see
 * isSafeWorkflowStepNameReplacement / isSafeActionPinReplacement below for
 * the (differently-shaped) safe cases there. Fails closed: requires both
 * sides to be a complete single-line JSON STRING field (so a nested
 * non-string validation leaf can never qualify merely because its key clears
 * the hint check, Codex UnT4H), requires the same key on both sides, that key
 * to clear VALIDATION_KEY_HINT, and reuses VALIDATION_REMOVAL_PATTERNS so a
 * value that smuggles a validation command under a harmless-looking key still
 * fails (Codex UkAe8, UguCZ).
 * @param {string} removedLine unified-diff line starting with `-`
 * @param {string} addedLine unified-diff line starting with `+`
 * @param {string} currentFile repo-relative path the pair belongs to
 * @returns {boolean}
 */
const isSafePackageJsonFieldReplacement = (removedLine, addedLine, currentFile) => {
  if (path.posix.basename(currentFile).toLowerCase() !== 'package.json') return false;
  const removedBody = removedLine.slice(1).trim();
  const addedBody = addedLine.slice(1).trim();
  if (!isJsonStringField(removedBody) || !isJsonStringField(addedBody)) return false;
  const removedKey = jsonFieldKey(removedBody);
  const addedKey = jsonFieldKey(addedBody);
  if (!removedKey || removedKey !== addedKey) return false;
  if (VALIDATION_KEY_HINT.test(removedKey)) return false;
  const addedAsRemoval = `-${addedLine.slice(1)}`;
  if (VALIDATION_REMOVAL_PATTERNS.some((pattern) => pattern.test(removedLine))) return false;
  if (VALIDATION_REMOVAL_PATTERNS.some((pattern) => pattern.test(addedAsRemoval))) return false;
  return true;
};

/**
 * True when a removed/added pair are both a workflow/action step's `name:`
 * label (`- name: Build` -> `- name: Compile`). A step name is a pure display
 * label with no execution semantics, so renaming it changes nothing about
 * what runs -- unlike `run:`/`uses:`, which this function never matches and
 * which stay subject to the default fail-closed behavior. Scoped to
 * `.github/workflows/` and `.github/actions/` so this cannot match an
 * unrelated `name:`-shaped line in some other gate file (e.g. a Makefile
 * variable). Still reuses VALIDATION_REMOVAL_PATTERNS so a step already named
 * for a validation purpose (matched upstream by detectValidationRemovals)
 * cannot reach here via a different code path.
 * @param {string} removedLine unified-diff line starting with `-`
 * @param {string} addedLine unified-diff line starting with `+`
 * @param {string} currentFile repo-relative path the pair belongs to
 * @returns {boolean}
 */
const isSafeWorkflowStepNameReplacement = (removedLine, addedLine, currentFile) => {
  if (!currentFile.startsWith('.github/workflows/') && !currentFile.startsWith('.github/actions/')) return false;
  const namePattern = /^[+-]\s*(?:-\s*)?name:\s*.+$/;
  if (!namePattern.test(removedLine) || !namePattern.test(addedLine)) return false;
  const addedAsRemoval = `-${addedLine.slice(1)}`;
  if (VALIDATION_REMOVAL_PATTERNS.some((pattern) => pattern.test(removedLine))) return false;
  if (VALIDATION_REMOVAL_PATTERNS.some((pattern) => pattern.test(addedAsRemoval))) return false;
  return true;
};

/**
 * True when `ref` is a full immutable commit SHA (40-hex SHA-1 or 64-hex
 * SHA-256), the only form GitHub Actions' own pinning guidance treats as
 * immutable. Deliberately stricter than this module's isUsableSha (which also
 * accepts abbreviated git object IDs): an abbreviated SHA is still a mutable
 * lookup as far as this immutability check is concerned.
 * @param {string} ref
 * @returns {boolean}
 */
const isFullActionSha = (ref) => /^[0-9a-f]{40}$|^[0-9a-f]{64}$/i.test(ref);

/**
 * True when a removed/added `uses:` pair pins the SAME action (identical
 * owner/repo[/path] before the `@`) to a different ref/SHA -- a routine pin
 * bump, not a substitution to a different action. The action path, not the
 * fixed `uses` key, is this line's real identity, so this cannot reuse
 * isSafePackageJsonFieldReplacement's same-key check: every `uses:` line
 * shares that key regardless of which action it names, so a same-key check
 * alone would admit a swap to an unrelated (possibly malicious) action.
 * Also rejects a full-SHA pin replaced by anything mutable (a tag, a branch,
 * an abbreviated SHA): that is a supply-chain weakening, not a routine bump,
 * even though the action path is unchanged (Codex UnT4I, UnS2f). Scoped to
 * workflow/action files; still fails closed via VALIDATION_REMOVAL_PATTERNS,
 * so a named security action (codeql-action, trivy-action, ...) is never
 * admitted here either -- it is already caught upstream by
 * detectValidationRemovals before reaching this scan (Codex UkAe8).
 * @param {string} removedLine unified-diff line starting with `-`
 * @param {string} addedLine unified-diff line starting with `+`
 * @param {string} currentFile repo-relative path the pair belongs to
 * @returns {boolean}
 */
const isSafeActionPinReplacement = (removedLine, addedLine, currentFile) => {
  if (!currentFile.startsWith('.github/workflows/') && !currentFile.startsWith('.github/actions/')) return false;
  const usesPattern = /^[+-]\s*(?:-\s*)?uses:\s*([^@\s'"]+)@(\S+?)\s*$/;
  const removedMatch = usesPattern.exec(removedLine);
  const addedMatch = usesPattern.exec(addedLine);
  if (!removedMatch || !addedMatch || removedMatch[1] !== addedMatch[1]) return false;
  if (isFullActionSha(removedMatch[2]) && !isFullActionSha(addedMatch[2])) return false;
  const addedAsRemoval = `-${addedLine.slice(1)}`;
  if (VALIDATION_REMOVAL_PATTERNS.some((pattern) => pattern.test(removedLine))) return false;
  if (VALIDATION_REMOVAL_PATTERNS.some((pattern) => pattern.test(addedAsRemoval))) return false;
  return true;
};

/**
 * Collect substantive removed gate lines from a `--unified=0` diff, pairing
 * each removed (`-`) line with the added (`+`) line at the same position within
 * its hunk. A pure DELETION (no positional replacement) is always collected;
 * a recognized safe replacement (a same-field descriptive value edit, a
 * package.json dependency/script edit, a workflow step rename, or an action
 * pin bump -- see the isSafe* helpers above) is skipped as a benign
 * modification. With `--unified=0` each contiguous change is its own hunk
 * whose removed lines all precede its added lines, so index pairing aligns
 * old<->new; hunk/file boundaries flush the pairing buffers so a removed line
 * never pairs across a hunk, and the current file (tracked from each `+++`
 * header) never leaks a package.json/workflow exemption into a different
 * file's lines. Blank/comment-only removals are ignored exactly as before.
 * @param {string} diff unified diff text (produced with unified=0)
 * @returns {string[]} truncated removed lines that are not safe replacements
 */
const collectContentRemovals = (diff) => {
  const findings = [];
  let removed = [];
  let added = [];
  let currentFile = '';
  const flushHunk = () => {
    for (let i = 0; i < removed.length; i += 1) {
      const line = removed[i];
      const body = line.slice(1).trim();
      // Keep `--coverage` / `--strict` removals: only skip blanks and comments.
      if (!body || body.startsWith('#')) continue;
      const replacement = added[i];
      // A same-position replacement recognized as benign is not a content
      // removal; a pure deletion (undefined) always fails closed.
      if (replacement !== undefined && (
        isSafeMetadataReplacement(line, replacement, currentFile)
        || isSafePackageJsonFieldReplacement(line, replacement, currentFile)
        || isSafeWorkflowStepNameReplacement(line, replacement, currentFile)
        || isSafeActionPinReplacement(line, replacement, currentFile)
      )) continue;
      findings.push(line.slice(0, 200));
    }
    removed = [];
    added = [];
  };
  for (const line of diff.split(/\r?\n/)) {
    if (line.startsWith('+++ ')) {
      flushHunk();
      const filePath = line.slice(4).trim();
      currentFile = filePath === '/dev/null' ? '' : filePath.replace(/^b\//, '');
      continue;
    }
    // Hunk / file boundaries flush the buffers so pairing never spans blocks.
    if (line.startsWith('@@') || isUnifiedDiffFileHeader(line)) {
      flushHunk();
      continue;
    }
    if (line.startsWith('-')) removed.push(line);
    else if (line.startsWith('+')) added.push(line);
  }
  flushHunk();
  return findings;
};

/**
 * Any substantive deleted content in gate files (not blank/comment-only, and
 * not a benign same-field metadata value edit). Used by CI to fail-closed on
 * replacements that neutralize smoke checks without matching
 * VALIDATION_REMOVAL_PATTERNS (Codex #4781495663). A pure line MODIFICATION of
 * an allowlisted descriptive field (e.g. a `package.json` version/description
 * bump) is not a removal; a pure DELETION, a lowered threshold, or any other
 * replacement still fails closed (see collectContentRemovals).
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
  return collectContentRemovals(diff);
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
    // .codereview.yml's added lines are prose (see readGateChanges /
    // classifyGateIntegrity) and can legitimately name a flag like --force
    // while describing a check; without this, classifyGateIntegrity cannot
    // tell that content apart from an executable invocation adding the flag.
    proseAddedLines: gate.proseAddedLines,
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
  collectContentRemovals,
  isSafeMetadataReplacement,
  isSafePackageJsonFieldReplacement,
  isSafeWorkflowStepNameReplacement,
  isSafeActionPinReplacement,
  isMechanicalLockfile,
};
