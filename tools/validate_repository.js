'use strict';

const { readFileSync, readdirSync, lstatSync } = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const payloadEntries = ['SKILL.md', 'agents', 'assets', 'references', 'scripts'];
// Bound validator memory: a pathological payload file should produce a
// deterministic FAIL instead of spiking memory or crashing CI.
const MAX_PAYLOAD_FILE_BYTES = 2 * 1024 * 1024;
const requiredFiles = [
  'SKILL.md',
  'agents/openai.yaml',
  'assets/pr-closeout.config.example.json',
  'references/error-recovery.md',
  'references/pr-closeout-validation.md',
  'scripts/debug_server.js',
  'scripts/pr_closeout.js',
];

// `git ls-files` is the source of truth for what the public repository ships.
// Keep exclusions explicit rather than relying on an incomplete list of roots:
// these local/VCS directories are intentionally neither tracked nor shipped.
const safetyScanExcludedPrefixes = new Map([
  ['.git/', 'Git object and worktree metadata'],
  ['node_modules/', 'locally installed third-party dependencies'],
  ['.tmp/', 'local audit artifacts'],
]);

const failures = [];

/**
 * Recursively walks a required payload entry (file or directory, relative to
 * `root`) and returns the flat list of regular-file paths under it, pushing
 * to the module-level `failures` array instead of throwing for any problem
 * short of an unexpected fs error. Uses `lstatSync` (never `statSync`) so
 * symlinks are detected and rejected rather than followed — a symlinked
 * directory or a symlink cycle would otherwise let `readdirSync` recurse
 * unbounded and hang or escape the payload tree during `npm run validate`.
 * A missing entry or a non-regular file (FIFO/socket/device) is likewise
 * recorded as a failure and excluded from the returned list, never handed to
 * a later `readFileSync`/`node --check` step.
 * @param {string} entry path relative to `root`.
 * @returns {string[]} regular-file paths (relative to `root`) found under `entry`.
 */
const walk = (entry) => {
  const absolute = path.join(root, entry);
  let info;
  try {
    info = lstatSync(absolute);
  } catch (error) {
    if (error.code === 'ENOENT') {
      failures.push(`Required payload entry is missing: ${entry}`);
      return [];
    }
    throw error;
  }
  if (info.isSymbolicLink()) {
    failures.push(`Payload entry must not be a symlink: ${entry}`);
    return [];
  }
  if (info.isDirectory()) {
    return readdirSync(absolute).flatMap((name) => walk(path.join(entry, name)));
  }
  if (info.isFile()) return [entry];
  failures.push(`Payload entry must be a regular file: ${entry}`);
  return [];
};

/**
 * Enumerate every tracked file rather than a hand-maintained collection of
 * payload/docs/tooling roots. A new public path therefore enters the safety
 * scan automatically. NUL-delimited output preserves unusual valid Git paths
 * without shell interpolation or line-splitting ambiguity.
 * @returns {string[]}
 */
const listTrackedRepositoryFiles = () => {
  const result = spawnSync('git', ['-C', root, 'ls-files', '-z'], { encoding: 'buffer' });
  if (result.error) {
    failures.push(`Unable to enumerate tracked repository files: ${result.error.message}`);
    return [];
  }
  if (result.status !== 0) {
    failures.push(`Unable to enumerate tracked repository files: ${String(result.stderr || '').trim() || 'git ls-files failed'}`);
    return [];
  }
  return Buffer.from(result.stdout || []).toString('utf8').split('\0').filter(Boolean);
};

const isSafetyScanExcluded = (file) => [...safetyScanExcludedPrefixes.keys()]
  .some((prefix) => file === prefix.slice(0, -1) || file.startsWith(prefix));

for (const file of requiredFiles) {
  try {
    const info = lstatSync(path.join(root, file));
    if (info.isSymbolicLink()) {
      failures.push(`Required file must not be a symlink: ${file}`);
    } else if (!info.isFile()) {
      failures.push(`Required file is not regular: ${file}`);
    }
  } catch {
    failures.push(`Required file is missing: ${file}`);
  }
}

const payloadFiles = payloadEntries.flatMap(walk).sort();
// Keep this count in lockstep with the skill payload tree under scripts/,
// agents/, assets/, references/, and SKILL.md (including new test modules).
// 31 -> 37: evidence tools (debug_evidence/debug_viewer/debug_diff + tests).
if (payloadFiles.length !== 37) {
  failures.push(`Expected 37 skill payload files, found ${payloadFiles.length}`);
}

try {
  const skill = readFileSync(path.join(root, 'SKILL.md'), 'utf8');
  if (!/^---\r?\nname:\s*debug\r?\n/m.test(skill)) failures.push('SKILL.md must declare name: debug');
  for (const trigger of ['cleanup GitHub', 'bug', 'debug']) {
    if (!skill.includes(`"${trigger}"`)) failures.push(`SKILL.md is missing automatic trigger: ${trigger}`);
  }
} catch {
  // Missing file is already reported by the required-file checks above.
}

try {
  const metadata = readFileSync(path.join(root, 'agents', 'openai.yaml'), 'utf8');
  if (!/allow_implicit_invocation:\s*true/.test(metadata)) {
    failures.push('agents/openai.yaml must allow implicit invocation');
  }
} catch {
  // Missing file is already reported by the required-file checks above.
}

for (const file of payloadFiles.filter((name) => name.endsWith('.json'))) {
  try {
    const abs = path.join(root, file);
    if (lstatSync(abs).size > MAX_PAYLOAD_FILE_BYTES) {
      failures.push(`Payload JSON exceeds validator size bound: ${file}`);
      continue;
    }
    JSON.parse(readFileSync(abs, 'utf8'));
  } catch (error) {
    failures.push(`Invalid JSON in ${file}: ${error.message}`);
  }
}

const publicSafetyPatterns = [
  ['credential token', /(?:gh[pousr]_|github_pat_|sk-|xox[baprs]-)[A-Za-z0-9_-]{20,}/],
  ['private key', /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/],
  ['personal Windows path', /[A-Za-z]:\\Users\\[^<\s]+/i],
  ['personal Unix path', /\/(?:Users|home)\/[^<\s]+/],
  ['generated attribution line', /^\s*Generated with \[Claude Code\]/m],
];

const safetyScanFiles = listTrackedRepositoryFiles()
  .filter((file) => !isSafetyScanExcluded(file))
  .sort();

/**
 * Reads one file and records a failure for each `publicSafetyPatterns` entry
 * it matches — credential-shaped tokens, private key headers, personal
 * Windows/Unix home paths, or a generated-attribution line — so none of
 * these ever ship in the public repository. A tracked file that disappears or
 * becomes unreadable is a validator failure, never a silently skipped scan.
 * The validator also refuses to read a non-regular-file or oversize
 * (`MAX_PAYLOAD_FILE_BYTES`) target rather than risk hanging or OOMing.
 * @param {string} file path relative to `root`.
 */
const scanFileForPublicSafety = (file) => {
  const abs = path.join(root, file);
  let info;
  try {
    info = lstatSync(abs);
  } catch (error) {
    failures.push(`Safety scan target cannot be inspected: ${file}: ${error.message}`);
    return;
  }
  if (!info.isFile()) {
    failures.push(`Safety scan target is not a regular file: ${file}`);
    return;
  }
  if (info.size > MAX_PAYLOAD_FILE_BYTES) {
    failures.push(`Safety scan file exceeds validator size bound: ${file}`);
    return;
  }
  let content;
  try {
    content = readFileSync(abs, 'utf8');
  } catch (error) {
    failures.push(`Safety scan target cannot be read: ${file}: ${error.message}`);
    return;
  }
  for (const [label, pattern] of publicSafetyPatterns) {
    if (pattern.test(content)) failures.push(`${file} contains ${label}`);
  }
};

for (const file of safetyScanFiles) scanFileForPublicSafety(file);

// The tracked-file census above covers scripts, tooling, tests, and any future
// JavaScript path, so syntax validation has the same complete scope.
const javascriptFiles = safetyScanFiles.filter((name) => name.endsWith('.js'));
for (const file of javascriptFiles) {
  const abs = path.join(root, file);
  let info;
  try {
    info = lstatSync(abs);
  } catch {
    failures.push(`JavaScript syntax check target missing: ${file}`);
    continue;
  }
  if (!info.isFile()) {
    failures.push(`JavaScript syntax check skipped non-regular file: ${file}`);
    continue;
  }
  // Codex Uonli: enforce the same MAX_PAYLOAD_FILE_BYTES bound the safety scan
  // uses above before spawning `node --check` — otherwise an oversized or
  // parser-pathological file still reaches the subprocess and can consume
  // unbounded parser memory/CPU despite the validator's stated size cap.
  if (info.size > MAX_PAYLOAD_FILE_BYTES) {
    failures.push(`JavaScript syntax check skipped oversize file: ${file}`);
    continue;
  }
  const result = spawnSync(process.execPath, ['--check', abs], {
    encoding: 'utf8',
  });
  // Never crash while reporting a syntax failure: spawn can fail with
  // result.error and null status, and stderr may be non-string.
  // Support string or Buffer stderr/stdout regardless of spawnSync encoding.
  const stderr = result.stderr ? String(result.stderr).trim() : '';
  const stdout = result.stdout ? String(result.stdout).trim() : '';
  if (result.error) {
    failures.push(`JavaScript syntax check spawn failed for ${file}: ${result.error.message}`);
    continue;
  }
  if (result.status !== 0) {
    const detail = stderr || stdout || `exit ${result.status ?? 'null'}`;
    failures.push(`JavaScript syntax failed for ${file}: ${detail}`);
  }
}

if (failures.length > 0) {
  for (const failure of failures) process.stderr.write(`FAIL: ${failure}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(JSON.stringify({
    status: 'PASS',
    payloadFiles: payloadFiles.length,
    javascriptFiles: javascriptFiles.length,
    safetyScanFiles: safetyScanFiles.length,
    dependencies: 0,
  }) + '\n');
}
