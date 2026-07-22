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

// Non-payload paths that still ship in the public repo and must pass the
// public-distribution safety scan (docs, workflows, tooling).
const safetyScanRoots = [
  'README.md',
  'SECURITY.md',
  'CONTRIBUTING.md',
  'NOTICE.md',
  'LICENSE',
  'package.json',
  '.codereview.yml',
  '.github/workflows',
  'tools',
];

const failures = [];

// Payload walker that fails closed on missing entries and never follows
// symlinks. statSync() follows symlinks and would let a symlinked directory
// or cycle trigger unbounded recursion; lstatSync() lets us detect symlinks
// and treat them as validation failures so a reviewed branch cannot hang or
// escape the payload tree during `npm run validate`. Non-regular files
// (FIFO/socket/device) must not enter readFileSync / node --check either.
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

// Soft walk for optional safety-scan roots: missing optional docs are skipped
// rather than failing the whole validator.
const walkOptional = (entry) => {
  const absolute = path.join(root, entry);
  let info;
  try {
    info = lstatSync(absolute);
  } catch (error) {
    if (error.code === 'ENOENT') return [];
    throw error;
  }
  if (info.isSymbolicLink()) {
    failures.push(`Safety-scan path must not be a symlink: ${entry}`);
    return [];
  }
  if (info.isDirectory()) {
    return readdirSync(absolute).flatMap((name) => walkOptional(path.join(entry, name)));
  }
  if (info.isFile()) return [entry];
  failures.push(`Safety-scan path must be a regular file: ${entry}`);
  return [];
};

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
if (payloadFiles.length !== 28) {
  failures.push(`Expected 28 skill payload files, found ${payloadFiles.length}`);
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

const safetyScanFiles = [...new Set([
  ...payloadFiles,
  ...safetyScanRoots.flatMap(walkOptional),
])].sort();

const scanFileForPublicSafety = (file) => {
  const abs = path.join(root, file);
  let info;
  try {
    info = lstatSync(abs);
  } catch {
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
  const content = readFileSync(abs, 'utf8');
  for (const [label, pattern] of publicSafetyPatterns) {
    if (pattern.test(content)) failures.push(`${file} contains ${label}`);
  }
};

for (const file of safetyScanFiles) scanFileForPublicSafety(file);

// Derive the JavaScript list from payloadFiles (scripts/ is already a payload
// entry) plus the optional tools/ walk, instead of re-walking scripts/ — that
// duplicate traversal repeated filesystem work and could surface walk() failures
// twice for missing/symlinked/non-regular entries.
const javascriptFiles = [
  ...payloadFiles.filter((name) => name.endsWith('.js')),
  ...walkOptional('tools').filter((name) => name.endsWith('.js')),
];
for (const file of javascriptFiles) {
  const abs = path.join(root, file);
  try {
    if (!lstatSync(abs).isFile()) {
      failures.push(`JavaScript syntax check skipped non-regular file: ${file}`);
      continue;
    }
  } catch {
    failures.push(`JavaScript syntax check target missing: ${file}`);
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
