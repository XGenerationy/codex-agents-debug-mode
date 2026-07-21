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

const failures = [];

// Payload walker that fails closed on missing entries and never follows
// symlinks. statSync() follows symlinks and would let a symlinked directory
// or cycle trigger unbounded recursion; lstatSync() lets us detect symlinks
// and treat them as validation failures so a reviewed branch cannot hang or
// escape the payload tree during `npm run validate`.
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
  if (!info.isDirectory()) return [entry];
  return readdirSync(absolute).flatMap((name) => walk(path.join(entry, name)));
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
if (payloadFiles.length !== 26) {
  failures.push(`Expected 26 skill payload files, found ${payloadFiles.length}`);
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

for (const file of payloadFiles) {
  const abs = path.join(root, file);
  try {
    if (lstatSync(abs).size > MAX_PAYLOAD_FILE_BYTES) {
      failures.push(`Payload file exceeds validator size bound: ${file}`);
      continue;
    }
  } catch {
    // Missing files are reported by the required-file checks; skip here.
    continue;
  }
  const content = readFileSync(abs, 'utf8');
  for (const [label, pattern] of publicSafetyPatterns) {
    if (pattern.test(content)) failures.push(`${file} contains ${label}`);
  }
}

const javascriptFiles = [
  ...walk('scripts').filter((name) => name.endsWith('.js')),
  ...walk('tools').filter((name) => name.endsWith('.js')),
];
for (const file of javascriptFiles) {
  const result = spawnSync(process.execPath, ['--check', path.join(root, file)], {
    encoding: 'utf8',
  });
  // Never crash while reporting a syntax failure: spawn can fail with
  // result.error and null status, and stderr may be non-string.
  const stderr = typeof result.stderr === 'string' ? result.stderr.trim() : '';
  const stdout = typeof result.stdout === 'string' ? result.stdout.trim() : '';
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
    dependencies: 0,
  }) + '\n');
}
