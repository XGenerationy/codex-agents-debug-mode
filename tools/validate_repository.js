'use strict';

const { readFileSync, readdirSync, statSync } = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const payloadEntries = ['SKILL.md', 'agents', 'assets', 'references', 'scripts'];
const requiredFiles = [
  'SKILL.md',
  'agents/openai.yaml',
  'assets/pr-closeout.config.example.json',
  'references/error-recovery.md',
  'references/pr-closeout-validation.md',
  'scripts/debug_server.js',
  'scripts/pr_closeout.js',
];

const walk = (entry) => {
  const absolute = path.join(root, entry);
  if (!statSync(absolute).isDirectory()) return [entry];
  return readdirSync(absolute).flatMap((name) => walk(path.join(entry, name)));
};

const failures = [];
for (const file of requiredFiles) {
  try {
    if (!statSync(path.join(root, file)).isFile()) failures.push(`Required file is not regular: ${file}`);
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
    JSON.parse(readFileSync(path.join(root, file), 'utf8'));
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
  const content = readFileSync(path.join(root, file), 'utf8');
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
  if (result.status !== 0) failures.push(`JavaScript syntax failed for ${file}: ${result.stderr.trim()}`);
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
