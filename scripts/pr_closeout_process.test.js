const assert = require('node:assert/strict');
const { execFileSync, spawn, spawnSync } = require('node:child_process');
const { readFileSync } = require('node:fs');
const { access, chmod, link, lstat, mkdir, mkdtemp, open, readdir, readFile, realpath, rename, rm, stat, symlink, writeFile } = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  SPAWN_MARK_ENV,
  MAX_ARTIFACT_HASH_BYTES,
  createCommandExecutor,
  createDecodedRedactor,
  createStreamingRedactor,
  environHasAnySpawnMark,
  listLivePidsWithCwdUnder,
  listLivePidsWithSpawnMark,
  probeCommandDefault,
  redactSecrets,
  redactStructure,
  probeGrafanaHealthDefault,
  probeRedisDefault,
  readBoundArtifactJson,
  resolveCommandShell,
  runPreflight,
  snapshotArtifactProof,
  spawnCaptured,
  sweepDetachedOrphans,
  terminateProcessTree,
  writeLogHeaderNoFollow,
} = require('./pr_closeout_process');

const { MIN_AUTO_SECRET_LENGTH, buildChildEnvironment } = require('./pr_closeout_stream');

const windowsAclIsCurrentUserOnly = (filePath) => {
  const encodedPath = Buffer.from(filePath, 'utf16le').toString('base64');
  const script = [
    `$path = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('${encodedPath}'))`,
    '$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User',
    '$acl = [IO.File]::GetAccessControl($path)',
    '$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))',
    'if ($acl.AreAccessRulesProtected -and $rules.Count -eq 1 -and $rules[0].IdentityReference.Value -eq $sid.Value -and $rules[0].AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and (($rules[0].FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl)) { [Console]::Out.Write("ok") } else { [Console]::Out.Write("not-owner-only"); exit 1 }',
  ].join('; ');
  return spawnSync(
    'powershell.exe',
    ['-NoLogo', '-NoProfile', '-NonInteractive', '-EncodedCommand', Buffer.from(script, 'utf16le').toString('base64')],
    { encoding: 'utf8', windowsHide: true, timeout: 15000 },
  );
};

const listen = (server) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => resolve(server.address().port));
});

const closeServer = (server) => new Promise((resolve, reject) => {
  server.close((error) => (error ? reject(error) : resolve()));
});

// CI failure diagnostics: when a status assertion fails, print the executor's
// evidence so the remote runner log carries the root cause.
const statusDiag = (result) =>
  `evidence: ${result?.evidence || ''} | terminationEvidence: ${result?.terminationEvidence || ''}`;


test('uses an explicit absolute Git Bash path on Windows', () => {
  const shell = resolveCommandShell({
    platform: 'win32',
    env: { OMO_CODEX_GIT_BASH_PATH: 'D:\\PortableGit\\bin\\bash.exe' },
  });
  assert.equal(shell, 'D:\\PortableGit\\bin\\bash.exe');
  assert.notEqual(shell, 'bash');
});

test('preflight blocks missing tools, credentials, service health, and disk', async () => {
  const result = await runPreflight({
    repo: 'C:/repo',
    config: {
      requiredEnv: ['REDIS_PASSWORD'],
      minFreeDiskGb: 5,
      services: { redis: { host: '127.0.0.1', port: 6379 } },
    },
    env: { REDIS_PASSWORD: '' },
    probeCommand: async (command) => ({
      exitCode: command.startsWith('pnpm --version') ? 1 : 0,
      stdout: command,
      stderr: '',
    }),
    diskFreeGb: async () => 1,
    probeTcp: async () => false,
    probeRedis: async () => false,
    probeHttp: async () => true,
  });
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.ok(result.checks.some(({ name, status }) => name === 'pnpm' && status === 'BLOCKED'));
  assert.ok(result.checks.some(({ name, status }) => name === 'env:REDIS_PASSWORD' && status === 'BLOCKED'));
  assert.ok(result.checks.some(({ name, status }) => name === 'redis' && status === 'BLOCKED'));
  assert.ok(result.checks.some(({ name, status }) => name === 'disk' && status === 'BLOCKED'));
  assert.doesNotMatch(JSON.stringify(result), /actual-secret-value/);
});

test('redacts configured secret values from command evidence', () => {
  const output = redactSecrets('token=secret-123 password=hunter2', {
    TOKEN: 'secret-123',
    PASSWORD: 'hunter2',
  }, ['TOKEN', 'PASSWORD']);
  assert.equal(output, 'token=[REDACTED] password=[REDACTED]');
});

test('redacts overlapping configured secrets longest-first', () => {
  const output = redactSecrets('token=secret-123', {
    SHORT_TOKEN: 'secret',
    LONG_TOKEN: 'secret-123',
  }, ['SHORT_TOKEN', 'LONG_TOKEN']);
  assert.equal(output, 'token=[REDACTED]');
});

test('does not auto-redact short sensitive values to avoid over-broad replacement', () => {
  // Short values (below MIN_AUTO_SECRET_LENGTH) would corrupt ordinary text
  // if they were auto-redacted everywhere as substrings, so the redactor
  // skips them. Long values from auto-discovered sensitive names are still
  // redacted along with their URL/base64/hex variants.
  const secret = 'x/secret-value-long-enough';
  const env = { GITHUB_TOKEN: secret, ORDINARY_VALUE: 'visible', SHORT_TOKEN: 'tiny' };
  const encoded = [
    encodeURIComponent(secret),
    JSON.stringify(secret).slice(1, -1),
    Buffer.from(secret).toString('base64'),
    Buffer.from(secret).toString('base64url'),
  ];
  const output = redactSecrets(`raw=${secret} url=${encoded[0]} json=${encoded[1]} b64=${encoded[2]} b64url=${encoded[3]} ordinary=${env.ORDINARY_VALUE} short=${env.SHORT_TOKEN}`, env);
  for (const value of [secret, ...encoded]) assert.equal(output.includes(value), false, value);
  assert.match(output, /ordinary=visible/);
  // The short auto-discovered value must remain visible to avoid corrupting
  // ordinary text where it appears as a substring.
  assert.match(output, /short=tiny/);
});

test('redacts auto-discovered secrets at exactly MIN_AUTO_SECRET_LENGTH and treats shorter as visible', () => {
  // The redactor uses value.length < MIN_AUTO_SECRET_LENGTH to skip short
  // auto-discovered values, so a value of exactly the threshold must be
  // redacted while anything shorter stays visible.
  const boundary = '12345678'; // length === MIN_AUTO_SECRET_LENGTH (8)
  assert.equal(boundary.length, MIN_AUTO_SECRET_LENGTH);
  const env = { API_TOKEN: boundary };
  assert.equal(redactSecrets(`tok=${boundary}`, env).includes(boundary), false);
  const shorter = '1234567'; // length === MIN_AUTO_SECRET_LENGTH - 1
  assert.equal(redactSecrets(`short=${shorter}`, { API_TOKEN: shorter }).includes(shorter), true);
});

test('streaming redaction covers automatically discovered encoded secrets across chunks', () => {
  // Long auto-discovered secret must still be redacted across chunk
  // boundaries; the encoded base64 form is also covered.
  const secret = 'long-enough-secret';
  const encoded = Buffer.from(secret).toString('base64');
  const redactor = createStreamingRedactor({ API_TOKEN: secret }, []);
  const output = redactor.push(`encoded=${encoded.slice(0, 3)}`)
    + redactor.push(encoded.slice(3))
    + redactor.flush();
  assert.equal(output, 'encoded=[REDACTED]');
});

test('redacts credentials and encoded components from sensitive URL environment variables', () => {
  const password = 'p@ss word';
  const databaseUrl = `postgresql://alice:${encodeURIComponent(password)}@db.example/app`;
  const output = redactSecrets([
    databaseUrl,
    password,
    encodeURIComponent(password),
    Buffer.from(password).toString('base64').replace(/=+$/u, ''),
    Buffer.from(password).toString('hex'),
  ].join(' '), { DATABASE_URL: databaseUrl });
  assert.doesNotMatch(output, /postgresql|alice|p@ss|p%40ss|cEBzcyB3b3Jk|70407373/i);
});

test('preserves shared object references while still terminating true cycles', () => {
  // report.toolVersions and report.preflight.toolVersions often alias the same
  // object; a traversal-wide WeakSet that marks every re-visit as Circular
  // corrupts one of those fields. Shared refs must stay equal after redaction.
  const toolVersions = { node: 'v22.0.0', pnpm: '9.0.0' };
  const preflight = { status: 'PASS', toolVersions };
  const report = { toolVersions, preflight, secret: 'supersecretvalue123' };
  const redacted = redactStructure(report, { API_TOKEN: 'supersecretvalue123' }, ['API_TOKEN']);
  assert.equal(redacted.toolVersions, redacted.preflight.toolVersions);
  assert.deepEqual(redacted.toolVersions, { node: 'v22.0.0', pnpm: '9.0.0' });
  assert.match(redacted.secret, /\[REDACTED\]/);
  // True cycles still terminate with [Circular].
  const cycle = { name: 'root' };
  cycle.self = cycle;
  const cycled = redactStructure(cycle, {}, []);
  assert.equal(cycled.self, '[Circular]');
  assert.equal(cycled.name, 'root');
});

test('redacts credential leaves parsed from JSON auth-blob environment values', () => {
  // A required/safe env var can hold a JSON auth blob such as
  // AUTH_CONFIG={"token":"..."}. The redactor must redact the token leaf so a
  // tool that prints just that value cannot leak it, not only the full blob.
  // Nested objects (e.g. {"auth":{"token":"..."}}) must also be covered.
  const leaf = 'supersecretvalue123';
  const nestedLeaf = 'nestedsecretvalue456';
  const blob = JSON.stringify({ token: leaf, auth: { token: nestedLeaf }, kind: 'service-account' });
  const output = redactSecrets(`config=${blob} isolated=${leaf} nested=${nestedLeaf}`, { AUTH_CONFIG: blob }, ['AUTH_CONFIG']);
  assert.equal(output.includes(leaf), false, 'the top-level JSON token leaf must be redacted');
  assert.equal(output.includes(nestedLeaf), false, 'a nested JSON token leaf must also be redacted');
  assert.match(output, /isolated=\[REDACTED\]/);
  assert.match(output, /nested=\[REDACTED\]/);
});

test('redacts bare Docker auth leaf from DOCKER_AUTH_CONFIG JSON', () => {
  // DOCKER_AUTH_CONFIG={"auths":{"registry":{"auth":"..."}}} stores the
  // base64 credential under the bare key `auth`, which does not end in
  // token/password/secret/key/credential. The leaf must still be redacted when
  // a package manager prints only that value.
  const leaf = 'supersecretvalue123';
  const blob = JSON.stringify({ auths: { registry: { auth: leaf } } });
  const output = redactSecrets(`isolated=${leaf}`, { DOCKER_AUTH_CONFIG: blob }, ['DOCKER_AUTH_CONFIG']);
  assert.equal(output.includes(leaf), false, 'bare auth JSON leaf must be redacted');
  assert.match(output, /isolated=\[REDACTED\]/);
});

test('matches explicit secret names case-insensitively against env keys', () => {
  // A config listing "npm_token" must redact NPM_TOKEN (buildChildEnvironment
  // uppercases the allowlist); the redaction allowlist must do the same so a
  // short explicit value is still redacted regardless of casing.
  const output = redactSecrets('leak: shrt', { NPM_TOKEN: 'shrt' }, ['npm_token']);
  assert.equal(output.includes('shrt'), false, 'short explicit (case-mismatched) value must be redacted');
});

test('explicitly-allowed short secret values are still redacted end-to-end', () => {
  // Explicitly-listed names opt in to redaction regardless of length so
  // users can still redact short tokens when they choose to.
  const output = redactSecrets('value=tiny', { SHORT_TOKEN: 'tiny' }, ['SHORT_TOKEN']);
  assert.equal(output, 'value=[REDACTED]');
});

test('preflight blocks required secrets that are too short for reliable evidence capture', async () => {
  const result = await runPreflight({
    repo: process.cwd(),
    config: { requiredEnv: ['API_TOKEN'], minFreeDiskGb: 0 },
    env: { ...process.env, API_TOKEN: 'x' },
    probeCommand: async () => ({ exitCode: 0, stdout: 'version 1', stderr: '' }),
    diskFreeGb: async () => 10,
  });
  const credential = result.checks.find(({ name }) => name === 'env:API_TOKEN');
  assert.equal(credential.status, 'BLOCKED');
  assert.match(credential.evidence, /too short/i);
});

test('redacts a secret split across output chunks', () => {
  const redactor = createStreamingRedactor({ TOKEN: 'secret-123' }, ['TOKEN']);
  const output = redactor.push('token=sec') + redactor.push('ret-123 done') + redactor.flush();
  assert.equal(output, 'token=[REDACTED] done');
});

test('redacts a multibyte secret split inside a UTF-8 code point', () => {
  const secret = 'påssword-秘密';
  const bytes = Buffer.from(`token=${secret} done`, 'utf8');
  const split = Buffer.from('token=p', 'utf8').length + 1;
  const redactor = createDecodedRedactor({ TOKEN: secret }, ['TOKEN']);
  const output = redactor.push(bytes.subarray(0, split))
    + redactor.push(bytes.subarray(split))
    + redactor.flush();
  assert.equal(output, 'token=[REDACTED] done');
});

test('command executor records timestamps, exit code, output, and a log', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-executor-'));
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const result = await execute(
    { id: 'probe', command: "process.stdout.write('clean output')" },
    'qualification',
  );
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.equal(result.exitCode, 0);
  assert.match(result.startedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.match(result.finishedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(result.stdout, 'clean output');
  assert.match(
    await readFile(path.join(outputDir, 'logs', 'qualification.probe.attempt-001.log'), 'utf8'),
    /clean output/,
  );
  assert.equal(result.logPath, '<output>/logs/qualification.probe.attempt-001.log');
});

test('keeps the full redacted raw log while capping report output', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-full-log-'));
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const result = await execute(
    { id: 'large-probe', command: "process.stdout.write('x'.repeat(2100000) + 'TAIL')" },
    'qualification',
  );
  const log = await readFile(
    path.join(outputDir, 'logs', 'qualification.large-probe.attempt-001.log'),
    'utf8',
  );
  assert.equal(result.stdout.length, 2_000_000);
  assert.match(log, /TAIL$/);
});

test('classifies warning output that appears after the report capture cap', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-tail-warning-'));
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const result = await execute({
    id: 'tail-warning',
    command: "process.stdout.write('x'.repeat(2100000) + '\\nUserWarning: unsafe tail')",
  }, 'qualification');
  assert.equal(result.stdout.length, 2_000_000);
  assert.doesNotMatch(result.stdout, /UserWarning/);
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.match(result.evidence, /UserWarning/);
});

test('classifies a no-work summary that appears after the report capture cap', async () => {
  // Codex UikNz: classifyOutput decides "no tests ran" from the capped
  // combined stdout/stderr. A runner that streams past CAPTURE_LIMIT before
  // its terminal "No tests found" summary pushes that line beyond the head
  // cap, so classifyOutput's combined-string checks never see it. The
  // independent streaming no-work scanner (fed the raw, uncapped stream) must
  // still catch it and thread a signal into detectedSignals so the executor
  // FAILs instead of PASSing. The "no-work:" prefix in the evidence is emitted
  // ONLY by that streaming detector -- classifyOutput's own combined path
  // produces different wording -- so matching it proves the post-cap summary
  // was caught by the stream, not by the (now blind) capped string.
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-tail-nowork-'));
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const result = await execute({
    id: 'tail-nowork',
    command: "process.stdout.write('x'.repeat(2100000) + '\\nNo tests found, exiting with code 0\\n')",
  }, 'qualification');
  assert.equal(result.stdout.length, 2_000_000);
  assert.doesNotMatch(result.stdout, /no tests found/i);
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.match(result.evidence, /no-work/i);
});

test('hashes full output beyond the report capture cap', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-digest-'));
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const first = await execute({ id: 'first', command: "process.stdout.write('x'.repeat(2100000) + 'A')" }, 'qualification');
  const second = await execute({ id: 'second', command: "process.stdout.write('x'.repeat(2100000) + 'B')" }, 'qualification');
  assert.equal(first.stdout, second.stdout);
  assert.notEqual(first.outputDigest.stdout, second.outputDigest.stdout);
});

test('fails a successful command when its artifact proof is missing and passes a refreshed artifact', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-artifact-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-artifact-logs-'));
  const execute = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const missing = await execute({
    id: 'missing-artifact',
    command: "process.stdout.write('clean')",
    proof: { type: 'artifact', path: 'render.json' },
  }, 'confirmation');
  assert.equal(missing.status, 'FAIL');
  const present = await execute({
    id: 'fresh-artifact',
    command: "require('node:fs').writeFileSync('render.json', '{\"ok\":true}')",
    proof: { type: 'artifact', path: 'render.json' },
  }, 'confirmation');
  assert.equal(present.status, 'PASS');
  assert.equal(present.proofResult.size > 0, true);
});

test('rejects a stale artifact that existed unchanged before the command', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-stale-artifact-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-stale-artifact-logs-'));
  await require('node:fs/promises').writeFile(path.join(repo, 'render.json'), '{"stale":true}');
  const execute = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const result = await execute({
    id: 'stale-artifact',
    command: "process.stdout.write('clean')",
    proof: { type: 'artifact', path: 'render.json' },
  }, 'confirmation');
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.match(result.evidence, /not refreshed by this run/i);
});

test('rejects timestamp-only artifact refreshes', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-touched-artifact-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-touched-artifact-logs-'));
  const artifact = path.join(repo, 'render.json');
  await writeFile(artifact, '{"same":true}');
  const execute = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const result = await execute({
    id: 'touch-only',
    command: "const fs=require('node:fs'); const now=new Date(); fs.utimesSync('render.json', now, now)",
    proof: { type: 'artifact', path: 'render.json' },
  }, 'confirmation');
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.match(result.evidence, /not refreshed/i);
});

test('rejects hard-linked artifact proof files', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-hardlink-artifact-'));
  const outside = path.join(repo, 'source.json');
  const artifact = path.join(repo, 'render.json');
  await writeFile(outside, '{"source":true}');
  await link(outside, artifact);
  const result = await snapshotArtifactProof({ proof: { type: 'artifact', path: 'render.json' }, cwd: repo });
  assert.equal((await stat(artifact)).nlink > 1, true);
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.match(result.evidence, /hard-linked/i);
});

test('rejects artifact proof paths whose real target escapes through a link', async () => {
  const cwd = path.resolve(process.cwd());
  const outside = path.resolve(cwd, '..', 'outside', 'render.json');
  const result = await snapshotArtifactProof({
    proof: { type: 'artifact', path: 'linked/render.json' },
    cwd,
    filesystem: {
      lstat: async () => ({
        isFile: () => true,
        isSymbolicLink: () => false,
        size: 12,
        mtimeMs: 1,
        ctimeMs: 1,
        dev: 1,
        ino: 1,
      }),
      realpath: async (target) => (path.resolve(target) === cwd ? cwd : outside),
    },
    hashArtifact: async () => 'digest',
  });
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.match(result.evidence, /resolves outside/i);
});

// Wraps a real FileHandle so a test can observe exactly how many bytes
// readBoundArtifactJson requested per read() call, without changing what the
// reads actually return.
const trackReads = (handle, reads) => ({
  stat: (...args) => handle.stat(...args),
  close: (...args) => handle.close(...args),
  read: async (buffer, offset, length, position) => {
    reads.push(length);
    return handle.read(buffer, offset, length, position);
  },
  // Recorded too so a regression back to the unbounded handle.readFile()
  // shows up as an unexpected 'readFile' entry instead of a thrown
  // "not a function", keeping the assertion failure legible.
  readFile: async (...args) => {
    reads.push('readFile');
    return handle.readFile(...args);
  },
});

test('readBoundArtifactJson parses an unchanged verified artifact via a bounded read', async () => {
  const cwd = await mkdtemp(path.join(tmpdir(), 'closeout-bound-read-'));
  try {
    const payload = { provider: 'grafana', ok: true };
    await writeFile(path.join(cwd, 'proof.json'), JSON.stringify(payload), 'utf8');
    const proofResult = await snapshotArtifactProof({ proof: { path: 'proof.json' }, cwd });
    assert.equal(proofResult.status, 'PASS', statusDiag(proofResult));

    const reads = [];
    const openArtifactFn = async (target) => trackReads(await open(target, 'r'), reads);
    const result = await readBoundArtifactJson(proofResult, { openArtifactFn });

    assert.equal(result.status, 'PASS', statusDiag(result));
    assert.deepEqual(result.value, payload);
    // Exactly the verified size, plus the one-byte growth probe -- never
    // however large the underlying file happens to be.
    assert.deepEqual(reads, [proofResult.size, 1]);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('readBoundArtifactJson rejects and never reads past the verified size when the artifact grows mid-verification', async () => {
  // chatgpt-codex-connector scripts/pr_closeout_process.js:2145: the previous
  // implementation used handle.readFile(), which reads to whatever EOF
  // exists at read time. A writer that keeps appending to the proof file
  // after snapshotArtifactProof took its "before" measurement could make this
  // allocate arbitrarily far past the documented 1 MiB bound before the
  // dev/ino/size/mtimeMs/digest comparison ever got a chance to reject the
  // mutation. Prove the fix reads exactly the verified size (positionally,
  // via handle.read) and detects any growth with a single one-byte probe --
  // never touching however much a concurrent writer actually appended.
  const cwd = await mkdtemp(path.join(tmpdir(), 'closeout-bound-read-grown-'));
  try {
    const payload = { provider: 'grafana', ok: true };
    const proofPath = path.join(cwd, 'proof.json');
    await writeFile(proofPath, JSON.stringify(payload), 'utf8');
    const proofResult = await snapshotArtifactProof({ proof: { path: 'proof.json' }, cwd });
    assert.equal(proofResult.status, 'PASS', statusDiag(proofResult));

    // Simulate a writer appending well past the verified size at the exact
    // moment readBoundArtifactJson performs its main bounded read -- after
    // the pre-read identity stat (which must still see the original size to
    // reach the read at all) but before the post-read growth probe.
    const reads = [];
    let appended = false;
    const openArtifactFn = async (target) => {
      const handle = await open(target, 'r');
      return {
        stat: (...args) => handle.stat(...args),
        close: (...args) => handle.close(...args),
        read: async (buffer, offset, length, position) => {
          reads.push(length);
          if (!appended && length === proofResult.size) {
            appended = true;
            await writeFile(target, 'x'.repeat(2_000_000), { flag: 'a' });
          }
          return handle.read(buffer, offset, length, position);
        },
        readFile: async (...args) => {
          reads.push('readFile');
          if (!appended) {
            appended = true;
            await writeFile(target, 'x'.repeat(2_000_000), { flag: 'a' });
          }
          return handle.readFile(...args);
        },
      };
    };
    const result = await readBoundArtifactJson(proofResult, { openArtifactFn });

    assert.equal(result.status, 'FAIL', statusDiag(result));
    assert.match(result.evidence, /changed while it was being verified/);
    // Bounded read plus the one-byte probe -- not the ~2 MB actually on disk.
    assert.deepEqual(reads, [proofResult.size, 1]);
  } finally {
    await rm(cwd, { recursive: true, force: true });
  }
});

test('requires explicit health evidence from a postcondition command', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-health-'));
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const result = await execute({
    id: 'hunter-build',
    command: "process.stdout.write('built')",
    proof: {
      type: 'command',
      command: `process.stdout.write(${JSON.stringify(JSON.stringify([
        { Service: 'hunter', State: 'running', Health: 'healthy' },
      ]))})`,
      expectedPattern: 'semantic:docker-compose-running-healthy',
    },
  }, 'confirmation');
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.equal(result.proofResult.matched, true);
});

test('rejects hunter proof when Docker reports running but unhealthy', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-unhealthy-'));
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const result = await execute({
    id: 'hunter-build',
    command: "process.stdout.write('built')",
    proof: {
      type: 'command',
      command: `process.stdout.write(${JSON.stringify(JSON.stringify([
        { Service: 'hunter', State: 'running', Health: 'unhealthy' },
      ]))})`,
      expectedPattern: 'semantic:docker-compose-running-healthy',
    },
  }, 'confirmation');
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.equal(result.proofResult.matched, false);
  assert.match(result.evidence, /running.*healthy/i);
});

test('rejects arbitrary proof regex syntax instead of evaluating it', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-regex-policy-'));
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const result = await execute({
    id: 'generic-proof',
    command: "process.stdout.write('clean')",
    proof: {
      type: 'command',
      command: "process.stdout.write('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')",
      expectedPattern: '^(a+)+$',
    },
  }, 'confirmation');
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.match(result.evidence, /literal:|semantic:/i);
});

test('never returns raw secrets embedded in primary or proof commands', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-secret-command-'));
  const secret = 'secret-12345';
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
    env: { ...process.env, TOKEN: secret },
    secretNames: ['TOKEN'],
  });
  const result = await execute({
    id: 'secret-command',
    command: `const token='${secret}'; process.stdout.write('clean')`,
    proof: {
      type: 'command',
      command: `const token='${secret}'; process.stdout.write('healthy')`,
      expectedPattern: 'literal:healthy',
    },
  }, 'confirmation');
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
  assert.match(result.command, /\[REDACTED\]/);
  assert.match(result.proof.command, /\[REDACTED\]/);
});

test('classifies status signals before redaction without retaining the raw secret', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-raw-signal-'));
  const secret = 'ERROR: super-sensitive-raw-signal';
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
    env: { ...process.env, API_TOKEN: secret },
    secretNames: ['API_TOKEN'],
  });
  const result = await execute({
    id: 'redacted-error',
    command: 'process.stdout.write(process.env.API_TOKEN)',
  }, 'qualification');
  const serialized = JSON.stringify(result);
  const log = await readFile(
    path.join(outputDir, 'logs', 'qualification.redacted-error.attempt-001.log'),
    'utf8',
  );
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.doesNotMatch(serialized, /super-sensitive-raw-signal/);
  assert.doesNotMatch(log, /super-sensitive-raw-signal/);
  assert.match(result.stdout, /\[REDACTED\]/);
});

test('does not pass ambient credentials to child commands', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-child-env-'));
  const dockerCredential = '{"auths":{"registry.example":{"auth":"ambient-secret"}}}';
  const allowedCredential = 'explicit-required-secret';
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
    env: {
      ...process.env,
      DOCKER_AUTH_CONFIG: dockerCredential,
      API_TOKEN: allowedCredential,
    },
    secretNames: ['API_TOKEN'],
  });
  const result = await execute({
    id: 'child-env',
    command: "process.stdout.write(JSON.stringify({docker:process.env.DOCKER_AUTH_CONFIG||null,allowed:process.env.API_TOKEN||null}))",
  }, 'qualification');
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.equal(result.stdout, '{"docker":null,"allowed":"[REDACTED]"}');
  assert.doesNotMatch(JSON.stringify(result), /ambient-secret|explicit-required-secret/);
});

test('normalizes repository and user paths before capture and logging', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-private-repo-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-private-output-'));
  const privateHome = 'C:\\Users\\PrivatePerson';
  const execute = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
    env: { ...process.env, USERPROFILE: privateHome },
  });
  const result = await execute({
    id: 'path-probe',
    command: "process.stdout.write(`${process.cwd()}|${process.env.USERPROFILE}`)",
  }, 'qualification');
  const log = await readFile(
    path.join(outputDir, 'logs', 'qualification.path-probe.attempt-001.log'),
    'utf8',
  );
  assert.equal(result.stdout, '<repo>|<home>');
  assert.doesNotMatch(JSON.stringify(result), /PrivatePerson|closeout-private-repo-/i);
  assert.doesNotMatch(log, /PrivatePerson|closeout-private-repo-/i);
});

test('does not turn a root-only HOME into a needle that mangles every path separator', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-root-home-repo-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-root-home-output-'));
  try {
    const execute = createCommandExecutor({
      repo,
      outputDir,
      shell: process.execPath,
      shellArgs: (command) => ['-e', command],
      // A container or service account where HOME resolves to the filesystem
      // root: without the fix, buildPathReplacements would add a bare '/'
      // (and its '\\' variant) as a <home> needle, and since needles apply
      // globally across the whole captured string, every path separator in
      // *unrelated* evidence -- not just an actual home directory -- would
      // be replaced, destroying the evidentiary value of any other absolute
      // path the command prints (CodeRabbit review).
      env: { ...process.env, HOME: '/' },
    });
    const unrelatedPath = '/var/log/app/output.txt';
    const result = await execute({
      id: 'root-home-probe',
      command: `process.stdout.write(${JSON.stringify(unrelatedPath)})`,
    }, 'qualification');
    assert.equal(
      result.stdout,
      unrelatedPath,
      `an unrelated absolute path must not be mangled by a root-derived HOME needle: ${JSON.stringify(result)}`,
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('uses unique logs for repeated baseline setup attempts', async () => {
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-baseline-logs-'));
  const execute = createCommandExecutor({
    repo: process.cwd(),
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const first = await execute({
    id: 'baseline-dependency-setup',
    command: "process.stdout.write('first-attempt')",
  }, 'baseline-setup');
  const second = await execute({
    id: 'baseline-dependency-setup',
    command: "process.stdout.write('second-attempt')",
  }, 'baseline-setup');
  assert.notEqual(first.logPath, second.logPath);
  assert.match(
    await readFile(path.join(outputDir, 'logs', 'baseline-setup.baseline-dependency-setup.attempt-001.log'), 'utf8'),
    /first-attempt/,
  );
  assert.match(
    await readFile(path.join(outputDir, 'logs', 'baseline-setup.baseline-dependency-setup.attempt-002.log'), 'utf8'),
    /second-attempt/,
  );
});

test('redacts a baseline worktree cwd the same way as the head repo', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-head-repo-'));
  const baselineCwd = await mkdtemp(path.join(tmpdir(), 'closeout-baseline-cwd-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-baseline-cwd-logs-'));
  try {
    const execute = createCommandExecutor({
      repo,
      outputDir,
      shell: process.execPath,
      shellArgs: (command) => ['-e', command],
    });
    const result = await execute({
      id: 'typecheck',
      command: 'process.stdout.write(process.cwd())',
    }, 'baseline', baselineCwd);
    // Without the baseline-cwd redaction fix, the captured stdout would
    // contain the raw baselineCwd path; with the fix it is normalized to
    // <repo> exactly like the head execution.
    assert.equal(result.stdout, '<repo>');
    assert.doesNotMatch(JSON.stringify(result), new RegExp(baselineCwd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));
  } finally {
    await rm(repo, { recursive: true, force: true });
    await rm(baselineCwd, { recursive: true, force: true });
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('redacts baseline cwd paths from artifact proof evidence', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-head-repo-'));
  const baselineCwd = await mkdtemp(path.join(tmpdir(), 'closeout-baseline-cwd-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-artifact-proof-logs-'));
  try {
    const execute = createCommandExecutor({
      repo,
      outputDir,
      shell: process.execPath,
      shellArgs: (command) => ['-e', command],
    });
    // The artifact does not exist before the run, so snapshotArtifactProof
    // records exists:false; the command then creates a non-empty file, so
    // verifyArtifactProof returns PASS with proofResult fields (path, realPath,
    // realRoot) resolved against baselineCwd. Without cwd-aware redaction on
    // the finalized result, those absolute baseline paths would leak.
    const result = await execute({
      id: 'make-sbom',
      command: "require('node:fs').writeFileSync('artifact.json','{\"name\":\"sbom\"}\\n');process.stdout.write(process.cwd())",
      proof: { type: 'artifact', path: 'artifact.json' },
    }, 'baseline', baselineCwd);
    assert.equal(result.status, 'PASS', result.evidence);
    assert.equal(result.stdout, '<repo>');
    assert.ok(result.proofResult, 'artifact proof result should be attached');
    const escaped = new RegExp(baselineCwd.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'));
    assert.doesNotMatch(result.stderr || '', escaped);
    assert.doesNotMatch(JSON.stringify(result), escaped);
    assert.doesNotMatch(JSON.stringify(result.proofResult), escaped);
  } finally {
    await rm(repo, { recursive: true, force: true });
    await rm(baselineCwd, { recursive: true, force: true });
    await rm(outputDir, { recursive: true, force: true });
  }
});

test('rejects canonicalized Git metadata artifact paths regardless of case', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-git-proof-'));
  for (const proofPath of [
    'nested/../.GiT/config',
    '.\\.GIT\\objects\\proof',
    'nested/.git/proof',
  ]) {
    const result = await snapshotArtifactProof({
      proof: { type: 'artifact', path: proofPath },
      cwd: repo,
    });
    assert.equal(result.status, 'FAIL', proofPath);
    assert.match(result.evidence, /Git metadata/i, proofPath);
  }
});

test('requires a RESP PING and exact PONG for Redis health', async () => {
  let request = '';
  const server = net.createServer((socket) => {
    socket.on('data', (chunk) => {
      request += chunk.toString('utf8');
      socket.end('+PONG\r\n');
    });
  });
  const port = await listen(server);
  try {
    assert.equal(await probeRedisDefault({ host: '127.0.0.1', port }), true);
    assert.equal(request, '*1\r\n$4\r\nPING\r\n');
  } finally {
    await closeServer(server);
  }

  const wrongServer = net.createServer((socket) => {
    socket.once('data', () => socket.end('+OK\r\n'));
  });
  const wrongPort = await listen(wrongServer);
  try {
    assert.equal(await probeRedisDefault({ host: '127.0.0.1', port: wrongPort }), false);
  } finally {
    await closeServer(wrongServer);
  }
});

test('requires verified Grafana API health JSON identity and status', async () => {
  let valid = true;
  const server = http.createServer((_request, response) => {
    response.setHeader('content-type', 'application/json');
    response.end(valid
      ? JSON.stringify({ database: 'ok', version: '11.1.0', commit: 'abc123' })
      : JSON.stringify({ status: 'ok' }));
  });
  const port = await listen(server);
  try {
    const url = `http://127.0.0.1:${port}/api/health`;
    assert.deepEqual(await probeGrafanaHealthDefault(url), {
      healthy: true,
      evidence: 'Grafana API identity and database health were verified.',
    });
    valid = false;
    assert.equal((await probeGrafanaHealthDefault(url)).healthy, false);
  } finally {
    await closeServer(server);
  }
});

test('bounds a trickling Grafana health response by wall-clock time', { timeout: 10000 }, async () => {
  const server = http.createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    const interval = setInterval(() => {
      if (!response.destroyed) response.write(' ');
    }, 20);
    response.once('close', () => clearInterval(interval));
    response.once('error', () => clearInterval(interval));
  });
  const port = await listen(server);
  try {
    const startedAt = Date.now();
    const result = await probeGrafanaHealthDefault(`http://127.0.0.1:${port}/api/health`, 100);
    const elapsedMs = Date.now() - startedAt;
    assert.equal(result.healthy, false);
    assert.match(result.evidence, /wall-clock deadline/i);
    assert.ok(elapsedMs < 1_000, `Grafana probe must respect its wall-clock deadline (took ${elapsedMs}ms)`);
  } finally {
    await closeServer(server);
  }
});

test('binds live Grafana artifact proof to a query result contract', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-grafana-live-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-grafana-live-logs-'));
  const execute = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
    // Origin must come from the independently probed service URL, not proof.grafanaOrigin.
    grafanaServiceUrl: 'http://127.0.0.1:3000',
  });
  const invalidPayload = {
    provider: 'grafana',
    operation: 'query',
    endpoint: 'http://127.0.0.1:3000/api/ds/query',
    httpStatus: 200,
    request: { queries: [{ refId: 'A' }] },
    response: { results: {} },
  };
  const invalid = await execute({
    id: 'grafana-live-render',
    command: `require('node:fs').writeFileSync('live.json',${JSON.stringify(JSON.stringify(invalidPayload))})`,
    proof: {
      type: 'artifact',
      path: 'live.json',
      semantic: 'grafana-live-result',
      grafanaOrigin: 'http://127.0.0.1:3000',
    },
  }, 'confirmation');
  assert.equal(invalid.status, 'FAIL');

  const validPayload = {
    ...invalidPayload,
    response: { results: { A: { frames: [{ data: { values: [[1], [2]] } }] } } },
  };
  const valid = await execute({
    id: 'grafana-live-render',
    command: `require('node:fs').writeFileSync('live.json',${JSON.stringify(JSON.stringify(validPayload))})`,
    proof: {
      type: 'artifact',
      path: 'live.json',
      semantic: 'grafana-live-result',
      grafanaOrigin: 'http://127.0.0.1:3000',
    },
  }, 'confirmation');
  assert.equal(valid.status, 'PASS');
  assert.match(valid.evidence, /Grafana live query result/i);

  // A 200 response can still carry per-refId errors (e.g. datasource
  // unavailable). The proof must FAIL instead of treating the non-empty
  // results object as clean.
  const errorPayload = {
    ...invalidPayload,
    response: { results: { A: { error: 'datasource unavailable' } } },
  };
  const errored = await execute({
    id: 'grafana-live-render',
    command: `require('node:fs').writeFileSync('live.json',${JSON.stringify(JSON.stringify(errorPayload))})`,
    proof: {
      type: 'artifact',
      path: 'live.json',
      semantic: 'grafana-live-result',
      grafanaOrigin: 'http://127.0.0.1:3000',
    },
  }, 'confirmation');
  assert.equal(errored.status, 'FAIL');
  assert.match(errored.evidence, /error/i);

  // proof.grafanaOrigin must not override the independently probed origin.
  const evilOrigin = await execute({
    id: 'grafana-live-render',
    command: `require('node:fs').writeFileSync('live.json',${JSON.stringify(JSON.stringify({
      ...validPayload,
      endpoint: 'http://evil.example:3000/api/ds/query',
    }))})`,
    proof: {
      type: 'artifact',
      path: 'live.json',
      semantic: 'grafana-live-result',
      grafanaOrigin: 'http://evil.example:3000',
    },
  }, 'confirmation');
  assert.equal(evilOrigin.status, 'FAIL');
  assert.match(
    evilOrigin.evidence,
    /origin|endpoint|host|service|grafana/i,
    `evil-origin FAIL must cite origin/service mismatch, got: ${evilOrigin.evidence}`,
  );

  // Missing grafanaServiceUrl must not fall back to proof.grafanaOrigin.
  const noServiceUrl = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
  });
  const missingService = await noServiceUrl({
    id: 'grafana-live-render',
    command: `require('node:fs').writeFileSync('live.json',${JSON.stringify(JSON.stringify(validPayload))})`,
    proof: {
      type: 'artifact',
      path: 'live.json',
      semantic: 'grafana-live-result',
      grafanaOrigin: 'http://127.0.0.1:3000',
    },
  }, 'confirmation');
  assert.equal(missingService.status, 'FAIL');
  assert.match(
    missingService.evidence,
    /origin|endpoint|host|service|grafana|url/i,
    `missing-service FAIL must cite missing/invalid service URL, got: ${missingService.evidence}`,
  );
});

test('timeout terminates descendants before they can mutate evidence', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-timeout-tree-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-timeout-tree-logs-'));
  const marker = path.join(repo, 'descendant-survived.txt');
  const ready = path.join(repo, 'descendant-ready.txt');
  const descendant = "const fs=require('node:fs');fs.writeFileSync(process.env.TIMEOUT_READY,String(process.pid));setTimeout(()=>fs.writeFileSync(process.env.TIMEOUT_MARKER,'survived'),900)";
  const execute = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
    env: { ...process.env, TIMEOUT_MARKER: marker, TIMEOUT_READY: ready },
    timeoutMs: 350,
  });
  const command = `const child=require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(descendant)}],{stdio:'ignore',env:process.env,detached:process.platform==='win32'});child.unref();setInterval(()=>{},1000)`;
  const result = await execute({ id: 'timeout-tree', command }, 'qualification');
  await access(ready);
  await new Promise((resolve) => setTimeout(resolve, 1000));
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.equal(result.timedOut, true);
  assert.equal(result.terminationStatus, 'PASS', result.terminationEvidence);
  await assert.rejects(access(marker));
});

test('failed tree termination latches the executor and prevents later commands', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-termination-failure-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-termination-failure-logs-'));
  const marker = path.join(repo, 'later-command-ran.txt');
  const execute = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
    timeoutMs: 40,
    terminationGraceMs: 100,
    terminateTree: async ({ child }) => {
      child.kill('SIGKILL');
      return { status: 'BLOCKED', evidence: 'Process-tree termination could not be proven.', escalated: true };
    },
  });
  const timedOut = await execute({ id: 'stuck', command: 'setInterval(()=>{},1000)' }, 'qualification');
  const later = await execute({
    id: 'later',
    command: `require('node:fs').writeFileSync(${JSON.stringify(marker)},'ran')`,
  }, 'qualification');
  assert.equal(timedOut.terminationStatus, 'BLOCKED');
  assert.match(timedOut.terminationEvidence, /could not be proven/i);
  assert.equal(later.status, 'BLOCKED');
  assert.match(later.evidence, /unsafe process tree/i);
  await assert.rejects(access(marker));
});

test('preflight treats warning output from a successful probe as failure', async () => {
  const result = await runPreflight({
    repo: process.cwd(),
    config: { minFreeDiskGb: 0 },
    probeCommand: async (command) => ({
      exitCode: 0,
      stdout: command.startsWith('node --version') ? 'DeprecationWarning: broken toolchain' : 'version 1',
      stderr: '',
    }),
    diskFreeGb: async () => 10,
  });
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.ok(result.checks.some(({ name, status }) => name === 'node' && status === 'FAIL'));
});

test('preflight converts rejecting service probes into BLOCKED checks instead of aborting the workflow', async () => {
  // An invalid host/port (or transient socket rejection) used to bubble up
  // through runPreflight and abort runCloseoutWorkflow's Promise.all, which
  // prevented writing any structured evidence report. Probes that reject must
  // now become BLOCKED entries so the workflow can still produce a report.
  const explodingRedis = async () => { throw new Error('invalid port'); };
  const explodingTcp = async () => { throw new Error('ECONNREFUSED'); };
  const explodingHttp = async () => { throw new Error('grafana unreachable'); };
  const result = await runPreflight({
    repo: process.cwd(),
    config: {
      minFreeDiskGb: 0,
      services: { redis: { host: '127.0.0.1', port: NaN }, grafana: { url: 'http://127.0.0.1:1' } },
      ports: [{ name: 'broken', host: '127.0.0.1', port: 'not-a-number' }],
    },
    probeCommand: async () => ({ exitCode: 0, stdout: 'v1', stderr: '' }),
    diskFreeGb: async () => 10,
    probeRedis: explodingRedis,
    probeTcp: explodingTcp,
    probeHttp: explodingHttp,
  });
  assert.notEqual(result.status, 'FAIL');
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  const redis = result.checks.find((c) => c.name === 'redis');
  const grafana = result.checks.find((c) => c.name === 'grafana');
  const port = result.checks.find((c) => c.name.startsWith('port:'));
  assert.equal(redis.status, 'BLOCKED');
  assert.match(redis.evidence, /invalid port/i);
  assert.equal(grafana.status, 'BLOCKED');
  assert.match(grafana.evidence, /grafana unreachable/i);
  assert.equal(port.status, 'BLOCKED');
  assert.match(port.evidence, /ECONNREFUSED/i);
});

test('captures write-stream errors in logWriteError instead of crashing', async () => {
  const badLogPath = path.join(tmpdir(), `closeout-missing-${Date.now()}-dir`, 'nested', 'log.txt');
  const result = await spawnCaptured({
    command: "process.stdout.write('hello')",
    cwd: process.cwd(),
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
    timeoutMs: 5000,
    env: process.env,
    logPath: badLogPath,
  });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, 'hello');
  assert.ok(result.logWriteError, 'logWriteError must be populated when the write stream fails');
  assert.equal(typeof result.logWriteError, 'string');
});

test('refuses to write a raw evidence log through a pre-existing symlink, without crashing', async (t) => {
  // A reused or caller-supplied outputDir can already contain this
  // predictable log path as a symlink; the append-mode write stream must
  // reject it instead of following it, and — like any other log open
  // failure — degrade to logWriteError rather than aborting a command that
  // has not even started yet.
  const logDir = await mkdtemp(path.join(tmpdir(), 'closeout-log-symlink-'));
  const outsideDir = await mkdtemp(path.join(tmpdir(), 'closeout-log-symlink-outside-'));
  const outsideTarget = path.join(outsideDir, 'clobber-me.txt');
  await writeFile(outsideTarget, 'do not overwrite this\n', 'utf8');
  const logPath = path.join(logDir, 'qualification.typecheck.attempt-001.log');
  try {
    await symlink(outsideTarget, logPath);
  } catch (error) {
    // File symlinks need SeCreateSymbolicLinkPrivilege on Windows.
    await rm(logDir, { recursive: true, force: true });
    await rm(outsideDir, { recursive: true, force: true });
    t.skip(`file symlinks unavailable here: ${error?.code || error}`);
    return;
  }
  try {
    const result = await spawnCaptured({
      command: "process.stdout.write('hello')",
      cwd: process.cwd(),
      shell: process.execPath,
      shellArgs: (command) => ['-e', command],
      timeoutMs: 5000,
      env: process.env,
      logPath,
    });
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, 'hello');
    assert.match(result.logWriteError, /symlink/i);

    const untouched = await readFile(outsideTarget, 'utf8');
    assert.equal(untouched, 'do not overwrite this\n', 'the symlink target must not be modified');
    const linkInfo = await lstat(logPath);
    assert.equal(linkInfo.isSymbolicLink(), true, 'the symlink itself must not be replaced');
  } finally {
    await rm(logDir, { recursive: true, force: true });
    await rm(outsideDir, { recursive: true, force: true });
  }
});

test('refuses to append a raw evidence log through a pre-existing hard link, without crashing', async () => {
  // Hard links need no symlink privilege and give a second name to the same
  // inode: appending through the predictable log path would modify the
  // outside file. The append stream must revalidate the opened descriptor
  // (regular file, nlink === 1, mirroring the header writer) and degrade to
  // logWriteError instead of appending.
  const logDir = await mkdtemp(path.join(tmpdir(), 'closeout-log-hardlink-'));
  const outsideDir = await mkdtemp(path.join(tmpdir(), 'closeout-log-hardlink-outside-'));
  const outsideTarget = path.join(outsideDir, 'clobber-me.txt');
  await writeFile(outsideTarget, 'do not overwrite this\n', 'utf8');
  // Codex UiXEj: the rejected write must not even *touch* permissions on the
  // shared inode. Pin a distinctive mode before linking so a regression
  // (chmod(0600) running before the nlink check) is caught even though 0600
  // happens to be a common default already.
  if (process.platform !== 'win32') await chmod(outsideTarget, 0o644);
  const logPath = path.join(logDir, 'qualification.typecheck.attempt-001.log');
  await link(outsideTarget, logPath);
  try {
    const result = await spawnCaptured({
      command: "process.stdout.write('hello')",
      cwd: process.cwd(),
      shell: process.execPath,
      shellArgs: (command) => ['-e', command],
      timeoutMs: 5000,
      env: process.env,
      logPath,
    });
    assert.equal(result.exitCode, 0);
    assert.equal(result.stdout, 'hello');
    assert.match(result.logWriteError, /hard links/i);

    const untouched = await readFile(outsideTarget, 'utf8');
    assert.equal(untouched, 'do not overwrite this\n', 'the hard-linked outside file must not be modified');
    if (process.platform !== 'win32') {
      const outsideMode = (await stat(outsideTarget)).mode & 0o777;
      assert.equal(
        outsideMode,
        0o644,
        'the hard-linked outside file must keep its own permissions, not the evidence-log chmod(0600)',
      );
    }
  } finally {
    await rm(logDir, { recursive: true, force: true });
    await rm(outsideDir, { recursive: true, force: true });
  }
});

test('refuses to write a command executor log header through a pre-existing symlink', async (t) => {
  // Same predictable-path threat as the append-stream case above, but for
  // the "command: ...\ncwd: ..." header createCommandExecutor writes before
  // spawnCaptured ever runs. This call has no local try/catch (matching the
  // plain writeFile it replaced): a genuine open failure here propagates to
  // whatever pool/phase runner is driving execute(), the same as it always
  // has for any other log-open failure at this call site.
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-header-symlink-'));
  const outsideDir = await mkdtemp(path.join(tmpdir(), 'closeout-header-symlink-outside-'));
  const outsideTarget = path.join(outsideDir, 'clobber-me.txt');
  await writeFile(outsideTarget, 'do not overwrite this\n', 'utf8');
  await mkdir(path.join(outputDir, 'logs'), { recursive: true });
  try {
    await symlink(outsideTarget, path.join(outputDir, 'logs', 'qualification.probe.attempt-001.log'));
  } catch (error) {
    // File symlinks need SeCreateSymbolicLinkPrivilege on Windows.
    await rm(outputDir, { recursive: true, force: true });
    await rm(outsideDir, { recursive: true, force: true });
    t.skip(`file symlinks unavailable here: ${error?.code || error}`);
    return;
  }
  try {
    const execute = createCommandExecutor({
      repo: process.cwd(),
      outputDir,
      shell: process.execPath,
      shellArgs: (command) => ['-e', command],
    });
    await assert.rejects(
      () => execute({ id: 'probe', command: "process.stdout.write('clean output')" }, 'qualification'),
      /symlink/i,
    );
    const untouched = await readFile(outsideTarget, 'utf8');
    assert.equal(untouched, 'do not overwrite this\n', 'the symlink target must not be modified');
  } finally {
    await rm(outputDir, { recursive: true, force: true });
    await rm(outsideDir, { recursive: true, force: true });
  }
});

test('revalidates the logs directory before the proof-command log write, not just once', async (t) => {
  // CodeRabbit UguCb: the logs-directory containment check ran once per
  // check(), before the main command's log header was written. A check's
  // main command can run for its full configured timeout before the proof
  // command's own log header is written -- if outputDir/logs is swapped for
  // a symlink in that window (standing in for a concurrently running check,
  // or the command under test, mutating the shared output directory), the
  // stale one-time check must not let the later proof-log write silently
  // follow it outside outputDir.
  //
  // The swap-attempt loop below races the whole check() call, so it can
  // also land in the brief (pre-existing, accepted) gap between the FIRST
  // ensureLogsDirSecured() call and the main log's own write -- narrowing
  // that gap rather than eliminating it is a documented tradeoff of this
  // design (Node's fs/promises has no directory-fd-based open to close it
  // fully), and it applies equally on both sides of this fix. Landing there
  // can leak the *main* log into attackerDir even though the fix works
  // correctly. What UguCb specifically guarantees is narrower and is what
  // this test asserts: no matter when the swap lands, the *proof*-command
  // log must never be written through the swapped-in directory, because the
  // second ensureLogsDirSecured() call revalidates immediately beforehand.
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-logsdir-swap-'));
  const attackerDir = await mkdtemp(path.join(tmpdir(), 'closeout-logsdir-swap-attacker-'));
  const logsDir = path.join(outputDir, 'logs');
  try {
    const execute = createCommandExecutor({
      repo: process.cwd(),
      outputDir,
      shell: process.execPath,
      shellArgs: (command) => ['-e', command],
    });
    const resultPromise = execute({
      id: 'logsdir-swap',
      command: "setTimeout(() => process.stdout.write('main-done'), 150)",
      proof: {
        type: 'command',
        command: "process.stdout.write('proof-ran')",
        expectedPattern: 'literal:proof-ran',
      },
    }, 'qualification');
    // The main command's own log append-stream keeps logsDir's header file
    // open (and, on Windows, the whole directory un-renameable) for its
    // entire ~150ms run, so the earliest real opportunity to swap it is
    // whenever that stream closes. Retry back-to-back with no delay between
    // attempts -- standing in for a genuinely concurrent check racing to
    // replace outputDir/logs -- rather than polling on a fixed interval,
    // which under this environment's variable fs-call latency was
    // empirically far less reliable at catching the window at all (a 5ms
    // poll interval let the window close unattempted often enough to stall
    // the whole swap for the rest of the test run).
    let swapped = false;
    let stop = false;
    let attempt = 0;
    const attemptSwap = async () => {
      if (swapped) return;
      // Unique per attempt: ensureLogsDirSecured's mkdir can recreate a
      // plain logsDir between this rename and the symlink call below,
      // making the symlink step fail. A fixed moved-aside destination
      // would then stay permanently occupied by that orphaned directory,
      // blocking every later rename attempt (EPERM) for the rest of the
      // test -- silently stalling the swap forever instead of retrying.
      const movedAside = `${logsDir}.moved-aside-${attempt}`;
      attempt += 1;
      try {
        // Not atomic (rename away, then symlink in) -- a real attacker
        // faces the same two-step gap, since POSIX rename cannot replace a
        // directory with a symlink in one call. The check must come out
        // safe whichever half of that gap it lands in: either it still
        // sees the (moved-aside) directory as gone and fails the open, or
        // it sees the newly created symlink and rejects outright. Neither
        // may let evidence land inside attackerDir.
        await rename(logsDir, movedAside);
        await symlink(attackerDir, logsDir, 'junction');
        swapped = true;
      } catch {
        // logsDir not yet free (still open), already swapped, or the
        // symlink step lost a race with a fresh mkdir; retry immediately.
      }
    };
    const retryLoop = (async () => {
      while (!stop && !swapped) {
        await attemptSwap();
      }
    })();
    let result;
    let rejection;
    try {
      result = await resultPromise;
    } catch (error) {
      rejection = error;
    } finally {
      stop = true;
      await retryLoop;
    }
    if (!swapped) {
      // Losing the setup race (e.g. an open append-stream keeps logsDir
      // un-renameable for the whole run, common on Windows) means the attack
      // scenario was never reproduced -- it does NOT mean the product
      // misbehaved. Report inconclusive rather than failing the whole test.
      t.diagnostic('could not win the logsDir swap race; setup inconclusive');
      return;
    }
    // The precise failure mode depends on exactly which window the swap
    // lands in: the second ensureLogsDirSecured() call rejects outright if
    // logsDir is already a symlink or already resolves outside outputDir
    // ("symlinked logs directory" / "outside the output directory"); a swap
    // landing in the narrower residual gap between that call and the actual
    // open is caught either as a raw ENOENT (open attempted while logsDir was
    // moved-aside and not yet re-created) or by assertLogParentIdentity's
    // post-open dev/ino comparison ("unverifiable parent directory" /
    // "swapped after validation") -- or, rarely, as a BLOCKED/FAIL result
    // instead of a thrown rejection. Every one of these is safe; only a
    // silent PASS built on evidence written through the swapped directory is
    // not.
    if (rejection) {
      assert.match(
        rejection.message,
        /symlinked logs directory|outside the output directory|unverifiable parent directory|swapped after validation|ENOENT/,
      );
    } else {
      assert.notEqual(result.status, 'PASS', `must not PASS with evidence redirected through a swapped logs directory: ${JSON.stringify(result)}`);
    }
    const attackerContents = await readdir(attackerDir);
    // Only the proof-log write is asserted against here (not "must be
    // totally empty"): the main log can legitimately land in the earlier,
    // pre-existing accepted gap described above, but the proof log must
    // never appear -- that guarantee is exactly what the second
    // ensureLogsDirSecured() call (this fix) provides.
    const leakedProofEvidence = attackerContents.filter((name) => name.includes('.proof.'));
    assert.deepEqual(leakedProofEvidence, [], `proof-command evidence must never land inside the swapped-in directory: ${JSON.stringify(attackerContents)}`);
  } finally {
    await rm(outputDir, { recursive: true, force: true }).catch(() => {});
    await rm(attackerDir, { recursive: true, force: true }).catch(() => {});
  }
});

test('binds an evidence log header write to the validated logs directory identity', async () => {
  // CodeRabbit UguCb: openLogNoFollow's O_NOFOLLOW guards only the final path
  // component, not the parent logs directory. Binding the header open to the
  // dev/ino ensureLogsDirSecured() captured must reject a write whose parent
  // no longer matches -- before truncating any prior content -- while still
  // writing when the identity matches.
  const logsDir = await mkdtemp(path.join(tmpdir(), 'closeout-dir-bind-'));
  const logPath = path.join(logsDir, 'qualification.probe.attempt-001.log');
  try {
    await writeFile(logPath, 'PRIOR-EVIDENCE', 'utf8');
    const real = await lstat(logsDir);
    // A mismatching identity stands in for a logsDir swapped between
    // validation and this open (same filesystem, different inode).
    await assert.rejects(
      writeLogHeaderNoFollow(logPath, 'command: x\ncwd: <repo>\n', { dev: real.dev + 1, ino: real.ino }),
      /logs directory swapped after validation/,
    );
    // Rejected before truncate: the prior content is intact.
    assert.equal(await readFile(logPath, 'utf8'), 'PRIOR-EVIDENCE');
    // The matching identity still writes the header (happy path preserved).
    await writeLogHeaderNoFollow(logPath, 'command: ok\ncwd: <repo>\n', { dev: real.dev, ino: real.ino });
    assert.match(await readFile(logPath, 'utf8'), /^command: ok/);
  } finally {
    await rm(logsDir, { recursive: true, force: true });
  }
});

test(
  'protects a written evidence log with a current-user-only Windows ACL',
  { skip: process.platform !== 'win32' && 'Windows ACL semantics only', timeout: 20000 },
  async () => {
    // Codex Ugisp: chmod(0600) at evidence-log open time is a no-op against
    // Windows' inherited DACL, so a log written into a directory whose
    // inherited ACL grants other local users access would otherwise stay
    // readable by them. openLogNoFollow must establish and verify the same
    // current-user-only ACL invariant already covered for the debug
    // collector's token/session-log writes (debug_server.test.js).
    const logDir = await mkdtemp(path.join(tmpdir(), 'closeout-log-acl-'));
    const logPath = path.join(logDir, 'qualification.typecheck.attempt-001.log');
    try {
      // Codex UiTM8: a fresh mkdtemp directory is already effectively
      // owner-only, so the ACL assertion below could pass vacuously without
      // protectWindowsPrivateFile actually removing anything. Reproduce the
      // scenario it guards -- a directory whose INHERITED ACL grants other
      // local users access -- by granting the well-known Users group
      // (S-1-5-32-545) an inheritable (object + container) read ACE. The log
      // file created inside then inherits it, so the post-run assertion
      // genuinely proves inheritance was broken by protectWindowsPrivateFile.
      const grant = spawnSync('icacls', [logDir, '/grant', '*S-1-5-32-545:(OI)(CI)(R)'], {
        encoding: 'utf8',
        windowsHide: true,
        timeout: 15000,
      });
      assert.equal(grant.status, 0, `icacls grant failed: ${grant.stdout}\n${grant.stderr}`);
      const result = await spawnCaptured({
        command: "process.stdout.write('hello')",
        cwd: process.cwd(),
        shell: process.execPath,
        shellArgs: (command) => ['-e', command],
        timeoutMs: 5000,
        env: process.env,
        logPath,
      });
      assert.equal(result.exitCode, 0);
      assert.equal(result.logWriteError, null);
      const acl = windowsAclIsCurrentUserOnly(logPath);
      assert.equal(acl.status, 0, `${acl.stdout}\n${acl.stderr}`);
      assert.equal(acl.stdout.trim(), 'ok');
    } finally {
      await rm(logDir, { recursive: true, force: true });
    }
  },
);

test('treats common database password env vars as sensitive', () => {
  // PGPASSWORD and MYSQL_PWD are standard database credential names that do
  // not contain any of the generic sensitive tokens (PASSWORD/PWD match no
  // segment boundary), so they must be named explicitly. Otherwise ambient
  // database credentials are forwarded to child commands and left visible in
  // captured evidence.
  const child = buildChildEnvironment({
    PGPASSWORD: 'pg-secret-123',
    MYSQL_PWD: 'mysql-secret-456',
    PGUSER: 'hunter',
    PATH: '/usr/bin',
  }, []);
  assert.equal(child.PGPASSWORD, undefined);
  assert.equal(child.MYSQL_PWD, undefined);
  assert.equal(child.PGUSER, 'hunter');
  assert.equal(child.PATH, '/usr/bin');
  assert.equal(redactSecrets('pw=pg-secret-123', { PGPASSWORD: 'pg-secret-123' }), 'pw=[REDACTED]');
  assert.equal(redactSecrets('pwd=mysql-secret-456', { MYSQL_PWD: 'mysql-secret-456' }), 'pwd=[REDACTED]');
  // Azure-style AccountKey leaves extracted from connection strings must
  // redact even when only the key value is printed by a CLI.
  const azureKey = 'SuperSecretAccountKeyValue99';
  const azureConn = `DefaultEndpointsProtocol=https;AccountName=demo;AccountKey=${azureKey};EndpointSuffix=core.windows.net`;
  assert.equal(
    redactSecrets(`isolated=${azureKey}`, { AZURE_STORAGE_CONNECTION_STRING: azureConn }, ['AZURE_STORAGE_CONNECTION_STRING']).includes(azureKey),
    false,
    'AccountKey leaf must be redacted when printed alone',
  );
});

test('redacts credential leaves from URL query parameters', () => {
  // A sensitive env value can be a URL carrying a query credential, e.g.
  // AUTH_CONFIG=https://host/callback?token=supersecretvalue123. A tool that
  // prints just the query token leaf must still be redacted, not only the
  // whole URL or its userinfo components.
  const leaf = 'supersecretvalue123';
  const value = `https://host/callback?token=${leaf}&next=/home`;
  const output = redactSecrets(`config=${value} isolated=${leaf}`, { AUTH_CONFIG: value }, ['AUTH_CONFIG']);
  assert.equal(output.includes(leaf), false, 'the URL query token leaf must be redacted');
  assert.match(output, /isolated=\[REDACTED\]/);
});

test('preflight preserves and redacts safeEnv credentials', async () => {
  // safeEnv entries are deliberately kept in the probe child environment and
  // must also be treated as explicitly-redacted inputs for probe evidence,
  // exactly like requiredEnv (mirroring the executor's secretNames). A probe
  // echoing a custom registry/auth value must not persist it in the report.
  const secret = 's3cr3t-registry-value';
  const result = await runPreflight({
    repo: process.cwd(),
    config: { requiredEnv: [], safeEnv: ['REGISTRY_LOGIN'], minFreeDiskGb: 0 },
    env: { REGISTRY_LOGIN: secret },
    probeCommand: async () => ({ exitCode: 0, stdout: `login ${secret}`, stderr: '' }),
    diskFreeGb: async () => 10,
  });
  assert.doesNotMatch(JSON.stringify(result.checks), /s3cr3t-registry-value/);
  assert.ok(Object.values(result.toolVersions).every((version) => !version.includes(secret)));
});

test('probeCommandDefault runs commands through a non-login shell (--noprofile --norc -c)', async () => {
  // Exercise the DEFAULT preflight probe path (not a stubbed probeCommand) to
  // guard the shell invocation: probeCommandDefault must use the same safe
  // argv as the executor (`--noprofile --norc -c`) so shell profiles cannot
  // inject side effects, while still resolving tools already on PATH.
  const { defaultShellArgs } = require('./pr_closeout_process');
  // Bash-compatible shells enable errexit + pipefail so compound/pipeline
  // failures cannot PASS (Codex #4781495663).
  assert.deepEqual(defaultShellArgs('true'), ['--noprofile', '--norc', '-c', 'set -eo pipefail; true']);
  assert.deepEqual(defaultShellArgs('true', 'bash'), ['--noprofile', '--norc', '-c', 'set -eo pipefail; true']);
  assert.deepEqual(defaultShellArgs('true', '/bin/bash'), ['--noprofile', '--norc', '-c', 'set -eo pipefail; true']);
  // Non-bash shells still require pipefail (fail closed if unsupported) so
  // pipeline left-hand failures cannot PASS (Codex #4781637950).
  assert.deepEqual(defaultShellArgs('true', 'zsh'), ['-c', 'set -e; set -o pipefail; true']);
  assert.deepEqual(defaultShellArgs('true', '/bin/dash'), ['-c', 'set -e; set -o pipefail; true']);
  assert.deepEqual(defaultShellArgs('true', 'C:\\\\Program Files\\\\Git\\\\bin\\\\bash.exe'), ['--noprofile', '--norc', '-c', 'set -eo pipefail; true']);
  const shell = resolveCommandShell({ env: process.env });
  const result = await probeCommandDefault({
    command: 'printf %s probe-default-ok',
    repo: process.cwd(),
    shell,
    env: process.env,
  });
  assert.equal(result.exitCode, 0, `default probe must succeed via non-login shell: ${JSON.stringify(result)}`);
  assert.equal(result.stdout, 'probe-default-ok');
  assert.equal(result.terminationStatus, 'PASS');
});

test('probeCommandDefault clears timeout timers so a fast probe does not hold the process', async () => {
  // Regression for Codex #4780229514: without clearTimeout on the close path,
  // eight preflight probes left eight 120s timers and npm test hung ~152s.
  const before = process.getActiveResourcesInfo
    ? process.getActiveResourcesInfo().filter((name) => name === 'Timeout').length
    : null;
  const shell = resolveCommandShell({ env: process.env });
  await probeCommandDefault({
    command: 'true',
    repo: process.cwd(),
    shell,
    env: process.env,
    timeoutMs: 120_000,
  });
  if (before !== null) {
    const after = process.getActiveResourcesInfo().filter((name) => name === 'Timeout').length;
    // Allow incidental timers from the test harness; the probe itself must not
    // leave a 120s timer behind.
    assert.ok(after <= before + 1, `expected no leaked probe timeout (before=${before}, after=${after})`);
  }
});

test('runPreflight BLOCKs when a probe reports process-tree cleanup failure', async () => {
  // Even if a version probe exits 0, an unreaped descendant must refuse
  // admission — matching the main command executor's terminationStatus latch.
  const result = await runPreflight({
    repo: process.cwd(),
    config: { minFreeDiskGb: 0 },
    env: process.env,
    probeCommand: async () => ({
      exitCode: 0,
      stdout: 'v1.0.0',
      stderr: '',
      terminationStatus: 'BLOCKED',
      terminationEvidence: 'Detached orphan still alive after SIGKILL.',
    }),
    diskFreeGb: async () => 10,
  });
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  const blockedProbe = result.checks.find(
    ({ name, status }) => name === 'git' && status === 'BLOCKED',
  );
  assert.ok(blockedProbe, `expected a BLOCKED tool probe: ${JSON.stringify(result.checks)}`);
  assert.match(blockedProbe.evidence, /orphan|SIGKILL|process-tree|cleanup/i);
});

test('preflight resolves required env names case-insensitively', async () => {
  // buildChildEnvironment and buildSecretReplacements match configured names
  // case-insensitively; the preflight presence check must do the same so a
  // config listing "npm_token" sees NPM_TOKEN instead of blocking as missing.
  const result = await runPreflight({
    repo: process.cwd(),
    config: { requiredEnv: ['npm_token'], minFreeDiskGb: 0 },
    env: { NPM_TOKEN: 'abcd1234' },
    probeCommand: async () => ({ exitCode: 0, stdout: 'v1', stderr: '' }),
    diskFreeGb: async () => 10,
  });
  const credential = result.checks.find(({ name }) => name === 'env:npm_token');
  assert.equal(credential.status, 'PASS');
  assert.equal(credential.evidence, 'present');
});

test('terminates background descendants left behind by a cleanly exiting command', { timeout: 20000 }, async (t) => {
  // POSIX-only: this sweeps the command's process group. Windows has no
  // process groups to probe once the root has exited, so the win32 path can
  // only report the root as already gone (covered by the terminateProcessTree
  // unit tests below).
  if (process.platform === 'win32') { t.skip('posix-only test'); return; }
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-clean-tree-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-clean-tree-logs-'));
  const marker = path.join(repo, 'descendant-survived.txt');
  const descendant = "setInterval(()=>{},1000);setTimeout(()=>require('node:fs').writeFileSync(process.env.CLEAN_MARKER,'survived'),600)";
  const execute = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
    env: { ...process.env, CLEAN_MARKER: marker },
  });
  const command = `const child=require('node:child_process').spawn(process.execPath,['-e',${JSON.stringify(descendant)}],{stdio:'ignore',env:process.env});child.unref();process.exit(0)`;
  const result = await execute({ id: 'clean-exit-tree', command }, 'qualification');
  assert.equal(result.status, 'PASS', result.evidence);
  assert.equal(result.terminationStatus, 'PASS', result.terminationEvidence);
  await new Promise((resolve) => setTimeout(resolve, 1200));
  await assert.rejects(access(marker));
});

test('terminates detached/setsid descendants that leave the process group', { timeout: 20000 }, async (t) => {
  // POSIX + /proc only: a validation script can `detached:true` / setsid a
  // child, exit 0, and leave a descendant outside the original process group.
  // Group kill alone would PASS; the spawn-mark environ sweep must still reap
  // it before the command is considered clean.
  if (process.platform === 'win32') { t.skip('posix-only test'); return; }
  if (listLivePidsWithSpawnMark('probe-no-such-mark') === null) { t.skip('requires /proc'); return; }
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-setsid-tree-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-setsid-tree-logs-'));
  const marker = path.join(repo, 'setsid-survived.txt');
  const ready = path.join(repo, 'setsid-ready.txt');
  const descendant = "const fs=require('node:fs');fs.writeFileSync(process.env.SETSID_READY,String(process.pid));setInterval(()=>{},1000);setTimeout(()=>fs.writeFileSync(process.env.SETSID_MARKER,'survived'),800)";
  const execute = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
    env: { ...process.env, SETSID_MARKER: marker, SETSID_READY: ready },
  });
  // detached:true puts the grandchild in a new session/process group so the
  // original group can exit empty while the orphan still holds the spawn mark.
  const command = [
    'const {spawn}=require("node:child_process");',
    `const child=spawn(process.execPath,["-e",${JSON.stringify(descendant)}],{stdio:"ignore",env:process.env,detached:true});`,
    'child.unref();',
    // Give the detached child time to start and inherit the spawn mark before
    // the process-group leader exits 0.
    'setTimeout(()=>process.exit(0),250);',
  ].join('');
  const result = await execute({ id: 'setsid-exit-tree', command }, 'qualification');
  assert.equal(result.terminationStatus, 'PASS', result.terminationEvidence);
  assert.match(result.terminationEvidence || '', /spawn-mark|Process group/i);
  await new Promise((resolve) => setTimeout(resolve, 1200));
  await assert.rejects(access(marker), 'detached descendant must not mutate the worktree after termination');
});

test('cwd/fd probe discovers mark-free processes that hold an open repo fd', { timeout: 15000 }, async (t) => {
  // Discovery helper listLivePidsWithCwdUnder still finds mark-free processes
  // that hold a repo fd (useful diagnostics). Orphan kill path no longer
  // reaps by cwd/fd alone — only spawn-mark PIDs are signaled. POSIX + /proc.
  if (process.platform === 'win32') { t.skip('posix-only test'); return; }
  if (listLivePidsWithSpawnMark('probe-no-such-mark') === null) { t.skip('requires /proc'); return; }
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-fd-sweep-'));
  let childPid = 0;
  let pipePid = 0;
  try {
    const held = path.join(repo, 'held.txt');
    await writeFile(held, 'open-handle');
    // Detached grandchild: carries no spawn mark, chdir's to tmpdir, but holds
    // an open read handle to a file inside the repo.
    const grandchild = [
      'const fs=require("node:fs");const os=require("node:os");const path=require("node:path");',
      'fs.openSync(path.join(process.argv[1],"held.txt"),"r");',
      'process.chdir(os.tmpdir());',
      'process.stdout.write(String(process.pid));',
      'setInterval(()=>{},10000);',
    ].join('');
    const child = spawn(process.execPath, ['-e', grandchild, repo], {
      stdio: ['ignore', 'pipe', 'ignore'],
      detached: true,
    });
    child.unref();
    child.stdout.on('data', (chunk) => { childPid = Number(String(chunk).trim()); });
    // Wait for the grandchild to start, chdir, and open the handle.
    for (let i = 0; i < 40 && !childPid; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(childPid > 0, 'grandchild must report its pid');

    const found = listLivePidsWithCwdUnder(repo, { selfPid: process.pid });
    assert.ok(found !== null, '/proc must be available');
    assert.ok(
      found.includes(childPid),
      `fd-holding orphan ${childPid} must be found by the sweep, got: ${JSON.stringify(found)}`,
    );

    // A sibling orphan that holds ONLY a pipe/socket (no repo file) must NOT be
    // reaped: pseudo fd targets like `pipe:[…]` are not absolute paths, so the
    // sweep must ignore them to avoid killing an unrelated process.
    const pipeOnly = [
      'const os=require("node:os");',
      'process.chdir(os.tmpdir());',
      'process.stdout.write(String(process.pid));',
      'setInterval(()=>{},10000);',
    ].join('');
    const pipeChild = spawn(process.execPath, ['-e', pipeOnly], {
      stdio: ['ignore', 'pipe', 'ignore'],
      detached: true,
    });
    pipeChild.unref();
    pipeChild.stdout.on('data', (chunk) => { pipePid = Number(String(chunk).trim()); });
    for (let i = 0; i < 40 && !pipePid; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(pipePid > 0, 'pipe-only orphan must report its pid');
    const found2 = listLivePidsWithCwdUnder(repo, { selfPid: process.pid });
    assert.ok(
      !(found2 || []).includes(pipePid),
      `pipe-only orphan ${pipePid} must NOT be reaped, got: ${JSON.stringify(found2)}`,
    );
  } finally {
    // Clean up both detached orphans even if an assertion throws mid-test.
    if (childPid) { try { process.kill(childPid, 'SIGKILL'); } catch {} }
    if (pipePid) { try { process.kill(pipePid, 'SIGKILL'); } catch {} }
    await rm(repo, { recursive: true, force: true });
  }
});

test('cwd/fd probe excludes a same-repo sibling still running under the runner', { timeout: 15000 }, async (t) => {
  // Codex UDDP_: with the runner's default parallelism 4, concurrent checks
  // share the repo as cwd in their own sessions. The mark-free cwd/fd
  // fallback must not attribute such a still-running SIBLING — an unbroken
  // PPID chain to the runner that never passes through this spawn's root —
  // to this spawn as a detached descendant. POSIX + /proc only.
  if (process.platform === 'win32') { t.skip('posix-only test'); return; }
  if (listLivePidsWithSpawnMark('probe-no-such-mark') === null) { t.skip('requires /proc'); return; }
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-sibling-sweep-'));
  let siblingPid = 0;
  let siblingHandle = null;
  try {
    // An exited stand-in for this spawn's root pid.
    const exited = spawn(process.execPath, ['-e', ''], { stdio: 'ignore' });
    await new Promise((resolve) => exited.once('exit', resolve));
    const rootPid = exited.pid;
    // Sibling: detached (own session), cwd inside the repo, no spawn mark,
    // parented directly to this test process (the runner).
    const sibling = spawn(
      process.execPath,
      ['-e', 'process.stdout.write(String(process.pid));setInterval(()=>{},10000);'],
      { stdio: ['ignore', 'pipe', 'ignore'], cwd: repo, detached: true },
    );
    sibling.unref();
    siblingHandle = sibling;
    sibling.stdout.on('data', (chunk) => { siblingPid = Number(String(chunk).trim()); });
    for (let i = 0; i < 40 && !siblingPid; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(siblingPid > 0, 'sibling must report its pid');

    // Fixture validity: without a root pid the bare cwd probe does match it.
    const attributed = listLivePidsWithCwdUnder(repo, { selfPid: process.pid });
    assert.ok(
      (attributed || []).includes(siblingPid),
      `sibling ${siblingPid} must match the bare cwd probe, got: ${JSON.stringify(attributed)}`,
    );
    // With the spawn's root pid known, the sibling's unbroken chain to the
    // runner excludes it: it is not this spawn's detached orphan.
    const excluded = listLivePidsWithCwdUnder(repo, { selfPid: process.pid, rootPid });
    assert.ok(
      !(excluded || []).includes(siblingPid),
      `sibling ${siblingPid} chaining to the runner must be excluded, got: ${JSON.stringify(excluded)}`,
    );
    // End to end: the sweep must not BLOCK an otherwise-clean check over it.
    const sweep = await sweepDetachedOrphans({
      mark: 'probe-sibling-sweep-mark',
      cwd: repo,
      rootPid,
      kill: () => {},
      selfPid: process.pid,
    });
    assert.equal(sweep.status, 'PASS', statusDiag(sweep));
  } finally {
    for (const pid of new Set([siblingPid, siblingHandle?.pid].filter(Boolean))) {
      try { process.kill(pid, 'SIGKILL'); } catch {}
    }
    siblingHandle?.stdout?.destroy();
    await rm(repo, { recursive: true, force: true });
  }
});

test('cwd/fd probe still flags a mark-free orphan whose chain to the runner is broken', { timeout: 15000 }, async (t) => {
  // Fail-closed guard for the sibling exclusion (Codex UDDP_): a genuine
  // detached orphan's PPID chain dead-ends at the exited spawn root (absent
  // pid), so it must stay attributed and force BLOCKED. POSIX + /proc only.
  if (process.platform === 'win32') { t.skip('posix-only test'); return; }
  if (listLivePidsWithSpawnMark('probe-no-such-mark') === null) { t.skip('requires /proc'); return; }
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-broken-chain-'));
  let orphanPid = 0;
  let rootPid = 0;
  try {
    // Intermediate "spawn root": launches a detached, mark-free grandchild
    // with cwd inside the repo, reports the grandchild pid, then exits — the
    // grandchild is reparented and its chain to the runner breaks.
    const launcher = [
      'const {spawn}=require("node:child_process");',
      'const child=spawn(process.execPath,["-e","setInterval(()=>{},10000);"],{stdio:"ignore",cwd:process.argv[1],detached:true});',
      'process.stdout.write(String(child.pid));',
      'child.unref();',
      'setTimeout(()=>process.exit(0),200);',
    ].join('');
    const root = spawn(process.execPath, ['-e', launcher, repo], { stdio: ['ignore', 'pipe', 'ignore'] });
    rootPid = root.pid;
    root.stdout.on('data', (chunk) => { orphanPid = Number(String(chunk).trim()); });
    await new Promise((resolve) => root.once('exit', resolve));
    for (let i = 0; i < 40 && !orphanPid; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(orphanPid > 0, 'orphan pid must be reported');
    // Wait until the orphan is reparented away from the exited root, so its
    // PPID chain no longer passes through rootPid (broken chain).
    let ppid = rootPid;
    for (let i = 0; i < 40 && ppid === rootPid; i += 1) {
      try {
        const stat = readFileSync(`/proc/${orphanPid}/stat`, 'utf8');
        ppid = Number(stat.slice(stat.lastIndexOf(')') + 1).trimStart().split(/\s+/)[1]);
      } catch { break; }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.notEqual(ppid, rootPid, 'orphan must be reparented after the root exited');

    const found = listLivePidsWithCwdUnder(repo, { selfPid: process.pid, rootPid });
    assert.ok(
      (found || []).includes(orphanPid),
      `broken-chain orphan ${orphanPid} must stay flagged, got: ${JSON.stringify(found)}`,
    );
    const sweep = await sweepDetachedOrphans({
      mark: 'probe-broken-chain-mark',
      cwd: repo,
      rootPid,
      kill: () => {},
      selfPid: process.pid,
    });
    assert.equal(sweep.status, 'BLOCKED', statusDiag(sweep));
    assert.match(sweep.evidence, /mark-free/i);
  } finally {
    if (orphanPid) { try { process.kill(orphanPid, 'SIGKILL'); } catch {} }
    await rm(repo, { recursive: true, force: true });
  }
});

test('environHasAnySpawnMark only matches a mark registered in knownMarks', () => {
  // Codex UikN4 (P1): matching ANY self-reported value (the original Codex
  // UfzOf fix) let a hostile detached process simply set SPAWN_MARK_ENV to
  // an arbitrary string and be excluded from the mark-free orphan sweep
  // regardless of whether any real sibling ever generated that value. Only a
  // mark this run's own registry actually generated for a tracked sibling
  // may exclude a candidate; an unregistered value -- even one that looks
  // exactly like a real mark -- must not.
  const knownMarks = new Set(['some-other-checks-mark']);
  const foreign = Buffer.from(`PATH=/usr/bin\0${SPAWN_MARK_ENV}=some-other-checks-mark\0HOME=/root`, 'utf8');
  assert.equal(environHasAnySpawnMark(foreign, knownMarks), true);

  // Same environ, no registry entry for it: presence alone is no longer
  // sufficient (this is exactly the pre-fix behavior being closed).
  assert.equal(environHasAnySpawnMark(foreign), false);
  assert.equal(environHasAnySpawnMark(foreign, new Set()), false);

  const forged = Buffer.from(`PATH=/usr/bin\0${SPAWN_MARK_ENV}=attacker-forged-mark\0HOME=/root`, 'utf8');
  assert.equal(environHasAnySpawnMark(forged, knownMarks), false);

  const none = Buffer.from('PATH=/usr/bin\0HOME=/root', 'utf8');
  assert.equal(environHasAnySpawnMark(none, knownMarks), false);

  const nearMiss = Buffer.from(`PATH=/usr/bin\0${SPAWN_MARK_ENV}_OTHER=some-other-checks-mark`, 'utf8');
  assert.equal(environHasAnySpawnMark(nearMiss, knownMarks), false);

  assert.equal(environHasAnySpawnMark('', knownMarks), false);
});

test('cwd/fd probe excludes a live process carrying a different check\'s own spawn mark', { timeout: 15000 }, async (t) => {
  // Codex UfzOf (P1): under the default test-runner parallelism, a sibling
  // check's own live, mark-tracked descendant can have a PPID chain that
  // looks broken relative to THIS spawn's rootPid/selfPid purely because it
  // descends from a different root. Reproduce that exact shape -- a detached,
  // reparented (broken-chain) grandchild whose environ carries a *different*
  // check's spawn mark -- and assert it is excluded, not misattributed.
  if (process.platform === 'win32') { t.skip('posix-only test'); return; }
  if (listLivePidsWithSpawnMark('probe-no-such-mark') === null) { t.skip('requires /proc'); return; }
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-foreign-mark-'));
  let siblingPid = 0;
  let rootPid = 0;
  try {
    const launcher = [
      'const {spawn}=require("node:child_process");',
      `const child=spawn(process.execPath,["-e","setInterval(()=>{},10000);"],{stdio:"ignore",cwd:process.argv[1],detached:true,env:{...process.env,${SPAWN_MARK_ENV}:"some-other-checks-mark"}});`,
      'process.stdout.write(String(child.pid));',
      'child.unref();',
      'setTimeout(()=>process.exit(0),200);',
    ].join('');
    const root = spawn(process.execPath, ['-e', launcher, repo], { stdio: ['ignore', 'pipe', 'ignore'] });
    rootPid = root.pid;
    root.stdout.on('data', (chunk) => { siblingPid = Number(String(chunk).trim()); });
    await new Promise((resolve) => root.once('exit', resolve));
    for (let i = 0; i < 40 && !siblingPid; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(siblingPid > 0, 'sibling pid must be reported');
    let ppid = rootPid;
    for (let i = 0; i < 40 && ppid === rootPid; i += 1) {
      try {
        const stat = readFileSync(`/proc/${siblingPid}/stat`, 'utf8');
        ppid = Number(stat.slice(stat.lastIndexOf(')') + 1).trimStart().split(/\s+/)[1]);
      } catch { break; }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.notEqual(ppid, rootPid, 'sibling must be reparented after its own root exited');

    // Codex UikN4 (P1): exclusion now requires the sibling's mark to be a
    // member of this run's own registry of marks it actually generated, not
    // merely present. Register it here to prove the legitimate UfzOf case
    // still works under the stricter model.
    const knownSiblingMarks = new Set(['some-other-checks-mark']);
    const found = listLivePidsWithCwdUnder(repo, { selfPid: process.pid, rootPid, knownSiblingMarks });
    assert.ok(
      !(found || []).includes(siblingPid),
      `foreign-marked sibling ${siblingPid} must be excluded, got: ${JSON.stringify(found)}`,
    );
    const sweep = await sweepDetachedOrphans({
      mark: 'probe-this-checks-mark-does-not-match',
      cwd: repo,
      rootPid,
      kill: () => {},
      selfPid: process.pid,
      knownSiblingMarks,
    });
    assert.equal(sweep.status, 'PASS', statusDiag(sweep));
  } finally {
    if (siblingPid) { try { process.kill(siblingPid, 'SIGKILL'); } catch {} }
    await rm(repo, { recursive: true, force: true });
  }
});

test('cwd/fd probe does not exclude a live process carrying an unregistered (forged) spawn mark', { timeout: 15000 }, async (t) => {
  // Codex UikN4 (P1): the fix for Codex UfzOf above excluded any candidate
  // whose environ carried ANY OMO_CLOSEOUT_SPAWN_MARK value, trusting the
  // value merely because it existed. A hostile detached process could copy
  // or guess a plausible-looking mark string and escape the orphan sweep
  // entirely. Reproduce the identical reparented-sibling shape as the test
  // above, but WITHOUT ever registering its mark as a known sibling -- it
  // must stay flagged and the sweep must BLOCK, not PASS.
  if (process.platform === 'win32') { t.skip('posix-only test'); return; }
  if (listLivePidsWithSpawnMark('probe-no-such-mark') === null) { t.skip('requires /proc'); return; }
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-forged-mark-'));
  let siblingPid = 0;
  let rootPid = 0;
  try {
    const launcher = [
      'const {spawn}=require("node:child_process");',
      `const child=spawn(process.execPath,["-e","setInterval(()=>{},10000);"],{stdio:"ignore",cwd:process.argv[1],detached:true,env:{...process.env,${SPAWN_MARK_ENV}:"attacker-forged-mark"}});`,
      'process.stdout.write(String(child.pid));',
      'child.unref();',
      'setTimeout(()=>process.exit(0),200);',
    ].join('');
    const root = spawn(process.execPath, ['-e', launcher, repo], { stdio: ['ignore', 'pipe', 'ignore'] });
    rootPid = root.pid;
    root.stdout.on('data', (chunk) => { siblingPid = Number(String(chunk).trim()); });
    await new Promise((resolve) => root.once('exit', resolve));
    for (let i = 0; i < 40 && !siblingPid; i += 1) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.ok(siblingPid > 0, 'sibling pid must be reported');
    let ppid = rootPid;
    for (let i = 0; i < 40 && ppid === rootPid; i += 1) {
      try {
        const stat = readFileSync(`/proc/${siblingPid}/stat`, 'utf8');
        ppid = Number(stat.slice(stat.lastIndexOf(')') + 1).trimStart().split(/\s+/)[1]);
      } catch { break; }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.notEqual(ppid, rootPid, 'sibling must be reparented after its own root exited');

    // No knownSiblingMarks passed here -- this run never generated
    // "attacker-forged-mark" for any tracked sibling, so it must not be
    // trusted regardless of how legitimate it looks.
    const found = listLivePidsWithCwdUnder(repo, { selfPid: process.pid, rootPid });
    assert.ok(
      (found || []).includes(siblingPid),
      `forged-mark sibling ${siblingPid} must NOT be excluded, got: ${JSON.stringify(found)}`,
    );
    const sweep = await sweepDetachedOrphans({
      mark: 'probe-this-checks-mark-does-not-match',
      cwd: repo,
      rootPid,
      kill: () => {},
      selfPid: process.pid,
    });
    assert.equal(sweep.status, 'BLOCKED', statusDiag(sweep));
  } finally {
    if (siblingPid) { try { process.kill(siblingPid, 'SIGKILL'); } catch {} }
    await rm(repo, { recursive: true, force: true });
  }
});

test('sweep BLOCKs instead of PASSing when /proc is unavailable, on any host platform', (t) => {
  // Codex Ugisk (P1): on macOS and other non-Linux POSIX hosts, /proc never
  // exists, so listLivePidsWithSpawnMark always returned null there. The old
  // code treated that as PASS ("process-group containment only") solely
  // because process.platform !== 'linux', silently accepting weaker evidence
  // on non-Linux hosts even though a real setsid descendant could still be
  // alive and mutating the repo after the seal. This host genuinely lacks
  // /proc (Windows), so it exercises the exact real-world condition the
  // finding describes without needing to fake the platform.
  if (listLivePidsWithSpawnMark('probe-no-such-mark') !== null) { t.skip('requires a host without /proc'); return; }
  return sweepDetachedOrphans({ mark: 'probe-ugisk-no-proc', kill: () => {} }).then((result) => {
    assert.equal(result.status, 'BLOCKED', statusDiag(result));
    assert.match(result.evidence, /proc.*missing/i);
  });
});

test('still runs taskkill /T when the Windows root PID has already exited', async () => {
  // A clean root exit does not prove descendants are gone; always run
  // taskkill /T so children are targeted. Non-zero taskkill after the root is
  // ESRCH is still PASS (the /T attempt was made).
  let taskkillRan = false;
  const result = await terminateProcessTree({
    child: { pid: 424242 },
    platform: 'win32',
    kill: (pid, signal) => {
      assert.equal(signal, 0);
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file, args) => {
      taskkillRan = true;
      assert.match(file, /taskkill\.exe$/i);
      assert.deepEqual(args, ['/PID', '424242', '/T', '/F']);
      return { stdout: '', stderr: '' };
    },
  });
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.equal(result.escalated, true);
  assert.equal(taskkillRan, true);
  assert.match(result.evidence, /taskkill/i);
});

test('runs taskkill for a live Windows process tree', async () => {
  const calls = [];
  const result = await terminateProcessTree({
    child: { pid: 1234 },
    platform: 'win32',
    env: { SystemRoot: 'C:\\Windows' },
    kill: () => true,
    runExecFile: async (file, args) => {
      calls.push([file, args]);
      return { stdout: 'SUCCESS', stderr: '' };
    },
  });
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.equal(result.escalated, true);
  assert.equal(calls.length, 1);
  assert.match(calls[0][0], /taskkill\.exe$/i);
  assert.deepEqual(calls[0][1], ['/PID', '1234', '/T', '/F']);
});

test('accepts a Windows tree that exits before taskkill lands, when no descendants survive', async () => {
  // taskkill fails because the root already died mid-call: it never got to
  // identify (let alone target) the tree, so a nonzero result here is not
  // proof descendants are gone. Independent enumeration finding nothing is
  // what actually proves the tree is clean.
  const result = await terminateProcessTree({
    child: { pid: 1234 },
    platform: 'win32',
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file) => {
      if (/taskkill\.exe$/i.test(file)) throw new Error('taskkill failed');
      assert.match(file, /(?:pwsh|powershell)\.exe$/i);
      return { stdout: '', stderr: '' };
    },
  });
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.equal(result.escalated, true);
  assert.match(result.evidence, /no live descendants/i);
});

test('terminates and confirms descendants that outlived a Windows root taskkill could not target', async () => {
  const killedPids = [];
  const result = await terminateProcessTree({
    child: { pid: 1234 },
    platform: 'win32',
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file, args) => {
      if (/taskkill\.exe$/i.test(file)) {
        if (args.includes('1234')) throw new Error('taskkill failed: root PID not found');
        const pid = args[args.indexOf('/PID') + 1];
        killedPids.push(pid);
        return { stdout: 'SUCCESS', stderr: '' };
      }
      assert.match(file, /(?:pwsh|powershell)\.exe$/i);
      return { stdout: '5555 1234\n5556 1234\n', stderr: '' };
    },
  });
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.equal(result.escalated, true);
  assert.deepEqual(killedPids.sort(), ['5555', '5556']);
  assert.match(result.evidence, /2 live descendant/i);
});

test('blocks a Windows tree when a descendant survives taskkill after the root already exited', async () => {
  const result = await terminateProcessTree({
    child: { pid: 1234 },
    platform: 'win32',
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file, args) => {
      if (/taskkill\.exe$/i.test(file)) {
        if (args.includes('1234')) throw new Error('taskkill failed: root PID not found');
        throw new Error('taskkill failed: access denied');
      }
      assert.match(file, /(?:pwsh|powershell)\.exe$/i);
      return { stdout: '5555 1234\n', stderr: '' };
    },
  });
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.match(result.evidence, /5555/);
  assert.match(result.evidence, /could not be confirmed terminated/i);
});

test('blocks a Windows tree when descendant enumeration itself fails after the root already exited', async () => {
  const result = await terminateProcessTree({
    child: { pid: 1234 },
    platform: 'win32',
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file) => {
      if (/taskkill\.exe$/i.test(file)) throw new Error('taskkill failed: root PID not found');
      throw new Error('powershell is not available');
    },
  });
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.match(result.evidence, /enumeration failed/i);
  assert.match(result.evidence, /powershell is not available/);
});


test('blocks a Windows tree when taskkill fails while the root is still alive', async () => {
  let powershellRan = false;
  const result = await terminateProcessTree({
    child: { pid: 1234 },
    platform: 'win32',
    env: { SystemRoot: 'C:\\Windows' },
    kill: () => true, // root still present
    runExecFile: async (file) => {
      if (/taskkill\.exe$/i.test(file)) throw new Error('taskkill failed: access denied');
      powershellRan = true;
      return { stdout: '', stderr: '' };
    },
  });
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.equal(powershellRan, false, 'descendant enumeration must not run while the root is alive');
  assert.match(result.evidence, /access denied/);
});

test('enumerates multi-level Windows descendants from a full process table', async () => {
  // Root 100 is gone; intermediate 200 was a direct child; grandchild 300 is
  // still alive under 200. A ParentProcessId=root-only query would miss 300
  // if 200 is still in the table as its parent — the full adjacency BFS finds it.
  const killed = [];
  const result = await terminateProcessTree({
    child: { pid: 100 },
    platform: 'win32',
    env: { SystemRoot: 'C:\\Windows' },
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file, args) => {
      if (/taskkill\.exe$/i.test(file)) {
        if (args.includes('100')) throw new Error('taskkill failed: root PID not found');
        killed.push(args[args.indexOf('/PID') + 1]);
        return { stdout: 'SUCCESS', stderr: '' };
      }
      assert.match(file, /(?:pwsh|powershell)\.exe$/i);
      // Full table: pid parentPid pairs
      return { stdout: '200 100\n300 200\n400 1\n', stderr: '' };
    },
  });
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.deepEqual(killed.sort(), ['200', '300']);
  assert.match(result.evidence, /2 live descendant/i);
});

test('proves a clean Windows tree from ONE native process-table snapshot', async () => {
  // Windows CI root cause: every full-table CIM query, including the
  // property-limited PID/PPID form, can exceed the 20s probe budget on
  // windows-latest runners (every createCommandExecutor test BLOCKED).
  // The clean path must need only the native CommandLine-free snapshot: with
  // no young/unknown-age orphan candidates in the table, the expensive
  // attribution probe must not run at all — exactly one powershell call.
  let powershellCalls = 0;
  const result = await terminateProcessTree({
    child: { pid: 424242 },
    platform: 'win32',
    cwd: 'C:\\work\\repo',
    minStarttime: 1000,
    pathExists: (candidate) => /pwsh\.exe$/i.test(candidate),
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file, args, options) => {
      if (/taskkill\.exe$/i.test(file)) throw new Error('taskkill failed: root PID not found');
      assert.match(file, /(?:pwsh|powershell)\.exe$/i);
      assert.deepEqual(
        Object.keys(options.env).sort(),
        ['ComSpec', 'PATHEXT', 'SYSTEMROOT', 'SystemRoot'],
        'snapshot probe must not forward ambient environment',
      );
      const script = args.at(-1);
      assert.match(script, /Get-Process \| ForEach-Object/);
      assert.match(script, /\$_\.Parent\.Id/);
      assert.doesNotMatch(script, /SELECT ProcessId,ParentProcessId FROM Win32_Process/);
      assert.doesNotMatch(script, /SELECT .*CommandLine/);
      assert.doesNotMatch(script, /CreationDate/);
      powershellCalls += 1;
      return { stdout: '400 1 500 services.exe\n', stderr: '' };
    },
  });
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.match(result.evidence, /no live descendants/i);
  assert.equal(powershellCalls, 1, 'clean tree must not pay for the CommandLine attribution probe');
});

test('blocks multi-level Windows orphans via the CommandLine attribution probe', async () => {
  // The orphan's parent (999999) is dead and absent from the table, so
  // ParentProcessId BFS can never reach it; only the worktree CommandLine
  // scan catches it (Codex #4781560042). The cheap snapshot comes first and
  // flags the young broken-chain row as an attribution candidate, so the
  // CommandLine-bearing probe runs exactly once more.
  let powershellCalls = 0;
  const result = await terminateProcessTree({
    child: { pid: 424242 },
    platform: 'win32',
    cwd: 'C:\\work\\repo',
    minStarttime: 1000,
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file, args) => {
      if (/taskkill\.exe$/i.test(file)) throw new Error('taskkill failed: root PID not found');
      assert.match(file, /(?:pwsh|powershell)\.exe$/i);
      powershellCalls += 1;
      if (powershellCalls === 2) {
        const script = args.at(-1);
        assert.match(script, /SELECT ProcessId,ParentProcessId,CommandLine FROM Win32_Process WHERE/);
        assert.match(script, /\$candidatePids\.Add\(565656\)/);
        assert.doesNotMatch(script, /SELECT .*CreationDate/);
      }
      return { stdout: '565656 999999 2000 node.exe C:\\work\\repo\\scripts\\orphan.js\n', stderr: '' };
    },
  });
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.match(result.evidence, /CommandLine/i);
  assert.match(result.evidence, /565656/);
  assert.equal(powershellCalls, 2, 'cheap snapshot plus one attribution probe for the candidate');
});

test('blocks multi-level Windows orphans whose CommandLine spells the worktree with forward slashes', async () => {
  // Separator variation must not escape the worktree scan: the orphan below
  // references C:/work/repo while cwd is C:\work\repo — same directory, so
  // the scan must still attribute it and BLOCK (CodeRabbit UC4NQ/UC4NX).
  let powershellCalls = 0;
  const result = await terminateProcessTree({
    child: { pid: 424242 },
    platform: 'win32',
    cwd: 'C:\\work\\repo',
    minStarttime: 1000,
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file) => {
      if (/taskkill\.exe$/i.test(file)) throw new Error('taskkill failed: root PID not found');
      assert.match(file, /(?:pwsh|powershell)\.exe$/i);
      powershellCalls += 1;
      return { stdout: '565656 999999 2000 node.exe C:/work/repo/scripts/orphan.js\n', stderr: '' };
    },
  });
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.match(result.evidence, /CommandLine/i);
  assert.match(result.evidence, /565656/);
  assert.equal(powershellCalls, 2, 'cheap snapshot plus one attribution probe for the candidate');
});

test('does not block a clean Windows tree on worktree processes started before the spawn', async () => {
  // A pre-existing editor/CI process whose CommandLine mentions the repo but
  // whose CreationDate predates the spawn must not false-BLOCK the tree
  // (CodeRabbit #4781622077 semantics, preserved through the single-snapshot
  // refactor).
  let powershellCalls = 0;
  const result = await terminateProcessTree({
    child: { pid: 424242 },
    platform: 'win32',
    cwd: 'C:\\work\\repo',
    minStarttime: 1000,
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file) => {
      if (/taskkill\.exe$/i.test(file)) throw new Error('taskkill failed: root PID not found');
      assert.match(file, /(?:pwsh|powershell)\.exe$/i);
      powershellCalls += 1;
      return { stdout: '565657 999999 500 C:\\tools\\editor.exe C:\\work\\repo\\README.md\n', stderr: '' };
    },
  });
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.match(result.evidence, /no live descendants/i);
  assert.equal(powershellCalls, 1);
});

test('does not block on a worktree CommandLine match whose unbroken ancestor chain predates the spawn', async () => {
  // Second Windows flake root cause (local full-suite evidence + original CI
  // failure analysis): under `node --test`, sibling per-file worker processes
  // carry the repo path in their command lines and start AFTER the checked
  // command's minStartMs, so neither the self/ancestor exclusion nor the
  // young-match age filter excludes them. Windows never reassigns
  // ParentProcessId: such a sibling's UNBROKEN chain reaches the pre-existing
  // runner (700001, createdMs 500 < minStarttime 1000), which proves it
  // cannot be an orphan of our exited child — excluding it is sound.
  let powershellCalls = 0;
  const result = await terminateProcessTree({
    child: { pid: 424242 },
    platform: 'win32',
    cwd: 'C:\\work\\repo',
    minStarttime: 1000,
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file) => {
      if (/taskkill\.exe$/i.test(file)) throw new Error('taskkill failed: root PID not found');
      assert.match(file, /(?:pwsh|powershell)\.exe$/i);
      powershellCalls += 1;
      return {
        stdout: '700001 1 500 C:\\tools\\runner.exe\n700002 700001 2000 node.exe C:\\work\\repo\\scripts\\other.test.js\n',
        stderr: '',
      };
    },
  });
  assert.equal(result.status, 'PASS', `sibling chaining to a pre-existing root must not BLOCK, got: ${result.evidence}`);
  assert.match(result.evidence, /no live descendants/i);
  assert.equal(powershellCalls, 1);
});

test('still blocks a worktree CommandLine match whose ancestor chain breaks at an absent pid', async () => {
  // Guard: the pre-existing-root exclusion must not weaken orphan detection.
  // 700003's parent (999999) is absent from the table — exactly the broken
  // chain a real multi-level orphan has — so it stays flagged (fail-closed).
  let powershellCalls = 0;
  const result = await terminateProcessTree({
    child: { pid: 424242 },
    platform: 'win32',
    cwd: 'C:\\work\\repo',
    minStarttime: 1000,
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file) => {
      if (/taskkill\.exe$/i.test(file)) throw new Error('taskkill failed: root PID not found');
      assert.match(file, /(?:pwsh|powershell)\.exe$/i);
      powershellCalls += 1;
      return { stdout: '700003 999999 2000 node.exe C:\\work\\repo\\scripts\\orphan.js\n', stderr: '' };
    },
  });
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.match(result.evidence, /CommandLine/i);
  assert.match(result.evidence, /700003/);
  assert.equal(powershellCalls, 2, 'cheap snapshot plus one attribution probe for the candidate');
});

test('still blocks a worktree CommandLine match whose ancestor chain reaches unknown-age processes', async () => {
  // Guard: an ancestor whose CreationDate is unreadable (createdMs 0) cannot
  // prove the chain predates the spawn — the walk stops there and the match
  // stays flagged (fail-closed), even though the chain then breaks.
  let powershellCalls = 0;
  const result = await terminateProcessTree({
    child: { pid: 424242 },
    platform: 'win32',
    cwd: 'C:\\work\\repo',
    minStarttime: 1000,
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file) => {
      if (/taskkill\.exe$/i.test(file)) throw new Error('taskkill failed: root PID not found');
      assert.match(file, /(?:pwsh|powershell)\.exe$/i);
      powershellCalls += 1;
      return {
        stdout: '700004 700005 2000 node.exe C:\\work\\repo\\scripts\\orphan.js\n700005 999999 0\n',
        stderr: '',
      };
    },
  });
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.match(result.evidence, /CommandLine/i);
  assert.match(result.evidence, /700004/);
  assert.equal(powershellCalls, 2, 'cheap snapshot plus one attribution probe for the candidates');
});

test('retries a failed Windows table snapshot once, then fails closed', async () => {
  // The snapshot probe is read-only/idempotent, so exactly one retry is
  // allowed to absorb transient shared-runner CIM slowness; persistent
  // failure must still BLOCK (never assume the tree is clean).
  let powershellCalls = 0;
  const result = await terminateProcessTree({
    child: { pid: 424242 },
    platform: 'win32',
    cwd: 'C:\\work\\repo',
    minStarttime: 1000,
    kill: () => {
      const error = new Error('no such process');
      error.code = 'ESRCH';
      throw error;
    },
    runExecFile: async (file) => {
      if (/taskkill\.exe$/i.test(file)) throw new Error('taskkill failed: root PID not found');
      powershellCalls += 1;
      throw new Error('CIM provider hung');
    },
  });
  assert.equal(result.status, 'BLOCKED', statusDiag(result));
  assert.match(result.evidence, /enumeration failed/i);
  assert.match(result.evidence, /CIM provider hung/);
  assert.equal(powershellCalls, 2, 'probe gets exactly one retry, never more');
});

test('rejects an untrusted SystemRoot absolute path for Windows cleanup tools', async () => {
  const calls = [];
  const result = await terminateProcessTree({
    child: { pid: 1234 },
    platform: 'win32',
    env: {
      SystemRoot: 'C:\\Users\\attacker\\planted',
    },
    pathExists: (candidate) => /planted/i.test(candidate),
    kill: () => true,
    runExecFile: async (file, args) => {
      calls.push(file);
      return { stdout: 'SUCCESS', stderr: '' };
    },
  });
  assert.equal(result.status, 'PASS', statusDiag(result));
  assert.equal(calls.length, 1);
  // path.join on non-Windows hosts may mix separators; normalize before assert.
  const normalized = calls[0].replace(/\\/g, '/').toLowerCase();
  assert.equal(normalized, 'c:/windows/system32/taskkill.exe');
  assert.doesNotMatch(calls[0], /planted/i);
});

test('fails artifact proof when the file exceeds the hash size ceiling', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-huge-artifact-'));
  try {
    const artifact = path.join(repo, 'huge.bin');
    // One byte over the ceiling: snapshotArtifactProof reads the real lstat
    // size before hashing, so 5 MiB + 1 is enough to trip the bound and is
    // cheap enough for CI.
    const oversized = Buffer.alloc(MAX_ARTIFACT_HASH_BYTES + 1, 0x61);
    await writeFile(artifact, oversized);
    const result = await snapshotArtifactProof({
      proof: { type: 'artifact', path: 'huge.bin' },
      cwd: repo,
    });
    assert.equal(result.status, 'FAIL', statusDiag(result));
    assert.match(result.evidence, /hash size limit/i);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('does not hang when the verified artifact is swapped for a FIFO', { timeout: 15000 }, async (t) => {
  // POSIX-only: Windows Node cannot see POSIX FIFOs. A proof command's
  // background process can swap the verified artifact for a FIFO between the
  // lstat and the hash open; opening a FIFO read-only without O_NONBLOCK
  // would block waiting for a writer, so the proof must fail closed instead.
  if (process.platform === 'win32') { t.skip('posix-only test'); return; }
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-fifo-artifact-'));
  const fifoPath = path.join(repo, 'render.json');
  execFileSync('mkfifo', [fifoPath]);
  const regularPath = path.join(repo, 'regular.json');
  await writeFile(regularPath, '{}');
  const regularStats = await lstat(regularPath);
  // Simulate the swap: lstat reports the pre-swap regular file while the path
  // now resolves to a FIFO.
  const result = await snapshotArtifactProof({
    proof: { type: 'artifact', path: 'render.json' },
    cwd: repo,
    filesystem: {
      lstat: async (target) => (path.resolve(target) === path.resolve(fifoPath) ? regularStats : lstat(target)),
      realpath,
    },
  });
  assert.equal(result.status, 'FAIL', statusDiag(result));
  assert.match(result.evidence, /not a regular file/i);
});

test('rejects Grafana live frames that carry no real series values', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-grafana-empty-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-grafana-empty-logs-'));
  const execute = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
    grafanaServiceUrl: 'http://127.0.0.1:3000',
  });
  const basePayload = {
    provider: 'grafana',
    operation: 'query',
    endpoint: 'http://127.0.0.1:3000/api/ds/query',
    httpStatus: 200,
    request: { queries: [{ refId: 'A' }] },
  };
  const proof = {
    type: 'artifact',
    path: 'live.json',
    semantic: 'grafana-live-result',
    grafanaOrigin: 'http://127.0.0.1:3000',
  };
  // A frame whose values are placeholders (null) must not pass as usable data.
  const nullSeries = await execute({
    id: 'grafana-live-render',
    command: `require('node:fs').writeFileSync('live.json',${JSON.stringify(JSON.stringify({
      ...basePayload,
      response: { results: { A: { frames: [{ data: { values: [null] } }] } } },
    }))})`,
    proof,
  }, 'confirmation');
  assert.equal(nullSeries.status, 'FAIL');
  assert.match(nullSeries.evidence, /non-empty frame data/i);

  // Series of only null datapoints (values: [[null, null]]) also fail.
  const nullPoints = await execute({
    id: 'grafana-live-render',
    command: `require('node:fs').writeFileSync('live.json',${JSON.stringify(JSON.stringify({
      ...basePayload,
      response: { results: { A: { frames: [{ data: { values: [[null, null]] } }] } } },
    }))})`,
    proof,
  }, 'confirmation');
  assert.equal(nullPoints.status, 'FAIL');
  assert.match(nullPoints.evidence, /non-empty frame data/i);

  // The legacy single-result shape has the same requirement.
  const legacyNullSeries = await execute({
    id: 'grafana-live-render',
    command: `require('node:fs').writeFileSync('live.json',${JSON.stringify(JSON.stringify({
      ...basePayload,
      response: { results: { A: { data: { values: [null] } } } },
    }))})`,
    proof,
  }, 'confirmation');
  assert.equal(legacyNullSeries.status, 'FAIL');
  assert.match(legacyNullSeries.evidence, /non-empty frame data/i);
});
