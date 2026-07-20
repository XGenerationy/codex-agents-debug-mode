const assert = require('node:assert/strict');
const { access, link, mkdtemp, readFile, rm, stat, writeFile } = require('node:fs/promises');
const http = require('node:http');
const net = require('node:net');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  createCommandExecutor,
  createDecodedRedactor,
  createStreamingRedactor,
  redactSecrets,
  probeGrafanaHealthDefault,
  probeRedisDefault,
  resolveCommandShell,
  runPreflight,
  snapshotArtifactProof,
  spawnCaptured,
} = require('./pr_closeout_process');

const listen = (server) => new Promise((resolve, reject) => {
  server.once('error', reject);
  server.listen(0, '127.0.0.1', () => resolve(server.address().port));
});

const closeServer = (server) => new Promise((resolve, reject) => {
  server.close((error) => (error ? reject(error) : resolve()));
});

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
  assert.equal(result.status, 'BLOCKED');
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

test('automatically redacts short sensitive environment values and encoded variants', () => {
  const secret = 'x/';
  const env = { GITHUB_TOKEN: secret, ORDINARY_VALUE: 'visible' };
  const encoded = [
    encodeURIComponent(secret),
    JSON.stringify(secret).slice(1, -1),
    Buffer.from(secret).toString('base64'),
    Buffer.from(secret).toString('base64url'),
  ];
  const output = redactSecrets(`raw=${secret} url=${encoded[0]} json=${encoded[1]} b64=${encoded[2]} b64url=${encoded[3]} ordinary=${env.ORDINARY_VALUE}`, env);
  assert.doesNotMatch(output, /x\//);
  for (const value of encoded) assert.equal(output.includes(value), false, value);
  assert.match(output, /ordinary=visible/);
});

test('streaming redaction covers automatically discovered encoded secrets across chunks', () => {
  const secret = 'tiny';
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
  assert.equal(result.status, 'PASS');
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
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /UserWarning/);
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
  assert.equal(result.status, 'FAIL');
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
  assert.equal(result.status, 'FAIL');
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
  assert.equal(result.status, 'FAIL');
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
  assert.equal(result.status, 'FAIL');
  assert.match(result.evidence, /resolves outside/i);
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
  assert.equal(result.status, 'PASS');
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
  assert.equal(result.status, 'FAIL');
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
  assert.equal(result.status, 'FAIL');
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
  assert.equal(result.status, 'PASS');
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
  assert.equal(result.status, 'FAIL');
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
  assert.equal(result.status, 'PASS');
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

test('binds live Grafana artifact proof to a query result contract', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-grafana-live-'));
  const outputDir = await mkdtemp(path.join(tmpdir(), 'closeout-grafana-live-logs-'));
  const execute = createCommandExecutor({
    repo,
    outputDir,
    shell: process.execPath,
    shellArgs: (command) => ['-e', command],
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
  assert.equal(result.status, 'BLOCKED');
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
  assert.equal(result.status, 'FAIL');
  assert.ok(result.checks.some(({ name, status }) => name === 'node' && status === 'FAIL'));
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
