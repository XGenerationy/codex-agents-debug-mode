const assert = require('node:assert/strict');
const { execFileSync, spawnSync } = require('node:child_process');
const { mkdtemp, readFile, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { MANDATORY_CHECKS } = require('./pr_closeout_core');

const script = path.join(__dirname, 'pr_closeout.js');
const git = (repo, ...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' });

test('prints help without touching a repository', () => {
  const result = spawnSync(process.execPath, [script, '--help'], { encoding: 'utf8' });
  assert.equal(result.status, 0);
  assert.match(result.stdout, /^Usage: pr_closeout\.js/);
  assert.match(result.stdout, /--plan/);
});

test('plan mode resolves all 19 checks without executing them', async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-cli-'));
  try {
    git(repo, 'init', '--quiet');
    git(repo, 'config', 'user.name', 'Closeout Test');
    git(repo, 'config', 'user.email', 'closeout@example.invalid');
    git(repo, 'config', 'commit.gpgSign', 'false');
    await writeFile(path.join(repo, 'package.json'), '{}');
    git(repo, 'add', '.');
    git(repo, 'commit', '--quiet', '-m', 'base');
    const commands = Object.fromEntries(
      MANDATORY_CHECKS.filter(({ fixed }) => !fixed).map(({ id }) => [id, `printf clean-${id}`]),
    );
    const configPath = path.join(repo, 'closeout.json');
    await writeFile(configPath, JSON.stringify({
      baseRef: 'HEAD',
      commands,
      services: {
        redis: { host: '127.0.0.1', port: 6379 },
        grafana: { url: 'http://127.0.0.1:3000/api/health' },
      },
      proofs: {
        'grafana-render': { type: 'artifact', path: 'artifacts/grafana.json' },
        'make-sbom': { type: 'artifact', path: 'artifacts/sbom.json' },
        'grafana-live-render': {
          type: 'artifact',
          path: 'artifacts/grafana-live.json',
          semantic: 'grafana-live-result',
          grafanaOrigin: 'http://127.0.0.1:3000',
        },
        'hunter-build': {
          type: 'command',
          command: 'docker compose ps --format json hunter',
          expectedPattern: 'semantic:docker-compose-running-healthy',
        },
      },
    }));
    const result = spawnSync(process.execPath, [script, '--repo', repo, '--config', configPath, '--plan'], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    const plan = JSON.parse(result.stdout);
    assert.equal(plan.checks.length, 19);
    assert.ok(plan.checks.every(({ command }) => command));
    assert.equal(plan.execution, 'not-started');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('example config uses the enforced semantic proof policies', async () => {
  const examplePath = path.join(__dirname, '..', 'assets', 'pr-closeout.config.example.json');
  const config = JSON.parse(await readFile(examplePath, 'utf8'));
  assert.deepEqual(config.safeEnv, []);
  assert.equal(config.proofs['grafana-live-render'].semantic, 'grafana-live-result');
  assert.equal(
    config.proofs['hunter-build'].expectedPattern,
    'semantic:docker-compose-running-healthy',
  );
});

test('rejects unknown arguments as a usage error', () => {
  const result = spawnSync(process.execPath, [script, '--weaken-gate'], { encoding: 'utf8' });
  assert.equal(result.status, 3);
  assert.match(result.stderr, /Unknown argument/);
});
