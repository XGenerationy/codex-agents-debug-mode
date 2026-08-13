'use strict';

// All logic for actions/debug-evidence lives here; action.yml is wiring only.
// Subcommands: start | run | report | teardown | finish, driven by
// DEBUG_ACTION_* env vars. State travels via action-state.json at the
// OUTPUT-DIR ROOT — deliberately outside the evidence child, because it
// carries the collector launch token and must never be uploaded.

const { appendFileSync, copyFileSync, mkdirSync, readFileSync, writeFileSync } = require('node:fs');
const { spawn, spawnSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');

const { probeReadyCollector, probeServer } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_server.js'));

const STATE_FILE = 'action-state.json';
const EVIDENCE_SUBDIR = 'debug-evidence-files';
const BOOT_SHIM = path.join(__dirname, 'collector_boot.js');
const REPORT_CLI = path.join(__dirname, '..', '..', 'scripts', 'debug_report.js');
const NAME_PATTERN = /^[A-Za-z0-9_-]+$/;

const resolveEvidenceDir = (outputDir) => path.join(outputDir, EVIDENCE_SUBDIR);

// Same helper contract as actions/closeout: the env-file path is the first
// argument so tests inject a temp file instead of the real GITHUB_OUTPUT.
const writeOutputs = (outputFile, pairs) => {
  const lines = Object.entries(pairs)
    .map(([name, value]) => `${name}=${String(value ?? '').replace(/\r?\n|\r/g, ' ')}`)
    .join('\n');
  appendFileSync(outputFile, `${lines}\n`);
};

const redactKnownSecrets = (text, secrets) => {
  let result = String(text);
  for (const secret of secrets) {
    if (typeof secret === 'string' && secret.length >= 8) {
      result = result.split(secret).join('[REDACTED]');
    }
  }
  return result;
};

const validateActionInputs = ({
  runCommand, sessionName, failOnCommandFailure, port, maxEvents, maxBytes,
  hypothesisId, workingDirectory = '.', outputDir = '', workspace = '',
}) => {
  const errors = [];
  if (!runCommand || !runCommand.trim()) errors.push('run: a command is required');
  if (!NAME_PATTERN.test(sessionName)) errors.push('session-name: must match [A-Za-z0-9_-]+');
  if (failOnCommandFailure !== 'true' && failOnCommandFailure !== 'false') {
    errors.push("fail-on-command-failure: must be 'true' or 'false'");
  }
  const portNumber = Number(port);
  if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) {
    errors.push('port: must be an integer between 1 and 65535');
  }
  for (const [name, value] of [['max-events', maxEvents], ['max-bytes', maxBytes]]) {
    if (value !== '' && (!/^\d+$/.test(value) || Number(value) < 1)) {
      errors.push(`${name}: must be a positive integer or empty`);
    }
  }
  if (hypothesisId !== '' && !NAME_PATTERN.test(hypothesisId)) {
    errors.push('hypothesis-id: must match [A-Za-z0-9_-]+ or be empty');
  }
  if (/[\r\n]/.test(workingDirectory) || /[\r\n]/.test(outputDir)) {
    errors.push('working-directory/output-dir: must not contain a CR or LF');
  }
  if (workspace) {
    const relative = path.relative(path.resolve(workspace), path.resolve(outputDir));
    if (relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))) {
      errors.push('output-dir: must be outside the repository workspace');
    }
  }
  return errors;
};

const writeState = (outputDir, state) => {
  mkdirSync(outputDir, { recursive: true });
  writeFileSync(path.join(outputDir, STATE_FILE), `${JSON.stringify(state)}\n`, { mode: 0o600 });
};

const readState = (outputDir) => {
  try {
    return JSON.parse(readFileSync(path.join(outputDir, STATE_FILE), 'utf8'));
  } catch {
    return null;
  }
};

const rejectForeignNonce = (state, env, subcommand) => {
  if (env.DEBUG_ACTION_INVOCATION_NONCE && state.nonce !== env.DEBUG_ACTION_INVOCATION_NONCE) {
    process.stderr.write(`debug-evidence-action: ${subcommand}: recorded state does not carry this invocation's nonce (output-dir overwritten by a concurrent run, or never written by this run); refusing to trust it.\n`);
    return true;
  }
  return false;
};

const defaultSpawnShim = (args, { env }) => spawn(process.execPath, [BOOT_SHIM, ...args], {
  env,
  detached: true,
  stdio: ['ignore', 'pipe', 'pipe'],
});

// Read the shim's single startup line (private pipe). Resolves the parsed
// JSON object; rejects on timeout, child exit, or unparsable output.
const readShimStartLine = (child, timeoutMs) => new Promise((resolve, reject) => {
  let settled = false;
  let stdout = '';
  let stderr = '';
  const settle = (fn, value) => {
    if (settled) return;
    settled = true;
    clearTimeout(timer);
    fn(value);
  };
  const timer = setTimeout(() => {
    settle(reject, new Error(`collector shim did not report startup within ${timeoutMs}ms`));
  }, timeoutMs);
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
    const newline = stdout.indexOf('\n');
    if (newline === -1) return;
    try {
      settle(resolve, JSON.parse(stdout.slice(0, newline)));
    } catch {
      settle(reject, new Error('collector shim printed an unparsable startup line'));
    }
  });
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  child.on('exit', () => {
    let reason = 'exited before startup';
    try { reason = JSON.parse(stderr.split('\n')[0]).reason ?? reason; } catch {}
    settle(reject, new Error(`collector shim did not report startup: ${reason}`));
  });
});

const startSubcommand = async ({
  inputs, outputDir, env = process.env, projectRoot = process.cwd(),
  spawnShim = defaultSpawnShim, probeReady = probeReadyCollector,
  nonce = randomUUID(), readyTimeoutMs = Number(env.DEBUG_ACTION_READY_TIMEOUT_MS || 15_000),
}) => {
  const errors = validateActionInputs({ ...inputs, outputDir, workspace: env.GITHUB_WORKSPACE || '' });
  if (errors.length > 0) throw new Error(`invalid inputs: ${errors.join('; ')}`);
  if (env.GITHUB_ENV) writeOutputs(env.GITHUB_ENV, { DEBUG_ACTION_INVOCATION_NONCE: nonce });
  const shimEnv = { ...env, DEBUG_PORT: inputs.port };
  if (inputs.maxEvents) shimEnv.DEBUG_ACTION_MAX_EVENTS = inputs.maxEvents;
  if (inputs.maxBytes) shimEnv.DEBUG_ACTION_MAX_BYTES = inputs.maxBytes;
  // Input redact-names EXTENDS (never replaces) any job-level DEBUG_REDACT_NAMES.
  if (inputs.redactNames) {
    shimEnv.DEBUG_REDACT_NAMES = [env.DEBUG_REDACT_NAMES, inputs.redactNames].filter(Boolean).join(',');
  }
  const child = spawnShim([projectRoot], { env: shimEnv });
  let startLine;
  try {
    startLine = await readShimStartLine(child, readyTimeoutMs);
  } catch (error) {
    try { child.kill(); } catch {}
    throw error;
  }
  if (startLine.status !== 'started') {
    throw new Error(`collector failed to start: ${startLine.reason ?? 'unknown'}`);
  }
  const identity = await probeReady(Number(inputs.port), startLine.project_hash, { deadlineMs: readyTimeoutMs });
  if (!identity || identity.project_hash !== startLine.project_hash || identity.ready !== true) {
    try { process.kill(startLine.pid); } catch {}
    throw new Error('collector did not become ready before the timeout');
  }
  child.stdout.destroy();
  child.stderr.destroy();
  child.unref();
  writeState(outputDir, {
    nonce,
    pid: startLine.pid,
    port: Number(inputs.port),
    launchToken: startLine.launch_token,
    projectRoot,
    sessionName: inputs.sessionName,
    hypothesisId: inputs.hypothesisId,
    hypothesisTitle: inputs.hypothesisTitle,
    failOnCommandFailure: inputs.failOnCommandFailure,
  });
  return 0;
};

const teardownSubcommand = ({ outputDir, env = process.env, kill = process.kill }) => {
  const state = readState(outputDir);
  if (!state) return 0; // start never wrote state — nothing to tear down
  if (rejectForeignNonce(state, env, 'teardown')) return 3;
  if (!Number.isInteger(state.pid) || state.pid < 1) {
    process.stderr.write('debug-evidence-action: teardown: recorded state carries no usable pid.\n');
    return 3;
  }
  try {
    kill(state.pid);
  } catch (error) {
    if (error?.code === 'ESRCH') return 0; // already gone — success, not a leak
    process.stderr.write(`debug-evidence-action: teardown: failed to stop collector pid ${state.pid}: ${error?.code ?? error}\n`);
    return 3;
  }
  return 0;
};

// Implemented in later tasks — stable export surface from day one.
const runSubcommand = async () => { throw new Error('not implemented: runSubcommand (Task 4)'); };
const reportSubcommand = async () => { throw new Error('not implemented: reportSubcommand (Task 5)'); };
const finishSubcommand = () => { throw new Error('not implemented: finishSubcommand (Task 5)'); };

const collectStateSecrets = (state) => [state?.launchToken, state?.sessionToken].filter(Boolean);

const main = async () => {
  const [subcommand] = process.argv.slice(2);
  const env = process.env;
  const outputDir = env.DEBUG_ACTION_OUTPUT_DIR
    || path.join(env.RUNNER_TEMP || os.tmpdir(), 'debug-evidence');
  const inputs = {
    runCommand: env.DEBUG_ACTION_RUN || '',
    sessionName: env.DEBUG_ACTION_SESSION_NAME || 'ci-debug',
    workingDirectory: env.DEBUG_ACTION_WORKDIR || '.',
    failOnCommandFailure: env.DEBUG_ACTION_FAIL_ON_COMMAND_FAILURE || 'true',
    port: env.DEBUG_ACTION_PORT || '8787',
    redactNames: env.DEBUG_ACTION_REDACT_NAMES || '',
    maxEvents: env.DEBUG_ACTION_MAX_EVENTS_INPUT || '',
    maxBytes: env.DEBUG_ACTION_MAX_BYTES_INPUT || '',
    hypothesisId: env.DEBUG_ACTION_HYPOTHESIS_ID || '',
    hypothesisTitle: env.DEBUG_ACTION_HYPOTHESIS_TITLE || '',
  };
  try {
    if (subcommand === 'start') {
      process.exitCode = await startSubcommand({ inputs, outputDir, env, projectRoot: env.GITHUB_WORKSPACE || process.cwd() });
    } else if (subcommand === 'run') {
      process.exitCode = await runSubcommand({ inputs, outputDir, env });
    } else if (subcommand === 'report') {
      process.exitCode = await reportSubcommand({ outputDir, env });
    } else if (subcommand === 'teardown') {
      process.exitCode = teardownSubcommand({ outputDir, env });
    } else if (subcommand === 'finish') {
      process.exitCode = finishSubcommand({ outputDir, env });
    } else {
      throw new Error(`Unknown subcommand: ${subcommand ?? '(none)'}. Use start, run, report, teardown, or finish.`);
    }
  } catch (error) {
    const secrets = collectStateSecrets(readState(outputDir));
    process.stderr.write(`debug-evidence-action: ${redactKnownSecrets(error?.message ?? String(error), secrets)}\n`);
    process.exitCode = 1;
  }
};

if (require.main === module) void main();

module.exports = {
  finishSubcommand,
  readShimStartLine,
  readState,
  redactKnownSecrets,
  reportSubcommand,
  resolveEvidenceDir,
  runSubcommand,
  startSubcommand,
  teardownSubcommand,
  validateActionInputs,
  writeOutputs,
  writeState,
};
