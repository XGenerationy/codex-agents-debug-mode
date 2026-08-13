'use strict';

// Boot shim for actions/debug-evidence: runs the collector PROGRAMMATICALLY
// (the CLI has no limit overrides) as a detached child of the `start` step.
// stdout is a PRIVATE pipe read once by support.js — the launch token in the
// startup line below never reaches step logs, outputs, or the artifact.
// The CLI's .debug/collector_token / collector_port / collector_claim files
// are deliberately NOT written: the only credential handoff is this pipe.

const path = require('node:path');
const { createDebugServer } = require(path.join(__dirname, '..', '..', 'scripts', 'debug_server.js'));

const fail = (reason) => {
  process.stderr.write(`${JSON.stringify({ status: 'error', reason })}\n`);
  process.exitCode = 1;
};

const parsePositiveInt = (value) => {
  if (!value) return undefined;
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 ? n : null;
};

const main = () => {
  const projectRoot = process.argv[2] || process.cwd();
  const port = Number(process.env.DEBUG_PORT || 8787);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return fail('invalid_port');
  const limits = {};
  const maxEvents = parsePositiveInt(process.env.DEBUG_ACTION_MAX_EVENTS);
  const maxBytes = parsePositiveInt(process.env.DEBUG_ACTION_MAX_BYTES);
  if (maxEvents === null || maxBytes === null) return fail('invalid_limits');
  if (maxEvents !== undefined) limits.maxEventsPerSession = maxEvents;
  if (maxBytes !== undefined) limits.maxTotalBytes = maxBytes;
  // redactionEnv defaults to { ...process.env } inside createDebugServer, and
  // this shim inherits the full job env from `start` — that inheritance is the
  // redaction guarantee for job secrets (spec Security invariant 3).
  const server = createDebugServer({
    projectRoot,
    limits,
    redactionNames: String(process.env.DEBUG_REDACT_NAMES ?? '')
      .split(',').map((name) => name.trim()).filter(Boolean),
  });
  server.on('error', (error) => {
    fail(error?.code === 'EADDRINUSE' ? 'port_in_use' : 'listen_failed');
  });
  server.listen(port, '127.0.0.1', () => {
    server.markCollectorReady();
    process.stdout.write(`${JSON.stringify({
      status: 'started',
      port,
      pid: process.pid,
      project_hash: server.collectorProjectHash,
      launch_token: server.collectorToken,
    })}\n`);
  });
};

main();
