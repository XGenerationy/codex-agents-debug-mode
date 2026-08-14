'use strict';

// Boot shim for actions/debug-evidence: runs the collector PROGRAMMATICALLY
// (the CLI has no limit overrides) as a detached child of the `start` step.
// stdout is a PRIVATE pipe read once by support.js — the launch token in the
// startup line below never reaches step logs, outputs, or the artifact.
// The CLI's .debug/collector_token / collector_port / collector_claim files
// are deliberately NOT written: the only credential handoff is this pipe.

const { generateKeyPairSync } = require('node:crypto');
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
  // The RESPONDER KEYPAIR, minted fresh per boot so it cannot outlive the
  // collector it identifies. It lets `run` — the step that captures, since
  // Task 5 round 6 — check that a served log came from THIS process rather
  // than from a counterfeit listener a wrapped command stood up on a port it
  // rewrote in the action's state file (Codex T5 r4 #1).
  //
  // Only the PUBLIC half is handed back. A shared secret would have to sit in
  // the environment of the step that verifies — the `run` step since Task 5
  // round 6. The wrapped command does NOT inherit that environment (run copies
  // it and strips every DEBUG_ACTION_* entry before spawning), but it runs as
  // a child of that step, and where the host's permissions allow it a child
  // can read a parent's environment out of /proc/<ppid>/environ. Whoever can
  // read a symmetric key can sign with it, and signing is the whole capability
  // this withholds (Codex T5 r5 #2); a public verification key gives such a
  // reader nothing. The private half is passed straight into the server and
  // never serialized: it appears in no startup line, no state file, no output,
  // no log.
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const server = createDebugServer({
    projectRoot,
    limits,
    responderPrivateKey: privateKey,
    // Comma OR whitespace separated, per the documented input contract: a
    // comma-only split turned `DEBUG_REDACT_NAMES="A B,C"` into the names
    // ['A B', 'C'], so A's and B's values were never redacted at all
    // (Codex T3 #5).
    redactionNames: String(process.env.DEBUG_REDACT_NAMES ?? '')
      .split(/[\s,]+/).map((name) => name.trim()).filter(Boolean),
  });
  // EPIPE survival (Codex T3 #1). This collector outlives the `start` step:
  // once the startup line below is read, the parent releases its end of these
  // pipes and eventually exits. Any later write from here — a stray warning,
  // an unhandled rejection trace — would then raise EPIPE on a stream with no
  // 'error' listener, which is an uncaught exception that kills the collector
  // mid-job. Swallowing pipe errors for the process's lifetime is the whole
  // fix; there is no diagnostic value left in a pipe nobody reads.
  process.stdout.on('error', () => {});
  process.stderr.on('error', () => {});
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
      // SPKI DER, base64: one line, no newlines, travels unharmed through
      // JSON, through GITHUB_OUTPUT's key=value format, and through the
      // runner's own step-output plumbing.
      verify_key: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    })}\n`);
  });
};

main();
