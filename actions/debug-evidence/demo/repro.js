'use strict';

// DEMO repro for the debug-evidence dogfood workflow
// (.github/workflows/debug-evidence-demo.yml). Deterministic by design: fixed
// messages, a seeded "bug", exit 1. NOT part of the skill payload — nothing
// under actions/ is installed by tools/install.sh.
//
// THE CONTRACT IT DEMONSTRATES. It authenticates with ONLY the environment the
// action's `run` step injects — DEBUG_LOG_URL, DEBUG_SESSION_ID,
// DEBUG_SESSION_TOKEN, plus DEBUG_HYPOTHESIS_ID when the caller configured a
// hypothesis-id — which is exactly what any consumer's wrapped command gets.
// It reads nothing else from the runner, and it CANNOT: `run` deletes every
// DEBUG_ACTION_* variable and the runner's own command-file variables
// (GITHUB_ENV / GITHUB_PATH / GITHUB_OUTPUT / GITHUB_STATE /
// GITHUB_STEP_SUMMARY) from the child environment before spawning it. A demo
// that quietly depended on one of those would work on a developer's machine
// and fail in the CI it exists to demonstrate, so the absence is CHECKED here
// rather than assumed — see exit 98 below.
//
// DEMO_FAKE_SECRET is the one extra variable, and it is a fixture rather than
// a contract: the workflow sets a fixed dummy value and passes the same name
// through `redact-names`, so the artifact must show [REDACTED] where this
// script logged it. That is the end-to-end proof that the collector scrubs job
// secrets out of events the wrapped command authored.
//
// EXIT CODES — the demo's whole vocabulary, kept distinct so a red job says
// which thing broke:
//   1  the SEEDED failure. What the demo is for; the dogfood job waives it
//      with `fail-on-command-failure: "false"` and the mirroring job does not.
//  98  the action's environment contract was violated (something that must be
//      stripped reached this process). Never expected; a real finding if seen.
//  99  the demo's own infrastructure broke — a missing fixture, or a collector
//      that refused an event. Distinct from 1 so a broken demo can never be
//      mistaken for the failure it is supposed to seed.

// Everything `run` promises to remove. Named here so the check below reads as
// the contract it is, and EXPORTED so support.test.js can assert it is deeply
// equal to RUNNER_COMMAND_FILE_VARS in support.js. That pin replaces an
// earlier invitation to compare the two lists by inspection, which pinned
// nothing: a sixth command-file variable added to support.js and not here
// would leave the exit 98 guard below silently checking five of six, staying
// green while covering less than it advertises.
const STRIPPED_CONTROL_PLANE = [
  'GITHUB_ENV',
  'GITHUB_PATH',
  'GITHUB_OUTPUT',
  'GITHUB_STATE',
  'GITHUB_STEP_SUMMARY',
];

const post = async (body) => {
  const response = await fetch(process.env.DEBUG_LOG_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-debug-session-token': process.env.DEBUG_SESSION_TOKEN,
    },
    body: JSON.stringify({ sessionId: process.env.DEBUG_SESSION_ID, ...body }),
  });
  if (response.status !== 202) throw new Error(`collector rejected event: HTTP ${response.status}`);
};

const main = async () => {
  // The fixture check comes FIRST, before any event exists. Without it the
  // demo's failure mode is silent: the third event would read
  // "token=undefined", the artifact would carry no [REDACTED] marker at all,
  // and a green job would prove nothing while looking like it had.
  if (!process.env.DEMO_FAKE_SECRET) {
    process.stderr.write('DEMO: DEMO_FAKE_SECRET is unset; the redaction proof would be vacuous.\n');
    process.exitCode = 99;
    return;
  }
  const leaked = [
    ...STRIPPED_CONTROL_PLANE.filter((name) => process.env[name] !== undefined),
    ...Object.keys(process.env).filter((name) => name.startsWith('DEBUG_ACTION_')),
  ];
  if (leaked.length > 0) {
    process.stderr.write(`DEMO: the wrapped command was handed variables the run step must strip: ${leaked.sort().join(', ')}\n`);
    process.exitCode = 98;
    return;
  }
  // Absent unless the caller configured a hypothesis-id, and absent is fine:
  // JSON.stringify drops an undefined value, so the event is simply untagged.
  const hypothesisId = process.env.DEBUG_HYPOTHESIS_ID;
  // Seeded bug: userId is "lost" between fetch and render.
  await post({ msg: 'DEMO fetch: userId=42 loaded from fixture', hypothesisId });
  await post({ msg: 'DEMO render: userId=null on first render', hypothesisId, data: { userId: null } });
  // Redaction proof: the raw secret value must NEVER appear in the artifact.
  await post({ msg: `DEMO config dump: token=${process.env.DEMO_FAKE_SECRET}`, hypothesisId });
  await post({ msg: 'DEMO unrelated background noise' });
  process.stderr.write('DEMO: seeded failure — exiting 1 so the report shows a red run\n');
  process.exitCode = 1;
};

// AS A PROGRAM ONLY, guarded exactly as support.js guards its own main.
// support.test.js requires this file to pin STRIPPED_CONTROL_PLANE against
// support.js, and an unguarded import would also run main() in the test
// process: DEMO_FAKE_SECRET is a workflow fixture that no test process sets,
// so the fixture check would set process.exitCode = 99 on the whole suite.
// The action always invokes this file as `node .../repro.js`, where
// require.main === module holds and nothing changes.
if (require.main === module) {
  main().catch((error) => {
    process.stderr.write(`DEMO repro failed unexpectedly: ${error.message}\n`);
    process.exitCode = 99; // 99 = demo infrastructure broke (≠ the seeded 1)
  });
}

module.exports = { STRIPPED_CONTROL_PLANE };
