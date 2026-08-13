#!/usr/bin/env node

const { forwardGateRetriesForBase, forwardGateRetry } = require('./pr_closeout_retry');

const HELP = `Usage:
  gate_retry_cli.js single --repository <owner/repo> --head-sha <sha> [--repo <path>]
  gate_retry_cli.js base --repository <owner/repo> --base-ref <ref> [--repo <path>]

"single" re-runs the closeout gate's most recent completed run at one PR head
(chatgpt-codex-connector PR7 #6YaxWe: the workflow_run-retry forwarder).

"base" discovers every open PR targeting --base-ref and does the same for
each of their current heads (chatgpt-codex-connector PR7 #6YbMwY: the
base-branch-drift forwarder).

Both modes are best-effort and never fail this step: a forwarded retry that
could not be triggered is reported in the printed result, not surfaced as a
step failure — this mechanism exists to opportunistically recover a stale
gate result, and its own unavailability is not itself a problem with any PR.
`;

/**
 * Parses CLI argv into `{ mode, repository, headSha?, baseRef?, repo? }`.
 * A flag that takes a value throws if the next token is missing or itself
 * looks like another flag, so a dropped value can never silently swallow
 * the next flag — mirrors pr_closeout.js's own parseArgs discipline.
 * @param {string[]} argv
 * @returns {object}
 */
const parseArgs = (argv) => {
  if (argv[0] === '-h' || argv[0] === '--help') return { help: true };
  const mode = argv[0];
  if (mode !== 'single' && mode !== 'base') {
    throw new Error(`Unknown mode "${mode ?? ''}" — expected "single" or "base".`);
  }
  const options = { mode, repo: process.cwd() };
  const rest = argv.slice(1);
  const takesValue = new Set(['--repository', '--head-sha', '--base-ref', '--repo']);
  for (let index = 0; index < rest.length; index += 1) {
    const flag = rest[index];
    if (!takesValue.has(flag)) throw new Error(`Unrecognized argument: ${flag}`);
    const value = rest[index + 1];
    if (value === undefined || value.startsWith('--')) throw new Error(`${flag} requires a value.`);
    index += 1;
    if (flag === '--repository') options.repository = value;
    else if (flag === '--head-sha') options.headSha = value;
    else if (flag === '--base-ref') options.baseRef = value;
    else if (flag === '--repo') options.repo = value;
  }
  if (!options.repository) throw new Error('--repository is required.');
  if (options.mode === 'single' && !options.headSha) throw new Error('--head-sha is required for "single" mode.');
  if (options.mode === 'base' && !options.baseRef) throw new Error('--base-ref is required for "base" mode.');
  return options;
};

const main = async () => {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    process.stdout.write(HELP);
    return;
  }
  const result = options.mode === 'single'
    ? await forwardGateRetry({ repository: options.repository, headSha: options.headSha, repo: options.repo })
    : await forwardGateRetriesForBase({ repository: options.repository, baseRef: options.baseRef, repo: options.repo });
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
};

if (require.main === module) {
  main().catch((error) => {
    // Best-effort forwarder (see HELP): print the failure for visibility but
    // never fail the step over it — this mechanism's own unavailability is
    // not itself a problem with any PR. A genuinely bad invocation (a typo'd
    // flag, missing --repository) still surfaces here rather than being
    // silently swallowed.
    process.stderr.write(`${error.message}\n`);
  });
}

module.exports = { parseArgs };
