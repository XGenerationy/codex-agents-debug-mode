#!/usr/bin/env node

const { readFile } = require('node:fs/promises');
const path = require('node:path');

const { runCloseoutWorkflow } = require('./pr_closeout_workflow');

const HELP = `Usage: pr_closeout.js --repo <path> --base-ref <ref> [options]

Run the mandatory 19-check PR closeout gate and write JSON, Markdown, and raw logs.

Options:
  --repo <path>        Repository worktree (default: current directory)
  --base-ref <ref>     Live PR base ref, such as origin/main
  --config <path>      Repository-specific closeout JSON
  --output-dir <path>  Evidence directory (default: system temp directory)
  --plan               Resolve and print commands without executing them
  -h, --help           Show this help
`;

/**
 * Parses CLI argv into `{ repo, plan, help, baseRef?, configPath?,
 * outputDir? }`. `repo` defaults to `process.cwd()`. Flags that take a
 * value (`--repo`, `--base-ref`, `--config`, `--output-dir`) throw if the
 * next token is missing or itself looks like another flag (starts with
 * `--`), so a dropped value can never silently swallow the next flag. Any
 * unrecognized argument throws immediately rather than being ignored, so a
 * typo'd or unexpected flag fails loudly instead of silently no-op'ing.
 * @param {string[]} argv arguments after the node executable and script path.
 * @returns {object} parsed options.
 */
const parseArgs = (argv) => {
  const options = { repo: process.cwd(), plan: false };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === '--help' || argument === '-h') options.help = true;
    else if (argument === '--plan') options.plan = true;
    else if (['--repo', '--base-ref', '--config', '--output-dir'].includes(argument)) {
      const value = argv[index + 1];
      if (!value || value.startsWith('--')) throw new Error(`Missing value for ${argument}.`);
      index += 1;
      const key = {
        '--repo': 'repo',
        '--base-ref': 'baseRef',
        '--config': 'configPath',
        '--output-dir': 'outputDir',
      }[argument];
      options[key] = value;
    } else {
      throw new Error(`Unknown argument: ${argument}`);
    }
  }
  return options;
};

/**
 * CLI entrypoint: parses argv, resolves the --help/--plan short-circuits,
 * loads the optional --config JSON, and runs the full closeout workflow via
 * runCloseoutWorkflow. Always writes one JSON line to stdout — the resolved
 * plan when --plan is set, otherwise the final status/headSha/report paths
 * — and exits non-zero whenever the result is not PASS: exit 2 means the
 * gate ran and found a non-PASS result, exit 3 means it could not run at
 * all (bad args, bad repo, missing base ref, unreadable config, ...), in
 * which case a machine-readable BLOCKED record is still written to stdout
 * (see inline comment below) alongside the human-readable stderr message.
 * @returns {Promise<void>}
 */
const main = async () => {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
    if (options.help) {
      process.stdout.write(HELP);
      return;
    }
    const config = options.configPath
      ? JSON.parse(await readFile(path.resolve(options.configPath), 'utf8'))
      : {};
    const baseRef = options.baseRef || config.baseRef;
    if (!baseRef) throw new Error('A live PR base is required via --base-ref or config.baseRef.');
    const result = await runCloseoutWorkflow({
      repo: path.resolve(options.repo),
      baseRef,
      config,
      outputDir: options.outputDir,
      planOnly: options.plan,
    });
    if (options.plan) {
      process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
      if (result.planStatus !== 'PASS') process.exitCode = 2;
      return;
    }
    process.stdout.write(`${JSON.stringify({
      status: result.report.overallStatus,
      headSha: result.report.headSha,
      report: result.paths,
    }, null, 2)}\n`);
    if (result.report.overallStatus !== 'PASS') process.exitCode = 2;
  } catch (error) {
    process.stderr.write(`pr-closeout: ${error.message}\n`);
    // Emit a machine-readable BLOCKED record so callers still get structured
    // evidence when init throws before an output directory/report is created
    // (bad repo path, missing base ref, unreadable metadata, etc.). Without
    // this, callers had only a stderr line and no JSON to act on.
    process.stdout.write(`${JSON.stringify({
      status: 'BLOCKED',
      overallStatus: 'BLOCKED',
      error: error?.message || String(error),
    })}\n`);
    process.exitCode = 3;
  }
};

if (require.main === module) void main();

module.exports = { HELP, main, parseArgs };
