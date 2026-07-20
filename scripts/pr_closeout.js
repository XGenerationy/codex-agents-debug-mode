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
    process.exitCode = 3;
  }
};

if (require.main === module) void main();

module.exports = { HELP, main, parseArgs };
