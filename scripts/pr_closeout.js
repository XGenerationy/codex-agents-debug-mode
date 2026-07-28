#!/usr/bin/env node

const { constants: fsConstants } = require('node:fs');
const { lstat } = require('node:fs/promises');
const path = require('node:path');

const { openNoFollow } = require('./pr_closeout_fs');
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

// Upper bound for a --config JSON document. Closeout configs name commands,
// services, and proofs for 19 checks; 1 MiB is far beyond any legitimate one.
const CONFIG_MAX_BYTES = 1_048_576;

/**
 * Loads the optional --config JSON through a guarded bounded read (Codex
 * #UDDQK): the path is opened via openNoFollow (the shared no-follow/
 * nonblocking attempt ladder from pr_closeout_fs.js) and the descriptor —
 * not the path — is verified to be a regular file within CONFIG_MAX_BYTES
 * before any byte is read, the same pattern hashFile and the debug
 * collector's readSmallRegularFile use. A symlinked config is rejected
 * without being followed and a FIFO/device can neither block the read nor
 * stream unbounded content into memory before JSON.parse. `openFile` is
 * injectable for tests (Windows CI cannot create symlinks/FIFOs).
 *
 * openNoFollow's ELOOP guarantee only holds where the platform actually
 * enforces O_NOFOLLOW; on Windows, or a filesystem that rejects the flag,
 * its attempt ladder falls back to a plain open that follows a symlink
 * instead of failing (see openNoFollow's own contract note: callers must
 * still lstat first as the primary guard when NOFOLLOW is unavailable). So
 * the path is lstat'd up front and rejected outright if it is already a
 * symlink, then the opened descriptor's dev/ino is compared back against
 * that lstat to catch a symlink swapped in during the gap between the two.
 * A pre-open lstat that fails with ENOENT (a --config path only ever names a
 * file the caller says already exists) and a dev/ino comparison where either
 * side reports ino 0 (some FAT/network mounts never assign real inodes) both
 * carry no verified identity to compare, so both are rejected rather than
 * silently skipping the comparison and trusting whatever the open returned.
 * @param {string} configPath path passed via --config.
 * @param {{
 *   openFile?: (target: string, flags: number) => Promise<import('node:fs/promises').FileHandle>,
 *   lstatFn?: (target: string) => Promise<import('node:fs').Stats>,
 * }} [deps]
 * @returns {Promise<object>} parsed config.
 */
const readCloseoutConfig = async (configPath, { openFile = openNoFollow, lstatFn = lstat } = {}) => {
  const target = path.resolve(configPath);
  const symlinkMessage = `Closeout config must not be a symlink: ${target}.`;
  let preInfo = null;
  try {
    preInfo = await lstatFn(target);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
  }
  if (preInfo?.isSymbolicLink()) throw new Error(symlinkMessage);
  let handle;
  try {
    handle = await openFile(target, fsConstants.O_RDONLY);
  } catch (error) {
    if (error?.code === 'ELOOP') throw new Error(symlinkMessage);
    throw error;
  }
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > CONFIG_MAX_BYTES) {
      throw new Error(`Closeout config must be a regular file of at most ${CONFIG_MAX_BYTES} bytes: ${target}.`);
    }
    // A null preInfo (ENOENT at the pre-open lstat) means the path had no
    // verified identity before the open, so a symlink created in the gap
    // between the failed lstat and the open would otherwise be accepted with
    // zero verification; a 0 ino on either side means the filesystem gives no
    // reliable identity to compare at all (some FAT/network mounts always
    // report ino 0 -- the same platforms where openNoFollow's O_NOFOLLOW
    // fallback also degrades, per its own contract note above). Both cases
    // are treated the same as a genuine identity mismatch: a --config path is
    // only ever passed when the caller says it already exists, so there is no
    // legitimate case that depends on tolerating either gap here.
    if (!preInfo || info.ino === 0 || preInfo.ino === 0
      || info.dev !== preInfo.dev || info.ino !== preInfo.ino) {
      throw new Error(symlinkMessage);
    }
    const buffer = Buffer.alloc(info.size);
    let offset = 0;
    while (offset < info.size) {
      const { bytesRead } = await handle.read(buffer, offset, info.size - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    return JSON.parse(buffer.subarray(0, offset).toString('utf8'));
  } finally {
    await handle.close().catch(() => {});
  }
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
      ? await readCloseoutConfig(options.configPath)
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
    // One JSON line on stdout (JSONL-style contract): no pretty-print indent,
    // so line-oriented wrappers can parse each record as a single line.
    if (options.plan) {
      process.stdout.write(`${JSON.stringify(result)}\n`);
      if (result.planStatus !== 'PASS') process.exitCode = 2;
      return;
    }
    process.stdout.write(`${JSON.stringify({
      status: result.report.overallStatus,
      headSha: result.report.headSha,
      report: result.paths,
    })}\n`);
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

module.exports = { HELP, main, parseArgs, readCloseoutConfig };
