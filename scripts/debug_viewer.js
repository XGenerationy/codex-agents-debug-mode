// Layout-C TUI + agent-mode session viewer (spec:
// docs/superpowers/specs/2026-08-06-evidence-tools-design.md). Mode rule:
// stdout TTY -> TUI; otherwise (or --json/--plain) -> agent mode, which
// applies the shared filter engine and re-emits the selected RAW stored
// lines byte-for-byte. Zero dependencies; all interactive state changes are
// pure reducers so they can be unit-tested without a terminal.
const path = require('node:path');
const {
  filterEntries,
  foldHypotheses,
  listSessions,
  readSessionFile,
  resolveSessionRef,
} = require('./debug_evidence');

const USAGE = 'Usage: debug_viewer.js [projectRoot] --session <id|path> '
  + '[--hypothesis <id>] [--type all|event|hypothesis] [--since <ISO>] '
  + '[--until <ISO>] [--run <id>] [--limit <n>] [--live|--file] [--json|--plain]';

// Flags that take a following value — used to reject `--flag=value` syntax
// (this parser only accepts space-separated values) and to stop a value
// consuming a following flag token (see takeValue below).
const VALUE_FLAGS = new Set(['--session', '--hypothesis', '--type', '--since', '--until', '--run', '--limit']);
const EQUALS_FLAG = /^(--[a-z]+)=/;

// Fail-closed argument parsing: unknown flags, duplicate flags, `--flag=value`
// syntax, and malformed values all throw a viewer_usage error rather than
// being ignored or silently accepted (an ignored typo would silently widen
// what gets shown — same stance as the GET route, which also rejects
// duplicate query params).
const parseViewerArgs = (argv) => {
  const parsed = {
    projectRoot: process.cwd(),
    session: undefined,
    filters: {},
    agentMode: false,
    forceLive: false,
    forceFile: false,
  };
  const args = [...argv];
  if (args[0] && !args[0].startsWith('--')) parsed.projectRoot = args.shift();
  const seen = new Set();
  while (args.length > 0) {
    const flag = args.shift();
    const eqMatch = flag.match(EQUALS_FLAG);
    if (eqMatch && VALUE_FLAGS.has(eqMatch[1])) {
      throw new Error(`viewer_usage:${eqMatch[1]} takes a space-separated value`);
    }
    if (seen.has(flag)) throw new Error(`viewer_usage:duplicate flag ${flag}`);
    seen.add(flag);
    const takeValue = () => {
      const value = args[0];
      if (value === undefined || value.startsWith('--')) {
        throw new Error(`viewer_usage:missing value for ${flag}`);
      }
      return args.shift();
    };
    if (flag === '--session') parsed.session = takeValue();
    else if (flag === '--hypothesis') parsed.filters.hypothesisId = takeValue();
    else if (flag === '--type') parsed.filters.type = takeValue();
    else if (flag === '--since') parsed.filters.sinceTs = takeValue();
    else if (flag === '--until') parsed.filters.untilTs = takeValue();
    else if (flag === '--run') parsed.filters.runId = takeValue();
    else if (flag === '--limit') {
      const raw = takeValue();
      if (!/^\d+$/.test(raw) || Number(raw) < 1) throw new Error('viewer_usage:--limit must be a positive integer');
      parsed.filters.limit = Number(raw);
    } else if (flag === '--json' || flag === '--plain') parsed.agentMode = true;
    else if (flag === '--live') parsed.forceLive = true;
    else if (flag === '--file') parsed.forceFile = true;
    else throw new Error(`viewer_usage:unknown flag ${flag}`);
  }
  if (parsed.filters.type !== undefined && !['all', 'event', 'hypothesis'].includes(parsed.filters.type)) {
    throw new Error('viewer_usage:--type must be all|event|hypothesis');
  }
  return parsed;
};

// Agent mode: read, filter, emit raw lines, exit. Byte-verbatim output is
// the contract — agents in any harness parse these lines as NDJSON.
const runAgentMode = async (parsed) => {
  if (parsed.session === undefined) {
    process.stderr.write(`${USAGE}\nagent mode requires --session\n`);
    return 2;
  }
  if (parsed.forceLive) {
    // Live wiring is Task 4 by design; until then fail honestly instead of
    // silently serving stale file contents to a caller that asked to tail.
    process.stderr.write(`${USAGE}\nviewer_usage:--live is not wired yet (Task 4)\n`);
    return 2;
  }
  const filePath = resolveSessionRef(parsed.projectRoot, parsed.session);
  const entries = await readSessionFile(filePath);
  const selected = filterEntries(entries, parsed.filters);
  for (const entry of selected) process.stdout.write(`${entry.raw}\n`);
  return 0;
};

// --- Pure TUI state (layout C): stream over hypothesis table over key bar.
const createInitialState = ({ sessionId }) => ({
  sessionId,
  focus: 'stream',
  paused: false,
  quit: false,
  mode: 'normal',
  filterDraft: '',
  activeFilter: undefined,
  streamScroll: 0,
  tableScroll: 0,
  pickerOpen: false,
});

// (state, key) -> state, no side effects. Keys mirror the spec: tab focus,
// space pause, f filter entry (text until return/escape), s session picker,
// q quit. Unknown keys are no-ops — an unmapped keystroke must never
// mutate state.
const reduce = (state, key) => {
  // Nullish or shapeless key input is a no-op — never throw on a malformed
  // event, and never mutate state for something that isn't a real key.
  if (!key || typeof key !== 'object') return state;
  if (state.mode === 'filter-input') {
    if (key.name === 'return') {
      return { ...state, mode: 'normal', activeFilter: state.filterDraft || undefined };
    }
    if (key.name === 'escape') return { ...state, mode: 'normal', filterDraft: '' };
    if (key.name === 'backspace') return { ...state, filterDraft: state.filterDraft.slice(0, -1) };
    // Code-point length (not UTF-16 .length) so a single emoji/astral
    // character — a surrogate pair — still counts as one unit, while
    // multi-code-point escape sequences (arrow keys, etc.) are still
    // excluded, same as before.
    if (typeof key.sequence === 'string' && [...key.sequence].length === 1) {
      return { ...state, filterDraft: state.filterDraft + key.sequence };
    }
    return state;
  }
  if (key.name === 'q') return { ...state, quit: true };
  if (key.name === 'tab') return { ...state, focus: state.focus === 'stream' ? 'table' : 'stream' };
  if (key.name === 'space') return { ...state, paused: !state.paused };
  if (key.name === 'f') return { ...state, mode: 'filter-input', filterDraft: '' };
  if (key.name === 's') return { ...state, pickerOpen: !state.pickerOpen };
  if (key.name === 'up' || key.name === 'down') {
    const delta = key.name === 'up' ? -1 : 1;
    if (state.focus === 'stream') return { ...state, streamScroll: Math.max(0, state.streamScroll + delta) };
    return { ...state, tableScroll: Math.max(0, state.tableScroll + delta) };
  }
  return state;
};

const main = async () => {
  let parsed;
  try {
    parsed = parseViewerArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(`${USAGE}\n${error.message}\n`);
    process.exitCode = 2;
    return;
  }
  if (parsed.agentMode || !process.stdout.isTTY) {
    process.exitCode = await runAgentMode(parsed);
    return;
  }
  // TUI loop lands in the next task; until then a real terminal invocation
  // reports honestly instead of pretending.
  process.stderr.write('debug_viewer TUI is not wired yet (agent mode: pipe stdout or pass --json)\n');
  process.exitCode = 3;
};

if (require.main === module) {
  main().catch((error) => {
    // Runtime failures (bad session path, ENOENT, etc.) must not crash out
    // through a raw Node stack dump — one clean line on stderr, exit 1.
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = {
  createInitialState,
  parseViewerArgs,
  reduce,
  runAgentMode,
};
