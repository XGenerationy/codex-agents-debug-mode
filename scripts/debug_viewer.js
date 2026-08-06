// Layout-C TUI + agent-mode session viewer (spec:
// docs/superpowers/specs/2026-08-06-evidence-tools-design.md). Mode rule:
// stdout TTY -> TUI; otherwise (or --json/--plain) -> agent mode, which
// applies the shared filter engine and re-emits the selected RAW stored
// lines byte-for-byte. Zero dependencies; all interactive state changes are
// pure reducers so they can be unit-tested without a terminal.
const path = require('node:path');
const {
  createSessionTail,
  discoverCollector,
  escapeEvidenceText,
  filterEntries,
  foldHypotheses,
  listSessions,
  readSessionFile,
  readSessionLive,
  resolveSessionRef,
} = require('./debug_evidence');

const USAGE = 'Usage: debug_viewer.js [projectRoot] --session <id|path> '
  + '[--hypothesis <id>] [--type all|event|hypothesis] [--since <ISO>] '
  + '[--until <ISO>] [--run <id>] [--limit <n>] '
  + '[--live (bare session ids only; .log file paths are file-mode)|--file] [--json|--plain]';

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
    // Live agent read: discover the collector, let the server apply the
    // filters (GET-parity guaranteed by the core's test), emit the raw
    // stored lines byte-verbatim. Errors (collector_not_running,
    // live_read_*) propagate to main's catch: one line, exit 1.
    const collector = await discoverCollector(parsed.projectRoot);
    const entries = await readSessionLive({ ...collector, sessionId: parsed.session, filters: parsed.filters });
    for (const entry of entries) process.stdout.write(`${entry.raw}\n`);
    return 0;
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
  // Ctrl+C must quit from every mode — raw stdin swallows the terminal's
  // own SIGINT-on-Ctrl+C, so without this check filter-input mode would
  // trap the user with no way out (plain 'q' just types into the draft).
  if (key.ctrl && key.name === 'c') return { ...state, quit: true };
  if (state.mode === 'filter-input') {
    if (key.name === 'return') {
      return { ...state, mode: 'normal', activeFilter: state.filterDraft || undefined };
    }
    if (key.name === 'escape') return { ...state, mode: 'normal', filterDraft: '' };
    // Code-point slice, matching the append below — backspacing an astral
    // character must remove the whole surrogate pair, never split it (a
    // lone surrogate would poison the committed filter downstream).
    if (key.name === 'backspace') return { ...state, filterDraft: [...state.filterDraft].slice(0, -1).join('') };
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

// Pure frame renderer for layout C. Returns a full-screen string of exactly
// `rows` lines, each hard-truncated to `columns` — the painter writes it in
// one stdout call, so tearing can't interleave partial rows. Kept free of
// cursor-addressing so unit tests can assert on plain text.
const formatEntryRow = (parsed) => {
  // Every interpolated field here is untrusted log content — route it
  // through escapeEvidenceText so it can never forge a row's structure or
  // (once JSON.parse rehydrates a stored escape sequence into a real
  // control character) inject terminal control sequences into the TUI.
  const time = escapeEvidenceText(typeof parsed.ts === 'string' ? parsed.ts.slice(11, 19) : '--:--:--');
  if (parsed.type === 'hypothesis') {
    const note = parsed.note ? ` "${escapeEvidenceText(parsed.note)}"` : '';
    return `${time} ◆ ${escapeEvidenceText(parsed.hypothesisId)} → ${escapeEvidenceText(parsed.status)}${note}`;
  }
  const tag = parsed.hypothesisId ? `${escapeEvidenceText(parsed.hypothesisId)} ` : '';
  const loc = parsed.loc ? `  ${escapeEvidenceText(parsed.loc)}` : '';
  return `${time} ${tag}${escapeEvidenceText(parsed.msg ?? '')}${loc}`;
};

const renderFrame = (state, entries, { columns, rows, live }) => {
  // Code-point-safe clip: slicing UTF-16 units can split a surrogate pair
  // at the boundary and emit a lone surrogate. Display-width (CJK/emoji
  // rendering as double-width cells) is explicitly out of scope for a
  // zero-dependency tool — code-unit well-formedness is the guarantee.
  const clip = (text) => {
    const points = [...text];
    return points.length > columns ? points.slice(0, Math.max(0, columns)).join('') : text;
  };
  const folded = foldHypotheses(entries);
  // Folded values are derived from untrusted log content just like raw
  // entries — same escapeEvidenceText discipline as formatEntryRow above.
  const tableRows = [...folded.values()].map((h) => {
    const when = escapeEvidenceText(typeof h.ts === 'string' ? h.ts.slice(11, 16) : '');
    const detail = escapeEvidenceText(h.title ?? h.note ?? '');
    return `${escapeEvidenceText(h.hypothesisId)}  ${escapeEvidenceText(h.status)}  ${detail}  ${when}`;
  });
  const tableHeight = Math.min(Math.max(tableRows.length, 1), Math.max(3, Math.floor(rows / 3)));
  const streamHeight = rows - tableHeight - 3;
  const streamRows = entries.map((entry) => formatEntryRow(entry.parsed));
  const visibleStream = streamRows.slice(-(streamHeight + state.streamScroll), streamRows.length - state.streamScroll || undefined);
  const status = state.paused ? 'paused' : (live ? '● live' : 'file');
  const filterBadge = state.activeFilter ? `  [${state.activeFilter}]` : '';
  const lines = [];
  lines.push(clip(`─ ${escapeEvidenceText(state.sessionId)}${filterBadge} ── ${status} ${'─'.repeat(Math.max(0, columns))}`));
  for (let i = 0; i < streamHeight; i += 1) lines.push(clip(visibleStream[i] ?? ''));
  lines.push(clip(`─ hypotheses ${'─'.repeat(Math.max(0, columns))}`));
  for (let i = 0; i < tableHeight; i += 1) lines.push(clip(tableRows[i + state.tableScroll] ?? ''));
  lines.push(clip('f:filter  s:sessions  tab:focus  space:pause  q:quit'));
  return lines.slice(0, rows).join('\n');
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
  // TUI loop: raw-mode stdin -> pure reducers -> full-frame repaint on the
  // alternate screen. The painter is the ONLY untested-by-CI code (spec
  // decision); everything it renders comes from tested functions.
  const readline = require('node:readline');
  let sessionId = parsed.session;
  if (sessionId === undefined) {
    const sessions = await listSessions(parsed.projectRoot);
    if (sessions.length === 0) {
      process.stderr.write('no sessions under .debug/\n');
      process.exitCode = 1;
      return;
    }
    sessionId = sessions[sessions.length - 1].sessionId;
  }
  let state = createInitialState({ sessionId });
  let entries = [];
  let live = false;
  let tail = null;
  if (!parsed.forceFile) {
    try {
      const collector = await discoverCollector(parsed.projectRoot);
      tail = createSessionTail({ ...collector, sessionId });
      entries = await tail.poll();
      live = true;
    } catch {
      tail = null;
    }
  }
  if (!live) {
    if (parsed.forceLive) {
      process.stderr.write('collector not reachable; --live unavailable\n');
      process.exitCode = 1;
      return;
    }
    entries = await readSessionFile(resolveSessionRef(parsed.projectRoot, sessionId));
  }
  const applyActiveFilter = (current, all) => (
    current.activeFilter ? filterEntries(all, { hypothesisId: current.activeFilter }) : all
  );
  const paint = () => {
    const { columns = 80, rows = 24 } = process.stdout;
    process.stdout.write(`\u001b[2J\u001b[H${renderFrame(state, applyActiveFilter(state, entries), { columns, rows, live })}`);
  };
  process.stdout.write('\u001b[?1049h');
  // Unconditional restore: covers any uncaught throw (e.g. the poll
  // fallback below) and external kills so a failure never strands the
  // terminal on the alternate screen in raw mode; shutdown() below is
  // the clean path, this is the belt-and-suspenders one.
  process.on('exit', () => {
    process.stdout.write('\u001b[?1049l');
    if (process.stdin.isTTY) process.stdin.setRawMode(false);
  });
  readline.emitKeypressEvents(process.stdin);
  if (process.stdin.isTTY) process.stdin.setRawMode(true);
  const pollTimer = setInterval(async () => {
    if (state.paused || tail === null) return;
    try {
      const fresh = await tail.poll();
      if (fresh.length > 0) {
        entries = entries.concat(fresh);
        paint();
      }
    } catch {
      // Session retired mid-watch: fall back to the file, visibly.
      live = false;
      tail = null;
      try {
        entries = await readSessionFile(resolveSessionRef(parsed.projectRoot, sessionId));
      } catch {
        // Fallback read failed too (collector stopped AND log removed).
        // setInterval never awaits this callback, so an unhandled
        // rejection here would kill the process with the alt-screen
        // still active and raw mode still on — stale evidence beats a
        // corrupted terminal, so keep the last-known entries instead.
      }
      paint();
    }
  }, 500);
  const shutdown = () => {
    clearInterval(pollTimer);
    process.stdout.off('resize', paint);
    process.stdout.write('\u001b[?1049l');
    if (process.stdin.isTTY) process.stdin.setRawMode(false);
    process.stdin.pause();
  };
  process.stdin.on('keypress', (_, key) => {
    state = reduce(state, key ?? {});
    if (state.quit) {
      shutdown();
      return;
    }
    paint();
  });
  process.stdout.on('resize', paint);
  paint();
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
  renderFrame,
  runAgentMode,
};
