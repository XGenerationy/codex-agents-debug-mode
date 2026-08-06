// Shared evidence core for debug_viewer.js and debug_diff.js (spec:
// docs/superpowers/specs/2026-08-06-evidence-tools-design.md). One module
// owns reading, filtering, and hypothesis folding so the two CLIs and the
// collector's GET /sessions/:id/logs route can never drift apart — the
// filter semantics here are asserted IDENTICAL to the route by a parity
// test in debug_evidence.test.js. Zero runtime dependencies.
const { readFile, readdir } = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');

// Parse complete NDJSON text into ordered { raw, parsed } entries. `raw` is
// preserved byte-for-byte so agent mode can re-emit stored lines verbatim.
// A malformed line fails closed with its 1-based line number — session logs
// are written exclusively by the collector, so a parse failure means the
// file was tampered with or truncated mid-line, and skipping it silently
// would present partial evidence as complete.
const parseSessionText = (text) => {
  const entries = [];
  let lineNumber = 0;
  for (const raw of text.split('\n')) {
    lineNumber += 1;
    if (!raw) continue;
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`malformed_session_line:${lineNumber}`);
    }
    entries.push({ raw, parsed });
  }
  return entries;
};

// Read a session log from disk. The collector terminates every persisted
// line with \n, so anything after the final newline is a torn tail from an
// in-flight append — dropped here exactly like the GET route's
// bytesWritten-bounded read never emits it.
const readSessionFile = async (filePath) => {
  const text = await readFile(filePath, 'utf8');
  const lastNewline = text.lastIndexOf('\n');
  return parseSessionText(lastNewline === -1 ? '' : text.slice(0, lastNewline + 1));
};

const FILTER_KEYS = new Set(['hypothesisId', 'type', 'sinceTs', 'untilTs', 'runId', 'limit']);
const TYPE_VALUES = new Set(['all', 'event', 'hypothesis']);

// Filter semantics MUST mirror GET /sessions/:id/logs exactly (enforced by
// the parity test): unknown keys and malformed values fail closed; `type`
// classifies lines WITHOUT a type field as events and unknown future types
// match only 'all'; time bounds are inclusive Date.parse comparisons and
// NaN-ts lines are excluded only while a time filter is active; hypothesisId
// and runId compare byte-exactly (both trimmed at write time by the
// collector); `limit` keeps the LAST n matches (tail-biased).
const filterEntries = (entries, filters = {}) => {
  for (const key of Object.keys(filters)) {
    if (!FILTER_KEYS.has(key)) throw new Error(`invalid_filter:${key}`);
  }
  const type = filters.type ?? 'all';
  if (!TYPE_VALUES.has(type)) throw new Error('invalid_filter:type');
  const parseBound = (name) => {
    if (filters[name] === undefined) return undefined;
    const parsed = Date.parse(filters[name]);
    if (Number.isNaN(parsed)) throw new Error(`invalid_filter:${name}`);
    return parsed;
  };
  const sinceTs = parseBound('sinceTs');
  const untilTs = parseBound('untilTs');
  let limit;
  if (filters.limit !== undefined) {
    if (!Number.isInteger(filters.limit) || filters.limit < 1) throw new Error('invalid_filter:limit');
    limit = filters.limit;
  }
  const matched = entries.filter(({ parsed }) => {
    const lineType = parsed.type === undefined ? 'event' : parsed.type;
    if (type !== 'all' && lineType !== type) return false;
    if (filters.hypothesisId !== undefined && parsed.hypothesisId !== filters.hypothesisId) return false;
    if (filters.runId !== undefined && parsed.runId !== filters.runId) return false;
    if (sinceTs !== undefined || untilTs !== undefined) {
      const lineTs = Date.parse(parsed.ts);
      if (Number.isNaN(lineTs)) return false;
      if (sinceTs !== undefined && lineTs < sinceTs) return false;
      if (untilTs !== undefined && lineTs > untilTs) return false;
    }
    return true;
  });
  return limit === undefined ? matched : matched.slice(-limit);
};

// Derive per-hypothesis state from lifecycle lines: latest line wins for
// status/note/ts (file order is the tiebreak for same-millisecond lines —
// guaranteed by the collector's per-session append chain), the FIRST
// non-empty title is retained (later status flips rarely restate it), and
// the full ordered history is preserved for audit.
const foldHypotheses = (entries) => {
  const folded = new Map();
  for (const { parsed } of entries) {
    if (parsed.type !== 'hypothesis') continue;
    const existing = folded.get(parsed.hypothesisId);
    const record = existing ?? {
      hypothesisId: parsed.hypothesisId,
      title: undefined,
      status: undefined,
      note: undefined,
      ts: undefined,
      history: [],
    };
    record.status = parsed.status;
    record.note = parsed.note;
    record.ts = parsed.ts;
    if (record.title === undefined && typeof parsed.title === 'string' && parsed.title !== '') {
      record.title = parsed.title;
    }
    record.history.push(parsed);
    if (!existing) folded.set(parsed.hypothesisId, record);
  }
  return folded;
};

const SESSION_FILE_PATTERN = /^debug-(.+)\.log$/;

// Enumerate session logs under <projectRoot>/.debug.
const listSessions = async (projectRoot) => {
  const names = await readdir(path.join(projectRoot, '.debug'));
  const sessions = [];
  for (const name of names) {
    const match = name.match(SESSION_FILE_PATTERN);
    if (match) sessions.push({ sessionId: match[1], filePath: path.join(projectRoot, '.debug', name) });
  }
  return sessions;
};

// A ref is either a direct path to a .log file or a bare session id.
const resolveSessionRef = (projectRoot, ref) => {
  if (ref.endsWith('.log')) return ref;
  return path.join(projectRoot, '.debug', `debug-${ref}.log`);
};

module.exports = {
  filterEntries,
  foldHypotheses,
  listSessions,
  parseSessionText,
  readSessionFile,
  resolveSessionRef,
};
