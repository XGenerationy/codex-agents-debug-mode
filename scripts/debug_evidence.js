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
// NaN-ts lines are excluded only while a time filter is active; `limit`
// keeps the LAST n matches (tail-biased). hypothesisId/runId semantics are
// documented at normalizeJoinKeyFilter below.
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
  // Mirrors the route's `query.get(name)?.trim() ?? undefined` EXACTLY: the
  // collector also trims these join keys at write time (POST /log), so a
  // caller-supplied value must be trimmed the same way or padded input would
  // silently fail to match. Only `undefined` means "no filter" — a value
  // that is empty or whitespace-only AFTER trimming is still a real filter
  // (for the empty string) that matches nothing, because the collector
  // rejects empty join keys at ingestion (invalid_join_key) so no stored
  // line ever has one; this mirrors the route rather than treating blank
  // input as absent or raising an error. Unlike the URL route — where
  // URLSearchParams.get always yields a string — this module's filters are
  // arbitrary JS values, so a non-string hypothesisId/runId has no route
  // analog and fails closed like every other malformed filter instead of
  // silently never matching.
  const normalizeJoinKeyFilter = (name) => {
    const value = filters[name];
    if (value === undefined) return undefined;
    if (typeof value !== 'string') throw new Error(`invalid_filter:${name}`);
    return value.trim();
  };
  const hypothesisIdFilter = normalizeJoinKeyFilter('hypothesisId');
  const runIdFilter = normalizeJoinKeyFilter('runId');
  const matched = entries.filter(({ parsed }) => {
    const lineType = parsed.type === undefined ? 'event' : parsed.type;
    if (type !== 'all' && lineType !== type) return false;
    if (hypothesisIdFilter !== undefined && parsed.hypothesisId !== hypothesisIdFilter) return false;
    if (runIdFilter !== undefined && parsed.runId !== runIdFilter) return false;
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
// Mirrors the route's path segment pattern (GET /sessions/:id/logs matches
// `/^\/sessions\/([A-Za-z0-9_-]+)\/logs$/`) — the same documented security
// control applies here: a bare id is interpolated into a filesystem path
// below, so it must be constrained to a safe character set or a value like
// `../../../etc/passwd` would escape the .debug directory entirely.
const SESSION_ID_PATTERN = /^[A-Za-z0-9_-]+$/;

// Enumerate session logs under <projectRoot>/.debug. A project that has
// never run a debug session has no .debug directory yet — that is normal,
// not an error, so ENOENT yields an empty list; any other readdir failure
// (permissions, not-a-directory, ...) still propagates.
const listSessions = async (projectRoot) => {
  let names;
  try {
    names = await readdir(path.join(projectRoot, '.debug'));
  } catch (error) {
    if (error?.code === 'ENOENT') return [];
    throw error;
  }
  const sessions = [];
  for (const name of names) {
    const match = name.match(SESSION_FILE_PATTERN);
    if (match) sessions.push({ sessionId: match[1], filePath: path.join(projectRoot, '.debug', name) });
  }
  return sessions;
};

// A ref is either a direct path to a .log file (passed through as-is — an
// explicit file path supplied by the caller, e.g. from listSessions) or a
// bare session id, which MUST match SESSION_ID_PATTERN before being
// interpolated into a path: unlike the .log passthrough, a bare id is
// untrusted input (e.g. a CLI argument) and would otherwise reach path.join
// unvalidated — `debug-../../..` would escape the .debug directory.
const resolveSessionRef = (projectRoot, ref) => {
  if (ref.endsWith('.log')) return ref;
  if (!SESSION_ID_PATTERN.test(ref)) throw new Error(`invalid_session_ref:${ref}`);
  return path.join(projectRoot, '.debug', `debug-${ref}.log`);
};

// Fetch a live session's filtered lines from the local collector. Filters
// are passed through to the GET route as query parameters — the server
// applies the SAME semantics filterEntries implements locally (parity test
// enforced). Errors surface as distinct codes, never swallowed: evidence
// integrity failures (409) and auth/liveness failures are actionable.
const readSessionLive = ({ port, token, sessionId, filters = {} }) => new Promise((resolve, reject) => {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined) query.set(key, String(value));
  }
  const suffix = query.size > 0 ? `?${query.toString()}` : '';
  const request = http.request({
    hostname: '127.0.0.1',
    port,
    path: `/sessions/${sessionId}/logs${suffix}`,
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` },
  }, (response) => {
    let text = '';
    response.setEncoding('utf8');
    response.on('data', (chunk) => { text += chunk; });
    response.on('end', () => {
      if (response.statusCode === 200) {
        try {
          resolve(parseSessionText(text));
        } catch (error) {
          reject(error);
        }
        return;
      }
      if (response.statusCode === 401) reject(new Error('live_read_unauthorized'));
      else if (response.statusCode === 404) reject(new Error('live_read_unknown_session'));
      else if (response.statusCode === 409) reject(new Error('live_read_log_replaced'));
      else reject(new Error(`live_read_failed:${response.statusCode}`));
    });
  });
  request.on('error', reject);
  request.end();
});

// Poll-by-count live tail: every poll re-fetches the full (filter-free)
// line set and emits only entries beyond the count already seen. Counting
// is immune to same-millisecond timestamps and needs no cursor state on the
// server. Filters are applied by the CALLER over the emitted entries so the
// seen-count always refers to the unfiltered stream.
const createSessionTail = ({ port, token, sessionId }) => {
  let seen = 0;
  return {
    async poll() {
      const entries = await readSessionLive({ port, token, sessionId });
      const fresh = entries.slice(seen);
      seen = entries.length;
      return fresh;
    },
  };
};

// Read the local collector's connection material persisted by its CLI:
// .debug/collector_port and .debug/collector_token.
const discoverCollector = async (projectRoot) => {
  const debugDir = path.join(projectRoot, '.debug');
  const [portText, tokenText] = await Promise.all([
    readFile(path.join(debugDir, 'collector_port'), 'utf8'),
    readFile(path.join(debugDir, 'collector_token'), 'utf8'),
  ]);
  const port = Number(portText.trim());
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('collector_port_invalid');
  return { port, token: tokenText.trim() };
};

module.exports = {
  createSessionTail,
  discoverCollector,
  filterEntries,
  foldHypotheses,
  listSessions,
  parseSessionText,
  readSessionFile,
  readSessionLive,
  resolveSessionRef,
};
