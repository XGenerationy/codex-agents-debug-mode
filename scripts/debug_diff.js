// Per-hypothesis before/after session diff (spec:
// docs/superpowers/specs/2026-08-06-evidence-tools-design.md). The engine
// presents RECORDED verdicts and deterministic deltas only — no severity or
// failure classification anywhere (deciding what "looks like" a failure
// would be pattern-guessing, which this skill forbids). One engine feeds
// three renderers; the no-flag default is TTY-aware: table for humans,
// JSON (schema: 1) for pipes, because agents must never scrape tables.
const {
  escapeEvidenceText,
  foldHypotheses,
  readSessionFile,
  resolveSessionRef,
} = require('./debug_evidence');

const DISAPPEARED_CAP = 20;

const USAGE = 'Usage: debug_diff.js <beforeRef> <afterRef> [projectRoot] [--format=table|md|json]';

// Distinct event-msg texts scoped per hypothesisId (plus an untagged
// bucket) — the deterministic raw material for "what stopped happening".
const messagesByHypothesis = (entries) => {
  const buckets = new Map();
  for (const { parsed } of entries) {
    if (parsed.type !== undefined) continue;
    // Only an ABSENT id is untagged. A present-but-null id is malformed and
    // must reach computeDiff's malformed accounting, exactly like `42` —
    // `?? ''` would silently merge it into the untagged bucket.
    const key = parsed.hypothesisId === undefined ? '' : parsed.hypothesisId;
    if (!buckets.has(key)) buckets.set(key, { messages: new Set(), events: 0 });
    const bucket = buckets.get(key);
    bucket.events += 1;
    if (typeof parsed.msg === 'string') bucket.messages.add(parsed.msg);
  }
  return buckets;
};

const diffBucket = (beforeBucket, afterBucket) => {
  const before = beforeBucket ?? { messages: new Set(), events: 0 };
  const after = afterBucket ?? { messages: new Set(), events: 0 };
  const disappeared = [...before.messages].filter((msg) => !after.messages.has(msg)).sort();
  return {
    beforeEvents: before.events,
    afterEvents: after.events,
    disappeared: disappeared.slice(0, DISAPPEARED_CAP),
    disappearedTruncated: Math.max(0, disappeared.length - DISAPPEARED_CAP),
  };
};

// The engine's contract is string hypothesis ids. Older/pre-validation
// logs can carry a non-string id (hypothesisId: 42 on an event line) or a
// hypothesis-lifecycle line with no id at all (hypothesisId: undefined) —
// either would otherwise reach renderTable's `.padEnd` and crash. The
// empty string is deliberately NOT "malformed": it is messagesByHypothesis'
// own sentinel for the untagged bucket, handled separately below.
const isValidHypothesisId = (id) => typeof id === 'string' && id !== '';

const computeDiff = (beforeEntries, afterEntries) => {
  const beforeFolded = foldHypotheses(beforeEntries);
  const afterFolded = foldHypotheses(afterEntries);
  const beforeBuckets = messagesByHypothesis(beforeEntries);
  const afterBuckets = messagesByHypothesis(afterEntries);
  const allKeys = new Set([
    ...beforeFolded.keys(), ...afterFolded.keys(),
    ...beforeBuckets.keys(), ...afterBuckets.keys(),
  ]);
  const ids = [];
  // Excluded (never silent): every non-string/empty key found anywhere in
  // the union is counted once, distinct-value basis, matching how `ids`
  // itself is deduplicated across the same four sources. The diff's whole
  // point is event deltas, so it is not enough to say a key was ignored —
  // the events bucketed under it (before + after) must be quantified too,
  // or 500 events under a malformed id would silently vanish from every
  // total while the summary implies only "1 id" was affected.
  let ignoredMalformedIds = 0;
  let ignoredMalformedEvents = 0;
  for (const key of allKeys) {
    if (key === '') continue;
    if (isValidHypothesisId(key)) {
      ids.push(key);
      continue;
    }
    ignoredMalformedIds += 1;
    ignoredMalformedEvents += (beforeBuckets.get(key)?.events ?? 0) + (afterBuckets.get(key)?.events ?? 0);
  }
  ids.sort();
  let verdictChanges = 0;
  let newHypotheses = 0;
  const hypotheses = ids.map((id) => {
    const before = beforeFolded.get(id);
    const after = afterFolded.get(id);
    const bucket = diffBucket(beforeBuckets.get(id), afterBuckets.get(id));
    if (before?.status !== after?.status && (before || after)) verdictChanges += 1;
    const seenBefore = before !== undefined || beforeBuckets.has(id);
    if (!seenBefore) newHypotheses += 1;
    return {
      id,
      title: after?.title ?? before?.title ?? null,
      before: { status: before?.status ?? null, note: before?.note ?? null, events: bucket.beforeEvents },
      after: { status: after?.status ?? null, note: after?.note ?? null, events: bucket.afterEvents },
      disappeared: bucket.disappeared,
      disappearedTruncated: bucket.disappearedTruncated,
    };
  });
  const untagged = diffBucket(beforeBuckets.get(''), afterBuckets.get(''));
  return {
    schema: 1,
    hypotheses,
    untagged: {
      before: { events: untagged.beforeEvents },
      after: { events: untagged.afterEvents },
      disappeared: untagged.disappeared,
      disappearedTruncated: untagged.disappearedTruncated,
    },
    summary: { verdictChanges, newHypotheses, ignoredMalformedIds, ignoredMalformedEvents },
  };
};

const renderJson = (diff) => `${JSON.stringify(diff, null, 2)}\n`;

// Stored msg/note/title text is untrusted — it is written by whatever
// process is being debugged, not by this tool. The rendered report IS the
// evidence that gets pasted into PRs/chat, so raw interpolation would let
// log content forge headings, verdicts, or break out of a backtick code
// span (report structure must reflect the engine, never log content).
// escapeEvidenceText (the shared core helper, also used by the viewer TUI)
// turns embedded newlines/quotes/control chars into their escaped literal
// form (a real newline becomes the two printable characters "\" + "n",
// never an actual line break) — this is the single source of truth for
// that layer. Two markdown/table-specific additions on top: backticks are
// escaped separately since JSON escaping does not touch them and this text
// can land inside a backtick code span, and the box-drawing pipe `│`
// becomes `¦` so a crafted id cannot mimic table cell borders — the docs
// promise report structure NEVER reflects log content, without
// qualification. JSON output needs none of this — JSON.stringify(diff, ...)
// already escapes everything correctly there.
function escapeText(value) {
  return escapeEvidenceText(value)
    // Markdown-significant punctuation is backslash-escaped so untrusted log
    // content renders as literal text in the Markdown report (the report is
    // what gets pasted into PRs). Backslash-escaping (CommonMark) neutralizes:
    // backticks (code-span delimiters, which ignore backslash INSIDE a span —
    // so we also avoid wrapping untrusted text in spans), the box-drawing
    // pipe (table-cell mimicry), raw-HTML delimiters <>& (XSS if a consumer
    // renders md with HTML enabled), and link/image syntax []()!. Table
    // output shows the literal backslash+char, consistent with how it already
    // rendered escaped backticks. JSON output needs none of this.
    .replaceAll('`', '\\`')
    .replaceAll('│', '¦')
    .replaceAll('<', '\\<')
    .replaceAll('>', '\\>')
    .replaceAll('&', '\\&')
    .replaceAll('[', '\\[')
    .replaceAll(']', '\\]')
    .replaceAll('(', '\\(')
    .replaceAll(')', '\\)')
    .replaceAll('!', '\\!');
}

// Stored status is untrusted log content, and older logs can carry a
// non-string value (foldHypotheses copies parsed.status verbatim). Escape
// it like every other rendered field, coerce to a string so `.padEnd`
// cannot throw on a number, cap it so it cannot widen or misalign the
// status columns, and retain the em-dash fallback for nullish values.
const STATUS_COLUMN_MAX = 12;
function statusOr(status) {
  if (status === null || status === undefined) return '—';
  const text = escapeText(status);
  return text.length > STATUS_COLUMN_MAX ? `${text.slice(0, STATUS_COLUMN_MAX - 1)}…` : text;
}

// Hypothesis ids are short identifiers by convention; 40 chars comfortably
// fits real-world ids while keeping the bordered table readable if an
// oversized id somehow reaches here — truncated with an ellipsis rather
// than silently overflowing the border or wrapping.
const ID_COLUMN_MAX = 40;
const truncateId = (id) => (id.length > ID_COLUMN_MAX ? `${id.slice(0, ID_COLUMN_MAX - 1)}…` : id);

const renderTable = (diff) => {
  // Escape BEFORE truncating so the 40-char cap — and therefore the id
  // column's width — measures what is actually printed, not the raw
  // (potentially longer, once escaped) source id.
  const displayIds = diff.hypotheses.map((h) => truncateId(escapeText(h.id)));
  // Width is sampled across every rendered id (not just the first row), so
  // the id column — and therefore every row's total width — stays aligned
  // regardless of which row has the longest id.
  const idWidth = Math.max(2, ...displayIds.map((id) => id.length));
  const rows = diff.hypotheses.map((h, i) => (
    `│ ${displayIds[i].padEnd(idWidth)} │ ${statusOr(h.before.status).padEnd(12)} │ ${statusOr(h.after.status).padEnd(12)} │ ${`${h.before.events} → ${h.after.events}`.padEnd(9)} │`
  ));
  const header = `│ ${'id'.padEnd(idWidth)} │ ${'before'.padEnd(12)} │ ${'after'.padEnd(12)} │ ${'events'.padEnd(9)} │`;
  // header and every row share the same column widths by construction, so
  // header's length IS the row width — no need to sample rows separately
  // (and this stays correct even when there are zero hypotheses to show).
  const width = header.length;
  const bar = '─'.repeat(Math.max(width - 2, 10));
  const lines = [`┌${bar}┐`, header, `├${bar}┤`, ...rows, `└${bar}┘`];
  for (const h of diff.hypotheses) {
    if (h.disappeared.length > 0) {
      lines.push(`disappeared after fix (${escapeText(h.id)}${h.disappearedTruncated ? `, +${h.disappearedTruncated} more` : ''}):`);
      for (const msg of h.disappeared) lines.push(`  - ${escapeText(msg)}`);
    }
  }
  if (diff.untagged.disappeared.length > 0) {
    lines.push('disappeared (untagged):');
    for (const msg of diff.untagged.disappeared) lines.push(`  - ${escapeText(msg)}`);
  }
  lines.push(`verdict changes: ${diff.summary.verdictChanges}  new hypotheses: ${diff.summary.newHypotheses}`);
  if (diff.summary.ignoredMalformedIds > 0) {
    lines.push(`${diff.summary.ignoredMalformedIds} malformed hypothesis ids ignored (${diff.summary.ignoredMalformedEvents} events excluded from totals)`);
  }
  return `${lines.join('\n')}\n`;
};

const renderMarkdown = (diff) => {
  const lines = ['## Evidence diff', ''];
  for (const h of diff.hypotheses) {
    const title = h.title ? ` — ${escapeText(h.title)}` : '';
    lines.push(`**${escapeText(h.id)}${title}**  ${statusOr(h.before.status)} → ${statusOr(h.after.status)}`);
    lines.push('');
    lines.push(`- events ${h.before.events} → ${h.after.events}`);
    // Double quotes, not a backtick code span: a Markdown code span treats
    // backticks as delimiters even when preceded by a backslash, so
    // escapeText's `\`` escaping cannot guarantee a backticked disappeared
    // message stays inside its span. Plain text in quotes relies on
    // escapeText for newline/control neutralization (the real safety) and
    // matches the note rendering on the next line.
    for (const msg of h.disappeared) lines.push(`- gone: "${escapeText(msg)}"`);
    if (h.disappearedTruncated > 0) lines.push(`- …and ${h.disappearedTruncated} more disappeared`);
    if (h.after.note) lines.push(`- note: "${escapeText(h.after.note)}"`);
    lines.push('');
  }
  lines.push(`_verdict changes: ${diff.summary.verdictChanges} · new hypotheses: ${diff.summary.newHypotheses}_`);
  if (diff.summary.ignoredMalformedIds > 0) {
    lines.push(`_${diff.summary.ignoredMalformedIds} malformed hypothesis ids ignored (${diff.summary.ignoredMalformedEvents} events excluded from totals)_`);
  }
  return `${lines.join('\n')}\n`;
};

// Fail-closed argv parsing, mirroring the viewer's stance: an unrecognized
// flag, a repeated --format, or the space form (`--format md`, which would
// otherwise silently swallow `md` as a positional and shift beforeRef/
// afterRef) all reject the invocation rather than guessing what was meant.
// `--format=<value>` is this tool's one canonical flag form.
const parseArgs = (args) => {
  const positional = [];
  let format;
  let formatSeen = false;
  for (const arg of args) {
    if (!arg.startsWith('--')) {
      positional.push(arg);
      continue;
    }
    if (arg.startsWith('--format=')) {
      if (formatSeen) return { error: 'duplicate --format flag' };
      formatSeen = true;
      format = arg.slice('--format='.length);
      continue;
    }
    if (arg === '--format') {
      return { error: '--format requires a value: --format=<table|md|json>' };
    }
    return { error: `unknown flag: ${arg}` };
  }
  return { positional, format };
};

const main = async () => {
  const args = process.argv.slice(2);
  const parsed = parseArgs(args);
  if (parsed.error) {
    process.stderr.write(`debug_diff: ${parsed.error}\n${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const { positional, format: formatArg } = parsed;
  // Reject any count other than two or three: a lower bound alone would
  // silently accept extra args (e.g. `debug_diff.js a b /root extra`), and
  // a mistyped ref or shell-glob expansion would then produce a report over
  // the wrong sessions with no warning — contradicting the fail-closed
  // stance documented above.
  if (positional.length < 2 || positional.length > 3) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const [beforeRef, afterRef, projectRoot = process.cwd()] = positional;
  const format = formatArg ?? (process.stdout.isTTY ? 'table' : 'json');
  if (!['table', 'md', 'json'].includes(format)) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  // Read before/after separately (not one shared try/catch) — a diff over
  // a missing or malformed session must never render a partial report, and
  // "cannot read session" alone leaves the operator guessing which of the
  // two refs was the problem.
  let beforeEntries;
  try {
    beforeEntries = await readSessionFile(resolveSessionRef(projectRoot, beforeRef));
  } catch (error) {
    process.stderr.write(`debug_diff: cannot read before session (${beforeRef}): ${error.message}\n`);
    process.exitCode = 1;
    return;
  }
  let afterEntries;
  try {
    afterEntries = await readSessionFile(resolveSessionRef(projectRoot, afterRef));
  } catch (error) {
    process.stderr.write(`debug_diff: cannot read after session (${afterRef}): ${error.message}\n`);
    process.exitCode = 1;
    return;
  }
  const diff = computeDiff(beforeEntries, afterEntries);
  const rendered = format === 'json' ? renderJson(diff) : format === 'md' ? renderMarkdown(diff) : renderTable(diff);
  process.stdout.write(rendered);
};

if (require.main === module) {
  main().catch((error) => {
    // Same discipline as debug_viewer: runtime failures surface as one
    // clean line on stderr, never a raw Node stack dump.
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { computeDiff, renderJson, renderMarkdown, renderTable };
