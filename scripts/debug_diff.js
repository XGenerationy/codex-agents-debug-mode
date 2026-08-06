// Per-hypothesis before/after session diff (spec:
// docs/superpowers/specs/2026-08-06-evidence-tools-design.md). The engine
// presents RECORDED verdicts and deterministic deltas only — no severity or
// failure classification anywhere (deciding what "looks like" a failure
// would be pattern-guessing, which this skill forbids). One engine feeds
// three renderers; the no-flag default is TTY-aware: table for humans,
// JSON (schema: 1) for pipes, because agents must never scrape tables.
const {
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
    const key = parsed.hypothesisId ?? '';
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

const computeDiff = (beforeEntries, afterEntries) => {
  const beforeFolded = foldHypotheses(beforeEntries);
  const afterFolded = foldHypotheses(afterEntries);
  const beforeBuckets = messagesByHypothesis(beforeEntries);
  const afterBuckets = messagesByHypothesis(afterEntries);
  const ids = [...new Set([
    ...beforeFolded.keys(), ...afterFolded.keys(),
    ...[...beforeBuckets.keys()].filter(Boolean), ...[...afterBuckets.keys()].filter(Boolean),
  ])].sort();
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
    summary: { verdictChanges, newHypotheses },
  };
};

const renderJson = (diff) => `${JSON.stringify(diff, null, 2)}\n`;

const statusOr = (status) => status ?? '—';

const renderTable = (diff) => {
  const rows = diff.hypotheses.map((h) => (
    `│ ${h.id.padEnd(4)} │ ${statusOr(h.before.status).padEnd(12)} │ ${statusOr(h.after.status).padEnd(12)} │ ${`${h.before.events} → ${h.after.events}`.padEnd(9)} │`
  ));
  const width = rows[0]?.length ?? 52;
  const bar = '─'.repeat(Math.max(width - 2, 10));
  const lines = [`┌${bar}┐`, `│ id   │ before       │ after        │ events    │`, `├${bar}┤`, ...rows, `└${bar}┘`];
  for (const h of diff.hypotheses) {
    if (h.disappeared.length > 0) {
      lines.push(`disappeared after fix (${h.id}${h.disappearedTruncated ? `, +${h.disappearedTruncated} more` : ''}):`);
      for (const msg of h.disappeared) lines.push(`  - ${msg}`);
    }
  }
  if (diff.untagged.disappeared.length > 0) {
    lines.push('disappeared (untagged):');
    for (const msg of diff.untagged.disappeared) lines.push(`  - ${msg}`);
  }
  lines.push(`verdict changes: ${diff.summary.verdictChanges}  new hypotheses: ${diff.summary.newHypotheses}`);
  return `${lines.join('\n')}\n`;
};

const renderMarkdown = (diff) => {
  const lines = ['## Evidence diff', ''];
  for (const h of diff.hypotheses) {
    const title = h.title ? ` — ${h.title}` : '';
    lines.push(`**${h.id}${title}**  ${statusOr(h.before.status)} → ${statusOr(h.after.status)}`);
    lines.push('');
    lines.push(`- events ${h.before.events} → ${h.after.events}`);
    for (const msg of h.disappeared) lines.push(`- gone: \`${msg}\``);
    if (h.disappearedTruncated > 0) lines.push(`- …and ${h.disappearedTruncated} more disappeared`);
    if (h.after.note) lines.push(`- note: "${h.after.note}"`);
    lines.push('');
  }
  lines.push(`_verdict changes: ${diff.summary.verdictChanges} · new hypotheses: ${diff.summary.newHypotheses}_`);
  return `${lines.join('\n')}\n`;
};

const main = async () => {
  const args = process.argv.slice(2);
  const formatFlag = args.find((a) => a.startsWith('--format='));
  const positional = args.filter((a) => !a.startsWith('--'));
  if (positional.length < 2) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const [beforeRef, afterRef, projectRoot = process.cwd()] = positional;
  let format = formatFlag ? formatFlag.slice('--format='.length) : (process.stdout.isTTY ? 'table' : 'json');
  if (!['table', 'md', 'json'].includes(format)) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  let beforeEntries;
  let afterEntries;
  try {
    beforeEntries = await readSessionFile(resolveSessionRef(projectRoot, beforeRef));
    afterEntries = await readSessionFile(resolveSessionRef(projectRoot, afterRef));
  } catch (error) {
    // Fail closed with the offending ref named — a diff over a missing or
    // malformed session must never render a partial report.
    process.stderr.write(`debug_diff: cannot read session (${error.message})\n`);
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
