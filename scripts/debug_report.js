#!/usr/bin/env node
'use strict';

// Single-session evidence report: the CI/step-summary sibling of
// debug_viewer (live analysis) and debug_diff (two-session verify).
// Dual mode: interactive TTY gets a human text summary; piped output
// defaults to markdown (Step Summary use case); --format=json is the
// machine surface. The renderer never classifies — it folds and counts
// exactly what the session recorded.

const path = require('node:path');
const {
  escapeMarkdownText,
  foldHypotheses,
  readSessionFile,
  resolveSessionRef,
} = require('./debug_evidence');

const USAGE = 'Usage: debug_report.js <sessionRef> [projectRoot] [--format=text|md|json]';
const EXCERPT_CAP = 20;
// Per-value length bounds for the HUMAN surfaces only. A GitHub Step Summary
// is capped at 1 MiB, and a single logged line can be far larger than any
// reader wants inline; renderJson stays verbatim because the machine surface
// is already bounded by the collector's own per-session byte/event limits.
const EXCERPT_CHAR_CAP = 500;
const FIELD_CHAR_CAP = 200;
const STATUS_CHAR_CAP = 40;
// Per-FIELD caps alone do not bound the DOCUMENT: a collector-valid session
// carrying 2,000 hypotheses rendered 1,732,966 bytes of markdown, well past
// the 1 MiB a Step Summary accepts. Blocks beyond this cap are announced, not
// dropped in silence, and report.json still carries every one of them.
const HYPOTHESIS_RENDER_CAP = 100;
const SESSION_FILE_PATTERN = /^debug-([A-Za-z0-9_-]+)\.log$/;

// Same equals-only convention as debug_diff (space-form values rejected).
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
      return { error: '--format requires a value: --format=<text|md|json>' };
    }
    return { error: `unknown flag: ${arg}` };
  }
  return { positional, format };
};

const buildReport = (entries, { sessionId = null, caveats = [] } = {}) => {
  const folded = foldHypotheses(entries);
  let events = 0;
  let hypothesisLines = 0;
  let otherTypedLines = 0;
  let untaggedEvents = 0;
  const taggedCounts = new Map();
  const allEventMsgs = [];
  for (const { parsed } of entries) {
    if (parsed.type === 'hypothesis') {
      hypothesisLines += 1;
      continue;
    }
    // Parity with the shared core and GET /sessions/:id/logs: ONLY an absent
    // type is an event. A line carrying a type this renderer predates is
    // counted on its own — folding it into events would inflate the counts
    // and leak an unknown line shape into the excerpts, while dropping it
    // silently would hide it; it still shows up in `entries`.
    if (parsed.type !== undefined) {
      otherTypedLines += 1;
      continue;
    }
    events += 1;
    // Verbatim, never String()-coerced: `String({a:1})` renders the useless
    // '[object Object]', and a msg object carrying `toString: null` would
    // make the coercion THROW. Values here come from JSON.parse, so they are
    // finite and acyclic — JSON.stringify is total once undefined is handled.
    allEventMsgs.push(typeof parsed.msg === 'string'
      ? parsed.msg
      : parsed.msg === undefined ? '(missing msg)' : JSON.stringify(parsed.msg));
    if (typeof parsed.hypothesisId === 'string' && parsed.hypothesisId !== '') {
      taggedCounts.set(parsed.hypothesisId, (taggedCounts.get(parsed.hypothesisId) ?? 0) + 1);
    } else {
      untaggedEvents += 1;
    }
  }
  const ids = [...new Set([...folded.keys(), ...taggedCounts.keys()])]
    .filter((id) => typeof id === 'string' && id !== '')
    .sort();
  const hypotheses = ids.map((id) => {
    const record = folded.get(id);
    return {
      id,
      title: typeof record?.title === 'string' ? record.title : null,
      status: typeof record?.status === 'string' ? record.status : null,
      note: typeof record?.note === 'string' ? record.note : null,
      lines: record ? record.history.length : 0,
      events: taggedCounts.get(id) ?? 0,
    };
  });
  // Keep the LAST events — the tail is where a failing run's story ends.
  const excerpts = allEventMsgs.slice(-EXCERPT_CAP);
  return {
    schema: 1,
    session: {
      id: sessionId, entries: entries.length, events, hypothesisLines, otherTypedLines,
    },
    // Labels that have to travel WITH the evidence rather than living only in
    // whatever log produced it: a reader holding the artifact and not the job
    // must still see them. Callers pass the wording; this only guarantees the
    // shape (non-empty strings, verbatim — the machine surface is never
    // capped, exactly as for excerpts and hypothesis fields).
    caveats: caveats.filter((caveat) => typeof caveat === 'string' && caveat !== ''),
    hypotheses,
    untaggedEvents,
    excerpts,
    excerptsTruncated: Math.max(0, allEventMsgs.length - EXCERPT_CAP),
  };
};

const renderJson = (report) => `${JSON.stringify(report, null, 2)}\n`;

// Truncation is ANNOUNCED, never silent: an over-cap value keeps its first
// cap-1 characters and ends in an ellipsis, so the result is exactly `cap`
// characters and a reader can tell the tail was dropped. Applied to the
// ESCAPED text (not the raw value) — escaping can multiply a hostile string's
// length several times over, so capping afterwards is the only order that
// actually bounds what the surface emits. Slicing escaped text is safe: it
// only removes characters, and every structural character is already neutered.
const capped = (value, cap) => {
  if (value.length <= cap) return value;
  const head = value.slice(0, cap - 1);
  // slice() counts UTF-16 code units, so a cut can land BETWEEN the halves of
  // an astral character (an emoji in a log message). The orphaned high
  // surrogate is not valid UTF-8 and would reach the reader as U+FFFD, so it
  // is dropped — the result is cap-1 characters in that case, never garbage.
  const lastUnit = head.charCodeAt(head.length - 1);
  const whole = lastUnit >= 0xD800 && lastUnit <= 0xDBFF ? head.slice(0, -1) : head;
  return `${whole}…`;
};

const statusOr = (status) => (
  status === null ? '—' : capped(escapeMarkdownText(status), STATUS_CHAR_CAP)
);

const renderMarkdown = (report) => {
  const lines = ['## Debug evidence report', ''];
  const id = report.session.id === null ? '(file)' : escapeMarkdownText(report.session.id);
  lines.push(`_session ${id} · ${report.session.events} events · ${report.session.hypothesisLines} hypothesis lines_`);
  lines.push('');
  // Above the evidence, never below it: a caveat qualifies everything that
  // follows, so a reader must meet it first.
  for (const caveat of report.caveats ?? []) {
    lines.push(`> **Caveat:** ${capped(escapeMarkdownText(caveat), EXCERPT_CHAR_CAP)}`);
    lines.push('');
  }
  for (const h of report.hypotheses.slice(0, HYPOTHESIS_RENDER_CAP)) {
    const title = h.title ? ` — ${capped(escapeMarkdownText(h.title), FIELD_CHAR_CAP)}` : '';
    lines.push(`**${capped(escapeMarkdownText(h.id), FIELD_CHAR_CAP)}${title}**  ${statusOr(h.status)}`);
    lines.push('');
    lines.push(`- events ${h.events} · hypothesis lines ${h.lines}`);
    if (h.note) lines.push(`- note: "${capped(escapeMarkdownText(h.note), FIELD_CHAR_CAP)}"`);
    lines.push('');
  }
  const hidden = Math.max(0, report.hypotheses.length - HYPOTHESIS_RENDER_CAP);
  if (hidden > 0) {
    lines.push(`_…and ${hidden} more ${hidden === 1 ? 'hypothesis' : 'hypotheses'} (full list in report.json)_`);
    lines.push('');
  }
  if (report.untaggedEvents > 0) {
    lines.push(`_untagged events: ${report.untaggedEvents}_`);
    lines.push('');
  }
  if (report.excerpts.length > 0) {
    lines.push('**Last events**');
    lines.push('');
    for (const msg of report.excerpts) lines.push(`- "${capped(escapeMarkdownText(msg), EXCERPT_CHAR_CAP)}"`);
    if (report.excerptsTruncated > 0) lines.push(`- …and ${report.excerptsTruncated} more earlier event${report.excerptsTruncated === 1 ? '' : 's'}`);
    lines.push('');
  }
  return `${lines.join('\n')}\n`;
};

const renderText = (report) => {
  const lines = [];
  const id = report.session.id === null ? '(file)' : escapeMarkdownText(report.session.id);
  lines.push(`Debug evidence report — session ${id}`);
  lines.push(`entries ${report.session.entries} · events ${report.session.events} · hypothesis lines ${report.session.hypothesisLines} · untagged ${report.untaggedEvents}`);
  for (const caveat of report.caveats ?? []) {
    lines.push(`caveat: ${capped(escapeMarkdownText(caveat), EXCERPT_CHAR_CAP)}`);
  }
  lines.push('');
  for (const h of report.hypotheses.slice(0, HYPOTHESIS_RENDER_CAP)) {
    const title = h.title ? ` — ${capped(escapeMarkdownText(h.title), FIELD_CHAR_CAP)}` : '';
    lines.push(`${capped(escapeMarkdownText(h.id), FIELD_CHAR_CAP)}${title}  [${statusOr(h.status)}]  events ${h.events}`);
    if (h.note) lines.push(`  note: ${capped(escapeMarkdownText(h.note), FIELD_CHAR_CAP)}`);
  }
  const hidden = Math.max(0, report.hypotheses.length - HYPOTHESIS_RENDER_CAP);
  if (hidden > 0) lines.push(`…and ${hidden} more ${hidden === 1 ? 'hypothesis' : 'hypotheses'} (full list in report.json)`);
  if (report.hypotheses.length > 0) lines.push('');
  if (report.excerpts.length > 0) {
    lines.push('last events:');
    for (const msg of report.excerpts) lines.push(`  - ${capped(escapeMarkdownText(msg), EXCERPT_CHAR_CAP)}`);
    if (report.excerptsTruncated > 0) lines.push(`  …and ${report.excerptsTruncated} more earlier`);
  }
  return `${lines.join('\n')}\n`;
};

const deriveSessionId = (resolvedPath) => {
  const match = SESSION_FILE_PATTERN.exec(path.basename(resolvedPath));
  return match ? match[1] : null;
};

// A failure MUST be exactly one stderr line. Both the message and the ref
// interpolated into it are attacker-influenced (a session ref from a workflow
// input, an OS error quoting that path), so a raw newline anywhere inside
// would split one diagnostic into what reads as two — and the action's
// log-tail capture treats one line as one failure.
const writeErrorLine = (message) => {
  process.stderr.write(`${String(message).replace(/\r?\n|\r/g, ' ')}\n`);
};

const main = async () => {
  const parsed = parseArgs(process.argv.slice(2));
  if (parsed.error) {
    process.stderr.write(`debug_report: ${parsed.error}\n${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const { positional } = parsed;
  if (positional.length < 1 || positional.length > 2) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const format = parsed.format ?? (process.stdout.isTTY ? 'text' : 'md');
  if (!['text', 'md', 'json'].includes(format)) {
    process.stderr.write(`${USAGE}\n`);
    process.exitCode = 2;
    return;
  }
  const [ref, projectRoot = process.cwd()] = positional;
  const filePath = resolveSessionRef(projectRoot, ref);
  let entries;
  try {
    entries = await readSessionFile(filePath);
  } catch (error) {
    writeErrorLine(`debug_report: cannot read session (${ref}): ${error.message}`);
    process.exitCode = 1;
    return;
  }
  const report = buildReport(entries, { sessionId: deriveSessionId(filePath) });
  if (format === 'json') process.stdout.write(renderJson(report));
  else if (format === 'md') process.stdout.write(renderMarkdown(report));
  else process.stdout.write(renderText(report));
};

if (require.main === module) {
  main().catch((error) => {
    writeErrorLine(error.message);
    process.exitCode = 1;
  });
}

module.exports = { buildReport, parseArgs, renderJson, renderMarkdown, renderText };
