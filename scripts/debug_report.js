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

const buildReport = (entries, { sessionId = null } = {}) => {
  const folded = foldHypotheses(entries);
  let events = 0;
  let hypothesisLines = 0;
  let untaggedEvents = 0;
  const taggedCounts = new Map();
  const allEventMsgs = [];
  for (const { parsed } of entries) {
    if (parsed.type === 'hypothesis') {
      hypothesisLines += 1;
      continue;
    }
    events += 1;
    allEventMsgs.push(typeof parsed.msg === 'string' ? parsed.msg : String(parsed.msg));
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
    session: { id: sessionId, entries: entries.length, events, hypothesisLines },
    hypotheses,
    untaggedEvents,
    excerpts,
    excerptsTruncated: Math.max(0, allEventMsgs.length - EXCERPT_CAP),
  };
};

const renderJson = (report) => `${JSON.stringify(report, null, 2)}\n`;

const statusOr = (status) => (status === null ? '—' : escapeMarkdownText(status));

const renderMarkdown = (report) => {
  const lines = ['## Debug evidence report', ''];
  const id = report.session.id === null ? '(file)' : escapeMarkdownText(report.session.id);
  lines.push(`_session ${id} · ${report.session.events} events · ${report.session.hypothesisLines} hypothesis lines_`);
  lines.push('');
  for (const h of report.hypotheses) {
    const title = h.title ? ` — ${escapeMarkdownText(h.title)}` : '';
    lines.push(`**${escapeMarkdownText(h.id)}${title}**  ${statusOr(h.status)}`);
    lines.push('');
    lines.push(`- events ${h.events} · hypothesis lines ${h.lines}`);
    if (h.note) lines.push(`- note: "${escapeMarkdownText(h.note)}"`);
    lines.push('');
  }
  if (report.untaggedEvents > 0) {
    lines.push(`_untagged events: ${report.untaggedEvents}_`);
    lines.push('');
  }
  if (report.excerpts.length > 0) {
    lines.push('**Last events**');
    lines.push('');
    for (const msg of report.excerpts) lines.push(`- "${escapeMarkdownText(msg)}"`);
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
  lines.push('');
  for (const h of report.hypotheses) {
    const title = h.title ? ` — ${escapeMarkdownText(h.title)}` : '';
    lines.push(`${escapeMarkdownText(h.id)}${title}  [${statusOr(h.status)}]  events ${h.events}`);
    if (h.note) lines.push(`  note: ${escapeMarkdownText(h.note)}`);
  }
  if (report.hypotheses.length > 0) lines.push('');
  if (report.excerpts.length > 0) {
    lines.push('last events:');
    for (const msg of report.excerpts) lines.push(`  - ${escapeMarkdownText(msg)}`);
    if (report.excerptsTruncated > 0) lines.push(`  …and ${report.excerptsTruncated} more earlier`);
  }
  return `${lines.join('\n')}\n`;
};

const deriveSessionId = (resolvedPath) => {
  const match = SESSION_FILE_PATTERN.exec(path.basename(resolvedPath));
  return match ? match[1] : null;
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
    process.stderr.write(`debug_report: cannot read session (${ref}): ${error.message}\n`);
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
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}

module.exports = { buildReport, parseArgs, renderJson, renderMarkdown, renderText };
