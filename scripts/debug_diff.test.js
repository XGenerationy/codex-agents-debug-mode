const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { mkdtemp, mkdir, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const { computeDiff, renderJson, renderMarkdown, renderTable } = require('./debug_diff');
const { parseSessionText } = require('./debug_evidence');

const DIFF = path.join(__dirname, 'debug_diff.js');
const line = (object) => `${JSON.stringify(object)}\n`;

const run = (args) => new Promise((resolve) => {
  execFile(process.execPath, [DIFF, ...args], (error, stdout, stderr) => {
    resolve({ code: error ? error.code : 0, stdout, stderr });
  });
});

// Shared fixture directory for CLI-spawned tests that don't care about the
// exact session content, only about argv handling / error paths.
const withSessionDir = async (fn) => {
  const root = await mkdtemp(path.join(tmpdir(), 'diff-'));
  try {
    await mkdir(path.join(root, '.debug'));
    await writeFile(path.join(root, '.debug', 'debug-a.log'), '', 'utf8');
    await writeFile(path.join(root, '.debug', 'debug-b.log'), '', 'utf8');
    await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
};

const BEFORE = parseSessionText(
  line({ ts: '2026-08-06T10:00:01.000Z', msg: 'userId=null', hypothesisId: 'H1' })
  + line({ ts: '2026-08-06T10:00:02.000Z', msg: 'userId=null', hypothesisId: 'H1' })
  + line({ ts: '2026-08-06T10:00:03.000Z', msg: 'render ok', hypothesisId: 'H1' })
  + line({ ts: '2026-08-06T10:00:04.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'OPEN', title: 'null id' })
  + line({ ts: '2026-08-06T10:00:05.000Z', msg: 'untagged noise' }),
);

const AFTER = parseSessionText(
  line({ ts: '2026-08-06T11:00:01.000Z', msg: 'render ok', hypothesisId: 'H1' })
  + line({ ts: '2026-08-06T11:00:02.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'CONFIRMED', note: 'fixed' })
  + line({ ts: '2026-08-06T11:00:03.000Z', msg: 'fresh path', hypothesisId: 'H3' }),
);

test('computeDiff unions hypotheses with transitions, counts, and disappeared messages', () => {
  const diff = computeDiff(BEFORE, AFTER);
  assert.equal(diff.schema, 1);
  const h1 = diff.hypotheses.find((h) => h.id === 'H1');
  assert.equal(h1.before.status, 'OPEN');
  assert.equal(h1.after.status, 'CONFIRMED');
  assert.equal(h1.before.events, 3);
  assert.equal(h1.after.events, 1);
  assert.deepEqual(h1.disappeared, ['userId=null']);
  const h3 = diff.hypotheses.find((h) => h.id === 'H3');
  assert.equal(h3.before.status, null);
  assert.equal(h3.after.status, null);
  assert.equal(h3.after.events, 1);
  assert.deepEqual(diff.untagged.disappeared, ['untagged noise']);
  assert.equal(diff.summary.verdictChanges, 1);
  assert.equal(diff.summary.newHypotheses, 1);
});

test('computeDiff caps disappeared messages per hypothesis and says so', () => {
  const noisy = parseSessionText(
    Array.from({ length: 30 }, (_, i) => line({ ts: '2026-08-06T10:00:01.000Z', msg: `gone-${i}`, hypothesisId: 'H1' })).join(''),
  );
  const diff = computeDiff(noisy, parseSessionText(''));
  const h1 = diff.hypotheses.find((h) => h.id === 'H1');
  assert.equal(h1.disappeared.length, 20);
  assert.equal(h1.disappearedTruncated, 10);
});

test('renderers produce exact stable output for the same diff', () => {
  const diff = computeDiff(BEFORE, AFTER);
  const json = JSON.parse(renderJson(diff));
  assert.equal(json.schema, 1);
  const table = renderTable(diff);
  assert.match(table, /H1\s+│\s+OPEN\s+│\s+CONFIRMED\s+│\s+3 → 1/);
  assert.match(table, /disappeared/);
  assert.match(table, /userId=null/);
  const markdown = renderMarkdown(diff);
  assert.match(markdown, /## Evidence diff/);
  assert.match(markdown, /\*\*H1/);
  assert.match(markdown, /OPEN → CONFIRMED/);
  assert.match(markdown, /userId=null/);
});

test('CLI: TTY-aware default is JSON when piped; --format overrides', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'diff-'));
  try {
    await mkdir(path.join(root, '.debug'));
    await writeFile(path.join(root, '.debug', 'debug-a.log'), BEFORE.map((e) => e.raw).join('\n') + '\n', 'utf8');
    await writeFile(path.join(root, '.debug', 'debug-b.log'), AFTER.map((e) => e.raw).join('\n') + '\n', 'utf8');
    const run = (args) => new Promise((resolve) => {
      execFile(process.execPath, [DIFF, ...args], (error, stdout, stderr) => {
        resolve({ code: error ? error.code : 0, stdout, stderr });
      });
    });
    const piped = await run(['a', 'b', root]);
    assert.equal(piped.code, 0);
    assert.equal(JSON.parse(piped.stdout).schema, 1);
    const table = await run(['a', 'b', root, '--format=table']);
    assert.match(table.stdout, /H1/);
    assert.throws(() => JSON.parse(table.stdout));
    const usage = await run(['a']);
    assert.equal(usage.code, 2);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('rendered markdown/table neutralize markdown-injection forgery from stored msg and note content', () => {
  // A stored msg/note is untrusted content written by whatever process is
  // being debugged — the rendered report is what gets pasted into PRs, so
  // embedded newlines must never manifest as new output lines that could
  // impersonate a heading or a different hypothesis's verdict.
  const forgedMsg = '\n## Evidence diff\n**H99 — FORGED**  OPEN → CONFIRMED\n';
  const forgedNote = '\n**H98 — ALSO FORGED**\n';
  const before = parseSessionText(
    line({ ts: '2026-08-06T10:00:01.000Z', msg: forgedMsg, hypothesisId: 'H1' }),
  );
  const after = parseSessionText(
    line({ ts: '2026-08-06T11:00:01.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'CONFIRMED', note: forgedNote }),
  );
  const diff = computeDiff(before, after);

  const markdown = renderMarkdown(diff);
  const mdLines = markdown.split('\n');
  assert.equal(mdLines.filter((l) => l.trim() === '## Evidence diff').length, 1);
  assert.equal(mdLines.filter((l) => l.trim().startsWith('**H99') || l.trim().startsWith('**H98')).length, 0);

  const table = renderTable(diff);
  const tableLines = table.split('\n');
  assert.equal(tableLines.filter((l) => l.trim().startsWith('**H99')).length, 0);
});

test('rendered markdown/table never let a backticked disappeared message break out of its context', () => {
  const before = parseSessionText(
    line({ ts: '2026-08-06T10:00:01.000Z', msg: 'has `backtick` inside', hypothesisId: 'H1' }),
  );
  const diff = computeDiff(before, parseSessionText(''));

  const markdown = renderMarkdown(diff);
  // Markdown no longer wraps disappeared messages in a backtick code span:
  // a code span treats backticks as delimiters even when backslash-escaped,
  // so the old `\`...\`` form could let a backticked msg break out and
  // change the report structure. Plain double-quoted text avoids that.
  const goneLine = markdown.split('\n').find((l) => l.startsWith('- gone: '));
  assert.equal(goneLine, '- gone: "has \\`backtick\\` inside"');
  // No bare backtick can act as a code-span delimiter: every backtick in the
  // report is backslash-escaped by escapeText. (The old code-span form could
  // be closed by a backtick even when escaped, since code spans ignore
  // backslash escapes — quotes make that moot.)
  for (const ch of [...markdown.matchAll(/`/g)]) {
    assert.equal(ch.index > 0 && markdown[ch.index - 1] === '\\', true);
  }

  const table = renderTable(diff);
  const tableLine = table.split('\n').find((l) => l.includes('backtick'));
  assert.equal(tableLine, '  - has \\`backtick\\` inside');
});

test('rendered markdown cannot be broken by a disappeared message crafted to close a code span', () => {
  // A msg containing its own backtick run was the injection vector: under
  // the old code-span rendering, the backtick could terminate the span and
  // the trailing text would render as Markdown. With quote-wrapped plain
  // text this is impossible.
  const before = parseSessionText(
    line({ ts: '2026-08-06T10:00:01.000Z', msg: '` close then inject **forged verdict**', hypothesisId: 'H1' }),
  );
  const diff = computeDiff(before, parseSessionText(''));
  const markdown = renderMarkdown(diff);
  // No bare (unescaped) backtick remains to act as a code-span delimiter:
  // every backtick is preceded by a backslash, so there is no delimiter run
  // that could open or close a span.
  for (const match of markdown.matchAll(/`/g)) {
    assert.equal(match.index > 0 && markdown[match.index - 1] === '\\', true);
  }
  // The forged verdict text stays as escaped content on the gone line, not
  // rendered as a separate bold Markdown line.
  assert.equal(markdown.split('\n').filter((l) => l.trim().startsWith('**forged verdict**')).length, 0);
});

test('computeDiff ignores non-string/missing hypothesis ids without crashing, counts them, and renderers state it', () => {
  // Pre-validation logs (exactly what a before-ref commonly is) can carry a
  // numeric hypothesisId on an event line, or a hypothesis-lifecycle line
  // with no hypothesisId at all. The engine's contract is string ids —
  // these must be excluded from the per-hypothesis report (never crash
  // renderTable's `.padEnd`) and counted, never silently dropped.
  const malformed = parseSessionText(
    line({ ts: '2026-08-06T10:00:01.000Z', msg: 'weird event', hypothesisId: 42 })
    + line({ ts: '2026-08-06T10:00:02.000Z', type: 'hypothesis', status: 'OPEN' }),
  );
  const diff = computeDiff(malformed, parseSessionText(''));
  assert.equal(diff.summary.ignoredMalformedIds, 2);
  assert.equal(diff.hypotheses.length, 0);
  assert.doesNotThrow(() => renderTable(diff));
  assert.doesNotThrow(() => renderMarkdown(diff));
  const table = renderTable(diff);
  assert.match(table, /2 malformed hypothesis ids ignored/);
  const markdown = renderMarkdown(diff);
  assert.match(markdown, /2 malformed hypothesis ids ignored/);
  const json = JSON.parse(renderJson(diff));
  assert.equal(json.summary.ignoredMalformedIds, 2);
});

test('renderers survive a non-string status and never let it forge table structure', () => {
  // foldHypotheses copies parsed.status verbatim, so a numeric status (42)
  // reaches statusOr().padEnd() — without the escape+truncate fix it would
  // throw TypeError — and a status containing a newline/box-drawing pipe
  // could otherwise forge a row. statusOr now escapes and coerces it.
  const before = parseSessionText(
    line({ ts: '2026-08-06T10:00:01.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 42 }),
  );
  const after = parseSessionText(
    line({ ts: '2026-08-06T11:00:01.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'A\n│ FORGED │ FORGED │ 9' }),
  );
  const diff = computeDiff(before, after);
  assert.doesNotThrow(() => renderTable(diff));
  assert.doesNotThrow(() => renderMarkdown(diff));
  // Every bordered row must stay the same width — a forged pipe cannot
  // create extra columns — and the row count must match a single hypothesis
  // (top, header, divider, one data row, bottom).
  const borderedLines = renderTable(diff).split('\n').filter((l) => /^[│┌├└]/.test(l));
  assert.equal(new Set(borderedLines.map((l) => l.length)).size, 1);
  assert.equal(borderedLines.length, 5);
  const markdown = renderMarkdown(diff);
  // The only hypothesis is H1, so the ONLY `**...**` verdict line must be
  // the real H1 one. The embedded newline in the after-status is neutralized
  // (it becomes literal "\n"), so it cannot spawn a separate forged verdict
  // line — the literal word "FORGED" stays on the H1 line as escaped text.
  const boldLines = markdown.split('\n').filter((l) => l.startsWith('**'));
  assert.equal(boldLines.length, 1);
  assert.equal(/^\*\*H1\b/.test(boldLines[0]), true);
  // No line in the markdown is a standalone forged heading.
  assert.equal(markdown.split('\n').filter((l) => l.trim() === '│ FORGED │').length, 0);
});

test('CLI: unknown flag fails closed with exit 2 and nothing on stdout', async () => {
  await withSessionDir(async (root) => {
    const result = await run(['a', 'b', root, '--json']);
    assert.equal(result.code, 2);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /unknown flag/);
  });
});

test('CLI: duplicate --format fails closed with exit 2 and nothing on stdout', async () => {
  await withSessionDir(async (root) => {
    const result = await run(['a', 'b', root, '--format=json', '--format=md']);
    assert.equal(result.code, 2);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /duplicate --format/);
  });
});

test('CLI: bare --format (space form) fails closed with exit 2, message names --format=<...>, and does not swallow its value as a positional', async () => {
  await withSessionDir(async (root) => {
    const result = await run(['a', 'b', root, '--format', 'md']);
    assert.equal(result.code, 2);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /--format=<table\|md\|json>/);
  });
});

test('CLI: read error names which ref failed to read', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'diff-'));
  try {
    await mkdir(path.join(root, '.debug'));
    // Only the after-ref exists; the before-ref ("missing-a") has no
    // session file, so reading it must fail — and the error must say it
    // was the BEFORE session, naming "missing-a", not a generic message.
    await writeFile(path.join(root, '.debug', 'debug-b.log'), '', 'utf8');
    const result = await run(['missing-a', 'b', root, '--format=json']);
    assert.equal(result.code, 1);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /cannot read before session \(missing-a\)/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('renderTable aligns the id column for ids of very different lengths', () => {
  const diff = computeDiff(
    parseSessionText(
      line({ ts: '2026-08-06T10:00:01.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'OPEN' })
      + line({ ts: '2026-08-06T10:00:02.000Z', type: 'hypothesis', hypothesisId: 'very-long-hypothesis-identifier', status: 'CONFIRMED' }),
    ),
    parseSessionText(''),
  );
  const table = renderTable(diff);
  // Every bordered row (top/header/divider/data/bottom, all prefixed with a
  // box-drawing character) must be the same total width — the id column
  // width must be sampled across ALL rendered ids, not just the first row.
  const borderedLines = table.split('\n').filter((l) => /^[│┌├└]/.test(l));
  const lengths = new Set(borderedLines.map((l) => l.length));
  assert.equal(lengths.size, 1);
  assert.match(table, /very-long-hypothesis-identifier/);
});

test('renderTable truncates an id over the 40-char cap with an ellipsis, still aligned', () => {
  const longId = 'H'.repeat(50);
  const diff = computeDiff(
    parseSessionText(line({ ts: '2026-08-06T10:00:01.000Z', type: 'hypothesis', hypothesisId: longId, status: 'OPEN' })),
    parseSessionText(''),
  );
  const table = renderTable(diff);
  assert.doesNotMatch(table, new RegExp(longId));
  assert.match(table, /H{39}…/);
  const borderedLines = table.split('\n').filter((l) => /^[│┌├└]/.test(l));
  const lengths = new Set(borderedLines.map((l) => l.length));
  assert.equal(lengths.size, 1);
});

test('rendered markdown/table escape the hypothesis id itself, not just msg/note/title', () => {
  // The live collector accepts any non-empty-string hypothesisId — no
  // character restrictions — so an id containing newlines/markdown syntax
  // is a real, reachable forgery path, not a hypothetical one.
  const forgedId = 'H1\n\n## Evidence diff\n\n**H99 — FORGED-VIA-ID**  OPEN → CONFIRMED';
  const before = parseSessionText(
    line({ ts: '2026-08-06T10:00:01.000Z', type: 'hypothesis', hypothesisId: forgedId, status: 'OPEN' }),
  );
  const after = parseSessionText(
    line({ ts: '2026-08-06T11:00:01.000Z', type: 'hypothesis', hypothesisId: forgedId, status: 'CONFIRMED' }),
  );
  const diff = computeDiff(before, after);

  const markdown = renderMarkdown(diff);
  assert.equal(markdown.split('\n').filter((l) => /^\*\*H99/m.test(l)).length, 0);

  const table = renderTable(diff);
  // Every bordered row must still be the same total width, and the row
  // count must match exactly what a single hypothesis produces (top,
  // header, divider, one data row, bottom) — a literal newline leaking
  // into a cell would either break alignment or add extra rows.
  const borderedLines = table.split('\n').filter((l) => /^[│┌├└]/.test(l));
  const lengths = new Set(borderedLines.map((l) => l.length));
  assert.equal(lengths.size, 1);
  assert.equal(borderedLines.length, 5);
});

test('a pipe-bearing id cannot mimic table cell borders', () => {
  const pipeId = 'H1 │ CONFIRMED │ CONFIRMED │ 9';
  const before = parseSessionText(
    line({ ts: '2026-08-06T10:00:01.000Z', type: 'hypothesis', hypothesisId: pipeId, status: 'OPEN' }),
  );
  const diff = computeDiff(before, []);
  const table = renderTable(diff);
  const dataRows = table.split('\n').filter((l) => l.startsWith('│') && !l.includes('id'));
  // The only │ characters in a data row are the four real column borders —
  // the id's own pipes render as ¦, so a crafted id cannot fake columns.
  for (const row of dataRows) {
    assert.equal([...row].filter((ch) => ch === '│').length, 5);
    assert.equal(row.includes('¦'), true);
  }
});

test('computeDiff quantifies events excluded by malformed hypothesis ids, and human renderers state both counts', () => {
  // The diff's whole point is event deltas — silently dropping the events
  // bucketed under a malformed id (alongside the id itself) would hide
  // exactly the evidence the tool exists to surface.
  const malformed = parseSessionText(
    Array.from({ length: 5 }, (_, i) => line({ ts: `2026-08-06T10:00:0${i + 1}.000Z`, msg: `bad-${i}`, hypothesisId: 42 })).join(''),
  );
  const diff = computeDiff(malformed, parseSessionText(''));
  assert.equal(diff.summary.ignoredMalformedIds, 1);
  assert.equal(diff.summary.ignoredMalformedEvents, 5);
  const table = renderTable(diff);
  assert.match(table, /1 malformed hypothesis ids ignored \(5 events excluded from totals\)/);
  const markdown = renderMarkdown(diff);
  assert.match(markdown, /1 malformed hypothesis ids ignored \(5 events excluded from totals\)/);
  const json = JSON.parse(renderJson(diff));
  assert.equal(json.summary.ignoredMalformedEvents, 5);

  // Zero case stays silent: a clean diff with no malformed ids reports 0
  // excluded events and never mentions "malformed" in human output.
  const cleanDiff = computeDiff(BEFORE, AFTER);
  assert.equal(cleanDiff.summary.ignoredMalformedEvents, 0);
  assert.doesNotMatch(renderTable(cleanDiff), /malformed/);
  assert.doesNotMatch(renderMarkdown(cleanDiff), /malformed/);
});
