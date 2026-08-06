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

test('rendered markdown/table keep a backticked disappeared message inside its delimiters', () => {
  const before = parseSessionText(
    line({ ts: '2026-08-06T10:00:01.000Z', msg: 'has `backtick` inside', hypothesisId: 'H1' }),
  );
  const diff = computeDiff(before, parseSessionText(''));

  const markdown = renderMarkdown(diff);
  const goneLine = markdown.split('\n').find((l) => l.startsWith('- gone: '));
  assert.equal(goneLine, '- gone: `has \\`backtick\\` inside`');

  const table = renderTable(diff);
  const tableLine = table.split('\n').find((l) => l.includes('backtick'));
  assert.equal(tableLine, '  - has \\`backtick\\` inside');
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
