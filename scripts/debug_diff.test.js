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
