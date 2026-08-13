'use strict';

const assert = require('node:assert');
const { execFile } = require('node:child_process');
const { mkdtemp, mkdir, rm, writeFile } = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const REPORT = path.join(__dirname, 'debug_report.js');
const { parseSessionText } = require('./debug_evidence');
const { buildReport, renderJson, renderMarkdown, renderText } = require('./debug_report');

const line = (object) => `${JSON.stringify(object)}\n`;

const run = (args) => new Promise((resolve) => {
  execFile(process.execPath, [REPORT, ...args], (error, stdout, stderr) => {
    resolve({ code: error ? error.code : 0, stdout, stderr });
  });
});

const SESSION = parseSessionText(
  line({ ts: '2026-08-13T10:00:01.000Z', msg: 'userId=null on first render', hypothesisId: 'H1' })
  + line({ ts: '2026-08-13T10:00:02.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'OPEN', title: 'null id' })
  + line({ ts: '2026-08-13T10:00:03.000Z', msg: 'render ok', hypothesisId: 'H1' })
  + line({ ts: '2026-08-13T10:00:04.000Z', msg: 'untagged noise' }),
);

test('buildReport counts events vs hypothesis lines and groups tagged events per hypothesis', () => {
  const report = buildReport(SESSION, { sessionId: 'demo-abc' });
  assert.equal(report.schema, 1);
  assert.equal(report.session.id, 'demo-abc');
  assert.equal(report.session.entries, 4);
  assert.equal(report.session.events, 3);
  assert.equal(report.session.hypothesisLines, 1);
  assert.equal(report.untaggedEvents, 1);
  assert.equal(report.hypotheses.length, 1);
  const h1 = report.hypotheses[0];
  assert.equal(h1.id, 'H1');
  assert.equal(h1.status, 'OPEN');
  assert.equal(h1.title, 'null id');
  assert.equal(h1.events, 2);
});

test('buildReport renders recorded statuses only — it never invents a verdict', () => {
  const report = buildReport(SESSION, { sessionId: null });
  assert.equal(report.hypotheses[0].status, 'OPEN');
  assert.ok(!('verdict' in report.hypotheses[0]), 'no synthesized verdict field');
});

test('excerpts keep the LAST events, cap at 20, and announce the overflow — no announce at exactly the cap', () => {
  const many = [];
  for (let i = 1; i <= 20; i += 1) many.push(line({ ts: '2026-08-13T10:00:05.000Z', msg: `m${i}` }));
  const exact = buildReport(parseSessionText(many.join('')), { sessionId: null });
  assert.equal(exact.excerpts.length, 20);
  assert.equal(exact.excerptsTruncated, 0);
  many.push(line({ ts: '2026-08-13T10:00:06.000Z', msg: 'm21' }));
  const over = buildReport(parseSessionText(many.join('')), { sessionId: null });
  assert.equal(over.excerpts.length, 20);
  assert.equal(over.excerpts[19], 'm21');
  assert.equal(over.excerpts[0], 'm2');
  assert.equal(over.excerptsTruncated, 1);
  const md = renderMarkdown(over);
  assert.ok(md.includes('…and 1 more earlier event'), 'announced overflow');
  assert.ok(!renderMarkdown(exact).includes('more earlier event'), 'no announce at exactly the cap');
});

test('renderMarkdown escapes hostile log content — structure reflects the renderer, never the log', () => {
  const hostile = buildReport(parseSessionText(
    line({ ts: '2026-08-13T10:00:01.000Z', msg: '## injected heading\n**bold** │ <img>' }),
  ), { sessionId: 'x' });
  const md = renderMarkdown(hostile);
  assert.ok(!md.includes('\n## injected heading'), 'stored newline must not open a real heading line');
  assert.ok(md.includes('\\*\\*bold\\*\\*'), 'markdown punctuation escaped');
  assert.ok(md.includes('¦'), 'box-drawing pipe swapped');
});

test('renderJson is verbatim machine output with schema 1 and no escaping layer', () => {
  const report = buildReport(SESSION, { sessionId: 'demo-abc' });
  const parsed = JSON.parse(renderJson(report));
  assert.equal(parsed.schema, 1);
  assert.equal(parsed.excerpts[0], 'userId=null on first render');
});

test('renderText and renderMarkdown are deterministic for identical input', () => {
  const a = buildReport(SESSION, { sessionId: 'demo-abc' });
  const b = buildReport(SESSION, { sessionId: 'demo-abc' });
  assert.equal(renderText(a), renderText(b));
  assert.equal(renderMarkdown(a), renderMarkdown(b));
});

const withSessionDir = async (fn) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'report-'));
  try {
    await mkdir(path.join(root, '.debug'));
    await fn(root);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
};

test('CLI: piped default is markdown; --format=json parses with schema 1; session id derived from the filename', async () => {
  await withSessionDir(async (root) => {
    const file = path.join(root, '.debug', 'debug-demo-abc.log');
    await writeFile(file, SESSION.map((e) => `${e.raw}\n`).join(''), 'utf8');
    const md = await run(['demo-abc', root]);
    assert.equal(md.code, 0);
    assert.ok(md.stdout.startsWith('## Debug evidence report'), 'piped default renders markdown');
    const json = await run([file, '--format=json']);
    assert.equal(json.code, 0);
    assert.equal(JSON.parse(json.stdout).schema, 1);
    assert.equal(JSON.parse(json.stdout).session.id, 'demo-abc');
  });
});

test('CLI usage errors exit 2: unknown flag, space-form format, bad format value, wrong positional count', async () => {
  for (const args of [['a', '--nope'], ['a', '--format', 'md'], ['a', '--format=xml'], []]) {
    const result = await run(args);
    assert.equal(result.code, 2, `args ${JSON.stringify(args)} must exit 2`);
    assert.ok(result.stderr.includes('Usage:'), 'usage printed');
  }
});

test('CLI runtime failure exits 1 with one clean stderr line and no stack', async () => {
  await withSessionDir(async (root) => {
    const result = await run(['missing-session', root]);
    assert.equal(result.code, 1);
    const stderrLines = result.stderr.split('\n').filter(Boolean);
    assert.equal(stderrLines.length, 1);
    assert.ok(!result.stderr.includes(' at '), 'no stack frames');
  });
});
