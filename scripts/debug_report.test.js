'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { mkdtemp, mkdir, rm, writeFile } = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const REPORT = path.join(__dirname, 'debug_report.js');
const { parseSessionText } = require('./debug_evidence');
const { CAVEAT_RENDER_CAP, buildReport, renderJson, renderMarkdown, renderText } = require('./debug_report');

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
  assert.equal(report.session.otherTypedLines, 0);
  assert.equal(report.untaggedEvents, 1);
  assert.equal(report.hypotheses.length, 1);
  const h1 = report.hypotheses[0];
  assert.equal(h1.id, 'H1');
  assert.equal(h1.status, 'OPEN');
  assert.equal(h1.title, 'null id');
  assert.equal(h1.events, 2);
  assert.equal(report.capturedAt, null);
});

test('buildReport records a capture timestamp when the caller supplies one', () => {
  const report = buildReport(SESSION, { sessionId: 'demo-abc', capturedAt: '2026-08-16T22:00:00.000Z' });
  assert.equal(report.capturedAt, '2026-08-16T22:00:00.000Z');
});

test('buildReport renders recorded statuses only — it never invents a verdict', () => {
  const report = buildReport(SESSION, { sessionId: null });
  assert.equal(report.hypotheses[0].status, 'OPEN');
  assert.ok(!('verdict' in report.hypotheses[0]), 'no synthesized verdict field');
});

test('a line with an unknown type is counted apart — never an event, never an excerpt', () => {
  const report = buildReport(parseSessionText(
    line({ ts: '2026-08-13T10:00:01.000Z', msg: 'real event' })
    + line({ ts: '2026-08-13T10:00:02.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'OPEN' })
    + line({ ts: '2026-08-13T10:00:03.000Z', type: 'marker', msg: 'a line shape this renderer predates' }),
  ), { sessionId: null });
  assert.equal(report.session.entries, 3, 'the unknown line still counts as an entry');
  assert.equal(report.session.events, 1);
  assert.equal(report.session.hypothesisLines, 1);
  assert.equal(report.session.otherTypedLines, 1);
  assert.deepEqual(report.excerpts, ['real event'], 'unknown line shapes stay out of the excerpts');
});

test('event messages are verbatim — objects serialize, a missing msg is named, and no coercion can throw', () => {
  const report = buildReport(parseSessionText(
    line({ ts: '2026-08-13T10:00:01.000Z', msg: { x: 1 } })
    + line({ ts: '2026-08-13T10:00:02.000Z' })
    + line({ ts: '2026-08-13T10:00:03.000Z', msg: { toString: null } }),
  ), { sessionId: null });
  assert.deepEqual(report.excerpts, ['{"x":1}', '(missing msg)', '{"toString":null}']);
  assert.doesNotThrow(() => renderMarkdown(report), 'a msg that breaks String() must still render');
  assert.doesNotThrow(() => renderText(report));
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

const excerptReport = (msg) => buildReport(
  parseSessionText(line({ ts: '2026-08-13T10:00:01.000Z', msg })),
  { sessionId: null },
);

test('human surfaces cap an excerpt at 500 chars with an announced ellipsis; JSON stays verbatim', () => {
  const atCap = excerptReport('a'.repeat(500));
  assert.ok(renderMarkdown(atCap).includes(`- "${'a'.repeat(500)}"`), 'exactly at the cap is untouched');
  assert.ok(renderText(atCap).includes(`  - ${'a'.repeat(500)}`));
  const overCap = excerptReport('a'.repeat(501));
  assert.ok(renderMarkdown(overCap).includes(`- "${'a'.repeat(499)}…"`), 'one over the cap loses its tail');
  assert.ok(renderText(overCap).includes(`  - ${'a'.repeat(499)}…`));
  assert.ok(!renderMarkdown(overCap).includes('a'.repeat(500)), 'no uncapped copy survives anywhere');
  assert.equal(JSON.parse(renderJson(overCap)).excerpts[0].length, 501, 'the machine surface is never capped');
  // The cap binds the ESCAPED text: 400 asterisks escape to 800 characters,
  // so capping the raw value first would let the surface emit 800 of them.
  const hostile = excerptReport('*'.repeat(400));
  const bullet = renderMarkdown(hostile).split('\n').find((l) => l.startsWith('- "'));
  assert.equal(bullet.length, 3 + 500 + 1, 'bullet is `- "` + exactly 500 capped chars + `"`');
});

const fieldsReport = (title, note) => buildReport(parseSessionText(line({
  ts: '2026-08-13T10:00:01.000Z', type: 'hypothesis', hypothesisId: 'H1', status: 'OPEN', title, note,
})), { sessionId: null });

test('human surfaces cap a hypothesis title and note at 200 chars, both sides of the boundary', () => {
  const atCap = fieldsReport('T'.repeat(200), 'N'.repeat(200));
  assert.ok(renderMarkdown(atCap).includes(`— ${'T'.repeat(200)}**`), 'title exactly at the cap is untouched');
  assert.ok(renderMarkdown(atCap).includes(`- note: "${'N'.repeat(200)}"`));
  const overCap = fieldsReport('T'.repeat(201), 'N'.repeat(201));
  assert.ok(renderMarkdown(overCap).includes(`— ${'T'.repeat(199)}…**`), 'one over the cap loses its tail');
  assert.ok(renderMarkdown(overCap).includes(`- note: "${'N'.repeat(199)}…"`));
  assert.ok(renderText(overCap).includes(`— ${'T'.repeat(199)}…`));
  assert.ok(renderText(overCap).includes(`  note: ${'N'.repeat(199)}…`));
  assert.equal(JSON.parse(renderJson(overCap)).hypotheses[0].title.length, 201, 'JSON keeps the whole field');
});

const hypothesesReport = (count) => {
  let text = '';
  for (let i = 0; i < count; i += 1) {
    text += line({
      ts: '2026-08-13T10:00:01.000Z',
      type: 'hypothesis',
      hypothesisId: `H${String(i).padStart(4, '0')}`,
      status: 'OPEN',
    });
  }
  return buildReport(parseSessionText(text), { sessionId: null });
};

test('human surfaces render at most 100 hypothesis blocks and announce the remainder', () => {
  const atCap = hypothesesReport(100);
  assert.equal(atCap.hypotheses.length, 100);
  assert.ok(!renderMarkdown(atCap).includes('more hypothes'), 'no announce at exactly the cap');
  assert.ok(!renderText(atCap).includes('more hypothes'));
  const overCap = hypothesesReport(101);
  assert.equal(overCap.hypotheses.length, 101, 'the report object keeps every hypothesis');
  const md = renderMarkdown(overCap);
  assert.ok(md.includes('_…and 1 more hypothesis (full list in report.json)_'), 'italic md footer, singular at 1');
  assert.equal((md.match(/^\*\*H\d{4}/gm) ?? []).length, 100, 'exactly 100 blocks rendered');
  assert.ok(!md.includes('H0100'), 'the 101st block never reaches the human surface');
  const txt = renderText(overCap);
  assert.ok(txt.includes('…and 1 more hypothesis (full list in report.json)'), 'plain text footer, singular at 1');
  assert.ok(!txt.includes('H0100'));
  assert.equal(JSON.parse(renderJson(overCap)).hypotheses.length, 101, 'the machine surface keeps all 101');
});

test('the hypothesis overflow announce pluralizes, like the excerpt announce above it', () => {
  const many = hypothesesReport(102);
  assert.ok(renderMarkdown(many).includes('_…and 2 more hypotheses (full list in report.json)_'));
  assert.ok(renderText(many).includes('…and 2 more hypotheses (full list in report.json)'));
});

test('human surfaces cap a hypothesis id at 200 chars and a status at 40', () => {
  const report = buildReport(parseSessionText(line({
    ts: '2026-08-13T10:00:01.000Z',
    type: 'hypothesis',
    hypothesisId: 'I'.repeat(201),
    status: 'S'.repeat(41),
  })), { sessionId: null });
  const md = renderMarkdown(report);
  assert.ok(md.includes(`**${'I'.repeat(199)}…**`), 'id capped at 200');
  assert.ok(md.includes(`${'S'.repeat(39)}…`), 'status capped at 40');
  assert.ok(!md.includes('I'.repeat(200)), 'no uncapped id survives');
  assert.ok(!md.includes('S'.repeat(40)), 'no uncapped status survives');
  const txt = renderText(report);
  assert.ok(txt.includes(`${'I'.repeat(199)}…`));
  assert.ok(txt.includes(`[${'S'.repeat(39)}…]`));
  const parsed = JSON.parse(renderJson(report));
  assert.equal(parsed.hypotheses[0].id.length, 201, 'JSON keeps the full id');
  assert.equal(parsed.hypotheses[0].status.length, 41, 'JSON keeps the full status');
});

test('truncation never splits a surrogate pair — an emoji title ends on a whole emoji', () => {
  const emoji = '\u{1F600}';
  // 101 emoji = 202 UTF-16 code units, so the 200-unit cap cuts mid-pair.
  const md = renderMarkdown(fieldsReport(emoji.repeat(101), null));
  assert.ok(md.includes(`— ${emoji.repeat(99)}…**`), 'drops the orphaned half, keeps 99 whole emoji');
  assert.ok(!md.includes('\uFFFD'), 'no replacement character in the string');
  assert.ok(!/[\uD800-\uDBFF](?![\uDC00-\uDFFF])/.test(md), 'no unpaired high surrogate');
  assert.ok(!Buffer.from(md, 'utf8').includes(Buffer.from('\uFFFD', 'utf8')), 'none in the UTF-8 bytes either');
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

test('CLI failure stays ONE line even when the ref (and the OS error quoting it) embeds a newline', async () => {
  const result = await run(['forged\nline.log']);
  assert.equal(result.code, 1);
  assert.equal(result.stderr.split('\n').filter(Boolean).length, 1);
  assert.ok(result.stderr.endsWith('\n'));
  assert.ok(!result.stderr.slice(0, -1).includes('\n'), 'no embedded newline survives the collapse');
  assert.ok(result.stderr.startsWith('debug_report: cannot read session (forged line.log)'), 'newline became a space');
});

// A caveat is a label that must travel WITH the evidence. The action stamps one
// on every report rendered on a host where the in-process guarantees its
// capture rests on were not established (Codex T6 r5), the same doctrine as the
// labeled unreachable-collector fallback: a reader who has the artifact and not
// the job must still see it. Absent by default, so an ordinary report is
// unchanged.
test('human surfaces render at most CAVEAT_RENDER_CAP caveats and announce the remainder', () => {
  const label = (i) => `caveat-${String(i).padStart(3, '0')}`;
  const atCap = buildReport([], { caveats: Array.from({ length: CAVEAT_RENDER_CAP }, (_, i) => label(i)) });
  assert.equal(atCap.caveats.length, CAVEAT_RENDER_CAP);
  assert.ok(!renderMarkdown(atCap).includes('more caveat'), 'no announce at exactly the cap');
  assert.ok(!renderText(atCap).includes('more caveat'));
  const overCap = buildReport([], {
    caveats: Array.from({ length: CAVEAT_RENDER_CAP + 1 }, (_, i) => label(i)),
  });
  assert.equal(overCap.caveats.length, CAVEAT_RENDER_CAP + 1, 'the report object keeps every caveat');
  const md = renderMarkdown(overCap);
  assert.ok(md.includes('_…and 1 more caveat (full list in report.json)_'), 'italic md footer, singular at 1');
  assert.equal((md.match(/^> \*\*Caveat:\*\* /gm) ?? []).length, CAVEAT_RENDER_CAP, 'exactly the cap rendered');
  assert.ok(!md.includes(label(CAVEAT_RENDER_CAP)), 'the cap-plus-one caveat never reaches the human surface');
  const txt = renderText(overCap);
  assert.ok(txt.includes('…and 1 more caveat (full list in report.json)'), 'plain text footer, singular at 1');
  assert.ok(!txt.includes(label(CAVEAT_RENDER_CAP)));
  assert.equal(JSON.parse(renderJson(overCap)).caveats.length, CAVEAT_RENDER_CAP + 1, 'the machine surface keeps every caveat');
});

test('the caveat overflow announce pluralizes, like the hypothesis announce above it', () => {
  const many = buildReport([], {
    caveats: Array.from({ length: CAVEAT_RENDER_CAP + 2 }, (_, i) => `c${i}`),
  });
  assert.ok(renderMarkdown(many).includes('_…and 2 more caveats (full list in report.json)_'));
  assert.ok(renderText(many).includes('…and 2 more caveats (full list in report.json)'));
});

test('caveats travel with the report: absent by default, verbatim in JSON, capped and prominent in the human surfaces', () => {
  const entries = [{ raw: line({ msg: 'e' }), parsed: { msg: 'e' } }];
  const plain = buildReport(entries, { sessionId: 'ci-debug-abc' });
  assert.deepEqual(plain.caveats, [], 'no caveat unless one is passed');
  assert.equal(renderMarkdown(plain).includes('Caveat'), false);
  assert.equal(renderText(plain).includes('caveat'), false);

  const caveat = 'in-process guarantees were NOT established on this host';
  const flagged = buildReport(entries, { sessionId: 'ci-debug-abc', caveats: [caveat, '', 42, null] });
  assert.deepEqual(flagged.caveats, [caveat], 'only non-empty strings survive');
  assert.deepEqual(JSON.parse(renderJson(flagged)).caveats, [caveat]);
  // Prominent: above the evidence, not buried under it.
  const markdown = renderMarkdown(flagged);
  assert.ok(markdown.includes(`> **Caveat:** ${caveat}`));
  assert.ok(markdown.indexOf('Caveat') < markdown.indexOf('Last events'), 'ahead of the evidence it qualifies');
  assert.ok(renderText(flagged).includes(`caveat: ${caveat}`));

  // Same discipline as every other rendered value: escaped, capped on the
  // human surfaces, whole on the machine one.
  const hostile = buildReport(entries, { caveats: [`${'x'.repeat(600)}<script>`] });
  assert.equal(JSON.parse(renderJson(hostile)).caveats[0].length, 608, 'the machine surface is never capped');
  const hostileMarkdown = renderMarkdown(hostile);
  assert.equal(hostileMarkdown.includes('<script>'), false, 'rendered caveats are escaped like any other text');
  assert.ok(hostileMarkdown.includes('…'), 'and the truncation is announced');
});
