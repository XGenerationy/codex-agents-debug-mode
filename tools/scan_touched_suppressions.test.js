const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { mkdir, mkdtemp, rm, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  collectContentRemovals,
  getComparisonStyle,
  resolveBaseSha,
} = require('./scan_touched_suppressions');

const git = (repo, ...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();

// resolveBaseSha reads process.env directly; save/restore the keys it consults
// so the tests stay hermetic regardless of the ambient CI environment.
const ENV_KEYS = ['CLOSEOUT_BASE_SHA', 'GITHUB_BASE_SHA', 'GITHUB_EVENT_BEFORE', 'GITHUB_BASE_REF'];

const setScanEnv = (eventBefore) => {
  const saved = {};
  for (const key of ENV_KEYS) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  process.env.GITHUB_EVENT_BEFORE = eventBefore;
  return () => {
    for (const key of ENV_KEYS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  };
};

const fixtureRepo = async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'scan-touched-suppressions-'));
  git(repo, 'init', '--quiet');
  git(repo, 'config', 'user.name', 'Scan Test');
  git(repo, 'config', 'user.email', 'scan@example.invalid');
  git(repo, 'config', 'commit.gpgsign', 'false');
  await writeFile(path.join(repo, 'tracked.txt'), 'base\n');
  git(repo, 'add', '.');
  git(repo, 'commit', '--quiet', '-m', 'base');
  await writeFile(path.join(repo, 'tracked.txt'), 'changed\n');
  git(repo, 'add', '.');
  git(repo, 'commit', '--quiet', '-m', 'second');
  return repo;
};

test('GITHUB_EVENT_BEFORE naming an unfetched commit falls through to another base', async () => {
  // actions/checkout defaults to fetch-depth: 1, so a format-valid push
  // preimage can name a commit that was never fetched. resolveBaseSha must not
  // select it as a two-dot base (the diff would die on an unknown revision
  // before the gate evaluates) and must fall through to the remaining
  // resolution chain instead (CodeRabbit discussion_r3652923145).
  const repo = await fixtureRepo();
  const restoreEnv = setScanEnv('0123456789abcdef0123456789abcdef01234567');
  try {
    const unfetched = process.env.GITHUB_EVENT_BEFORE;
    const base = resolveBaseSha(repo);
    assert.notEqual(base, unfetched);
    assert.notEqual(getComparisonStyle(), 'two-dot');
    // Fall-through still resolves a usable base (fail-closed chain intact).
    assert.match(base, /^[0-9a-f]{40}$/i);
  } finally {
    restoreEnv();
    await rm(repo, { recursive: true, force: true });
  }
});

test('GITHUB_EVENT_BEFORE naming a fetched commit selects the two-dot preimage base', async () => {
  const repo = await fixtureRepo();
  const firstSha = git(repo, 'rev-list', '--max-parents=0', 'HEAD');
  const restoreEnv = setScanEnv(firstSha);
  try {
    const base = resolveBaseSha(repo);
    assert.equal(base, firstSha);
    assert.equal(getComparisonStyle(), 'two-dot');
  } finally {
    restoreEnv();
    await rm(repo, { recursive: true, force: true });
  }
});

test('isMechanicalLockfile recognizes generated dependency lockfiles', () => {
  const { isMechanicalLockfile } = require('./scan_touched_suppressions');
  for (const file of [
    'package-lock.json', 'dir/package-lock.json', 'pnpm-lock.yaml',
    'yarn.lock', 'Cargo.lock', 'poetry.lock', 'go.sum', 'composer.lock',
    'Gemfile.lock', 'gradle.lockfile', 'bun.lockb', 'Pipfile.lock',
  ]) {
    assert.equal(isMechanicalLockfile(file), true, `${file} should be a lockfile`);
  }
  // Non-lockfile gate/config files must NOT be excluded — they can hold real
  // validation steps/scripts and must remain in the fail-closed scan.
  for (const file of ['package.json', 'tsconfig.json', '.eslintrc.json', 'Makefile']) {
    assert.equal(isMechanicalLockfile(file), false, `${file} must not be treated as a lockfile`);
  }
});

// Build a real `git diff --unified=0` (the exact form diffUnified feeds the
// content-removal scanner) for one file edited between two commits, so the
// pairing/allowance logic is exercised against genuine git output rather than a
// hand-built diff string.
const singleFileDiff = async (relPath, before, after) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'scan-content-removal-'));
  try {
    git(repo, 'init', '--quiet');
    git(repo, 'config', 'user.name', 'Scan Test');
    git(repo, 'config', 'user.email', 'scan@example.invalid');
    git(repo, 'config', 'commit.gpgsign', 'false');
    const abs = path.join(repo, relPath);
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, before);
    git(repo, 'add', '.');
    git(repo, 'commit', '--quiet', '-m', 'base');
    await writeFile(abs, after);
    git(repo, 'add', '.');
    git(repo, 'commit', '--quiet', '-m', 'head');
    return execFileSync(
      'git',
      ['diff', '--unified=0', '--no-ext-diff', '--no-textconv', 'HEAD~1', 'HEAD', '--', relPath],
      { cwd: repo, encoding: 'utf8' },
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
};

const pkg = (fields) => `${JSON.stringify({ name: 'x', ...fields }, null, 2)}\n`;

// Same as singleFileDiff but commits several files in one pair of commits and
// diffs them together, mirroring how diffUnified feeds collectContentRemovals
// one combined diff for every touched gate file at once.
const multiFileDiff = async (entries) => {
  const repo = await mkdtemp(path.join(tmpdir(), 'scan-content-removal-multi-'));
  try {
    git(repo, 'init', '--quiet');
    git(repo, 'config', 'user.name', 'Scan Test');
    git(repo, 'config', 'user.email', 'scan@example.invalid');
    git(repo, 'config', 'commit.gpgsign', 'false');
    for (const { relPath, before } of entries) {
      const abs = path.join(repo, relPath);
      await mkdir(path.dirname(abs), { recursive: true });
      await writeFile(abs, before);
    }
    git(repo, 'add', '.');
    git(repo, 'commit', '--quiet', '-m', 'base');
    for (const { relPath, after } of entries) {
      await writeFile(path.join(repo, relPath), after);
    }
    git(repo, 'add', '.');
    git(repo, 'commit', '--quiet', '-m', 'head');
    return execFileSync(
      'git',
      ['diff', '--unified=0', '--no-ext-diff', '--no-textconv', 'HEAD~1', 'HEAD', '--', ...entries.map((e) => e.relPath)],
      { cwd: repo, encoding: 'utf8' },
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
};

test('collectContentRemovals exempts a lone package.json version bump (single-line hunk)', async () => {
  // The exact reported false-positive: a benign version bump (removal +
  // same-field replacement) must no longer be a content removal / CI failure.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.2.3', scripts: { test: 'node --test' } }),
    pkg({ version: '1.2.4', scripts: { test: 'node --test' } }),
  );
  assert.deepEqual(collectContentRemovals(diff), []);
});

test('collectContentRemovals exempts a package.json version + description bump (multi-line hunk)', async () => {
  // Two adjacent same-field value edits share one hunk; index pairing must
  // align each removed line with its own replacement, not mispair them.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.2.3', description: 'old summary' }),
    pkg({ version: '1.2.4', description: 'new summary' }),
  );
  assert.deepEqual(collectContentRemovals(diff), []);
});

test('collectContentRemovals STILL flags a .codereview.yml version field weakening (metadata exemption must not leak, Codex UnKZ7)', async () => {
  // The SAFE_METADATA_KEY allowlist (version, description, ...) matches by key
  // name alone; without file scoping it would treat a gate-POLICY file's own
  // `version:` schema field as a cosmetic package-manifest bump. A
  // .codereview.yml is not a package manifest, so this same-key replacement
  // must stay flagged exactly like any other unscoped content removal.
  const before = 'version: 1\nrules:\n  - id: no-suppressions\n';
  const after = 'version: 0\nrules:\n  - id: no-suppressions\n';
  const diff = await singleFileDiff('.codereview.yml', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /version:\s*1/.test(line)),
    `expected the .codereview.yml version weakening to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals exempts a version bump in other package manifests (pyproject.toml, Cargo.toml)', async () => {
  // The metadata-replacement allowlist is scoped to recognized package
  // manifests generically, not just package.json -- SAFE_METADATA_KEY already
  // matches TOML's unquoted `key = "value"` form. A routine version bump in a
  // Python/Rust manifest must stay exempt exactly like package.json's.
  const pyBefore = '[project]\nname = "x"\nversion = "1.2.3"\n';
  const pyAfter = '[project]\nname = "x"\nversion = "1.2.4"\n';
  const pyDiff = await singleFileDiff('pyproject.toml', pyBefore, pyAfter);
  assert.deepEqual(collectContentRemovals(pyDiff), []);

  const cargoBefore = '[package]\nname = "x"\nversion = "1.2.3"\n';
  const cargoAfter = '[package]\nname = "x"\nversion = "1.2.4"\n';
  const cargoDiff = await singleFileDiff('Cargo.toml', cargoBefore, cargoAfter);
  assert.deepEqual(collectContentRemovals(cargoDiff), []);
});

test('collectContentRemovals STILL flags a weakened test script replacement', async () => {
  // Preserve detection: `"test": "jest --coverage"` -> `"echo skip"`. The key
  // `test` is not an allowlisted descriptive field, so the removal is not a
  // safe replacement and must still fail closed.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.0.0', scripts: { test: 'jest --coverage' } }),
    pkg({ version: '1.0.0', scripts: { test: 'echo skip' } }),
  );
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /jest --coverage/.test(line)),
    `expected the removed jest command to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals STILL flags a lowered coverage threshold replacement', async () => {
  // Preserve detection: lowering a coverage threshold (`lines: 80` -> `50`) is
  // a same-key numeric edit, but `lines` is not an allowlisted descriptive
  // field, so it must still be reported (never exempted as a metadata bump).
  const before = 'module.exports = {\n  coverageThreshold: {\n    global: {\n      lines: 80,\n    },\n  },\n};\n';
  const after = 'module.exports = {\n  coverageThreshold: {\n    global: {\n      lines: 50,\n    },\n  },\n};\n';
  const diff = await singleFileDiff('jest.config.js', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /lines:\s*80/.test(line)),
    `expected the lowered coverage threshold to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals STILL flags a pure deletion of a workflow step (no replacement)', async () => {
  // Preserve detection: a step removed with no positional replacement is a pure
  // deletion and always fails closed, even when it matches no named validation
  // pattern (`./scripts/verify-artifacts.sh`).
  const before = 'name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo build\n      - run: ./scripts/verify-artifacts.sh\n';
  const after = 'name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo build\n';
  const diff = await singleFileDiff('.github/workflows/ci.yml', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /verify-artifacts\.sh/.test(line)),
    `expected the deleted step to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals STILL flags a non-named validation step replaced with echo (Codex #4781495663)', async () => {
  // The critical negative case: a real validation step that evades
  // VALIDATION_REMOVAL_PATTERNS, replaced with `echo passed`. `run` is not an
  // allowlisted descriptive field, so the modification is NOT exempted — the
  // fail-closed catch-all this scanner exists for must still fire.
  const before = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - run: ./scripts/verify-artifacts.sh\n';
  const after = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - run: echo passed\n';
  const diff = await singleFileDiff('.github/workflows/ci.yml', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /verify-artifacts\.sh/.test(line)),
    `expected the replaced validation step to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals does NOT exempt a metadata field that smuggles a validation command', async () => {
  // Defense in depth: even an allowlisted key (`description`) is not blindly
  // exempted when its removed value reads as a validation command — the
  // VALIDATION_REMOVAL_PATTERNS guard keeps it failing closed.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.0.0', description: 'run npm test before shipping' }),
    pkg({ version: '1.0.0', description: 'a safe rewording' }),
  );
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /npm test/.test(line)),
    `expected the command-bearing description removal to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals handles a mixed diff: exempt metadata, flag weakenings together', async () => {
  // One realistic diff mixing a benign version+description bump with a lowered
  // `coverage` value and a weakened `test` script. Only the two weakenings are
  // reported; the metadata edits are exempt.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.2.3', description: 'old', coverage: 90, scripts: { test: 'jest --coverage' } }),
    pkg({ version: '1.2.4', description: 'new', coverage: 50, scripts: { test: 'echo skip' } }),
  );
  const removals = collectContentRemovals(diff);
  assert.ok(removals.some((line) => /"coverage":\s*90/.test(line)), `coverage lowering must be flagged; got ${JSON.stringify(removals)}`);
  assert.ok(removals.some((line) => /jest --coverage/.test(line)), `test weakening must be flagged; got ${JSON.stringify(removals)}`);
  assert.ok(!removals.some((line) => /"version"/.test(line)), `version bump must be exempt; got ${JSON.stringify(removals)}`);
  assert.ok(!removals.some((line) => /"description"/.test(line)), `description bump must be exempt; got ${JSON.stringify(removals)}`);
});

test('collectContentRemovals exempts a package.json dependency version bump', async () => {
  // Reported false positive (Codex UguCZ/UkAe8): bumping a dependency's
  // pinned version is a routine, benign edit. The dependency name is the
  // key's own identity, so a same-key value edit is safe exactly like a
  // metadata bump.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.0.0', dependencies: { lodash: '^4.17.20' } }),
    pkg({ version: '1.0.0', dependencies: { lodash: '^4.17.21' } }),
  );
  assert.deepEqual(collectContentRemovals(diff), []);
});

test('collectContentRemovals exempts a package.json non-validation script edit', async () => {
  // Reported false positive: rewriting a non-validation script's command
  // (`deploy`) must not be treated as a validation removal. The `deploy` key
  // names no validation surface, unlike `test`/`lint`/etc.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.0.0', scripts: { deploy: 'node deploy.js' } }),
    pkg({ version: '1.0.0', scripts: { deploy: 'node deploy.mjs --prod' } }),
  );
  assert.deepEqual(collectContentRemovals(diff), []);
});

test('collectContentRemovals STILL flags a script whose key names a validation surface (lint)', async () => {
  // The new package.json same-key allowance is itself a denylist on the key
  // (VALIDATION_KEY_HINT), independent of the pre-existing SAFE_METADATA_KEY
  // allowlist: a `lint` script edit must stay flagged even though it is a
  // same-key replacement exactly like the exempt `deploy` case above.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.0.0', scripts: { lint: 'eslint .' } }),
    pkg({ version: '1.0.0', scripts: { lint: 'echo ok' } }),
  );
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /eslint \./.test(line)),
    `expected the replaced lint script to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals STILL flags weakened npm lifecycle-prefixed validation scripts (pretest/posttest/prebuild, Codex UnYbr)', async () => {
  // VALIDATION_KEY_HINT's word-boundary match alone cannot see the internal
  // "pre"/"post" + keyword seam inside one concatenated word. npm's own
  // lifecycle-hook naming (`npm test` runs pretest, test, then posttest) means
  // these prefixed keys must hint just like their bare form, or a real
  // fixture-guard script silently becomes a no-op without ever being flagged.
  for (const key of ['pretest', 'posttest', 'prebuild']) {
    const diff = await singleFileDiff(
      'package.json',
      pkg({ version: '1.0.0', scripts: { [key]: 'node scripts/assert-fixtures.js' } }),
      pkg({ version: '1.0.0', scripts: { [key]: 'echo skipped' } }),
    );
    const removals = collectContentRemovals(diff);
    assert.ok(
      removals.some((line) => /assert-fixtures\.js/.test(line)),
      `expected the replaced ${key} script to be flagged; got ${JSON.stringify(removals)}`,
    );
  }
});

test('collectContentRemovals STILL flags a custom-keyed script that swaps out a real validation tool (Codex UxMWy)', async () => {
  // VALIDATION_KEY_HINT only denylists specific known key names (test, lint,
  // build, etc). A repo-specific script name like `quality` never matches it,
  // so the same-key package.json allowance used to wave through replacing a
  // real validation invocation (`eslint .`) with a no-op (`echo ok`) purely
  // because the key stayed the same. VALIDATION_TOOL_HINT closes this gap by
  // checking the VALUE for a known validation tool name independent of the key.
  const diff = await singleFileDiff(
    'package.json',
    pkg({ version: '1.0.0', scripts: { quality: 'eslint .' } }),
    pkg({ version: '1.0.0', scripts: { quality: 'echo ok' } }),
  );
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /eslint \./.test(line)),
    `expected the replaced quality script to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals does not let an in-hunk "+++ b/package.json" content line spoof currentFile (Codex UxMW8)', async () => {
  // With --unified=0, a source line whose literal content is `++ b/<path>` or
  // `-- a/<path>` becomes textually indistinguishable from a real diff file
  // header once git prefixes its own +/- marker. A naive `startsWith('+++ ')`
  // check (with no notion of being inside a hunk) would treat that in-hunk
  // content as a genuine header and corrupt currentFile to "package.json" for
  // the rest of the diff -- wrongly granting the package.json-only same-key
  // exemption to an unrelated edit in this tsconfig.json file. Padding lines
  // force the spoofing line and the real "sync" edit into separate hunks so
  // the corruption (if present) survives a hunk boundary, exactly like the
  // pre-existing cross-hunk pairing guard above.
  const before = [
    '{',
    '  "compilerOptions": {',
    '    "strict": true',
    '  },',
    '  "padding01": "a",',
    '  "padding02": "b",',
    '  "padding03": "c",',
    '  "padding04": "d",',
    '  "padding05": "e",',
    '  "padding06": "f",',
    '  "padding07": "g",',
    '  "padding08": "h",',
    '  "sync": "run-integration-check.sh"',
    '}',
    '',
  ].join('\n');
  const after = [
    '{',
    '  "compilerOptions": {',
    '    "strict": true',
    '  },',
    '++ b/package.json',
    '  "padding01": "a",',
    '  "padding02": "b",',
    '  "padding03": "c",',
    '  "padding04": "d",',
    '  "padding05": "e",',
    '  "padding06": "f",',
    '  "padding07": "g",',
    '  "padding08": "h",',
    '  "sync": "true"',
    '}',
    '',
  ].join('\n');
  const diff = await singleFileDiff('tsconfig.json', before, after);
  const hunkCount = (diff.match(/^@@/gm) || []).length;
  assert.ok(hunkCount >= 2, `fixture must produce multiple hunks to test cross-hunk currentFile spoofing; got ${hunkCount}`);
  assert.ok(
    /^\+\+\+ b\/package\.json$/m.test(diff),
    `fixture must produce an in-hunk line indistinguishable from a package.json header; got ${diff}`,
  );
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /run-integration-check\.sh/.test(line)),
    `expected the sync script edit to stay flagged (currentFile must remain tsconfig.json); got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals exempts a quoted workflow action pin bump (CodeRabbit Uohnw)', async () => {
  // YAML authors quote `uses:` routinely; isSafeActionPinReplacement's action-
  // path/ref alternatives both exclude quote characters, so a quoted pin bump
  // (single- or double-quoted) must be recognized as the same benign
  // same-action rotation as the bare form tested above.
  const singleQuotedBefore = "name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: 'actions/checkout@v3'\n";
  const singleQuotedAfter = "name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: 'actions/checkout@v4'\n";
  const singleDiff = await singleFileDiff('.github/workflows/ci.yml', singleQuotedBefore, singleQuotedAfter);
  assert.deepEqual(collectContentRemovals(singleDiff), []);

  const doubleQuotedBefore = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: "actions/checkout@v3"\n';
  const doubleQuotedAfter = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: "actions/checkout@v4"\n';
  const doubleDiff = await singleFileDiff('.github/workflows/ci.yml', doubleQuotedBefore, doubleQuotedAfter);
  assert.deepEqual(collectContentRemovals(doubleDiff), []);
});

test('collectContentRemovals STILL flags a tsconfig.json value change (package.json-only exemption must not leak)', async () => {
  // The package.json same-key allowance is deliberately scoped to
  // package.json specifically (where the key is the change's true identity,
  // since every npm script is invoked by its own key). A same-shaped
  // `"key": value` edit in a different JSON gate file must not be exempted.
  const before = '{\n  "compilerOptions": {\n    "strict": true\n  }\n}\n';
  const after = '{\n  "compilerOptions": {\n    "strict": false\n  }\n}\n';
  const diff = await singleFileDiff('tsconfig.json', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /"strict":\s*true/.test(line)),
    `expected the tsconfig strict-mode change to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals STILL flags a nested coverageThreshold value inside package.json (Codex UnT4H)', async () => {
  // The package.json same-key allowance is meant for top-level, single-line
  // JSON *string* fields (dependency versions, script commands) where the key
  // is the change's true identity. A nested numeric leaf like
  // `coverageThreshold.global.lines` shares no such guarantee -- `lines` is a
  // generic key that says nothing about what it gates -- so it must stay
  // flagged even though it is a same-key, same-line replacement.
  const before = pkg({
    version: '1.0.0',
    jest: { coverageThreshold: { global: { lines: 80 } } },
  });
  const after = pkg({
    version: '1.0.0',
    jest: { coverageThreshold: { global: { lines: 50 } } },
  });
  const diff = await singleFileDiff('package.json', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /"lines":\s*80/.test(line)),
    `expected the lowered nested coverage threshold to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals STILL flags a nested passWithNoTests boolean inside package.json (Codex UnT4H)', async () => {
  // Same root cause as the coverageThreshold case: a non-string (boolean)
  // nested leaf must never qualify as a safe same-key package.json field
  // replacement, even though `passWithNoTests` itself clears
  // VALIDATION_KEY_HINT and the surrounding jest block is a same-key edit.
  const before = pkg({ version: '1.0.0', jest: { passWithNoTests: false } });
  const after = pkg({ version: '1.0.0', jest: { passWithNoTests: true } });
  const diff = await singleFileDiff('package.json', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /"passWithNoTests":\s*false/.test(line)),
    `expected the weakened passWithNoTests flag to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals exempts a workflow action pin bump (same action, different ref)', async () => {
  // Reported false positive: bumping actions/checkout's pinned SHA/tag is a
  // routine, benign edit -- the action path (not the fixed `uses` key) is
  // this line's real identity, and it is unchanged here.
  const before = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v3\n';
  const after = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n';
  const diff = await singleFileDiff('.github/workflows/ci.yml', before, after);
  assert.deepEqual(collectContentRemovals(diff), []);
});

test('collectContentRemovals STILL flags a full-SHA action pin downgraded to a mutable ref (Codex UnT4I/UnS2f)', async () => {
  // A 40-char (or 64-char) hex `uses:` ref is the immutable pin GitHub
  // Actions' own guidance recommends; replacing it with a mutable tag or
  // branch name reintroduces the exact supply-chain risk pinning exists to
  // prevent. This must stay flagged even though the action path is unchanged
  // and it is otherwise a same-key replacement identical in shape to the
  // exempt tag-bump case above.
  const before = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3\n';
  const after = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@main\n';
  const diff = await singleFileDiff('.github/workflows/ci.yml', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /actions\/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3/.test(line)),
    `expected the SHA-to-mutable-ref downgrade to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals exempts a full-SHA action pin rotated to a different full-SHA', async () => {
  // A SHA-to-SHA rotation (e.g. picking up a new upstream release commit)
  // must remain exempt -- the immutability guarantee is preserved, so the
  // UnT4I/UnS2f fix must not overreject legitimate same-strength pin updates.
  const before = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3\n';
  const after = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@f43a0e5ff2bd294095638e18286ca9a3d1956744\n';
  const diff = await singleFileDiff('.github/workflows/ci.yml', before, after);
  assert.deepEqual(collectContentRemovals(diff), []);
});

test('collectContentRemovals STILL flags a uses: line swapped to a different action', async () => {
  // Adversarial case for the pin-bump allowance: the `uses` key is fixed for
  // every step regardless of which action it names, so a same-key check alone
  // would wrongly admit a swap to an unrelated action. The action path here
  // differs, so it must stay flagged.
  const before = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n';
  const after = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - uses: some-untrusted/action@v1\n';
  const diff = await singleFileDiff('.github/workflows/ci.yml', before, after);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /actions\/checkout@v4/.test(line)),
    `expected the swapped action to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals exempts a workflow step name: rename', async () => {
  // Reported false positive: a step's `name:` is a display label with no
  // execution semantics, so renaming it changes nothing about what runs.
  const before = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - name: Build\n        run: npm run build\n';
  const after = 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - name: Compile\n        run: npm run build\n';
  const diff = await singleFileDiff('.github/workflows/ci.yml', before, after);
  assert.deepEqual(collectContentRemovals(diff), []);
});

test('collectContentRemovals tracks the current file across a multi-file diff', async () => {
  // diffUnified diffs every touched gate file together into one combined diff
  // blob. currentFile must update at each file boundary so a package.json
  // exemption from one file in the diff never leaks into a different file's
  // lines (or vice versa).
  const diff = await multiFileDiff([
    {
      relPath: 'package.json',
      before: pkg({ version: '1.0.0', dependencies: { lodash: '^4.17.20' } }),
      after: pkg({ version: '1.0.0', dependencies: { lodash: '^4.17.21' } }),
    },
    {
      relPath: '.github/workflows/ci.yml',
      before: 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - run: ./scripts/verify-artifacts.sh\n',
      after: 'name: ci\non: push\njobs:\n  build:\n    steps:\n      - run: echo passed\n',
    },
  ]);
  const removals = collectContentRemovals(diff);
  assert.ok(!removals.some((line) => /lodash/.test(line)), `dependency bump must stay exempt; got ${JSON.stringify(removals)}`);
  assert.ok(
    removals.some((line) => /verify-artifacts\.sh/.test(line)),
    `workflow validation replacement must still be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals does not pair a removal with an unrelated addition in a distant hunk (Codex UmlJp)', async () => {
  // Same-key pairing must stay scoped to the hunk it occurs in. Padding lines
  // force the version removal and the unrelated `overrides.version` addition
  // into separate hunks under --unified=0; the removal must not be
  // opportunistically paired with a same-keyed addition from a different hunk.
  const before = pkg({
    version: '1.2.3',
    padding01: 'a', padding02: 'b', padding03: 'c', padding04: 'd',
    padding05: 'e', padding06: 'f', padding07: 'g', padding08: 'h',
    scripts: { build: 'webpack' },
  });
  const after = pkg({
    padding01: 'a', padding02: 'b', padding03: 'c', padding04: 'd',
    padding05: 'e', padding06: 'f', padding07: 'g', padding08: 'h',
    scripts: { build: 'webpack' },
    overrides: { version: '9.9.9' },
  });
  const diff = await singleFileDiff('package.json', before, after);
  const hunkCount = (diff.match(/^@@/gm) || []).length;
  assert.ok(hunkCount >= 2, `fixture must produce multiple hunks to test cross-hunk pairing; got ${hunkCount}`);
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /"version":\s*"1\.2\.3"/.test(line)),
    `expected the unpaired version removal to be flagged; got ${JSON.stringify(removals)}`,
  );
});

test('collectContentRemovals does not pair a removal in one file with an addition in a different file (Codex UmlJp)', async () => {
  // currentFile tracking must gate pairing exactly like exemption checks do:
  // a version removed from the root package.json must never be paired with an
  // unrelated version added to a nested package.json in the same combined diff.
  const diff = await multiFileDiff([
    {
      relPath: 'package.json',
      before: pkg({ version: '1.2.3', scripts: { build: 'webpack' } }),
      after: pkg({ scripts: { build: 'webpack' } }),
    },
    {
      relPath: 'packages/nested/package.json',
      before: pkg({ scripts: { build: 'webpack' } }),
      after: pkg({ version: '9.9.9', scripts: { build: 'webpack' } }),
    },
  ]);
  // Guard against a vacuous pass: without this precondition, a future
  // regression that made multiFileDiff emit only the first file's diff would
  // still flag the 1.2.3 removal (it is a pure deletion in that single-file
  // diff too) and the test would report success without ever exercising
  // cross-file pairing (CodeRabbit).
  assert.ok(
    /^\+\+\+ b\/package\.json$/m.test(diff)
    && /^\+\+\+ b\/packages\/nested\/package\.json$/m.test(diff),
    `fixture must produce a combined two-file diff to test cross-file pairing; got ${diff}`,
  );
  const removals = collectContentRemovals(diff);
  assert.ok(
    removals.some((line) => /"version":\s*"1\.2\.3"/.test(line)),
    `expected the version removal in package.json to be flagged; got ${JSON.stringify(removals)}`,
  );
});
