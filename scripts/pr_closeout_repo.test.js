const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { chmod, mkdir, mkdtemp, rm, symlink, utimes, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  cleanTreeStatus,
  gitChildEnv,
  readGateChanges,
  readProjectMetadata,
  resolveRepositoryState,
  scanTouchedSuppressions,
  withNoTextconv,
  workingTreeFingerprint,
} = require('./pr_closeout_repo');
const { buildCheckPlan } = require('./pr_closeout_core');

const git = (repo, ...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();

test('gitChildEnv strips GIT_* keys case-insensitively (Windows env bypass)', () => {
  // On Windows env names are case-insensitive; Git still honors git_dir /
  // Git_Config_* as GIT_* routing/config. Uppercase-only scrub was insufficient
  // (Qodo #4781532944).
  const sanitized = gitChildEnv({
    PATH: '/usr/bin',
    HOME: '/tmp/home',
    GIT_DIR: '/evil/git',
    git_dir: '/evil/lower',
    Git_Work_Tree: '/evil/work',
    GIT_EXTERNAL_DIFF: '/evil/diff',
    Git_Config_Count: '1',
    Git_Config_Key_0: 'diff.external',
    Git_Config_Value_0: '/evil/diff',
    OMO_CODEX_SHELL_PATH: '/bin/bash',
    NOT_GIT_RELATED: 'keep',
  });
  const remaining = Object.keys(sanitized).sort();
  assert.deepEqual(remaining, ['HOME', 'NOT_GIT_RELATED', 'OMO_CODEX_SHELL_PATH', 'PATH']);
  assert.equal(sanitized.PATH, '/usr/bin');
  assert.equal(sanitized.NOT_GIT_RELATED, 'keep');
});

const fixtureRepo = async () => {
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-repo-'));
  git(repo, 'init', '--quiet');
  git(repo, 'config', 'user.name', 'Closeout Test');
  git(repo, 'config', 'user.email', 'closeout@example.invalid');
  git(repo, 'config', 'commit.gpgsign', 'false');
  await writeFile(path.join(repo, 'package.json'), JSON.stringify({ scripts: { typecheck: 'tsc --noEmit' } }));
  await writeFile(path.join(repo, 'Makefile'), 'smoke:\n\t@echo ok\n\ngrafana-render:\n\t@echo render\n');
  await writeFile(path.join(repo, 'tracked.txt'), 'base\n');
  git(repo, 'add', '.');
  git(repo, 'commit', '--quiet', '-m', 'base');
  return repo;
};

test('collects committed, staged, unstaged, and untracked touched files', async () => {
  const repo = await fixtureRepo();
  try {
    await writeFile(path.join(repo, 'tracked.txt'), 'changed\n');
    await writeFile(path.join(repo, 'staged.txt'), 'staged\n');
    git(repo, 'add', 'staged.txt');
    await writeFile(path.join(repo, 'untracked.txt'), 'untracked\n');
    const state = await resolveRepositoryState({ repo, baseRef: 'HEAD' });
    assert.match(state.headSha, /^[a-f0-9]{40}$/);
    assert.equal(state.baseSha, state.headSha);
    assert.deepEqual(state.touchedFiles, ['staged.txt', 'tracked.txt', 'untracked.txt']);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('reads project metadata, fingerprints changes, and reports clean-tree truth', async () => {
  const repo = await fixtureRepo();
  try {
    const metadata = await readProjectMetadata(repo);
    assert.equal(metadata.packageScripts.typecheck, 'tsc --noEmit');
    assert.ok(metadata.makeTargets.includes('grafana-render'));
    const clean = await cleanTreeStatus(repo);
    assert.equal(clean.status, 'PASS');
    await writeFile(path.join(repo, 'new.txt'), 'first');
    const first = await workingTreeFingerprint(repo);
    await writeFile(path.join(repo, 'new.txt'), 'second');
    const second = await workingTreeFingerprint(repo);
    assert.notEqual(first, second);
    assert.equal((await cleanTreeStatus(repo)).status, 'FAIL');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('readProjectMetadata discovers make targets from GNUmakefile and makefile defaults', async () => {
  // GNU make searches GNUmakefile, makefile, then Makefile. Repositories that
  // use the lowercase form must still surface their named targets so named
  // checks do not stay unresolved.
  for (const filename of ['GNUmakefile', 'makefile']) {
    const repo = await mkdtemp(path.join(tmpdir(), 'closeout-make-defaults-'));
    try {
      git(repo, 'init', '--quiet');
      git(repo, 'config', 'user.name', 'Closeout Test');
      git(repo, 'config', 'user.email', 'closeout@example.invalid');
      await writeFile(path.join(repo, filename), 'grafana-render:\n\t@echo render\n');
      git(repo, 'add', '.');
      git(repo, 'commit', '--quiet', '-m', 'baseline');
      const metadata = await readProjectMetadata(repo);
      assert.ok(
        metadata.makeTargets.includes('grafana-render'),
        `${filename} targets must be discovered, got: ${JSON.stringify(metadata.makeTargets)}`,
      );
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  }
});

test('readProjectMetadata captures make recipe bodies, and buildCheckPlan blocks a neutralizing one end-to-end (Codex Ummss)', async () => {
  // A resolved make target was trusted by name only; readProjectMetadata never
  // captured the recipe body, so buildCheckPlan's findMakeRecipeNeutralizer
  // always saw makeRecipes = {} and could never fire in production. Proves the
  // full path: a real Makefile's recipe text flows from readProjectMetadata
  // into buildCheckPlan and blocks a failure-hiding recipe.
  const repo = await mkdtemp(path.join(tmpdir(), 'closeout-make-recipe-'));
  try {
    git(repo, 'init', '--quiet');
    git(repo, 'config', 'user.name', 'Closeout Test');
    git(repo, 'config', 'user.email', 'closeout@example.invalid');
    await writeFile(path.join(repo, 'Makefile'), 'grafana-render:\n\t-@echo render ignoring failure\n');
    git(repo, 'add', '.');
    git(repo, 'commit', '--quiet', '-m', 'baseline');
    const metadata = await readProjectMetadata(repo);
    assert.ok(
      metadata.makeRecipes['grafana-render']?.includes('-@echo render ignoring failure'),
      `expected the grafana-render recipe body to be captured, got: ${JSON.stringify(metadata.makeRecipes)}`,
    );
    const plan = buildCheckPlan({ ...metadata, touchedFiles: [] });
    const check = plan.checks.find((c) => c.id === 'grafana-render');
    assert.equal(check.status, 'BLOCKED');
    assert.match(check.evidence, /neutralizes failures \(-\)/);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint hashes untracked symlinks instead of following them', async () => {
  // A validation command can leave an untracked symlink that points at an
  // outside file or device. Following it could hang (e.g. /dev/zero) or read
  // outside the repository before the dirty-tree check stops the run. The
  // fingerprint must hash the link target string, not dereference the link.
  const repo = await fixtureRepo();
  try {
    const outside = await mkdtemp(path.join(tmpdir(), 'closeout-fingerprint-outside-'));
    try {
      const outsideFile = path.join(outside, 'payload.txt');
      await writeFile(outsideFile, 'fingerprint-content');
      const linkPath = path.join(repo, 'link-to-outside.txt');
      try {
        await symlink(outsideFile, linkPath);
      } catch (error) {
        if (error.code === 'EPERM' || error.code === 'ENOSYS') {
          // Windows without developer mode / privileged symlink creation.
          return;
        }
        throw error;
      }
      const fingerprint = await workingTreeFingerprint(repo);
      // The fingerprint must be stable across re-reads (link target unchanged).
      const repeat = await workingTreeFingerprint(repo);
      assert.equal(fingerprint, repeat);
      // And it must NOT incorporate the outside file's contents: changing the
      // outside payload must not change the fingerprint of the untracked link.
      await writeFile(outsideFile, 'different-content');
      const afterChange = await workingTreeFingerprint(repo);
      assert.equal(fingerprint, afterChange, 'untracked symlink must be hashed as a link, not followed');
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint streams large untracked files instead of buffering them whole', async () => {
  // The fingerprint runs several times per closeout. A single large untracked
  // artifact must not be materialized in memory via readFile(); the streaming
  // hash must produce the SAME digest as a one-shot hash while keeping
  // memory bounded. Use a file larger than the default highWaterMark so the
  // stream is exercised across multiple chunks.
  const repo = await fixtureRepo();
  try {
    const large = path.join(repo, 'large-untracked.bin');
    const payload = Buffer.from('A'.repeat(1024));
    const stream = require('node:fs').createWriteStream(large);
    for (let i = 0; i < 8 * 1024; i += 1) stream.write(payload); // ~8 MiB
    await new Promise((resolve, reject) => {
      stream.end(resolve);
      stream.on('error', reject);
    });
    const expected = require('node:crypto').createHash('sha256').update(
      require('node:fs').readFileSync(large),
    ).digest('hex');
    const { fingerprintEntries } = require('../scripts/pr_closeout_git');
    const trackedDiff = require('node:child_process').execFileSync(
      'git', ['diff', '--binary', '--no-ext-diff', '--no-textconv', 'HEAD'], { cwd: repo },
    );
    // workingTreeFingerprint also seals .git/info/exclude and core.excludesFile.
    const excludePath = path.join(repo, '.git', 'info', 'exclude');
    const crypto = require('node:crypto');
    const fs = require('node:fs');
    const hashBytes = (value) => crypto.createHash('sha256').update(value).digest('hex');
    // Mirror hashFsEntry: regular files seal content AND permission bits so a
    // mode-only flip on an ignored reproducibility artifact cannot keep the
    // same digest. Missing paths hash to a fixed marker.
    const hashFileOrMissing = (filePath) => {
      try {
        const st = fs.lstatSync(filePath);
        if (st.isFile()) {
          const content = crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
          return hashBytes(`regular:mode=${st.mode & 0o777}:sha=${content}`);
        }
      } catch (error) {
        if (error.code !== 'ENOENT') throw error;
      }
      return hashBytes('missing');
    };
    let excludesFileHash = hashBytes('unset');
    try {
      const configured = git(repo, 'config', '--get', 'core.excludesFile');
      if (configured) {
        const resolved = path.isAbsolute(configured) ? configured : path.resolve(repo, configured);
        excludesFileHash = hashBytes(`path:${resolved}\0${hashFileOrMissing(resolved)}`);
      }
    } catch {
      // unset
    }
    // Global exclude seal must match workingTreeFingerprint (XDG + global core).
    const os = require('node:os');
    const globalExcludeParts = [];
    try {
      const globalExcludes = git(repo, 'config', '--global', '--get', 'core.excludesFile');
      if (globalExcludes) {
        const resolved = path.isAbsolute(globalExcludes)
          ? globalExcludes
          : path.resolve(os.homedir(), globalExcludes);
        globalExcludeParts.push(`globalCore:${resolved}\0${hashFileOrMissing(resolved)}`);
      } else {
        globalExcludeParts.push('globalCore:unset');
      }
    } catch {
      globalExcludeParts.push('globalCore:unset');
    }
    const xdgConfig = process.env.XDG_CONFIG_HOME
      ? process.env.XDG_CONFIG_HOME
      : path.join(os.homedir(), '.config');
    const xdgIgnore = path.join(xdgConfig, 'git', 'ignore');
    globalExcludeParts.push(`xdg:${xdgIgnore}\0${hashFileOrMissing(xdgIgnore)}`);
    const globalExcludesHash = hashBytes(globalExcludeParts.sort().join('\n'));
    const expectedFingerprint = fingerprintEntries([
      { path: '__tracked_diff__', hash: require('node:crypto').createHash('sha256').update(trackedDiff).digest('hex') },
      { path: '__git_info_exclude__', hash: hashFileOrMissing(excludePath) },
      { path: '__git_core_excludesFile__', hash: excludesFileHash },
      { path: '__git_global_excludes__', hash: globalExcludesHash },
      // No per-directory .gitignore in this fixture, so the seal is the empty hash.
      { path: '__gitignore_files__', hash: hashBytes('') },
      { path: 'large-untracked.bin', hash: hashFileOrMissing(large) },
    ]);
    const fingerprint = await workingTreeFingerprint(repo);
    // The streamed hash (with mode bits) must match the expected seal entry.
    assert.equal(fingerprint, expectedFingerprint, 'streamed hash must match a one-shot SHA-256 of the large file');
    // Sanity: content-only digest is still produced for the file itself.
    assert.equal(
      crypto.createHash('sha256').update(fs.readFileSync(large)).digest('hex'),
      expected,
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('extracts gate changes and scans the complete touched-file set', async () => {
  const repo = await fixtureRepo();
  try {
    const marker = ['eslint', '-disable'].join('');
    await writeFile(path.join(repo, 'source.js'), `// ${marker}\n`);
    await writeFile(path.join(repo, 'package.json'), JSON.stringify({ scripts: { test: 'vitest' } }, null, 2));
    const state = await resolveRepositoryState({ repo, baseRef: 'HEAD' });
    const findings = await scanTouchedSuppressions(repo, state.touchedFiles);
    const gate = await readGateChanges(repo, state.baseSha);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].file, 'source.js');
    assert.deepEqual(gate.changedFiles, ['package.json']);
    assert.ok(gate.addedLines.some((line) => line.includes('vitest')));
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('tags .codereview.yml added lines separately from other gate files', async () => {
  const repo = await fixtureRepo();
  try {
    // .codereview.yml is a declarative, non-executable gate config: its prose
    // can legitimately name a flag (e.g. "without --force") while describing
    // what a check requires. classifyGateIntegrity uses proseAddedLines to
    // exempt exactly those lines from its executable-invocation weakening
    // scan; readGateChanges must attribute added lines to the right file so
    // a change to a DIFFERENT gate file (package.json here) is never
    // exempted alongside it.
    await writeFile(path.join(repo, '.codereview.yml'), 'version: 1\n');
    git(repo, 'add', '.codereview.yml');
    git(repo, 'commit', '--quiet', '-m', 'add codereview config');
    const state = await resolveRepositoryState({ repo, baseRef: 'HEAD' });
    await writeFile(
      path.join(repo, '.codereview.yml'),
      'version: 1\ninstructions: |\n  FAIL on an existing target without --force, or invalid output.\n',
    );
    await writeFile(path.join(repo, 'package.json'), JSON.stringify({ scripts: { test: 'vitest', passWithNoTests: true } }));
    const gate = await readGateChanges(repo, state.baseSha);
    assert.deepEqual(gate.changedFiles, ['.codereview.yml', 'package.json']);
    const proseLine = gate.proseAddedLines.find((line) => line.includes('--force'));
    assert.ok(proseLine, `expected a --force line in proseAddedLines, got: ${JSON.stringify(gate.proseAddedLines)}`);
    // proseAddedLines is a tag, not an extraction: the line must still be
    // present in the full addedLines pool too.
    assert.ok(gate.addedLines.includes(proseLine));
    // package.json's added line must reach addedLines but never proseAddedLines,
    // even though it is scanned in the same combined diff.
    assert.ok(gate.addedLines.some((line) => line.includes('passWithNoTests')));
    assert.ok(!gate.proseAddedLines.some((line) => line.includes('passWithNoTests')));
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('surfaces deleted gate files on a dedicated channel', async () => {
  const repo = await fixtureRepo();
  try {
    // Deleting a validation-defining file contributes no added lines, so it
    // must reach classifyGateIntegrity through deletedFiles to fail closed.
    await rm(path.join(repo, 'Makefile'));
    await rm(path.join(repo, 'tracked.txt'));
    const state = await resolveRepositoryState({ repo, baseRef: 'HEAD' });
    const gate = await readGateChanges(repo, state.baseSha);
    assert.deepEqual(gate.deletedFiles, ['Makefile']);
    assert.ok(gate.changedFiles.includes('Makefile'));
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('decodes untracked gate files through the safe multi-encoding decoder', async () => {
  const repo = await fixtureRepo();
  try {
    // Untracked UTF-16LE biome.json with weakening content that the older
    // plain UTF-8 readFile path would silently mis-decode. Use an untracked
    // gate file (biome.json) instead of overwriting the tracked package.json,
    // because tracked modifications flow through `git diff` (UTF-8) and never
    // reach the decodeTouchedText branch in readGateChanges.
    const utf16 = Buffer.concat([
      Buffer.from([0xff, 0xfe]),
      Buffer.from(JSON.stringify({ linter: { enabled: false } }), 'utf16le'),
    ]);
    await writeFile(path.join(repo, 'biome.json'), utf16);
    const state = await resolveRepositoryState({ repo, baseRef: 'HEAD' });
    const gate = await readGateChanges(repo, state.baseSha);
    assert.deepEqual(gate.changedFiles, ['biome.json']);
    // The safe decoder must surface the weakening token instead of garbling it.
    assert.ok(
      gate.addedLines.some((line) => line.includes('"enabled":false') || line.includes('"enabled": false')),
      `expected weakening token in added lines, got: ${JSON.stringify(gate.addedLines)}`,
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('scans UTF-16 touched files and blocks unrecognized NUL-containing files', async () => {
  const repo = await fixtureRepo();
  try {
    const marker = ['eslint', '-disable'].join('');
    const utf16 = Buffer.concat([
      Buffer.from([0xff, 0xfe]),
      Buffer.from(`// ${marker}\n`, 'utf16le'),
    ]);
    await writeFile(path.join(repo, 'utf16-source.js'), utf16);
    await writeFile(path.join(repo, 'binary.dat'), Buffer.from([0x41, 0x00, 0x42, 0xff]));
    const state = await resolveRepositoryState({ repo, baseRef: 'HEAD' });
    const findings = await scanTouchedSuppressions(repo, state.touchedFiles);
    assert.ok(findings.some(({ file, category }) => file === 'utf16-source.js' && category === 'marker'));
    assert.ok(findings.some(({ file, category }) => file === 'binary.dat' && category === 'scan-error'));
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('fingerprints explicitly declared ignored generator output', async () => {
  const repo = await fixtureRepo();
  try {
    await writeFile(path.join(repo, '.gitignore'), 'generated/\n');
    git(repo, 'add', '.gitignore');
    git(repo, 'commit', '--quiet', '-m', 'ignore generated output');
    const generated = path.join(repo, 'generated');
    await mkdir(generated);
    await writeFile(path.join(generated, 'client.js'), 'first');
    const first = await workingTreeFingerprint(repo, ['generated']);
    await writeFile(path.join(generated, 'client.js'), 'second');
    const second = await workingTreeFingerprint(repo, ['generated']);
    assert.notEqual(first, second);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('repository seal includes permission bits for reproducibility entries', async () => {
  // Ignored generated artifacts are sealed via reproducibilityPaths; content
  // alone is not enough — flipping only the executable bit must change the
  // fingerprint so a later validation step cannot quietly re-mark the file.
  if (process.platform === 'win32') {
    // Windows does not preserve POSIX mode bits the same way; skip rather
    // than claim a false positive pass on an unsupported surface.
    return;
  }
  const repo = await fixtureRepo();
  try {
    await writeFile(path.join(repo, '.gitignore'), 'generated/\n');
    git(repo, 'add', '.gitignore');
    git(repo, 'commit', '--quiet', '-m', 'ignore generated output');
    const generated = path.join(repo, 'generated');
    await mkdir(generated);
    const artifact = path.join(generated, 'tool.sh');
    await writeFile(artifact, '#!/bin/sh\necho ok\n');
    await chmod(artifact, 0o644);
    const before = await workingTreeFingerprint(repo, ['generated']);
    await chmod(artifact, 0o755);
    const after = await workingTreeFingerprint(repo, ['generated']);
    assert.notEqual(before, after, 'mode-only change must break the repository seal');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('rejects touched symlinks instead of following them', async (t) => {
  const repo = await fixtureRepo();
  try {
    const marker = ['eslint', '-disable'].join('');
    await writeFile(path.join(repo, 'target.js'), `// ${marker}\n`);
    try {
      await symlink('target.js', path.join(repo, 'link.js'));
    } catch (error) {
      if (error.code === 'EPERM' || error.code === 'ENOSYS') {
        t.skip(`symlink creation not permitted on this platform (${error.code})`);
        return;
      }
      throw error;
    }
    const state = await resolveRepositoryState({ repo, baseRef: 'HEAD' });
    const findings = await scanTouchedSuppressions(repo, state.touchedFiles);
    const linkFinding = findings.find(({ file }) => file === 'link.js');
    assert.ok(linkFinding, 'expected a finding for the touched symlink');
    assert.equal(linkFinding.category, 'scan-error');
    assert.match(linkFinding.match, /symlink/i);
    assert.ok(
      !findings.some((finding) => finding.file === 'link.js' && finding.category !== 'scan-error'),
      'symlink must not be followed into suppression findings',
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('handles untracked gate files with more than 100k lines without RangeError', async () => {
  const repo = await fixtureRepo();
  try {
    const lineCount = 120_000;
    const body = Array.from({ length: lineCount }, (_, i) => `line-${i}`).join('\n');
    await writeFile(path.join(repo, 'pnpm-lock.yaml'), `${body}\n`);
    const state = await resolveRepositoryState({ repo, baseRef: 'HEAD' });
    const gate = await readGateChanges(repo, state.baseSha);
    assert.deepEqual(gate.changedFiles, ['pnpm-lock.yaml']);
    assert.equal(gate.addedLines.length, lineCount + 1);
    assert.ok(gate.addedLines.every((line) => line.startsWith('+')));
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('readProjectMetadata rejects non-regular metadata before reading it', async () => {
  // A reviewed branch can replace package.json or the first default makefile
  // with a directory (or FIFO): a plain read then throws EISDIR or blocks
  // before runCloseoutWorkflow has created any structured evidence report.
  // Fail closed with a clear error instead.
  for (const entry of ['package.json', 'GNUmakefile']) {
    const repo = await fixtureRepo();
    try {
      await rm(path.join(repo, entry), { force: true });
      await mkdir(path.join(repo, entry));
      await assert.rejects(readProjectMetadata(repo), /non-regular metadata/);
    } finally {
      await rm(repo, { recursive: true, force: true });
    }
  }
});

test('workingTreeFingerprint records a bounded marker for non-regular reproducibility entries', async (t) => {
  if (process.platform === 'win32') {
    t.skip('FIFO creation is not available on Windows');
    return;
  }
  // A generator can leave a FIFO under a configured reproducibility path such
  // as node_modules/.prisma. Streaming it blocks forever waiting for a writer
  // before any structured evidence report is written; the fingerprint must
  // record a bounded non-regular marker instead.
  const repo = await fixtureRepo();
  try {
    await mkdir(path.join(repo, 'out'));
    execFileSync('mkfifo', [path.join(repo, 'out', 'fifo')]);
    const hang = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('workingTreeFingerprint hung on a FIFO')), 5000).unref();
    });
    const fingerprint = await Promise.race([workingTreeFingerprint(repo, ['out']), hang]);
    const repeat = await workingTreeFingerprint(repo, ['out']);
    assert.equal(fingerprint, repeat, 'non-regular entry fingerprint must be stable across re-reads');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint seals core.excludesFile path and contents', async () => {
  // --exclude-standard honors core.excludesFile; mutating it can hide untracked
  // files without changing info/exclude. The seal must change when the config
  // path or the file contents change.
  const repo = await fixtureRepo();
  const outside = await mkdtemp(path.join(tmpdir(), 'closeout-excludes-file-'));
  try {
    const before = await workingTreeFingerprint(repo);
    const excludesPath = path.join(outside, 'extra-excludes');
    await writeFile(excludesPath, 'hidden/\n');
    git(repo, 'config', 'core.excludesFile', excludesPath);
    const afterConfig = await workingTreeFingerprint(repo);
    assert.notEqual(before, afterConfig, 'setting core.excludesFile must change the fingerprint');
    await mkdir(path.join(repo, 'hidden'));
    await writeFile(path.join(repo, 'hidden', 'x'), 'secret');
    // hidden/x is ignored via core.excludesFile. The seal must still move when
    // ignored inputs appear on disk (Codex #4781560042); --exclude-standard
    // alone would hide them from the untracked list.
    const withHidden = await workingTreeFingerprint(repo);
    assert.notEqual(withHidden, afterConfig, 'creating ignored untracked inputs must change the fingerprint');
    await writeFile(excludesPath, 'hidden/\nother/\n');
    const afterContents = await workingTreeFingerprint(repo);
    assert.notEqual(withHidden, afterContents, 'mutating core.excludesFile contents must change the fingerprint');
  } finally {
    await rm(repo, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint seals contents behind a core.excludesFile symlink', async () => {
  // Git follows core.excludesFile when it is a symlink. Hashing only the link
  // target string would leave the seal unchanged when the target file's
  // contents are rewritten to ignore newly created untracked files.
  if (process.platform === 'win32') return;
  const repo = await fixtureRepo();
  const outside = await mkdtemp(path.join(tmpdir(), 'closeout-excludes-symlink-'));
  try {
    const target = path.join(outside, 'real-excludes');
    const link = path.join(outside, 'excludes-link');
    await writeFile(target, 'hidden/\n');
    try {
      await symlink(target, link);
    } catch (error) {
      // Restricted sandboxes may disallow symlink creation; match sibling tests.
      if (error.code === 'EPERM' || error.code === 'ENOSYS' || error.code === 'EACCES') return;
      throw error;
    }
    git(repo, 'config', 'core.excludesFile', link);
    const before = await workingTreeFingerprint(repo);
    await writeFile(target, 'hidden/\nother/\n');
    const after = await workingTreeFingerprint(repo);
    assert.notEqual(
      before,
      after,
      'mutating the file behind a core.excludesFile symlink must change the fingerprint',
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint expands a tilde core.excludesFile the way Git does', async () => {
  // Git expands a leading ~/ in pathname config values against $HOME. Without
  // that expansion a value like ~/gitignore would be hashed as a repo-relative
  // path and a command could set excludesFile to hide untracked files without
  // changing the seal. The resolved path must be $HOME-relative.
  const repo = await fixtureRepo();
  const home = await mkdtemp(path.join(tmpdir(), 'closeout-tilde-home-'));
  try {
    const before = await workingTreeFingerprint(repo);
    // Place the real excludes file in the fake HOME and reference it via ~/.
    const relExcludes = path.join(home, 'gitignore');
    await writeFile(relExcludes, 'hidden/\n');
    // Point core.excludesFile at a ~/ pathname so expansion is exercised.
    git(repo, 'config', 'core.excludesFile', '~/gitignore');
    // os.homedir() reads HOME on POSIX and USERPROFILE on Windows; set both so
    // the resolved home is the fake home on every platform.
    const oldHome = process.env.HOME;
    const oldUserProfile = process.env.USERPROFILE;
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    try {
      const after = await workingTreeFingerprint(repo);
      assert.notEqual(before, after, 'a tilde excludesFile must resolve to $HOME and change the fingerprint');
      // A repo-relative interpretation (<repo>/~/gitignore) would not match the
      // real file; confirm the seal reflects the HOME-resolved file contents by
      // mutating it and observing a further change.
      await writeFile(relExcludes, 'hidden/\nother/\n');
      const afterMutate = await workingTreeFingerprint(repo);
      assert.notEqual(after, afterMutate, 'mutating the HOME-resolved tilde excludesFile must change the fingerprint');
    } finally {
      process.env.HOME = oldHome;
      process.env.USERPROFILE = oldUserProfile;
    }
  } finally {
    await rm(repo, { recursive: true, force: true });
    await rm(home, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint seals newly created ignored inputs like .env', async () => {
  // Codex #4781560042: gitignored inputs created mid-run must move the seal.
  const repo = await fixtureRepo();
  try {
    await writeFile(path.join(repo, '.gitignore'), '.env\n', 'utf8');
    git(repo, 'add', '.gitignore');
    git(repo, 'commit', '--quiet', '-m', 'ignore env');
    const before = await workingTreeFingerprint(repo);
    await writeFile(path.join(repo, '.env'), 'SECRET=1\n', 'utf8');
    const after = await workingTreeFingerprint(repo);
    assert.notEqual(before, after, 'creating a gitignored .env must change the fingerprint');
    await writeFile(path.join(repo, '.env'), 'SECRET=2\n', 'utf8');
    const afterMutate = await workingTreeFingerprint(repo);
    assert.notEqual(after, afterMutate, 'mutating a gitignored .env must change the fingerprint');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint fails closed when the ignored-untracked listing fails', async () => {
  // Codex Ukpkr: a constant placeholder hash on listing failure contributes the
  // same value to every fingerprint, so a listing that keeps failing the same
  // way before and after a validation command would hide a real change to an
  // ignored file. The whole fingerprint must reject instead.
  const repo = await fixtureRepo();
  try {
    const failingLister = async () => {
      throw new Error('simulated git ls-files failure');
    };
    await assert.rejects(
      workingTreeFingerprint(repo, [], { listIgnoredUntracked: failingLister }),
      /Failed to list ignored untracked files.*simulated git ls-files failure/,
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint seals an untracked self-ignoring .gitignore that hides files', async () => {
  // A validation command can write an untracked .gitignore that ignores itself
  // and an artifact directory. --exclude-standard then omits both the ignore
  // file and the hidden files, so without sealing per-directory ignore files
  // the fingerprint would be unchanged. The seal must change when a new
  // self-ignoring .gitignore appears.
  const repo = await fixtureRepo();
  try {
    const before = await workingTreeFingerprint(repo);
    // Create an untracked .gitignore that ignores itself and a hidden dir.
    await mkdir(path.join(repo, 'hidden'));
    await writeFile(path.join(repo, 'hidden', '.gitignore'), '.gitignore\nhidden/\n');
    await writeFile(path.join(repo, 'hidden', 'x'), 'secret');
    const after = await workingTreeFingerprint(repo);
    assert.notEqual(before, after, 'a newly-appeared self-ignoring .gitignore must change the fingerprint');
    // The hidden file is genuinely ignored by Git, but the ignore-file seal now
    // records it; mutating the ignore contents must change the seal again.
    await writeFile(path.join(repo, 'hidden', '.gitignore'), '.gitignore\nhidden/\nother/\n');
    const afterMutate = await workingTreeFingerprint(repo);
    assert.notEqual(after, afterMutate, 'mutating a self-ignoring .gitignore must change the fingerprint');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('cleanTreeStatus rejects assume-unchanged and skip-worktree index bits', async () => {
  // git update-index --assume-unchanged / --skip-worktree hide working-tree
  // modifications from `git status` and `git diff`, so a validation command can
  // edit a tracked file after marking it and leave porcelain clean. The seal
  // must fail closed when either bit is set on a tracked file.
  const repo = await fixtureRepo();
  try {
    // sanity: clean tree is PASS before any bit is set
    assert.equal((await cleanTreeStatus(repo)).status, 'PASS');
    await writeFile(path.join(repo, 'tracked.txt'), 'changed-but-assumed\n');
    git(repo, 'update-index', '--assume-unchanged', 'tracked.txt');
    const assumed = await cleanTreeStatus(repo);
    assert.equal(assumed.status, 'FAIL', `assume-unchanged must fail closed: ${JSON.stringify(assumed)}`);
    assert.match(assumed.evidence, /assume-unchanged|skip-worktree/i);
    // Clear the bit and set skip-worktree instead.
    git(repo, 'update-index', '--no-assume-unchanged', 'tracked.txt');
    git(repo, 'update-index', '--skip-worktree', 'tracked.txt');
    const skipped = await cleanTreeStatus(repo);
    assert.equal(skipped.status, 'FAIL', `skip-worktree must fail closed: ${JSON.stringify(skipped)}`);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('cleanTreeStatus detects a chmod change even when core.fileMode is disabled', async () => {
  // When core.fileMode=false, git status/diff ignore executable-bit changes.
  // The internal safety override forces core.fileMode=true so a chmod change to
  // a tracked file cannot hide from the clean-tree seal. POSIX-only: Windows
  // has no Unix executable bit for git to compare.
  if (process.platform === 'win32') return;
  const repo = await fixtureRepo();
  try {
    assert.equal((await cleanTreeStatus(repo)).status, 'PASS');
    git(repo, 'config', 'core.fileMode', 'false');
    const target = path.join(repo, 'tracked.txt');
    await chmod(target, 0o755);
    const result = await cleanTreeStatus(repo);
    assert.equal(result.status, 'FAIL', `chmod change must be detected despite core.fileMode=false: ${JSON.stringify(result)}`);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint does not invoke a configured clean filter driver', async () => {
  // Codex Ugise: `git diff` (used by hashGitOutput/workingTreeFingerprint to
  // seal the tracked diff against HEAD) genuinely needs content-level
  // comparison and so invokes a configured `clean` filter to convert the
  // worktree copy before diffing -- confirmed by manual repro: a plain `git
  // status --porcelain` does NOT invoke the filter to detect the same
  // modification (git's status dirty-check is stat/hash based and never
  // needed clean-filtered content), but `git diff --binary --no-ext-diff
  // --no-textconv HEAD` does. A touched .gitattributes selecting a
  // configured filter (or a validation command writing one to local config)
  // must not get that driver executed by workingTreeFingerprint's internal
  // diff call outside spawnCaptured's containment.
  const repo = await fixtureRepo();
  const marker = path.join(repo, 'evil-clean-ran');
  try {
    await writeFile(path.join(repo, '.gitattributes'), 'tracked.txt filter=evil\n');
    git(repo, 'add', '.gitattributes');
    git(repo, 'commit', '--quiet', '-m', 'attributes');
    // Drive the filter via `node <script>` rather than a `#!/bin/sh` shebang
    // so the driver runs identically on POSIX and native Windows git (a
    // shebang script isn't executable through Windows git's shell handling).
    const evilScript = path.join(repo, 'evil-clean.js');
    await writeFile(
      evilScript,
      `const fs=require('fs');fs.appendFileSync(${JSON.stringify(marker)},'ran\\n');process.stdin.pipe(process.stdout);`,
    );
    const filterCommand = `${JSON.stringify(process.execPath)} ${JSON.stringify(evilScript)}`;
    git(repo, 'config', 'filter.evil.clean', filterCommand);
    git(repo, 'config', 'filter.evil.required', 'true');
    // Baseline BEFORE the tracked modification: proves the post-mutation
    // fingerprint actually incorporated the change under the neutralized
    // filter, rather than silently degrading to a constant fallback hash on a
    // filter error (which would also be truthy, but wrong).
    const before = await workingTreeFingerprint(repo);
    // Modify the filtered file so the tracked-diff hash has a reason to
    // compare it against the index (and thus a reason to run the clean
    // filter absent neutralization).
    await writeFile(path.join(repo, 'tracked.txt'), 'changed\n');
    const fingerprint = await workingTreeFingerprint(repo);
    assert.ok(fingerprint, 'fingerprint must still be computed despite the modification');
    assert.notEqual(
      fingerprint,
      before,
      'tracked diff must actually incorporate the change under the neutralized filter',
    );
    assert.equal(
      require('node:fs').existsSync(marker),
      false,
      'filter.evil.clean must never have been invoked by an internal diff call',
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('scanTouchedSuppressions fails closed when file identity changes between lstat and open (TOCTOU)', async () => {
  // The suppression scan lstats the touched path, then opens it. openNoFollow
  // can fall back to a following open where O_NOFOLLOW is unavailable, so a
  // path (or a parent directory) swapped in that gap could redirect the read to
  // a different, clean file and miss a real suppression. The re-stat must be
  // bound back to the pre-open identity and fail closed on a mismatch instead
  // of scanning the swapped file.
  const repo = await fixtureRepo();
  try {
    const marker = ['eslint', '-disable'].join('');
    // A real file that DOES contain a suppression marker: if the identity gate
    // were bypassed, the scan would read it and emit a `marker` finding.
    await writeFile(path.join(repo, 'sneaky.js'), `// ${marker}\n`);
    const { lstat: realLstat } = require('node:fs/promises');
    // Simulate a pre-open lstat that observed a different on-disk file than the
    // descriptor openNoFollow ultimately returns. Override the device id (a
    // small-magnitude volume identifier, so +1 is always exact) as the robust
    // discriminator: NTFS inode numbers can exceed 2**53, where a naive ino+1
    // would be lost to float rounding and vacuously match. Kind is preserved so
    // the scan reaches the identity gate rather than tripping an earlier guard.
    const lstatFn = async (target) => {
      const real = await realLstat(target);
      return {
        ...real,
        dev: real.dev + 1,
        ino: real.ino + 4096,
        isFile: () => real.isFile(),
        isSymbolicLink: () => real.isSymbolicLink(),
        isDirectory: () => real.isDirectory(),
      };
    };
    const findings = await scanTouchedSuppressions(repo, ['sneaky.js'], { lstatFn });
    const finding = findings.find((f) => f.file === 'sneaky.js');
    assert.ok(finding, 'expected a finding for the identity-mismatched file');
    assert.equal(finding.category, 'scan-error', `must fail closed, got: ${JSON.stringify(finding)}`);
    assert.match(finding.match, /identity/i);
    assert.ok(
      !findings.some((f) => f.file === 'sneaky.js' && f.category === 'marker'),
      'a possibly-swapped file must never be scanned into a suppression finding',
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint structurally seals gitignored node_modules mutations', async () => {
  // git ignores node_modules and the ignored-untracked listing pathspec-
  // excludes it, so a dependency mutated/added/removed for the next validation
  // command to execute would otherwise leave every seal identical. The
  // structural digest (path + size + mtime + mode, not contents) must move the
  // fingerprint on any such change.
  const repo = await fixtureRepo();
  try {
    await writeFile(path.join(repo, '.gitignore'), 'node_modules/\n');
    git(repo, 'add', '.gitignore');
    git(repo, 'commit', '--quiet', '-m', 'ignore node_modules');
    const pkg = path.join(repo, 'node_modules', 'left-pad');
    await mkdir(pkg, { recursive: true });
    await writeFile(path.join(pkg, 'index.js'), 'module.exports = () => {};\n');
    await writeFile(path.join(pkg, 'package.json'), JSON.stringify({ name: 'left-pad', version: '1.0.0' }));

    // Sanity: node_modules is genuinely ignored, so git never surfaces it as an
    // untracked touched file — only the structural digest can seal it.
    const state = await resolveRepositoryState({ repo, baseRef: 'HEAD' });
    assert.ok(
      !state.touchedFiles.some((file) => file.startsWith('node_modules/')),
      `node_modules must be ignored, got: ${JSON.stringify(state.touchedFiles)}`,
    );

    const baseline = await workingTreeFingerprint(repo);
    // Re-reading an unchanged tree must be stable across runs.
    assert.equal(baseline, await workingTreeFingerprint(repo), 'unchanged tree must be stable');

    // (1) A file added under node_modules must move the seal.
    await writeFile(path.join(pkg, 'extra.js'), 'added\n');
    const afterAdd = await workingTreeFingerprint(repo);
    assert.notEqual(baseline, afterAdd, 'a file added under node_modules must change the fingerprint');

    // (2) Editing an existing file (size/content change) must move the seal.
    await writeFile(path.join(pkg, 'index.js'), 'module.exports = (s) => String(s).padStart(10, " ");\n');
    const afterEdit = await workingTreeFingerprint(repo);
    assert.notEqual(afterAdd, afterEdit, 'editing a file under node_modules must change the fingerprint');

    // (2b) A pure mtime bump (identical contents/size) must also move the seal,
    // proving mtime is part of the structural listing.
    const past = new Date('2020-01-01T00:00:00Z');
    await utimes(path.join(pkg, 'index.js'), past, past);
    const afterTouch = await workingTreeFingerprint(repo);
    assert.notEqual(afterEdit, afterTouch, 'a mtime change under node_modules must change the fingerprint');

    // (3) Removing a file must move the seal.
    await rm(path.join(pkg, 'extra.js'));
    const afterRemove = await workingTreeFingerprint(repo);
    assert.notEqual(afterTouch, afterRemove, 'removing a file under node_modules must change the fingerprint');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint node_modules structural digest stays fast for a few hundred files', async () => {
  const repo = await fixtureRepo();
  try {
    await writeFile(path.join(repo, '.gitignore'), 'node_modules/\n');
    git(repo, 'add', '.gitignore');
    git(repo, 'commit', '--quiet', '-m', 'ignore node_modules');
    // ~300 files spread across a handful of nested package directories.
    for (let p = 0; p < 15; p += 1) {
      const dir = path.join(repo, 'node_modules', `pkg-${p}`, 'lib');
      await mkdir(dir, { recursive: true });
      for (let f = 0; f < 20; f += 1) {
        await writeFile(path.join(dir, `mod-${f}.js`), `module.exports = ${f};\n`);
      }
    }
    const start = Date.now();
    const fingerprint = await workingTreeFingerprint(repo);
    const elapsed = Date.now() - start;
    assert.ok(fingerprint, 'fingerprint computed over a few-hundred-file node_modules');
    // Generous bound: proves the structural walk does not hang or explode,
    // without being flaky on slow or loaded CI.
    assert.ok(elapsed < 10_000, `structural digest should be fast; took ${elapsed}ms`);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('readGateChanges does not let a forged +++ header inside a hunk exempt weakening', async () => {
  // CodeRabbit UmlJc: with --unified=0, an ADDED source line whose content is
  // literally `++ b/.codereview.yml` is emitted in the diff as
  // `+++ b/.codereview.yml` INSIDE the hunk. If that were treated as a prose
  // file header, the rest of a non-prose gate file's added lines would be
  // exempted from the weakening scan (proseAddedLines), letting real weakening
  // self-exempt. Header detection must be gated on hunk state.
  const repo = await fixtureRepo();
  try {
    const workflowDir = path.join(repo, '.github', 'workflows');
    await mkdir(workflowDir, { recursive: true });
    const workflow = path.join(workflowDir, 'ci.yml');
    await writeFile(workflow, 'name: ci\non: push\n');
    git(repo, 'add', '.');
    git(repo, 'commit', '--quiet', '-m', 'add workflow');
    const state = await resolveRepositoryState({ repo, baseRef: 'HEAD' });
    // Append a forged prose-file header line followed by a real weakening line.
    await writeFile(workflow, 'name: ci\non: push\n++ b/.codereview.yml\n  run: git commit --no-verify\n');
    const gate = await readGateChanges(repo, state.baseSha);
    assert.ok(gate.changedFiles.includes('.github/workflows/ci.yml'));
    // The weakening line must still be scanned as an added line...
    assert.ok(
      gate.addedLines.some((line) => line.includes('git commit --no-verify')),
      `weakening line must be in addedLines, got: ${JSON.stringify(gate.addedLines)}`,
    );
    // ...but must NOT be exempted via the prose channel by the forged header.
    assert.ok(
      !gate.proseAddedLines.some((line) => line.includes('--no-verify')),
      `forged header must not exempt weakening, got proseAddedLines: ${JSON.stringify(gate.proseAddedLines)}`,
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint moves the seal when node_modules is created from absent', async () => {
  // UmlJh: structuralDigest returns null when the root is absent, contributing
  // no entry; its later creation (a validation command installing deps mid-run)
  // must move the seal by making the entry appear. Every other node_modules
  // case starts already-populated, so this null->present transition is the one
  // a mid-run install actually exercises.
  const repo = await fixtureRepo();
  try {
    await writeFile(path.join(repo, '.gitignore'), 'node_modules/\n');
    git(repo, 'add', '.gitignore');
    git(repo, 'commit', '--quiet', '-m', 'ignore node_modules');
    // No node_modules yet.
    const before = await workingTreeFingerprint(repo);
    const pkg = path.join(repo, 'node_modules', 'x');
    await mkdir(pkg, { recursive: true });
    await writeFile(path.join(pkg, 'index.js'), 'module.exports = 1;\n');
    const after = await workingTreeFingerprint(repo);
    assert.notEqual(before, after, 'creating node_modules from absent must change the fingerprint');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint seals node_modules content even when size and mtime are preserved', async () => {
  // Codex UnKZx: a same-length in-place content rewrite that restores the
  // original mtime (touch -r / cp -p) leaves size + mtime + mode identical. The
  // structural digest also seals ctimeMs, which no user-facing API can reset, so
  // the swap still moves the fingerprint.
  const { statSync } = require('node:fs');
  const repo = await fixtureRepo();
  try {
    await writeFile(path.join(repo, '.gitignore'), 'node_modules/\n');
    git(repo, 'add', '.gitignore');
    git(repo, 'commit', '--quiet', '-m', 'ignore node_modules');
    const pkg = path.join(repo, 'node_modules', 'dep');
    await mkdir(pkg, { recursive: true });
    const target = path.join(pkg, 'index.js');
    // Pin mtime to a fixed integer-ms instant so restoring it after the rewrite
    // yields a byte-identical mtimeMs (no sub-ms rounding), isolating ctime as
    // the only differing metadata.
    const fixed = new Date('2021-06-01T00:00:00.000Z');
    await writeFile(target, 'AAAA');
    await utimes(target, fixed, fixed);
    const s1 = statSync(target);
    const before = await workingTreeFingerprint(repo);
    // Same-length rewrite, then restore the pinned mtime.
    await writeFile(target, 'BBBB');
    await utimes(target, fixed, fixed);
    const s2 = statSync(target);
    const after = await workingTreeFingerprint(repo);
    // Preconditions: only ctime differs between the two snapshots.
    assert.equal(s2.size, s1.size, 'precondition: same length');
    assert.equal(s2.mtimeMs, s1.mtimeMs, 'precondition: mtime restored to an identical value');
    assert.notEqual(s2.ctimeMs, s1.ctimeMs, 'precondition: ctime moved (the only differing metadata)');
    assert.notEqual(before, after, 'a same-length rewrite with restored mtime must still change the fingerprint');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint fails closed when a node_modules tree exceeds the structural cap', async () => {
  // Codex UnKZ0 / Qodo UmhWL: exceeding the entry cap must BLOCK (throw), not
  // silently seal a truncated prefix that stays identical across checkpoints
  // while hiding a dependency changed past the cutoff. The cap is injectable so
  // the truncation path is pinned without building a 200k-entry tree.
  const repo = await fixtureRepo();
  try {
    await writeFile(path.join(repo, '.gitignore'), 'node_modules/\n');
    git(repo, 'add', '.gitignore');
    git(repo, 'commit', '--quiet', '-m', 'ignore node_modules');
    const pkg = path.join(repo, 'node_modules', 'dep');
    await mkdir(pkg, { recursive: true });
    for (let i = 0; i < 8; i += 1) {
      await writeFile(path.join(pkg, `file-${i}.js`), `module.exports = ${i};\n`);
    }
    // A generous cap seals the whole tree without error.
    const ok = await workingTreeFingerprint(repo, [], { maxStructuralDigestEntries: 10_000 });
    assert.ok(ok, 'a tree under the cap seals normally');
    // A tiny cap forces truncation, which must fail closed.
    await assert.rejects(
      workingTreeFingerprint(repo, [], { maxStructuralDigestEntries: 3 }),
      /structural walk exceeded 3 entries/,
      'exceeding the structural cap must throw (fail closed), not seal a truncated prefix',
    );
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test('workingTreeFingerprint seals nested workspace node_modules roots', async () => {
  // Codex Ummso: in a monorepo, a package-local node_modules
  // (packages/api/node_modules) is pathspec-excluded from the ignored-untracked
  // listing and is NOT under the repo-root node_modules, so a repo-root-only
  // structural digest would miss a mutation there. All workspace node_modules
  // roots must be discovered and sealed.
  const repo = await fixtureRepo();
  try {
    await writeFile(path.join(repo, '.gitignore'), 'node_modules/\n');
    git(repo, 'add', '.gitignore');
    git(repo, 'commit', '--quiet', '-m', 'ignore node_modules');
    const nested = path.join(repo, 'packages', 'api', 'node_modules', 'dep');
    await mkdir(nested, { recursive: true });
    await writeFile(path.join(nested, 'index.js'), 'AAAA');

    // Sanity: the nested node_modules is genuinely ignored (not an untracked
    // touched file), so only the structural digest can seal it.
    const state = await resolveRepositoryState({ repo, baseRef: 'HEAD' });
    assert.ok(
      !state.touchedFiles.some((file) => file.includes('node_modules/')),
      `nested node_modules must be ignored, got: ${JSON.stringify(state.touchedFiles)}`,
    );

    const before = await workingTreeFingerprint(repo);
    // Mutate the package-local dependency (size change) — must move the seal.
    await writeFile(path.join(nested, 'index.js'), 'BBBBBB');
    const after = await workingTreeFingerprint(repo);
    assert.notEqual(before, after, 'a package-local node_modules mutation must change the fingerprint');
    // Adding a file under the nested root must also move the seal.
    await writeFile(path.join(nested, 'extra.js'), 'x\n');
    const afterAdd = await workingTreeFingerprint(repo);
    assert.notEqual(after, afterAdd, 'adding a file under a nested node_modules must change the fingerprint');
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});
