const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const { mkdir, mkdtemp, rm, symlink, writeFile } = require('node:fs/promises');
const { tmpdir } = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  cleanTreeStatus,
  readGateChanges,
  readProjectMetadata,
  resolveRepositoryState,
  scanTouchedSuppressions,
  workingTreeFingerprint,
} = require('./pr_closeout_repo');

const git = (repo, ...args) => execFileSync('git', args, { cwd: repo, encoding: 'utf8' }).trim();

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
