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
  withNoTextconv,
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
    const hashFileOrMissing = (filePath) => {
      try {
        const st = fs.lstatSync(filePath);
        if (st.isFile()) return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
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
      { path: 'large-untracked.bin', hash: expected },
    ]);
    const fingerprint = await workingTreeFingerprint(repo);
    // The streamed hash must match a one-shot SHA-256 of the large file.
    assert.equal(fingerprint, expectedFingerprint, 'streamed hash must match a one-shot SHA-256 of the large file');
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
    // hidden/x is ignored via core.excludesFile, so it must not appear as an
    // untracked entry — but the seal already recorded the excludes file.
    const withHidden = await workingTreeFingerprint(repo);
    assert.equal(withHidden, afterConfig, 'ignored untracked files must not change fingerprint beyond excludes seal');
    await writeFile(excludesPath, 'hidden/\nother/\n');
    const afterContents = await workingTreeFingerprint(repo);
    assert.notEqual(afterConfig, afterContents, 'mutating core.excludesFile contents must change the fingerprint');
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
