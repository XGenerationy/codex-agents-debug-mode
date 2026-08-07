# Closeout Engine Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an explicit `--mode strict|engine` tier to the PR closeout gate — strict stays byte-for-byte today's 19-check gate; engine mode runs a config-supplied matrix through the same integrity machinery, with mode-bound attestation digests, labeled reports, and a plan-mode admission block.

**Architecture:** The mode enters at the CLI (`pr_closeout.js`), threads through `runCloseoutWorkflow` into `buildCheckPlan` (`pr_closeout_core.js`), which sources definitions from either `MANDATORY_CHECKS` or a new fail-closed `validateEngineChecks(config.engineChecks)`. The attestation digest input gains `mode` (schemaVersion 2→3 — deliberate one-time invalidation, recorded in the spec). Reports gain a `mode` field and an engine-only banner. `--plan` gains an `admission` block. Spec: `docs/superpowers/specs/2026-08-07-closeout-engine-mode-design.md`.

**Tech Stack:** Node >= 20, CommonJS, zero dependencies, `node --test --test-concurrency=1`, hermetic tests with injected `runGh`/dependency fakes.

**Ground rules for every task:**
- Branch `feat/closeout-engine-mode`. Never push. One commit per task, message as specified, each ending with exactly:

```
Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_013VQCeNzNXziDk5maCRSSvp
```

- STRICT-MODE INVARIANCE IS THE PRIME DIRECTIVE: no existing test may be modified (additive appends to test files only), and no strict-run behavior may change except the additive `mode` report/plan field. If a change you're making would alter any existing test's outcome, STOP and report BLOCKED.
- `pr_closeout_process.js` (3879 lines) and `pr_closeout_process.test.js` must not be read whole or modified. `pr_closeout_core.js`/`pr_closeout_workflow.js`/`pr_closeout_repo.js`/their tests are 1500-3600 lines: bounded reads around the anchors this plan names, never whole-file reads.
- Run only ONE test invocation at a time, foreground (concurrent suites cause spurious access violations on this machine). Targeted runs during TDD; ONE full `npm test` only in Task 7.

---

### Task 1: CLI `--mode` flag + workflow-entry mode guard

**Files:**
- Modify: `scripts/pr_closeout.js` (parseArgs ~lines 34-56, HELP ~10-21, main ~198-217)
- Modify: `scripts/pr_closeout_workflow.js` (wrapper ~936-946, body signature ~952-959)
- Test: `scripts/pr_closeout_cli.test.js` (append), `scripts/pr_closeout_workflow.test.js` (append)

- [ ] **Step 1: Write the failing tests**

Append to `scripts/pr_closeout_cli.test.js` (it already requires `parseArgs` from `./pr_closeout`; if not, extend its existing destructured require):

```js
test('parseArgs defaults mode to strict and accepts --mode engine', () => {
  assert.equal(parseArgs([]).mode, 'strict');
  assert.equal(parseArgs(['--mode', 'engine']).mode, 'engine');
  assert.equal(parseArgs(['--mode', 'strict']).mode, 'strict');
});

test('parseArgs rejects unknown --mode values and a missing value', () => {
  assert.throws(() => parseArgs(['--mode', 'lenient']), /Unknown --mode value: lenient/);
  assert.throws(() => parseArgs(['--mode']), /Missing value for --mode/);
  assert.throws(() => parseArgs(['--mode', '--plan']), /Missing value for --mode/);
});
```

Append to `scripts/pr_closeout_workflow.test.js` (NOTE: model the dependency-injection shape on the file's existing `runCloseoutWorkflow` tests — it exports `runCloseoutWorkflow` from `./pr_closeout_workflow`; the injected `resolveRepositoryState` fake that throws proves the rejection happens before any repository work):

```js
test('config.mode is rejected before any repository work — mode comes only from the invocation', async () => {
  await assert.rejects(
    () => runCloseoutWorkflow({
      repo: process.cwd(),
      baseRef: 'origin/main',
      config: { mode: 'engine' },
      planOnly: true,
      dependencies: {
        resolveRepositoryState: async () => { throw new Error('must not be called'); },
      },
    }),
    /mode cannot be set from config/,
  );
});
```

- [ ] **Step 2: Run to verify failures**

Run: `node --test --test-concurrency=1 scripts/pr_closeout_cli.test.js scripts/pr_closeout_workflow.test.js`
Expected: the two new CLI tests fail (`mode` is `undefined`, `--mode` is an unknown argument); the workflow test fails (config.mode is currently ignored). All pre-existing tests still pass.

- [ ] **Step 3: Implement**

In `scripts/pr_closeout.js`:

1. HELP text — add one line after the `--output-dir` row and re-pad the sibling rows so every description starts at the same column (post-review alignment):

```
  --mode <strict|engine>  Gate tier (default: strict; engine runs config.engineChecks)
```

2. `parseArgs` — initialize `const options = { repo: process.cwd(), plan: false, mode: 'strict' };`, add `'--mode'` to the value-flag array `['--repo', '--base-ref', '--config', '--output-dir', '--mode']` and to the key map (`'--mode': 'mode'`), and after the parse loop, before `return options;`:

```js
  // The mode is operator intent, not configuration: an unknown value is a
  // hard could-not-run error (exit 3 class), never a silent strict fallback.
  if (options.mode !== 'strict' && options.mode !== 'engine') {
    throw new Error(`Unknown --mode value: ${options.mode}. Use strict or engine.`);
  }
```

3. `main` — pass the mode through: add `mode: options.mode,` to the `runCloseoutWorkflow({...})` call alongside `planOnly`.

In `scripts/pr_closeout_workflow.js`:

1. `runCloseoutWorkflow` wrapper (~line 936): accept `mode = 'strict'` in its destructured params and forward `mode,` in the object it passes to `runCloseoutWorkflowBody` (the call at ~940-946 that currently forwards `repo, baseRef, config, outputDir, planOnly, dependencies`).
2. `runCloseoutWorkflowBody` (~line 952): accept `mode = 'strict'` and add, as the FIRST statements of the body (before `const d = ...`):

```js
  // Mode is invocation-only: a config file that could switch a strict run
  // into engine mode would be a silent weakening channel, so its presence in
  // config is a hard error rather than an ignored key.
  if (Object.hasOwn(config, 'mode')) {
    throw new Error('The closeout mode cannot be set from config; pass --mode on the invocation.');
  }
  if (mode !== 'strict' && mode !== 'engine') {
    throw new Error(`Unknown closeout mode "${mode}". Use strict or engine.`);
  }
```

- [ ] **Step 4: Run to verify green**

Run: `node --test --test-concurrency=1 scripts/pr_closeout_cli.test.js scripts/pr_closeout_workflow.test.js`
Expected: all pass, including every pre-existing test. `node --check scripts/pr_closeout.js scripts/pr_closeout_workflow.js` clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/pr_closeout.js scripts/pr_closeout_workflow.js scripts/pr_closeout_cli.test.js scripts/pr_closeout_workflow.test.js
git commit -m "feat(closeout): --mode flag, invocation-only, fail-closed"
```

(with the standard two trailers)

---

### Task 2: `validateEngineChecks` — fail-closed engine matrix schema

**Files:**
- Modify: `scripts/pr_closeout_core.js` (insert after `REQUIRED_PROOFS`, ~line 294; extend `module.exports` ~line 1674)
- Test: `scripts/pr_closeout_core.test.js` (append)

- [ ] **Step 1: Write the failing tests**

Append to `scripts/pr_closeout_core.test.js` (add `validateEngineChecks` to the existing destructured require at the top — additive edit to that require only):

```js
test('validateEngineChecks normalizes a valid matrix', () => {
  const defs = validateEngineChecks([
    { id: 'unit', command: 'cargo test' },
    { id: 'lint', label: 'Lint', scripts: ['lint', 'lint:all'], baselineSafe: true, timeoutMs: 60000 },
  ]);
  assert.deepEqual(defs[0], {
    id: 'unit', label: 'unit', command: 'cargo test', baselineSafe: false, generator: false, engine: true,
  });
  assert.deepEqual(defs[1], {
    id: 'lint', label: 'Lint', packageCandidates: ['lint', 'lint:all'], baselineSafe: true, generator: false, timeoutMs: 60000, engine: true,
  });
});

test('validateEngineChecks fails closed on every malformed shape', () => {
  assert.throws(() => validateEngineChecks(undefined), /non-empty array/);
  assert.throws(() => validateEngineChecks([]), /non-empty array/);
  assert.throws(() => validateEngineChecks(['x']), /must be an object/);
  assert.throws(() => validateEngineChecks([{ command: 'x' }]), /non-empty string id/);
  assert.throws(() => validateEngineChecks([{ id: ' padded ', command: 'x' }]), /leading or trailing whitespace/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x' }, { id: 'a', command: 'y' }]), /unique/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', fixed: true }]), /unknown field "fixed"/);
  assert.throws(() => validateEngineChecks([{ id: 'a' }]), /exactly one of "command" or "scripts"/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', scripts: ['y'] }]), /exactly one of "command" or "scripts"/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: '   ' }]), /command must be a non-empty string/);
  assert.throws(() => validateEngineChecks([{ id: 'a', scripts: [] }]), /non-empty array of non-empty script names/);
  assert.throws(() => validateEngineChecks([{ id: 'a', scripts: ['ok', 42] }]), /non-empty array of non-empty script names/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', label: '' }]), /label must be a non-empty string/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', baselineSafe: 'yes' }]), /baselineSafe must be a boolean/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', timeoutMs: 0 }]), /timeoutMs must be a positive integer/);
  assert.throws(() => validateEngineChecks([{ id: 'a', command: 'x', timeoutMs: 1.5 }]), /timeoutMs must be a positive integer/);
});

test('validateEngineChecks hardening: id charset, prototype collisions, timer bound, read-once fields', () => {
  for (const id of ['bad\nid', 'a\tb', '.dot-start', '-dash-start', 'sp ace', '__proto__']) {
    assert.throws(
      () => validateEngineChecks([{ id, command: 'x' }]),
      /must start alphanumeric|collides with an Object\.prototype member/,
    );
  }
  for (const id of ['constructor', 'toString', 'valueOf', 'hasOwnProperty']) {
    assert.throws(
      () => validateEngineChecks([{ id, command: 'x' }]),
      /collides with an Object\.prototype member/,
    );
  }
  assert.equal(validateEngineChecks([{ id: 'ok.check_1-x', command: 'x' }])[0].id, 'ok.check_1-x');
  assert.throws(
    () => validateEngineChecks([{ id: 'big', command: 'x', timeoutMs: 2147483648 }]),
    /no greater than 2147483647/,
  );
  // Read-once: a getter that swaps its value after the first read cannot
  // sneak a different command past validation into the emitted definition.
  let reads = 0;
  const swapped = validateEngineChecks([{
    id: 'g1',
    get command() { reads += 1; return reads === 1 ? 'safe command' : 'npm test || true'; },
  }])[0];
  assert.equal(swapped.command, 'safe command');
  const scriptsSource = ['ok'];
  const proxied = validateEngineChecks([new Proxy({ id: 'p1', scripts: scriptsSource }, {
    get(target, property) {
      if (property === 'scripts') return [...scriptsSource];
      return target[property];
    },
  })])[0];
  assert.deepEqual(proxied.packageCandidates, ['ok']);
});
```

- [ ] **Step 2: Run to verify failures**

Run: `node --test --test-concurrency=1 --test-name-pattern="validateEngineChecks" scripts/pr_closeout_core.test.js`
Expected: both fail (`validateEngineChecks` is not exported). Then run the file WITHOUT the name pattern once to confirm every pre-existing test still passes.

- [ ] **Step 3: Implement (insert into `scripts/pr_closeout_core.js` immediately after the `REQUIRED_PROOFS` block, ~line 294)**

```js
// Fields an engine-mode check definition may carry. Anything else — most
// pointedly `fixed`, `packageCandidates`, or `makeCandidates` — is either a
// weakening vector or a typo; both fail closed rather than being ignored.
const ENGINE_CHECK_FIELDS = new Set(['id', 'label', 'command', 'scripts', 'baselineSafe', 'generator', 'timeoutMs']);

// Engine ids reach id-keyed plain-object lookups (timeoutsMs, proofs,
// resourceGroups) and rendered reports downstream: a charset gate plus an
// Object.prototype collision check (below) closes prototype-shaped and
// control-character ids deterministically instead of relying on every
// downstream lookup failing closed by accident.
const ENGINE_CHECK_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/**
 * Validate and normalize `config.engineChecks` into check definitions the
 * shared resolution pipeline in buildCheckPlan can consume. Engine mode
 * replaces the strict matrix WHOLESALE (spec decision: no merging, no
 * inheritance — a hybrid would be neither guarantee), so this is the single
 * gate every engine matrix passes through. Every violation is a named error
 * and the whole matrix is rejected — a partially-valid matrix is not a
 * matrix. Ids are used verbatim in reports, digests, and attestations, so
 * padded ids are rejected instead of silently trimmed. `baselineSafe`
 * defaults to false (fail-closed: baseline verification must be opted into,
 * never assumed). The returned definitions carry `engine: true` so
 * buildCheckPlan resolves commands through the engine branch (placeholder,
 * neutralizer, and make-recipe validation — user-supplied commands are never
 * trusted the way the strict matrix's own hardcoded commands are).
 * @param {unknown} engineChecks - config.engineChecks as supplied.
 * @returns {object[]} normalized definitions.
 */
const validateEngineChecks = (engineChecks) => {
  if (!Array.isArray(engineChecks) || engineChecks.length === 0) {
    throw new Error('Engine mode requires config.engineChecks: a non-empty array of check definitions.');
  }
  const seen = new Set();
  return engineChecks.map((entry, index) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error(`Engine check at index ${index} must be an object.`);
    }
    // Read every field exactly once, up front: validation and emission both
    // use these locals, so a getter/Proxy entry can never swap the emitted
    // value after validation — read-once makes the fail-closed claim true by
    // construction, not by JSON.parse happening to produce plain data.
    const { id, label, command, scripts, baselineSafe, generator, timeoutMs } = entry;
    const scriptsCopy = Array.isArray(scripts) ? [...scripts] : scripts;
    for (const field of Object.keys(entry)) {
      if (!ENGINE_CHECK_FIELDS.has(field)) {
        const where = typeof id === 'string' && id ? `"${id}"` : `at index ${index}`;
        const hint = field === 'qualificationSafe' || field === 'resourceGroup'
          ? ` (${field} belongs in the id-keyed config map config.${field === 'qualificationSafe' ? 'qualificationSafe' : 'resourceGroups'}, not inline)`
          : '';
        throw new Error(`Engine check ${where} has unknown field "${field}"; unknown fields are never ignored${hint}.`);
      }
    }
    if (typeof id !== 'string' || !id.trim()) {
      throw new Error(`Engine check at index ${index} must have a non-empty string id.`);
    }
    if (id !== id.trim()) {
      throw new Error(`Engine check id "${id}" must not have leading or trailing whitespace.`);
    }
    if (!ENGINE_CHECK_ID_PATTERN.test(id)) {
      throw new Error(`Engine check id "${id}" must start alphanumeric and use only letters, digits, ".", "_", "-".`);
    }
    if (id in {}) {
      throw new Error(`Engine check id "${id}" collides with an Object.prototype member; choose another id.`);
    }
    if (seen.has(id)) throw new Error(`Engine check ids must be unique: "${id}" at index ${index} appears more than once.`);
    seen.add(id);
    const hasCommand = Object.hasOwn(entry, 'command');
    const hasScripts = Object.hasOwn(entry, 'scripts');
    if (hasCommand === hasScripts) {
      throw new Error(`Engine check "${id}" must define exactly one of "command" or "scripts".`);
    }
    if (hasCommand && (typeof command !== 'string' || !command.trim())) {
      throw new Error(`Engine check "${id}": command must be a non-empty string.`);
    }
    if (hasScripts && (
      !Array.isArray(scriptsCopy) || scriptsCopy.length === 0
      || scriptsCopy.some((name) => typeof name !== 'string' || !name.trim())
    )) {
      throw new Error(`Engine check "${id}": scripts must be a non-empty array of non-empty script names.`);
    }
    if (Object.hasOwn(entry, 'label') && (typeof label !== 'string' || !label.trim())) {
      throw new Error(`Engine check "${id}": label must be a non-empty string when present.`);
    }
    const booleanFlags = { baselineSafe, generator };
    for (const flag of ['baselineSafe', 'generator']) {
      if (Object.hasOwn(entry, flag) && typeof booleanFlags[flag] !== 'boolean') {
        throw new Error(`Engine check "${id}": ${flag} must be a boolean when present.`);
      }
    }
    // Upper bound: Node timers clamp durations above 2^31-1 down to ~1ms — a
    // fail-closed but baffling instant kill — so an over-bound timeout is
    // rejected here where the author can see why.
    if (Object.hasOwn(entry, 'timeoutMs') && (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2147483647)) {
      throw new Error(`Engine check "${id}": timeoutMs must be a positive integer no greater than 2147483647 when present.`);
    }
    return {
      id,
      label: label ?? id,
      ...(hasCommand ? { command } : { packageCandidates: scriptsCopy }),
      baselineSafe: baselineSafe ?? false,
      generator: generator ?? false,
      ...(Object.hasOwn(entry, 'timeoutMs') ? { timeoutMs } : {}),
      engine: true,
    };
  });
};
```

Extend `module.exports` (~line 1674 region) with `validateEngineChecks` (alphabetical position).

- [ ] **Step 4: Run to verify green**

Run: `node --test --test-concurrency=1 scripts/pr_closeout_core.test.js`
Expected: all pass including the two new tests and every pre-existing one (the order-locked matrix test at the top of the file is untouched). `node --check scripts/pr_closeout_core.js` clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/pr_closeout_core.js scripts/pr_closeout_core.test.js
git commit -m "feat(closeout): fail-closed engine matrix validation"
```

(with the standard two trailers)

---

### Task 3: `buildCheckPlan` mode support — engine resolution, strict guard

**Files:**
- Modify: `scripts/pr_closeout_core.js` (`buildCheckPlan` ~lines 359-507)
- Test: `scripts/pr_closeout_core.test.js` (append)

- [ ] **Step 1: Write the failing tests**

Append to `scripts/pr_closeout_core.test.js`:

```js
test('strict mode rejects engine-only config keys as weakening attempts, never ignores them', () => {
  const withMatrix = buildCheckPlan({ config: { engineChecks: [{ id: 'a', command: 'x' }] } });
  assert.match(withMatrix.errors.join('\n'), /engineChecks is only valid with --mode engine/);
  const withRunner = buildCheckPlan({ config: { scriptRunner: 'npm run' } });
  assert.match(withRunner.errors.join('\n'), /scriptRunner is only valid with --mode engine/);
  // The strict matrix itself still resolves; the error rides alongside.
  assert.equal(withMatrix.checks.length, MANDATORY_CHECKS.length);
});

test('engine mode resolves inline commands and script discovery through the shared pipeline', () => {
  const plan = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [
        { id: 'unit', command: 'cargo test --workspace' },
        { id: 'lint', scripts: ['lint:ci', 'lint'] },
        { id: 'ghost', scripts: ['does-not-exist'] },
      ],
    },
    packageScripts: { lint: 'eslint .' },
  });
  assert.deepEqual(plan.errors, []);
  assert.deepEqual(plan.checks.map(({ id }) => id), ['unit', 'lint', 'ghost']);
  const unit = plan.checks.find(({ id }) => id === 'unit');
  assert.equal(unit.command, 'cargo test --workspace');
  assert.equal(unit.resolution, 'engine-command');
  assert.equal(unit.status, undefined);
  const lint = plan.checks.find(({ id }) => id === 'lint');
  assert.equal(lint.command, 'npm run lint');
  assert.equal(lint.resolution, 'package-script');
  const ghost = plan.checks.find(({ id }) => id === 'ghost');
  assert.equal(ghost.status, 'BLOCKED');
  assert.equal(ghost.resolution, 'unresolved');
});

test('engine mode never trusts user-supplied commands: placeholder, neutralizer, and make-recipe validation', () => {
  const plan = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [
        { id: 'todo', command: '<replace me>' },
        { id: 'hidden', command: 'npm test || true' },
        { id: 'uncaptured', command: 'make smoke' },
        { id: 'neutralized', command: 'make lie' },
      ],
    },
    makeRecipes: { lie: '-npm test' },
  });
  assert.equal(plan.checks.find(({ id }) => id === 'todo').status, 'BLOCKED');
  assert.match(plan.checks.find(({ id }) => id === 'todo').evidence, /placeholder/i);
  assert.equal(plan.checks.find(({ id }) => id === 'hidden').status, 'BLOCKED');
  assert.match(plan.checks.find(({ id }) => id === 'hidden').evidence, /neutralizes failures/);
  assert.equal(plan.checks.find(({ id }) => id === 'uncaptured').status, 'BLOCKED');
  assert.match(plan.checks.find(({ id }) => id === 'uncaptured').evidence, /No recipe text was captured/);
  assert.equal(plan.checks.find(({ id }) => id === 'neutralized').status, 'BLOCKED');
  assert.match(plan.checks.find(({ id }) => id === 'neutralized').evidence, /neutralizes failures/);
});

test('engine mode fails closed at the matrix level: invalid matrix or forbidden keys yield BLOCKED-empty plans', () => {
  const invalid = buildCheckPlan({ mode: 'engine', config: { engineChecks: [{ id: 'a' }] } });
  assert.deepEqual(invalid.checks, []);
  assert.match(invalid.errors.join('\n'), /exactly one of "command" or "scripts"/);
  const missing = buildCheckPlan({ mode: 'engine', config: {} });
  assert.deepEqual(missing.checks, []);
  assert.match(missing.errors.join('\n'), /non-empty array/);
  const withCommands = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'a', command: 'x' }], commands: { a: 'y' } },
  });
  assert.match(withCommands.errors.join('\n'), /config\.commands is not accepted in engine mode/);
  const badMode = buildCheckPlan({ mode: 'lenient' });
  assert.deepEqual(badMode.checks, []);
  assert.match(badMode.errors.join('\n'), /Unknown closeout mode/);
});

test('engine scriptRunner is validated and applied; strict package-script output is untouched', () => {
  const custom = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: 'pnpm run' },
    packageScripts: { lint: 'eslint .' },
  });
  assert.equal(custom.checks.find(({ id }) => id === 'lint').command, 'pnpm run lint');
  const neutralizing = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: 'npm run || true &&' },
    packageScripts: { lint: 'eslint .' },
  });
  assert.match(neutralizing.errors.join('\n'), /scriptRunner neutralizes failures/);
  const multiline = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], scriptRunner: 'npm\nrun' },
    packageScripts: { lint: 'eslint .' },
  });
  assert.match(multiline.errors.join('\n'), /single-line non-empty string/);
  // Strict path still emits pnpm run — byte-identical to today.
  const strict = buildCheckPlan({ packageScripts: { typecheck: 'tsc --noEmit' } });
  assert.equal(strict.checks.find(({ id }) => id === 'typecheck').command, 'pnpm run typecheck');
});

test('engine mode never consults a smuggled config.commands entry: the map is structurally dead, not just error-flagged', () => {
  const smuggled = buildCheckPlan({
    mode: 'engine',
    config: { engineChecks: [{ id: 'lint', scripts: ['lint'] }], commands: { lint: 'make lie' } },
    packageScripts: { lint: 'eslint .' },
  });
  assert.match(smuggled.errors.join('\n'), /config\.commands is not accepted in engine mode/);
  const lint = smuggled.checks.find(({ id }) => id === 'lint');
  assert.equal(lint.resolution, 'package-script');
  assert.equal(lint.command, 'npm run lint');
});

test('engine mode validates voluntarily attached proofs at plan time; strict proof behavior unchanged', () => {
  const badShape = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'artifact', path: '' } },
    },
  });
  assert.equal(badShape.checks.find(({ id }) => id === 'render').status, 'BLOCKED');
  assert.match(badShape.checks.find(({ id }) => id === 'render').evidence, /proof/i);
  const escaping = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'artifact', path: '../outside.json' } },
    },
  });
  assert.match(escaping.checks.find(({ id }) => id === 'render').evidence, /relative worktree path without ".."/);
  const good = buildCheckPlan({
    mode: 'engine',
    config: {
      engineChecks: [{ id: 'render', command: 'node render.js' }],
      proofs: { render: { type: 'artifact', path: 'artifacts/render.json' } },
    },
  });
  assert.equal(good.checks.find(({ id }) => id === 'render').status, undefined);
  assert.deepEqual(good.checks.find(({ id }) => id === 'render').proof, { type: 'artifact', path: 'artifacts/render.json' });
});
```

- [ ] **Step 2: Run to verify failures**

Run: `node --test --test-concurrency=1 scripts/pr_closeout_core.test.js`
Expected: the six new tests fail (buildCheckPlan has no `mode` parameter — engine configs resolve against MANDATORY_CHECKS and strict runs ignore engineChecks); every pre-existing test passes.

- [ ] **Step 3: Implement (surgical edits inside `buildCheckPlan`)**

1. Signature (~line 359): add `mode = 'strict'` as the FIRST destructured option, and make the `commands` capture on the next line mode-aware (post-review hardening — a scripts-resolved engine check must never be able to consult a smuggled `config.commands` entry through the configured branch, which lacks make-recipe inspection):

```js
const buildCheckPlan = ({ mode = 'strict', config = {}, packageScripts = {}, makeTargets = [], makeRecipes = {}, touchedFiles = [], mergeBaseSha } = {}) => {
  // Engine mode rejects config.commands below, but rejection alone leaves
  // the map live in the resolution loop, where a scripts-resolved engine
  // check could still consult a smuggled entry through the configured
  // branch (which lacks make-recipe inspection). Emptying the map in engine
  // mode makes that path structurally dead rather than relying on the
  // errors→FAIL rollup to keep it inert.
  const commands = mode === 'engine' ? {} : (config.commands || {});
```

2. Immediately after `const errors = [];` (~line 364), insert the mode gates:

```js
  // Unknown mode: fail closed with an empty plan rather than guessing a tier.
  if (mode !== 'strict' && mode !== 'engine') {
    return { checks: [], errors: [`Unknown closeout mode "${mode}". Use strict or engine.`] };
  }
  // Engine-only keys in a strict run are weakening attempts (someone trying
  // to swap the matrix or its script runner without saying --mode engine) —
  // named errors, never silently ignored keys.
  if (mode === 'strict') {
    if (Object.hasOwn(config, 'engineChecks')) {
      errors.push('config.engineChecks is only valid with --mode engine; a strict run never accepts a replacement matrix.');
    }
    if (Object.hasOwn(config, 'scriptRunner')) {
      errors.push('config.scriptRunner is only valid with --mode engine.');
    }
  }
  // Engine mode: the matrix is engineChecks, full stop. config.commands
  // coexisting with it would create a second command source and an override
  // ambiguity, so it is rejected outright.
  if (mode === 'engine' && Object.hasOwn(config, 'commands')) {
    errors.push('Engine mode defines commands inline in engineChecks; config.commands is not accepted in engine mode.');
  }
  // The script runner used for engine `scripts` discovery. Strict keeps its
  // hardcoded `pnpm run` (byte-identical output); engine defaults to the
  // ecosystem-neutral `npm run` and accepts an override that is itself
  // validated like any other command fragment.
  let scriptRunner = 'npm run';
  if (mode === 'engine' && Object.hasOwn(config, 'scriptRunner')) {
    if (typeof config.scriptRunner !== 'string' || !config.scriptRunner.trim() || /[\r\n]/.test(config.scriptRunner)) {
      errors.push('scriptRunner must be a single-line non-empty string.');
    } else {
      const runnerNeutralizer = findCommandFailureNeutralizer(config.scriptRunner);
      if (runnerNeutralizer) {
        errors.push(`scriptRunner neutralizes failures (${runnerNeutralizer}); closeout cannot admit a failure-hiding runner.`);
      } else {
        scriptRunner = config.scriptRunner.trim();
      }
    }
  }
  // Engine matrix validation converts throws into the errors channel so the
  // caller still gets a machine-readable BLOCKED plan (and the provisional
  // report path still works) instead of an exception.
  let definitions = MANDATORY_CHECKS;
  if (mode === 'engine') {
    try {
      definitions = validateEngineChecks(config.engineChecks);
    } catch (error) {
      return { checks: [], errors: [...errors, error.message] };
    }
  }
  const packageRunner = mode === 'engine' ? scriptRunner : 'pnpm run';
```

3. Change the map source (~line 377) from `MANDATORY_CHECKS.map((definition) => {` to `definitions.map((definition) => {`, and insert the engine-command branch as the FIRST branch inside the map callback, before the `if (definition.fixed) {` branch:

```js
    if (definition.engine && definition.command) {
      // Engine commands are user-supplied: apply the full distrust pipeline
      // the configured-command branch uses (placeholder, neutralizer) PLUS
      // the make-recipe inspection the fixed branch applies to `make`
      // invocations — an engine matrix must not be able to smuggle a
      // failure-hiding recipe behind a clean-looking `make target`.
      const trimmed = definition.command.trim();
      if (/^(?:<[^>]+>|REPLACE(?:_|\b))/i.test(trimmed)) {
        return {
          ...definition,
          status: 'BLOCKED',
          resolution: 'engine-command',
          evidence: `Replace the example placeholder for ${definition.label}.`,
        };
      }
      const engineCommand = expand(trimmed);
      const engineNeutralizer = findCommandFailureNeutralizer(engineCommand);
      if (engineNeutralizer) {
        return {
          ...definition,
          command: engineCommand,
          status: 'BLOCKED',
          resolution: 'engine-command',
          evidence: `Engine command for ${definition.label} neutralizes failures (${engineNeutralizer}); closeout cannot admit a failure-hiding command.`,
        };
      }
      const engineMakeTarget = /^make\s+(\S+)$/.exec(trimmed)?.[1];
      if (engineMakeTarget) {
        if (!Object.hasOwn(makeRecipes, engineMakeTarget)) {
          return {
            ...definition,
            command: engineCommand,
            status: 'BLOCKED',
            resolution: 'engine-command',
            evidence: `No recipe text was captured for make target "${engineMakeTarget}" (${definition.label}); closeout cannot trust an uninspected recipe.`,
          };
        }
        const engineRecipeNeutralizer = findMakeRecipeNeutralizer(makeRecipes[engineMakeTarget]);
        if (engineRecipeNeutralizer) {
          return {
            ...definition,
            command: engineCommand,
            status: 'BLOCKED',
            resolution: 'engine-command',
            evidence: `Make recipe for ${definition.label} neutralizes failures (${engineRecipeNeutralizer}); closeout cannot admit a failure-hiding recipe.`,
          };
        }
      }
      return { ...definition, command: engineCommand, resolution: 'engine-command' };
    }
```

4. In the package-script branch (~lines 446-464), replace both `` `pnpm run ${packageScript}` `` occurrences with `` `${packageRunner} ${packageScript}` `` (there are two: the neutralizer-BLOCKED return and the clean return). Strict output is unchanged because `packageRunner` is `'pnpm run'` in strict mode.
5. In the second-pass map (~lines 507-527), extend the proof handling: after the existing `if (proofType && !validArtifact && !validCommand) { ... }` block, add the engine-only validation for voluntarily attached proofs (checks with no REQUIRED_PROOFS entry). It must reuse the SAME artifact-path rules the `validArtifact` branch applies (the block at ~lines 529-537):

```js
    // Engine mode: a voluntarily attached proof (no REQUIRED_PROOFS entry
    // exists for engine ids) is still validated at plan time — a malformed
    // proof must block admission here exactly like a required one, not fail
    // later inside the executor. Strict behavior is untouched: strict checks
    // only ever carry proofs through the proofType path above.
    if (mode === 'engine' && proof && !proofType) {
      const engineArtifact = proof?.type === 'artifact'
        && typeof proof.path === 'string' && proof.path.trim();
      const engineCommandProof = proof?.type === 'command'
        && typeof proof.command === 'string' && proof.command.trim()
        && typeof proof.expectedPattern === 'string' && proof.expectedPattern.trim();
      if (!engineArtifact && !engineCommandProof) {
        const proofEvidence = `Configured proof for ${check.label} is malformed; engine proofs must be a complete artifact or command proof.`;
        resolved = resolved.status === 'BLOCKED'
          ? { ...resolved, evidence: `${resolved.evidence} ${proofEvidence}` }
          : { ...resolved, status: 'BLOCKED', evidence: proofEvidence };
      } else if (engineArtifact) {
        const rel = String(proof.path).replaceAll('\\', '/').trim();
        if (path.isAbsolute(proof.path) || rel.startsWith('/') || /^[A-Za-z]:\//.test(rel)
          || rel.split('/').includes('..') || rel.startsWith('../')) {
          const proofEvidence = `Artifact proof path must be a relative worktree path without "..": ${proof.path}`;
          resolved = resolved.status === 'BLOCKED'
            ? { ...resolved, evidence: `${resolved.evidence} ${proofEvidence}` }
            : { ...resolved, status: 'BLOCKED', evidence: proofEvidence };
        }
      }
    }
```

NOTE: the second-pass map callback must have `mode` in scope — it is defined in `buildCheckPlan`'s closure, so no signature change is needed there. Verify the variable names in the second pass match the file (`resolved`, `proof`, `proofType`, `check`) — they are quoted here from the current source at ~lines 507-527.

- [ ] **Step 4: Run to verify green**

Run: `node --test --test-concurrency=1 scripts/pr_closeout_core.test.js`
Expected: all pass — the six new tests AND every pre-existing test (the strict path is byte-identical: same matrix source object, same `pnpm run` literal output, no new errors for engine-free configs). `node --check scripts/pr_closeout_core.js` clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/pr_closeout_core.js scripts/pr_closeout_core.test.js
git commit -m "feat(closeout): buildCheckPlan engine mode — shared distrust pipeline, strict guard"
```

(with the standard two trailers)

---

### Task 4: Workflow threading — mode-bound digest, engine timeouts, plan `mode`

**Files:**
- Modify: `scripts/pr_closeout_workflow.js` (body ~952-1043; exports)
- Test: `scripts/pr_closeout_workflow.test.js` (append)

- [ ] **Step 1: Write the failing tests**

Append to `scripts/pr_closeout_workflow.test.js`. NOTE: model fixture plumbing on the file's existing planOnly tests — the assertions below are the contract; the injected dependency set (`resolveRepositoryState`, `readProjectMetadata`, `digestValidationConfig`) mirrors what the file already injects for plan-mode tests. Add `mergeEngineTimeouts` to the destructured require from `./pr_closeout_workflow`.

```js
const planDeps = (digests) => ({
  resolveRepositoryState: async ({ repo, baseRef }) => ({
    repo, baseRef, baseSha: 'basesha000', headSha: 'headsha000', mergeBaseSha: 'mergebase000', touchedFiles: [],
  }),
  readProjectMetadata: async () => ({ packageScripts: {}, makeTargets: [], makeRecipes: {} }),
  digestValidationConfig: (value) => {
    digests.push(value);
    return `digest-${digests.length}`;
  },
});

test('the validation-config digest binds the mode (schemaVersion 3)', async () => {
  const digests = [];
  await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, config: {},
    dependencies: planDeps(digests),
  });
  await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, mode: 'engine',
    config: { engineChecks: [{ id: 'unit', command: 'cargo test' }] },
    dependencies: planDeps(digests),
  });
  assert.equal(digests[0].schemaVersion, 3);
  assert.equal(digests[0].mode, 'strict');
  assert.equal(digests[1].mode, 'engine');
});

test('strict and engine digests differ even for identical config bytes, and a matrix edit changes the engine digest', async () => {
  const { digestValidationConfig } = require('./pr_closeout_git');
  const realDeps = () => ({
    resolveRepositoryState: async ({ repo, baseRef }) => ({
      repo, baseRef, baseSha: 'basesha000', headSha: 'headsha000', mergeBaseSha: 'mergebase000', touchedFiles: [],
    }),
    readProjectMetadata: async () => ({ packageScripts: {}, makeTargets: [], makeRecipes: {} }),
    digestValidationConfig,
  });
  const strictPlan = await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, config: {}, dependencies: realDeps(),
  });
  const enginePlan = await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, mode: 'engine',
    config: { engineChecks: [{ id: 'unit', command: 'cargo test' }] }, dependencies: realDeps(),
  });
  const editedPlan = await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, mode: 'engine',
    config: { engineChecks: [{ id: 'unit', command: 'cargo test --all' }] }, dependencies: realDeps(),
  });
  assert.notEqual(strictPlan.configDigest, enginePlan.configDigest);
  assert.notEqual(enginePlan.configDigest, editedPlan.configDigest);
  assert.equal(strictPlan.mode, 'strict');
  assert.equal(enginePlan.mode, 'engine');
});

test('mergeEngineTimeouts lets inline engine timeouts win over config.timeoutsMs', () => {
  assert.deepEqual(
    mergeEngineTimeouts({ unit: 5000, lint: 7000 }, [
      { id: 'unit', timeoutMs: 9000 },
      { id: 'style' },
    ]),
    { unit: 9000, lint: 7000 },
  );
  assert.deepEqual(mergeEngineTimeouts(undefined, [{ id: 'a', timeoutMs: 100 }]), { a: 100 });
  assert.deepEqual(mergeEngineTimeouts({ a: 1 }, []), { a: 1 });
});
```

- [ ] **Step 2: Run to verify failures**

Run: `node --test --test-concurrency=1 scripts/pr_closeout_workflow.test.js`
Expected: the three new tests fail (digest input has schemaVersion 2 and no mode; plan output has no `mode`; `mergeEngineTimeouts` not exported). Pre-existing tests pass — EXCEPT any pre-existing test that pins the digest input's `schemaVersion: 2` or a literal digest value: if one exists, STOP and report it to the coordinator before touching it (expected outcome per spec: the digest input change is deliberate; the coordinator will rule on the specific test).

- [ ] **Step 3: Implement**

In `scripts/pr_closeout_workflow.js`:

1. `runCloseoutWorkflowBody`: pass `mode` into `buildCheckPlan` (~line 964): add `mode,` as the first property of its options object.
2. Digest input (~line 975): change to

```js
  const configDigest = d.digestValidationConfig({
    // schemaVersion 2 -> 3: the digest now binds the gate tier. Deliberate
    // one-time invalidation of outstanding attestations (spec: Migration
    // consequence) — a strict-minted attestation can never admit an engine
    // run because the digests can no longer collide across modes.
    schemaVersion: 3,
    mode,
    config: validationConfig,
    resolved: {
      baselineSetupCommand,
      checks: plan.checks.map((check) => ({
        id: check.id,
        command: check.command,
        resolution: check.resolution,
        qualificationSafe: check.qualificationSafe,
        resourceGroup: check.resourceGroup,
        baselineSafe: check.baselineSafe,
        generator: check.generator,
        proof: check.proof,
      })),
    },
  });
```

3. planOnly return (~line 1000): add `mode,` immediately after `execution: 'not-started',`.
4. New exported pure helper (place near the other small helpers, before `runCloseoutWorkflowBody`):

```js
/**
 * Merge per-check inline engine timeouts into the id-keyed timeoutsMs map
 * the command executor consumes. The engine matrix is authoritative for its
 * own checks, so an inline timeoutMs wins over a config.timeoutsMs entry for
 * the same id; ids without an inline value keep whatever config supplied.
 * @param {Record<string, number>|undefined} configTimeouts
 * @param {Array<{id: string, timeoutMs?: number}>} checks
 * @returns {Record<string, number>}
 */
const mergeEngineTimeouts = (configTimeouts, checks) => ({
  ...(configTimeouts || {}),
  ...Object.fromEntries(checks.filter((check) => check.timeoutMs).map((check) => [check.id, check.timeoutMs])),
});
```

5. Executor wiring (~line 1041): change `timeoutsMs: config.timeoutsMs,` to `timeoutsMs: mergeEngineTimeouts(config.timeoutsMs, mode === 'engine' ? plan.checks : []),`.
6. Export `mergeEngineTimeouts` from the module's exports.

- [ ] **Step 4: Run to verify green**

Run: `node --test --test-concurrency=1 scripts/pr_closeout_workflow.test.js`
Expected: all pass. `node --check scripts/pr_closeout_workflow.js` clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/pr_closeout_workflow.js scripts/pr_closeout_workflow.test.js
git commit -m "feat(closeout): mode-bound attestation digest, engine timeouts, plan mode field"
```

(with the standard two trailers)

---

### Task 5: Plan-mode `admission` block

**Files:**
- Modify: `scripts/pr_closeout_workflow.js` (planOnly branch ~999-1022; new helper; exports)
- Test: `scripts/pr_closeout_workflow.test.js` (append)

- [ ] **Step 1: Write the failing tests**

Append to `scripts/pr_closeout_workflow.test.js` (add `resolvePlanAdmission` to the destructured require):

```js
test('resolvePlanAdmission reports present, absent, and unavailable attestation states plus tree and preflight readiness', async () => {
  const base = {
    repo: '/r', baseSha: 'b1', headSha: 'h1', configDigest: 'd1',
    d: {
      readLiveGateAttestation: async () => ({ status: 'PASS', evidence: 'attested by reviewer' }),
      cleanTreeStatus: async () => ({ status: 'PASS', evidence: 'clean' }),
      runPreflight: async () => ({ status: 'PASS', checks: [], toolVersions: { git: '2.45' } }),
    },
  };
  const present = await resolvePlanAdmission(base);
  assert.equal(present.attestation.status, 'present');
  assert.equal(present.cleanTree.status, 'PASS');
  assert.equal(present.preflight.status, 'PASS');

  const absent = await resolvePlanAdmission({
    ...base,
    d: { ...base.d, readLiveGateAttestation: async () => ({ status: 'BLOCKED', evidence: 'no matching attestation' }) },
  });
  assert.equal(absent.attestation.status, 'absent');
  assert.match(absent.attestation.evidence, /no matching attestation/);

  const unavailable = await resolvePlanAdmission({
    ...base,
    d: {
      ...base.d,
      readLiveGateAttestation: async () => { throw new Error('gh: not logged in'); },
      runPreflight: async () => { throw new Error('probe crashed'); },
      cleanTreeStatus: async () => { throw new Error('git unavailable'); },
    },
  });
  assert.equal(unavailable.attestation.status, 'unavailable');
  assert.match(unavailable.attestation.evidence, /gh: not logged in/);
  assert.equal(unavailable.preflight.status, 'BLOCKED');
  assert.match(unavailable.preflight.evidence, /probe crashed/);
  assert.equal(unavailable.cleanTree.status, 'BLOCKED');
  assert.match(unavailable.cleanTree.evidence, /git unavailable/);
});

test('planOnly output carries the admission block', async () => {
  const plan = await runCloseoutWorkflow({
    repo: process.cwd(), baseRef: 'origin/main', planOnly: true, config: {},
    dependencies: {
      resolveRepositoryState: async ({ repo, baseRef }) => ({
        repo, baseRef, baseSha: 'basesha000', headSha: 'headsha000', mergeBaseSha: 'mergebase000', touchedFiles: [],
      }),
      readProjectMetadata: async () => ({ packageScripts: {}, makeTargets: [], makeRecipes: {} }),
      digestValidationConfig: () => 'digest-a',
      readLiveGateAttestation: async () => ({ status: 'BLOCKED', evidence: 'no matching attestation' }),
      cleanTreeStatus: async () => ({ status: 'PASS', evidence: 'clean' }),
      runPreflight: async () => ({ status: 'PASS', checks: [], toolVersions: {} }),
    },
  });
  assert.equal(plan.admission.attestation.status, 'absent');
  assert.equal(plan.admission.cleanTree.status, 'PASS');
  assert.equal(plan.admission.preflight.status, 'PASS');
});
```

- [ ] **Step 2: Run to verify failures**

Run: `node --test --test-concurrency=1 scripts/pr_closeout_workflow.test.js`
Expected: both new tests fail (`resolvePlanAdmission` not exported; plan output has no `admission`). Pre-existing tests pass — NOTE: if any pre-existing planOnly test injects NO `readLiveGateAttestation`/`cleanTreeStatus`/`runPreflight` fake and starts failing because the real dependencies now run in plan mode, that is a real behavioral conflict: resolve it by having `resolvePlanAdmission` catch those failures into `unavailable`/`BLOCKED` states (the design below already does — plan mode must never throw because gh or git probes fail). Do not modify the pre-existing test.

- [ ] **Step 3: Implement**

In `scripts/pr_closeout_workflow.js`, add near the other helpers (before `runCloseoutWorkflowBody`):

```js
/**
 * Read-only admission readiness for plan mode: WHY would the full gate block
 * right now? Consumed by the Action's push-time preview (sub-project B) so an
 * ordinary push gets an honest "attestation absent / gh unavailable / tree
 * dirty" answer without paying for the full gate. Every probe failure is
 * caught into a structured state — plan mode must never throw because gh is
 * unauthenticated or a probe crashed; that is precisely what it exists to
 * report. The attestation predicate mirrors the full run's admission
 * (`initialAttestation.status === 'PASS'` — see attestationAdmitted below).
 * @param {{repo: string, baseSha: string, headSha: string, configDigest: string, config?: object, d: object}} options
 * @returns {Promise<{attestation: object, cleanTree: object, preflight: object}>}
 */
const resolvePlanAdmission = async ({ repo, baseSha, headSha, configDigest, config = {}, d }) => {
  let attestation;
  try {
    const live = await d.readLiveGateAttestation({
      repo,
      expectedBaseSha: baseSha,
      expectedHeadSha: headSha,
      expectedConfigDigest: configDigest,
    });
    attestation = live?.status === 'PASS'
      ? { status: 'present', evidence: live.evidence }
      : { status: 'absent', evidence: live?.evidence || 'No live attestation matches the current base, head, and config digest.' };
  } catch (error) {
    attestation = { status: 'unavailable', evidence: `Attestation lookup failed: ${error.message}` };
  }
  let cleanTree;
  try {
    cleanTree = await d.cleanTreeStatus(repo);
  } catch (error) {
    cleanTree = { status: 'BLOCKED', evidence: `Working tree inspection failed: ${error.message}` };
  }
  let preflight;
  try {
    preflight = await d.runPreflight({ repo, config, env: process.env });
  } catch (error) {
    preflight = { status: 'BLOCKED', evidence: `Preflight probe failed: ${error.message}` };
  }
  return { attestation, cleanTree, preflight };
};
```

NOTE: before wiring, confirm with a bounded read how the full-run path invokes `d.runPreflight` (~line 1089: `d.runPreflight({ repo: initial.repo, config, env: childEnv })`) and mirror that argument shape; plan mode passes `process.env` because `childEnv` is built only on the full-run path — the preflight only probes tool presence/versions, and building the full child environment in plan mode would be work plan mode exists to avoid.

In the planOnly branch (~line 999), compute and include the block:

```js
  if (planOnly) {
    const admission = await resolvePlanAdmission({
      repo: initial.repo,
      baseSha: initial.baseSha,
      headSha: initial.headSha,
      configDigest,
      config,
      d,
    });
    return redactStructure({
      execution: 'not-started',
      mode,
      admission,
      ...
```

(keep every existing field of the returned object exactly as it is today — only `mode` and `admission` are added). Export `resolvePlanAdmission`.

- [ ] **Step 4: Run to verify green**

Run: `node --test --test-concurrency=1 scripts/pr_closeout_workflow.test.js`
Expected: all pass, including Task 4's tests (their planDeps fixtures don't inject the three admission dependencies — the DEFAULTS versions run and are caught into structured states, or the injected fakes cover them; if a Task 4 test now hits a real `gh` call, extend THAT test's `planDeps` (it is new in this branch, not pre-existing) with the three fakes from the planOnly test above). `node --check` clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/pr_closeout_workflow.js scripts/pr_closeout_workflow.test.js
git commit -m "feat(closeout): plan-mode admission readiness block"
```

(with the standard two trailers)

---

### Task 6: Report labeling — `mode` field, engine banner

**Files:**
- Modify: `scripts/pr_closeout_workflow.js` (report assembly ~1361-1374; provisional report — grep `PROVISIONAL` / the forced-BLOCKED report write ~907-914)
- Modify: `scripts/pr_closeout_report.js` (markdown summary list ~line 186 region)
- Test: `scripts/pr_closeout_report.test.js` (append), `scripts/pr_closeout_workflow.test.js` (append)

- [ ] **Step 1: Write the failing tests**

Append to `scripts/pr_closeout_report.test.js` (NOTE: mirror the file's existing pattern for building a minimal report object and rendering markdown — it feeds report objects to the exported renderer; reuse whatever minimal fixture helper its existing tests use and extend it with the new fields):

```js
test('markdown renders the mode line in both modes and the engine banner only in engine mode', () => {
  const strictReport = hostileReport();
  strictReport.mode = 'strict';
  strictReport.matrixSource = null;
  const strictMarkdown = renderMarkdown(strictReport);
  assert.match(strictMarkdown, /- Mode: strict/);
  assert.doesNotMatch(strictMarkdown, /ENGINE MODE/);

  const engineReport = hostileReport();
  engineReport.mode = 'engine';
  engineReport.matrixSource = { source: 'config.engineChecks', digest: 'engine-digest-1', checkCount: 3 };
  const engineMarkdown = renderMarkdown(engineReport);
  assert.match(engineMarkdown, /- Mode: engine/);
  assert.match(engineMarkdown, /ENGINE MODE/);
  assert.match(engineMarkdown, /repo-defined check matrix/);
  assert.match(engineMarkdown, /different, weaker guarantee than the strict 19-check gate/);
  assert.match(engineMarkdown, /engine-digest-1/);
  assert.match(engineMarkdown, /3 checks/);
});
```

(`hostileReport()` is the file's existing report-fixture builder and `renderMarkdown` its existing renderer export — both already in the file; extend the top require only if `renderMarkdown` is somehow absent from it, which it is not as of `97676da`.)

Append to `scripts/pr_closeout_workflow.test.js` TWO tests. First, a field-presence test cloned from the file's cheapest existing full-run fixture asserting `report.mode === 'strict'` and `report.matrixSource === null` on a strict run. Second — this is spec test-group 3's core case — an engine-mode full-run test cloned from an existing full-run fixture (reuse its injected `execute`/dependency fakes wholesale) with: `mode: 'engine'`, a config of `{ engineChecks: [{ id: 'unit', command: 'echo ok' }] }` (adjust the command to whatever the fixture's fake executor accepts), and the injected `scanTouchedSuppressions` returning one finding — assert the run's `overallStatus` is `FAIL` (suppression auto-FAIL overrides an all-green custom matrix) and `report.mode === 'engine'`. If the existing full-run fixtures resist a clone (they are substantial), report BLOCKED with what you found rather than weakening the assertion — this test is a spec requirement, not an optional nicety. Do not modify any pre-existing test.

- [ ] **Step 2: Run to verify failures**

Run: `node --test --test-concurrency=1 scripts/pr_closeout_report.test.js scripts/pr_closeout_workflow.test.js`
Expected: new tests fail (no mode line, no banner, no mode field); pre-existing pass.

- [ ] **Step 3: Implement**

1. `scripts/pr_closeout_workflow.js` report assembly (~1361): after `configDigest,` add:

```js
    mode,
    // Engine runs name their matrix provenance so a reader of report.json can
    // never mistake a repo-defined matrix for the strict 19-check gate.
    matrixSource: mode === 'engine'
      ? { source: 'config.engineChecks', digest: configDigest, checkCount: plan.checks.length }
      : null,
```

2. Locate the provisional forced-BLOCKED report assembly (grep `provisional` case-insensitively in `pr_closeout_workflow.js`, ~907-914 region) and add the same two fields there, so a crashed run's report still names its tier.
3. `scripts/pr_closeout_report.js` (~line 186 region — the markdown summary list array containing `- Configuration digest: ...`): add immediately after the configuration-digest entry:

```js
    `- Mode: ${safeText(report.mode || 'strict')}`,
    ...(report.mode === 'engine' ? [
      '',
      '> **ENGINE MODE** — this run used a repo-defined check matrix '
        + `(${Number(report.matrixSource?.checkCount) || 0} checks from ${safeText(report.matrixSource?.source || 'config.engineChecks')}, `
        + `digest ${safeText(report.matrixSource?.digest || 'unresolved')}). `
        + 'This is a different, weaker guarantee than the strict 19-check gate.',
    ] : []),
```

NOTE: match the file's actual array/string-building idiom at that site (it is a flat array of markdown lines around line 186; splice accordingly and keep `safeText` — it is the file's existing sanitizer).

- [ ] **Step 4: Run to verify green**

Run: `node --test --test-concurrency=1 scripts/pr_closeout_report.test.js scripts/pr_closeout_workflow.test.js`
Expected: all pass. `node --check` on both modified files clean.

- [ ] **Step 5: Commit**

```bash
git add scripts/pr_closeout_workflow.js scripts/pr_closeout_report.js scripts/pr_closeout_report.test.js scripts/pr_closeout_workflow.test.js
git commit -m "feat(closeout): mode-labeled reports with engine banner"
```

(with the standard two trailers)

---

### Task 7: Full verification + review handoff

- [ ] **Step 1:** `npm test` — foreground, ONCE, 10-minute timeout; expect 0 fail (pre-existing skips OK). The strict-invariance claim is proven here: every pre-existing closeout test passes unmodified.
- [ ] **Step 2:** `git diff codex/publish-debug-skill...HEAD --stat` — confirm ONLY these files changed: `pr_closeout.js`, `pr_closeout_core.js`, `pr_closeout_workflow.js`, `pr_closeout_report.js`, their four test files, the spec, and this plan. `pr_closeout_process.js`, `pr_closeout_git.js`, `pr_closeout_github.js`, `pr_closeout_runner.js`, `debug_server.js`, and all evidence tools: zero lines.
- [ ] **Step 3:** `npm run validate` → PASS (payload file COUNT is unchanged — no new files; if it fails, something created a file this plan does not sanction). `npm run scan:suppressions` → no suppression findings; the gate-scan will print its BLOCKED advisory for validation-surface changes — expected and honest, report it verbatim.
- [ ] **Step 4:** Confirm test-file changes are append-only: `git diff codex/publish-debug-skill...HEAD -- scripts/pr_closeout_core.test.js scripts/pr_closeout_cli.test.js scripts/pr_closeout_workflow.test.js scripts/pr_closeout_report.test.js | grep '^-' | grep -v '^---'` must output nothing (no deleted lines) except require-line extensions; report any deletion honestly.
- [ ] **Step 5:** Report results to the coordinator; the final whole-implementation review follows via the coordinator's standing reviewer.

---

## Spec test-group traceability

| Spec test group | Where |
|---|---|
| 1. Strict invariance | Task 1 (default mode), Task 3 (engineChecks/scriptRunner rejected in strict, `pnpm run` output pinned), Task 6 (strict report fields), Task 7 (whole unmodified suite green) |
| 2. Engine matrix validation | Task 2 (schema), Task 3 (BLOCKED-empty plans, forbidden `commands`, distrust pipeline, scriptRunner) |
| 3. Invariant preservation | Task 6 (engine full-run: suppression ⇒ FAIL over a green custom matrix; provisional report carries mode). Qualification short-circuit, env allowlist, and output-dir checks are mode-independent code paths this plan does not touch — their existing tests, passing unmodified (Task 7), are the evidence; re-running them "under engine mode" would exercise identical code. |
| 4. Labeling | Task 6 (report `mode`/`matrixSource`, markdown banner, provisional report) |
| 5. Digest binding | Task 4 (mode in digest input, schemaVersion 3, strict≠engine digests, matrix edit changes digest). The spec's "named mode-mismatch error" is delivered mechanically: mode-crossed attestations can no longer digest-match, so admission rejects them through the existing digest-mismatch evidence, and the mode is visible in the plan admission block and report fields. Recorded as an execution decision to sync into the spec. |
| 6. Plan admission block | Task 5 (present/absent/unavailable attestation, cleanTree, preflight — all failure-proof) |
| 7. Regression battery | Task 7 |

Plan-level decisions to sync into the spec during execution (coordinator): `scriptRunner` config key (engine-only, validated, default `npm run`); digest-mismatch as the mode-mismatch mechanism; inline `timeoutMs` winning over `config.timeoutsMs` for engine ids.
