# Closeout Gate Engine Mode — Design (Cycle 3, Sub-project A)

**Date:** 2026-08-07
**Status:** Approved (design dialogue in session; reuse model, trigger story, action shape,
and decomposition chosen by maintainer)
**Components:** `scripts/pr_closeout.js` (CLI), `scripts/pr_closeout_core.js` (matrix),
`scripts/pr_closeout_workflow.js` (labeling/admission), `scripts/pr_closeout_github.js`
(attestation digest), `scripts/pr_closeout_report.js` (report fields)
**Roadmap:** cycle 3, sub-project A — precedes sub-project B (composite GitHub Action +
workflows + docs). Branch: `feat/closeout-engine-mode` off `codex/publish-debug-skill`
(`97676da`).

## Problem

The 19-check closeout gate is deliberately application-specific: eight checks are
`fixed: true` (config override = hard error) and the rest discover stack-specific package
scripts. In an arbitrary repository the plan resolves to BLOCKED and confirmation never
runs — correct under the never-weaken ethos, but it means the forthcoming reusable GitHub
Action (sub-project B) could only ever serve repos matching the exact
pnpm/Prisma/Redis/Grafana/Make/Docker stack. The maintainer chose a **two-tier** reuse
model: the strict gate stays untouched as the default, and a clearly-labeled **engine
mode** ships the gate's integrity machinery with a repo-defined check matrix.

## Decisions already made (maintainer-approved)

- **Reuse model: two-tier.** `strict` (default) = today's gate, byte-for-byte. `engine` =
  repo-supplied matrix, explicitly labeled a *different, weaker guarantee* in reports and
  bound into the attestation digest.
- **Trigger story (consumed by B):** full gate runs on `pull_request_review` /
  `workflow_dispatch`; ordinary pushes get a cheap `--plan` preview including admission
  readiness. This sub-project adds the plan `admission` block that makes the preview honest.
- **Action shape (B):** composite action at this repo's root — one codebase, the Action
  version IS the gate version.
- **Decomposition: A then B, stacked.** This spec is A only.

## Mode mechanics

- New CLI flag `--mode strict|engine`, default `strict`. **Config may not set the mode** —
  the operator's invocation must say it, so a config file can never silently weaken a
  strict run. Unknown mode values are a hard error (exit 3 class).
- **Strict mode is byte-for-byte today's behavior.** Same `MANDATORY_CHECKS`, same
  `fixed: true` hard errors, same order-locked tests, no behavioral delta. The only
  additive change visible in strict runs is the new `mode: "strict"` field in reports.
- **Engine mode replaces the matrix wholesale** with `config.engineChecks` — there is no
  merging with, or selective inheritance from, the strict matrix (a hybrid would be
  neither guarantee). Strict's check ids are not reserved; an engine matrix may reuse a
  name, and the report labeling plus digest binding make the provenance unambiguous.

## Engine matrix schema (`config.engineChecks`)

An array of check objects validated fail-closed at plan time; any violation is a named
error and the run is BLOCKED before anything executes:

- `id` — non-empty string, unique across the array (duplicate/non-string/empty → error);
  charset-gated (`/^[A-Za-z0-9][A-Za-z0-9._-]*$/`) and rejected on `Object.prototype`
  member collisions, closing prototype-shaped and control-character ids at the gate
  instead of relying on downstream lookups failing closed by accident (review decision).
  Field reads are read-once (getter/Proxy entries cannot swap values between validation
  and emission), and `timeoutMs` is bounded to the 32-bit timer maximum (review
  decisions).
- Command source — exactly one of the shapes the strict matrix already uses: a fixed
  `command` (a single shell-command string, the same form every `fixed: true` strict
  check and the executor use) or a `scripts` discovery list (package.json script names
  tried in order). Both absent, or both present → error.
- Optional fields mirror strict semantics with the same validation: `timeoutMs` (inline
  value wins over a `config.timeoutsMs` entry for the same id — the matrix is
  authoritative for its own checks), `baselineSafe`, `generator`; `qualificationSafe` and
  `resourceGroup` continue to come from their existing id-keyed config maps, and proofs
  from `config.proofs` (validated at plan time in engine mode even when voluntary).
- `scripts` discovery runs through an engine-only `config.scriptRunner` (default
  `npm run`; validated single-line without tabs/quotes, neutralizer-scanned) — strict
  keeps its hardcoded `pnpm run` byte-for-byte. `scriptRunner` in a strict config is a
  hard error like `engineChecks`.
- **Engine-only `config.requiredTools` (review decision, Task 5):** an array of
  preflight probe names drawn from the existing probe catalog (`git`, `node`, `pnpm`,
  `make`, `docker`, `docker-compose`, `docker-daemon`, `prisma`). Engine-mode preflight
  probes exactly `git` + `node` (the gate's own dependencies) plus the declared names,
  deduplicated, in catalog order; strict runs keep the full hardcoded probe list
  byte-for-byte. A non-array value, a non-string entry, or a name outside the catalog is
  a named config error (fail-closed, never a silent skip), and `requiredTools` in a
  strict-mode config is a hard error naming the key — same class as `engineChecks` and
  `scriptRunner`. Rationale: strict's hardcoded pnpm/prisma/docker probes would block
  engine admission on every non-pnpm repo — the exact repos engine mode exists to
  serve — and an explicit declaration keeps the probe set operator-visible and
  digest-bound (it lives in config, so the existing digest binding covers it). It also
  removes the ~30s docker-daemon probe cost from `--plan` on repos that never declare
  docker. Implementation is sanctioned to touch `pr_closeout_process.js` in exactly one
  way: `runPreflight` gains an optional `toolProbes` parameter defaulting to the
  existing `TOOL_PROBES` table (strict callers pass nothing — zero strict delta), and
  the table joins the module's exports so the workflow can filter it by name — frozen,
  pairs included, so the catalog-only guarantee (configs supply probe NAMES, never
  probe COMMANDS) is structural rather than conventional (review decision, Task 5
  round 2). No other edit to that file is in scope. One accepted edge (review
  disposition, Task 5 round 2): when `requiredTools` itself is malformed, the plan
  admission preflight falls back to the full catalog while the plan reports FAIL —
  loud and fail-closed; the probe-cost saving simply does not apply on runs that are
  already doomed.
- **Resolved-command make gate (review decision):** recipe bodies are only inspectable
  when a command is EXACTLY `make <target>`. On every engine resolution path — inline
  commands AND scriptRunner-resolved scripts — the FINAL resolved command passes a make
  gate: the pure form gets its recipe inspected (uncaptured or failure-neutralizing
  recipes → BLOCKED), and any other command that invokes make (wrapped, prefixed,
  pathed, flagged, or argument-extended — `cd x && make lie`, `env make lie`,
  `/usr/bin/make lie`, `make -s lie`, `make lie && true`, quoted/substituted forms,
  and the platform aliases `gmake`/`bmake`/`pmake`/`nmake`/`mingw32-make`/
  `mingw64-make`/`make.exe`) is BLOCKED outright: an uninspectable make invocation is
  never admitted. The alias predicate is honestly a denylist — genuinely exotic
  wrappers cannot be enumerated; the gate blocks everything reachable by typing the
  obvious thing and does not claim completeness. Token-level basename matching leaves
  non-make commands (`cmake`, `make-docs`, `node make.js`) unaffected; a package
  script literally named `make` is blocked errs-safe with a rename hint. Strict
  definitions never pass through this gate (invariance).
- **Engine command proofs get strict parity at plan time (review decision):** a
  postcondition command proof is neutralizer-scanned and its `expectedPattern` must be
  a non-empty `literal:` policy — both enforced at admission, mirroring the strict path
  and the executor's policy rules, so an engine check can never carry a proof that
  cannot fail.
- Unknown fields → error (never ignored).
- Empty array, missing `engineChecks` in engine mode, or `engineChecks` present in a
  strict-mode config → error. The strict-mode rejection matters most: a config carrying an
  engine matrix into a strict run is someone trying to weaken the gate, and it fails
  loudly rather than being ignored.

## Integrity invariants engine mode may NOT relax

Enforced in code and pinned by tests — the engine IS these invariants:

1. Suppression findings are an automatic FAIL overriding everything.
2. Two-phase execution: bounded-parallel qualification over `qualificationSafe` checks,
   then strictly serial confirmation over the full matrix, only if qualification is clean.
3. A provisional forced-BLOCKED report is written before any check runs; a mid-run crash
   leaves an unambiguously incomplete report, never a false PASS.
4. Clean-working-tree admission and seal checks.
5. `--output-dir` must resolve outside the repository.
6. The environment allowlist (`ESSENTIAL_ENV` + explicit `requiredEnv`/`safeEnv`).
7. Live-PR verification and the independent head-SHA-bound attestation requirement.
8. Atomic report commit ordering with post-rename identity re-verification.
9. Fail-closed rollup: empty or unresolved anything ⇒ BLOCKED.

## Labeling

- `report.json`: new top-level `mode` field (`"strict"` | `"engine"`, present in both
  modes) and, in engine mode, a `matrixSource` block naming the config path/digest and the
  check count.
- `report.md`: engine reports render a banner section stating: repo-defined matrix, a
  different and weaker guarantee than the strict 19-check gate, with the matrix digest.
- Strict reports gain only the `mode` field — no banner, no other change.
- Renderer hardening (review decision, Task 6 round): one normalized mode value drives
  both the markdown label and the banner condition (matched case-insensitively), so no
  mode-value casing or coercion can render an engine label without its warning banner;
  and when `mode` is absent the renderer falls back to the `matrixSource` tell (non-null
  only on engine runs) rather than claiming strict — stripping one field from an engine
  `report.json` cannot upgrade its markdown to the stronger strict claim, while true
  legacy reports (neither field) still render strict. Reachable today only through the
  exported `renderMarkdown`; live the moment sub-project B re-renders stored reports.

## Attestation digest binding

The attestation line format stays `PR-CLOSEOUT-ATTESTATION v1 base=<sha> head=<sha>
config=<digest> decision=not-weakened`. The digest input now incorporates the **mode and
the resolved engine matrix**: the digested object gains a top-level `mode` field
(`'strict'` | `'engine'`) as its own discriminator — mode-crossed digests differ by
construction, with no sentinel/matrix collision risk — and the matrix content flows
through the existing `config` (which carries `engineChecks` verbatim) and
`resolved.checks` (the validated, resolved matrix) fields, so a matrix edit changes the
digest through both channels (implementation decision, recorded at Task 4 review).
Consequences, all deliberate:

- An attestation minted for a strict run can never admit an engine run, and vice versa —
  the mechanism is the digest itself (mode-crossed attestations can no longer
  digest-match, so admission rejects them through the existing digest-mismatch
  evidence), with the running mode visible in the plan admission block and report
  fields (execution decision).
- Any edit to the engine matrix invalidates outstanding attestations — including
  reordering it: confirmation executes the matrix strictly serially, so order is
  load-bearing and digested positionally, like any other matrix edit.
- Reviewers attesting an engine-mode PR are attesting a specific matrix, visible in the
  digest.
- **Migration consequence, deliberate:** because the digest input changes, any attestation
  minted before this change lands is invalidated once — reviewers re-attest the current
  head under the new digest. Stated here so the first post-upgrade BLOCKED reads as the
  designed behavior, not a regression.

## Plan-mode admission readiness

`--plan` output gains an `admission` block so B's push-time preview can honestly say *why*
the full gate would block without running it: attestation state for the current
head (and mode), `gh` availability/auth, toolchain preflight probe results, clean-tree
state. Probes are read-only; the block is additive to the existing plan output. All
GitHub interaction stays behind the injectable `runGh` seam so tests are hermetic.

Attestation state is a four-value vocabulary, not a boolean (review decision, Task 5):

- `present` — the live read returned PASS: a mode-matched attestation for this exact
  base/head/config-digest snapshot exists.
- `weakened` — the live read returned FAIL: an attestation matching this snapshot exists
  but records a weakened decision. Collapsing this into "absent" would hide an active
  weakening signal from B's push-time preview. Note (review, Task 5 round 2): today's
  reader emits only PASS/BLOCKED — a weakened review fails the `decision=not-weakened`
  marker match and lands in `absent` — so this state is defensive, kept for reader
  evolution; sub-project B should not build UI that depends on it firing.
- `absent` — the live read returned BLOCKED for a snapshot reason (no matching approving
  review, or the PR head/base has moved past the expected snapshot).
- `unavailable` — the read itself could not complete (gh missing, unauthenticated,
  network failure). `readLiveGateAttestation` never throws — its internal catch converts
  every error into BLOCKED — so this state needs a machine-readable discriminator: the
  catch-path return gains an additive `reason: 'unavailable'` field. This is a
  deliberate, spec-recorded strict-visible addition (same class as the report `mode`
  field); mapping MUST use the field, never prose-matching on evidence text. Injected
  readers that throw (test fakes) still map to `unavailable` via the admission helper's
  own catch.

## Error handling

| Case | Behavior |
|---|---|
| Unknown `--mode` value | error before any work, exit 3 class |
| `engineChecks` in config during a strict run | hard error naming the key — weakening attempt, never ignored |
| Engine mode without `engineChecks` | hard error |
| Engine matrix schema violation (dup/non-string id, both/neither command source, unknown field, empty array) | named error per violation; planStatus FAIL; admission FAIL; nothing executes |
| Attestation mode mismatch (strict-minted attestation at engine admission or vice versa) | named admission error; run BLOCKED |
| `requiredTools` not an array, non-string entry, or name outside the probe catalog | named config error; planStatus FAIL (same containment as engine matrix errors); nothing executes |
| `requiredTools` in a strict-mode config | hard error naming the key — same class as `engineChecks`/`scriptRunner` |
| Fixed-check override in strict mode | unchanged hard error (existing behavior, re-pinned) |

## Testing (repo requirements: `node --test --test-concurrency=1`, zero dependencies, hermetic — injected `runGh`/fs fakes, no network)

1. **Strict invariance:** entire existing closeout suite passes unmodified; new pins —
   default mode is strict; `engineChecks` present in a strict-mode config is a hard error;
   fixed-check override still throws; strict report carries `mode: "strict"`.
2. **Engine matrix validation, fail-closed:** duplicate ids, non-string/empty ids, empty
   array, unknown fields, both/neither command sources, malformed optional fields — each a
   named error; empty/unresolvable matrix ⇒ plan BLOCKED and confirmation never runs.
3. **Invariant preservation in engine mode:** a suppression finding ⇒ FAIL despite an
   all-green custom matrix; qualification failure short-circuits confirmation; the
   provisional report exists and reads BLOCKED when the run dies mid-flight (existing
   crash-report test pattern); in-repo `--output-dir` still throws; env allowlist still
   applied to engine-check subprocesses.
4. **Labeling:** `report.json` mode field in both modes; engine `matrixSource` block;
   `report.md` engine banner rendered; strict markdown unchanged except nothing (no
   banner).
5. **Digest binding:** identical config bytes produce different digests strict-vs-engine;
   an engine matrix edit changes the digest; a strict-minted attestation is rejected at
   engine-mode admission (and vice versa) with the named mode-mismatch error.
6. **Plan admission block:** attestation-missing, gh-unavailable, and dirty-tree shapes
   surface as structured fields in plan output via injected fakes; the four attestation
   states are distinguished end-to-end (PASS→present, FAIL→weakened,
   snapshot-BLOCKED→absent, reason-tagged catch path→unavailable) and the
   `reason: 'unavailable'` discriminator is pinned at the github reader's catch path;
   engine-mode preflight probes exactly git+node+declared `requiredTools`
   (probe-set assertion via an injected `runPreflight` capturing `toolProbes`), strict
   preflight passes no `toolProbes` and keeps the full catalog; unknown `requiredTools`
   names are a named error.
7. **Regression battery:** full suite 0 fail; `npm run validate` PASS;
   `npm run scan:suppressions` clean (the gate-scan will flag the validation-surface
   changes for PR-time independent review — by design, reported honestly).

## Non-goals

- No action.yml, workflows, or Action docs — that is sub-project B.
- No relaxation of any integrity invariant in either mode.
- No merging/inheritance between strict and engine matrices.
- No change to the attestation line format version (digest input changes; the `v1` frame
  and parser do not).
- No network access in any test.

## Success criteria

- Strict-mode behavior is provably unchanged: the pre-existing closeout suite passes
  without modification, and the only observable strict-run delta is the additive
  `mode` report field.
- Engine mode cannot run without an explicit operator flag, a valid matrix, and a
  mode-matched attestation — every failure path is a named, tested error.
- Reports and attestation digests make the tier unmistakable to both humans and machines.
- The plan `admission` block gives sub-project B everything its push-time preview needs.
