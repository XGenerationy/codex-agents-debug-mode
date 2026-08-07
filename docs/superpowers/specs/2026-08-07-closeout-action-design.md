# Closeout Gate Composite Action — Design (Cycle 3, Sub-project B)

Packages the PR closeout gate as a reusable composite GitHub Action so any repo can
enforce it in CI, on top of sub-project A's engine mode (merged as `0a2ddd1`). Touches
`actions/closeout/` (new: `action.yml`, `support.js`, `support.test.js`, `README.md`),
`.github/workflows/` (two new dogfood workflows), `tools/workflow_checks.js` (new,
with tests) wired into `tools/validate_repository.js`, and README pointers. The
`pr_closeout_*` gate scripts themselves are NOT modified by this sub-project.

Location decision (plan-time amendment): the support script lives at
`actions/closeout/support.js`, NOT under `scripts/` — the validator's payload census
ships everything under `scripts/` with the skill, and the action support is CI
tooling, exactly the "repository governance and CI files" the README says are not
copied into the skill directory. The skill payload count therefore stays 37. The
tracked-file census still puts the new files through the safety scan and `node
--check` automatically, and `node --test` discovers `actions/closeout/support.test.js`
without any script change.

## Problem

Sub-project A made the gate's integrity engine reusable (`--mode engine`), but a
consumer still has to hand-write CI: check out with full history, set up Node, install
gh auth, invoke the CLI with the right flags, interpret three exit codes, and surface
evidence somewhere reviewable. Every consumer would re-derive the same workflow — and
most would get the failure semantics wrong (a preview that hard-fails before any review
exists, or a gate that swallows evidence when it fails).

## Decisions already made (maintainer-approved)

- Composite action, in this repo (not a separate repo, not Docker).
- Triggers: review-triggered full gate + cheap `--plan` preview on ordinary PR pushes.
- Two-tier reuse: strict default untouched; engine mode explicitly labeled.
- Action lives at `actions/closeout/` — consumers write
  `uses: XGenerationy/codex-agents-debug-mode/actions/closeout@<ref>`. The repo's
  skill/collector identity stays primary; future actions get sibling directories.
- Preview surfaces: Step Summary + evidence artifact always; PR comment strictly
  opt-in (`pr-comment: true`) because it needs `pull-requests: write`.
- This repo dogfoods the action with live workflows; those files are the canonical
  examples the README embeds.

## Action interface (`actions/closeout/action.yml`)

Composite action; every step's logic lives in `actions/closeout/support.js`
(reachable as `${{ github.action_path }}/support.js`; the gate CLI as
`${{ github.action_path }}/../../scripts/pr_closeout.js`) so it is hermetically
testable. The YAML contains wiring only.

Inputs (all strings, validated fail-closed by the support script BEFORE the gate CLI is
spawned — unknown values are a named error, never a silent default):

| Input | Values | Default | Meaning |
|---|---|---|---|
| `run` | `plan` \| `full` | `plan` | Preview tier vs enforcing gate. Safe default is the read-only tier. |
| `mode` | `strict` \| `engine` | `strict` | Forwarded verbatim as `--mode`. The CLI re-validates — the action never widens what the CLI accepts. |
| `base-ref` | ref | empty | Live PR base ref for `--base-ref`. An explicit value is passed to the CLI VERBATIM — no `origin/` prefixing; the operator's value is authoritative. When empty, the support script resolves fail-closed down a ladder: `origin/$GITHUB_BASE_REF` (pull_request events) → `origin/<event.pull_request.base.ref>` from the event payload (pull_request_review events) → nothing, in which case the CLI's own `config.baseRef`-or-error contract applies. The automatic branches prefix `origin/` because env/event carry bare branch names; consumers must therefore check out with `fetch-depth: 0` (full history) or `origin/<branch>` does not exist and the gate errors — a stated consumer requirement, not an assumption (README §9). The resolved value is recorded in the Step Summary. |
| `config` | path | empty | Optional closeout config path, forwarded when non-empty. |
| `output-dir` | path | `${{ runner.temp }}/closeout-evidence` | Evidence directory. Default satisfies the gate's outside-the-repository requirement. |
| `node-version` | version spec | `24` | Passed to SHA-pinned `actions/setup-node` inside the composite. |
| `pr-comment` | `true` \| `false` | `false` | Opt-in preview comment (documented as requiring `pull-requests: write`). |
| `artifact-name` | string | `closeout-evidence` | Evidence artifact name. |

Outputs (written to `GITHUB_OUTPUT` by the support script; machine consumers key on
these fields, never on evidence prose — consumer contract from A's final review):

| Output | Content |
|---|---|
| `status` | `run: full` → the report's `overallStatus`; `run: plan` → `planStatus`. |
| `mode` | The run's mode as reported by the gate (`report.mode` / plan `mode`). |
| `attestation` | Plan runs: the four-state `admission.attestation.status` (`present` / `weakened` / `absent` / `unavailable`). Full runs: empty. |
| `report-path` | Absolute path of `report.json` (full) or the captured plan JSON file (plan). |

Composite step sequence:

1. SHA-pinned `actions/setup-node` with `node-version`.
2. `node <support> run` — validates inputs, spawns
   `node <gate>/scripts/pr_closeout.js` with the mapped flags and
   `GH_TOKEN: ${{ github.token }}` in env, captures the single-line JSON stdout and
   exit code, writes outputs, writes the Step Summary, persists the captured plan JSON
   into `output-dir` (plan runs), and records the exit decision for step 4.
3. SHA-pinned `actions/upload-artifact` uploading `output-dir` as `artifact-name`
   (`if: always()`, `if-no-files-found: ignore` — a crashed run may still have the
   provisional report; an empty dir is not itself an error).
4. Optional `node <support> comment` step (`if: always()` + `pr-comment == 'true'`):
   upserts a marker-tagged PR comment via `gh api` when the event carries PR context;
   outside PR context it emits a notice and succeeds (skip, never fail). Runs BEFORE
   the exit step so a failing gate still gets its comment. Plan runs comment the plan
   summary; full runs comment the key-fields block plus an artifact pointer — never
   the embedded `report.md` (comment cap is 60 KiB).
5. `node <support> finish` — applies the exit decision table (below) so the job fails
   only after evidence has been surfaced everywhere. Runs with `if: always()`.

## Failure semantics (exit decision table)

The two tiers fail differently by design:

| Tier | CLI outcome | Job result |
|---|---|---|
| `run: full` | exit 0 | success |
| `run: full` | exit 2 (FAIL) or 3 (BLOCKED) | **job fails with the same class**, after summary + artifact are written |
| `run: plan` | a parseable single-line plan JSON was captured (any exit code) | success — even when `planStatus` is FAIL or admission says `absent`/`unavailable`; pre-review "not ready yet" is the preview's normal honest state, and a preview that goes red before anyone could review trains people to ignore it. The exit code is deliberately not consulted: A's CLI emits a structured JSON line even on blocked runs, the action's own input validation has already excluded flag-misuse before spawning, and remaining config-level errors land honestly in `planStatus` |
| `run: plan` | no parseable single-line JSON on stdout | job fails — the preview itself is broken, which must be loud |
| either | input validation failure (unknown `run`/`mode`/`pr-comment` value) | job fails before the CLI is spawned, named error |

The readiness signal for plan runs lives in the Step Summary and the `status` /
`attestation` outputs, not in the job's color.

Defense in depth (review decision, Task 1 round): the exit-decision function itself
fails CLOSED on any tier value that is not exactly `plan` or `full` — input
validation normally makes that unreachable, but an unvalidated value must never fall
into the more permissive plan branch and report success for a failing full gate. The
JSON-line parser likewise rejects any record carrying an own `__proto__` key
(the gate never emits one; such a record is hostile or garbled, and would hijack the
prototype of a later `Object.assign`-style copy).

## Step Summary and PR comment rendering

- Plan runs: a summary table — mode, planStatus, config digest, and the admission
  block (attestation state, clean-tree, preflight statuses with first-line evidence).
  All four attestation states render distinctly; `weakened` renders as a warning row
  (it is defensive-only today — recorded in A's spec — but if it ever fires it must
  not look like `absent`).
- Full runs: key fields (overallStatus, mode, digest, engine banner presence) plus the
  gate-written `report.md` embedded verbatim below a divider, capped at 512 KiB (the
  Step Summary hard limit is 1 MiB); when capped, the truncation is announced in the
  summary itself with a pointer to the artifact. B embeds the gate's own `report.md` —
  it does NOT re-render `report.json` through `renderMarkdown`, so the re-render
  contract stays unexercised (updates A's consumer note 4: B is not that first caller).
- Escaping (review decision, Task 1 round): every evidence-derived string that the
  support script itself interpolates into markdown passes through `escapeActionText`,
  which is the EXACT `safeText` transform from `pr_closeout_report.js` — newline
  collapse to the visible return mark, then numeric-entity escape of every character
  outside the allowlist `[A-Za-z0-9 ._⏎-]`, control bytes included. A partial
  markdown-denylist claiming safeText parity was rejected in review (strikethrough
  tildes, tilde fences, and GFM-autolinked URLs rendered active through it). Accepted
  residuals, identical to the gate's own reports and documented in code: allowlisted
  `_`/`.`/`-` keep their rare markdown meanings; a bare www.-prefixed word can still
  autolink. Tests pin hostile payloads (forged headings, blockquotes, pipes,
  strikethrough, URLs, control bytes). The embedded `report.md` is exempt — it was
  already rendered through the gate's own `safeText` pipeline and re-escaping would
  corrupt it.
- PR comment (opt-in): same content as the plan summary, prefixed with an HTML marker
  comment (`<!-- closeout-preview -->` + repo/PR identifiers) enabling upsert-in-place
  via `gh api` (find comment carrying the marker → PATCH, else POST). Comment bodies
  are capped at 60 KiB with the same truncation honesty.

## Dogfood workflows (house style: SHA-pinned `uses`, `permissions` block, concurrency group, `fetch-depth: 0`)

- `.github/workflows/closeout-preview.yml` — `on: pull_request` + `workflow_dispatch`.
  `permissions: contents: read, pull-requests: read` (gh needs PR read for the
  admission attestation lookup). Steps: checkout (full history), then
  `uses: ./actions/closeout` with `run: plan`. No comment (this repo reads summaries).
- `.github/workflows/closeout-gate.yml` — `on: pull_request_review` (types:
  `submitted`) + `workflow_dispatch`. Same permissions. Checks out the PR head
  explicitly (`ref: ${{ github.event.pull_request.head.sha }}`, `fetch-depth: 0`) —
  the gate independently re-verifies the live head via gh and BLOCKS stale snapshots,
  but the checkout must present the head being attested. Runs `run: full`. Concurrency
  group keyed per PR so a re-review supersedes an in-flight run.
- Fork-PR honesty note (README + workflow comments): `pull_request` from forks gets a
  read-only token — the preview works (it is read-only by design); the comment opt-in
  does not, and is skipped with a notice. `pull_request_review` runs in base-repo
  context with normal token scope.

## Support script (`actions/closeout/support.js`)

Zero dependencies, same license/header conventions as sibling scripts. Subcommands
`run`, `finish`, `comment`; all state between steps flows through files in
`output-dir` and `GITHUB_OUTPUT`/`GITHUB_STEP_SUMMARY`/`GITHUB_ENV` append files —
every path injectable via env for hermetic tests (tests point them at temp files; no
network, no real gh: the gh invocation seam is an injectable `runGh` like the gate's
own tests use). Pure functions exported for direct testing: `validateActionInputs`,
`decideExit`, `renderPlanSummary`, `renderFullSummary`, `buildCommentBody`,
`escapeActionText`, `writeOutputs`. Output values are sanitized to single lines
before writing, so `GITHUB_OUTPUT` uses only the plain `name=value` form — no
multiline heredoc delimiters, no delimiter-collision surface at all.

## Validator additions (`tools/validate_repository.js`)

Two new zero-dependency, regex-level checks over tracked files (no YAML parser — the
checks are deliberately shallow and honest about it):

1. **SHA-pin check:** every `uses:` line in `.github/workflows/*.yml` and
   `actions/**/action.yml` must reference a 40-hex commit SHA (`@<40-hex>`) — except
   local path references (`uses: ./...`), which are same-repo by construction.
2. **Permissions check:** every workflow file must contain a top-level `permissions:`
   block.

The two predicates live in a new `tools/workflow_checks.js` module (the validator
requires it; a sibling test file covers the predicates hermetically plus one
integration spawn of the real validator expecting PASS — same pattern as
`tools/scan_touched_suppressions.test.js`). The skill payload count stays 37: no new
file enters the payload roots. The gate-scan will flag the validation-surface change
for independent PR review — expected and honest, as always.

## Error handling

| Case | Behavior |
|---|---|
| Unknown `run` / `mode` / `pr-comment` input value | named error, job fails before the CLI is spawned |
| Gate CLI exit 2/3 on `run: full` | summary + artifact first, then job fails with the same class |
| Plan JSON missing/unparseable on `run: plan` | job fails — broken preview is loud |
| `pr-comment: true` outside PR context | notice + success (skip, never fail) |
| Comment upsert API failure | step fails with the gh error surfaced; summary/artifact already written |
| Step Summary / comment over size cap | truncated with an in-band truncation notice pointing at the artifact |
| Workflow file with unpinned `uses:` or missing `permissions:` | `npm run validate` FAIL |

## Testing (repo requirements: `node --test --test-concurrency=1`, zero dependencies, hermetic — injected `runGh`/env-path fakes, no network)

1. **Input validation, fail-closed:** every input validated; unknown `run`, `mode`,
   `pr-comment` values are named errors; defaults applied exactly as specified;
   nothing spawns on invalid input.
2. **Exit decision table:** all rows pinned — full 0/2/3 propagation, plan
   success-despite-FAIL-planStatus, plan failure on malformed/absent JSON and on CLI
   misuse class.
3. **Summary rendering:** plan summary renders all four attestation states
   distinctly (weakened ≠ absent); full summary embeds `report.md` verbatim, caps at
   512 KiB with in-band truncation notice; hostile evidence strings (forged headings,
   blockquotes, pipes, control bytes) neutralized by `escapeActionText`; the embedded
   gate-rendered `report.md` is not double-escaped.
4. **Comment body + upsert:** marker line present and stable; upsert chooses PATCH
   when a marker-tagged comment exists, POST otherwise (via injected `runGh`);
   non-PR context skips with notice; 60 KiB cap honored.
5. **Outputs:** `GITHUB_OUTPUT` writes are append-only, single-line-sanitized, and
   parse back exactly; `status`/`mode`/`attestation`/`report-path` populated per tier.
6. **Validator:** SHA-pin and permissions checks catch seeded violations (fixture
   strings, not real files); local `./` uses are exempt; the repo's own workflows and
   action file pass both checks; updated counts asserted.
7. **Regression battery:** full suite 0 fail; `npm run validate` PASS;
   `npm run scan:suppressions` clean; gate-scan advisory reported verbatim.

The composite YAML's runtime behavior on real runners is not hermetically testable —
the dogfood workflows are its integration test, and this spec records that honestly
rather than pretending a YAML unit test exists.

## Non-goals

- No Marketplace publishing, branding, or major-version tag management (a follow-up
  once the action has soaked on this repo's own PRs).
- No Docker action, no separate action repo.
- No modification to any `pr_closeout_*` script — the gate is consumed as merged.
- No collector/evidence-tools action (future roadmap item).
- No engine-mode template config beyond the README example (with `requiredTools`, per
  A's consumer note — consumers on non-pnpm stacks need it or preflight blocks).
- No network access in any test.

## Success criteria

- A consumer repo can enforce the gate with two short workflows copied from the
  README, and this repo's own PRs run exactly those workflows.
- `run: plan` never fails a job for honest not-ready states; `run: full` never
  passes one that the CLI failed; evidence always lands in the artifact and Step
  Summary before any failure surfaces.
- Machine consumers can key every decision on `status`/`mode`/`attestation` outputs
  without parsing prose.
- `npm run validate` enforces SHA-pinned `uses:` and per-workflow `permissions`
  blocks from now on, for every workflow in the repo.
- The strict/engine tier of a run is unmistakable in the Step Summary, the comment,
  the artifact, and the outputs — A's labeling carried through every CI surface.
