# Closeout Gate Action

`actions/closeout` packages this repository's evidence-first PR closeout gate as a
reusable composite GitHub Action. It wraps `scripts/pr_closeout.js` — `action.yml` is
wiring only, every decision lives in `actions/closeout/support.js` — and gives any
consuming workflow a read-only plan preview plus a review-triggered enforcing gate,
without hand-writing the checkout, setup, exit-code interpretation, and evidence
surfacing every consumer would otherwise re-derive.

## What it is

The action ships two tiers, always labeled unmistakably in every surface (Step
Summary, PR comment, evidence artifact, and the `mode` output):

- **`mode: strict`** (default) — the gate's own fixed 19-check matrix: package-script
  discovery, generator reproducibility, baseline comparisons, and the full fixed-check
  set, byte-for-byte identical to what this repository enforces on itself.
- **`mode: engine`** — the same integrity engine (two-phase qualification then
  confirmation, a suppression finding overrides everything, a provisional report is
  written before anything runs) but over a repo-supplied `config.engineChecks` matrix
  instead of the fixed 19 checks. It is explicitly documented, in every rendered
  report and in the attestation digest, as a **different and weaker guarantee** than
  strict — a repository defines its own matrix, so the gate can no longer promise the
  specific 19 checks strict promises.

Every run is either a `run: plan` preview (spawns the CLI's `--plan` mode, always
succeeds for honest not-ready states, never touches PR review state) or a `run: full`
enforcing gate (propagates the CLI's real exit code as the job result).

## Quick start

Two workflows cover the two triggers this action is designed for: a cheap, read-only
preview on ordinary pushes, and a review-triggered enforcing gate. The examples below
are this repository's own dogfood workflows, copied verbatim.

### Plan preview — `.github/workflows/closeout-preview.yml`

```yaml
name: Closeout preview

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  pull-requests: read
  checks: read

concurrency:
  group: closeout-preview-${{ github.ref }}
  cancel-in-progress: true

jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          # Check out the PR HEAD, not GitHub's synthetic merge ref — the plan
          # records this SHA and the attestation reader compares it to the PR's
          # actual headRefOid. workflow_dispatch has no PR context, so it falls
          # back to the dispatched ref.
          ref: ${{ github.event.pull_request.head.sha || github.ref }}
          # Full history: the gate resolves merge-base and diffs the whole
          # PR range, not just the tip commit.
          fetch-depth: 0
          # Do not persist checkout credentials: plan admission can execute
          # repository-local preflight probes.
          persist-credentials: false

      # Fork-PR note: this preview is read-only by design, so the reduced
      # fork token is sufficient. The pr-comment opt-in would NOT work from
      # a fork; this repo reads Step Summaries instead.
      - name: Closeout plan preview
        uses: ./actions/closeout
        with:
          run: plan
          # Match the enforcing gate's mode and matrix so the preview's
          # attestation marker is digest-compatible with run: full.
          mode: engine
          config: .github/closeout-engine.json
```

### Enforcing gate — `.github/workflows/closeout-gate.yml`

```yaml
name: Closeout gate

on:
  pull_request_review:
    types: [submitted, dismissed, edited]
  pull_request:
    # Re-run when the review state that admitted a prior gate result changes
    # without a fresh `submitted` event: a dismissed approval, an edited
    # review body, a pushed head change, or a reopened PR must each produce a
    # fresh gate result so a stale PASS cannot outlive the state it attested.
    types: [opened, reopened, synchronize, edited, ready_for_review, converted_to_draft]
  workflow_dispatch:
    inputs:
      base-ref:
        description: "Live PR base ref (dispatch runs have no PR context)"
        default: origin/main
      pr-number:
        description: "PR number to gate (needed for a fork PR, or a dispatch not run from the PR's own branch)"
        default: ""
  # Re-run once a sibling CI workflow that was still pending when the gate
  # last ran has settled: an approval submitted while your own CI is still
  # queued/in-progress makes the live-state check correctly BLOCK on that
  # pending check, and nothing else re-triggers the gate once it later
  # completes. List every workflow whose completion could unblock a prior
  # BLOCKED gate result — substitute your own CI workflow name(s) for
  # "Validate" below; "Closeout preview" is this action's own preview
  # workflow above. Handled by the retry-forwarder job below, NOT by `gate`
  # itself — see that job's comment for why.
  workflow_run:
    workflows: ["Validate", "Closeout preview"]
    types: [completed]
  # Re-verify every open PR's gate after a push to a branch PRs target: the
  # attestation is base-SHA-bound, so a base-only advance with an unchanged
  # PR head silently leaves a stale PASS live otherwise. Handled by the
  # base-drift-forwarder job below, NOT by `gate` itself.
  push: {}

permissions:
  contents: read
  pull-requests: read
  checks: read
  # statuses: read covers legacy commit-status contexts (as opposed to
  # check runs) that the live-state rollup can also return — needed if any
  # of your CI publishes commit statuses instead of check runs.
  statuses: read
  # actions: read is required for the gate's own self-exclusion (finding
  # its own displayed check name via the Jobs API) to work on a named or
  # matrixed job; omitting it degrades self-exclusion, it does not error.
  actions: read

# cancel-in-progress is deliberately FALSE for the enforcing gate: workflow-level
# concurrency is evaluated before the job-level if, so a comment-only review
# submitted mid-run would otherwise cancel an in-flight gate and then skip
# itself — leaving the PR with no gate result and no automatic re-trigger. A
# cancelled gate result is a missing gate result; a superseded run invalidates
# itself anyway because the attestation is head-bound. The preview workflow
# keeps newest-wins cancellation, where it is correct.
#
# github.event.pull_request.number covers pull_request/pull_request_review
# events; workflow_run events carry no top-level pull_request, so the
# retry-forwarder job's own run instead keys off
# workflow_run.pull_requests[0].number (empty for a fork PR). Without this
# fallback, every workflow_run-triggered run across every PR would share one
# concurrency group keyed on github.ref (the base branch).
concurrency:
  group: closeout-gate-${{ github.event.pull_request.number || github.event.workflow_run.pull_requests[0].number || github.ref }}
  cancel-in-progress: false

jobs:
  gate:
    # Cost guard only: the gate independently re-verifies the live review
    # state, head SHA, and attestation through gh — this condition just
    # avoids spending a full run on no-op events. It runs on any
    # pull_request activity, a submitted approval, a submitted
    # CHANGES_REQUESTED, a submitted COMMENT review (inline review threads
    # with no approval — those threads can carry unresolved comments that
    # readLivePrState would block, so a stale PASS cannot survive them),
    # any dismissed review, and an edited APPROVAL only (an edited
    # non-approval is unchanged state). A completed sibling workflow run and
    # a base-branch push do NOT run this job directly — see retry-forwarder
    # and base-drift-forwarder below.
    if: ${{ github.event_name == 'workflow_dispatch' || github.event_name == 'pull_request' || github.event.review.state == 'approved' || github.event.review.state == 'changes_requested' || github.event.review.state == 'commented' || github.event.action == 'dismissed' || (github.event.action == 'edited' && github.event.review.state == 'approved') }}
    runs-on: ubuntu-latest
    steps:
      # Resolves an explicit workflow_dispatch `pr-number` input to its head
      # SHA before checkout, so a manual dispatch can target a fork PR (not
      # selectable in the dispatch UI's own ref picker) or a same-repo PR
      # without first switching to its branch.
      - name: Resolve workflow_dispatch PR head
        id: resolve-dispatch-pr
        if: ${{ github.event_name == 'workflow_dispatch' && github.event.inputs.pr-number != '' }}
        env:
          GH_TOKEN: ${{ github.token }}
          # Event-derived values go through env, never into the script body:
          # a ${{ }} expression is substituted into the shell source TEXT
          # before bash parses it, so a crafted value could close the quote
          # and append commands.
          PR_NUMBER: ${{ github.event.inputs.pr-number }}
        run: |
          set -euo pipefail
          case "$PR_NUMBER" in
            ''|*[!0-9]*)
              echo "::error::pr-number must be a plain decimal PR number; got '$PR_NUMBER'."
              exit 1
              ;;
          esac
          sha=$(gh pr view "$PR_NUMBER" --repo "$GITHUB_REPOSITORY" --json headRefOid --jq .headRefOid)
          if [ -z "$sha" ]; then
            echo "::error::Could not resolve a head SHA for PR #${PR_NUMBER} in ${GITHUB_REPOSITORY}."
            exit 1
          fi
          echo "head-sha=$sha" >> "$GITHUB_OUTPUT"

      - name: Check out reviewed head
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          # The gate re-verifies the live head via gh and BLOCKS stale
          # snapshots; the checkout must present the head being attested.
          # This job's `if:` above no longer admits workflow_run or push
          # events, so github.event.pull_request.head.sha is always present
          # except for workflow_dispatch — the step above resolves an
          # explicit pr-number input to a head SHA when given; github.ref is
          # the last resort for a same-repo dispatch with no pr-number input.
          ref: ${{ github.event.pull_request.head.sha || steps.resolve-dispatch-pr.outputs.head-sha || github.ref }}
          fetch-depth: 0
          # Do not persist checkout credentials: the gate runs PR-controlled
          # validation commands that could otherwise use the saved git token.
          persist-credentials: false

      - name: Closeout gate
        uses: ./actions/closeout
        with:
          run: full
          # Match this repo's engine matrix (npm-based, no pnpm/Prisma).
          # Consumers on other stacks: use mode: strict or your own engine config.
          mode: engine
          config: .github/closeout-engine.json
          base-ref: ${{ github.event.inputs.base-ref || '' }}

  # Re-runs the gate's most recent completed run at a PR's head once a
  # sibling workflow above completes, so a result that was BLOCKED on that
  # sibling gets a correctly SHA-associated retry instead of one whose
  # implicit check run attaches to the wrong commit (see the workflow_run
  # KNOWN LIMITATION entry below — now resolved by this job). Deliberately
  # separate from `gate`: only this job gets `actions: write`, and only to
  # call the rerun API — it checks out no PR-controlled ref and runs no
  # PR-controlled command.
  retry-forwarder:
    if: ${{ github.event_name == 'workflow_run' && github.event.workflow_run.event == 'pull_request' && github.event.workflow_run.pull_requests[0] != null }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
      actions: write
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          persist-credentials: false
      - env:
          GH_TOKEN: ${{ github.token }}
          HEAD_SHA: ${{ github.event.workflow_run.pull_requests[0].head.sha }}
        run: |
          set -euo pipefail
          node scripts/gate_retry_cli.js single \
            --repository "$GITHUB_REPOSITORY" \
            --head-sha "$HEAD_SHA"

  # Re-runs the gate for every open PR targeting a branch that was just
  # pushed to, closing the base-branch-drift gap (see the KNOWN LIMITATION
  # entry below — now resolved by this job). Same isolation rationale as
  # retry-forwarder.
  base-drift-forwarder:
    if: ${{ github.event_name == 'push' && github.ref_type == 'branch' }}
    runs-on: ubuntu-latest
    permissions:
      contents: read
      # A job-level permissions: block REPLACES the workflow-level one rather
      # than merging with it, so pull-requests: read must be repeated here —
      # this job's `gh pr list` discovery silently finds zero PRs without it.
      pull-requests: read
      actions: write
    steps:
      - uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          persist-credentials: false
      - env:
          GH_TOKEN: ${{ github.token }}
          # Via env, not interpolated: git ref names permit `$`, backticks
          # and `;`, so a branch name substituted into the script text could
          # append commands.
          BASE_REF: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          node scripts/gate_retry_cli.js base \
            --repository "$GITHUB_REPOSITORY" \
            --base-ref "$BASE_REF"
```

The `workflow_run`/`push` triggers and their forwarder jobs above are optional
but recommended: without them, a gate run that BLOCKS on a still-pending
sibling CI check, or a PASS attested against a base branch that has since
advanced, is never automatically retried and stays stuck until unrelated PR
or review activity happens to re-trigger the gate. `scripts/gate_retry_cli.js`
and `scripts/pr_closeout_retry.js` are plain Node scripts with no dependency
on `actions/closeout` itself — copy them alongside this workflow. See
`.github/workflows/closeout-gate.yml` in this repository for the full version
with its complete rationale comments.

Both examples above use the **local dogfood form**, `uses: ./actions/closeout`,
because they live in the same repository as the action. Consuming this action from
another repository, use the **remote form** instead, pinned to an exact commit SHA —
never a branch name or a floating version tag:

```yaml
      - name: Closeout plan preview
        uses: XGenerationy/codex-agents-debug-mode/actions/closeout@<commit-sha>
        with:
          run: plan
```

Replace `<commit-sha>` with the full 40-character commit hash of the revision you want
to consume, and re-pin deliberately when you upgrade. This repository's own validator
(`tools/workflow_checks.js`) fails any workflow or composite action whose `uses:` line
is not SHA-pinned; apply the same discipline to how you pin this action from the
outside.

## Inputs

All inputs are strings. Unrecognized values for `run`, `mode`, or `pr-comment` are a
named error raised before the gate CLI is ever spawned — an invalid value is never
silently coerced to the default.

| Input | Values | Default | Description |
|---|---|---|---|
| `run` | `plan` \| `full` | `plan` | `plan` (read-only preview) or `full` (enforcing gate). |
| `mode` | `strict` \| `engine` | `strict` | `strict` (19-check gate) or `engine` (`config.engineChecks`). |
| `base-ref` | ref | *(empty)* | Live PR base ref; empty resolves via `GITHUB_BASE_REF` or the event payload. See [Checkout requirements](#checkout-requirements). |
| `config` | path | *(empty)* | Path to a closeout config JSON. |
| `output-dir` | path | *(empty)* | Caller-facing evidence location (must be outside the repository). When empty, the composite step falls back to `${{ runner.temp }}/closeout-evidence`. Evidence files are NOT written directly into this directory: they live in a private, action-created `closeout-action-evidence/` child of it, and this directory's own permissions are never modified — see [Evidence directory layout](#evidence-directory-layout). |
| `node-version` | version spec | `24` | Node.js version for the gate. |
| `pr-comment` | `true` \| `false` | `false` | `true` to upsert a marker-tagged PR comment (needs `pull-requests: write`). |
| `artifact-name` | string | `closeout-evidence` | Evidence artifact name. See [Artifact-name uniqueness and concurrency](#artifact-name-uniqueness-and-concurrency). |

## Outputs

Every output is empty until the gate step (`support.js run`) has actually executed — a
run that fails input validation never reaches it, so all four stay empty in that case.

| Output | Content |
|---|---|
| `status` | `overallStatus` (full runs) or `planStatus` (plan runs); empty until the gate step has run. |
| `mode` | The gate-reported mode of the run; empty until the gate step has run. |
| `attestation` | Plan runs: the four-state `admission.attestation.status` (`present` \| `weakened` \| `absent` \| `unavailable`). Full runs: empty. Empty until the gate step has run. |
| `report-path` | Absolute path of `report.json` (full runs) or the captured plan JSON (plan runs); empty until the gate step has run. |
| `admission-status` | Plan runs: `PASS` \| `FAIL` \| `BLOCKED` \| `unavailable` — the aggregate of the admission sub-probes (`attestation`, `cleanTree`, `preflight`). This is the readiness signal to key automation on: `planStatus`/`status` alone reflects only whether the check MATRIX resolved, not whether the plan is actually admissible — a resolved matrix with a failed or blocked preflight/clean-tree probe still reports `status: PASS`, but `admission-status` correctly reports `BLOCKED`/`FAIL`. Full runs: empty. Empty until the gate step has run. |

## Evidence directory layout

Evidence is written into a **private, action-created child directory** of
`output-dir`, never into `output-dir` itself (chatgpt-codex-connector PR7
#6Yd4Qx):

```
<output-dir>/                          # caller-owned; a pre-existing directory is never chmodded
└── closeout-action-evidence/          # action-created; owner-only (0700) on POSIX
    ├── plan.json                      # plan runs
    ├── report.json                    # full runs
    ├── report.md                      # full runs
    ├── action-state.json              # the run's recorded exit decision
    └── logs/                          # full runs: per-check probe logs
```

(If `output-dir` does not exist yet — the default case — the action creates
it owner-only as a conservative starting point, and never re-chmods it on any
later run: only a directory the action itself just created gets a mode from
it, never one that already existed.)

Why the child exists: the evidence files can carry unredacted runner paths and
base refs before the gate CLI's redaction runs, so on a multi-user runner the
directory that holds them must be owner-only (`0700`). Earlier versions
enforced that by chmodding `output-dir` itself and restoring its mode
afterwards — which meant a caller pointing `output-dir` at a shared directory
(`${{ runner.temp }}`, `/tmp` at `01777`) had that directory narrowed to
`0700` for the entire gate run, up to the configured timeout, breaking
concurrent users of it. Now the action creates, verifies (refusing a
pre-planted symlink or another user's directory at that fixed name), and
secures only its own child; a pre-existing caller directory's mode is never
touched by the action or by the gate CLI it spawns (the CLI is handed the
child as its `--output-dir`, so its own `0700` chmod lands there too).

What this changes for consumers:

- **The downloaded evidence artifact is unchanged.** The upload globs all
  point inside the child, and it is their common ancestor, so
  `plan.json`/`report.json`/`report.md`/`action-state.json`/`logs/` still sit
  at the artifact root exactly as before.
- **The `report-path` output is unchanged in meaning.** It has always been
  the absolute path of the report file, and it now points inside the child —
  consumers using the output need no changes.
- **Breaking change for hardcoded local paths:** a workflow step that set
  `output-dir: /some/path` and then read `/some/path/report.json` directly
  from the runner's filesystem will no longer find it — the file is at
  `/some/path/closeout-action-evidence/report.json`. Use the `report-path`
  output instead of hardcoding, or add the `closeout-action-evidence/`
  segment.
- The child's name is fixed (a composite action's static YAML must be able to
  glob it, and the separate comment/verdict steps must re-derive it from
  `output-dir` alone), so two invocations sharing an `output-dir` still
  collide inside the shared child — the requirement to give each invocation a
  distinct `output-dir` (see
  [Artifact-name uniqueness and concurrency](#artifact-name-uniqueness-and-concurrency))
  is unchanged.
- On Windows, POSIX modes are advisory: the child directory itself carries no
  verified DACL (same as `output-dir` itself did before this layout), but
  every evidence file is individually protected with an owner-only DACL.

## Permissions

The composite action authenticates as `GH_TOKEN: ${{ github.token }}` (wired
internally — there is no `token` input) to query the live PR state and attestation.
The minimum `permissions:` block for any workflow that uses this action:

```yaml
permissions:
  contents: read
  pull-requests: read
  checks: read
  statuses: read
  actions: read
```

`contents: read` covers the checkout; `pull-requests: read` covers the attestation and
PR-state lookups the gate makes through `gh`, needed on both `run: plan` and
`run: full`; `checks: read` lets the live-state classifier read the PR's
`statusCheckRollup` check runs via `gh pr view --json`; `statuses: read` covers
the legacy `StatusContext` entries that also appear in `statusCheckRollup`
(without it the lookup cannot retrieve the complete rollup and the gate blocks
as unavailable on PRs that publish commit statuses instead of check runs).
`actions: read` is not load-bearing the same way — its absence degrades
gracefully rather than blocking the run — but it is required for correct
self-exclusion when the workflow that calls this action runs the gate step
in a `strategy.matrix` or under a job `name:` override: self-exclusion
resolves the running job's TRUE displayed name via the Jobs API
(`GET .../actions/runs/{run_id}/jobs`), and an explicit `permissions:`
block disables every scope it does not list. Without `actions: read` that
call 403s, the resolver silently falls back to `null`, and a matrixed or
renamed gate job can never recognize its own in-progress check in the
rollup — it stays BLOCKED on itself indefinitely.

If you opt into `pr-comment: true`, add `pull-requests: write`:

```yaml
permissions:
  contents: read
  pull-requests: write
  checks: read
  statuses: read
  actions: read
```

`gh` **2.31 or newer** is required on the runner for every PR-context invocation
(`run: plan` and `run: full`), not only when `pr-comment: true`. The core
attestation reader (`scripts/pr_closeout_github.js`) uses `gh api --paginate
--slurp` for review/permission lookups, and the comment upsert uses it too; both
fail with `unknown flag: --slurp` on an older `gh`, surfacing as an unavailable
attestation. GitHub-hosted runners ship a current `gh`; on a self-hosted runner,
ensure `gh --version` reports 2.31+.

**Fork-PR note:** a `pull_request`-triggered workflow running against a fork PR
receives a reduced, read-only token regardless of the `permissions:` block above.
`run: plan` still works there — it is read-only by design — but `pr-comment: true`
will not: the token cannot write to the PR, so the comment step **fails the job
with the gh 403 error**. That is deliberate — you opted into the comment, and a
silent skip would hide that it never posted (the Step Summary and artifact are
already written by then either way). Do not enable `pr-comment` on workflows that
fork PRs can trigger. `pull_request_review` runs in the base repository's own
context with the workflow's normal token scope, so the enforcing gate (triggered
by `pull_request_review`, as in `closeout-gate.yml`) is unaffected.

## Failure semantics

The two tiers fail differently by design — this is the exit decision table from the
design spec, restated for consumers:

| Tier | Gate outcome | Job result |
|---|---|---|
| `run: full` | CLI exit 0 with the contractual JSON record captured | success |
| `run: full` | CLI exit 0 but no parseable JSON record | job fails — the gate always writes one JSON line, so its absence means the wrapper or stdout path broke; never a silent PASS on missing evidence |
| `run: full` | CLI exit 2 (FAIL) or exit 3 (BLOCKED) | job fails with the same class, after the Step Summary and evidence artifact have already been written |
| `run: plan` | a parseable plan JSON line was captured, whatever the exit code | success — even when `planStatus` is `FAIL` or admission reports `absent`/`unavailable`. Pre-review "not ready yet" is the preview's normal, honest state; a preview that turns red before anyone could review the PR trains people to ignore it |
| `run: plan` | no parseable plan JSON line on stdout | job fails — a broken preview must be loud |
| either | unrecognized `run`, `mode`, or `pr-comment` input value | job fails before the gate CLI is ever spawned, with a named error |

The readiness signal for `run: plan` lives in the Step Summary and in the `status` /
`attestation` outputs — never in the job's pass/fail color, which stays green for
every honest not-ready state. `status`/`attestation` alone can still read as ready
when it is not: `status: PASS` only means the check matrix resolved, and
`attestation: present` only means a matching review exists — neither reflects a
failed or blocked clean-tree/preflight probe. **`admission-status` is the single
aggregate field to key automation on** — it is `PASS` only when every admission
sub-probe (attestation, clean tree, preflight) is itself `PASS` (Codex PR7 review,
"Document the aggregate readiness output").

## Attestation model

The gate's attestation is **review-triggered**, **head-SHA-bound**, and
**digest-bound**: a maintainer's approving review on the live PR is what mints it, it
names the exact head commit it covers, and it is bound to a digest of the resolved
check matrix and mode. Change the matrix, change the mode, or push a new head commit,
and the existing attestation stops matching. `run: full` independently re-verifies all
of this against the live PR state through `gh` — it never trusts the checked-out
snapshot alone.

**An ordinary approval is not enough.** The review's body must contain the exact
`PR-CLOSEOUT-ATTESTATION` marker line that `run: plan` (or `run: full` on a prior
head) emits for the current base, head, and config digest — bound to all three, so a
review approving one commit or config cannot be replayed onto another. The plan's Step
Summary and its `attestation: absent`/`present` output tell you whether a matching
attestation exists; when it is `absent`, the plan JSON's
`gateIntegrityAttestationRequired.marker` field carries the verbatim marker line the
approving reviewer must paste into their
review body. The reviewer must be someone other than the PR author and must hold
repository write permission (`OWNER`/`MEMBER`/`COLLABORATOR` with proven `WRITE`+);
`classifyGateAttestation` rejects self-approval and unauthorized authors.

`run: plan` surfaces the live attestation lookup as one of four states, both as the
`attestation` output and as the `admission.attestation.status` field of the captured
plan JSON:

| State | Meaning |
|---|---|
| `present` | A mode-matched attestation for this exact base/head/config-digest snapshot exists. |
| `weakened` | An attestation matching this snapshot exists but records a weakened decision. **Defensive only today:** the live reader only ever returns PASS or BLOCKED, never FAIL, so a weakened review lands in `absent` instead — this state is kept for reader evolution. Do not build automation that depends on `weakened` firing yet. |
| `absent` | No matching approving review yet (the normal state before review), or the PR head/base has moved past the snapshot the last attestation covered. |
| `unavailable` | The attestation lookup itself could not complete (`gh` missing, unauthenticated, or a network failure) — distinct from `absent`, which says nothing about whether a review exists. |

Machine consumers must key decisions on the `status` and `attestation` outputs, never
on Step Summary or comment prose — rendered wording can change between releases; the
outputs are the stable contract.

## Engine mode

`mode: engine` runs the same integrity engine over a repository-supplied check matrix
instead of the fixed 19-check gate. It is explicitly a **different, and weaker,**
guarantee than strict, and is labeled as such everywhere: reports, Step Summary, PR
comment, and the attestation digest. A strict-minted attestation can never satisfy an
engine-mode admission, and vice versa.

Know this before your first run: **strict preflight requires all eight probes to
pass** — git, node, pnpm, make, docker, docker-compose, a running docker daemon, and
prisma — and `strict` is the default `mode`. On any stack other than this
repository's own (a Rust repo, a Python repo, a plain-npm repo), strict admission
BLOCKS at preflight: the plan preview stays green (honest not-ready is its normal
state) but its Step Summary reports probes like `pnpm --version` failing. That is
the signal you want `mode: engine` with `requiredTools`, not a broken setup.

Point `config` at a JSON file, for example:

```json
{
  "engineChecks": [
    { "id": "unit", "scripts": ["test:ci", "test"] },
    { "id": "lint", "scripts": ["lint:ci", "lint"] },
    { "id": "build", "command": "npm run build" }
  ],
  "requiredTools": ["git", "node"],
  "scriptRunner": "npm run"
}
```

- `engineChecks` is required in engine mode (and a hard error in strict mode, if
  present). Each entry needs a unique `id` and exactly one command source: a fixed
  `command` string, or a `scripts` list of package-script names tried in order.
- `requiredTools` matters most for repositories that are not the pnpm-based stack the
  strict gate assumes. Engine-mode preflight probes only `git` and `node` by default,
  plus whatever names you list here, drawn from the fixed probe catalog (`git`,
  `node`, `pnpm`, `make`, `docker`, `docker-compose`, `docker-daemon`, `prisma`).
  npm itself is not in the catalog because it ships with Node — the `node` probe
  covers it, which is why the npm-only example above declares nothing beyond the
  always-probed defaults (its `requiredTools` line is the explicit spelling of the
  default; a check that invoked docker would add `"docker"` and `"docker-daemon"`).
  Declare every catalog tool your `engineChecks` commands actually invoke, or preflight has no
  way to confirm it is present, and a check depending on it can fail later with no
  preflight evidence explaining why. Strict mode's own preflight, by contrast, always
  runs the full 8-probe catalog including pnpm and prisma — exactly the requirement
  engine mode exists to let non-pnpm repositories opt out of.
- `scriptRunner` (default `npm run`) is the command used to invoke a resolved
  `scripts` entry. Strict mode hardcodes `pnpm run` and rejects `scriptRunner` in its
  own config as a hard error.
- **Make-gate honesty:** a resolved command's recipe is only inspectable when the
  command is exactly `make <target>`. Any other way of invoking make — wrapped,
  prefixed, piped, quoted, chained, or through an alias such as `gmake` — is BLOCKED
  outright rather than trusted. In practice: use `make <target>`, or don't use make.
- **One-time digest migration:** upgrading a consumer that already has outstanding
  review attestations minted under an earlier gate version invalidates them once,
  because the attestation digest input itself changed (it now binds in the run's
  mode as well as the matrix). The first post-upgrade run reads BLOCKED with a
  digest-mismatch admission error — that is the designed behavior, not a regression.
  Reviewers re-attest the current head and it clears.
- **Engine-command environment allowlist, two different tiers:** engine check
  commands (a `run: full`, attested run) and plan-mode preflight probes
  (`run: plan`, untrusted PR-controlled code, pre-attestation) both run under a
  filtered child environment, never the full step environment — runner command
  files (`GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY`,
  `GITHUB_STATE`) are hard-denied regardless of config in either tier — but the
  two tiers are NOT the same filter. **Full run:** `ESSENTIAL_ENV` plus your
  `requiredEnv` / `safeEnv` lists — credential-shaped names ARE passed through,
  since the run is attested and your checks may legitimately need `API_TOKEN`,
  `DATABASE_URL`, etc. **Exception:** `GH_TOKEN` and `GITHUB_TOKEN` are ALWAYS
  stripped (even in full runs) to prevent engine checks from using the workflow
  token for authenticated git/API operations; provide your own token via a
  separate `safeEnv` entry if a check needs GitHub auth. To pass a secret into
  your engine checks in a full run, list it in `safeEnv`; to require it, list
  it in `requiredEnv` (a missing `requiredEnv` var fails the run before checks
  execute). **Plan preview:** `ESSENTIAL_ENV` only — `config.requiredEnv` and
  `config.safeEnv` are NOT honored here at all, regardless of what they name.
  This is stricter than filtering by name pattern: `config` is itself read from
  the checked-out (PR-controlled) config path, so a PR could otherwise add an
  existing job secret's name to `safeEnv` under a name a pattern-based denylist
  does not recognize. The consequence for `requiredEnv`: a plan preview never
  fails preflight for a "missing" required variable — that check does not run
  in plan mode at all, since plan mode was never meant to need a full run's
  credentials, and the plan-specific config handed to preflight has
  `requiredEnv`/`safeEnv` cleared. `HOME`, `USERPROFILE`, `APPDATA`, and
  `LOCALAPPDATA` are additionally isolated for plan-mode preflight: each is
  substituted with a fresh, empty temp directory created for that probe call
  and removed afterward, so a probe cannot read credential-bearing files
  (`.npmrc`, `.netrc`, the `gh` CLI's own token store) from the runner's real
  profile by path, independent of what is or is not in the filtered env. The
  gate injects one trusted, non-secret, repo-derived variable in BOTH tiers:
  `CLOSEOUT_RESOLVED_BASE_REF` (already rev-parsed to a stable SHA), so engine
  commands that need the PR base — for example
  `git diff --check "${CLOSEOUT_RESOLVED_BASE_REF:-origin/main}"...HEAD` —
  resolve the correct base even though `GITHUB_BASE_REF` is stripped from the
  filtered environment. Quote the expansion to survive base refs containing
  spaces.

## Preview cost

`run: plan` always runs the admission preflight, in both modes — there is no opt-out.
Strict `--plan` runs the full 8-probe catalog (git, node, pnpm, make, docker,
docker-compose, docker-daemon, prisma), measured at roughly 27 seconds with a running
Docker daemon; without one, the docker probes wait out their connect timeouts, so it
can take longer. Engine `--plan` narrows to `git` + `node` + whatever
`requiredTools` you declared, measured at roughly 5 seconds. If you wire `run: plan`
into every push — as this repository's own `closeout-preview.yml` does — budget for
the strict cost, or use engine mode's `requiredTools` narrowing to keep it cheap.

## Checkout requirements

The gate needs full repository history to resolve a merge-base and diff the whole PR
range, not just the tip commit. `fetch-depth: 0` on the consumer's checkout step is
**required** — the default depth-1 checkout leaves no `origin/<branch>` ref for the
gate to diff against, and it errors.

The `base-ref` input has two different behaviors depending on where the value comes
from, and both are load-bearing:

- **Explicit `base-ref` input:** passed to the gate CLI **verbatim**, with no
  `origin/` prefix added — the operator's value is authoritative. Pass
  `base-ref: main` and the CLI receives exactly `main`.
- **Automatic resolution (input left empty):** the support script resolves it down a
  fail-closed ladder — `origin/$GITHUB_BASE_REF` (set on `pull_request` events), then
  `origin/<event.pull_request.base.ref>` from the event payload
  (`pull_request_review` events), then nothing, in which case the gate CLI's own
  `config.baseRef`-or-error contract applies. Both automatic branches add the
  `origin/` prefix themselves, because `GITHUB_BASE_REF` and the event payload only
  ever carry a bare branch name (for example `main`), never a full ref.

In practice: leave `base-ref` empty on ordinary `pull_request`/`pull_request_review`
triggers and let the ladder resolve it. Set it explicitly only where there is no PR
event to resolve from — `workflow_dispatch`, as `closeout-gate.yml` does with its own
`base-ref` dispatch input — and when you do, include the `origin/` prefix yourself if
that is what your checkout needs.

## Artifact-name uniqueness and concurrency

The evidence artifact contains the gate's own (redacted) report files plus
`action-state.json` — the run's recorded exit decision and rendered summaries. On
failure paths those can embed **unredacted CLI error text** (the same text the run
log shows), the resolved base ref, and absolute runner paths. The artifact is a
run-log-equivalent surface by design: treat a downloaded copy with the same care as
the run log, and don't paste its contents into public threads unreviewed.

`actions/upload-artifact@v4` rejects a duplicate artifact name **within one workflow
run**. If you invoke this action more than once in the same run — a plan step and a
full step in one workflow, or a matrix across operating systems — give each
invocation a distinct `artifact-name` (for example, suffix it with the job name or the
matrix key). The composite action cannot do this for you: input defaults in
`action.yml` cannot embed expressions such as `${{ matrix.os }}`, so there is no
default that varies per invocation. Miss this and the failure surfaces as an
artifact-upload error, not a gate error — it reads as unrelated CI infrastructure
trouble rather than anything this action or the gate did.

The same caveat applies to `output-dir`, and it is the more dangerous of the two:
two invocations in the same job that both omit `output-dir` share
`${{ runner.temp }}/closeout-evidence` — and with it the
`closeout-action-evidence/` child where evidence actually lives (see
[Evidence directory layout](#evidence-directory-layout); the child's name is
fixed for the same no-expressions-in-defaults reason, so it provides no
per-invocation isolation) — so the second run's `action-state.json`
overwrites the first's, and the first's evidence is uploaded before the
overwrite only by step ordering. The composite action's input defaults cannot
embed expressions (no `${{ matrix.os }}`, no step name), so it cannot compute a
unique per-step path for you. **When you invoke this action more than once in one
job, give each invocation a distinct `output-dir` too** (a runner-temp-relative
path is outside the repository and satisfies the evidence-location requirement),
in addition to a distinct `artifact-name`.

Two related concurrency notes, matching this repository's own dogfood workflows:

- Gate workflows (`run: full`) should set `cancel-in-progress: false` on their
  concurrency group. Workflow-level concurrency is evaluated before a job's own `if:`
  condition, so a comment-only review submitted mid-run would otherwise cancel an
  in-flight enforcing gate and then skip itself — leaving the PR with no gate result
  and nothing to re-trigger it. A cancelled gate run is a missing gate result, and a
  genuinely superseded run self-invalidates anyway through the head-bound
  attestation.
- Preview workflows (`run: plan`) should keep newest-wins cancellation
  (`cancel-in-progress: true`) — there is no enforcement stake in an outdated preview,
  so cancelling it in favor of the newest push is correct and saves runner time.

## Known limitations

Two integrity gaps follow from packaging the gate as an action that consumes itself,
and are recorded here honestly rather than hidden. Both require changes to the gate
CLI (`scripts/pr_closeout_*`), which this action consumes as-is and does not modify;
they are roadmap items, not accepted risk:

- **The enforcing gate is not self-protecting against a PR that modifies the action.**
  When a PR changes `actions/closeout/action.yml`, `support.js`, or the gate scripts,
  the dogfood `closeout-gate.yml` checks out that untrusted PR revision and runs
  `uses: ./actions/closeout` against it — so such a PR could replace the gate's
  verdict with an unconditional PASS. A self-protecting gate must invoke an immutable
  revision of the action (for example, the version merged on the base branch) rather
  than the PR's local copy. Until then, a PR that touches the action or gate scripts
  requires a maintainer to re-run the gate from the base branch after review; the
  `statusCheckRollup` and attestation re-verification still catch every other class of
  PR. Consumers who pin the action to a tag (`uses: owner/repo/actions/closeout@<ref>`)
  are not affected — only this repository's own `uses: ./actions/closeout` dogfood is.
- ~~The running gate observes its own in-progress check as unresolved.~~ **Resolved.**
  `classifyLivePrState` (scripts/pr_closeout_github.js) excludes the current job's
  own checks from the live `statusCheckRollup` before classifying it: it omits
  every check matching both the running workflow (`GITHUB_WORKFLOW`) and job's
  DISPLAYED name — **regardless of status or conclusion**, including a PRIOR
  COMPLETED run of the same job, even a FAILURE (chatgpt-codex-connector PR7
  #6YaIaU, correcting this bullet — CodeRabbit PR7 #6Yb44Sl). This is broader
  than it may first look, and deliberately so: the `workflow_run` retry trigger
  (below) re-runs the gate specifically to recover from a run that correctly
  BLOCKED on a still-pending sibling check — GitHub Actions has no native
  "blocked" job conclusion, so that run's own check is recorded as a `FAILURE`.
  Keeping that stale self-FAILURE classified would make every retry re-derive
  FAIL from its own earlier blocked attempt, forever, for the exact scenario the
  retry exists to recover from. This is safe: every OTHER blocker/failure signal
  (mergeability, review decision, unresolved threads, gate attestation, and
  every check that is NOT this job — including a genuinely different sibling
  check, e.g. `preview`, which is never excluded) is independently re-derived
  from LIVE state on each call, so a stale self check-run carries no additional
  protection to lose. Making the `Closeout gate` check a required merge gate is
  therefore safe; it can reach PASS on its own run (CodeRabbit PR7 #6X_pwH,
  refined by #6YSx9w — landed before this bullet was corrected, CodeRabbit
  #6YW9UF).
- ~~**A verdict recorded while a sibling check is still pending goes stale
  once that check settles.**~~ **The gate correctly RE-EVALUATES for
  same-repo PRs; the required PR check itself is NOT resolved
  (chatgpt-codex-connector PR7 #6Yb44Sh — this bullet previously overstated
  the fix as "Resolved").** If an approval is submitted (re-running the gate)
  while another check (e.g. the Node validation matrix, or `preview`) is
  still queued or in progress, `classifyLivePrState` correctly classifies
  that check as a blocker and the gate reports BLOCKED. `closeout-gate.yml`
  now also subscribes to `workflow_run` (`types: [completed]`), scoped by
  name to exactly the two sibling workflows (`Validate`, `Closeout preview`)
  — deliberately NOT `Closeout gate` itself, so the gate's own completion can
  never retrigger this path; there is no retrigger loop to guard against, by
  construction. `readActionsPrNumber` and `resolveBaseRef` both gained a
  `workflow_run.pull_requests[0]` fallback (populated for a same-repo PR) so
  the triggered run can still identify, diff against, and internally
  re-classify the correct PR. **What that internal re-evaluation does NOT
  do:** a `workflow_run`-triggered run's own implicit GitHub Actions
  check-run is associated with the SHA that triggered the `workflow_run`
  event itself — the default branch's latest commit — never the PR head,
  regardless of which ref the run actually checks out and tests (see the
  `KNOWN LIMITATION #6YaxWe` comment (historical — see **Resolved** note
  below) on the `workflow_run:` block in `.github/workflows/closeout-gate.yml`
  for the full analysis, including empirical verification against this repo's
  own Actions history). So even when the retry's internal verdict is PASS,
  branch protection and `gh pr view --json statusCheckRollup` still show the
  ORIGINAL blocked/stuck `Closeout gate` check on the PR — the retry's Step
  Summary, evidence artifact, and (if enabled) PR comment are produced, but
  nothing about them clears the required check the PR is actually stuck on.
  **Resolved (chatgpt-codex-connector PR7 #6YaxWe):** rather than publishing
  an explicit Checks-API check run (whose correctness would depend on
  unverifiable branch-protection behavior — does a fresh API-created check
  run sharing a name with a stale FAILURE implicit check run actually win as
  "latest"), a separate `retry-forwarder` job (see the example above) finds
  the gate's own most recent COMPLETED run at the PR's head — already
  correctly SHA-associated, since it was triggered by a real
  `pull_request`/`pull_request_review` event — and asks GitHub to re-run
  it. The re-run executes as a new attempt of that SAME run under its
  ORIGINAL trigger context, so its implicit check run updates correctly on
  the PR head; the SHA-association problem does not arise in the first
  place. `scripts/pr_closeout_retry.js` / `scripts/gate_retry_cli.js`
  implement this; they are plain Node with no dependency on the rest of this
  action.
  **Residual gap for fork PRs (separate from the above, still present):**
  GitHub does not populate `workflow_run.pull_requests` for a fork PR's
  associated workflow runs, so `retry-forwarder` cannot resolve the PR number
  for a fork PR and skips it (safe — never a false PASS, and never a spent
  API call on an unresolvable target) rather than forwarding a retry.
  Interim control for fork PRs specifically: re-run the gate via
  `workflow_dispatch` with the `pr-number` input (see below), or wait for the
  next naturally covered event (a head push or a new/edited review) once all
  sibling checks have settled (CodeRabbit PR7 #6YW9UP).
- ~~**Event triggers do not cover a base-branch advance.**~~ **Resolved
  (chatgpt-codex-connector PR7 #6YbMwY).** The attestation is base-SHA-bound,
  so if the base branch receives a new commit while a PR's head is unchanged,
  the prior attestation no longer matches and the gate should re-run, but
  GitHub fires no `pull_request` event for a base-only advance (only
  `synchronize` on head changes). The example workflow above now also
  subscribes to `push: {}`; a `base-drift-forwarder` job (same file) responds
  to it by discovering every OPEN PR targeting the pushed branch (`gh pr list
  --base <branch> --state open` — no push event payload names them) and
  forwarding a retry (via the same rerun-the-most-recent-completed-run
  mechanism as `retry-forwarder` above) for each one's current head,
  sequentially, bounding worst-case Actions-API load on a branch with many
  open PRs against it. A tag push is skipped (`github.ref_type == 'branch'`)
  since a tag has no PRs "targeting" it.
- **Runner command-file env vars are hard-denied from child commands.** The gate
  CLI's `buildWorkflowEnvironment` (used by both the plan preflight and the
  attested full run, including `mode: engine`) strips `GITHUB_PATH`,
  `GITHUB_ENV`, `GITHUB_OUTPUT`, `GITHUB_STEP_SUMMARY`, and `GITHUB_STATE` via
  `DENYLISTED_ENV_NAMES` before spawning any repository-defined command, so a
  malicious check cannot write to those files to alter the runner. (`GH_TOKEN`/
  `GITHUB_TOKEN` are likewise stripped.) Treat engine-mode check commands with
  the same trust discipline as any CI step that shares the runner environment;
  this denylist is the action's contribution to that posture, not a substitute
  for runner hygiene.
- **Reopening a review thread does not re-trigger the gate.** GitHub fires a
  `pull_request_review_thread` `unresolved` webhook event when a resolved thread
  reopens, but that event is **not** a supported GitHub Actions workflow trigger
  (`on:`), so an event-triggered gate cannot observe it. The head SHA is
  unchanged, so the prior PASS stays live even though `readLivePrState` would
  now BLOCK on the unresolved thread. Interim control: a head push, a new/edited
  review, or a manual `workflow_dispatch` re-runs the gate and catches the
  reopened thread. A scheduled re-validation sweep is the long-term fix.
- ~~**Manual dispatch runs have no PR context.**~~ **Resolved for the common
  case (chatgpt-codex-connector PR7 #6Yd4Qs).** `github.event.pull_request`
  is always empty on `workflow_dispatch`, so without an explicit `pr-number`
  input the gate's argument-less `gh pr view` falls back to guessing from the
  checked-out branch — wrong, or failing outright, for a fork PR (not
  selectable in the dispatch UI's own ref picker at all) or a dispatch
  launched from the default branch. The example workflow above now declares
  a `pr-number` dispatch input; when set, a `Resolve workflow_dispatch PR
  head` step resolves it to a head SHA *before* checkout (so a fork PR's
  head is checked out correctly, detached, with no branch of its own needed
  in the base repo), and `readActionsPrNumber`
  (`scripts/pr_closeout_github.js`) reads the same `pr-number` input back out
  of the event payload as an explicit fallback, so `gh pr view` resolves the
  right PR even from that detached HEAD. Leaving `pr-number` empty still
  falls back to the previous behavior (`github.ref`) — correct only for a
  same-repo dispatch already run from the PR's own branch.
- **A broad, caller-overridden `output-dir` can still leak an unrelated
  file that happens to share one of this action's evidence filenames
  (CodeRabbit PR7 #6YYcNT) — now only via the evidence child, which
  narrows the gap substantially but does not close it.** Three safeguards
  exist here: stale-evidence cleanup only removes prior files once an
  authenticated `action-state.json` marker proves THIS action wrote them
  (`hadPriorEvidence` in `support.js`, chatgpt-codex-connector PR7 #6YaIal);
  the "Upload evidence artifact" step (chatgpt-codex-connector PR7 #6Yb3lY)
  uploads only the exact well-known names (`plan.json`, `report.json`,
  `report.md`, `action-state.json`, `logs/`) rather than a whole directory;
  and since chatgpt-codex-connector PR7 #6Yd4Qx those names are globbed (and
  cleaned) only inside the action-created `closeout-action-evidence/` child
  (see [Evidence directory layout](#evidence-directory-layout)) — an
  unrelated tool's same-named file sitting directly in a broad shared
  `output-dir` (`${{ runner.temp }}`, `/tmp`) is therefore no longer
  deleted or published at all. The residual gap that remains: an unrelated
  tool that writes one of those same generic names INSIDE
  `<output-dir>/closeout-action-evidence/` would still be picked up by the
  upload (mere filename match, not proof of ownership, is all
  `if-no-files-found: ignore` can check) — far less plausible by accident
  than a bare `/tmp/plan.json`, but not impossible; and on POSIX a
  pre-planted symlink or foreign-owned directory at that child name is
  refused fail-closed, whereas a world-writable NON-sticky shared parent
  still lets a local attacker swap the verified child after the check
  (sticky `/tmp` prevents this; file-level no-follow/`O_EXCL` defenses still
  apply either way). The default (`${{ runner.temp }}/closeout-evidence`,
  paired with **a distinct `output-dir` per invocation** as required above)
  is action-owned and not exposed to any of this; the risk exists only when
  a caller overrides `output-dir` to a pre-existing broad path shared with
  other tools or steps. Recommended: point `output-dir` at an action-owned
  leaf directory (the default, or a dedicated subdirectory you don't share
  with any other step) rather than a broad shared path. What #6Yd4Qx also
  removed outright: the action no longer chmods a caller-owned `output-dir`
  at any point, so pointing it at a shared directory can no longer make that
  directory owner-only for the duration of the gate run.
- **Regex-based `uses:` validation cannot parse all YAML.** The
  `tools/workflow_checks.js` SHA-pin check is deliberately regex-based (no YAML
  parser in a zero-dependency repo). It is conservatively fail-closed: any
  `uses:` token it cannot positively confirm as a clean block-style pinned/local
  reference is flagged. This means flow style, anchors, multi-entry flow
  sequences, and other non-block YAML forms are rejected (rewrite them in block
  style). The one accepted residual: a `uses:`-like token inside a `run: |`
  block-scalar continuation line could theoretically false-positive; this is
  vanishingly rare in real workflows. A real YAML parser is the long-term fix.
- **Reviewer permission checks are N+1.** The gate's `readLivePrState` fetches
  each matching review's collaborator-permission record individually via `gh`,
  and the two-snapshot stability check repeats this up to four times. On PRs
  with many reviews this creates an N+1 network pattern. This is a performance
  characteristic, not a correctness issue — each lookup is independent and the
  stability check ensures consistency. A batched GraphQL query would reduce the
  request count; the current per-review approach is simpler and the N is
  bounded by the number of reviews on the PR (typically small).
