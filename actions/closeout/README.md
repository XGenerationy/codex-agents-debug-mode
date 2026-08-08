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

      # Fork-PR note: this preview is read-only by design, so the reduced
      # fork token is sufficient. The pr-comment opt-in would NOT work from
      # a fork; this repo reads Step Summaries instead.
      - name: Closeout plan preview
        uses: ./actions/closeout
        with:
          run: plan
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
    types: [opened, reopened, synchronize, edited]
  workflow_dispatch:
    inputs:
      base-ref:
        description: "Live PR base ref (dispatch runs have no PR context)"
        default: origin/main

permissions:
  contents: read
  pull-requests: read

# cancel-in-progress is deliberately FALSE for the enforcing gate: workflow-level
# concurrency is evaluated before the job-level if, so a comment-only review
# submitted mid-run would otherwise cancel an in-flight gate and then skip
# itself — leaving the PR with no gate result and no automatic re-trigger. A
# cancelled gate result is a missing gate result; a superseded run invalidates
# itself anyway because the attestation is head-bound. The preview workflow
# keeps newest-wins cancellation, where it is correct.
concurrency:
  group: closeout-gate-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: false

jobs:
  gate:
    # Cost guard only: the gate independently re-verifies the live review
    # state, head SHA, and attestation through gh — this condition just
    # avoids spending a full run on comment-only review events. The
    # pull_request triggers and the dismissed/edited review events run
    # unconditionally: a head change or a revoked/revised approval must
    # produce a fresh gate result (the gate then BLOCKS on the
    # no-longer-APPROVED review decision rather than trusting the prior run).
    if: ${{ github.event_name == 'workflow_dispatch' || github.event_name == 'pull_request' || github.event.review.state == 'approved' || github.event.review.state == 'changes_requested' || github.event.action == 'dismissed' || (github.event.action == 'edited' && github.event.review.state == 'approved') }}
    runs-on: ubuntu-latest
    steps:
      - name: Check out reviewed head
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          # The gate re-verifies the live head via gh and BLOCKS stale
          # snapshots; the checkout must present the head being attested.
          ref: ${{ github.event.pull_request.head.sha || github.ref }}
          fetch-depth: 0

      - name: Closeout gate
        uses: ./actions/closeout
        with:
          run: full
          base-ref: ${{ github.event.inputs.base-ref || '' }}
```

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
| `output-dir` | path | *(empty)* | Evidence directory (must be outside the repository). When empty, the composite step falls back to `${{ runner.temp }}/closeout-evidence`. |
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

## Permissions

The composite action authenticates as `GH_TOKEN: ${{ github.token }}` (wired
internally — there is no `token` input) to query the live PR state and attestation.
The minimum `permissions:` block for any workflow that uses this action:

```yaml
permissions:
  contents: read
  pull-requests: read
```

`contents: read` covers the checkout; `pull-requests: read` covers the attestation and
PR-state lookups the gate makes through `gh`, needed on both `run: plan` and
`run: full`.

If you opt into `pr-comment: true`, add `pull-requests: write`:

```yaml
permissions:
  contents: read
  pull-requests: write
```

`pr-comment: true` also requires `gh` **2.31 or newer** on the runner (the comment
upsert uses `gh api --paginate --slurp`). GitHub-hosted runners ship a current `gh`;
on a self-hosted runner with an older one, every comment attempt fails with
`unknown flag: --slurp`, which reads like an unrelated tooling problem.

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
every honest not-ready state.

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
attestation exists; when it is `absent`, the plan JSON's `gateAttestationRequired`
field carries the verbatim marker line the approving reviewer must paste into their
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
`${{ runner.temp }}/closeout-evidence`, so the second run's `action-state.json`
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
- **The running gate observes its own in-progress check as unresolved.** Near the end
  of a full run, the gate reads the live PR's `statusCheckRollup` and treats every
  non-PASS check as a blocker; its own `Closeout gate` check is still `IN_PROGRESS`
  at that moment, so it blocks itself and can never reach PASS while it is a required
  check. The CLI's `classifyLivePrState` has no self-exclusion today. The practical
  workaround while this remains: do not make the `Closeout gate` check a **required**
  merge gate (require the attestation-bearing review instead, which the gate already
  re-verifies independently), or run the gate via `workflow_dispatch` after the check
  has a settled state. A proper fix threads a self-exclusion signal (the running
  check's name or run id) through `readLivePrState` so the live-state classifier omits
  the gate's own in-progress check.
- **Event triggers do not cover a base-branch advance.** The attestation is
  base-SHA-bound, so if the base branch receives a new commit while a PR's head is
  unchanged, the prior attestation no longer matches and the gate should re-run.
  GitHub fires no `pull_request` event for a base-only advance (only `synchronize`
  on head changes), so an event-triggered gate cannot observe it without polling.
  Interim control: re-run the gate via `workflow_dispatch` (or re-push/re-approve to
  fire a covered event) after a base-branch merge that affects an open, already-gated
  PR. A scheduled re-validation sweep is the natural long-term fix.
- **Runner command-file env vars reach repository-defined validation commands.** In
  `mode: engine`, the gate CLI's `buildChildEnvironment` passes `GITHUB_PATH`,
  `GITHUB_ENV`, and `GITHUB_OUTPUT` through to repository-defined commands (they are
  not credential-shaped, so the sensitive-name filter does not strip them). Those
  paths live in the isolated `RUNNER_TEMP`/workspace and carry no credentials, but a
  malicious engine check could write to `GITHUB_PATH`/`GITHUB_ENV` to alter the
  runner. Stripping these runner-control vars from the child environment is a gate-CLI
  change (out of this action's scope); until then, treat engine-mode check commands
  with the same trust discipline as any CI step that shares the runner environment.
