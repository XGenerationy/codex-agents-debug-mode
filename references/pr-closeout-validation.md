# PR Closeout Validation

Run this gate after implementation and review cleanup are finished, before claiming that a PR is
clean. This gate is mandatory for `$debug` GitHub cleanup work.

## Contents

- [Acceptance Contract](#acceptance-contract)
- [Prepare the Validation Run](#prepare-the-validation-run)
- [Deterministic Runner](#deterministic-runner)
- [Mandatory Validation Matrix](#mandatory-validation-matrix)
- [Suppression-Free Touched Files](#suppression-free-touched-files)
- [Fix and Rerun Loop](#fix-and-rerun-loop)
- [Status Semantics](#status-semantics)
- [Completion Evidence](#completion-evidence)

## Acceptance Contract

Do not finish while any requested surface reports a warning, error, block, problem, skip, or
failure. Fix the underlying cause and rerun the affected check. Do not weaken a test, rule, audit,
threshold, configuration, or validation command to obtain a passing result.

Treat zero residual risk as an evidence gate. Claim completion only when every required check has
current passing evidence, every suppression marker in the touched-file set is gone, and no known
risk remains. If validation is incomplete or an external dependency prevents proof, report the PR
as blocked. Never convert uncertainty into a clean claim.

## Prepare the Validation Run

1. Resolve the live PR base, head SHA, authoritative worktree, and repository validation commands.
2. Build the touched-file inventory from the complete PR diff plus tracked and untracked working
   changes. Refresh it after generators or formatters run.
3. Preserve unrelated user changes. Use a clean or disposable worktree to compare the PR base.
4. Inspect `package.json`, workspace manifests, `Makefile`, CI workflows, and project docs to map
   named checks to their real commands. Do not invent a test path or silently substitute a weaker
   command.
5. Record each command, exit code, relevant output, and head SHA. Redact secrets and personal data.

## Deterministic Runner

Use the skill's runner as the authoritative executor for this matrix. Start from
[`assets/pr-closeout.config.example.json`](../assets/pr-closeout.config.example.json), save a
repository-specific copy outside the checkout, and replace every command placeholder. Delete a
placeholder only when the runner can discover the authoritative package script or Make target.
Populate `requiredEnv`, `safeEnv`, service probes, ports, timeouts, artifact and health-command
proofs, resource groups, explicit qualification-safe opt-ins, and any additional ignored generated
paths before execution. Proof artifact paths must be repository-relative files that the
corresponding command refreshes and leaves non-empty. `expectedPattern` is a proof policy, not a
free-form regular expression: use `literal:<text>` for an exact literal requirement. The `hunter`
proof must use `semantic:docker-compose-running-healthy`; the runner parses Docker Compose JSON and
requires exact `running` state plus `healthy` health rather than trusting text order or substring
matches.

The true live Grafana artifact must set `semantic` to `grafana-live-result`. A query proof binds a
Grafana `/api/ds/query` request to a successful HTTP response with non-empty request queries and
response results. A render proof binds a `/render/` endpoint to an image content type, positive byte
count, and SHA-256 digest. Set `grafanaOrigin` when the proof must be restricted to a specific live
Grafana origin. Arbitrary proof regular expressions are rejected.

First resolve the plan without running commands:

```text
node <debug-skill>/scripts/pr_closeout.js --repo <worktree> --base-ref <live-base-ref> --config <config.json> --plan
```

A plan is admissible only when all 19 commands and required proofs resolve and no fixed command was
overridden. The plan prints the exact base SHA, head SHA, configuration digest, and one exact
`PR-CLOSEOUT-ATTESTATION` marker. An independent reviewer must add that marker as its own complete
line in an `APPROVED` GitHub PR review for the exact head commit. The PR author cannot attest their
own gate, and a comment, stale review, duplicate marker, or locally configured review object is not
evidence. Changing a command, proof, resource assignment, baseline setup, base, head, or digest
invalidates the review. Confirm fresh `gh` authentication, then run the same invocation without
`--plan`. By default, evidence is written under the system temporary directory as `report.json`,
`report.md`, and complete redacted files under `logs/`. A custom `--output-dir` must remain outside
the repository so writing evidence cannot dirty the validated tree.

The runner performs these safeguards automatically:

- preflights the explicit command shell, Git, Node, pnpm, Make, Docker Compose and daemon, Prisma,
  configured credentials, disk space, Redis, Grafana, and configured ports;
- compares validation-defining files with the PR base and requires an independent live GitHub
  `APPROVED` review bound to the exact base, head, configuration digest, and `not-weakened` decision;
- treats only built-in safe checks as concurrent by default; additional qualification checks require
  explicit opt-in, and checks sharing a configured resource group run serially;
- requires a clean qualification phase, and then
  reruns the complete 19-check matrix sequentially for final confirmation;
- runs Prisma generation twice and compares tracked, untracked, and configured ignored generated
  outputs to prove idempotence;
- installs frozen-lockfile dependencies in the detached base worktree before rerunning baseline-safe
  failures with the same command and tool versions; setup failure blocks any baseline label;
- hashes the complete redacted command output even when report excerpts are capped, and redacts
  environment secrets, URL credentials, and encoded variants safely across output chunk boundaries;
- terminates and awaits the complete ordinary process tree after a timeout; if termination cannot
  be proven, blocks the run and prevents the executor from starting another validation command;
- verifies refreshed, non-empty artifacts for Grafana and SBOM checks, a real Redis probe for Redis
  integration, a live Grafana probe, and explicit running/healthy evidence for `hunter`;
- refreshes the head SHA and touched-file inventory, rescans suppressions and gate changes, requires
  a clean final working tree, verifies live GitHub checks, review threads, merge state, and external
  services, then seals the repository identity and fingerprint again before `PASS`.

The runner records truth; it does not fix failures or publish changes. Fix every non-pass result,
rerun the affected command, then rerun the full runner until the final report is `PASS`.

## Mandatory Validation Matrix

Run every row. Commands shown literally must be executed literally from the repository's required
working directory. For named checks without a literal command, use the repository's authoritative
target or the test runner's narrowest correct path/filter.

| Order | Check | Required proof |
|---:|---|---|
| 1 | `git diff --check` | Exit 0 with no whitespace errors. |
| 2 | `pnpm audit --audit-level high` | Exit 0; investigate and repair every reported actionable vulnerability or warning. |
| 3 | `pnpm prisma validate` | Schema validates against the actual project configuration. |
| 4 | `pnpm prisma generate` | Generation exits 0; generated changes are reviewed and added to the touched-file inventory. |
| 5 | Focused queue registry tests | The queue registry's authoritative focused tests pass. |
| 6 | Focused producer tests | Every producer affected by the PR has focused passing evidence. |
| 7 | Focused worker tests | Every affected worker and its failure/retry behavior pass focused tests. |
| 8 | Focused API route tests | Affected route tests pass for success, validation, authorization, and relevant error paths. |
| 9 | Real Redis integration test | Exercise a real Redis service, not a mock. If infrastructure is unavailable, status is `BLOCKED`, not skipped or passed. |
| 10 | Scoped Biome on touched files | Run the project-authoritative Biome check on the complete touched-file set with no ignored diagnostics. |
| 11 | Typecheck | Run the repository's full authoritative typecheck; exit 0 with no hidden errors. |
| 12 | Playwright smoke | Run `playwright-smoke` or the canonical equivalent through a real browser surface. |
| 13 | Grafana render | Run the repository's deterministic Grafana render check and inspect the produced output. |
| 14 | `make smoke` | Exit 0 and inspect warnings, not only the exit code. |
| 15 | `make sbom` | Exit 0; verify the SBOM is generated, non-empty, current, and contains no reported generation problem. |
| 16 | `make audit` | Exit 0 with every finding resolved rather than suppressed. |
| 17 | True live Grafana render | Render against running Grafana and its real data source; verify a non-empty result and no Grafana, query, or data-source error. |
| 18 | `docker compose up -d --build hunter` | Exit 0; confirm the `hunter` service is running and healthy using the project's health evidence and logs. |
| 19 | `make pr-check` | Run the complete PR gate last and classify known baselines with proof. No failing baseline may be counted as a pass. |

After any fix, rerun the directly affected check. When all rows appear clean, rerun the entire matrix
from a consistent state so the final evidence belongs to the final head and final generated output.

## Suppression-Free Touched Files

Scan every file in the complete touched-file inventory, whether old or newly created, for at least:

- `skipcq`
- `biome-ignore`
- `eslint-disable`
- `@ts-ignore`
- `@ts-expect-error`
- `noqa`
- `nosec`
- `# type: ignore`
- config-level rule disabling, per-file ignores, exclusions, threshold reductions, or test skips
  whose purpose is to conceal an applicable diagnostic

Use a case-insensitive exact text search and inspect the full changed configuration, not only source
comments. For every match:

1. remove the suppression,
2. reproduce the diagnostic it concealed,
3. fix the underlying code, test, dependency, schema, or configuration problem,
4. rerun the narrow check, and
5. rescan the touched-file set.

Do not replace one suppression mechanism with another. Do not exclude a touched file from Biome,
typechecking, tests, audit, or coverage to make the gate green. The final suppression scan must return
no matches in the touched-file set.

## Fix and Rerun Loop

For each non-clean result:

1. Preserve the command, raw failure, exit code, and environment.
2. Classify the failing layer and identify the root cause.
3. Make the smallest correct fix without weakening validation.
4. Add or strengthen a regression guard when test infrastructure exists.
5. Rerun the focused check until clean.
6. Rerun dependent checks whose inputs or generated artifacts changed.
7. Repeat the full matrix before closeout.

Never stop after a retry happens to pass. Investigate intermittent results and prove the source of
nondeterminism. Never use a timeout increase, retry, skip, mock, fallback, or baseline label as a
substitute for a root-cause fix.

## Status Semantics

Use these labels exactly and attach evidence:

- **PASS**: The required command ran on the final head and produced clean evidence.
- **FAIL**: The command or observed behavior is incorrect. Fix it; do not close out.
- **WARN / ERROR / PROBLEM**: Treat as failing even if the process exits 0. Fix and rerun.
- **SKIPPED**: Not acceptable for an applicable required check. Run it or mark the task blocked.
- **BLOCKED**: Proof cannot be completed because of a verified external or environment dependency.
  Name the dependency and required next action; do not claim the PR is clean.
- **BASELINE**: Reproduced unchanged on the PR base in a clean or disposable worktree. Record the
  base SHA and exact matching evidence. Under the zero-residual-risk gate, a failing baseline still
  prevents completion until fixed within authorized scope or the user explicitly changes the gate.
- **N/A**: Use only when repository evidence proves the component does not exist or cannot be affected;
  explain why. Do not use N/A as a synonym for inconvenient, unavailable, or skipped.

## Completion Evidence

The final report must identify the validated base SHA, head SHA, configuration digest, preflight,
qualification evidence, tool versions, and exactly one final row per mandatory check with:

- command or authoritative target,
- PASS, FAIL, BLOCKED, or BASELINE status,
- exit code and concise evidence,
- fixes made and reruns performed,
- baseline comparison when applicable.

Also report the independent gate attestation, final repository seal, touched-file suppression scan,
and live PR state: unresolved threads, checks, approvals, ruleset or branch-protection blockers, and
external services. Finish only when all 19 rows are PASS, the suppression scan is empty, the live PR
surfaces and repository seal are clean, and no known residual risk remains. A FAIL must be fixed; a
BLOCKED or BASELINE result prevents completion and must retain exact evidence. Continue fixing
whenever the remaining work is within the authorized PR scope.
