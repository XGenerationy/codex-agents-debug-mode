# Debug Evidence Action — Design

**Date:** 2026-08-13
**Cycle:** 4 (roadmap: bring the evidence-first debugging assets to CI)
**Status:** Approved design — implementation follows the plan derived from this spec
**Branch:** `feat/debug-evidence-action` (from `af89573`, the merged closeout-action tip)

## Goal

Package the debug collector and evidence tools (cycles 1–2: `scripts/debug_server.js`,
`scripts/debug_evidence.js`, `scripts/debug_viewer.js`, `scripts/debug_diff.js`) as a reusable
composite GitHub Action at `actions/debug-evidence/`, so any workflow can wrap a failing
command in an instrumented debugging session and get an evidence artifact plus a rendered
Step Summary — the same way cycle 3 brought the closeout gate to CI at `actions/closeout/`.

## Consumer story

One action call wraps one debugging session:

```yaml
- uses: XGenerationy/codex-agents-debug-mode/actions/debug-evidence@<40-hex-sha>
  with:
    run: npm test -- --filter flaky-suite
```

The action starts the collector, runs the consumer's command with collector credentials
injected, captures the session evidence, renders a report to the Step Summary, uploads the
evidence artifact, tears the collector down, and then (by default) mirrors the wrapped
command's exit status.

## Non-goals

1. No start/stop action pair — the wrap-one-command story is the only surface this cycle.
2. No capture-on-failure mode consuming a pre-existing collector.
3. No marketplace publishing, tags, or releases (deferred until both actions have soaked;
   one release event should version both).
4. No changes to any `pr_closeout_*` script or to the closeout action.
5. No multi-session diff rendering in CI (debug_diff needs two refs; the dogfood produces
   one session — single-session reporting is this cycle's renderer).
6. No Windows/macOS runner support commitment: steps use `shell: bash` and are tested on
   Linux runners; other runners are best-effort (same posture as the closeout action).

## Architecture

`actions/debug-evidence/` clones the proven closeout-action shape:

- **`action.yml` is pure wiring** — inputs, outputs, and a fixed step chain. Every step
  either calls `support.js` with a subcommand or invokes a SHA-pinned third-party action.
  No logic in YAML expressions beyond input defaulting and `if:` guards.
- **`support.js` holds all logic** — zero dependencies, driven by `DEBUG_ACTION_*` env
  vars, every seam injectable (spawn, env-file paths, clock, collector module), fully
  covered by hermetic `node:test` tests in `support.test.js`.
- **State between steps** travels via `<output-dir>/action-state.json` (the closeout
  `action-state.json` pattern). The state file lives in the job-scoped runner temp area
  and is never copied into the artifact.
- **No `GH_TOKEN` anywhere.** The action makes no GitHub API calls. Artifact upload uses
  the pinned `upload-artifact` action, which needs no token input.

### action.yml contract

Inputs:

| input | default | meaning |
|---|---|---|
| `run` | (required) | Command to execute under instrumentation, passed to `bash -c` in `working-directory`. |
| `working-directory` | `.` | Where the wrapped command runs. |
| `session-name` | `ci-debug` | Session label recorded in evidence and the report. |
| `fail-on-command-failure` | `true` | `true`: the action's final step fails when the wrapped command exited non-zero. `false`: command failure is reported but does not fail the action. |
| `output-dir` | `${{ runner.temp }}/debug-evidence` | Evidence staging dir; becomes the artifact. Same defaulting expression in every referencing site. |
| `artifact-name` | `debug-evidence` | Name of the uploaded artifact. |
| `node-version` | `24` | Passed to pinned setup-node. |
| `port` | `8787` | Collector port (`DEBUG_PORT`). README documents self-hosted collision risk. |
| `redact-names` | `''` | Comma/space-separated additional `DEBUG_REDACT_NAMES` entries for the collector env. |
| `max-events` | `''` (collector default) | Per-session event-count limit override. |
| `max-bytes` | `''` (collector default) | Total evidence byte-limit override. |
| `hypothesis-id` | `''` | Optional: when set, `run` posts one `status: OPEN` hypothesis line (launch-token capability) and injects `DEBUG_HYPOTHESIS_ID` into the wrapped command's env. |
| `hypothesis-title` | `''` | Optional title for that hypothesis line; ignored when `hypothesis-id` is empty. |

Outputs (all written by `support.js` via `GITHUB_OUTPUT`; each is empty until its
producing step has run — documented per-output, closeout style):

| output | producer | meaning |
|---|---|---|
| `command-exit-code` | `run` step | Exit code of the wrapped command (string). |
| `session-id` | `run` step | Collector session id for the wrapped run. |
| `event-count` | `report` step | Events captured in the session. |
| `report-path` | `report` step | Absolute path of `report.md` inside `output-dir`. |

Step chain (composite, `shell: bash` everywhere):

1. **setup-node** — pinned `actions/setup-node` at the same 40-hex SHA the closeout action
   uses (cross-verified both directions at plan time).
2. **start** — `support.js start`: spawns the detached boot shim, waits for readiness,
   persists state. Failure here fails the action immediately; no wrapped command runs.
3. **run** — `support.js run`: mints a session, executes the wrapped command with injected
   collector env, records the exit code in state and `GITHUB_OUTPUT`. This step itself
   never fails on command failure (the decision is deferred to `finish`).
4. **report** — `support.js report`, `if: always()`: copies session evidence into
   `output-dir`, renders `report.md` via `scripts/debug_report.js`, appends the report to
   `GITHUB_STEP_SUMMARY`, writes `event-count`/`report-path`. If state records no
   successful `start`, the subcommand no-ops successfully (finish already owns the
   failure decision for a failed start).
5. **upload-artifact** — pinned, `if: always()`, `if-no-files-found: ignore`, uploads
   `output-dir` as `artifact-name`.
6. **teardown** — `support.js teardown`, `if: always()`: kills the boot-shim PID from
   state; an already-dead process is success, a missing state file is success (start
   never ran). Never masks earlier failures.
7. **finish** — `support.js finish`, `if: always()`: decides the action's exit per the
   error taxonomy below.

### Boot shim and collector lifecycle

The collector CLI exposes no limit overrides, so the action uses the programmatic path:
`actions/debug-evidence/collector_boot.js` (action-local, not payload) requires
`scripts/debug_server.js` and calls `createDebugServer` with limits derived from
`DEBUG_ACTION_MAX_EVENTS` / `DEBUG_ACTION_MAX_BYTES`, binding loopback only.

- `start` spawns the shim **detached**, with the **full inherited job environment** plus
  `DEBUG_PORT`, `DEBUG_REDACT_NAMES` (input-extended). Env inheritance is a correctness
  requirement: the collector's redaction snapshot must include job secrets so anything the
  wrapped process logs is scrubbed. The README states this invariant explicitly.
- The shim prints one structured JSON line (port, pid, launch token, project dir) on
  ready; `start` also polls `/health` for `ready:true` with a bounded timeout
  (`DEBUG_ACTION_READY_TIMEOUT_MS`, default 15000). Timeout ⇒ infra-failure exit.
- `start` writes `action-state.json`: `{ nonce, pid, port, launchToken, projectRoot,
  sessionName, hypothesisId, hypothesisTitle, failOnCommandFailure }` (later subcommands
  extend it with the session/command/capture results). *(Amended after Task 3 spec
  review: the original sketch listed five fields and `projectDir`; the byte-authoritative
  plan ships the superset above.)* The state file stays in runner temp, is never
  uploaded, and its token values never appear in outputs, summaries, or logs.
- `run` mints a session via `POST /session` with the launch token, then executes the
  wrapped command with exactly three injected variables: `DEBUG_LOG_URL`
  (`http://127.0.0.1:<port>/log`), `DEBUG_SESSION_ID`, and `DEBUG_SESSION_TOKEN` —
  plus `DEBUG_HYPOTHESIS_ID` when the `hypothesis-id` input is set. *(Amended during
  planning: SKILL.md documents no env vars for instrumented processes — its snippets use
  inline `REPLACE_WITH_*` constants — so the action defines this convention, reusing the
  names SKILL.md already uses as constants. `POST /log` carries the session id in the
  body, so the wrapped process needs three values, not two.)* The launch token is never
  exposed to the wrapped command.
- Optional `hypothesis-id` (+ `hypothesis-title`) inputs *(amended during planning)*:
  `POST /hypothesis` requires the launch token, which the wrapped command never gets —
  so when `hypothesis-id` is set, `run` itself posts one `status: OPEN` hypothesis line
  before executing the command and injects `DEBUG_HYPOTHESIS_ID` so the wrapped process
  can tag its events. The action never posts any other status: verdicts remain
  human/agent judgment, so the report renders whatever statuses the session actually
  recorded (the CI dogfood shows `OPEN`).
- `teardown` kills the shim PID; hosted runners also reap the process tree at job end.
  The README documents that self-hosted runners rely on the teardown step (and on the
  collector's own 15-minute idle timeout as a backstop).

### Evidence artifact — clean by construction

`report` **copies** the session log (`.debug/debug-<session-id>.log` — NDJSON content,
`.log` extension) plus rendered `report.md` and machine `report.json` into a fixed
evidence child of `output-dir`; the upload step enumerates exactly those well-known
filenames (closeout pattern), never a bare directory. `action-state.json` lives at the
`output-dir` root — outside the evidence child — because it carries the launch token;
it is never enumerated in the upload path block. The collector's `.debug/` internals
(claim, port, salt, any token files) are never copied, so the token-exfiltration hazard
is closed structurally. `support.test.js` pins that the staged evidence child contains
no token byte-sequence and that the upload path block never references
`action-state.json` or a bare directory.

## Security invariants

1. Collector binds `127.0.0.1` only; no CI service container, no exposed port.
2. Launch token: state file only. Session token: wrapped command env only. Neither ever
   reaches outputs, Step Summary, logs, or the artifact.
3. The collector inherits the full job env at start so redaction covers job secrets;
   `redact-names` extends, never replaces, that coverage.
4. All rendered log text in `report.md` / Step Summary passes the same escaping
   discipline as `debug_diff` (report structure reflects the renderer, never log content).
5. Every `uses:` in `action.yml` and the dogfood workflow is 40-hex SHA-pinned; the
   workflow declares least-privilege top-level `permissions` (`contents: read`). The
   repo validator enforces both automatically.
6. Caps on rendered rows are announced ("…and N more"), never silent (closeout lesson).

## Exit semantics

| condition | action result |
|---|---|
| start failure (spawn error, ready timeout, port busy) | fail, infra-error message; wrapped command never runs |
| wrapped command non-zero, `fail-on-command-failure: true` | fail: `command exited <code>` |
| wrapped command non-zero, `fail-on-command-failure: false` | succeed; exit code in the `command-exit-code` output and visible in the step log (the wrapped command runs with inherited stdio). *(Amended after Task 5 spec review: the summary carries evidence only — `report.md` stays a deterministic render of the session, and the exit code's surfaces are the output and the log.)* |
| evidence capture/report failure | fail (evidence integrity is the product; fail-closed) |
| collector died before capture | fail with diagnostic (partial evidence still staged if readable) |
| teardown failure after otherwise-green run | fail with diagnostic (leaked process on self-hosted is a real defect) |

`finish` evaluates the recorded state fail-closed: an absent or unparsable state file, or
a state file with no recorded command result after a successful `start`, is an
infra-failure, never a pass. Unknown `fail-on-command-failure` values fail (only the
strings `true`/`false` are accepted).

## scripts/debug_report.js (payload, dual-mode)

Single-session renderer over the shared `debug_evidence.js` core, following the
viewer/diff conventions:

- Input: a session NDJSON path (or project dir + session id, same resolution helpers as
  the existing tools).
- TTY: human-readable summary (layout consistent with `debug_viewer`'s aesthetic).
- Piped default: markdown; `--format=md` and `--format=json` explicit. JSON carries
  `schema: 1`.
- Sections: session metadata (session id plus entry/event/hypothesis-line counts —
  the evidence schema carries no session-name field, and duration is left underived),
  per-hypothesis lifecycle blocks (heading + bullets) showing recorded statuses only —
  the renderer never classifies or invents a verdict — then capped + announced
  tail-event excerpts, all content escaped in md/TTY via the shared
  `escapeMarkdownText`. *(Amended after Task 2 spec review: the original wording
  promised name/duration metadata and a literal table; the plan — the byte
  authority — renders counts and heading+bullet blocks instead.)*
- Deterministic for identical input bytes (stable ordering, no timestamps beyond those in
  the evidence).
- Payload census: 41 → 43 (`debug_report.js` + `debug_report.test.js`), bumped in
  `tools/validate_repository.js` with the history comment extended in the same commit.
- README and SKILL.md gain the tool alongside viewer/diff (dual-mode documented).

## Demo and dogfood workflow

- `actions/debug-evidence/demo/repro.js` (action-local, outside the payload census): a
  deterministic scripted session — seeded synthetic bug, posts tagged events (via
  `DEBUG_HYPOTHESIS_ID`), untagged noise, and one secret-shaped value proving redaction,
  then exits 1. *(Amended during planning: the wrapped command holds only the session
  token, so it cannot post hypothesis/verdict lines itself — the dogfood instead sets
  `hypothesis-id`, so the action posts the `OPEN` line and the report exercises the
  hypothesis table with the truthful `OPEN` status.)* Clearly labeled DEMO in its output
  and in the rendered report title.
- `.github/workflows/debug-evidence-demo.yml`: `pull_request` + `workflow_dispatch`,
  top-level `permissions: contents: read`, per-ref concurrency with
  `cancel-in-progress: true` (advisory demo — cancellation is safe, unlike the gate),
  `fetch-depth: 1` (the action needs no history), invokes the local action via
  `uses: ./actions/debug-evidence` with `fail-on-command-failure: false` and
  `artifact-name: debug-evidence-demo`.
- **Integration decisions (recorded here deliberately):**
  1. The demo workflow IS added to the gate's `workflow_run` retry-forwarder list
     (`["Validate", "Closeout preview"]` → plus `"Debug evidence demo"`). *(Amended
     during planning — the original decision misread the forwarder's purpose: it exists
     to re-run the GATE after the gate correctly BLOCKED on a sibling workflow's
     then-pending check. A per-PR demo is exactly such a sibling; omitting it would
     leave the gate stuck red whenever an approval lands while the demo is still
     running — the CodeRabbit PR7 #6YW9UP gap, reopened.)*
  2. The closeout gate's self-exclusion is re-verified against the new workflow name in
     the implementation battery (the exclusion logic was reworked five times in PR #7 —
     treat it as fragile and pin the interaction with a test or a documented manual check).
  3. The gate-scan advisory will flag the new workflow/action files as additive changes —
     as with cycle 3, the PR review is the designed answer to that advisory.

## Testing strategy

All hermetic `node:test`, one invocation at a time (established battery discipline):

1. `support.test.js`: subcommand tests with injected seams; lifecycle tests against a
   **real loopback collector** via the importable `createDebugServer` (ephemeral port);
   token-hygiene pins (no token bytes in staged artifact dir, outputs, or summary);
   exit-taxonomy table tests incl. fail-closed unknowns; teardown idempotence.
2. `debug_report.test.js`: fixture sessions → pinned md/json output bytes; TTY vs piped
   mode switch; escaping pins (hostile log content never alters report structure); cap
   announcement boundaries (at cap: no announce; cap+1: announced).
3. `action.yml` structural pins (in `support.test.js`, closeout style): wiring-only steps,
   40-hex pins, `output-dir` default expression identical in all referencing sites,
   `if: always()` on report/upload/teardown/finish.
4. Demo determinism: two runs of `repro.js` produce byte-identical evidence modulo
   timestamps/ids, and the rendered report is stable.
5. Repo battery: `npm test` green, `npm run validate` green with census 43, scan clean
   apart from the designed additive-only gate-scan advisory.

## Execution pipeline (cycle 4 process)

Per the maintainer's directive: implementation subagents run **Opus 5 at max effort**;
spec-compliance review per task as before; per-task **code review by Codex** via
`/codex:review` (fallback: the `codex:rescue` shared-runtime skill with a review brief).
All review decisions are recorded as spec/plan amendments before code moves. Final
whole-implementation review precedes the finishing options.

## Roadmap notes

- Marketplace publishing (deferred) should version `actions/closeout` and
  `actions/debug-evidence` in one release event; first release freezes `ACTION_MARKER`.
- The probe-catalog question (config-extensible vs engine-selectable fixed additions)
  remains a design-first backlog item; nothing in this cycle touches it.
- A future two-session mode (baseline vs fix evidence, `debug_diff --format=md` in CI)
  builds naturally on this action once a second session source exists.
