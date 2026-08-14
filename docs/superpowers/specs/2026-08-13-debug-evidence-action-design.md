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
| `event-count` | `run` step | Events captured in the session. |
| `report-path` | `run` step | Absolute path of `report.md` inside `output-dir`. |
| `evidence-digest` | `run` step | SHA-256 of each staged evidence file. A convenience copy of the step-log digests, never the trust anchor (see the artifact section). |

*(Table corrected, Task 6: capture moved from `report` into `run` in Task 5 round
6, so every evidence-asserting output is produced by `run`. Output existence does
not imply authenticity — a red `run` still publishes outputs describing labeled
partial evidence.)*

Step chain (composite, `shell: bash` everywhere):

1. **setup-node** — pinned `actions/setup-node` at the same 40-hex SHA the closeout action
   uses (cross-verified both directions at plan time).
2. **start** — `support.js start`: spawns the detached boot shim, waits for readiness,
   performs the whole launch-token lifecycle in memory (occupant auth, session mint,
   the optional `OPEN` hypothesis post), emits the responder public verification key
   as a step output, persists state. Failure here fails the action immediately; no wrapped
   command runs. *(Rewritten, Task 5 rounds 3–4; the mint and post formerly lived in
   `run`.)*
3. **run** — `support.js run`: the trusted process. It receives the responder
   verification key in its env *before the wrapped command exists*, clears stale
   staged files, executes the wrapped command with collector env injected from
   state and the runner control plane stripped, and then — in the same process,
   still holding the authentic key — captures the session over a
   responder-authenticated, bounded live read, validates the hypothesis set,
   renders `report.md` / `report.json` from the in-memory bytes via
   `scripts/debug_report.js`, hashes all three payloads in memory, stages them,
   prints the digests, and writes
   `command-exit-code`/`session-id`/`event-count`/`report-path`/`evidence-digest`.
   Any integrity failure exits 3 with nothing staged — a failed composite step
   cannot be un-failed by a later one. Command failure alone never fails this step
   (that decision stays with `finish`). *(Rewritten, Task 5 round 6: capture moved
   here from `report`, which no post-command step can be trusted to perform.)*
4. **report** — `support.js report`, `if: always()`: publish-only and key-free.
   It appends the staged report to `GITHUB_STEP_SUMMARY` when `run` recorded a
   capture, and otherwise ensures no stale evidence remains staged and records the
   diagnostic `finish` needs. It performs no capture, holds no credential, and
   makes no integrity decision. If state records no
   successful `start`, the subcommand no-ops successfully (finish already owns the
   failure decision for a failed start).
5. **upload-artifact** — pinned, `if-no-files-found: ignore`, uploads the three
   enumerated payloads from `steps.start.outputs.evidence-dir` as `artifact-name`,
   guarded by `always() && steps.start.outputs.evidence-dir != ''`. *(Rewritten,
   Task 6 round 2: both come from a PRE-COMMAND `start` output, never from
   `output-dir`, from `report`'s outcome, or from any output written after the
   wrapped command has run.)*
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
- The shim prints one structured JSON line (port, pid, launch token, responder
  public verification key, project dir) on
  ready; `start` also polls `/health` for `ready:true` with a bounded timeout
  (`DEBUG_ACTION_READY_TIMEOUT_MS`, default 15000). Timeout ⇒ infra-failure exit.
- `start` performs the whole launch-token lifecycle in memory — handshake, mask,
  occupant auth (`probeLaunchToken`), `POST /session` mint, session-token mask, and the
  optional single `POST /hypothesis` `OPEN` line — then writes `action-state.json`:
  `{ nonce, pid, port, projectRoot, sessionName, sessionId, sessionToken, hypothesisId,
  hypothesisTitle, failOnCommandFailure }` — NO `launchToken` field exists. *(Rewritten,
  Task 5 round 3; earlier shapes persisted the launch token.)* Later subcommands extend
  the state with command/capture results. The state file stays in runner temp, is never
  uploaded, and its token values never appear in outputs, summaries, or logs.
- `run` executes the wrapped command with exactly three variables injected from
  state: `DEBUG_LOG_URL` (`http://127.0.0.1:<port>/log`), `DEBUG_SESSION_ID`, and
  `DEBUG_SESSION_TOKEN` — plus `DEBUG_HYPOTHESIS_ID` when the `hypothesis-id` input
  is set. The session was already minted by `start`; `run` never talks to the
  collector. *(Amended during planning; mint moved to `start` in Task 5 round 3.
  SKILL.md documents no env vars for instrumented processes — its snippets use
  inline `REPLACE_WITH_*` constants — so the action defines this convention, reusing the
  names SKILL.md already uses as constants. `POST /log` carries the session id in the
  body, so the wrapped process needs three values, not two.)* The launch token no
  longer exists anywhere when `run` begins.
- Optional `hypothesis-id` (+ `hypothesis-title`) inputs *(amended during planning;
  the post moved to `start` in Task 5 round 3)*: `POST /hypothesis` requires the
  launch token, which only `start` ever holds — so when `hypothesis-id` is set,
  `start` posts one `status: OPEN` hypothesis line at mint time and `run` injects
  `DEBUG_HYPOTHESIS_ID` so the wrapped process
  can tag its events. The action never posts any other status: verdicts remain
  human/agent judgment, so the report renders whatever statuses the session actually
  recorded (the CI dogfood shows `OPEN`).
- `teardown` kills the shim PID; hosted runners also reap the process tree at job end.
  The README documents that self-hosted runners rely on the teardown step (and on the
  collector's own 15-minute idle timeout as a backstop).

### Evidence artifact — clean by construction

`run` **stages** the session log (`.debug/debug-<session-id>.log` — NDJSON content,
`.log` extension) plus rendered `report.md` and machine `report.json` into an
evidence child of `output-dir` *(it was `report` that copied them until capture moved
into `run` in Task 5 round 6)*; the upload step enumerates exactly those well-known
filenames (closeout pattern), never a bare directory.

*(Rewritten, Task 6 round 1.)* That child is **invocation-scoped**:
`debug-evidence-files-<invocation nonce>`, resolved from the nonce the step was
handed and refused outright if that value is not a safe path segment. A fixed child
name is a rendezvous point for invocations sharing an `output-dir` — the default one
under `runner.temp`, or a reused custom directory on a self-hosted runner — and
everything downstream keys off three fixed filenames: one invocation's entry clear
destroys another's evidence, a concurrent restage lands in exactly the names the
upload step enumerates, and a stale entry that cannot be unlinked (a directory where
`session.log` belongs) fails `report` while the `always()` upload still expands that
directory into the artifact.

*(Rewritten again, Task 6 round 2.)* The upload step's guard AND its `path:` entries
both come from `start`'s `evidence-dir` step output — published, with the nonce it is
derived from, before `start` validates anything and therefore before the wrapped
command exists. A value published by `run` cannot serve here however carefully it is
computed: `run` writes its step outputs AFTER the command has executed, into a file
under `RUNNER_TEMP/_runner_file_commands` that the command can append to itself
(removing `GITHUB_OUTPUT` from the child's environment hides the variable, not the
file). The command can claim any key `run` does not write, and for a key `run` does
write it can open a heredoc whose delimiter is the exact line `run` is about to
append, swallowing it as body and leaving an attacker-chosen multiline path set with
an open gate. `run` therefore publishes NO upload-controlling output at all; the gate
is empty only when `start` never executed, and `if-no-files-found: ignore` covers the
case where `start` ran but nothing was staged. It is deliberately NOT gated on
`report` succeeding: a Step Summary failure must never suppress evidence `run` proved.
A second residual follows from same-user staging and is documented rather than
prevented: a hostile command can create files INSIDE the invocation-scoped directory,
so the artifact may carry payloads this action never staged. The trust unit answers
it — evidence is bytes whose SHA-256 matches a digest line the trusted `run` process
printed to its own step log; a planted file has no backing digest, and a `run` that
staged nothing prints none. Known and unprevented: `actions/upload-artifact` v4.6.2 exposes no symlink control — its seven
inputs carry none, and its glob options hardcode `followSymbolicLinks: true` and
`implicitDescendants: true` (verified against the pinned SHA) — so a hostile swap
inside the staging window can substitute a symlink to an unrelated readable file and
pull its bytes into the artifact. As with every other post-staging swap, the defence
is detection: the digest `run` printed to its own step log before staging does not
match what the artifact then carries. `action-state.json` lives at the
`output-dir` root — outside the evidence child — and is never enumerated in the
upload path block. *(Corrected, Task 6 round 2: it no longer carries the launch
token — that token has lived only in `start`'s memory since Task 5 round 3 — but
it does carry the session token and the invocation nonce, so it stays out of the
artifact.)* The collector's `.debug/` internals
(claim, port, salt, any token files) are never copied, so the token-exfiltration hazard
is closed structurally. `support.test.js` pins that the staged evidence child contains
no token byte-sequence and that the upload path block never references
`action-state.json` or a bare directory. *(Added, Task 5 round 3; hardened round 4.)*
Because upload happens in a later step of the same job, a hostile wrapped command's
detached child could rewrite staged files in the window — inherent to same-user
composite staging and outside the prevention boundary. `run` therefore validates,
renders, and SHA-256-hashes all three payloads from one immutable in-memory buffer
(the live read is bounded: absolute deadline, byte cap, idle timeout), writes the
staged files only afterwards as write-only sinks, and prints the digests to the step
log (immutable once streamed) and the `evidence-digest` output — the recorded digests
always describe the intended bytes, so any post-staging swap is detectable against
the artifact. *(Wording fixed, Task 5 round 8.)* The artifact is therefore NOT
self-authenticating, and neither the artifact nor the Step Summary alone is
authoritative: the unit of trust is **the artifact plus the matching digest from
the trusted `run` process's step log**. Duplicate or conflicting `evidence-sha256`
lines invalidate the artifact; the `evidence-digest` output is a convenience, not
the trust anchor. Output existence likewise does not imply authenticity — a red
`run` still publishes outputs describing labeled partial evidence, and the failed
`run` outcome is the provenance signal.

## Security invariants

**Platform prerequisite (added, Task 6 round 5).** Every in-process guarantee
below — the trusted `run` process, the memory-held verification key, the
collector's private key — assumes the host RESTRICTS same-UID `ptrace`
attachment (Linux Yama `ptrace_scope >= 1`, the default on GitHub-hosted
runners). On a host permitting classic same-UID attachment (`ptrace_scope = 0`,
or a container granted `CAP_SYS_PTRACE`), a hostile native wrapped command can
attach to the `run` process or to the collector — whose pid is recorded in state
— and inject code or read signing state, defeating authenticated evidence
outright. Neither process is made non-dumpable. The action DETECTS the policy and
labels the evidence when the prerequisite is not met (see invariant 11); it does
not create the boundary. Self-hosted configurations permitting same-UID
attachment are OUTSIDE the supported threat model.

1. Collector binds `127.0.0.1` only; no CI service container, no exposed port.
2. *(Rewritten, Task 5 round 3.)* The launch token exists ONLY in the `start` step's
   process memory — it is never written to disk, so a same-user wrapped command has
   nothing to steal; after `start` returns, no credential capable of posting hypothesis
   lines exists anywhere in the job. The session token is the wrapped command's only
   credential (env-injected; also recorded in state for `run`'s authenticated read
   after the command exits — the collector grants it same-session read scope).
   *(Corrected, Task 6 round 3: the authenticated read moved to `run` in Task 5
   round 6.)* Neither token ever reaches
   outputs, Step Summary, logs, or the artifact; both are runner-masked at first
   existence.
3. The collector inherits the full job env at start so redaction covers job secrets;
   `redact-names` extends, never replaces, that coverage.
4. All rendered log text in `report.md` / Step Summary passes the same escaping
   discipline as `debug_diff` (report structure reflects the renderer, never log content).
5. Every `uses:` in `action.yml` and the dogfood workflow is 40-hex SHA-pinned; the
   workflow declares least-privilege top-level `permissions` (`contents: read`). The
   repo validator enforces both automatically.
6. Caps on rendered rows are announced ("…and N more"), never silent (closeout lesson).
7. *(Added, Task 5 round 2.)* Captured evidence's hypothesis lines must equal EXACTLY
   the set the action itself posted (none, or the single `OPEN` line from
   `hypothesis-id`); any other hypothesis line is forged by definition — the action is
   the only legitimate launch-token holder in the wrap-one-command model — and capture
   refuses the evidence. Events remain attacker-authored by design. The action's own
   wiring vars (`DEBUG_ACTION_*`) are stripped from the wrapped command's env.
8. *(Added, Task 5 round 2.)* The collector keeps an incremental SHA-256 of every byte
   it appends per session and verifies the on-disk content against it before serving
   `GET /sessions/:id/logs` — a same-length in-place rewrite is refused
   (`session_log_tampered`, 409 replaced-class), closing the gap in
   metadata-plus-byte-count identity checking.
9. *(Added, Task 5 round 4; rewritten round 5.)* Capture authenticates the RESPONDER
   with an asymmetric proof: the boot shim generates an Ed25519 keypair at boot; the
   PRIVATE key exists only in the collector process's memory (never serialized —
   not in the handshake line, not in state, not in any output), and `start` emits
   the PUBLIC verification key as a step output — parsed into runner memory from
   `start`'s `GITHUB_OUTPUT` before the wrapped command ever runs, and delivered to
   `run`'s env by the runner itself. *(Corrected, Task 6 round 2: `report` never
   receives or consumes it — see the round-6 restructure in the step chain.)* The channel guards the key's INTEGRITY, not
   its secrecy: disclosure of a verification key is harmless, but only runner memory
   prevents a same-user process from substituting its own keypair — the key is never
   read from state or any attacker-writable file. The collector signs a
   domain-separated canonical record — method, the exact request target as received,
   the challenge nonce, and the SHA-256 of the served bytes — and `run` verifies
   the signature over the record it INTENDED: the unfiltered full-session target,
   its own fresh nonce, the hash of the received bytes. A counterfeit cannot sign
   (no private key); a filtered relay through the real collector signs a different
   target and fails verification (the collector is not a signing oracle for
   incomplete responses); a recorded proof cannot answer a fresh nonce.
   Attacker-writable state (`port`/`sessionId`/`sessionToken`) is routing data,
   never a capture trust anchor. The signing key authorizes nothing — it only signs
   responses. *(Extended, Task 5 round 6.)* The verification key is consumed ONLY
   inside the `run` step's process, whose environment is resolved before the
   wrapped command exists and whose memory a child cannot rewrite. It never
   crosses a step boundary after the wrapped command has executed, because no
   post-command step's environment can be trusted (see invariant 10).
10. *(Added, Task 5 round 6; SCOPE MADE EXPLICIT, Task 6 round 3.)* **The
    integrity guarantees in this document hold for the FIRST — in practice, the
    only — invocation of this action in a job.** A hostile wrapped command can
    poison every LATER
    step of the job — it can reach the runner's command files and set `BASH_ENV`,
    which non-interactive bash sources at shell startup, after step-level `env:`
    has been resolved. That reaches a *second* invocation's `start` step too:
    its bash shell sources the attacker's code before `start` runs, and that code
    can append a last-wins `evidence-dir=` line to the second invocation's own
    `GITHUB_OUTPUT`, so even pre-command step outputs stop being trustworthy once
    an instrumented command has executed in the job. Per-instance step outputs
    prevent accidental cross-invocation inheritance; they do NOT provide
    adversarial isolation. Same-job secure reuse is not achievable through this
    runner channel: run a second instrumented command in a SEPARATE JOB.
    This is inherent to executing an arbitrary command in
    GitHub Actions and applies to every action sharing that job. The action's
    answer is structural rather than preventive: every evidence decision happens
    inside `run`, before any such poisoning can take effect, and an integrity
    failure exits 3 from `run` itself — a failed composite step cannot be
    un-failed by a later step, so a poisoned `report`/`finish` cannot manufacture
    green. The wrapped command's environment additionally strips `GITHUB_ENV`,
    `GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STATE`, and `GITHUB_STEP_SUMMARY`
    alongside `DEBUG_ACTION_*`; this raises the bar (the command must enumerate
    runner-temp command files) and is documented as such, never as a boundary.
    Command-failure semantics are deliberately outside this model: a hostile
    command can always choose its own exit code. *(Extended, Task 6 round 1.)*
    Invocation identity travels as a `start` STEP OUTPUT, never through
    `GITHUB_ENV`: env-file values persist to every later step of the job and DO
    appear in the expression `env` context (verified against the runner source —
    an earlier note in this design claiming otherwise was wrong), so a
    job-global nonce lets a failed later invocation inherit an earlier one's
    identity and claim its evidence. Step outputs are per-invocation by
    construction. The staged evidence child is likewise invocation-scoped, and
    the upload step's guard and paths come from that same PRE-COMMAND `start`
    output. *(Corrected, Task 6 round 2: an earlier form of this note had the
    upload step trusting `run`'s post-command outputs. It cannot — `run` writes
    them after the wrapped command has executed, into a runner command file the
    command can append to, so a heredoc whose delimiter is the exact line `run`
    will write swallows it and leaves the attacker holding both the path set and
    the gate. Only pre-command outputs are outside the command's reach.)* *(Extended, Task 5 round 7.)*
    EVERY evidence verdict — integrity failure, unreachable collector, and
    success — is decided inside `run`; none is deferred to a later step through
    state or env. `finish` retains only the command-failure mirror and teardown
    reporting, neither of which is security-critical.

## Exit semantics

| condition | action result |
|---|---|
| start failure (spawn error, ready timeout, port busy) | fail, infra-error message; wrapped command never runs |
| wrapped command non-zero, `fail-on-command-failure: true` | fail: `command exited <code>` |
| wrapped command non-zero, `fail-on-command-failure: false` | succeed; exit code in the `command-exit-code` output and visible in the step log (the wrapped command runs with inherited stdio). *(Amended after Task 5 spec review: the summary carries evidence only — `report.md` stays a deterministic render of the session, and the exit code's surfaces are the output and the log.)* |
| evidence capture/report failure | fail (evidence integrity is the product; fail-closed) — *(Task 5 round 6)* raised by the `run` step itself as exit 3 with nothing staged, so no later step can reverse it |
| collector died before capture | fail with diagnostic (partial evidence still staged if readable) — *(Task 5 round 7)* raised as exit 3 by `run` itself, not deferred to `finish`: the labeled fallback is a reader's aid, never a gate, and a later step must not be able to flip the verdict |
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
