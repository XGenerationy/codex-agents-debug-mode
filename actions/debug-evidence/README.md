# Debug Evidence Session Action

`actions/debug-evidence` wraps **one** CI command in an instrumented debug-collector
session, then publishes what that session recorded: a rendered report in the job's
Step Summary and an evidence artifact you can download. `action.yml` is wiring only —
every decision lives in `actions/debug-evidence/support.js`.

It exists for the evidence-first loop this repository's skill describes
(`hypothesize -> instrument -> reproduce -> analyze -> fix -> verify`, see
[`SKILL.md`](../../SKILL.md) and the repository
[README](../../README.md#evidence-tools)): instead of re-reading a red job's scrollback,
you get the session the failing command actually produced, folded into a report by
[`scripts/debug_report.js`](../../scripts/debug_report.js).

This action **never posts a verdict**. It can open one hypothesis line with status
`OPEN` if you ask it to; confirming or rejecting a hypothesis stays with you.

## What it does

One invocation is seven composite steps, in this order:

| step | what it does |
|---|---|
| `Set up Node.js` | `actions/setup-node`, pinned by SHA, at the `node-version` input. |
| `Start collector` | Publishes this invocation's identity, decides admission (see [Evidence trust](#evidence-trust-strict-and-best-effort)), boots a loopback collector, mints a session, and optionally posts the one `OPEN` hypothesis line. |
| `Run wrapped command` | Runs your command under `bash --noprofile --norc -e -o pipefail -c` (the same errexit/pipefail semantics a `shell: bash` workflow step gets, so a failing line in a multi-line command — or a failing producer in a pipe — is the recorded verdict, never the last command's status), then, in the same process, reads the session back from the collector over an authenticated, signature-checked request, renders the report, hashes the payloads, and stages them. |
| `Render evidence report` | Appends the staged `report.md` to `$GITHUB_STEP_SUMMARY` when this invocation's run captured one; otherwise it clears the staging slots it will not publish. Publish-only: it verifies nothing and decides nothing. |
| `Upload evidence artifact` | `actions/upload-artifact`, pinned by SHA, over three enumerated file paths. |
| `Stop collector` | Signals the detached collector process. |
| `Apply verdict` | Applies the exit taxonomy (see [Exit semantics](#exit-semantics)). |

The last four run under `if: always()`, so a failing command still produces a summary,
an artifact and a teardown. Capture, validation, rendering, hashing and staging all
happen inside the `Run wrapped command` step — the only process in the job that spans
your command's execution.

## Quick start

```yaml
name: Repro
on: pull_request

permissions:
  contents: read

jobs:
  repro:
    runs-on: ubuntu-latest
    steps:
      - name: Check out repository
        uses: actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10 # v6.0.3
        with:
          persist-credentials: false

      - name: Reproduce under instrumentation
        id: repro
        uses: XGenerationy/codex-agents-debug-mode/actions/debug-evidence@0000000000000000000000000000000000000000 # replace with a real 40-hex commit SHA
        with:
          run: npm test
          session-name: ci-repro
          # GitHub-hosted runners ship sudo, so the default `strict` REFUSES to run
          # your command there. See "Evidence trust" before copying this line.
          evidence-trust: best-effort
```

**Pin a 40-hex commit SHA, never a branch and never a tag.** A branch reference lets
whoever can move that branch replace the code that runs inside your job — and this
action's whole product is evidence, which is worth exactly as much as the code that
produced it. The two third-party actions inside the composite are pinned the same way.

`XGenerationy/codex-agents-debug-mode` is this repository; substitute your fork if you
use one. Nothing in the action needs the checkout except the ordinary case where your
wrapped command does.

## Inputs

Every default below is the literal default in [`action.yml`](action.yml).

| input | required | default | what it is |
|---|---|---|---|
| `run` | yes | — | Command to execute under instrumentation (`bash -e -o pipefail -c`, matching workflow-step semantics). |
| `working-directory` | no | `.` | Directory the wrapped command runs in. |
| `session-name` | no | `ci-debug` | Session label (`[A-Za-z0-9_-]+`); the session id derives from it. |
| `fail-on-command-failure` | no | `"true"` | `'true'`: the action fails when the wrapped command exits non-zero. `'false'`: the failure is reported in the summary/outputs only. Evidence capture, artifact upload, and teardown happen regardless. |
| `output-dir` | no | `""` -> `${{ runner.temp }}/debug-evidence` | Evidence staging dir (**must be outside the workspace**). It is the **staging root**, not the artifact: only the three paths under this invocation's nonce child are submitted to the upload step. |
| `artifact-name` | no | `debug-evidence` | Uploaded evidence artifact name. |
| `node-version` | no | `24` | Node.js version for the collector and renderer. |
| `port` | no | `8787` | Collector port (loopback only). Self-hosted runners sharing a host must pick distinct ports. |
| `redact-names` | no | `""` | Comma- or whitespace-separated extra env-var names to always redact (extends `DEBUG_REDACT_NAMES`). |
| `max-events` | no | `""` | Per-session event limit override (collector default 2000). |
| `max-bytes` | no | `""` | Total evidence byte limit override (collector default 16MB). |
| `hypothesis-id` | no | `""` | Optional: when set, the action posts one status `OPEN` hypothesis line (a launch-token capability the wrapped command does not hold) and injects `DEBUG_HYPOTHESIS_ID` into the wrapped command's environment. The action never posts any other status — verdicts stay with you. |
| `hypothesis-title` | no | `""` | Optional title for the hypothesis line; ignored without `hypothesis-id`. |
| `evidence-trust` | no | `strict` | `strict` refuses to run your command unless this host positively establishes the in-process boundary the evidence depends on; `best-effort` runs anyway and labels the result. See [Evidence trust](#evidence-trust-strict-and-best-effort). |

> **Release note — `run` shell semantics.** The wrapped command executes under
> `bash --noprofile --norc -e -o pipefail -c`, the same semantics an ordinary
> `shell: bash` workflow step gets. This is a deliberate behavior change from
> the earlier bare `bash -c`, and it is **breaking** for inputs that relied on
> last-command status: `failing-step; cleanup` now stops at (and reports) the
> failing step, and a failing producer in a pipeline is no longer laundered by
> a succeeding consumer. Scripts that want the old tolerance must say so
> explicitly (`failing-step || true`), exactly as they would in a workflow
> step. Any future relaxation of these flags is itself a semantics change and
> gets the same treatment here.

Input validation is fail-closed and happens in `Start collector`, before the collector
is booted and before your command exists. A rejected input is an **exit 1** with an
`invalid inputs: …` diagnostic, not a silently rounded value:

- `session-name` and `hypothesis-id` must match `[A-Za-z0-9_-]+` (`hypothesis-id` may
  also be empty);
- `fail-on-command-failure` must be exactly `true` or `false`;
- `evidence-trust` must be exactly `strict` or `best-effort` — an **explicitly empty**
  value is an error, while an omitted one means `strict`;
- `port` must be an integer in 1–65535;
- `max-events` / `max-bytes` must be a positive integer or empty;
- `working-directory` and `output-dir` must not contain CR or LF;
- `output-dir` must be outside the repository workspace, checked both as written and
  again after both paths are resolved through symlinks.

## Outputs

| output | value |
|---|---|
| `command-exit-code` | Exit code of the wrapped command; empty until the run step has run. |
| `session-id` | Collector session id; empty until the run step has run. |
| `event-count` | Events captured in the session; empty until the run step has captured one. |
| `report-path` | Path of `report.md` in the staged evidence: `output-dir` joined with this invocation's staging child, so it is absolute exactly when `output-dir` is — which the default is. Nothing resolves it, so a relative custom `output-dir` produces a relative value. Empty until the run step has captured one. |
| `evidence-digest` | The SHA-256 digest line for the staged payloads, byte-identical to the line the run step printed to its own step log. Empty until the run step has captured a session. |

`event-count`, `report-path` and `evidence-digest` are written only when the report
rendered; `command-exit-code` and `session-id` are written whenever the run step
reached its state commit.

**All five outputs are availability-only, and all five are attacker-suppressible.**
They are written after your command has already run, into the runner's step-output
file — a file your command can append to itself, whether or not `GITHUB_OUTPUT` is in
its environment. It can claim a key the action does not write, and for a key the action
does write it can open a heredoc whose delimiter is the exact line the action is about
to append, swallowing that line as body. So nothing security-critical rides on these
values: **the verdict is the run step's exit code**, which no later step can un-fail,
and the digest's better copy is the run step's own log line. `evidence-digest` exists so
a workflow can compare an artifact without scraping logs — it is a convenience, not the
trust anchor.

## What the wrapped command receives

Added to the step environment before your command starts:

| variable | value |
|---|---|
| `DEBUG_LOG_URL` | `http://127.0.0.1:<port>/log` |
| `DEBUG_SESSION_ID` | This invocation's collector session id |
| `DEBUG_SESSION_TOKEN` | This session's token |
| `DEBUG_HYPOTHESIS_ID` | Only when you set `hypothesis-id`; otherwise deliberately deleted, so a job-level value cannot file your events under a hypothesis this action never opened |

Removed before your command starts: every `DEBUG_ACTION_*` variable and the runner's
own command-file variables `GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`, `GITHUB_STATE`
and `GITHUB_STEP_SUMMARY`. That removal is **defence in depth and explicitly not a
boundary**: a determined child can still enumerate the runner's command files under
`RUNNER_TEMP`. What actually protects the capture is that no security decision is left
for a later step to make.

The **launch token is never exposed**. It is minted by the collector, read once by
`start` over a private pipe, registered with the runner's log redactor, used to mint the
session (and to post the one `OPEN` hypothesis line), and then dropped: it is never
written to the state file, never emitted as a step output, and never persisted to
`.debug/` — the boot shim deliberately does not write the CLI's `collector_token`,
`collector_port` or `collector_claim` files.

`DEBUG_SESSION_TOKEN` is a scoped capability, not a spare launch token. It can append
events to **this** session via `POST /log`, and read **this** session's log back via
`GET /sessions/<id>/logs`. It cannot mint a session and it cannot post a hypothesis
line, so a wrapped command cannot forge a verdict into its own evidence.

Posting an event — this is the shape the demo uses:

```js
const post = async (body) => {
  const response = await fetch(process.env.DEBUG_LOG_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-debug-session-token': process.env.DEBUG_SESSION_TOKEN,
    },
    body: JSON.stringify({ sessionId: process.env.DEBUG_SESSION_ID, ...body }),
  });
  if (response.status !== 202) throw new Error(`collector rejected event: HTTP ${response.status}`);
};

await post({ msg: 'fetch: userId=42 loaded', hypothesisId: process.env.DEBUG_HYPOTHESIS_ID });
```

`202` is success. `hypothesisId` may be `undefined` — `JSON.stringify` drops it and the
event is simply untagged.

## The evidence artifact

The upload step publishes exactly three enumerated payload paths:

```text
session.log   the session's NDJSON, one JSON event per line, already redacted
report.md     the rendered report (the file the Step Summary is appended from)
report.json   the machine surface, schema: 1
```

They are staged in an **invocation-scoped** child of the output directory named
`debug-evidence-files-<invocation-nonce>`, and the upload step enumerates the three
file paths individually — never the bare directory. So no other file that happens to
sit in that directory is uploaded *by name*.

`action-state.json` — this invocation's state, including the **session** token (never
the launch token) — lives at the **root** of the output directory, outside the staging
child, so no path the upload step enumerates names it. Note the exact shape of that
claim: it is about the paths, not about the bytes. The uploader follows symlinks
unconditionally, so a substitution inside the staging window can still carry the state
file's bytes into the archive under an enumerated payload name — see
[Scope, limitations, and residual risks](#scope-limitations-and-residual-risks), which is
the reason the sentence is written that way.

The collector's own session log under `<workspace>/.debug/debug-<session-id>.log` is not
enumerated either, and the same qualification applies to it: no path the upload step
enumerates names that file, which is a weaker statement than "its bytes cannot reach the
archive". The collector writes it there, through the same redaction path, and it is left
in the checkout — if a later step of yours diffs or archives the workspace, it will see
it.

## Redaction invariant

The collector's redaction snapshot **is the environment of the step that starts it**,
and this action deliberately starts the collector with the job's full environment. That
inheritance is the guarantee: sensitive-named values in the job env are scrubbed to
`[REDACTED]` at ingestion, before any event byte is persisted, including their
URL-encoded, JSON-escaped, base64 and hex variants and extracted components.

`redact-names` **extends** — never replaces — any job-level `DEBUG_REDACT_NAMES`, and
the two are concatenated. Names listed there also bypass the 8-character
auto-discovery floor, so list only names whose values are genuinely high-entropy: a
short or common value would be scrubbed wherever it appears as a substring.

This is why the action offers no "clean env" option. Starting the collector with a
stripped environment would leave the job's secrets **out of the redaction snapshot** —
so anything the wrapped command logged that happened to contain one would be persisted
raw, into the artifact you are about to publish. A collector that inherits less is a
collector that redacts less.

## Evidence trust: `strict` and `best-effort`

The evidence this action produces is only as good as one platform property: that the
wrapped command **cannot rewrite the process capturing it**. The run step reads the
collector's verification key before your command exists and keeps it in its own memory;
an ordinary child has no interface for writing into its parent's address space. On a
host where the command can reach root, or can `ptrace` a same-UID process, that
argument collapses — and no in-process argument survives it.

So the action classifies the host before running anything. `strict` admission is a
four-way conjunction, and **every probe that cannot be evaluated denies**:

| reading | clear value |
|---|---|
| Linux Yama `ptrace_scope` (`/proc/sys/kernel/yama/ptrace_scope`) | `3` |
| effective uid | non-root |
| `sudo` binary | absent at `/usr/bin/sudo`, `/bin/sudo`, `/usr/local/bin/sudo` **and** at `<dir>/sudo` for every directory on the inherited `PATH` |
| this process's own permitted/effective capabilities (`/proc/self/status`) | none of `CAP_SYS_ADMIN`, `CAP_BPF`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE` |

Three of those four readings are Linux-only claims: off Linux, the ptrace, `sudo` and
capability probes each return `unknown`, and `unknown` denies. **`strict` therefore
refuses on every non-Linux runner** — macOS and Windows included — whatever else is true
of the host.

Every `sudo` candidate is `lstat`-ed and **never executed**: sudoers rules are
command-specific, so probing one command could never establish the absence of a rule for
another, and a `PATH`-planted fake could fabricate a denial that *granted* admission. The
conventional absolute paths are checked whatever `PATH` says, so a hostile `PATH` can
only ever add candidates.

- **`strict`** (the default) — if any reading is not clear, `start` writes a diagnostic
  and returns 3 **before the collector is booted and before your command exists**. The
  command does not run at all. Labelling could not substitute for this: the hazard is a
  command able to rewrite the capturing process, and such a command can strip the label
  that warns about it. Only a refusal that precedes the command is out of its reach.
- **`best-effort`** — the command runs, and the capture, its digest, the report and the
  post-command qualification are **diagnostic claims only; none of them authenticates
  anything**. The one thing that survives is the admission record `start` streamed
  before your command existed, and all it establishes is that best-effort was
  consciously selected.

After a successful strict admission the trust unit is three things together: the
pre-command admission record in the `start` step's log, the matching digest line from the
`run` step's log, and the artifact. Not the artifact and the digest alone — a compromised
run produces both. **This action verifies none of that correspondence**; the comparison
is external and manual, and only meaningful between copies carrying the same invocation
nonce (see [Verifying a run by hand](#verifying-a-run-by-hand)).

And these are the escalation routes this action checks, **not a proof that no route
exists**: a setuid binary, a mounted container socket or a writable privileged service
grants the same power and none of them is visible from here.

### Why `strict` refuses on the default hosted configuration

GitHub-hosted runner images ship `sudo`, so the sudo reading is not clear and `start`
returns 3. That one finding is enough to deny on its own, and it is the one this repository
pins. Nothing here asserts a current `ptrace_scope` value for those images: `ubuntu-latest`
is a moving external image, and copying an assertion out of `action.yml` would not be
verification of it. The sudo finding, by contrast, is not a claim taken on trust — this
repository's own
[`debug-evidence-demo.yml`](../../.github/workflows/debug-evidence-demo.yml) runs a
`strict-refusal` job on a real hosted runner on every pull request, which asserts the
exit 3, the single admission record, and a `sudo binary: present: …` finding inside that
record. If GitHub ever shipped an image without `sudo`, that job goes red and says so.

**Hardening the runner with `sysctl -w kernel.yama.ptrace_scope=3` does not make hosted
execution strict-admissible, and this repository deliberately does not demonstrate it
that way.** Two independent reasons: the `sudo` you used to set the sysctl is still
installed, so the sudo reading denies regardless; and even without that, mode 3 is
*necessary, not sufficient* — Yama governs `ptrace` and nothing else, so a principal that
can reach root overwrites another task's userspace memory with a privileged tracing BPF
program (`bpf_probe_write_user()`) or a kernel module, without ever calling `ptrace`. A
sysctl-only "strict" demo would advertise a guarantee the host does not provide.

### What `best-effort` costs, and where `strict` is actually reachable

`best-effort` is the correct choice for hosted CI, and the repository's own dogfood uses
it. What you give up is precise: nothing the run step produces is authenticated, so the
digest and the report answer "what did this process say it staged", not "what is
provably this session". They remain useful — a red build's session is still the story of
that build — but they are not a tamper-evident record on that host.

`strict` is reachable only where the wrapped principal has **no route to root**: in
practice a locked-down container or VM with no `sudo` binary installed anywhere on the
inherited `PATH` or at the conventional locations, Yama at mode 3, a non-root job user,
and none of the four dangerous capabilities held by the runner process. A self-hosted
runner whose job user can `sudo` is not such an environment; neither is any hosted
runner in its default configuration.

### When the sudo reading says `unknown: empty-or-relative PATH entry`

`PATH` entries that cannot be resolved to a stable absolute path are candidates the
action could not check, and an unchecked candidate denies. Two cases produce this
reading:

- a **relative** entry (anything not starting with `/`), which resolves against a working
  directory this action has no business reasoning about; and
- an **empty** entry — including `PATH=""` in its entirety, because POSIX and bash read a
  null component as the *current directory*, which is a place a `sudo` can sit.

The fixed literal above is all the action reports: `PATH` is attacker-influenced text and
this value travels into the step log, the admission record and the artifact, so the
offending component is never interpolated.

**Precedence, because more than one of these can be true at once.** A host can satisfy
several of the conditions below simultaneously, and the reading names only the winner.
The order is **`present` > unreadable > empty-or-relative > `absent`** (`support.js:299`):

1. if **any** candidate exists, the reading is `present: <count> at sha256=…` — so a host
   carrying `/usr/bin/sudo` *and* `PATH=""` reports `present: 1 at sha256=…`, not this
   `unknown`;
2. otherwise, if any candidate could not be `lstat`-ed for a reason other than "no such
   file", the reading is the bare `unknown`;
3. otherwise, if any `PATH` component was empty or relative, the reading is
   `unknown: empty-or-relative PATH entry`;
4. otherwise `absent`, the only one that clears.

An empty or relative component therefore *contributes* to the reading rather than
deciding it. Every one of the first three denies strict admission, so the precedence
changes what the record says about a host, never whether that host qualifies.

**Remediation: unset `PATH` rather than emptying it.** An absent variable means
"conventional locations only" and can still clear; an explicitly empty string is
unresolvable and denies. If you are stripping `PATH` to lock a runner down, remove the
variable — do not set it to `""` — and drop any relative entries.

## Reading the step logs

### Log-line grammar

Every diagnostic and evidence line this action prints follows one of three shapes.

| shape | stream | emitted by | meaning |
|---|---|---|---|
| `debug-evidence-action: <step>: <text>` | stderr | `start`, `run`, `report`, `teardown`, `finish` | A diagnostic. The `<step>` token is the provenance: it is the subcommand that printed the line — one of those five, which map to the composite steps `Start collector`, `Run wrapped command`, `Render evidence report`, `Stop collector`, `Apply verdict`. |
| `evidence-qualification <admission-record line>` | stdout | `run` only | The admission record, repeated beside the digest so a reader cannot see the digest and miss the regime it was produced under. |
| `evidence-sha256 <name>=<64 hex> …` | stdout | `run` only | The digest line for the payloads this invocation staged. |

Two lines have no step prefix and are worth recognising: `debug-evidence-action: wrapped
command exited <code>.` (from `finish`, the command-failure mirror) and the top-level
`debug-evidence-action: <message>` line an unhandled error produces (exit 1).

The one other thing the action writes to stdout is not a log line at all: `::add-mask::`,
the runner's own redaction command, registered for the launch token and the session token
before either is used — and only when `GITHUB_ACTIONS` is `true`, so it never prints a
secret onto a terminal outside Actions. And your wrapped command runs with **inherited
stdio**, so its own output lands in the `Run wrapped command` step's log, interleaved with
the two lines above.

**Strict and best-effort are distinguished inside the record, not by the prefix.** The
record's first line always carries all three fields:

```text
evidence-trust=strict|best-effort; in-process boundary=ESTABLISHED|NOT established; admission=STRICT (authenticated)|DIAGNOSTIC ONLY.
```

`admission=STRICT (authenticated)` requires **both** halves — the regime you selected and
a clear host — so a best-effort run on a spotless host reads
`in-process boundary=ESTABLISHED` and `admission=DIAGNOSTIC ONLY`. That is not a
contradiction; it is the point. An unrecognised regime fails closed to `DIAGNOSTIC ONLY`.

**Duplicate and conflicting lines.** Nothing prevents a job — or a wrapped command with
access to a step's stdout — from emitting more lines that look like these. A reader
therefore selects, never searches:

- for a given invocation nonce there must be **exactly one** admission record headline in
  the `start` step's log, and its `Findings:` line is the line at the **next position**,
  not "some findings line in the file";
- there must be **exactly one** `evidence-sha256` line in the `run` step's log for that
  invocation;
- if you find duplicates, or two lines that disagree, **reject the set**. The action
  makes no attempt to arbitrate them, and a digest paired with a different invocation's
  record proves nothing at all.

This is the discipline the demo workflow's `strict-refusal` job implements, if you want
a worked example of the greps.

### The admission record, as it is actually printed

Nine lines, from a run with `evidence-trust: best-effort` on a host whose ptrace policy
is bypassable and where the inspection found a `sudo` binary (the `start` step's copy;
`run`'s copy is the same text with the `evidence-qualification ` prefix). The nonce is
per-run, and the count and `sha256=` value are per-host:

```text
debug-evidence-action: start: ADMISSION RECORD (streamed by start before the wrapped command existed): invocation=3f2b1c9e-0d4a-4b8e-9c11-7a6f5e4d3c2b; evidence-trust=best-effort; in-process boundary=NOT established; admission=DIAGNOSTIC ONLY.
debug-evidence-action: start: Findings: same-UID ptrace policy: privilege-bypassable; sudo binary: present: 1 at sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.
debug-evidence-action: start: Checked: Yama ptrace mode, effective uid, sudo binary presence, and this process's own permitted/effective capabilities.
debug-evidence-action: start: The sudo check covers the conventional absolute paths and every sudo candidate on the inherited PATH, lstat-ed and never executed. Any sudo binary at a conventional absolute path or anywhere on the inherited PATH denies strict admission, because sudoers rules are command-specific and no probe of one command can establish the absence of a rule for another.
debug-evidence-action: start: These are the escalation routes this action checks, not a proof that no route exists: a setuid binary, a mounted container socket, or a writable privileged service grants the same power unobserved.
debug-evidence-action: start: The in-process guarantees were NOT established on this host, so a same-user process may be able to attach to the collector or to the capturing step, or to rewrite their memory without ptrace at all where it can reach root.
debug-evidence-action: start: This run was NOT admitted under strict, and the capture, its digest and this report are diagnostic claims only; the copy of this record in start's own step log is the only one the wrapped command could not reach.
debug-evidence-action: start: This action verifies none of that correspondence. Compare the copies by hand, and only against the start record with the same invocation=3f2b1c9e-0d4a-4b8e-9c11-7a6f5e4d3c2b.
debug-evidence-action: start: A digest paired with a different invocation's admission record proves nothing at all. The nonce does not enforce the pairing — nothing here does; it lets a reader detect a mismatch that would otherwise be invisible.
```

Reading it:

- **`Findings:` lists only the readings that block.** A host where all four are clear
  says `Findings: every checked route clear.` — the two clear readings above (`effective
  uid`, `privileged capabilities`) are simply absent from the list.
- On a **successful strict admission** the headline ends
  `in-process boundary=ESTABLISHED; admission=STRICT (authenticated).`, and the two
  best-effort lines are replaced by one: *"The trust unit is this admission record, plus
  the matching digest from run's step log, plus the artifact — all three together, and
  none of them alone."*
- Under **`strict` on a host that does not qualify**, the record is still printed — and
  is followed by a `refusing to run the wrapped command:` diagnostic naming what was
  found and both ways forward. The wrapped command never runs.

The same nine lines travel into the artifact as report caveats. The copies are not
byte-identical across surfaces, and it matters which one you compare:

| surface | fidelity |
|---|---|
| `start` / `run` step logs | Verbatim, with the line prefix from the grammar above. |
| `report.json` -> `caveats[]` | **Verbatim, uncapped.** This is the copy to compare against. |
| `report.md` (and the Step Summary) | Markdown-**escaped** and capped at 500 characters per caveat with an announced ellipsis. A reading surface, not a comparison surface. |

## Verifying a run by hand

Everything below is manual by design; the action performs none of it.

1. **Download the artifact** for the run, and open the `start` and `run` step logs.
2. **Take the invocation nonce** from the `start` log's admission-record headline
   (`invocation=…`). Every later check uses that one value.
3. **Select exactly one admission record, and exactly one qualification-plus-digest
   block**, for that nonce, by the rules under [Log-line grammar](#log-line-grammar). The
   block is what binds the record to the digest: `run` writes its
   `evidence-qualification ` lines and its single `evidence-sha256` line back to back,
   from one process at one moment, and **the `evidence-sha256` line carries no nonce of
   its own** — the qualification lines beside it are the only thing that says which
   invocation the digest belongs to. Nothing enforces that adjacency (a detached child of
   your command can still write to the same stream), which is precisely why you select
   one block rather than searching for a digest. Reject the set on any duplicate or
   disagreement.
4. **Check the regime**: `admission=STRICT (authenticated)` means the three-part trust
   unit applies. `DIAGNOSTIC ONLY` means it does not, and steps 5–6 below tell you what
   the run *said*, not what is provably true.
5. **Recompute the payload digests.** The `run` step printed, in one line:

   ```text
   evidence-sha256 session.log=<hex> report.md=<hex> report.json=<hex>
   ```

   Each value is the lowercase hex SHA-256 of that payload's **UTF-8 bytes**, computed
   from memory *before* the file was written — so `sha256sum session.log` over the
   downloaded artifact reproduces it exactly **when the archive's entry under that name is
   the file the run step staged**, and any divergence means the bytes carried under that
   name are not the bytes staged (a symlink or a directory substituted at one of the three
   enumerated paths is such a divergence, and detecting it is the point). A run that staged
   only `session.log` (renderer failure) prints only that one pair; a run that staged
   nothing prints no digest line at all.
6. **Compare the record copies**: strip the `debug-evidence-action: start: ` and
   `evidence-qualification ` prefixes from the two log copies and compare them to
   `report.json`'s `caveats[]` array. All three must agree line for line, and all three
   must carry the nonce from step 2.

### Recomputing the sudo fingerprint

When a host is refused for `sudo`, the reading is `present: <count> at sha256=<64 hex>`.
The matched paths themselves are deliberately never emitted — they are attacker-
influenced bytes that would otherwise travel into the log, the record and the artifact —
so the fingerprint is what makes the finding checkable. The exact recipe, so you can
reproduce it from your own host:

1. **Derive the candidate list.** Start with the three conventional paths
   `/usr/bin/sudo`, `/bin/sudo`, `/usr/local/bin/sudo`. Then split the **inherited**
   `PATH` on `:`; for each entry that starts with `/`, strip **all** trailing slashes and
   append `/sudo`. (An entry that does not start with `/`, including an empty one, is not
   a candidate. It does not by itself decide the reading: see
   [the precedence](#when-the-sudo-reading-says-unknown-empty-or-relative-path-entry) —
   `unknown: empty-or-relative PATH entry` is reported only when nothing was found and
   nothing was unreadable.)
2. **Deduplicate by exact spelling, on the derived candidate** — after trailing-slash
   normalisation and after the conventional paths are merged in. So `/usr/bin:/usr/bin`
   yields one candidate, `/usr/bin:/usr/bin/` yields one candidate, and a `PATH` entry
   naming `/usr/bin` does not double-count against the conventional `/usr/bin/sudo`. Two
   **distinct spellings** count separately even when they resolve to the same file:
   `/a/sudo` and `/b/sudo` are 2, regardless of filesystem identity — there is no
   `realpath`, and no inode comparison.
3. **Keep the candidates that exist**, by `lstat` (a dangling symlink counts as present;
   nothing is executed). That surviving set is what both numbers describe.
4. **`<count>`** is the size of that set — matched candidate *spellings*, not distinct
   binaries or inodes.
5. **`<64 hex>`** is `SHA-256` over the matched candidates **sorted** with JavaScript's
   default comparison (UTF-16 code-unit order) and **joined with a single NUL byte
   (`\0`)**, the joined string hashed as **UTF-8**, printed as **lowercase hex**.

Two hosts with the same `sudo` set fingerprint identically, so you can confirm a finding
against your own inventory without the action disclosing a path list.

## Exit semantics

Three classes, and telling them apart is the point of the taxonomy:

| result | meaning |
|---|---|
| the wrapped command's own code (1–255) | **Your command failed.** `finish` mirrors it verbatim. A recorded code outside 1–255 becomes a plain `1` rather than being wrapped modulo 256 into a code that looks like a different failure. |
| `3` | **The action detected a problem and refused.** Strict admission denied; no usable invocation nonce; state that is not this invocation's; no recorded session; no usable collector verification key; the collector could not be authenticated or refused to serve the session; the renderer failed or returned no schema-1 report; another invocation took ownership of the output directory while your command ran; a staged report that cannot be read back; a teardown kill that failed for anything other than "already gone". |
| `1` | **The action itself failed with an unhandled error.** Invalid inputs, a collector that would not start or would not become ready in time, a lock or persistence failure, a transport error. |

The line between `3` and `1` is mechanical rather than editorial: a *returned* refusal is
`3`, a *thrown* error is `1`. Input validation is the case worth memorising — it is a
detected problem and a refusal, and it exits **1**, because it raises rather than returns.

Two more rules:

- **Every evidence verdict is raised by the `Run wrapped command` step itself**, which
  exits 3 with nothing staged. The composite declares no `continue-on-error` on any step,
  and a failed composite step is precisely what no later step can un-fail. `report`,
  `upload`, `teardown` and `finish` still run under `always()`, so you keep the summary,
  the artifact and the teardown — but none of them can turn a failed capture green.
- **`fail-on-command-failure: "false"` waives only the command mirror.** Capture
  integrity, admission refusal and machinery failures are unaffected; the exit code
  still appears in the `command-exit-code` output and in the step log, since the wrapped
  command runs with inherited stdio.

**Signals.** A command killed by a signal is recorded as exit **128**: when the `bash -c`
process the action spawned is itself terminated by a signal, its reported status is `null`
and 128 is the sentinel the action stores in its place. (A signal that kills something
*inside* your script is different — bash then exits normally with `128+n`, and that code
is mirrored like any other.) The **signal name is recorded in the state file only** — a
path the upload step does not enumerate, and one nothing renders — and no diagnostic
prints it either, so **the signal name is absent from normal rendered evidence**, which is
a claim about paths and not one about bytes: it is not categorically unable to leave the
runner, because the symlink substitution described under
[residual risks](#scope-limitations-and-residual-risks) can put the state file's bytes into
the archive under an enumerated payload name. A command that could not be spawned at all
is recorded as **127**.

**One invocation at a time per output directory.** `action-state.json` sits at the root
of the output directory and carries exactly one invocation's identity. Sequential reuse
inside a job works — the repository's demo does it deliberately, with a distinct `port`
for the second invocation (see [Self-hosted runners](#self-hosted-runners)). Two invocations
running *concurrently* against the same directory are refused fail-closed rather than
merged: the second `start` claims the state, and the first invocation's `run` finds the
claim changed and returns 3 ("another invocation now owns this output-dir"), with its
`report`, `teardown` and `finish` likewise refusing a state that is not theirs. Staged
*bytes* are not arbitrated by that mechanism at all — each invocation stages into its own
`debug-evidence-files-<nonce>` child, so invocations do not collide there, but nothing
stops any same-user process from writing into those directories (see
[residual risks](#scope-limitations-and-residual-risks)).

## Permissions

**The action needs no GitHub token.** No step reads `github.token` or
`secrets.GITHUB_TOKEN`, nothing in `support.js` calls the GitHub API, and every request
it makes goes to `127.0.0.1`. The calling job needs only what your own steps need — in
practice `contents: read` for the checkout:

```yaml
permissions:
  contents: read
```

That is exactly what this repository's demo workflow declares, and its dogfood job
uploads the evidence artifact under those permissions.

Two pinned third-party steps run inside the composite — `actions/setup-node` and
`actions/upload-artifact`. Neither is handed a `token:` input by this action, and neither
is given anything beyond the `node-version` and the artifact name/paths. What they do
otherwise is their own contract, not something this file can vouch for; both are pinned
by SHA so it is at least a contract you can read.

**Fork pull requests:** nothing in this action is token-gated, so a fork PR is not
restricted by anything the action does. Whatever *your* workflow does with the evidence
afterwards (commenting, uploading elsewhere) may still be.

## Self-hosted runners

- **`Stop collector` is this action's own teardown.** The collector is detached and
  outlives the `start` step, so no other step of this action stops it. Its `always()`
  guard covers an *earlier step of this job* failing — but only while the runner survives
  to run it.
- **Normal runner job cleanup also attempts to kill the tracked collector, on hosted and
  self-hosted runners alike.** That is *runner* behaviour, not a property of the hosted
  images, and this action does nothing to opt out of it: the runner exports
  `RUNNER_TRACKING_ID` into every step's environment, `start` hands its step's **complete**
  environment to the detached shim and never clears that variable, so the collector stays
  a tracked process and the runner's job finalization terminates tracked orphans.
- **Those are two separate backstops, and runner death defeats both.** Treat neither as a
  guarantee, and do not read either as covering the other. Job finalization is unavailable
  if process tracking was disabled or altered on that runner — there the `always()` step is
  all you have. And if the runner *process* itself dies, **neither** runs: the step never
  executes, and finalizing the job is work that same dead process would have had to do. The
  `always()` step does not cover that case. Nothing in this action does, and together with
  the next bullet, that is the path which can leave a listener behind.
- **The collector's idle timeout never terminates the process.** Be precise about this,
  in both directions: on the action path idle retirement is **disabled entirely** — the
  boot shim sets `sessionIdleTimeoutMs = Infinity`, because the finite default retired a
  quiet wrapped command's session before `run`'s only capture read — so *in-memory session
  credentials are never idle-retired here*: they stay valid for the collector's whole
  lifetime, bounded by `Stop collector`, runner job finalization, and process death — not
  by time. (The 15-minute retirement, after which a later `POST /log` gets
  `unknown_session`, applies only to a collector started with default limits, e.g. the
  CLI.) If neither `Stop collector` nor the runner's own cleanup runs, the process keeps
  listening on its port — holding its still-valid session credentials — until something
  else stops it.
- **Pick distinct `port` values** for invocations that can overlap on one host. Teardown
  signals the collector and returns without waiting for it to exit, so even a strictly
  sequential second invocation on the same port is racing a listener that may still hold
  it — the boot shim would report `port_in_use` and that `start` would fail.
- **A reused `output-dir` accumulates.** Each invocation stages into its own
  `debug-evidence-files-<nonce>` child and nothing removes another invocation's child (by
  design — it may belong to a live concurrent run). On a persistent runner that directory
  grows one child per invocation, plus `action-state.json`. Clean it up out of band, or
  leave the input at its default so each job gets a fresh `runner.temp`.
- **`output-dir` must be outside the workspace**, checked as written and again after
  symlink resolution. The collector's own session log still lands in the checkout, under
  `<workspace>/.debug/`.

## Demo

`.github/workflows/debug-evidence-demo.yml` dogfoods the action on every pull request,
against `actions/debug-evidence/demo/repro.js` — a deterministic scripted session with a
seeded bug that exits 1.

Three jobs:

1. **Seeded failure, waived.** Runs the repro with `fail-on-command-failure: "false"`, so
   the step reports the failure without failing the job, then asserts the outputs
   (`command-exit-code=1`, four events, a session id, a digest, three staged payloads).
2. **Strict refuses an unhardened hosted runner.** Probes the `start` subcommand at the
   default `evidence-trust`, and asserts exit 3, exactly one admission record carrying
   this invocation's own nonce, a `sudo binary: present:` finding on that record's own
   findings line, the refusal diagnostic, and that nothing was staged.
3. **Two invocations, one job (namespacing only).** Two calls sharing one output
   directory with distinct artifact names and distinct ports, plus a third `start` that
   fails validation against the same directory and takes nothing from either. It
   demonstrates **expression scoping** — each invocation's steps read their own `start`.
   It is explicitly **not** adversarial isolation, and proves nothing about what a
   hostile command could reach.

**What the redaction half of the demo proves, exactly.** `DEMO_FAKE_SECRET` is a fixed
dummy value committed in the clear, set in the workflow's job environment and passed to
`redact-names`. The repro logs it, and the assertion step then requires — over the
*staged bytes*, not over a log summary — that exactly one event mentions a token, that
its `msg` field equals the whole string `DEMO config dump: token=[REDACTED]`, and that
the fixture value appears in none of `session.log`, `report.md`, `report.json`.

That is the claim and the whole of it: **the demo proves the exact
`DEMO_FAKE_SECRET` -> `[REDACTED]` fixture, end to end, on a real runner.** It does not
prove that arbitrary secrets cannot leak. Every capturing job in the demo also runs
`evidence-trust: best-effort`, which is the correct setting for a hosted runner and is
labelled as such in every artifact it produces.

## Scope, limitations, and residual risks

Each of these is documented rather than prevented, and each is a consequence of the
wrapped command running as the **same OS user** as the action.

1. **The integrity guarantees are scoped to the first (or only) invocation in a job.**
   They do **not** survive an earlier instrumented command in the same job: that
   command's own `GITHUB_ENV` file can set `BASH_ENV`, which every later `shell: bash`
   step sources at shell startup — a second invocation's `start` included, before
   `support.js` runs — so it can append a last-wins `evidence-dir=` to that start's own
   output file and redirect the upload path set, or rewrite the verification key handed
   to the run step. **Wrapping a second command after an instrumented one belongs in a
   separate job.** Same-job reuse is not something this runner channel can be made to
   guarantee.
2. **A wrapped command can plant files in the staging directory.** It runs as the same
   user, and `RUNNER_TEMP` is in its environment. On the strict path the digest answers
   it: a planted file has no backing digest line. Under best-effort that answer degrades
   to a diagnostic claim, because the same command may be able to rewrite the process
   that prints the digest.
3. **The uploader follows symlinks, unconditionally.** `actions/upload-artifact@v4.6.2`
   exposes no control over it: it declares seven inputs, none of them about links, and
   hardcodes `followSymbolicLinks: true` with `implicitDescendants: true` in its glob
   options — a reading `action.yml` records as taken against the pinned SHA. A swap
   inside the staging window can therefore make one of the three enumerated names resolve
   to an unrelated readable file — `action-state.json` among them — and a *directory*
   substituted at one of those names contributes its descendants, so the archive is not
   guaranteed to hold three entries either. This is why the
   artifact section scopes its claim to the *paths* the upload step enumerates and stops
   there, instead of promising anything about the bytes the archive ends up carrying.
   Same answer as above: the digest describes what the run step staged, not what the
   artifact carries.
4. **The staging race is detectable, not prevented.** Staging and upload are separate
   steps of one composite action; a detached child of your command can rewrite a staged
   file in between. The digest is printed to the run step's log at staging time, and a
   streamed step log cannot be revised afterwards — so a swap is visible to whoever
   compares. Under best-effort, immutability defends the line against later *editing*,
   never against a process that was able to choose what the line said in the first place.
5. **The three-part trust unit is compared by a human.** The action verifies no
   correspondence between the admission record, the digest and the artifact. The nonce
   enforces nothing — it lets a reader detect a mismatch that would otherwise be
   invisible.
6. **The admission check names routes, not their absence.** A clear reading means the
   escalation routes this action checks came back clear. A setuid binary, a mounted
   container socket or a writable privileged service grants the same power and is
   invisible from here.
7. **A reused output directory accumulates staging children**, and nothing in the action
   removes another invocation's evidence — deliberately, since it may belong to a live
   concurrent run.
