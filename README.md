# Codex and Agents Debug Mode

[![Validate](https://github.com/XGenerationy/codex-agents-debug-mode/actions/workflows/validate.yml/badge.svg)](https://github.com/XGenerationy/codex-agents-debug-mode/actions/workflows/validate.yml)

An independent, community-maintained, evidence-first debugging and GitHub pull-request cleanup
skill for Codex-compatible and Agents-compatible skill loaders.

The workflow follows one rule:

```text
Do not guess -> hypothesize -> instrument -> reproduce -> analyze -> fix -> verify
```

It covers:

- runtime and frontend debugging with an authenticated local evidence collector;
- systematic test, build, and error recovery;
- live GitHub pull-request inspection and cleanup;
- a deterministic 19-check PR closeout gate;
- suppression detection, secret redaction, repository sealing, and race-aware GitHub attestation.

## Project status

The skill implementation is introduced through a reviewed pull request so the public repository
retains a clear, auditable publication history.

## Automatic triggers

The skill declares implicit invocation for:

- `cleanup GitHub` and `clean up GitHub`;
- `bug`, `debug`, and `fix a bug`;
- failing tests, broken builds, and unexpected errors;
- PR cleanup, review comments, and failing PR checks.

## Install

Node.js 20 or newer is required for the bundled collector, closeout runner, and tests.

### PowerShell

```powershell
git clone https://github.com/XGenerationy/codex-agents-debug-mode.git
cd codex-agents-debug-mode
.\tools\install.ps1 -Target Both
```

If a target already exists, rerun with `-Force`. The installer renames the existing target to a
timestamped backup before installing the new copy.

### Bash

```bash
git clone https://github.com/XGenerationy/codex-agents-debug-mode.git
cd codex-agents-debug-mode
bash ./tools/install.sh --target both
```

Use `--force` to preserve an existing target as a timestamped backup and replace it.

Supported targets:

- Codex: `~/.codex/skills/debug`
- Agents: `~/.agents/skills/debug`

Only the skill payload is installed: `SKILL.md`, `agents/`, `assets/`, `references/`, and
`scripts/`. Repository governance and CI files are not copied into the skill directory.

## Validate

The repository has no runtime npm dependencies.

```bash
npm ci --ignore-scripts
npm audit --audit-level=high
npm run validate
npm test
```

CI runs the same checks on Windows and Linux with supported Node.js versions. The repository
validator checks the payload shape, metadata, automatic-trigger contract, JSON assets, JavaScript
syntax, and public-distribution safety.

The 19-check application PR gate is intentionally stricter than this repository's own package
validation. When the skill is used against an application repository, missing Prisma, Redis,
Grafana, Hunter, browser, or independent-review evidence must be reported honestly rather than
converted into a pass.

## Safety

The skill is fail-closed. Missing infrastructure, uncertain process ownership, incomplete GitHub
evidence, skipped checks, warning output, stale artifacts, and unverifiable service health block a
clean result.

The collector additionally enforces the secrets half of Critical Rule 5 at ingestion: known
secrets — sensitive-named environment values, `DEBUG_REDACT_NAMES` opt-ins, and the collector's
own launch and session tokens — are replaced with `[REDACTED]`, including their URL-encoded,
JSON-escaped, base64, and hex variants and extracted components (URL credentials,
connection-string leaves), before any event byte is persisted. A redaction failure rejects the
write instead of storing raw evidence. Note the deliberate trade-off: if a secret value or one
of its components equals a common word (a dev-default `postgres` password, for example), that
word is scrubbed from all evidence — the guarantee is unconditional, so prefer distinct dev
credential values. `DEBUG_REDACT_NAMES` entries additionally bypass the 8-character
auto-discovery floor, so list only names whose values are genuinely high-entropy secrets — a
short or common value would be scrubbed wherever it appears as a substring. PII redaction
remains an agent responsibility.

### Debug collector trust model

`scripts/debug_server.js` is a single-operator, loopback-only server: it binds to `127.0.0.1`,
validates the TCP peer and Host header before anything else (`isAllowedHost`), and serves exactly
one `projectRoot` per process. There is no multi-tenant or `client_id` concept because there is no
multi-tenant deployment target — every authenticated write path is scoped by one of two random,
unguessable tokens instead:

- the server-wide **launch token** (persisted to `.debug/collector_token`, mode `0600`) authorizes
  `POST /session`;
- a **per-session token**, minted fresh in the `/session` response, authorizes `POST /log` for that
  session only — a token valid for one session is rejected against every other session.

Both checks funnel through the single `authorizeRequest` choke point in `debug_server.js` so a new
authenticated endpoint cannot add an inline check and skip the timing-safe comparison or the `401`
response shape.

Every persisted event also passes one fail-closed redaction choke point
(`createRedactionContext` / `redactEventForAppend`): values of sensitive-named environment
variables, names listed in `DEBUG_REDACT_NAMES`, and the collector's own tokens can never reach
a session log in raw or encoded form. The token registry is capped at 512 entries per process —
the launch token plus up to 511 session mints, only successful mints consume entries (a mint
that fails setup registers nothing); at the cap further sessions are refused with
`session_registry_full`, signaled once on stderr as `redaction.registry_full` — restart the
collector to reset it.

Two launch-token capabilities extend the model: `POST /hypothesis` records
event-sourced hypothesis status lines through the same append and redaction
path, and `GET /sessions/:id/logs` serves filtered, verbatim, already-redacted
NDJSON for live sessions with the append path's own file-identity checks. The
per-session token keeps exactly one capability: writing events via `POST /log`.
`GET /health` additionally reports redaction registry headroom counts
(cardinality only, never token values).

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

### Evidence tools

`scripts/debug_viewer.js` (layout-C TUI for humans; verbatim filtered NDJSON for agents when
piped) and `scripts/debug_diff.js` (per-hypothesis before/after report; TTY-aware default —
table interactively, versioned `schema: 1` JSON when piped; `--format=md` for PR comments)
consume session logs through the shared `scripts/debug_evidence.js` core, whose filter
semantics are test-guaranteed identical to `GET /sessions/:id/logs`. The diff never
classifies severity or infers failures — recorded verdicts and deterministic deltas only —
and rendered log text is escaped in the human formats, so report structure reflects the
engine, never log content.

## License

MIT. See [LICENSE](LICENSE).

This project is not affiliated with or endorsed by OpenAI, Cursor, or any other referenced product
vendor. See [NOTICE.md](NOTICE.md).
