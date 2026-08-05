# Hypothesis Lifecycle + Session Read Endpoint — Design (Sub-project A)

**Date:** 2026-08-06
**Status:** Approved (design dialogue in session; scope and storage approach chosen by maintainer)
**Component:** `scripts/debug_server.js` (runtime evidence collector)
**Roadmap:** cycle 2, sub-project A of "A then B, stacked". Sub-project B (`debug_viewer.js`
TUI + agent mode, `debug_diff.js` per-hypothesis diff) consumes what A records and is a
separate spec. Branch: `feat/hypothesis-endpoint`, stacked on `feat/collector-redaction`.

## Problem

Hypotheses are freeform today: agents tag events with `hypothesisId` but outcomes
(confirmed/rejected) live only in conversation. `debug_diff.js` (sub-project B) needs recorded
verdicts to compare two sessions per hypothesis, and the maintainer chose a first-class
hypothesis lifecycle over verdict inference. Separately, tools need a supported HTTP read path
for live sessions (`GET /sessions/:id/logs`) alongside direct file reads.

## Decisions already made (maintainer-approved)

- Viewer form factor (B): terminal TUI for humans + agent mode (same filter engine, plain
  NDJSON out) — no browser dependency; agents in any harness consume it.
- Data source (B): both direct file reads and the A endpoint, from day one.
- Verdicts: full hypothesis state machine on the collector (this spec), not inference.
- Decomposition: A (this spec) then B, stacked.
- Reports: belong to B's tools; the collector stays a minimal evidence store — no session
  close, no auto-report.
- Storage: **typed lines in the existing session log** (approach A1) — not a sidecar file,
  not in-memory.

## Data model — typed lines, event-sourced

Existing event lines are unchanged; a line without a `type` field is an event. New line shape,
appended through the existing `appendSessionEvent` chain:

```json
{"ts":"2026-08-06T09:00:02.000Z","type":"hypothesis","hypothesisId":"H1","status":"OPEN","title":"userId null before fetch"}
{"ts":"2026-08-06T09:07:11.000Z","type":"hypothesis","hypothesisId":"H1","status":"CONFIRMED","note":"null until session loads"}
```

- Server sets `ts` (ISO-8601 UTC) and `type: "hypothesis"`. Client fields are allowlisted:
  `hypothesisId`, `status`, `title`, `note`, `runId` — nothing else is copied.
- `hypothesisId`: required non-empty string (same free-form ids agents already put on events).
- `status`: required, validated enum `OPEN | CONFIRMED | REJECTED | INCONCLUSIVE`.
- `title` and `note` are optional strings; they pass the existing redaction choke point
  (`redactEventForAppend`) like every other string, so secrets in hypothesis text are
  `[REDACTED]` at rest.
- **Event-sourced**: a status change appends a new line; the latest line for a `hypothesisId`
  defines its current status; history is never mutated. **No transition restrictions** — any
  status may follow any status (an agent may flip CONFIRMED → REJECTED on new evidence); the
  append-only log preserves the full audit trail, which is the evidence-first guarantee.
- Hypothesis lines consume the same per-session `maxEventsPerSession` and aggregate
  `maxTotalBytes` budgets as events, through the same reservation/rollback path.

## Route: `POST /hypothesis`

- **Auth: launch token** via the existing `authorizeRequest` choke point. This is the
  capability split: the session token (held by the instrumented app) keeps exactly what it has
  today — writing events via `/log`; the launch token (held by the operator/agent via
  `.debug/collector_token`) gains hypothesis writes and reads. The app never gains read-back
  or hypothesis powers.
- Body (snake_case accepted like `/log`): `{sessionId, hypothesisId, status, title?, note?,
  runId?}` read via the existing `readJson` limits (`maxBodyBytes`, `bodyTimeoutMs`).
- Pipeline mirrors `/log`: retire-inactive housekeeping → session lookup → auth → field
  validation → allowlisted line assembly → `redactEventForAppend` → capacity reservation →
  `appendSessionEvent` → `202 {status:"recorded"}`. A successful hypothesis write refreshes
  `session.lastActivityAt` (the agent is actively debugging).
- Errors reuse the established family: `unknown_session` 404, `session_initializing` 425,
  new `invalid_hypothesis_id` 400 and `invalid_hypothesis_status` 400,
  `event_limit_reached` / `storage_limit_reached` 429, `log_redaction_failed` 500,
  `session_log_replaced` 409, single 401 shape for auth.

## Route: `GET /sessions/:id/logs`

- **Auth: launch token**, same 401 shape. No CORS change (existing allowedOrigins logic
  applies; this endpoint targets local tools, not pages).
- **Strict path parsing**: the pathname must match `/sessions/<id>/logs` where `<id>` matches
  `/^[A-Za-z0-9_-]+$/`; the id is used ONLY as a `sessions` map key — client input never
  reaches filesystem path construction, so there is no traversal surface.
- **Live sessions only**: housekeeping (`retireInactiveSessions`) runs first; a session not in
  the map — unknown, retired, or provisional-failed — returns `404 unknown_session`
  (provisional sessions return `425 session_initializing`). Historical analysis is exactly
  what direct file reads (sub-project B) are for. A GET does **not** refresh
  `lastActivityAt` — reads by the operator do not prove the instrumented app is alive.
- **Query filters** (all optional, combined with AND):
  - `hypothesisId=<string>` — lines whose `hypothesisId` equals the value;
  - `type=event|hypothesis|all` (default `all`); `event` = lines without `type`,
    `hypothesis` = `type:"hypothesis"` lines;
  - `sinceTs=<ISO>` / `untilTs=<ISO>` — inclusive bounds compared via `Date.parse` of the
    line's `ts`; a line whose `ts` fails to parse is excluded only when a time filter is
    present;
  - `runId=<string>` — equality on the line's `runId`;
  - `limit=<n>` — keep the LAST n matching lines (tail-biased; the newest evidence is the
    interesting end), clamped to 2000 (`maxEventsPerSession` — a session cannot legally
    exceed it under one server).
  - Any unparseable filter value (bad `type`, unparseable timestamps, non-numeric or
    non-positive `limit`) → `400 invalid_query`. Unknown query parameter names → `400
    invalid_query` (fail-closed against typos silently disabling a filter).
- **Response**: `200`, `Content-Type: application/x-ndjson`. Matching lines are emitted as
  the stored bytes, verbatim — parsed only to evaluate predicates, never re-serialized, so
  the response can never mutate evidence and is already redacted at rest.
- **Read integrity**: the read joins the session's `appendChain` (no interleaving with an
  in-flight append) and re-verifies the log file's identity exactly as appends do
  (`openNoFollow`, dev/ino, birth time, `bytesWritten`) before reading; a mismatch returns
  `409 session_log_replaced`. Only complete lines are considered: the read stops at the last
  `\n` (with `bytesWritten` bounding, a torn trailing line cannot be emitted).

## Error handling summary

| Case | Response |
|---|---|
| Missing/wrong bearer token (either route) | 401, single shape via `authorizeRequest` |
| Session unknown/retired | 404 `unknown_session` |
| Session provisional | 425 `session_initializing` |
| Bad `hypothesisId` / bad `status` | 400 `invalid_hypothesis_id` / `invalid_hypothesis_status` |
| Bad/unknown GET query parameter | 400 `invalid_query` |
| Caps exceeded on hypothesis write | 429 (existing codes) |
| Redaction walk failure | 500 `log_redaction_failed`, nothing persisted |
| Log file identity mismatch (write or read) | 409 `session_log_replaced` |

## Testing (`scripts/debug_server.test.js` idiom, no new dependencies)

1. `POST /hypothesis` happy path: line lands with server `ts`, `type:"hypothesis"`, allowlisted
   fields only; a secret-bearing `title`/`note` is `[REDACTED]` on disk.
2. Lifecycle: OPEN then CONFIRMED appended for the same id; both lines preserved in order;
   invalid `status` and empty/missing `hypothesisId` → 400 with nothing persisted.
3. Capability split, both directions: session token on `/hypothesis` → 401; launch token
   works on `/hypothesis`; `/log` behavior unchanged (session token works; wrong token 401).
4. Caps: hypothesis lines consume `maxEventsPerSession` and `maxTotalBytes` (both 429 paths),
   with reservation rollback on append failure.
5. GET filter correctness on a seeded session (events + hypotheses): each filter alone and
   combined; `limit` tail bias; every emitted line parses as JSON; verbatim-bytes check
   (emitted line equals stored line).
6. GET fail-closed: no/wrong token 401; unknown and retired session 404; provisional 425;
   bad `type`/timestamps/`limit`/unknown param → 400 `invalid_query`; swapped log file → 409.
7. GET output never contains a raw known secret (seed env secret, log it, read back).
8. Full-suite regression: all existing tests stay green.

## Documentation

- SKILL.md Log Format: add the hypothesis line shape and a short workflow note (record
  hypothesis status transitions via `POST /hypothesis` as evidence accumulates; latest wins).
- README trust model: capability-split sentence (session token = event writes only; launch
  token = hypothesis writes + reads) and the new routes in the route list.
- This spec carries the decision records: launch-token reads, live-only GET, no transition
  restrictions, tail-biased `limit`, fail-closed `invalid_query` on unknown params.

## Non-goals

- No mutation or deletion of hypothesis lines; no transition validation beyond the enum.
- No historical-session GET (direct file reads cover history).
- No SSE/WebSocket streaming (parked backlog item).
- No report generation or session-close concept (sub-project B / rejected respectively).
- No pagination beyond `limit`; no multi-value filters.

## Success criteria

- All eight test groups pass on Windows and Linux CI via `npm test`; `npm run validate` PASS.
- Existing routes byte-identical in behavior (full suite green, no fixture edits).
- Capability split enforced and tested in both directions.
- The GET path provably cannot read outside the session's recorded log file identity and
  cannot emit unredacted or torn content.
