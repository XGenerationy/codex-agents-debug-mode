# Evidence Tools — debug_viewer + debug_diff — Design (Sub-project B)

**Date:** 2026-08-06
**Status:** Approved (design dialogue in session; layout, formats, and build shape chosen by maintainer)
**Components:** `scripts/debug_evidence.js` (new shared core), `scripts/debug_viewer.js` (new),
`scripts/debug_diff.js` (new)
**Roadmap:** cycle 2, sub-project B — consumes sub-project A (hypothesis lifecycle lines +
`GET /sessions/:id/logs`, merged in PR #3). Branch: `feat/evidence-tools` off
`codex/publish-debug-skill` (`112a0de`).

## Problem

Session evidence is now first-class (typed NDJSON with recorded hypothesis verdicts) but the
only consumers are `cat` and hand-rolled greps. Phase 5 (Analyze) needs a filterable live
view; Phase 7 (Verify) needs a per-hypothesis before/after comparison. Both humans and agents
consume this — the maintainer works across multiple agent harnesses and requires every
human-facing interface to keep an agent-consumable mode.

## Decisions already made (maintainer-approved)

- Viewer form factor: terminal TUI + agent mode (one filter engine, two frontends).
- TUI layout: **C — full-width stream over a full-width hypothesis verdict table** (session
  switching via key overlay, not a persistent pane).
- Diff formats: **table, markdown, and JSON all ship** from one engine; the no-flag default is
  **TTY-aware — table when interactive, JSON when piped** (agents never scrape tables);
  `--format=table|md|json` overrides.
- Build shape: **B1 — one shared evidence core + two thin CLIs** (rejected: self-contained
  duplicating tools — filter drift; one merged binary — conflated interaction models).
- Data sources: both direct file reads (history) and the live GET endpoint, from day one.
- Verdicts come only from recorded hypothesis lines — no inference (sub-project A decision).

## Shared core — `scripts/debug_evidence.js` (zero dependencies)

One module owns everything both tools must agree on:

- **`readSessionFile(filePath)`** — read a session log from disk; returns ordered entries
  `{raw, parsed}` (raw stored line preserved for verbatim re-emit; incomplete trailing line
  dropped).
- **`readSessionLive({port, token, sessionId})`** — fetch `GET /sessions/:id/logs` from the
  local collector (loopback only) with the launch token; same `{raw, parsed}` shape.
  Collector discovery reads `.debug/collector_port` and `.debug/collector_token` relative to
  the project root.
- **`filterEntries(entries, {hypothesisId, type, sinceTs, untilTs, runId, limit})`** —
  semantics IDENTICAL to the GET route's: `type` `all|event|hypothesis` with "no `type` field
  = event" and unknown future types matching only `all`; inclusive `Date.parse` bounds with
  NaN-`ts` lines excluded only when a time filter is present; byte-exact `hypothesisId`/
  `runId` equality (both trimmed at write time by sub-project A); tail-biased `limit`.
  A **parity test** runs the same scenario through this function and through a live server's
  GET and asserts identical emitted lines — the single source of truth is enforced, not
  assumed.
- **`foldHypotheses(entries)`** — derive per-hypothesis state from lifecycle lines:
  latest-wins `status`/`note`/`ts`, first non-empty `title`, plus full ordered history.
  File order is the tiebreak for same-millisecond lines (guaranteed by the collector's
  append chain).
- **`listSessions(projectRoot)` / `resolveSessionRef(projectRoot, ref)`** — enumerate
  `.debug/debug-*.log`; accept a session id or a direct file path.
- **Live tail = poll-by-count**: re-fetch and emit only entries beyond the count already
  seen. No timestamp cursors, no same-millisecond dedupe hazards. When a watched live
  session retires (GET starts returning 404 `unknown_session`) the caller falls back to the
  file transparently and surfaces that the stream is no longer live.
- Fail-closed error surfacing: 401 (bad/missing launch token), 404 (unknown/retired), 409
  (`session_log_replaced`) are distinct, actionable errors — never swallowed.

## `scripts/debug_viewer.js`

- **Mode selection:** stdout TTY → TUI; non-TTY or `--json`/`--plain` → agent mode.
- **Agent mode:** apply the same filters, print the RAW stored lines (verbatim contract
  preserved end to end), exit 0. `--json` and `--plain` are synonyms today (lines are
  already NDJSON); both exist so intent reads clearly in scripts.
- **TUI (layout C):** full-width stream (auto-tail, verdict lines highlighted `◆`), then a
  full-width hypothesis table (id, status, title/note, last-update time), then a key bar.
  Keys: `f` edit filter, `s` session picker overlay, `tab` focus stream/table (scroll
  focused region), `space` pause/resume tail, `q` quit. ANSI alternate screen + raw-mode
  stdin, resize-aware. No curses dependency.
- **Testability by design:** the TUI's state transitions are pure reducers
  (`(state, key) → state`) covered by unit tests; only the thin ANSI painter is exempt from
  CI (documented). Agent mode is covered end-to-end by spawning the real CLI.
- **CLI:** `node debug_viewer.js [projectRoot] --session <id|path> [--hypothesis <id>]
  [--type all|event|hypothesis] [--since <ISO>] [--until <ISO>] [--run <id>] [--limit <n>]
  [--live|--file] [--json|--plain]`. Without `--session` in TUI mode, open the picker;
  in agent mode, exit with a usage error (agents must be explicit).

## `scripts/debug_diff.js`

- **CLI:** `node debug_diff.js <beforeRef> <afterRef> [projectRoot]
  [--format=table|md|json]`. Refs are session ids or file paths. Default format: TTY-aware
  (table interactive, JSON piped).
- **Engine (deterministic, no inference):** for the union of hypothesis ids across both
  sessions — `statusBefore → statusAfter` (from recorded lifecycle lines; `—` when absent),
  per-hypothesis event counts before/after, and **disappeared messages**: distinct event
  `msg` texts present in the before-session and absent in the after-session, scoped to that
  hypothesis's events (plus an unscoped bucket for untagged events), capped per hypothesis
  with the cap stated in the output. **No severity/failure classification** — deciding what
  counts as a failure would be pattern-guessing; the report presents recorded verdicts and
  deterministic deltas only.
- **JSON output carries `schema: 1`** — a stable, versioned contract for agents, CI gates,
  and the closeout runner. Table and markdown render the same engine result; markdown uses
  per-hypothesis sections with verdict transitions, suitable for PR comments.

## Error handling

| Case | Behavior |
|---|---|
| Unknown session ref (file absent, GET 404) | exit 1 with a distinct message naming the ref; viewer TUI shows it inline |
| Live GET 401 | exit 1: launch token missing/mismatched (`.debug/collector_token`) |
| Live GET 409 `session_log_replaced` | exit 1, surfaced verbatim — evidence integrity failure is never softened |
| Live session retires mid-watch | automatic file fallback + visible "no longer live" state |
| Agent mode without `--session` | usage error, exit 2 (agents must be explicit) |
| Malformed stored line encountered by the core | fail closed: name the line number, exit 1 (never skip silently) |

## Testing (no new dependencies; hermetic — explicit `redactionEnv: {}` wherever a server spins)

1. Core filter parity with the live GET route (same seeded scenario → identical lines).
2. Core folding: latest-wins, first-title retention, trimmed join keys, same-ms file-order
   tiebreak, full history preservation.
3. Poll-by-count tail: no duplicates, no gaps across three poll rounds with interleaved
   appends.
4. Viewer agent mode e2e: spawn the real CLI piped with filter flags → exact expected NDJSON;
   non-TTY default selection; usage error without `--session`.
5. Viewer reducers: key-by-key state transitions (filter entry, focus, pause, picker).
6. Diff engine fixtures: verdict transitions, absent-before/absent-after hypotheses,
   disappeared-message scoping and cap.
7. Renderer exact-string tests for table, markdown, and JSON (including `schema: 1` and the
   TTY-aware default selection logic).
8. Error paths: unknown ref, wrong token, retired-session fallback, malformed line.
9. Full-suite regression: all existing tests stay green; `npm run validate` passes with the
   three new payload files.

## Documentation

- SKILL.md: an "Analyze & Verify tooling" subsection — viewer usage for Phase 5 (TUI and
  agent-mode examples) and diff usage for Phase 7, including the TTY-aware defaults.
- README: tools blurb under the collector section.
- This spec carries the decision records listed above.

## Non-goals

- No WebSocket/SSE streaming (parked backlog item) — poll-by-count is the mechanism.
- No web dashboard, no annotations/editing from the viewer, no cross-session search.
- No severity, failure, or PII heuristics anywhere in the pipeline.
- No `--format` for the viewer (it emits raw NDJSON in agent mode, period).

## Success criteria

- All nine test groups pass on Windows and Linux CI via `npm test`; validator PASS with the
  three new files in the payload.
- The parity test proves core filters and GET filters cannot drift.
- Agent mode output is byte-identical to the stored lines it selects.
- The diff JSON schema is stable, versioned, and consumed without scraping.
