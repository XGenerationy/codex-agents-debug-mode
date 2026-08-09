# Collector-Side Secret Redaction — Design

**Date:** 2026-08-05
**Status:** Approved (design dialogue in session; scope and approach chosen by maintainer)
**Component:** `scripts/debug_server.js` (runtime evidence collector)
**Roadmap:** first of three cycles (next: log viewer + session diff report; then closeout GitHub Action)

## Problem

Critical Rule 5 (SKILL.md) — *"Never expose secrets or PII: redact credentials, tokens,
cookies, and personal data from logs, replies, reports, and handoffs"* — is enforced only by
agent discipline on the runtime-evidence path. The collector deliberately persists
redaction-free events (`scripts/debug_server.js` `/log` doc-comment and the comment above the
Windows ACL hardening in the `/session` handler); protection is filesystem-only (`0600`,
owner-only Windows ACL). A single undisciplined `debugLog(...)` call can persist a raw
credential to `<projectRoot>/.debug/`.

This design turns the secrets half of Rule 5 into a collector-enforced guarantee.

## Guarantee

No **known secret** is ever persisted to a session log. Before any event byte reaches disk,
the collector replaces with `[REDACTED]` every occurrence — including all encoded variants
(URL-encoded upper/lower/double, JSON-string-escaped, `\uXXXX` unicode-escaped,
base64/base64url padded and unpadded, hex upper/lower) and compound-secret components (URL
username/password/credential query params, connection-string leaves, JSON auth-blob leaves) —
of:

1. **Auto-discovered env secrets** — values of env vars in the collector process whose *name*
   matches the existing `SENSITIVE_ENV_NAME` / npm `_auth` heuristic
   (`isSensitiveEnvName` in `scripts/pr_closeout_stream.js`), subject to the existing
   8-character `MIN_AUTO_SECRET_LENGTH` floor.
2. **Operator-listed names** — env vars named in a new `DEBUG_REDACT_NAMES` env var
   (comma-separated, case-insensitive match against env keys, values resolved from the startup
   snapshot). Explicit names bypass the length floor, mirroring the closeout `names` opt-in.
3. **The collector's own tokens** — the launch token and every session token minted during the
   process lifetime, folded in as explicit synthetic entries (see Data flow), so they receive
   full variant expansion with no length floor.

### Honest limitation (documented, not hidden)

This enforces the **secrets** half of Rule 5 mechanically. **PII** (emails, personal names,
addresses) remains agent discipline: pattern-based detection was considered and rejected by
the maintainer to protect evidence fidelity (false-positive redaction corrupts runtime
evidence). SKILL.md keeps Rule 5 as a defense-in-depth agent rule.

Component extraction can over-redact common words: `buildSecretReplacements` extracts URL
usernames/passwords and connection-string leaves from secret values, so a dev-default
`DATABASE_URL` like `postgres://postgres:postgres@localhost/app` makes the literal word
`postgres` a needle and scrubs it from all evidence. Decision (review round 3): behavior
stands — the configured value IS a known secret, and raising the component floor would
silently leak short real passwords, which the unconditional guarantee forbids. The collateral
is documented in README/SKILL.md troubleshooting instead.

Sequential replacement over overlapping needles can also leave a fragment: when two distinct
registered secrets share a substring boundary inside one string (`abcdefgh` + `efghijkl` in
`abcdefghijkl` → `[REDACTED]ijkl`), neither whole value persists, but a suffix of one may.
Inherited from the closeout redactor's semantics; requires two secrets overlapping *and*
appearing adjacently in evidence, so it is accepted rather than special-cased.

### Non-goals

- No regex/pattern detectors and no plugin API. The single `redactEventValue` function is the
  seam where a future pattern layer would attach.
- The `/session` HTTP **response** is not redacted — it must deliver the real session token;
  it is the authentication channel, transmitted only over the authenticated loopback socket.
- `.debug/collector_token` is unchanged — it is the token distribution mechanism and already
  has `0600` + Windows owner-only ACL hardening.
- No retroactive redaction of logs written before this feature.
- No opt-out flag. The guarantee is unconditional.

## Approach (chosen: A)

`debug_server.js` gains one local import, `require('./pr_closeout_stream')` — verified
self-contained (its only dependency is `node:string_decoder`) — and reuses the
already-reviewed builders: `buildSecretReplacements(env, names)` producing a deduplicated,
longest-first `[needle, '[REDACTED]']` list.

Rejected alternatives:
- **B — extract a shared `redaction.js`:** cleaner naming, but churns a security-reviewed
  module plus its importers and tests while the publication PR is open. Acceptable as a
  mechanical post-merge refactor; not now.
- **C — inline a minimal redactor:** duplicates ~200 lines of hardened logic (variant
  expansion, component extraction, length policy) that would drift.

## Data flow

1. **Startup (server build):** snapshot `process.env` once; parse `DEBUG_REDACT_NAMES`;
   build and cache the replacement list from
   `{...snapshot, __COLLECTOR_TOKEN_0: launchToken}` with explicit names
   `[...parsedNames, '__COLLECTOR_TOKEN_0']`.
2. **Session mint (`/session` handler):** the server keeps an append-only token registry
   (launch token at index 0). After minting the session token and before the session leaves
   `provisional` state: **push the token onto the registry first, then** rebuild the cached
   list from the registry (`__COLLECTOR_TOKEN_<index>` synthetic entries). Rebuilds derive
   entirely from the registry, so they are idempotent and concurrent `/session` mints
   converge — push-then-rebuild ordering guarantees whichever rebuild finishes last includes
   every registered token (plain last-writer-wins over the rebuilt list would race and could
   drop a concurrent session's token). Tokens of retired/expired sessions stay registered for
   the process lifetime — deliberate, so a stale token appearing in a later event body still
   redacts. The registry is capped at 512 registered tokens per process — the launch token
   plus up to 511 successful session mints (a mint that fails setup registers nothing); when
   the cap is reached, further session mints fail closed rather than degrade redaction or
   rebuild cost.
3. **Per event (`/log` handler):** between event construction (the allowlisted
   `{ts, msg, data, hypothesisId, loc, runId}` assembly) and `JSON.stringify`, apply
   `redactEventValue(event)`:
   - Deep-walk the event: strings are redacted via the cached longest-first needle list
     (ordered `replaceAll`, case-sensitive — same semantics as the closeout replacer);
     arrays walk items; objects rebuild with **both keys and values** walked; numbers,
     booleans, and null pass through untouched.
   - If two sibling keys collide after redaction, disambiguate deterministically
     (`[REDACTED]`, `[REDACTED]#2`, …) so no entry is silently dropped.
   - Input comes from `JSON.parse`, so cycles are impossible; recursion depth is bounded by
     the existing `maxBodyBytes` cap, and any `RangeError` from hostile nesting hits the
     fail-closed path (parity: `JSON.stringify` recurses identically today).
   - Because only string contents are rewritten, the serialized line remains valid NDJSON by
     construction.
4. **Downstream unchanged:** serialization, byte accounting, capacity reservation, and
   `appendSessionEvent` are untouched. Accounting uses post-redaction bytes (correct:
   `[REDACTED]` may shrink or slightly grow an event, and `logFileIdentity.bytesWritten`
   tracks what was actually written).

## Error handling — fail-closed at all three stages

| Stage | Failure | Behavior |
|---|---|---|
| Startup list build | throw | Server refuses to start (same as other init failures) |
| Session-mint rebuild | throw | `500 session_registry_full` when the lifetime mint cap is reached (permanent until restart; signaled once on stderr as `redaction.registry_full`), `500 session_redaction_failed` for any other rebuild failure; no session created either way |
| Event walk/apply | throw | `500 log_redaction_failed`; nothing persisted (sits before capacity reservation, so no rollback interaction). Superseded by the explicit `REDACTION_MAX_DEPTH` (64) bound landed in the merged review pass: nesting beyond the bound throws a defined error mapped to `log_redaction_failed`, making the fail-closed code deterministic across platforms. |

## Testing (`scripts/debug_server.test.js` idiom, no new dependencies)

1. Env secret appearing in `msg`, nested `data` values, and object keys → `[REDACTED]` in the
   on-disk log; post-redaction line still parses as JSON.
2. Encoded variants (base64, URL-encoded, JSON-escaped) of an env secret → redacted.
3. Launch token and both of two concurrent sessions' tokens in an event body → redacted
   (including cross-session: session A's log never contains session B's token).
4. Short (<8 chars) auto-discovered value → **not** redacted; the same value under a
   `DEBUG_REDACT_NAMES` name → redacted.
5. Hostile deep nesting over HTTP → `500 log_redaction_failed` (deterministic since the `REDACTION_MAX_DEPTH` bound), log file byte-identical, session healthy afterward; plus a unit test pinning the exact mapping and a boundary test at the depth bound.
6. Non-string leaves (numbers, booleans, null) pass through unchanged.
7. Key-collision disambiguation produces `[REDACTED]` / `[REDACTED]#2`.
8. Full existing suite green: secret-free events are byte-identical to today's output.

## Documentation changes

- Rewrite the two now-stale "redaction-free" comments: the `/log` route doc-comment and the
  comment above the Windows ACL block in the `/session` handler (keep its ACL rationale).
- README: add collector-enforced redaction to the Safety section and the
  "Debug collector trust model" section.
- SKILL.md: annotate Critical Rule 5 — the collector now enforces the known-secret classes at
  ingestion; agents remain responsible for PII and for secrets the collector cannot know.

## Success criteria

- All eight test groups pass on Windows and Linux CI with `npm test`.
- `npm run validate` passes (payload contract unchanged — no new files shipped beyond the
  existing `scripts/` payload).
- No behavior change for secret-free events (byte-identical logs).
- The guarantee statement in this spec is reproducible by inspection: exactly one redaction
  choke point, reached by every persisted event.
