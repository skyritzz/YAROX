# YAROX Canonical Security Event — Contract (Phase 11)

**Status:** implemented and tested. **Version:** `1.0` (`schemas.canonical_event.CANONICAL_EVENT_SCHEMA_VERSION`).

This is the one typed, validated, versioned shape that every event source is
normalized into before it reaches the event bus, storage
(`models.event.Event`), detection (`detection/engine.py`, `detection/rules.py`)
or correlation (`correlation/engine.py`). It exists so that a future connector
(Sysmon, Suricata EVE, Splunk HEC — none implemented yet; see "Out of scope"
below) has a single, documented target to normalize into, instead of having
to reverse-engineer `GenericJSONParser`'s inline logic the way this document's
predecessor state required.

Implementation: [`backend/schemas/canonical_event.py`](../backend/schemas/canonical_event.py)
(`CanonicalSecurityEvent`, a Pydantic v2 model). Tests:
[`backend/tests/test_canonical_event.py`](../backend/tests/test_canonical_event.py) (17 tests).

## Why this is needed (the gap it closes)

Before this phase, three structurally-similar-but-different shapes existed
with no single source of truth: the SQLAlchemy `Event` ORM model, the
`IngestEventRequest` Pydantic schema (HTTP boundary only), and the plain
`dict` returned by `GenericJSONParser.parse()` (used by both live ingestion
and replay). None was versioned, and two of the three (`Event`, the parser's
dict) had no field-level validation. This was tracked in
`docs/YAROX_REALITY_AUDIT.md` as **E-3** (canonical model, OPEN) and **E-4**
(no connector plugins exist yet, OPEN — deliberately still OPEN, see "Out of
scope").

## The contract

| Field | Type | Required | Default | Notes |
|---|---|---|---|---|
| `schema_version` | `Literal["1.0"]` | no | `"1.0"` | See **Versioning policy** below. |
| `event_id` | `UUID` | no | `uuid4()` | Assigned **once**, at normalization time, by whichever path (live ingest or replay) first produces the event. Becomes `Event.id`. |
| `timestamp` | `datetime` (tz-aware) | no | `now(UTC)` | Unparseable or missing input falls back to now(UTC) rather than rejecting the event — matches pre-existing behavior. |
| `hostname` | `str` | no | `"unknown"` | Sentinel, not `None` — see **The "unknown" sentinel** below. |
| `user_name` | `str` | no | `"unknown"` | Same sentinel convention. |
| `source` | `str` (1–128 chars) | yes* | — | *`from_raw()` defaults to `"generic"` if absent — see **Validation & error behavior**. |
| `event_type` | `str` (1–128 chars) | yes* | — | *`from_raw()` defaults to `"unknown"` if absent. Holds the taxonomy-normalized value when recognized, else the raw source string verbatim. |
| `canonical_event_type` | `core.taxonomy.CanonicalEventType` | no | `UNKNOWN` | Always computed by the contract itself from `event_type`/`raw_log`, never accepted from the caller. **Not currently a persisted column** — see **Compatibility**. |
| `severity` | `str`, one of `INFO/LOW/MEDIUM/HIGH/CRITICAL` | no | `"INFO"` | Invalid non-empty values are **rejected**, not silently coerced. |
| `raw_log` | `Dict[str, Any]` | yes | — | Preserved verbatim for the evidentiary chain of custody. Non-dict input is wrapped as `{"payload": str(...)}`. Capped at 64 KB serialized. |
| `metadata` | `Dict[str, Any]` | no | `{}` | Structured fields read by detection/entity-extraction via **plain dict access** — see **Detection compatibility**. |

## Mapping from existing event sources

### 1. Live HTTP ingestion — `POST /events/ingest`

`backend/api/ingest.py` validates the request body against
`schemas.ingest.IngestEventRequest` first (auth via `X-API-Key`, Redis
rate limiting, then Pydantic field validation — unchanged by this phase),
then calls `generic_parser.parse(request.model_dump())`, which now does:

```
IngestEventRequest.model_dump() → CanonicalSecurityEvent.from_raw() → CanonicalSecurityEvent.to_orm_kwargs()
```

Because `IngestEventRequest` already requires `source`/`event_type` and
already validates severity strictly, live-ingested events can never hit the
`from_raw()` fallback defaults (`"generic"`/`"unknown"`) in practice — those
defaults only matter for the replay path below, which has no HTTP-layer
schema in front of it.

`event_id`: previously, `api/ingest.py` minted its own `uuid.uuid4()` and
stuffed it into the normalized dict *after* parsing, independently of
whatever `Event.id` would default to. **This was a real latent
inconsistency between the two callers** (see next section) and has been
fixed: the contract itself assigns `event_id` inside `from_raw()`, and
`api/ingest.py` now reads it back (`event_id = str(normalized_dict["id"])`)
instead of generating a second, different UUID. Verified live: a real
`POST /events/ingest` call's returned `event_id` was confirmed to match the
`event_id` on `GET /events/{id}/integrity` for the same event (see Evidence
below) — previously these were two unrelated values by construction, though
no user-visible symptom had been observed because nothing ever compared them.

### 2. Dataset replay — `replay/engine.py`

`ReplayEngine.stream_events()` reads `datasets/<scenario>/events.json` and,
per event, calls the same `self.parser.parse(raw_event)` (a
`GenericJSONParser` instance) used by live ingestion — i.e. replay and live
ingestion share the identical normalization codepath, but replay reaches it
directly rather than through the HTTP/API-key/rate-limit layer. Confirmed
dataset shapes (one real sample per dataset, field-for-field):

| Dataset | Top-level keys observed | `raw_log` present? | `user` vs `user_name` | `severity` present? |
|---|---|---|---|---|
| `apt29_simulation` | `source, event_type, timestamp, hostname, user_name, raw_log{EventID, metadata{...}}` | yes, nested `metadata` inside `raw_log` | `user_name` | no (all 8 events) — defaults to `INFO` |
| `apt_blackout` | `timestamp, source, event_type, user_name, hostname, metadata{...}` | **no** — `raw_log` falls back to the whole raw event dict (`raw_data.get("raw_log", raw_data)`) | `user_name` | no (all 7 events) |
| `credential_theft` | `timestamp, hostname, user, source, event_type, severity, metadata{...}` | no, same fallback | `user` (handled by the `user_name or user` fallback chain) | yes, all valid (`LOW/MEDIUM/HIGH/INFO`) |
| `insider_threat` | same shape as `credential_theft` | no | `user` | yes, all valid |

All 25 real events across all four datasets were run through the actual
`generic_parser.parse()` in `test_canonical_event.py` (parametrized over the
four dataset names) — every one normalizes successfully and constructs a
real `Event(**kwargs)` row without error. This is a direct regression test,
not a smoke test: it reads the real files under `/datasets`, not fixtures.

`event_id`: previously replay events had **no** `id` key in the dict
published to `EventNormalized`, so `Event(**data)` relied on the ORM
column's `default=uuid.uuid4()` at insert time. Now the contract assigns
`event_id` in `from_raw()` uniformly, so replayed events get their ID the
same way live-ingested events do — functionally equivalent (both end up
with a random UUID before the row exists), but now a single code path
instead of two divergent ones.

### 3. Windows/Sysmon EventID → canonical taxonomy

Unchanged by this phase — `core/taxonomy.py`'s `EventTaxonomyNormalizer`
still does this mapping (numeric EventID lookup, e.g. `4625→AUTH_FAILURE`,
`1→PROCESS_EXECUTION` (Sysmon Process Create), `3→NETWORK_TRAFFIC` (Sysmon
Network Connection), plus the keyword/phrase table for non-numeric
`event_type` strings). The contract's `_apply_taxonomy` model validator
calls this exact function; it is not duplicated or reimplemented.

## Validation & error behavior

| Condition | Behavior | Surfaces as |
|---|---|---|
| Invalid, non-empty `severity` (e.g. `"BOGUS"`) | **Rejected** — `CanonicalEventValidationError` | Live ingest: `422` (existing broad `except Exception` in `api/ingest.py`, unchanged). Replay: the single bad event is skipped and logged (`[REPLAY] Skipping invalid event at index N in <scenario>: ...`); the stream continues. |
| Missing/empty `severity` | Defaults to `"INFO"` | No error — same as before. |
| `raw_log` serialized > 64 KB | **Rejected** — `CanonicalEventValidationError` | Same as above (422 live / skip+log replay). |
| `raw_log` is not a JSON object (e.g. a bare string) | **Not** rejected — wrapped as `{"payload": str(raw_log)}` | No error — matches pre-existing behavior exactly. |
| `timestamp` missing or unparseable | **Not** rejected — falls back to `now(UTC)` | No error — matches pre-existing behavior exactly. This is a deliberate, pre-existing leniency, not new. |
| `hostname`/`user_name` missing | **Not** rejected — defaults to `"unknown"` | No error. See sentinel note below. |
| `source`/`event_type` missing (replay path only; impossible via the HTTP path, which already requires them) | **Not** rejected — `from_raw()` defaults to `"generic"`/`"unknown"` | No error — matches pre-existing behavior exactly. |
| `raw_data` itself is not a JSON object at all | **Rejected** — `CanonicalEventValidationError` | New; previously would have thrown an unguarded `AttributeError` deep in the old parser's `.get()` calls. |

**Behavior change made in this phase:** `GenericJSONParser` previously
*silently coerced* an invalid severity string to `"INFO"` instead of
rejecting it — inconsistent with `IngestEventRequest.validate_severity`,
which already rejected invalid severities at the HTTP layer. The contract
now rejects consistently on both paths. This was checked against real data
before making the change: all four replay datasets were inspected
(`python3` one-liner over every `events.json`) and use only valid severities
or omit the field entirely, so no existing dataset is affected by the
stricter behavior — see the per-dataset table above.

**Replay resilience added in this phase:** `ReplayEngine.stream_events()`
previously had no `try/except` around `self.parser.parse(raw_event)`; any
exception there (now newly possible, given the stricter validation above)
would have propagated up and silently killed the whole replay's background
asyncio task. It now catches `CanonicalEventValidationError` specifically,
logs which index/scenario was skipped, and continues to the next event.
Verified by `test_replay_engine_skips_a_malformed_event_without_killing_the_stream`,
which feeds a 3-event dataset (good, bad-severity, good) through the real
`ReplayEngine` and asserts exactly 2 `EventNormalized` publishes plus a
`ReplayCompleted` lifecycle event (i.e. the bad event doesn't kill the
stream, and doesn't get silently republished as if valid either).

## The "unknown" sentinel (pre-existing convention, preserved not changed)

`hostname`/`user_name` default to the literal string `"unknown"`, never
`None`. This is intentional: `correlation/engine.py` explicitly excludes
`"unknown"` (and `"system"`, `"anonymous"`, `""`, case-insensitive) from
entity-correlation matching, so an event without a real host/user becomes
inert for correlation rather than erroring. This contract does not change
that convention — it documents and preserves it, since silently changing it
to `None` would be an undocumented behavior change with no test coverage
that would have caught the resulting correlation regression.

## Compatibility with storage and detection

**ORM.** `CanonicalSecurityEvent.to_orm_kwargs()` returns exactly the keys
`models.event.Event`'s constructor accepts (`id, timestamp, hostname,
user_name, source, event_type, severity, raw_log, metadata_`) —
`test_to_orm_kwargs_constructs_a_real_event_row_and_hashes_without_error`
constructs a real `Event(**kwargs)` and asserts no error.

**Integrity hash.** `core/integrity.py`'s `HASHED_FIELDS` is `(timestamp,
hostname, user_name, source, event_type, severity, raw_log, metadata)` —
`event_id`/`id` was already excluded from the hash before this phase (by
design, for duplicate detection), so assigning it uniformly earlier in the
pipeline does not change hash values. Verified: same test asserts
`compute_event_hash()` is identical regardless of which `id` value is
attached to otherwise-identical kwargs, and the live verification below
confirms a real ingested event's returned `event_id` now matches the row
whose hash verifies `true`.

**Detection rules.** All 4 rules in `detection/rules.py`
(`FailedLoginBruteForce`, `PrivilegeEscalation`, `SuspiciousProcessExecution`,
`LateralMovement`) and the Sigma matcher in `rules/sigma/engine.py` read
`event.event_type` (string) and `event.raw_log`/`raw_log["metadata"]` (plain
dict access — `command_line`, `process_name`, `ip_address`) directly off the
stored `Event` row. This contract preserves that exact nesting — `raw_log`
and `metadata` pass through unchanged in shape, only `event_type` is
possibly rewritten to its canonical value (same as the pre-existing
parser behavior). No rule needed to change.

**`canonical_event_type` is not a persisted column.** Adding one would
require an Alembic migration; per the user's item 5 of this restoration
phase (no migration/schema changes without a separate remediation proposal),
that is explicitly out of scope here. Nothing is lost: detection rules that
need the canonical type already call `taxonomy_normalizer.normalize()`
themselves against the stored `event_type`/`raw_log`, exactly as before.
Future connector or rule code that wants the canonical type from a
`CanonicalSecurityEvent` instance in memory (before it's persisted) can read
`.canonical_event_type` directly instead of re-deriving it.

## Versioning policy

`schema_version` is a fixed `Literal["1.0"]`, not a free string — pydantic
rejects any other explicit value outright. Additive, backward-compatible
changes (a new optional field with a safe default) may stay on `"1.0"`.
A breaking change — a new required field, a changed default, a validation
rule that could reject previously-accepted input, or a change to which
fields feed the integrity hash — requires bumping to a new literal (e.g.
`"1.1"` or `"2.0"`) and is a decision for the phase that needs it, not
something to silently repoint the existing literal at. If a version bump
ever changes which fields are hashed, `core.integrity.HASH_VERSION`
(currently `"yarox-event-v1"`, independent of this contract's version) must
be bumped in lockstep — they are two different version identifiers for two
different concerns and must not be conflated.

## Known limitations (carried forward, not fixed in this phase)

- **Field-naming mismatch, pre-existing and confirmed real:**
  `detection/engine.py`'s entity extraction reads only
  `raw_dict['metadata']['ip_address']` (falling back to a top-level `ip`
  key) — `grep`ing all four dataset files shows `apt29_simulation`,
  `apt_blackout` and `insider_threat` each also contain events using
  `metadata.destination_ip` instead (network-connection/exfiltration-type
  events specifically, e.g. `apt29_simulation` line 42, `apt_blackout`
  lines 67/80, `insider_threat` line 57). Those events normalize through
  this contract without error (`metadata` is preserved verbatim, as
  designed), but their IP never becomes a graph entity, because
  `_extract_entities` never looks at `destination_ip`. This is a pre-existing
  detection-layer gap, not something this contract introduced or could fix
  by itself without either renaming fields in real vendor payloads (wrong)
  or changing `detection/engine.py` (out of scope for a contract-only
  phase). Flagged here so Phase 12 connector work and any future
  detection-layer phase does not silently rediscover it.
- **`FILE_OPERATION` and `SYSTEM_ALERT`** exist in `CanonicalEventType` but
  have no keyword/EventID mapping producing them, and no detection rule
  consumes them — unreachable in practice today. Not fixed here (taxonomy
  and detection-rule expansion is separate work, not a contract concern).
- **No network/C2 detection rule exists** (audit finding D-4) —
  `NETWORK_TRAFFIC` events normalize successfully through this contract but
  have nothing downstream to detect on them. This is why the user's plan
  explicitly requires Scenario 3 (Suricata/network C2) to be marked
  **blocked** when Phase 13 scenario tests are eventually attempted — the
  contract does not create a detection capability that doesn't exist.
- **No connectors implemented.** This phase is explicitly the contract
  only, "before implementing connectors" per the governing instruction.
  Sysmon/Suricata EVE/Splunk HEC connectors (CLAUDE.md roadmap Step 5) are
  future work; when built, they should each have their own `from_raw()`-style
  adapter (or reuse it directly, if the vendor shape is close enough) and
  must each ship with a test proving real sample payloads from that vendor
  normalize correctly, per the user's item 3 ("do not begin Phase 13 until
  ... at least one real connector are tested").
- **Ingestion metrics remain process-local** (pre-existing, unrelated to
  this phase — tracked under audit item A-8 and Phase 10/durable-bus work).

## Evidence (this phase)

- `docker compose exec backend pytest -v tests/` → **232 passed** (215
  baseline + 17 new in `test_canonical_event.py`), after fixing one
  pre-existing test (`test_event_integrity.py::test_integrity_endpoint_reports_verification_and_legacy_rows`)
  that broke because it now legitimately receives an `id` key from
  `_normalized()` where it previously didn't (an intentional, documented
  result of this phase's `event_id` fix, not a defect).
- Live, on the running stack (`docker compose restart backend celery_worker`
  to pick up the change): a real `POST /events/ingest` call returned
  `event_id: 731ad377-…`; `GET /events/731ad377-…/integrity` confirmed
  `verified: true` for that exact ID (proving the ingest response's ID and
  the stored row's ID are now the same value, not independently generated).
  A deliberately invalid-severity ingest call returned `422`. A real
  `credential_theft` replay (`POST /replay/start`) produced a genuine
  case (`Brute Force + Command and Scripting Interpreter`, HIGH severity)
  with evidence items citing real `event_id`s and a Sigma-boosted
  `importance_score: 0.92` on the PowerShell evidence — confirming
  detection rules see identical data through the rewired parser. No errors
  in `backend` or `celery_worker` logs across the restart, ingest, or replay.

## Completion criterion

Phase 11 is complete for the scope explicitly requested: a documented,
validated, versioned canonical event contract exists
(`schemas/canonical_event.py`), is wired into both real normalization paths
(live ingest and replay) rather than sitting unused beside them, is proven
compatible with stored events (ORM + integrity hash) and with replay
(dataset regression test + live replay run), and its validation/error
behavior is both tested and documented above — including the two
deliberate, evidence-checked behavior changes (strict severity, per-event
replay resilience). Connector implementation is explicitly out of scope per
"before implementing connectors" and remains a separate, future phase.
