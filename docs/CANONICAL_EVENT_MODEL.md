# YAROX Canonical Security Event — Contract (Phase 11)

**Status:** implemented and tested. **Version:** `1.0` (`schemas.canonical_event.CANONICAL_EVENT_SCHEMA_VERSION`).

This is the one typed, validated, versioned shape that every event source is
normalized into before it reaches the event bus, storage
(`models.event.Event`), detection (`detection/engine.py`, `detection/rules.py`)
or correlation (`correlation/engine.py`). It exists so that a connector
(Sysmon, Suricata EVE and Splunk HEC — all three now implemented; see
"Connectors" below) has a single, documented target to normalize into,
instead of having to reverse-engineer `GenericJSONParser`'s inline logic the
way this document's predecessor state required.

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

- **Field-naming mismatch, pre-existing, confirmed real, now partially
  addressed:** `detection/engine.py`'s entity extraction reads
  `metadata['ip_address']` (falling back to a top-level `ip` key) — `grep`ing
  all four replay dataset files shows `apt29_simulation`, `apt_blackout` and
  `insider_threat` each also contain events using `metadata.destination_ip`
  instead, which `_extract_entities` never looks at, so those specific
  events' IPs never become graph entities. Not fixed at the dataset/detection
  layer (out of scope, would mean editing fixture data or detection code for
  a contract/connector phase). The Sysmon connector added in this session
  (see **Connectors** below) sidesteps this for events *it* produces by
  writing both `metadata['ip_address']` and `metadata['destination_ip']` to
  the same value — a real fix for its own output, not a fix for the
  pre-existing dataset/detection mismatch itself.
- **A related, more serious defect was found and fixed while building the
  Sysmon connector**: `detection/rules.py`'s `SuspiciousProcessExecution`
  and four spots in `detection/engine.py` (`_extract_entities`, Sigma
  evaluation, evidence artifact/dedup) read `event.raw_log.get('metadata')`
  instead of the real `event.metadata_` ORM column. This only ever worked
  because every existing caller (replay datasets, every hand-built test
  fixture) happened to *duplicate* metadata inside `raw_log` too. The first
  real connector that correctly kept `raw_log` as the untouched original
  payload and supplied `metadata` as a genuinely separate field (exactly as
  this contract's own field semantics say to) silently produced **zero
  detections** — proven by a failing end-to-end test before the fix. Fixed
  by a shared `detection.rules._event_metadata(event)` helper that reads
  `event.metadata_` first, falling back to `raw_log['metadata']` for
  backward compatibility with existing data. See **Connectors** below for
  the full account; this is the concrete defect that justified touching
  `detection/` during connector work, per the "do not redesign without
  identifying a concrete defect" instruction.
- **`FILE_OPERATION` and `SYSTEM_ALERT` are now reachable** (Sysmon EventID
  11 and Suricata EVE `alert` respectively map to them — see **Connectors**
  below) **but still have no detection rule consuming them**, same as
  `NETWORK_TRAFFIC`. Producing the canonical type and detecting on it are
  separate concerns; connector work only does the former.
- **No network/C2 or IDS-alert detection rule exists** (audit findings D-4/
  D-5) — `NETWORK_TRAFFIC` and `SYSTEM_ALERT` events normalize successfully
  through this contract but have nothing downstream to detect on them. This
  is why the user's plan explicitly requires Scenario 3 (Suricata/network
  C2) to be marked **blocked** when Phase 13 scenario tests are eventually
  attempted — the contract (and now the Suricata connector) does not create
  a detection capability that doesn't exist.
- **All three named connectors implemented (Sysmon, Suricata EVE, Splunk
  HEC).** The original contract phase was scoped "before implementing
  connectors"; follow-up sessions implemented all three named in CLAUDE.md
  roadmap Step 5 (see **Connectors** below). Phase 13 scenarios that depend
  on a connector existing are no longer blocked on that basis. The
  Suricata/network-C2 scenario specifically remains blocked by the missing
  network/C2 detection rule (D-4/D-5), not by a missing connector — no
  connector can substitute for a detection rule that doesn't exist yet.
- **Ingestion metrics remain process-local** (pre-existing, unrelated to
  this phase — tracked under audit item A-8 and Phase 10/durable-bus work).

## Connectors

### Sysmon (connector #1, implemented)

**What it is.** Accepts telemetry from Sysinternals Sysmon — specifically the
flattened JSON shape common shippers (Winlogbeat, NXLog) produce when
forwarding the `Microsoft-Windows-Sysmon/Operational` channel, e.g.
`{"EventID": 1, "UtcTime": "2026-09-20 08:15:22.123", "Hostname": "...",
"User": "...", "Image": "...", "CommandLine": "...", ...}` — **not** raw
EVTX/XML.

**Endpoint.** `POST /events/ingest/sysmon`, same `X-API-Key` header and Redis
rate limiter as `POST /events/ingest` (reuses `verify_ingestion_api_key` and
`ingestion_rate_limiter` unchanged). Request body: `{"event": {...}}`, one
Sysmon event per request — batched delivery is not supported (see
Limitations). Response:
`{"status": "accepted"|"duplicate", "event_id", "timestamp", "hostname",
"event_type", "canonical_event_type", "ingest_mode"}`.

**Supported EventIDs and field mapping** (`backend/plugins/parsers/sysmon.py`):

| Sysmon EventID | Meaning | `canonical_event_type` | Fields mapped into `metadata` |
|---|---|---|---|
| `1` | Process Create | `PROCESS_EXECUTION` | `process_name` (basename of `Image`), `command_line` (`CommandLine`), `parent_process` (basename of `ParentImage`), `parent_command_line`, `hashes` (if present) |
| `3` | Network Connect | `NETWORK_TRAFFIC` | `process_name`, `ip_address` **and** `destination_ip` (both set to `DestinationIp` — closes the ip_address/destination_ip naming gap in "Known limitations" for this connector's own output), `source_ip`, `destination_port`, `protocol` |
| `11` | File Create | `FILE_OPERATION` | `process_name`, `target_filename` (`TargetFilename`) |

Any other EventID — including `4624`/`4625`/`4672` (Windows Security
auditing, a genuinely different provider from Sysmon even though
`core.taxonomy` maps those IDs too) — is rejected with `422` and an explicit
message naming which IDs are supported. This is a deliberate choice: a
connector should say what it doesn't support, not silently drop or
mis-normalize it. Windows Security auditing is real future connector
material (see "How to add another connector" below), just not this one.

Other field handling:
- `hostname`: `Hostname` (Winlogbeat's own added field) if present, else
  `Computer` (the raw forwarded XML field).
- `user_name`: `User`, with a `DOMAIN\`/`HOST\` prefix stripped
  (`WORKSTATION-01\jdoe` → `jdoe`) to match the bare usernames used
  everywhere else in the system (detection rules, correlation, replay
  datasets).
- `timestamp`: Sysmon's `UtcTime` (`"YYYY-MM-DD HH:MM:SS.fff"`, space
  separated) is **not** strict ISO-8601, so the connector parses it with
  `dateutil.parser.parse()` (lenient) and hands the canonical contract a
  real `datetime` object directly — the contract's own `from_raw()` only
  accepts strict ISO strings via `isoparse`, which would have silently
  fallen back to "now" for every Sysmon event otherwise.
- `raw_log`: the entire original Sysmon event, untouched — this connector
  never rewrites or duplicates fields into it, unlike the replay datasets
  and generic ingest, which is exactly what exposed the `metadata_`-reading
  defect documented above.
- `severity`: always `"INFO"`. Sysmon carries no native severity; the
  connector does not fabricate a risk assessment it has no authority to
  make. Real severity comes from whichever detection rule matches
  afterward (e.g. `SuspiciousProcessExecution` assigns `HIGH`).

**Duplicate-event handling.** Before publishing, the endpoint computes the
same SHA-256 content hash `core.integrity.compute_event_hash()` would (over
`timestamp, hostname, user_name, source, event_type, severity, raw_log,
metadata`) and queries `events.payload_sha256` (already indexed) for a match
(`core.integrity.find_duplicate_event_id`). A match returns
`{"status": "duplicate", "event_id": <existing id>}` immediately, without
publishing again. **This is best-effort, not a hard guarantee**: there is no
unique constraint on `payload_sha256` (adding one needs a migration — out of
scope while the Alembic fresh-install remediation is still only a proposal,
see `docs/MIGRATION_REMEDIATION_PROPOSAL.md`), and the check runs before the
*first* submission's async consumer has necessarily committed it to Postgres
— two submissions of the identical event arriving within that window (proven
live: two `curl` calls issued back-to-back, no delay, both stored with
identical hashes) will race past the check and both be stored. Confirmed
live that the check **does** work for the realistic case — a redelivery
arriving after the first has actually landed (a few seconds' gap; real
shipper restarts take far longer than that) is correctly suppressed and
returns the original `event_id` with no second row created.

**Why `detection/rules.py` and `detection/engine.py` were touched.** Per the
explicit instruction not to redesign the canonical contract without a
concrete defect: building this connector's end-to-end test (a real Sysmon
Process Create event with an encoded PowerShell command line) found that
`SuspiciousProcessExecution` never fired, and no evidence was ever created —
not a flaky test, a real, 100%-reproducible miss. The rule (and four spots in
`detection/engine.py`) read `event.raw_log.get('metadata', {})`, expecting
`metadata` to be duplicated *inside* `raw_log`. Every existing caller
(`GenericJSONParser`'s fallback logic, every replay dataset, every hand-built
test fixture) happened to do exactly that — nest metadata inside raw_log —
so this was never exercised as a failure before. The canonical contract's
own field semantics keep `metadata` and `raw_log` as separate, sibling
fields (`to_orm_kwargs()` writes them to separate ORM columns:
`metadata_`/`raw_log`), and the Sysmon connector is the first real caller to
follow that correctly — which is exactly what surfaced the bug. Fixed with
one shared helper, `detection.rules._event_metadata(event)`, that reads the
real `event.metadata_` column first and falls back to `raw_log['metadata']`
only for legacy-shaped data — a strict improvement with no backward-compat
risk, since `from_raw()` always populates `metadata_` with at least whatever
`raw_log['metadata']` would have contained anyway. Verified: the end-to-end
test fails without this fix (confirmed via `git stash` of just these two
files) and passes with it; the full 262-test suite is unaffected.

### Suricata EVE (connector #2, implemented)

**What it is.** Accepts records from Suricata's EVE JSON output
(`eve.json`), the flow-oriented, line-delimited JSON the Suricata IDS/IPS
engine emits — not the legacy unified2/fast.log formats. Each EVE record
carries its own top-level `event_type` field (Suricata's own field name,
distinct from the canonical contract's `event_type` concept) that
discriminates the record shape, e.g. `{"event_type": "alert", "src_ip":
"...", "dest_ip": "...", "alert": {"signature": "...", "severity": 1, ...}}`.

**Endpoint.** `POST /events/ingest/suricata`, same `X-API-Key` header, Redis
rate limiter, and duplicate-suppression approach as `POST
/events/ingest/sysmon` (reuses `verify_ingestion_api_key`,
`ingestion_rate_limiter`, `core.integrity.find_duplicate_event_id`
unchanged). Request body: `{"event": {...}}`, one EVE record per request —
`eve.json` is line-delimited on disk, but batching multiple lines into one
request is not supported (see Limitations). Response:
`{"status": "accepted"|"duplicate", "event_id", "timestamp", "hostname",
"event_type", "canonical_event_type", "ingest_mode"}`.

**Supported EVE `event_type` values and field mapping**
(`backend/plugins/parsers/suricata.py`):

| EVE `event_type` | Meaning | `canonical_event_type` | Fields mapped into `metadata` |
|---|---|---|---|
| `alert` | NIDS signature match | `SYSTEM_ALERT` | `signature`, `signature_id`, `category`, `alert_action` (from the nested `alert` object), `suricata_severity` (Suricata's own 1–3 value), plus the shared network fields below |
| `flow` | Connection/flow record | `NETWORK_TRAFFIC` | `app_proto`, `bytes_toserver`, `bytes_toclient`, `pkts_toserver`, `pkts_toclient`, `flow_state` (from the nested `flow` object), plus the shared network fields below |

Shared network fields (both types): `source_ip` (`src_ip`), `source_port`
(`src_port`), `destination_ip` **and** `ip_address` (both set to `dest_ip` —
same dual-key convention the Sysmon connector uses for its Network Connect
mapping, for the same entity-extraction compatibility reason),
`destination_port` (`dest_port`), `protocol` (`proto`).

Both `canonical_event_type` mappings are new, purely additive entries in
`core/taxonomy.py`'s `_TAXONOMY_MAP` (`"suricata alert"` →`SYSTEM_ALERT`,
`"network flow"` → `NETWORK_TRAFFIC`). `SYSTEM_ALERT` existed in the
`CanonicalEventType` enum but had no string/ID mapping reaching it before
this connector — the same "defined but unreachable" situation
`FILE_OPERATION` was in before the Sysmon connector added Sysmon EventID 11.

Any other EVE `event_type` — `dns`, `http`, `tls`, `fileinfo`, `stats`, etc.
— is rejected with `422` and an explicit message, not silently normalized.
Each of those record types has a materially different field shape; adding
one means giving it its own explicit mapping the same way `flow` was added
here, not stretching this connector's assumptions to cover fields it was
never built to read.

Other field handling:
- `hostname`: EVE carries no built-in identity for the traffic's endpoints
  (Suricata observes the wire, not a process) — `host` is the *sensor's*
  own hostname, populated only when Suricata's optional `host-info` EVE
  output extension is enabled. When absent, the canonical contract's own
  `"unknown"` sentinel default applies, same as any source with no real
  host (excluded from correlation matching, per the contract's existing
  convention).
- `user_name`: not set by this connector (EVE carries no user identity);
  defaults to the contract's `"unknown"` sentinel.
- `timestamp`: EVE's timestamp (`"2026-09-20T10:15:22.123456+0000"`) uses a
  colon-less UTC offset that the contract's own strict `isoparse` does not
  reliably accept, so the connector parses it with `dateutil.parser.parse()`
  (lenient) and hands the contract a real `datetime` object directly — same
  approach and same reason as the Sysmon connector's `UtcTime` handling.
- `raw_log`: the entire original EVE record, untouched, for chain of
  custody — same convention as the Sysmon connector.
- `severity`: for `alert` records, mapped from Suricata's own
  `alert.severity` (1 = highest priority in Suricata/ET convention) via a
  conservative table — `1`→`HIGH`, `2`→`MEDIUM`, `3` or missing/unrecognized
  →`LOW` (never `INFO`, since an `alert` record is by definition always a
  signature match, and never `CRITICAL`, since this connector normalizes
  vendor severity, it does not decide investigation severity — no
  detection rule reads this field yet). For `flow` records, always
  `"INFO"` — a flow record is raw telemetry, not itself a finding, same
  rationale as the Sysmon connector's Network Connect events.
- `alert.signature` is required for `alert` records (rejected with `422` if
  missing) — an alert connector's core job is to carry a signature match
  forward as evidence (CLAUDE.md Rule 5); an "alert" with no signature
  would misrepresent what it is.

**No detection rule currently targets `SYSTEM_ALERT` or `NETWORK_TRAFFIC`**
(see "How to add another connector" step 7 below, and
`YAROX_REALITY_AUDIT.md` D-4/D-5). A Suricata alert — even a genuine,
high-confidence signature match like "ET TROJAN Cobalt Strike Beaconing
Detected" — is normalized, stored, hashed, and available as evidence exactly
like any other event, but does not by itself create an `InvestigationCase`
yet. Confirmed live: a real alert event posted to the running stack stored
correctly (`canonical_event_type: SYSTEM_ALERT`, `severity: HIGH`,
`metadata.signature` intact, `payload_sha256` verified) with no
`EvidenceItem`/`InvestigationCase` created — the expected, documented
behavior, not a defect in this connector. Closing that gap is Phase 13
detection-rule work.

### Splunk HEC (connector #3, implemented)

**What it is.** Accepts Splunk's HTTP Event Collector (HEC) JSON envelope —
`{"time": <epoch>, "host": ..., "source": ..., "sourcetype": ..., "index":
..., "event": {...}}` — targeting an inner `event` shaped as a Splunk Common
Information Model (CIM) Alert, the shape a Splunk "Alert Action" webhook
forwards for a matched correlation search (see
`docs/YAROX_ARCHITECTURAL_RECONSTRUCTION.md` "Ingestion Mechanisms" and its
Connector Transformation Matrix, row "Splunk CIM Alert").

**Endpoint.** `POST /events/ingest/splunk`, same `X-API-Key` header, rate
limiter and duplicate-suppression approach as the other two connectors.
Unlike `SysmonIngestRequest`/`SuricataIngestRequest`, the request schema is
**not** `{"event": {...}}` nested one level down — it's the HEC envelope
fields at the top level (`time`, `host`, `source`, `sourcetype`, `index`,
`event`), because that already *is* HEC's real wire shape; adding another
wrapping layer would not match what a real HEC client sends. Response shape
is otherwise identical to the other two connectors'.

**Different in kind from Sysmon/Suricata: no closed event-type enum.**
Sysmon has a fixed set of numeric EventIDs; Suricata EVE has a fixed set of
`event_type` strings. A Splunk correlation search's `signature` can be any
text an operator has written — there is no fixed set to enumerate and
reject against. This connector's job is therefore CIM field-name
translation only (`backend/plugins/parsers/splunk.py`); classifying the
resulting `event_type` string reuses the same generic taxonomy heuristics
(`core.taxonomy.EventTaxonomyNormalizer`'s substring matching) that
`plugins.parsers.generic.GenericJSONParser` already applies for live/generic
ingestion — **no new taxonomy mapping was added for this connector**,
unlike Sysmon (EventID 11) or Suricata (`alert`/`flow`).

**CIM field mapping** (per the architecture doc's Connector Transformation
Matrix, "Splunk CIM Alert" row):

| CIM field | Canonical field | Notes |
|---|---|---|
| `_time` (in `event`), else HEC's own `time` | `timestamp` | Both are Unix epoch, not ISO strings — parsed with `datetime.fromtimestamp()`, not the contract's `isoparse` |
| `dest`, else `dvc` | `hostname` | Per the transformation matrix: "entity resolution," not an IP field |
| `dest_ip` (separate from `dest`) | `metadata.destination_ip` **and** `metadata.ip_address` | Disambiguated from `dest`/hostname — same dual-key convention as Sysmon/Suricata |
| `src` | `metadata.source_ip` | |
| `user` | `user_name` | `DOMAIN\` prefix stripped, same rule as Sysmon |
| `signature`, else `sourcetype`, else `"Splunk HEC Event"` | `event_type` (pre-taxonomy) | Feeds the generic heuristic classifier — see above |
| `severity` (CIM string: informational/low/medium/high/critical) | `severity` | Case-insensitive direct map to YAROX's severities; missing/unrecognized → `INFO` |
| `app` | `metadata.app` | **Deliberately not** forced into `protocol` or `process_name` despite the architecture doc's literal "app → protocol / process_name" suggestion — CIM's `app` names a reporting application/technology (e.g. `"win:security"`), which is neither reliably a network protocol nor a process name; mapping it into either would fabricate a fact the field doesn't actually state (CLAUDE.md Rule 2/Rule 5). A documented, deliberate narrowing, not an oversight. |
| `source`/`sourcetype`/`index` (HEC's own routing fields) | `metadata.splunk_source`/`splunk_sourcetype`/`splunk_index` | Kept distinct from this connector's own `source` value (`"splunk"`, the connector identity) to avoid conflating the two |

**Validation.** The envelope must be a JSON object with an `event` key (the
one thing every HEC payload has by protocol definition), and `event` itself
must be a JSON object — **raw-text HEC events are explicitly rejected**
(`422`), not silently accepted with an empty/fabricated metadata dict. HEC
officially allows raw-text events, but this connector cannot reliably
extract CIM fields (`dest`, `user`, `signature`, ...) from unstructured
text without an NLP layer this phase does not add.

**No detection rule currently targets most heuristically-classified
`event_type`s beyond what the existing rules already cover** — but unlike
the Suricata connector, this one *can* and does drive a real detection: a
`signature` like `"Multiple Failed Logon Attempts"` matches the existing
`fail`+`logon` substring heuristic → `AUTH_FAILURE` → the unmodified
`FailedLoginBruteForce` rule. Verified both by an end-to-end test (two HEC
alerts for the same synthetic user, real `InvestigationCase` created) and
live against the running stack (see Evidence below) — this connector proves
CIM-mapped events integrate with the *existing* detection surface, not
just that rows land in Postgres, without needing any new detection rule.

### How to add another connector

The Sysmon, Suricata EVE and Splunk HEC connectors are the template. To add
another one:

1. Write a parser module under `backend/plugins/parsers/<name>.py`
   implementing `ParserInterface` (`plugins/parsers/generic.py`) — a
   `parse(raw_data) -> Dict[str, Any]` returning `Event`-constructor kwargs.
   In practice: transform the vendor's field names into the generic shape
   (`timestamp`, `hostname`, `user_name`, `source`, `event_type`, `severity`,
   `raw_log`, `metadata`) and call
   `schemas.canonical_event.CanonicalSecurityEvent.from_raw(...)` — reuse the
   one contract's validation, don't reimplement it. Keep `raw_log` as the
   untouched original payload (chain of custody) and put extracted,
   detection-relevant fields only in `metadata` — do not duplicate them into
   `raw_log`, and do not skip this because `detection/` now reads
   `metadata_` correctly regardless.
2. Explicitly enumerate which of the vendor's event types/IDs the connector
   supports and reject anything else with a clear error — don't silently
   normalize unknown input to `UNKNOWN`. If the vendor's event IDs overlap
   with another provider's (like Sysmon's numeric IDs vs. Windows Security's
   4624/4625/4672), keep them in genuinely separate connectors named for
   their real source, not bundled under a convenient but inaccurate label.
3. Add a request schema in `backend/schemas/ingest.py` (or a new
   `schemas/<name>.py`) — usually just `{event: Dict[str, Any]}` with a
   payload-size guard; let the parser be the single source of field-level
   validation, matching the Sysmon schema's approach.
4. Add an endpoint in `backend/api/ingest.py`:
   `@router.post("/<name>", ...)`, reusing `verify_ingestion_api_key`,
   `ingestion_rate_limiter`, `metrics_tracker`, and `event_bus.publish(...)`
   unchanged. Decide whether duplicate suppression matters for this source
   (it does for anything that might redeliver, e.g. file-tailing shippers)
   and reuse `core.integrity.find_duplicate_event_id` if so.
5. If the vendor's event types need new taxonomy coverage, extend
   `core/taxonomy.py`'s `_EVENT_ID_MAP`/`_TAXONOMY_MAP` — purely additive,
   safe, and exactly how this connector added Sysmon EventID 11 →
   `FILE_OPERATION` (previously unreachable).
6. Write tests covering, at minimum: field mapping (one test per supported
   event type), validation failures (missing/invalid required vendor
   fields, unsupported event types, oversized payload), duplicate-event
   handling, and one real end-to-end test — HTTP request through the real
   event bus to a real stored, hashed row, and, if a detection rule should
   plausibly match your test payload, confirmation that it actually does
   (this is what catches defects like the `metadata_` one above; a version
   of the end-to-end test that stops at "row exists in Postgres" would have
   missed it entirely).
7. If detection doesn't fire when you expected it to, check whether the
   miss is because no rule covers that `canonical_event_type` yet (e.g.
   `NETWORK_TRAFFIC`/`FILE_OPERATION`/`SYSTEM_ALERT` currently have no
   detection rule — D-4/D-5) before assuming the connector or contract is
   broken. Adding new detection rules is Phase 13 territory, not connector
   work — a connector's job is to normalize correctly, not to guarantee
   detection.

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

## Evidence (Sysmon connector, follow-up session)

- Files: `backend/plugins/parsers/sysmon.py` (new), `backend/schemas/ingest.py`
  (+`SysmonIngestRequest`/`SysmonIngestResponse`), `backend/api/ingest.py`
  (+`POST /events/ingest/sysmon`), `backend/core/integrity.py`
  (+`find_duplicate_event_id`), `backend/core/taxonomy.py` (+EventID 11 →
  `FILE_OPERATION`), `backend/detection/rules.py`/`backend/detection/engine.py`
  (`_event_metadata()` fix — see "Connectors" above for why), new test file
  `backend/tests/test_sysmon_connector.py` (18 tests).
- `docker compose exec backend pytest -v tests/test_sysmon_connector.py` →
  **18 passed**: 6 field-mapping tests (per-EventID mapping, domain-stripping,
  Hostname/Computer fallback, lenient `UtcTime` parsing, missing-timestamp
  fallback, severity default), 7 validation-failure tests (missing EventID,
  non-integer EventID, unsupported EventID incl. explicitly the Windows
  Security `4688` case, non-dict payload, oversized payload over HTTP,
  missing API key), 3 duplicate-detection tests (unit-level hash match/no-match,
  one HTTP-level redelivery test), 1 end-to-end test through the real bus.
- Confirmed the end-to-end test and the `_event_metadata` fix are both real,
  not decorative: `git stash push -- backend/detection/rules.py
  backend/detection/engine.py` and re-running
  `test_end_to_end_process_create_is_stored_hashed_and_detected` reproduces
  the original failure (`AssertionError: ... must trigger
  SuspiciousProcessExecution and be cited as evidence`); restoring the stash
  passes it again.
- `docker compose exec backend pytest -q tests/` → **262 passed** (244 + 18),
  run 3 times consecutively, zero flakes.
- Live, on the running stack (`docker compose restart backend celery_worker`):
  - `POST /events/ingest/sysmon` with a real Process Create event (`cmd.exe
    /c hostname`) → `202 {"status": "accepted", ...}`; a joined Postgres
    query confirmed a real `InvestigationCase` ("Command and Scripting
    Interpreter", HIGH) with a matching `EvidenceItem` citing the exact
    `event_id`.
  - An immediate (no-delay) duplicate resend raced past the dedup check and
    was stored a second time with an identical `payload_sha256` — this is
    the documented race-window limitation reproduced live, not a surprise.
  - The same test repeated with a 3-second gap correctly returned
    `{"status": "duplicate", "event_id": <original>}` with no second row —
    `SELECT count(*) ... = 1`, confirming the intended, realistic-case
    behavior.
  - Network Connect (`EventID 3`) and File Create (`EventID 11`) events both
    ingested successfully with `canonical_event_type` reported as
    `NETWORK_TRAFFIC`/`FILE_OPERATION` respectively.
  - `EventID 7` (unsupported) and `EventID 4688` (Windows Security, a
    different provider) both returned `422` with the expected message.
  - No errors or tracebacks in `backend`/`celery_worker` logs across the
    restart or any of the above requests.

**Known limitations specific to this connector** (beyond the ones listed
above): no batch ingestion (one event per HTTP request); duplicate detection
has a race window (documented and reproduced live, both above); Windows
Security auditing events (4624/4625/4672) are explicitly not accepted by
this connector and remain unimplemented as their own connector; only 3 of
Sysmon's ~29 event types are mapped (Process Create, Network Connect, File
Create) — chosen because they're the most common and, for EventID 1, the
only one with existing detection coverage.

**Completion criterion (connector):** the Sysmon connector is implemented
using the existing canonical contract (no parallel validation path), field
mapping/validation/duplicate/end-to-end behavior is each backed by a test,
the tests are confirmed to genuinely discriminate (not decorative), it has
been verified live against the running stack including a real detection
match, and the one concrete defect found along the way
(`detection/`'s `raw_log`-only metadata reads) is fixed with evidence, not
worked around. Per the governing instruction, Phase 13 has not been started.

## Evidence (Suricata EVE connector, follow-up session)

- Files: `backend/plugins/parsers/suricata.py` (new), `backend/schemas/ingest.py`
  (+`SuricataIngestRequest`/`SuricataIngestResponse`), `backend/api/ingest.py`
  (+`POST /events/ingest/suricata`), `backend/core/taxonomy.py` (+`"suricata
  alert"` → `SYSTEM_ALERT`, `"network flow"` → `NETWORK_TRAFFIC`), new test
  file `backend/tests/test_suricata_connector.py` (19 tests). No changes to
  `detection/` this time — no concrete defect was found (see below on why
  the end-to-end test doesn't assert a detection match).
- `docker compose exec backend pytest -v tests/test_suricata_connector.py` →
  **19 passed**: 9 field-mapping tests (`alert`/`flow` mapping, Suricata
  severity 1/3/missing → HIGH/LOW/LOW, missing-host fallback to the
  `"unknown"` sentinel, colon-less EVE timestamp offset parsing,
  missing-timestamp fallback), 8 validation-failure tests (missing EVE
  `event_type`, unsupported EVE `event_type` both at the parser level and
  over HTTP, `alert` record missing `alert.signature` both with and without
  the `alert` object present, non-dict payload, oversized payload over HTTP,
  missing API key), 1 duplicate-redelivery test, 1 end-to-end test through
  the real bus.
- `docker compose exec backend pytest -q tests/` → **284 passed** (265 + 19:
  262 Phase-11/Sysmon baseline + 3 `test_migration_genesis.py` from the X-5
  fix + 19 new here), no regressions.
- Live, on the running stack (`docker compose restart backend celery_worker`):
  `POST /events/ingest/suricata` with a real `alert` record (`ET TROJAN
  Cobalt Strike Beaconing Detected`, `alert.severity: 1`) → `202
  {"status": "accepted", "canonical_event_type": "SYSTEM_ALERT", ...}`; a
  direct Postgres query confirmed the stored row: `source=suricata`,
  `event_type=SYSTEM_ALERT`, `severity=HIGH`,
  `metadata->>'signature'='ET TROJAN Cobalt Strike Beaconing Detected'`, and
  a non-null `payload_sha256`. Confirmed **no** `EvidenceItem` was created
  for it — the expected, documented outcome (no detection rule targets
  `SYSTEM_ALERT` yet; D-4/D-5), not a bug. The manually-inserted
  verification row was deleted afterward to keep the dev database clean, per
  the standing "do not purge dev data" constraint — this was a row created
  and removed within this same verification step, not pre-existing data.

**Known limitations specific to this connector**: no batch ingestion (one
EVE record per HTTP request, same as Sysmon); duplicate detection has the
same race window documented for the Sysmon connector (not independently
re-verified live for this connector — the unit/HTTP-level tests cover the
non-race-window case); only two of EVE's several record types are mapped
(`alert`, `flow`) — `dns`/`http`/`tls`/`fileinfo`/`stats` remain
unimplemented and are rejected explicitly rather than silently accepted;
`hostname` reflects the Suricata sensor, not either traffic endpoint (EVE
has no concept of an "originating host" the way Sysmon does), so
correlation by hostname will not connect a Suricata alert to the endpoint
that produced the traffic without additional IP-to-host attribution this
phase does not add; most importantly, `SYSTEM_ALERT` and `NETWORK_TRAFFIC`
events reaching this contract still have no detection rule consuming them —
the connector normalizes correctly, it does not create a detection
capability that doesn't exist (D-4/D-5, Phase 13 territory).

**Completion criterion (connector):** the Suricata EVE connector is
implemented using the existing canonical contract (no parallel validation
path, both new taxonomy entries purely additive), field
mapping/validation/duplicate/end-to-end behavior is each backed by a test,
and it has been verified live against the running stack with a real stored,
hashed row. Unlike the Sysmon connector, no detection-side defect was found
or claimed to be fixed — the end-to-end test and the live verification both
explicitly confirm the documented absence of `SYSTEM_ALERT`/`NETWORK_TRAFFIC`
detection coverage rather than asserting a match that would not occur. Per
the governing instruction, Phase 13 (detection rules for these types) has
not been started.

## Evidence (Splunk HEC connector, follow-up session)

- Files: `backend/plugins/parsers/splunk.py` (new), `backend/schemas/ingest.py`
  (+`SplunkHECIngestRequest`/`SplunkHECIngestResponse`), `backend/api/ingest.py`
  (+`POST /events/ingest/splunk`), new test file
  `backend/tests/test_splunk_connector.py` (23 tests). No changes to
  `core/taxonomy.py` or `detection/` — see "Splunk HEC" above for why (no
  closed event-type set; reuses the existing generic heuristic classifier).
- `docker compose exec backend pytest -v tests/test_splunk_connector.py` →
  **23 passed**: 12 field-mapping tests (CIM field mapping, `dest`/`dvc`
  fallback, `dest_ip` disambiguation from `dest`, parametrized CIM severity
  mapping across all 5 values, missing-severity default, `_time`/`time`
  priority and fallback, missing-both-timestamps fallback, signature-driven
  taxonomy classification via the *existing* heuristics, signature/sourcetype
  fallback chain), 6 validation-failure tests (missing `event` key, raw-string
  `event` rejected both at the parser level and over HTTP, non-dict envelope,
  oversized payload, missing API key), 1 duplicate-redelivery test, 1
  end-to-end test asserting a real detection match (not just storage).
- `docker compose exec backend pytest -q tests/` → **307 passed** (284 + 23),
  no regressions.
- Live, on the running stack (`docker compose restart backend celery_worker`):
  two real `POST /events/ingest/splunk` calls, both `signature: "Multiple
  Failed Logon Attempts"` for the same synthetic user, 1 second apart → both
  `202 {"canonical_event_type": "AUTH_FAILURE", ...}`; a joined Postgres
  query confirmed a real `InvestigationCase` ("Brute Force", HIGH) with a
  matching `EvidenceItem` (`evidence_type: AUTHENTICATION_FAILURE`) citing
  the second event's `event_id` — the same `FailedLoginBruteForce` rule
  Sysmon's own live verification exercised, now proven reachable from a
  third, independently-mapped source with zero rule changes. The live
  verification also (as expected) triggered the real Phase 7 Celery
  multi-agent investigation pipeline against the synthetic case; all
  verification rows (events, evidence, attack technique, security
  relationship, agent executions/reasoning/tool-call rows, and the case
  itself) were deleted afterward once the in-flight agent executions
  finished, to avoid deleting rows out from under a running background task.

**Known limitations specific to this connector**: no batch ingestion (one
HEC envelope per HTTP request); raw-text HEC events are not supported
(structured CIM `event` objects only); `app` is preserved as-is rather than
being split into `protocol`/`process_name` as the architecture doc's
transformation matrix literally suggests (see field-mapping table above for
the reasoning); classification quality for any signature not already
covered by the existing generic taxonomy heuristics is whatever
`EventTaxonomyNormalizer` already provides (i.e. often `UNKNOWN`) — this
connector adds no new classification intelligence of its own, by design;
duplicate detection has the same race-window characteristics documented for
Sysmon (not independently re-verified live here).

**Completion criterion (connector):** the Splunk HEC connector is
implemented using the existing canonical contract, CIM field mapping is
justified against `docs/YAROX_ARCHITECTURAL_RECONSTRUCTION.md`'s own
Connector Transformation Matrix (with one deliberate, documented narrowing),
field mapping/validation/duplicate/end-to-end behavior is each backed by a
test, and it has been verified live against the running stack **with a real
detection match** — a stronger bar than the Suricata connector could meet,
met here because this source's classification path reuses detection
coverage that already exists. All three connectors named in CLAUDE.md
roadmap Step 5 (Sysmon, Suricata EVE, Splunk HEC) are now implemented.
