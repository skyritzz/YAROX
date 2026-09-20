# YAROX Phase 14 — Scenario Orchestration

**Status:** implemented and tested — three scenarios, real-stack verified.

This phase builds a reusable way to mechanically verify YAROX's full pipeline
— scenario definition → real event ingestion → durable storage → detection →
case correlation → asynchronous multi-agent investigation → evidence-linked
report → structured pass/fail result — closing the gap identified before any
code was written: nothing in the automated test suite drove a
*detection-triggered* (not directly-invoked) Celery investigation to
completion and compared the outcome against a declared expectation.

## 1. What already existed (audited before writing anything)

Two relevant systems existed and were extended from, not duplicated:

1. **`evaluation/runner.py` + `evaluation/schemas.py`** (Phase 4C) — a mature
   "expected outcome" contract (`GroundTruthScenario`: 12 scenarios across
   BENIGN/CLEAR_INCIDENT/AMBIGUOUS/MULTI_STAGE/CONCURRENT/ADVERSARIAL). **But
   it bypasses the real pipeline**: it constructs `Event` ORM rows directly
   and calls `detection_engine.process_event()` / `orchestrator.
   run_investigation()` synchronously in-process — never touching the event
   bus, Redis Streams, connector parsers, or Celery. Its DB/orchestrator-
   driving code has zero pytest coverage (only its pure scoring functions
   are unit-tested); it is a CLI-only tool. Left untouched — a separate
   system with a separate purpose (agent-quality scoring), not what this
   phase needed.
2. **`replay/engine.py` + `api/replay.py`** — a real, working system
   (`ReplayEngine`, one instance per session — confirmed not a shared
   singleton, so concurrent sessions don't collide on its own state — loads
   `datasets/{name}/events.json` via `GenericJSONParser`, publishes onto the
   real event bus, tracks progress via a `ReplaySession` row). Its only
   existing test used a fully mocked event bus — no real Redis Streams, no
   real detection, no real case/evidence verification ever happened for
   this path before this phase.

Neither system drove connector-shaped events (Suricata EVE, Sysmon, Splunk
HEC) through their real HTTP endpoints, waited for a real Celery-dispatched
investigation using the correct completion signal, or produced a reusable
pass/fail result with reasons. That is what this phase adds — reusing
`ReplayEngine.load_dataset()` for dataset loading and the real, existing
ingestion endpoints for event dispatch, per the governing instruction not to
build a parallel replay or event-publishing system.

## 2. Scenario contract — `backend/scenarios/schemas.py`

`ScenarioDefinition` (versioned, `SCENARIO_CONTRACT_VERSION = "1.0"`):
`scenario_id`, `name`, `description`, `events: List[ScenarioEventDef]`
(non-empty), `expected: ExpectedOutcome`, `notes`.

`ScenarioEventDef`: `connector` (`"suricata"|"sysmon"|"splunk"|"generic"|
"replay"`), `relative_offset_seconds`, `payload` (raw, connector-shaped —
real Suricata EVE JSON / Sysmon flattened JSON / Splunk HEC envelope / a
generic canonical-ish dict), `label`.

**Why five connector values, not four.** `"suricata"`/`"sysmon"`/`"splunk"`
map to the real `POST /events/ingest/<name>` HTTP endpoints. `"generic"`
maps to the real `POST /events/ingest` endpoint, which requires the payload
to already satisfy `schemas.ingest.IngestEventRequest` (`raw_log` present).
**`"replay"` was added after discovering a real incompatibility**:
`datasets/insider_threat/events.json`'s raw event shape predates that
schema — it has no `raw_log` key and uses `user`, not `user_name`.
`CanonicalSecurityEvent.from_raw()` tolerates this (`raw_log` defaults to
the whole input dict); `IngestEventRequest`'s stricter schema does not.
Rather than fabricate a synthetic `raw_log` wrapper around a real fixture,
`"replay"` dispatches through the same lower-level path
`replay.engine.ReplayEngine.stream_events()` itself uses internally
(`GenericJSONParser.parse()` + a direct event-bus publish) — a second real,
pre-existing path, not an invented one.

`ExpectedOutcome`: `should_create_case`, `min_case_count`/`max_case_count`,
`expected_detections: List[ExpectedDetection]` (`evidence_type` +
`min_count`), `expect_correlated_single_case`, `min_evidence_count`,
`expect_investigation_to_run`, `expect_report`. Kept structurally separate
from `ScenarioExecutionResult` (actual outcomes) throughout — a scenario
"passing" is always a comparison between the two, computed in
`ScenarioOrchestrator._evaluate_expectations`, never a proxy like "the API
returned 2xx."

## 3. Orchestrator — `backend/scenarios/orchestrator.py`

`ScenarioOrchestrator.run(scenario, *, wait_for_investigation, event_storage_timeout,
investigation_timeout, cleanup)` → `ScenarioExecutionResult` (`execution_id`,
`passed`, `reasons` — non-empty iff `passed` is `False` — `warnings`,
`event_ids`, `case_ids`, `evidence_counts`, `investigations`,
`cleanup_performed`/`cleanup_skipped_reason`).

Lifecycle: validate → dispatch every event through its real endpoint/path,
honoring `relative_offset_seconds` (capped at `MAX_INTER_EVENT_SLEEP_SECONDS
= 2.0`, the same "smart fast-forward" policy `ReplayEngine` already applies
to its own pacing) → confirm durable storage (bounded poll, never assumed) →
discover correlated cases/evidence (poll-until for a scenario expecting
detection, a fixed grace window for one that doesn't — see §4) → wait for
each case's investigation to reach a terminal state if expected → compare
against `expected` → build `reasons` → optionally clean up.

### Isolation, not a marker field alone

Per-execution correctness (which events/cases belong to *this* run) is
anchored to the real event IDs the real ingestion paths return — never to a
tag a specific connector parser might drop. A best-effort trace tag
(`_apply_isolation`) additionally rides in whichever field each connector's
real parser actually preserves verbatim for that shape (top-level key in
`raw_log` for Suricata/Sysmon; inside the `event` sub-object for Splunk,
since its envelope is Pydantic-validated before reaching the parser and
would silently drop an unrecognized top-level key; the real `metadata` field
for generic/replay) — useful for a human debugging a stuck run by querying
the database directly, never load-bearing for correctness.

Hostname/user values ARE suffixed per execution (necessary: `correlation.
engine.CorrelationEngine` matches on those columns, so two concurrent
executions of the same fixture would otherwise correlate into each other's
case). This is not a new risk — every Phase 11-13 connector test and live
verification already does exactly this. `tests/test_scenario_orchestration.
py::test_isolation_suffix_does_not_change_whether_the_detection_rule_matches`
explicitly proves the suffix changes nothing about whether a rule fires.

## 4. Three real bugs found and fixed while validating this against the running stack

None were caught by writing the code — all three were caught by actually
running it against a real Celery worker and real Ollama, which is exactly
why this phase's own live verification (not just its unit tests) matters.

**Bug 1 — a race between event storage and detection.** The first design
queried for correlated evidence immediately after confirming event storage.
But detection runs off a *separate* real event-bus consumer
(`EventStored` → `detection_consumer`) reacting asynchronously to storage —
"the event row exists" does not imply "detection has finished." Fixed: for
a scenario expecting a detection, the orchestrator now polls until enough
evidence appears (bounded, `event_storage_timeout`); for one expecting none,
it waits a fixed grace window long enough for detection to have fired if it
were going to, then takes one final read — never a single unconditional
read immediately after storage.

**Bug 2 — a race in "has the investigation finished" itself.** The first
implementation treated "no `AgentExecution` row currently has status
`'running'`" as terminal. Live testing against the real Suricata scenario
caught this failing for real: between the Triage/Timeline/Threat-Intel
agents finishing and the Report (SOC Lead) agent's own `AgentExecution` row
being created, there is a genuine window where every *existing* row is
terminal but the investigation is not actually done — the run was declared
"finished" one step early, and the case never received a persisted report.
Fixed by switching to `InvestigationCase.status` leaving `ANALYZING`
(`core/case_state.py`'s state machine — set exactly once, atomically, at the
true end of `AgentOrchestrator._run_locked()`, either to
`WAITING_FOR_REVIEW` on success or back to `OPEN`/previous on failure) as
the authoritative signal, immune to the inter-agent gap. `AgentExecution`
rows are still queried afterward, but only to populate the result's
`agent_statuses` diagnostic field, never to decide terminal-ness.

**Bug 3 — a test-only bug, but one that would have silently made the whole
LLM-marked test category meaningless.** The first pytest runs of Scenario A
and B failed with `agent_statuses={}`, `final_case_status='OPEN'` — the
investigation never started at all, even after a 180s timeout. Root cause
(documented in `conftest.py`'s own module docstring, which this phase had
read but not yet connected to this specific failure): pytest's isolated
environment dispatches Celery tasks onto Redis logical DB 15, but the real
`yarox-celery-worker` container only ever consumes DB 0 — "tasks dispatched
by tests can never reach it." A manual script run directly in the backend
container (not through pytest) had already exercised the exact same
orchestrator code successfully against the real worker, which is what made
this failure mode surprising rather than obviously a dispatch problem.
Fixed by wrapping the three tests that wait for a real investigation in the
existing `tests/support/celery.py` in-process test worker
(`running_test_worker()` — the same helper `tests/test_investigation_worker.py`
already established), which binds to DB 15 and genuinely processes the
task. A second, smaller issue surfaced once the worker was correctly
attached: the test-support context manager's default 30s shutdown grace
period was too short for a task that had just spent several real minutes
on LLM calls to finish its own internal housekeeping — `running_test_worker`
was extended with an optional, backward-compatible `shutdown_timeout`
parameter (existing callers unaffected) rather than silently increasing it
for everyone.

## 5. A genuine, unplanned-for system behavior observed live (not a bug)

Running the insider-threat scenario (5 events, 2 detections close together)
live showed the case's investigation take **two full passes**: Celery log
confirmed `"Investigation for case ... already running; re-run requested"`
followed later by `"Re-running investigation for case ... (evidence arrived
during pass 1)"` — `agents/orchestrator.py`'s own real rerun-on-new-evidence
mechanism (`consume_rerun_request`, up to `settings.
INVESTIGATION_MAX_RERUNS` passes) correctly handling a second detection
landing on the same case while the first pass was still investigating. This
is intended, pre-existing production behavior, not a scenario-orchestration
defect — but it means multi-detection scenarios can take roughly double the
wall-clock time of a single-detection one with local Ollama inference.
Scenario B's `investigation_timeout` is set generously (480s) to account for
this, and it is documented here so a future timeout tuning isn't mistaken
for a hang.

## 6. Scenarios — `backend/scenarios/definitions.py`

Every event payload is either a verbatim reuse of an existing, already-
proven fixture, or loaded directly from an existing dataset file — no
fabricated telemetry:

- **`suricata_intrusion_alert`**: the same "ET TROJAN Cobalt Strike
  Beaconing Detected" payload shape already exercised in
  `test_suricata_connector.py` and Phase 13's own live verification.
  Expects exactly one case, `NETWORK_INTRUSION_ALERT` evidence, a completed
  investigation and a persisted report.
- **`insider_threat_archive_and_transfer`**: `datasets/insider_threat/
  events.json` loaded via `ReplayEngine.load_dataset()`. Expects
  `DATA_STAGING` and `POSSIBLE_DATA_EXFILTRATION` evidence correlated into
  one case. `notes` carries the explicit hedge: demonstrates a suspicious
  activity *pattern*, not proof of malicious intent or confirmed
  exfiltration — matching `detection/rules.py`'s own docstring language for
  both rules.
- **`benign_negative_control`**: `evaluation/datasets/ground_truth.json`'s
  existing `benign_user_logon` scenario's `telemetry_events`, reused
  verbatim (not a new fixture invented for this phase). Expects zero cases
  — an explicit, structural assertion of absence, not merely an unset
  positive expectation.

All three fixtures had sufficient real support already in the repository;
no scenario needed to be dropped or backed by invented data.

## 7. Tests — `backend/tests/test_scenario_orchestration.py`

18 tests, explicitly separated by real-stack dependency (see the file's own
module docstring):

- **Deterministic, no real stack** (6): contract validation (valid
  definition accepted; empty events / unknown connector / `max_case_count <
  min_case_count` rejected; orchestrator semantic validation flags an empty
  payload; an invalid scenario fails fast without dispatching anything).
- **Isolation-tagging effects** (4): the suffix doesn't mutate the original
  payload; it survives in `raw_log` for Suricata; **it does not change
  whether `NetworkIntrusionAlert` matches** (the explicit proof the task
  asked for); the generic-connector tag lands in `metadata`.
- **Real-stack, no LLM** (5): a back-to-back duplicate still produces
  exactly one evidence row despite the *documented, pre-existing* storage-
  level race window (proven, not hidden — see the test's own docstring for
  why this differs from a spaced-out redelivery, which a second test proves
  *is* caught at the ingestion layer); two concurrent executions have fully
  disjoint `event_ids`/`case_ids`; cleanup never touches a separately-
  created, unrelated pre-existing case (explicit "do not purge dev data"
  boundary test).
- **Real-stack, requires a reachable LLM** (marked `@pytest.mark.llm`,
  reusing `pytest.ini`'s existing, previously-unused marker for exactly this
  case) (3): Scenario A and Scenario B's full lifecycles, each genuinely
  waiting for a real Celery-dispatched, Ollama-backed investigation to
  finish and asserting a real persisted report; and the investigation-
  timeout test — a deliberately-too-short `investigation_timeout` is
  reported as an honest failure, never a false pass, and cleanup correctly
  refuses to run while the investigation is genuinely still executing.
  **All three require the real in-process test Celery worker**
  (`tests/support/celery.py`'s `running_test_worker`, extended with a
  configurable `shutdown_timeout` — backward compatible, needed because a
  real multi-minute LLM-backed investigation can still be finishing
  housekeeping when the `with` block exits) — found live: without it, a
  detection-triggered dispatch never reaches any worker at all, because the
  isolated test broker (Redis DB 15) is never consumed by the real dev
  worker (DB 0 only; see `conftest.py`'s own module docstring). Scenario C's
  full lifecycle test needs no LLM (no investigation is expected) and runs
  unmarked.

`docker compose exec backend pytest -q tests/ -m "not llm"` → **340 passed**
(324 baseline + 16, including 1 no-longer-`llm`-marked scenario test in this
run), run against the isolated test database. The three `llm`-marked tests
were run separately (see §8) since they take real wall-clock minutes with
local Ollama inference — Scenario A 97.74s, the timeout test 192.46s,
Scenario B 295.94s (the two-pass rerun behavior in §5) — consistent with
keeping deterministic and real-stack-with-LLM tests clearly separated per
the governing instruction. Full suite, all markers:
`docker compose exec backend pytest -q tests/` → **342 passed** (324 + 18
new), zero regressions.

Also consolidated: the three connector test files
(`test_{sysmon,suricata,splunk}_connector.py`) each carried a near-identical
private `_wait_until` helper. `scenarios.orchestrator` needed the exact same
polling pattern as production code, which is what justified extracting it
once into `backend/scenarios/wait.py` and having all three test files import
it instead of a fourth duplicate — not incidental cleanup.

## 8. Real-stack verification (live, not simulated)

`docker compose restart backend celery_worker`, then the orchestrator run
directly against the real dev database (not the pytest test database),
mirroring exactly what the pytest suite already proves but against real,
persistent infrastructure:

- **Scenario A**: real case created (`Application Layer Protocol`, HIGH,
  matching Suricata's own severity classification), real `EvidenceItem`
  (`NETWORK_INTRUSION_ALERT`), a real 5-agent Celery investigation completed
  (`Memory Agent`/`Triage Analyst`/`Forensic Timeline Analyst`/`SOC Lead`
  = `completed`, `Threat Intel Analyst` = `degraded` — a normal partial-
  degradation outcome, not a crash), case reached `WAITING_FOR_REVIEW`, a
  real `InvestigationReport` row persisted (`status: "partial"`, matching
  the one degraded agent). Cleanup ran and fully removed all rows —
  confirmed via direct SQL afterward.
- **Scenario B**: this run is what surfaced §5's two-pass rerun behavior
  live — both `DATA_STAGING` and `POSSIBLE_DATA_EXFILTRATION` evidence
  correlated into exactly one case, both passes completed
  (`WAITING_FOR_REVIEW`), and cleanup correctly *refused* to run on the
  first attempt (investigation still on its second pass), reporting why,
  before succeeding once the case genuinely left `ANALYZING` — the cleanup-
  safety design working exactly as intended under a real, unplanned-for
  timing condition, not just in a controlled test.
- **Scenario C**: real event stored, zero cases created, cleanup removed
  the one event row.

## 9. Known limitations

- **The event-storage-level duplicate-suppression race window is
  pre-existing** (documented in the Sysmon connector's own docs since
  Phase 11) and is not fixed by this phase — §7's tests prove the
  user-visible outcome (evidence count) stays correct despite it, not that
  the race itself is closed.
- **No new authenticated REST endpoint.** The orchestrator is a module +
  pytest suite + a `scenarios/cli.py` CLI entry (matching `evaluation/
  runner.py`'s own convention), per the explicit scope boundary ("keep the
  frontend out of scope unless a minimal interface is necessary" — tests and
  the CLI exercise it directly; no interface was necessary).
- **`evaluation/runner.py` is untouched** — a separate system (agent-quality
  scoring against 12 ground-truth scenarios), left exactly as it was.
- **`detection/rules.py`, `detection/engine.py`, `rules/sigma/engine.py` are
  untouched** — no silent D-1/Sigma expansion, per explicit constraint.
- **Investigation wall-clock time scales with evidence volume and rerun
  passes** under local Ollama inference (§5) — `investigation_timeout`
  values in this phase's tests/CLI defaults are chosen from *observed* real
  timings, not a formal SLA; a slower machine or model could need larger
  values.
- **Concurrency isolation is proven at the two-execution scale** (the test
  suite's concurrent test runs two executions in parallel) — not
  load-tested at higher concurrency.

## 10. Completion criterion

The full pipeline — real ingestion, durable storage, detection, correlation,
a real Celery-dispatched investigation reaching a terminal state via the
correct state-machine signal, and a persisted report — is mechanically
verified by a reusable orchestrator, backed by 18 tests (15 passing without
any LLM dependency, 3 requiring one and verified live) and independent live
verification against the real running stack for all three scenarios,
including cleanup that correctly refuses to run while real background work
is still in flight. No scenario in this phase claims C2 identification,
confirmed malicious intent, or enterprise readiness beyond what its
underlying, already-hedged detection rules actually assert.
