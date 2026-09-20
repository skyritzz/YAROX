"""
Phase 14 scenario orchestration tests.

Test categories, explicitly separated per the governing instruction ("clearly
mark real-stack tests and their dependencies"):

* **Deterministic / no real stack beyond Postgres**: contract validation,
  isolation-tagging effects (proven directly against detection rules, not
  through a full pipeline run).
* **Real-stack, no LLM**: duplicate replay, concurrent execution isolation,
  timeout behavior, cleanup safety — these use the real event bus, real
  Postgres, real detection engine, but either expect no investigation or
  deliberately don't wait long enough for one to finish.
* **Real-stack, requires a reachable LLM** (marked ``@pytest.mark.llm``,
  reusing pytest.ini's existing, previously-unused marker for exactly this):
  Scenario A/B/C's full runs, each waiting for a real Celery-dispatched,
  Ollama-backed multi-agent investigation to reach a terminal state. These
  take real wall-clock time — tens of seconds for Scenario A/C, several
  minutes for Scenario B, which was observed live to trigger the real
  rerun-on-new-evidence mechanism (orchestrator.AgentOrchestrator's own
  ``consume_rerun_request`` loop) because its 5 events produce two
  detections close together — a genuine system behavior, not a bug; see
  scenarios/orchestrator.py's docstring and docs/PHASE_14_SCENARIO_ORCHESTRATION.md.

No mocks of the systems under test in the real-stack tests — same standing
rule as every prior phase's connector/detection tests.
"""
import asyncio
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from pydantic import ValidationError

from consumers.db_writer import register_consumers
from consumers.detection_consumer import register_detection_consumers
from core.events import RedisStreamEventBus, event_bus
from core.taxonomy import CanonicalEventType
from database.session import AsyncSessionLocal
from detection.rules import NetworkIntrusionAlert
from models.investigation import InvestigationCase, InvestigationStatus, Severity
from plugins.parsers.suricata import suricata_parser
from scenarios.definitions import BENIGN_NEGATIVE_CONTROL, SURICATA_INTRUSION_ALERT, build_insider_threat_scenario
from scenarios.orchestrator import ScenarioOrchestrator, _apply_isolation, scenario_orchestrator
from scenarios.schemas import ExpectedOutcome, ScenarioDefinition, ScenarioEventDef
from scenarios.wait import wait_until
from tests.support.celery import running_test_worker


@pytest_asyncio.fixture
async def running_event_bus():
    """Same pattern as tests/test_sysmon_connector.py's fixture of the same name."""
    if isinstance(event_bus, RedisStreamEventBus):
        client = await event_bus._client()
        await client.delete(
            RedisStreamEventBus.stream_key("EventNormalized"),
            RedisStreamEventBus.stream_key("EventStored"),
        )
    register_consumers()
    register_detection_consumers()
    event_bus.start()
    yield
    event_bus.stop()


def _suricata_alert_event(**overrides) -> dict:
    event = {
        "timestamp": "2026-09-22T09:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "dest_ip": "185.220.101.1",
        "dest_port": 443,
        "proto": "TCP",
        "host": "TEST-SENSOR",
        "alert": {
            "action": "allowed", "gid": 1, "signature_id": 2024297, "rev": 2,
            "signature": "ET TROJAN Cobalt Strike Beaconing Detected",
            "category": "A Network Trojan was detected", "severity": 1,
        },
    }
    event.update(overrides)
    return event


# ============================================================= contract validation

def test_valid_scenario_definition_is_accepted():
    scenario = ScenarioDefinition(
        scenario_id="s1", name="n", description="d",
        events=[ScenarioEventDef(connector="generic", label="l", payload={"a": 1})],
        expected=ExpectedOutcome(should_create_case=False),
    )
    assert scenario.scenario_id == "s1"


def test_empty_events_list_is_rejected():
    with pytest.raises(ValidationError):
        ScenarioDefinition(
            scenario_id="s1", name="n", description="d", events=[],
            expected=ExpectedOutcome(should_create_case=False),
        )


def test_unknown_connector_is_rejected():
    with pytest.raises(ValidationError):
        ScenarioEventDef(connector="not_a_real_connector", label="l", payload={"a": 1})


def test_max_case_count_below_min_is_rejected():
    with pytest.raises(ValidationError):
        ExpectedOutcome(should_create_case=True, min_case_count=3, max_case_count=1)


def test_orchestrator_semantic_validation_flags_empty_payload():
    scenario = ScenarioDefinition(
        scenario_id="s1", name="n", description="d",
        events=[ScenarioEventDef(connector="generic", label="l", payload={})],
        expected=ExpectedOutcome(should_create_case=False),
    )
    problems = ScenarioOrchestrator().validate(scenario)
    assert any("empty" in p for p in problems)


@pytest.mark.asyncio
async def test_invalid_scenario_run_fails_fast_without_dispatching_anything():
    scenario = ScenarioDefinition(
        scenario_id="s1", name="n", description="d",
        events=[ScenarioEventDef(connector="generic", label="l", payload={})],
        expected=ExpectedOutcome(should_create_case=False),
    )
    result = await scenario_orchestrator.run(scenario)
    assert result.passed is False
    assert result.event_ids == []
    assert any("invalid scenario" in r for r in result.reasons)


# ============================================================= isolation tagging effects

def test_isolation_suffix_does_not_mutate_the_original_payload():
    original = _suricata_alert_event()
    tagged = _apply_isolation("suricata", original, "exec-1", "abc123")
    assert original["host"] == "TEST-SENSOR"  # untouched
    assert tagged["host"] == "TEST-SENSOR-abc123"
    assert tagged["_yarox_scenario_execution_id"] == "exec-1"


def test_isolation_suffix_survives_in_raw_log_for_suricata():
    tagged = _apply_isolation("suricata", _suricata_alert_event(), "exec-1", "abc123")
    canonical = suricata_parser.to_canonical(tagged)
    assert canonical.hostname == "TEST-SENSOR-abc123"
    assert canonical.raw_log["_yarox_scenario_execution_id"] == "exec-1"  # best-effort trace tag preserved verbatim


def test_isolation_suffix_does_not_change_whether_the_detection_rule_matches():
    """The whole point of tagging hostname is safe cross-execution isolation - it must
    never be the reason a rule that should fire, doesn't (or vice versa)."""
    class _FakeEvent:
        def __init__(self, event_type, metadata, raw_log):
            self.event_type = event_type
            self.raw_log = raw_log
            self.metadata_ = metadata

    untagged_raw = _suricata_alert_event()
    tagged_raw = _apply_isolation("suricata", untagged_raw, "exec-1", "abc123")

    untagged = suricata_parser.to_canonical(untagged_raw)
    tagged = suricata_parser.to_canonical(tagged_raw)

    assert untagged.canonical_event_type == CanonicalEventType.SYSTEM_ALERT
    assert tagged.canonical_event_type == CanonicalEventType.SYSTEM_ALERT

    rule = NetworkIntrusionAlert()
    fake_untagged = _FakeEvent(untagged.event_type, untagged.metadata, untagged.raw_log)
    fake_tagged = _FakeEvent(tagged.event_type, tagged.metadata, tagged.raw_log)

    import asyncio as _asyncio
    assert _asyncio.get_event_loop().run_until_complete(rule.match(fake_untagged)) is True
    assert _asyncio.get_event_loop().run_until_complete(rule.match(fake_tagged)) is True


def test_isolation_generic_tag_lands_in_metadata():
    payload = {"hostname": "H", "user_name": "U", "source": "s", "event_type": "e", "raw_log": {}}
    tagged = _apply_isolation("generic", payload, "exec-2", "xyz789")
    assert tagged["hostname"] == "H-xyz789"
    assert tagged["user_name"] == "U-xyz789"
    assert tagged["metadata"]["scenario_execution_id"] == "exec-2"


# ============================================================= real-stack, no LLM

@pytest.mark.asyncio
async def test_back_to_back_duplicate_still_produces_exactly_one_evidence_row(running_event_bus):
    """
    Two identical events dispatched with zero delay race past
    core.integrity.find_duplicate_event_id's known window (documented in
    plugins/parsers/sysmon.py and confirmed live for the Sysmon connector: "two
    submissions of the identical event arriving within that window... will race
    past the check and both be stored") — so both genuinely get stored as
    distinct Event rows here, which this test does NOT paper over. What it does
    verify is the layer that is NOT racy: detection/engine.py's evidence dedup
    (matching case_id + artifact + evidence_type, fully synchronous within one
    event's processing) still produces exactly one evidence row for the case,
    so the user-visible outcome (one finding, not two) is correct despite the
    known, pre-existing storage-level race.
    """
    scenario = ScenarioDefinition(
        scenario_id="dup_test_race", name="n", description="d",
        events=[
            ScenarioEventDef(connector="suricata", label="first", payload=_suricata_alert_event()),
            ScenarioEventDef(connector="suricata", label="duplicate_of_first", payload=_suricata_alert_event()),
        ],
        expected=ExpectedOutcome(should_create_case=True, min_case_count=1, max_case_count=1, min_evidence_count=1),
    )
    result = await scenario_orchestrator.run(scenario, wait_for_investigation=False, event_storage_timeout=15.0, cleanup=True)
    assert result.passed, result.reasons
    assert sum(result.evidence_counts.values()) == 1, "evidence-level dedup must still collapse a raced duplicate to one row"


@pytest.mark.asyncio
async def test_spaced_duplicate_is_caught_at_the_ingestion_layer(running_event_bus):
    """The redelivery case the dedup check IS designed for (a real gap, not zero delay —
    same distinction the Sysmon/Suricata connector tests already draw): the second
    dispatch must return the same event_id as the first, not create a new row."""
    scenario = ScenarioDefinition(
        scenario_id="dup_test_spaced", name="n", description="d",
        events=[
            ScenarioEventDef(connector="suricata", label="first", payload=_suricata_alert_event()),
            ScenarioEventDef(connector="suricata", relative_offset_seconds=2.0, label="redelivery", payload=_suricata_alert_event()),
        ],
        expected=ExpectedOutcome(should_create_case=True, min_case_count=1, max_case_count=1, min_evidence_count=1),
    )
    result = await scenario_orchestrator.run(scenario, wait_for_investigation=False, event_storage_timeout=15.0, cleanup=True)
    assert result.passed, result.reasons
    assert len(set(result.event_ids)) == 1, "a spaced-out redelivery must be recognized as a duplicate at the ingestion layer"
    assert sum(result.evidence_counts.values()) == 1


@pytest.mark.asyncio
async def test_concurrent_executions_have_disjoint_owned_records(running_event_bus):
    scenario_a = ScenarioDefinition(
        scenario_id="concurrent_a", name="n", description="d",
        events=[ScenarioEventDef(connector="suricata", label="alert", payload=_suricata_alert_event())],
        expected=ExpectedOutcome(should_create_case=True, min_evidence_count=1),
    )
    scenario_b = ScenarioDefinition(
        scenario_id="concurrent_b", name="n", description="d",
        events=[ScenarioEventDef(connector="suricata", label="alert", payload=_suricata_alert_event())],
        expected=ExpectedOutcome(should_create_case=True, min_evidence_count=1),
    )

    result_a, result_b = await asyncio.gather(
        scenario_orchestrator.run(scenario_a, wait_for_investigation=False, event_storage_timeout=15.0, cleanup=True),
        scenario_orchestrator.run(scenario_b, wait_for_investigation=False, event_storage_timeout=15.0, cleanup=True),
    )

    assert result_a.passed, result_a.reasons
    assert result_b.passed, result_b.reasons
    assert result_a.execution_id != result_b.execution_id
    assert set(result_a.event_ids).isdisjoint(result_b.event_ids)
    assert set(result_a.case_ids).isdisjoint(result_b.case_ids)


@pytest.mark.asyncio
@pytest.mark.llm
async def test_investigation_timeout_is_reported_not_silently_passed(running_event_bus):
    """A real detection-triggered investigation genuinely dispatches onto the isolated
    test broker (Redis DB 15 — see conftest.py's module docstring: the real dev Celery
    worker only consumes DB 0, so this needs the in-process test worker,
    tests.support.celery.running_test_worker, exactly like tests/test_investigation_worker.py
    already does). Real LLM calls take well over half a second to even start, so a
    deliberately tiny timeout here reliably reproduces 'did not reach a terminal state'
    without needing to stop any real infrastructure."""
    scenario = ScenarioDefinition(
        scenario_id="timeout_test", name="n", description="d",
        events=[ScenarioEventDef(connector="suricata", label="alert", payload=_suricata_alert_event())],
        expected=ExpectedOutcome(should_create_case=True, min_evidence_count=1, expect_investigation_to_run=True),
    )
    with running_test_worker(shutdown_timeout=90):
        result = await scenario_orchestrator.run(
            scenario, wait_for_investigation=True, event_storage_timeout=15.0, investigation_timeout=0.5, cleanup=True,
        )
        assert result.passed is False
        assert any("did not reach a terminal state" in r for r in result.reasons)
        # Cleanup must refuse while the (still-running) investigation is unresolved —
        # never delete data out from under a real Celery task.
        assert result.cleanup_performed is False
        assert result.cleanup_skipped_reason is not None

        # Manual cleanup (worker still running) so this test doesn't leak a real,
        # still-in-flight investigation once the `with` block exits.
        if result.case_ids:
            await _wait_and_cleanup(result.case_ids[0], result.event_ids)


async def _wait_and_cleanup(case_id: str, event_ids):
    """Used only to tidy up after test_investigation_timeout_is_reported_not_silently_passed,
    whose whole point is a deliberately-too-short timeout — the real investigation it
    triggered is still running and needs a real wait before it's safe to delete."""
    async def _left_analyzing() -> bool:
        async with AsyncSessionLocal() as session:
            case = await session.get(InvestigationCase, uuid.UUID(case_id))
            return case is not None and case.status != InvestigationStatus.ANALYZING

    await wait_until(_left_analyzing, timeout=180.0)

    from scenarios.orchestrator import ScenarioExecutionResult
    stand_in = ScenarioExecutionResult(
        execution_id="timeout-test-manual-cleanup", scenario_id="timeout_test",
        started_at=datetime.now(timezone.utc), case_ids=[case_id], event_ids=list(event_ids),
    )
    await scenario_orchestrator._cleanup(stand_in)


@pytest.mark.asyncio
async def test_cleanup_does_not_touch_an_unrelated_pre_existing_case(running_event_bus):
    """Explicit boundary test against 'do not purge dev data' — cleanup for one
    execution must never delete a case it did not itself create."""
    unrelated_case = InvestigationCase(
        title="Pre-existing unrelated case", status=InvestigationStatus.OPEN, severity=Severity.LOW,
    )
    async with AsyncSessionLocal() as session:
        session.add(unrelated_case)
        await session.commit()
        await session.refresh(unrelated_case)
    unrelated_case_id = unrelated_case.id

    scenario = ScenarioDefinition(
        scenario_id="cleanup_boundary_test", name="n", description="d",
        events=[ScenarioEventDef(connector="suricata", label="alert", payload=_suricata_alert_event())],
        expected=ExpectedOutcome(should_create_case=True, min_evidence_count=1),
    )
    result = await scenario_orchestrator.run(scenario, wait_for_investigation=False, event_storage_timeout=15.0, cleanup=True)
    assert result.passed, result.reasons
    assert str(unrelated_case_id) not in result.case_ids

    async with AsyncSessionLocal() as session:
        still_there = await session.get(InvestigationCase, unrelated_case_id)
        assert still_there is not None, "cleanup for an unrelated execution must never delete a pre-existing case"
        await session.delete(still_there)  # test's own cleanup of the fixture it created
        await session.commit()


# ============================================================= real-stack, requires LLM

@pytest.mark.asyncio
@pytest.mark.llm
async def test_scenario_a_suricata_intrusion_alert_full_lifecycle(running_event_bus):
    """Wrapped in the in-process test Celery worker (tests.support.celery.running_test_worker)
    — see conftest.py's module docstring: the isolated test broker (Redis DB 15) is never
    consumed by the real dev worker (DB 0 only), so nothing would ever pick up the
    detection-triggered dispatch without this, exactly like tests/test_investigation_worker.py."""
    with running_test_worker(shutdown_timeout=90):
        result = await scenario_orchestrator.run(
            SURICATA_INTRUSION_ALERT, wait_for_investigation=True,
            event_storage_timeout=15.0, investigation_timeout=180.0, cleanup=True,
        )
    assert result.passed, f"reasons={result.reasons} warnings={result.warnings}"
    assert len(result.case_ids) == 1
    assert result.evidence_counts.get("NETWORK_INTRUSION_ALERT", 0) >= 1
    assert result.investigations[0].reached_terminal_state is True
    assert result.investigations[0].report_id is not None
    assert result.cleanup_performed is True


@pytest.mark.asyncio
@pytest.mark.llm
async def test_scenario_b_insider_threat_archive_and_transfer_full_lifecycle(running_event_bus):
    scenario = await build_insider_threat_scenario()
    # Observed live: 5 events triggering 2 close-together detections into one case
    # reliably invokes the real rerun-on-new-evidence mechanism (a second full
    # investigation pass), so this needs a generous timeout with local Ollama latency.
    with running_test_worker(shutdown_timeout=120):
        result = await scenario_orchestrator.run(
            scenario, wait_for_investigation=True,
            event_storage_timeout=20.0, investigation_timeout=480.0, cleanup=True,
        )
    assert result.passed, f"reasons={result.reasons} warnings={result.warnings}"
    assert len(result.case_ids) == 1, "both detections must correlate into one case"
    assert result.evidence_counts.get("DATA_STAGING", 0) >= 1
    assert result.evidence_counts.get("POSSIBLE_DATA_EXFILTRATION", 0) >= 1
    assert result.investigations[0].reached_terminal_state is True
    assert result.cleanup_performed is True


@pytest.mark.asyncio
async def test_scenario_c_benign_negative_control_full_lifecycle(running_event_bus):
    """No @pytest.mark.llm — this scenario expects no investigation, so it never
    depends on a reachable LLM; it still exercises the real event bus/detection engine."""
    result = await scenario_orchestrator.run(
        BENIGN_NEGATIVE_CONTROL, wait_for_investigation=False,
        event_storage_timeout=15.0, cleanup=True,
    )
    assert result.passed, f"reasons={result.reasons} warnings={result.warnings}"
    assert result.case_ids == []
    assert sum(result.evidence_counts.values()) == 0
    assert result.cleanup_performed is True
