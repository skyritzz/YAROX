"""
Splunk HEC connector (Phase 11, connector #3): field mapping, validation
failures, duplicate-event suppression, and end-to-end ingestion through the
real canonical contract, durable event bus, storage and detection engine.

Unlike the Sysmon/Suricata connectors, this one adds no new taxonomy
mapping - classification runs through the same generic heuristics
core.taxonomy.EventTaxonomyNormalizer already applies for live/generic
ingestion (see plugins/parsers/splunk.py). The end-to-end test below
therefore targets a signature text ("Multiple Failed Logon Attempts") the
existing heuristics already classify as AUTH_FAILURE, and confirms a real
FailedLoginBruteForce detection fires - proving the CIM field mapping
integrates with the unmodified detection pipeline, not just that a row
lands in Postgres.

No mocks of the systems under test: the end-to-end test uses the real Redis
Streams event bus, real Postgres, same pattern already established in
tests/test_sysmon_connector.py and tests/test_suricata_connector.py.
"""
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select

from api.main import app
from core.config import settings
from core.events import RedisStreamEventBus, event_bus
from core.integrity import compute_event_hash
from core.taxonomy import CanonicalEventType
from database.session import AsyncSessionLocal
from models.event import Event
from plugins.parsers.splunk import splunk_hec_parser
from schemas.canonical_event import CanonicalEventValidationError

API_KEY_HEADERS = {"X-API-Key": settings.INGESTION_API_KEY, "content-type": "application/json"}


def _hec_envelope(**overrides) -> dict:
    envelope = {
        "time": 1789900000,
        "host": "splunk-hf-01",
        "source": "SecurityAlerts",
        "sourcetype": "corp:alert",
        "index": "security",
        "event": {
            "_time": 1789900010,
            "signature": "Excessive File Download Volume",
            "dest": "WIN-DC01",
            "dvc": "10.0.0.1",
            "user": "CORP\\jdoe",
            "app": "win:security",
            "severity": "high",
            "src": "203.0.113.5",
        },
    }
    envelope.update(overrides)
    return envelope


# --------------------------------------------------------------- field mapping

def test_alert_maps_cim_fields():
    canonical = splunk_hec_parser.to_canonical(_hec_envelope())
    assert canonical.source == "splunk"
    assert canonical.hostname == "WIN-DC01"  # 'dest' preferred over 'dvc'
    assert canonical.user_name == "jdoe"  # DOMAIN\\ prefix stripped
    assert canonical.metadata["app"] == "win:security"
    assert canonical.metadata["source_ip"] == "203.0.113.5"
    assert canonical.metadata["splunk_sourcetype"] == "corp:alert"
    assert canonical.metadata["splunk_index"] == "security"
    assert canonical.raw_log["sourcetype"] == "corp:alert"  # original envelope preserved verbatim


def test_dvc_used_when_dest_absent():
    event = _hec_envelope()
    del event["event"]["dest"]
    canonical = splunk_hec_parser.to_canonical(event)
    assert canonical.hostname == "10.0.0.1"


def test_dest_ip_mapped_separately_from_dest_hostname():
    event = _hec_envelope()
    event["event"]["dest_ip"] = "198.51.100.9"
    canonical = splunk_hec_parser.to_canonical(event)
    assert canonical.hostname == "WIN-DC01"  # dest stays the hostname/entity
    assert canonical.metadata["destination_ip"] == "198.51.100.9"
    assert canonical.metadata["ip_address"] == "198.51.100.9"


@pytest.mark.parametrize("cim_severity,expected", [
    ("critical", "CRITICAL"),
    ("High", "HIGH"),  # case-insensitive
    ("medium", "MEDIUM"),
    ("low", "LOW"),
    ("informational", "INFO"),
])
def test_cim_severity_mapping(cim_severity, expected):
    canonical = splunk_hec_parser.to_canonical(_hec_envelope(event={**_hec_envelope()["event"], "severity": cim_severity}))
    assert canonical.severity == expected


def test_missing_severity_defaults_to_info_connector_does_not_fabricate_severity():
    event = _hec_envelope()
    del event["event"]["severity"]
    canonical = splunk_hec_parser.to_canonical(event)
    assert canonical.severity == "INFO"


def test_inner_time_takes_priority_over_outer_time():
    canonical = splunk_hec_parser.to_canonical(_hec_envelope())
    # event._time = 1789900010, envelope time = 1789900000 - inner wins
    assert canonical.timestamp == datetime.fromtimestamp(1789900010, tz=timezone.utc)


def test_falls_back_to_outer_time_when_inner_time_absent():
    event = _hec_envelope()
    del event["event"]["_time"]
    canonical = splunk_hec_parser.to_canonical(event)
    assert canonical.timestamp == datetime.fromtimestamp(1789900000, tz=timezone.utc)


def test_missing_both_timestamps_falls_back_to_now_not_a_hard_failure():
    event = _hec_envelope()
    del event["event"]["_time"]
    del event["time"]
    before = datetime.now(timezone.utc)
    canonical = splunk_hec_parser.to_canonical(event)
    assert canonical.timestamp >= before


def test_signature_drives_taxonomy_classification_via_existing_heuristics():
    event = _hec_envelope()
    event["event"]["signature"] = "Multiple Failed Logon Attempts"
    canonical = splunk_hec_parser.to_canonical(event)
    # No new taxonomy mapping was added for Splunk - this exercises the
    # same generic substring heuristic GenericJSONParser already relies on.
    assert canonical.canonical_event_type == CanonicalEventType.AUTH_FAILURE


def test_missing_signature_falls_back_to_sourcetype():
    event = _hec_envelope()
    del event["event"]["signature"]
    canonical = splunk_hec_parser.to_canonical(event)
    assert canonical.event_type == "corp:alert"  # 'sourcetype' has no taxonomy match, so it passes through unchanged


def test_missing_signature_and_sourcetype_falls_back_to_generic_label():
    event = _hec_envelope()
    del event["event"]["signature"]
    del event["sourcetype"]
    canonical = splunk_hec_parser.to_canonical(event)
    assert canonical.canonical_event_type == CanonicalEventType.UNKNOWN


# ----------------------------------------------------------- validation failures

def test_missing_event_key_is_rejected():
    event = _hec_envelope()
    del event["event"]
    with pytest.raises(CanonicalEventValidationError, match="missing required field 'event'"):
        splunk_hec_parser.to_canonical(event)


def test_raw_string_event_is_rejected_not_silently_misclassified():
    event = _hec_envelope()
    event["event"] = "user jdoe failed login from 10.0.0.5"
    with pytest.raises(CanonicalEventValidationError, match="raw string events are not supported"):
        splunk_hec_parser.to_canonical(event)


def test_non_dict_envelope_is_rejected():
    with pytest.raises(CanonicalEventValidationError, match="must be a JSON object"):
        splunk_hec_parser.to_canonical("not a dict")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_oversized_splunk_payload_is_rejected_with_422():
    huge_event = _hec_envelope()
    huge_event["event"]["signature"] = "A" * 70_000
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/splunk", json=huge_event, headers=API_KEY_HEADERS)
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_raw_string_event_over_http_is_rejected_with_422():
    event = _hec_envelope()
    event["event"] = "not structured"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/splunk", json=event, headers=API_KEY_HEADERS)
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_missing_api_key_is_rejected():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/splunk", json=_hec_envelope())
    assert res.status_code == 401


# --------------------------------------------------------------- duplicate events

@pytest.mark.asyncio
async def test_http_redelivery_of_an_identical_event_is_reported_as_duplicate_not_stored_twice():
    event = _hec_envelope(time=1789900100)
    event["event"] = {**event["event"], "_time": 1789900110}

    canonical = splunk_hec_parser.to_canonical(event)
    kwargs = canonical.to_orm_kwargs()
    content_hash = compute_event_hash(kwargs)
    async with AsyncSessionLocal() as session:
        session.add(Event(**kwargs, payload_sha256=content_hash))
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/splunk", json=event, headers=API_KEY_HEADERS)

    assert res.status_code == 202
    body = res.json()
    assert body["status"] == "duplicate"
    assert body["event_id"] == str(canonical.event_id)

    async with AsyncSessionLocal() as session:
        rows = (
            await session.execute(select(Event).where(Event.payload_sha256 == content_hash))
        ).scalars().all()
    assert len(rows) == 1, "a redelivered identical event must not create a second row"


# --------------------------------------------------------------- end-to-end ingestion

@pytest_asyncio.fixture
async def running_event_bus():
    """Same pattern as tests/test_sysmon_connector.py's fixture of the same name."""
    if isinstance(event_bus, RedisStreamEventBus):
        client = await event_bus._client()
        await client.delete(
            RedisStreamEventBus.stream_key("EventNormalized"),
            RedisStreamEventBus.stream_key("EventStored"),
        )

    from consumers.db_writer import register_consumers
    from consumers.detection_consumer import register_detection_consumers

    register_consumers()
    register_detection_consumers()
    event_bus.start()
    yield
    event_bus.stop()


# See scenarios/wait.py for the implementation — extracted there (Phase 14) once the
# scenario orchestrator needed the exact same pattern as production code, replacing
# this and two near-identical copies in test_sysmon_connector.py/test_suricata_connector.py.
from scenarios.wait import wait_until as _wait_until


@pytest.mark.asyncio
async def test_end_to_end_two_failed_logon_alerts_trigger_brute_force_detection(running_event_bus):
    """
    Real HTTP request -> real API-key auth -> real rate limiter -> SplunkHECParser
    -> generic taxonomy heuristic classification -> canonical contract -> real
    Redis Streams publish -> real consumer -> real Postgres rows -> real
    FailedLoginBruteForce detection (threshold 2, same user, same 5-minute
    window) -> a real InvestigationCase, through the unmodified existing
    pipeline. This is the case the module docstring promises: proof the CIM
    mapping (not just storage) integrates with detection as-is.
    """
    marker_user = f"e2e.splunk.{uuid.uuid4().hex[:8]}"
    base_time = 1789901000

    event_ids = []
    for i in range(2):
        envelope = _hec_envelope(
            time=base_time + i * 10,
            event={
                "_time": base_time + i * 10,
                "signature": "Multiple Failed Logon Attempts",
                "dest": "WIN-DC01",
                "user": marker_user,
                "severity": "medium",
            },
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post("/events/ingest/splunk", json=envelope, headers=API_KEY_HEADERS)
        assert res.status_code == 202
        body = res.json()
        assert body["status"] == "accepted"
        assert body["canonical_event_type"] == "AUTH_FAILURE"
        event_ids.append(uuid.UUID(body["event_id"]))

    async def _both_events_stored() -> bool:
        async with AsyncSessionLocal() as session:
            for eid in event_ids:
                if (await session.get(Event, eid)) is None:
                    return False
            return True

    assert await _wait_until(_both_events_stored), "events published through the real bus must be durably stored"

    from models.investigation import EvidenceItem

    async def _evidence_exists_for_second_event() -> bool:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event_ids[1]))
            return result.scalars().first() is not None

    assert await _wait_until(_evidence_exists_for_second_event), (
        "two Splunk HEC 'Multiple Failed Logon Attempts' alerts for the same user within the "
        "brute-force window must trigger FailedLoginBruteForce and be cited as evidence — "
        "this is the real detection engine, not a mock"
    )

    async with AsyncSessionLocal() as session:
        stored = await session.get(Event, event_ids[0])
        assert stored.source == "splunk"
        from core.integrity import verify_event_integrity
        assert verify_event_integrity(stored) is True
