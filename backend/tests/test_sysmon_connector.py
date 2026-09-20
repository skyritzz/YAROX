"""
Sysmon connector (Phase 11, connector #1): field mapping, validation failures,
duplicate-event suppression, and end-to-end ingestion through the real
canonical contract, durable event bus, storage and detection engine.

No mocks of the systems under test: the end-to-end tests use the real Redis
Streams event bus, real Postgres, and the real detection engine — the same
pattern already established and passing in tests/test_event_bus.py.
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
from core.integrity import compute_event_hash, find_duplicate_event_id
from core.taxonomy import CanonicalEventType
from database.session import AsyncSessionLocal
from models.event import Event
from plugins.parsers.sysmon import sysmon_parser
from schemas.canonical_event import CanonicalEventValidationError

API_KEY_HEADERS = {"X-API-Key": settings.INGESTION_API_KEY, "content-type": "application/json"}


def _process_create_event(**overrides) -> dict:
    event = {
        "EventID": 1,
        "UtcTime": "2026-09-20 08:15:22.123",
        "Hostname": "FINANCE-PC-07",
        "User": "FINANCE-PC-07\\jdoe",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ParentImage": "C:\\Windows\\explorer.exe",
        "ParentCommandLine": "explorer.exe",
        "Hashes": "SHA256=ABCDEF1234567890",
    }
    event.update(overrides)
    return event


def _network_connect_event(**overrides) -> dict:
    event = {
        "EventID": 3,
        "UtcTime": "2026-09-20 08:16:00.000",
        "Computer": "FINANCE-PC-07",
        "User": "jdoe",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "SourceIp": "10.0.0.5",
        "DestinationIp": "185.220.101.1",
        "DestinationPort": "443",
        "Protocol": "tcp",
    }
    event.update(overrides)
    return event


def _file_create_event(**overrides) -> dict:
    event = {
        "EventID": 11,
        "UtcTime": "2026-09-20 08:17:30.500",
        "Hostname": "FINANCE-PC-07",
        "User": "jdoe",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "TargetFilename": "C:\\Users\\jdoe\\Downloads\\payload.exe",
    }
    event.update(overrides)
    return event


# --------------------------------------------------------------- field mapping

def test_process_create_maps_command_line_and_process_names():
    canonical = sysmon_parser.to_canonical(_process_create_event())
    assert canonical.source == "sysmon"
    assert canonical.hostname == "FINANCE-PC-07"
    assert canonical.user_name == "jdoe"  # DOMAIN\\ / HOST\\ prefix stripped
    assert canonical.canonical_event_type == CanonicalEventType.PROCESS_EXECUTION
    assert canonical.metadata["process_name"] == "cmd.exe"
    assert canonical.metadata["command_line"] == "cmd.exe /c whoami"
    assert canonical.metadata["parent_process"] == "explorer.exe"
    assert canonical.metadata["hashes"] == "SHA256=ABCDEF1234567890"
    assert canonical.raw_log["EventID"] == 1  # original payload preserved verbatim


def test_network_connect_maps_ip_fields_both_keys_for_entity_extraction_compat():
    canonical = sysmon_parser.to_canonical(_network_connect_event())
    assert canonical.canonical_event_type == CanonicalEventType.NETWORK_TRAFFIC
    assert canonical.hostname == "FINANCE-PC-07"  # fell back to 'Computer' (no 'Hostname' key)
    assert canonical.metadata["ip_address"] == "185.220.101.1"
    assert canonical.metadata["destination_ip"] == "185.220.101.1"
    assert canonical.metadata["source_ip"] == "10.0.0.5"
    assert canonical.metadata["destination_port"] == "443"
    assert canonical.metadata["protocol"] == "tcp"


def test_file_create_maps_target_filename_and_uses_new_taxonomy_mapping():
    canonical = sysmon_parser.to_canonical(_file_create_event())
    # EventID 11 -> FILE_OPERATION was unreachable before this phase (no mapping existed)
    assert canonical.canonical_event_type == CanonicalEventType.FILE_OPERATION
    assert canonical.metadata["target_filename"] == "C:\\Users\\jdoe\\Downloads\\payload.exe"


def test_utc_time_is_parsed_despite_space_separator_not_being_strict_iso8601():
    canonical = sysmon_parser.to_canonical(_process_create_event(UtcTime="2026-09-20 08:15:22.123"))
    assert canonical.timestamp.year == 2026
    assert canonical.timestamp.month == 9
    assert canonical.timestamp.day == 20
    assert canonical.timestamp.hour == 8
    assert canonical.timestamp.minute == 15
    assert canonical.timestamp.tzinfo is not None


def test_missing_utc_time_falls_back_to_now_not_a_hard_failure():
    event = _process_create_event()
    del event["UtcTime"]
    before = datetime.now(timezone.utc)
    canonical = sysmon_parser.to_canonical(event)
    assert canonical.timestamp >= before


def test_severity_defaults_to_info_connector_does_not_fabricate_severity():
    canonical = sysmon_parser.to_canonical(_process_create_event())
    assert canonical.severity == "INFO"


# ----------------------------------------------------------- validation failures

def test_missing_event_id_is_rejected():
    event = _process_create_event()
    del event["EventID"]
    with pytest.raises(CanonicalEventValidationError, match="missing required field 'EventID'"):
        sysmon_parser.to_canonical(event)


def test_non_integer_event_id_is_rejected():
    with pytest.raises(CanonicalEventValidationError, match="must be an integer"):
        sysmon_parser.to_canonical(_process_create_event(EventID="not-a-number"))


def test_unsupported_event_id_is_rejected_not_silently_normalized():
    # EventID 7 (Image Loaded) is a real Sysmon event type this connector does not
    # claim to support - it must be an explicit rejection, not silently accepted
    # and normalized to UNKNOWN.
    with pytest.raises(CanonicalEventValidationError, match="Unsupported Sysmon EventID 7"):
        sysmon_parser.to_canonical(_process_create_event(EventID=7))


def test_windows_security_event_ids_are_explicitly_out_of_scope():
    # 4688 is Windows Security's own "process creation" event ID - a different
    # provider from Sysmon's EventID 1, even though both describe process
    # creation and core.taxonomy maps 4688 too. The Sysmon connector must not
    # silently accept it under the wrong source label.
    with pytest.raises(CanonicalEventValidationError, match="Unsupported Sysmon EventID 4688"):
        sysmon_parser.to_canonical(_process_create_event(EventID=4688))


def test_non_dict_payload_is_rejected():
    with pytest.raises(CanonicalEventValidationError, match="must be a JSON object"):
        sysmon_parser.to_canonical("not a dict")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_oversized_sysmon_payload_is_rejected_with_422():
    huge_event = _process_create_event(CommandLine="A" * 70_000)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/sysmon", json={"event": huge_event}, headers=API_KEY_HEADERS)
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_unsupported_event_id_over_http_is_rejected_with_422():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post(
            "/events/ingest/sysmon", json={"event": _process_create_event(EventID=7)}, headers=API_KEY_HEADERS
        )
    assert res.status_code == 422
    assert "Unsupported Sysmon EventID 7" in res.json()["detail"]


@pytest.mark.asyncio
async def test_missing_api_key_is_rejected():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/sysmon", json={"event": _process_create_event()})
    assert res.status_code == 401


# --------------------------------------------------------------- duplicate events

@pytest.mark.asyncio
async def test_find_duplicate_event_id_detects_identical_content():
    canonical = sysmon_parser.to_canonical(_process_create_event(UtcTime="2026-09-20 09:00:00.000"))
    kwargs = canonical.to_orm_kwargs()
    content_hash = compute_event_hash(kwargs)

    async with AsyncSessionLocal() as session:
        assert await find_duplicate_event_id(session, content_hash) is None
        session.add(Event(**kwargs, payload_sha256=content_hash))
        await session.commit()

    async with AsyncSessionLocal() as session:
        found = await find_duplicate_event_id(session, content_hash)
        assert found == canonical.event_id


@pytest.mark.asyncio
async def test_find_duplicate_event_id_does_not_match_different_content():
    canonical_a = sysmon_parser.to_canonical(_process_create_event(UtcTime="2026-09-20 09:05:00.000"))
    canonical_b = sysmon_parser.to_canonical(_process_create_event(UtcTime="2026-09-20 09:06:00.000"))  # different timestamp
    kwargs_a = canonical_a.to_orm_kwargs()
    hash_a = compute_event_hash(kwargs_a)
    hash_b = compute_event_hash(canonical_b.to_orm_kwargs())
    assert hash_a != hash_b

    async with AsyncSessionLocal() as session:
        session.add(Event(**kwargs_a, payload_sha256=hash_a))
        await session.commit()
        assert await find_duplicate_event_id(session, hash_b) is None


@pytest.mark.asyncio
async def test_http_redelivery_of_an_identical_event_is_reported_as_duplicate_not_stored_twice():
    event = _process_create_event(UtcTime="2026-09-20 09:10:00.000", CommandLine="cmd.exe /c hostname")

    # Seed storage directly (equivalent to a prior successful ingest having already
    # run through the real pipeline) so this test doesn't depend on the durable
    # bus's consumer timing to set up its precondition.
    canonical = sysmon_parser.to_canonical(event)
    kwargs = canonical.to_orm_kwargs()
    content_hash = compute_event_hash(kwargs)
    async with AsyncSessionLocal() as session:
        session.add(Event(**kwargs, payload_sha256=content_hash))
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/sysmon", json={"event": event}, headers=API_KEY_HEADERS)

    assert res.status_code == 202
    body = res.json()
    assert body["status"] == "duplicate"
    assert body["event_id"] == str(canonical.event_id)

    async with AsyncSessionLocal() as session:
        count = (
            await session.execute(select(Event).where(Event.payload_sha256 == content_hash))
        ).scalars().all()
    assert len(count) == 1, "a redelivered identical event must not create a second row"


# --------------------------------------------------------------- end-to-end ingestion

@pytest_asyncio.fixture
async def running_event_bus():
    """
    Starts the real consumers on the real global event bus, same pattern as
    tests/test_health.py's fixture (including draining the two real streams
    first, for the same reason documented there: other tests call
    consumers.db_writer.handle_event_normalized directly, which still publishes
    onto the real "EventStored" stream with nothing consuming it yet).
    """
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
# this and two near-identical copies in test_suricata_connector.py/test_splunk_connector.py.
from scenarios.wait import wait_until as _wait_until


@pytest.mark.asyncio
async def test_end_to_end_process_create_is_stored_hashed_and_detected(running_event_bus):
    """
    Real HTTP request -> real API-key auth -> real rate limiter -> SysmonParser ->
    canonical contract -> real Redis Streams publish -> real consumer -> real
    Postgres row with a verifying hash -> real detection engine -> a real
    InvestigationCase, through the unmodified existing pipeline.
    """
    marker_host = f"E2E-SYSMON-{uuid.uuid4().hex[:8]}"
    event = _process_create_event(
        Hostname=marker_host,
        UtcTime="2026-09-20 10:00:00.000",
        CommandLine="powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgA",
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/sysmon", json={"event": event}, headers=API_KEY_HEADERS)

    assert res.status_code == 202
    body = res.json()
    assert body["status"] == "accepted"
    assert body["canonical_event_type"] == "PROCESS_EXECUTION"
    event_id = uuid.UUID(body["event_id"])

    async def _event_is_stored() -> bool:
        async with AsyncSessionLocal() as session:
            return (await session.get(Event, event_id)) is not None

    assert await _wait_until(_event_is_stored), "event published through the real bus must be durably stored"

    async with AsyncSessionLocal() as session:
        stored = await session.get(Event, event_id)
        assert stored.hostname == marker_host
        assert stored.source == "sysmon"
        assert stored.payload_sha256 is not None
        from core.integrity import verify_event_integrity
        assert verify_event_integrity(stored) is True

    # SuspiciousProcessExecution matches PROCESS_EXECUTION + a command line containing
    # '-enc' - explain()'s description doesn't include the hostname, so check evidence instead.
    from models.investigation import EvidenceItem

    async def _evidence_exists_for_event() -> bool:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event_id))
            return result.scalars().first() is not None

    assert await _wait_until(_evidence_exists_for_event), (
        "a Sysmon Process Create event with an encoded PowerShell command line must trigger "
        "SuspiciousProcessExecution and be cited as evidence — this is the real detection engine, not a mock"
    )
