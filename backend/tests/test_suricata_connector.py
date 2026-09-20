"""
Suricata EVE connector (Phase 11, connector #2): field mapping, validation
failures, duplicate-event suppression, and end-to-end ingestion through the
real canonical contract, durable event bus, storage and detection engine.

No mocks of the systems under test: the end-to-end test uses the real Redis
Streams event bus, real Postgres, same pattern already established in
tests/test_sysmon_connector.py and tests/test_event_bus.py.

Note on detection: as of Phase 13 (detection/rules.py's NetworkIntrusionAlert,
see tests/test_phase13_detection.py), SYSTEM_ALERT events *do* now reach a
real detection rule and produce a case — this was not true when this
connector was first built (D-4 was fully open then). NETWORK_TRAFFIC events
still have no IDS-signature-based rule (LargeExternalDataTransfer is a
volume heuristic, not a signature match, and does not apply to every
NETWORK_TRAFFIC event — see its docstring). The end-to-end test below now
asserts the real SYSTEM_ALERT detection match, superseding the earlier
"storage only" version of this test.
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
from plugins.parsers.suricata import suricata_parser
from schemas.canonical_event import CanonicalEventValidationError

API_KEY_HEADERS = {"X-API-Key": settings.INGESTION_API_KEY, "content-type": "application/json"}


def _alert_event(**overrides) -> dict:
    event = {
        "timestamp": "2026-09-20T10:15:22.123456+0000",
        "flow_id": 1234567890123456,
        "in_iface": "eth0",
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "src_port": 49512,
        "dest_ip": "198.51.100.44",
        "dest_port": 443,
        "proto": "TCP",
        "host": "SOC-SENSOR-01",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2024297,
            "rev": 2,
            "signature": "ET TROJAN Cobalt Strike Beaconing Detected",
            "category": "A Network Trojan was detected",
            "severity": 1,
        },
    }
    event.update(overrides)
    return event


def _flow_event(**overrides) -> dict:
    event = {
        "timestamp": "2026-09-20T10:16:00.000000+0000",
        "flow_id": 9988776655443322,
        "event_type": "flow",
        "src_ip": "10.0.0.5",
        "src_port": 49512,
        "dest_ip": "198.51.100.44",
        "dest_port": 443,
        "proto": "TCP",
        "host": "SOC-SENSOR-01",
        "app_proto": "tls",
        "flow": {
            "pkts_toserver": 12,
            "pkts_toclient": 10,
            "bytes_toserver": 3400,
            "bytes_toclient": 5200,
            "state": "established",
        },
    }
    event.update(overrides)
    return event


# --------------------------------------------------------------- field mapping

def test_alert_maps_signature_and_uses_new_system_alert_taxonomy():
    canonical = suricata_parser.to_canonical(_alert_event())
    assert canonical.source == "suricata"
    assert canonical.hostname == "SOC-SENSOR-01"
    # SYSTEM_ALERT was unreachable before this connector - no string/ID mapping reached it
    assert canonical.canonical_event_type == CanonicalEventType.SYSTEM_ALERT
    assert canonical.metadata["signature"] == "ET TROJAN Cobalt Strike Beaconing Detected"
    assert canonical.metadata["signature_id"] == 2024297
    assert canonical.metadata["category"] == "A Network Trojan was detected"
    assert canonical.metadata["destination_ip"] == "198.51.100.44"
    assert canonical.metadata["ip_address"] == "198.51.100.44"
    assert canonical.raw_log["event_type"] == "alert"  # original EVE record preserved verbatim


def test_alert_severity_1_maps_to_high():
    canonical = suricata_parser.to_canonical(_alert_event())
    assert canonical.severity == "HIGH"
    assert canonical.metadata["suricata_severity"] == 1


def test_alert_severity_3_maps_to_low():
    event = _alert_event()
    event["alert"]["severity"] = 3
    canonical = suricata_parser.to_canonical(event)
    assert canonical.severity == "LOW"


def test_alert_missing_severity_defaults_to_low_not_info():
    event = _alert_event()
    del event["alert"]["severity"]
    canonical = suricata_parser.to_canonical(event)
    assert canonical.severity == "LOW"


def test_flow_maps_network_fields_and_uses_new_network_traffic_taxonomy():
    canonical = suricata_parser.to_canonical(_flow_event())
    assert canonical.canonical_event_type == CanonicalEventType.NETWORK_TRAFFIC
    assert canonical.metadata["app_proto"] == "tls"
    assert canonical.metadata["bytes_toserver"] == 3400
    assert canonical.metadata["bytes_toclient"] == 5200
    assert canonical.metadata["flow_state"] == "established"


def test_flow_severity_defaults_to_info_connector_does_not_fabricate_severity():
    canonical = suricata_parser.to_canonical(_flow_event())
    assert canonical.severity == "INFO"


def test_missing_host_falls_back_to_unknown_sentinel_not_a_hard_failure():
    event = _alert_event()
    del event["host"]
    canonical = suricata_parser.to_canonical(event)
    assert canonical.hostname == "unknown"


def test_eve_timestamp_with_colonless_offset_is_parsed():
    canonical = suricata_parser.to_canonical(_alert_event(timestamp="2026-09-20T10:15:22.123456+0000"))
    assert canonical.timestamp.year == 2026
    assert canonical.timestamp.month == 9
    assert canonical.timestamp.day == 20
    assert canonical.timestamp.hour == 10
    assert canonical.timestamp.tzinfo is not None


def test_missing_timestamp_falls_back_to_now_not_a_hard_failure():
    event = _alert_event()
    del event["timestamp"]
    before = datetime.now(timezone.utc)
    canonical = suricata_parser.to_canonical(event)
    assert canonical.timestamp >= before


# ----------------------------------------------------------- validation failures

def test_missing_eve_event_type_is_rejected():
    event = _alert_event()
    del event["event_type"]
    with pytest.raises(CanonicalEventValidationError, match="missing required field 'event_type'"):
        suricata_parser.to_canonical(event)


def test_unsupported_eve_event_type_is_rejected_not_silently_normalized():
    # 'dns' is a real EVE record type this connector does not claim to support -
    # must be an explicit rejection, not silently accepted and normalized to UNKNOWN.
    with pytest.raises(CanonicalEventValidationError, match="Unsupported Suricata EVE event_type 'dns'"):
        suricata_parser.to_canonical(_alert_event(event_type="dns"))


def test_alert_without_signature_is_rejected():
    event = _alert_event()
    del event["alert"]["signature"]
    with pytest.raises(CanonicalEventValidationError, match="missing a required 'alert.signature'"):
        suricata_parser.to_canonical(event)


def test_alert_without_alert_object_is_rejected():
    event = _alert_event()
    del event["alert"]
    with pytest.raises(CanonicalEventValidationError, match="missing a required 'alert.signature'"):
        suricata_parser.to_canonical(event)


def test_non_dict_payload_is_rejected():
    with pytest.raises(CanonicalEventValidationError, match="must be a JSON object"):
        suricata_parser.to_canonical("not a dict")  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_oversized_suricata_payload_is_rejected_with_422():
    huge_event = _alert_event()
    huge_event["alert"]["signature"] = "A" * 70_000
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/suricata", json={"event": huge_event}, headers=API_KEY_HEADERS)
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_unsupported_eve_event_type_over_http_is_rejected_with_422():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post(
            "/events/ingest/suricata", json={"event": _alert_event(event_type="http")}, headers=API_KEY_HEADERS
        )
    assert res.status_code == 422
    assert "Unsupported Suricata EVE event_type 'http'" in res.json()["detail"]


@pytest.mark.asyncio
async def test_missing_api_key_is_rejected():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/suricata", json={"event": _alert_event()})
    assert res.status_code == 401


# --------------------------------------------------------------- duplicate events

@pytest.mark.asyncio
async def test_http_redelivery_of_an_identical_alert_is_reported_as_duplicate_not_stored_twice():
    event = _alert_event(timestamp="2026-09-20T11:00:00.000000+0000")

    # Seed storage directly (equivalent to a prior successful ingest having already
    # run through the real pipeline), same pattern as the Sysmon connector's
    # equivalent test - doesn't depend on the durable bus's consumer timing.
    canonical = suricata_parser.to_canonical(event)
    kwargs = canonical.to_orm_kwargs()
    content_hash = compute_event_hash(kwargs)
    async with AsyncSessionLocal() as session:
        session.add(Event(**kwargs, payload_sha256=content_hash))
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/suricata", json={"event": event}, headers=API_KEY_HEADERS)

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


async def _wait_until(condition, timeout=10.0, interval=0.1) -> bool:
    import asyncio
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if await condition():
            return True
        await asyncio.sleep(interval)
    return False


@pytest.mark.asyncio
async def test_end_to_end_alert_is_stored_hashed_and_detected(running_event_bus):
    """
    Real HTTP request -> real API-key auth -> real rate limiter -> SuricataParser
    -> canonical contract -> real Redis Streams publish -> real consumer -> real
    Postgres row with a verifying hash -> real NetworkIntrusionAlert detection
    rule (detection/rules.py, added in Phase 13) -> a real InvestigationCase,
    through the unmodified existing pipeline. Supersedes the earlier version of
    this test, which predated NetworkIntrusionAlert and asserted storage only.
    """
    marker_host = f"E2E-SURICATA-{uuid.uuid4().hex[:8]}"
    event = _alert_event(host=marker_host, timestamp="2026-09-20T12:00:00.000000+0000")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest/suricata", json={"event": event}, headers=API_KEY_HEADERS)

    assert res.status_code == 202
    body = res.json()
    assert body["status"] == "accepted"
    assert body["canonical_event_type"] == "SYSTEM_ALERT"
    event_id = uuid.UUID(body["event_id"])

    async def _event_is_stored() -> bool:
        async with AsyncSessionLocal() as session:
            return (await session.get(Event, event_id)) is not None

    assert await _wait_until(_event_is_stored), "event published through the real bus must be durably stored"

    async with AsyncSessionLocal() as session:
        stored = await session.get(Event, event_id)
        assert stored.hostname == marker_host
        assert stored.source == "suricata"
        assert stored.payload_sha256 is not None
        from core.integrity import verify_event_integrity
        assert verify_event_integrity(stored) is True
        assert stored.metadata_["signature"] == "ET TROJAN Cobalt Strike Beaconing Detected"

    from models.investigation import EvidenceItem

    async def _evidence_exists_for_event() -> bool:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event_id))
            return result.scalars().first() is not None

    assert await _wait_until(_evidence_exists_for_event), (
        "a Suricata alert must now trigger NetworkIntrusionAlert and be cited as evidence "
        "(Phase 13) — this is the real detection engine, not a mock"
    )

    async with AsyncSessionLocal() as session:
        result = await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event_id))
        evidence = result.scalars().first()
        assert evidence.evidence_type == "NETWORK_INTRUSION_ALERT"
        assert "ET TROJAN Cobalt Strike Beaconing Detected" in evidence.reason
