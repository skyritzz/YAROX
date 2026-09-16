"""
SHA-256 event integrity: deterministic canonicalization, change detection, and
round-trip through PostgreSQL JSONB storage.
"""
import copy
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select, update

from api.main import app
from consumers.db_writer import handle_event_normalized
from core.auth import get_current_user
from core.integrity import compute_event_hash, canonical_event_payload, verify_event_integrity
from database.session import AsyncSessionLocal
from models.event import Event
from models.user import User, UserRole
from plugins.parsers.generic import generic_parser
from unittest.mock import AsyncMock, patch

RAW_EVENT = {
    "timestamp": "2026-09-17T10:01:00.123456Z",
    "hostname": "FINANCE-PC-04",
    "user": "asmith",
    "source": "Sysmon",
    "event_type": "Process Creation",
    "severity": "MEDIUM",
    "metadata": {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -NoP -W Hidden -enc JABzAD0A",
        "pid": 4108,
        "ratio": 0.5,
        "nested": {"b": 2, "a": [1, "x", None, True]},
    },
}


def _normalized():
    return generic_parser.parse(copy.deepcopy(RAW_EVENT))


def test_same_event_produces_same_hash():
    first, second = _normalized(), _normalized()
    assert compute_event_hash(first) == compute_event_hash(second)
    assert len(compute_event_hash(first)) == 64


def test_key_order_does_not_change_hash():
    a = _normalized()
    b = dict(reversed(list(a.items())))
    b["raw_log"] = dict(reversed(list(a["raw_log"].items())))
    assert compute_event_hash(a) == compute_event_hash(b)


def test_equivalent_timezones_produce_same_hash():
    a = _normalized()
    b = dict(a)
    b["timestamp"] = a["timestamp"].astimezone(timezone(timedelta(hours=5, minutes=30)))
    assert compute_event_hash(a) == compute_event_hash(b)


@pytest.mark.parametrize("mutate", [
    lambda e: e.__setitem__("hostname", "FINANCE-PC-05"),
    lambda e: e.__setitem__("user_name", "bsmith"),
    lambda e: e.__setitem__("severity", "HIGH"),
    lambda e: e.__setitem__("timestamp", e["timestamp"] + timedelta(microseconds=1)),
    lambda e: e["raw_log"]["metadata"].__setitem__("command_line", "powershell.exe -enc AAAA"),
    lambda e: e["raw_log"]["metadata"]["nested"]["a"].append(2),
    lambda e: e["metadata_"].__setitem__("pid", 4109),
])
def test_changed_event_produces_different_hash(mutate):
    original = _normalized()
    changed = copy.deepcopy(original)
    mutate(changed)
    assert compute_event_hash(original) != compute_event_hash(changed)


def test_canonical_payload_is_documented_format():
    payload = canonical_event_payload(_normalized())
    assert payload.startswith('{"event_type":"PROCESS_EXECUTION","hash_version":"yarox-event-v1"')
    assert '"timestamp":"2026-09-17T10:01:00.123456+00:00"' in payload


@pytest.mark.asyncio
async def test_stored_event_hash_survives_postgres_roundtrip_and_detects_tampering():
    data = _normalized()
    event_id = uuid.uuid4()
    data["id"] = str(event_id)

    with patch("consumers.db_writer.event_bus.publish", new_callable=AsyncMock):
        await handle_event_normalized(data)

    async with AsyncSessionLocal() as session:
        stored = await session.get(Event, event_id)
        assert stored.payload_sha256 == compute_event_hash(data)
        assert verify_event_integrity(stored) is True

        # Tamper with the stored row directly in the database
        tampered_raw = dict(stored.raw_log)
        tampered_raw["hostname"] = "SOMEONE-ELSE"
        await session.execute(update(Event).where(Event.id == event_id).values(raw_log=tampered_raw))
        await session.commit()

    async with AsyncSessionLocal() as session:
        reloaded = (await session.execute(select(Event).where(Event.id == event_id))).scalar_one()
        assert verify_event_integrity(reloaded) is False


@pytest.mark.asyncio
async def test_integrity_endpoint_reports_verification_and_legacy_rows():
    user = User(id=uuid.uuid4(), email="viewer-integrity@test.local", hashed_password="x", role=UserRole.VIEWER, is_active=True)
    app.dependency_overrides[get_current_user] = lambda: user
    try:
        data = _normalized()
        hashed_id = uuid.uuid4()
        data["id"] = str(hashed_id)
        with patch("consumers.db_writer.event_bus.publish", new_callable=AsyncMock):
            await handle_event_normalized(data)

        legacy_id = uuid.uuid4()
        async with AsyncSessionLocal() as session:
            legacy = dict(_normalized())
            session.add(Event(id=legacy_id, **legacy))  # stored without a hash, like pre-migration rows
            await session.commit()

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            ok = (await ac.get(f"/events/{hashed_id}/integrity")).json()
            old = (await ac.get(f"/events/{legacy_id}/integrity")).json()
    finally:
        app.dependency_overrides.clear()

    assert ok["verified"] is True
    assert ok["stored_sha256"] == ok["computed_sha256"]
    assert old["verified"] is None
    assert old["stored_sha256"] is None
