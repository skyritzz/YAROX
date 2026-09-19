"""
Canonical Security Event contract (Phase 11): construction, validation/error
behavior, taxonomy normalization, and compatibility with the Event ORM model,
the SHA-256 integrity hash, real replay dataset fixtures, and the replay
engine's per-event error handling.
"""
import asyncio
import json
import os
import tempfile
import uuid

import pytest

from core.integrity import compute_event_hash
from core.taxonomy import CanonicalEventType
from models.event import Event
from plugins.parsers.generic import generic_parser
from schemas.canonical_event import (
    CANONICAL_EVENT_SCHEMA_VERSION,
    CanonicalEventValidationError,
    CanonicalSecurityEvent,
)


def test_schema_version_is_the_documented_literal():
    event = CanonicalSecurityEvent.from_raw({"source": "sysmon", "event_type": "Process Creation", "raw_log": {}})
    assert event.schema_version == CANONICAL_EVENT_SCHEMA_VERSION == "1.0"


def test_ingest_shaped_payload_normalizes_with_known_taxonomy_mapping():
    raw = {
        "timestamp": "2026-09-19T06:00:00Z",
        "hostname": "FINANCE-PC-04",
        "user_name": "asmith",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "high",
        "raw_log": {"EventID": 4688, "metadata": {"process_name": "cmd.exe", "command_line": "cmd.exe /c whoami"}},
        "metadata": {"process_name": "cmd.exe", "command_line": "cmd.exe /c whoami"},
    }
    event = CanonicalSecurityEvent.from_raw(raw)
    assert event.hostname == "FINANCE-PC-04"
    assert event.user_name == "asmith"
    assert event.severity == "HIGH"
    assert event.canonical_event_type == CanonicalEventType.PROCESS_EXECUTION
    assert event.event_type == "PROCESS_EXECUTION"
    assert event.metadata["raw_event_type"] == "Process Creation"


def test_invalid_severity_is_rejected_not_silently_coerced():
    with pytest.raises(CanonicalEventValidationError):
        CanonicalSecurityEvent.from_raw(
            {"source": "sysmon", "event_type": "Process Creation", "severity": "BOGUS", "raw_log": {}}
        )


def test_missing_severity_defaults_to_info():
    event = CanonicalSecurityEvent.from_raw({"source": "sysmon", "event_type": "Process Creation", "raw_log": {}})
    assert event.severity == "INFO"


def test_oversized_raw_log_is_rejected():
    huge_raw_log = {"payload": "A" * 70_000}
    with pytest.raises(CanonicalEventValidationError):
        CanonicalSecurityEvent.from_raw({"source": "sysmon", "event_type": "Process Creation", "raw_log": huge_raw_log})


def test_non_dict_raw_log_is_wrapped_not_rejected():
    event = CanonicalSecurityEvent.from_raw({"source": "auditd", "event_type": "syscall", "raw_log": "raw text line"})
    assert event.raw_log == {"payload": "raw text line"}


def test_hostname_and_user_name_default_to_unknown_sentinel():
    event = CanonicalSecurityEvent.from_raw({"source": "sysmon", "event_type": "Process Creation", "raw_log": {}})
    assert event.hostname == "unknown"
    assert event.user_name == "unknown"


def test_unknown_event_type_passes_through_unchanged():
    event = CanonicalSecurityEvent.from_raw(
        {"source": "vendor-x", "event_type": "Some Vendor Specific Thing", "raw_log": {}}
    )
    assert event.canonical_event_type == CanonicalEventType.UNKNOWN
    assert event.event_type == "Some Vendor Specific Thing"
    assert "raw_event_type" not in event.metadata


def test_event_id_is_assigned_by_the_contract():
    event = CanonicalSecurityEvent.from_raw({"source": "sysmon", "event_type": "Process Creation", "raw_log": {}})
    assert isinstance(event.event_id, uuid.UUID)


def test_to_orm_kwargs_constructs_a_real_event_row_and_hashes_without_error():
    event = CanonicalSecurityEvent.from_raw(
        {
            "timestamp": "2026-09-19T06:00:00Z",
            "hostname": "HOST-1",
            "user_name": "jdoe",
            "source": "Sysmon",
            "event_type": "Process Creation",
            "severity": "MEDIUM",
            "raw_log": {"EventID": 4688},
            "metadata": {"process_name": "powershell.exe"},
        }
    )
    kwargs = event.to_orm_kwargs()
    assert set(kwargs.keys()) == {"id", "timestamp", "hostname", "user_name", "source", "event_type", "severity", "raw_log", "metadata_"}
    db_event = Event(**kwargs)
    assert db_event.id == event.event_id
    # compute_event_hash must not raise on the to_orm_kwargs() shape, and id must not affect the hash
    digest = compute_event_hash(kwargs)
    assert len(digest) == 64
    kwargs_different_id = dict(kwargs, id=uuid.uuid4())
    assert compute_event_hash(kwargs_different_id) == digest


def test_generic_parser_delegates_to_the_canonical_contract():
    parsed = generic_parser.parse({"source": "sysmon", "event_type": "Process Creation", "raw_log": {"EventID": 4688}})
    assert parsed["event_type"] == "PROCESS_EXECUTION"
    assert "id" in parsed and isinstance(parsed["id"], uuid.UUID)


def test_generic_parser_raises_the_canonical_error_type_on_invalid_input():
    with pytest.raises(CanonicalEventValidationError):
        generic_parser.parse({"source": "sysmon", "event_type": "x", "severity": "NOT_REAL", "raw_log": {}})


DATASET_NAMES = ["apt29_simulation", "apt_blackout", "credential_theft", "insider_threat"]


@pytest.mark.parametrize("dataset_name", DATASET_NAMES)
def test_every_replay_dataset_sample_event_normalizes_through_the_real_parser(dataset_name):
    dataset_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "..", "datasets", dataset_name, "events.json")
    )
    with open(dataset_path) as f:
        data = json.load(f)
    events = data if isinstance(data, list) else data.get("events", [])
    assert events, f"dataset {dataset_name} has no events to validate the contract against"
    for raw_event in events:
        parsed = generic_parser.parse(raw_event)
        assert parsed["source"]
        assert parsed["event_type"]
        assert parsed["severity"] in {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
        Event(**parsed)  # must construct without error


class _StubEventBus:
    def __init__(self):
        self.published = []

    async def publish(self, topic, data):
        self.published.append((topic, data))


def test_replay_engine_skips_a_malformed_event_without_killing_the_stream():
    from replay.engine import ReplayEngine

    good_event = {
        "timestamp": "2026-09-19T06:00:00Z",
        "source": "sysmon",
        "event_type": "Process Creation",
        "hostname": "H1",
        "user_name": "u1",
        "raw_log": {"EventID": 4688},
    }
    bad_event = {
        "timestamp": "2026-09-19T06:00:01Z",
        "source": "sysmon",
        "event_type": "Process Creation",
        "severity": "NOT_A_REAL_SEVERITY",
        "hostname": "H1",
        "user_name": "u1",
        "raw_log": {"EventID": 4688},
    }
    another_good_event = {
        "timestamp": "2026-09-19T06:00:02Z",
        "source": "sysmon",
        "event_type": "Process Creation",
        "hostname": "H1",
        "user_name": "u1",
        "raw_log": {"EventID": 4688},
    }

    with tempfile.TemporaryDirectory() as tmp:
        dataset_dir = os.path.join(tmp, "datasets", "mixed_validity_scenario")
        os.makedirs(dataset_dir)
        with open(os.path.join(dataset_dir, "events.json"), "w") as f:
            json.dump([good_event, bad_event, another_good_event], f)

        bus = _StubEventBus()
        engine = ReplayEngine(bus)
        # load_dataset resolves relative to replay/engine.py's own location (../../datasets);
        # patch it directly rather than fighting that path resolution.
        async def fake_load_dataset(scenario_name):
            return [good_event, bad_event, another_good_event]
        engine.load_dataset = fake_load_dataset
        engine.speed_multiplier = 1000.0  # keep the test fast regardless of timestamp deltas

        class _FakeDBContext:
            async def __aenter__(self):
                return self
            async def __aexit__(self, *a):
                return False
            async def get(self, *a, **k):
                return None
            async def commit(self):
                pass

        import replay.engine as engine_module
        original_session_local = None
        try:
            import database.session as db_session_module
            original_session_local = db_session_module.AsyncSessionLocal
            db_session_module.AsyncSessionLocal = lambda: _FakeDBContext()

            asyncio.run(engine.stream_events("mixed_validity_scenario", str(uuid.uuid4())))
        finally:
            if original_session_local is not None:
                db_session_module.AsyncSessionLocal = original_session_local

    normalized_published = [data for topic, data in bus.published if topic == "EventNormalized"]
    assert len(normalized_published) == 2, "the malformed event must be skipped, not crash the stream or silently pass through"
    lifecycle_topics = [topic for topic, _ in bus.published]
    assert "ReplayStarted" in lifecycle_topics
    assert "ReplayCompleted" in lifecycle_topics
