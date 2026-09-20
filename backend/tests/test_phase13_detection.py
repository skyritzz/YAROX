"""
Phase 13 detection foundations: the D-1 (first-match-only engine bug), D-4
(network/IDS-alert detection) and D-5 (insider-threat/data-staging detection)
gaps from docs/YAROX_REALITY_AUDIT.md.

No mocks of the systems under test: every test here stores a real Event row
through a real AsyncSession and runs the real detection_engine.process_event
against it — the same pattern already established in
tests/test_report_persistence.py's `_create_detected_case()` helper. Rules
are exercised through the real canonical taxonomy round-trip (event_type is
re-normalized from the *stored* value, not the original raw string), which
is what caught a real bug during development: see
test_canonical_types_survive_taxonomy_round_trip below.
"""
import uuid

import pytest
from sqlalchemy import select

from core.taxonomy import taxonomy_normalizer, CanonicalEventType
from database.session import AsyncSessionLocal
from detection.engine import detection_engine
from models.event import Event
from models.investigation import EvidenceItem
from models.mitre import AttackTechnique
from plugins.parsers.generic import generic_parser
from plugins.parsers.suricata import suricata_parser


async def _store_and_detect(raw_event: dict):
    """Real generic-ingest normalization -> real Postgres row -> real detection_engine,
    same helper pattern as tests/test_report_persistence.py's _create_detected_case()."""
    parsed = generic_parser.parse(raw_event)
    async with AsyncSessionLocal() as session:
        event = Event(**parsed)
        session.add(event)
        await session.commit()
        await session.refresh(event)
        case = await detection_engine.process_event(session, event)
        return event, case


async def _store_suricata_and_detect(eve_event: dict):
    canonical = suricata_parser.to_canonical(eve_event)
    kwargs = canonical.to_orm_kwargs()
    async with AsyncSessionLocal() as session:
        event = Event(**kwargs)
        session.add(event)
        await session.commit()
        await session.refresh(event)
        case = await detection_engine.process_event(session, event)
        return event, case


# ============================================================= taxonomy round-trip
# The regression test for the real bug found while building this file: rules
# re-normalize event.event_type from the *stored* value (already rewritten to
# the canonical value's own string by CanonicalSecurityEvent._apply_taxonomy),
# not the original raw string. Any canonical type a rule gates on must survive
# being fed back into taxonomy_normalizer.normalize() as its own value.lower().

def test_canonical_types_survive_taxonomy_round_trip():
    for canonical_type in (
        CanonicalEventType.SYSTEM_ALERT,
        CanonicalEventType.NETWORK_TRAFFIC,
        CanonicalEventType.AUTH_FAILURE,
        CanonicalEventType.PROCESS_EXECUTION,
    ):
        assert taxonomy_normalizer.normalize(canonical_type.value, {}) == canonical_type, (
            f"{canonical_type.value} does not survive re-normalization of its own stored "
            "value — any rule gating on this type will never fire against a real, "
            "already-persisted event, only against a freshly-constructed one"
        )


def test_generic_network_connection_string_maps_to_network_traffic():
    """The exact raw event_type string used by datasets/insider_threat/events.json."""
    assert taxonomy_normalizer.normalize("Network Connection", {}) == CanonicalEventType.NETWORK_TRAFFIC


# ============================================================= D-1: multi-rule matching

@pytest.mark.asyncio
async def test_single_event_matching_two_rules_records_evidence_for_both():
    """
    Previously (YAROX_REALITY_AUDIT.md D-1): DetectionEngine.process_event returned
    on the first matching rule, silently skipping the rest of self.rules for that
    event. A raw event_type string is always collapsed to exactly one
    canonical_event_type at ingest time (schemas.canonical_event.CanonicalSecurityEvent
    rewrites event_type to that single resolved value before storage), so two
    rules can only both match one *stored* event if they gate on the *same*
    canonical type via different secondary conditions — which SuspiciousProcess
    Execution and DataStagingViaArchiveUtility do (both require
    PROCESS_EXECUTION, then check disjoint things: a powershell/-enc keyword vs.
    an archive-utility process name). A process named '7z.exe' invoked with a
    command line that happens to also contain '-enc' is not a realistic
    real-world command line — it is deliberately constructed to exercise both
    conditions on the same event, the only way current rule overlap can occur.
    """
    host = f"DC-{uuid.uuid4().hex[:8]}"
    user = f"user-{uuid.uuid4().hex[:8]}"
    raw = {
        "timestamp": "2026-09-21T09:00:00Z",
        "hostname": host,
        "user_name": user,
        "source": "test",
        "event_type": "Process Creation",
        "severity": "HIGH",
        "metadata": {
            "process_name": "7z.exe",
            "command_line": "7z.exe -enc a -tzip archive.zip sensitive.csv",
        },
    }
    event, case = await _store_and_detect(raw)
    assert case is not None

    async with AsyncSessionLocal() as session:
        evidence = (
            await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event.id))
        ).scalars().all()
        techniques = (
            await session.execute(select(AttackTechnique).where(AttackTechnique.case_id == case.id))
        ).scalars().all()

    evidence_types = {e.evidence_type for e in evidence}
    technique_ids = {t.technique_id for t in techniques}
    assert evidence_types == {"PROCESS_EXECUTION", "DATA_STAGING"}, (
        f"expected both rules' evidence, got {evidence_types} — the first-match bug would leave only one"
    )
    assert technique_ids == {"T1059", "T1560"}
    # Both findings landed on the same case (same event -> same user/host -> correlation_engine reuses it)
    assert all(e.case_id == case.id for e in evidence)


# ============================================================= D-4: NetworkIntrusionAlert

def _alert_eve(**overrides) -> dict:
    event = {
        "timestamp": "2026-09-21T10:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "dest_ip": "185.220.101.1",
        "dest_port": 443,
        "proto": "TCP",
        "host": f"NIDS-{uuid.uuid4().hex[:8]}",
        "alert": {
            "signature": "ET TROJAN Generic Backdoor Beacon",
            "category": "A Network Trojan was detected",
            "severity": 1,
        },
    }
    event.update(overrides)
    return event


@pytest.mark.asyncio
async def test_suricata_alert_creates_case_citing_real_signature():
    event, case = await _store_suricata_and_detect(_alert_eve())
    assert case is not None
    assert case.severity == "HIGH"  # Suricata severity 1 -> HIGH, unmodified by this rule

    async with AsyncSessionLocal() as session:
        evidence = (
            await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event.id))
        ).scalars().first()
    assert evidence.evidence_type == "NETWORK_INTRUSION_ALERT"
    assert "ET TROJAN Generic Backdoor Beacon" in evidence.reason
    assert "A Network Trojan was detected" in evidence.reason


@pytest.mark.asyncio
async def test_plain_network_flow_below_transfer_threshold_creates_no_case():
    """A Suricata 'flow' record with no IDS signature and a small byte count should not
    fabricate a network intrusion or exfiltration finding from generic flow data alone."""
    flow = {
        "timestamp": "2026-09-21T10:05:00.000000+0000",
        "event_type": "flow",
        "src_ip": "10.0.0.5",
        "dest_ip": "93.184.216.34",
        "dest_port": 443,
        "proto": "TCP",
        "host": f"NIDS-{uuid.uuid4().hex[:8]}",
        "app_proto": "tls",
        "flow": {"bytes_toserver": 4096, "bytes_toclient": 8192, "state": "established"},
    }
    _, case = await _store_suricata_and_detect(flow)
    assert case is None


@pytest.mark.asyncio
async def test_system_alert_with_empty_metadata_does_not_crash():
    """NetworkIntrusionAlert.match() only checks canonical_event_type; explain() must
    not crash when a SYSTEM_ALERT-classified event has no metadata at all."""
    raw = {
        "timestamp": "2026-09-21T10:10:00Z",
        "hostname": "unknown",
        "source": "test",
        "event_type": "SYSTEM_ALERT",  # already-canonical value, exercising the round-trip path directly
        "severity": "MEDIUM",
        "raw_log": {},
        "metadata": {},
    }
    event, case = await _store_and_detect(raw)
    assert case is not None
    async with AsyncSessionLocal() as session:
        evidence = (
            await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event.id))
        ).scalars().first()
    assert "Unspecified network intrusion signature" in evidence.reason


@pytest.mark.asyncio
async def test_duplicate_identical_alert_does_not_duplicate_evidence():
    """Same signature, same case (correlated by host), delivered twice: the second
    match must be recognized as duplicate evidence via the signature-based artifact,
    not silently double-counted."""
    host = f"NIDS-{uuid.uuid4().hex[:8]}"
    first = _alert_eve(host=host)
    second = _alert_eve(host=host, timestamp="2026-09-21T10:00:05.000000+0000")

    _, case1 = await _store_suricata_and_detect(first)
    _, case2 = await _store_suricata_and_detect(second)
    assert case1 is not None and case2 is not None
    assert case1.id == case2.id  # same host correlates into the same case

    async with AsyncSessionLocal() as session:
        evidence = (
            await session.execute(select(EvidenceItem).where(EvidenceItem.case_id == case1.id))
        ).scalars().all()
    assert len(evidence) == 1, "an identical repeated signature must not create duplicate evidence rows"


# ============================================================= D-5: DataStagingViaArchiveUtility

@pytest.mark.asyncio
async def test_archive_utility_invocation_creates_case_citing_command_line():
    """Reproduces datasets/insider_threat/events.json's own 7z.exe event verbatim."""
    host = f"WORKSTATION-{uuid.uuid4().hex[:8]}"
    raw = {
        "timestamp": "2026-09-21T08:07:00Z",
        "hostname": host,
        "user_name": f"asmith-{uuid.uuid4().hex[:8]}",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "HIGH",
        "metadata": {
            "process_name": "7z.exe",
            "command_line": r"7z a -tzip archive.zip \\FS-01\HR\Employee_Salaries.csv \\FS-01\Finance\Q1_Report.xlsx",
        },
    }
    event, case = await _store_and_detect(raw)
    assert case is not None

    async with AsyncSessionLocal() as session:
        evidence = (
            await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event.id))
        ).scalars().first()
    assert evidence.evidence_type == "DATA_STAGING"
    assert "Employee_Salaries.csv" in evidence.reason
    async with AsyncSessionLocal() as session:
        technique = (
            await session.execute(
                select(AttackTechnique).where(
                    AttackTechnique.case_id == case.id, AttackTechnique.technique_id == "T1560"
                )
            )
        ).scalars().first()
    assert technique is not None


@pytest.mark.asyncio
async def test_ordinary_process_creation_does_not_match_archive_rule():
    raw = {
        "timestamp": "2026-09-21T08:08:00Z",
        "hostname": "WORKSTATION-01",
        "user_name": f"asmith-{uuid.uuid4().hex[:8]}",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "INFO",
        "metadata": {"process_name": "notepad.exe", "command_line": "notepad.exe report.txt"},
    }
    _, case = await _store_and_detect(raw)
    assert case is None


@pytest.mark.asyncio
async def test_missing_process_name_does_not_crash_archive_rule():
    raw = {
        "timestamp": "2026-09-21T08:09:00Z",
        "hostname": "WORKSTATION-01",
        "user_name": f"asmith-{uuid.uuid4().hex[:8]}",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "INFO",
        "metadata": {},
    }
    _, case = await _store_and_detect(raw)
    assert case is None


# ============================================================= D-5: LargeExternalDataTransfer

@pytest.mark.asyncio
async def test_large_transfer_to_public_ip_creates_case():
    """Reproduces datasets/insider_threat/events.json's own network-connection event verbatim
    (bytes_sent: 15000000 to 203.0.113.50) — this exact record is the audit's own cited D-5 gap."""
    host = f"WORKSTATION-{uuid.uuid4().hex[:8]}"
    raw = {
        "timestamp": "2026-09-21T08:10:00Z",
        "hostname": host,
        "user_name": f"asmith-{uuid.uuid4().hex[:8]}",
        "source": "Network Monitor",
        "event_type": "Network Connection",
        "severity": "HIGH",
        "metadata": {
            "destination_ip": "203.0.113.50",
            "destination_port": 443,
            "bytes_sent": 15000000,
            "process_name": "chrome.exe",
            "domain": "mega.nz",
        },
    }
    event, case = await _store_and_detect(raw)
    assert case is not None

    async with AsyncSessionLocal() as session:
        evidence = (
            await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event.id))
        ).scalars().first()
    assert evidence.evidence_type == "POSSIBLE_DATA_EXFILTRATION"
    assert "203.0.113.50" in evidence.reason
    assert "14.3 MB" in evidence.reason
    assert "does not confirm exfiltration" in evidence.reason  # the hedge is not optional


@pytest.mark.asyncio
async def test_large_transfer_to_private_ip_creates_no_case():
    raw = {
        "timestamp": "2026-09-21T08:11:00Z",
        "hostname": "WORKSTATION-01",
        "user_name": f"asmith-{uuid.uuid4().hex[:8]}",
        "source": "Network Monitor",
        "event_type": "Network Connection",
        "severity": "LOW",
        "metadata": {"destination_ip": "10.0.0.50", "bytes_sent": 15000000},
    }
    _, case = await _store_and_detect(raw)
    assert case is None


@pytest.mark.asyncio
async def test_small_transfer_to_public_ip_creates_no_case():
    raw = {
        "timestamp": "2026-09-21T08:12:00Z",
        "hostname": "WORKSTATION-01",
        "user_name": f"asmith-{uuid.uuid4().hex[:8]}",
        "source": "Network Monitor",
        "event_type": "Network Connection",
        "severity": "LOW",
        "metadata": {"destination_ip": "203.0.113.50", "bytes_sent": 1024},
    }
    _, case = await _store_and_detect(raw)
    assert case is None


@pytest.mark.asyncio
async def test_missing_byte_count_does_not_crash_and_creates_no_case():
    raw = {
        "timestamp": "2026-09-21T08:13:00Z",
        "hostname": "WORKSTATION-01",
        "user_name": f"asmith-{uuid.uuid4().hex[:8]}",
        "source": "Network Monitor",
        "event_type": "Network Connection",
        "severity": "LOW",
        "metadata": {"destination_ip": "203.0.113.50"},
    }
    _, case = await _store_and_detect(raw)
    assert case is None


@pytest.mark.asyncio
async def test_malformed_destination_ip_does_not_crash_and_creates_no_case():
    raw = {
        "timestamp": "2026-09-21T08:14:00Z",
        "hostname": "WORKSTATION-01",
        "user_name": f"asmith-{uuid.uuid4().hex[:8]}",
        "source": "Network Monitor",
        "event_type": "Network Connection",
        "severity": "LOW",
        "metadata": {"destination_ip": "not-an-ip-address", "bytes_sent": 15000000},
    }
    _, case = await _store_and_detect(raw)
    assert case is None


@pytest.mark.asyncio
async def test_suricata_flow_bytes_toserver_field_also_recognized():
    """Suricata's own field name ('bytes_toserver'), not the generic dataset's ('bytes_sent')."""
    flow = {
        "timestamp": "2026-09-21T10:20:00.000000+0000",
        "event_type": "flow",
        "src_ip": "10.0.0.5",
        "dest_ip": "203.0.113.77",
        "dest_port": 443,
        "proto": "TCP",
        "host": f"NIDS-{uuid.uuid4().hex[:8]}",
        "app_proto": "tls",
        "flow": {"bytes_toserver": 20_000_000, "bytes_toclient": 1200, "state": "closed"},
    }
    event, case = await _store_suricata_and_detect(flow)
    assert case is not None
    async with AsyncSessionLocal() as session:
        evidence = (
            await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event.id))
        ).scalars().first()
    assert evidence.evidence_type == "POSSIBLE_DATA_EXFILTRATION"
    assert "203.0.113.77" in evidence.reason


# ============================================================= real dataset replay (D-5)

@pytest.mark.asyncio
async def test_real_insider_threat_dataset_now_produces_detections():
    """
    Loads the actual, pre-existing datasets/insider_threat/events.json (the exact
    file YAROX_REALITY_AUDIT.md D-5 cites as producing zero detections) through the
    real ReplayEngine.load_dataset() + generic_parser path, and confirms the two
    behaviors it contains — 7z.exe archiving two file shares together, and a 15MB
    transfer to an external IP — now each produce a real case.
    """
    from replay.engine import ReplayEngine
    from core.events import event_bus as real_bus

    engine = ReplayEngine(real_bus)
    events = await engine.load_dataset("insider_threat")
    assert events, "datasets/insider_threat/events.json must exist and be non-empty for this test to be meaningful"

    # One shared suffix for the whole replay (not per-event) so events that share a
    # hostname in the original fixture (the process-creation and network-connection
    # records both run on WORKSTATION-HR) still correlate the same way a real replay
    # would, while still not colliding with rows left by a previous run of this test.
    run_suffix = uuid.uuid4().hex[:6]
    cases = []
    for raw_event in events:
        raw_event = dict(raw_event)
        raw_event["hostname"] = f"{raw_event.get('hostname', 'unknown')}-{run_suffix}"
        _, case = await _store_and_detect(raw_event)
        if case:
            cases.append(case)

    evidence_types = set()
    async with AsyncSessionLocal() as session:
        for case in cases:
            rows = (
                await session.execute(select(EvidenceItem).where(EvidenceItem.case_id == case.id))
            ).scalars().all()
            evidence_types.update(r.evidence_type for r in rows)

    assert "DATA_STAGING" in evidence_types, "the dataset's own 7z.exe event must now be detected"
    assert "POSSIBLE_DATA_EXFILTRATION" in evidence_types, "the dataset's own 15MB transfer must now be detected"
