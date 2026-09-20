"""
Phase 14's three scenario definitions.

Every event payload here is either a verbatim reuse of an existing, already-
proven fixture (never fabricated telemetry), or loaded directly from an
existing dataset file at import/call time:

* Scenario A reuses the exact Suricata alert shape already exercised by
  tests/test_suricata_connector.py and Phase 13's own live verification
  (ET TROJAN Cobalt Strike Beaconing Detected).
* Scenario B loads datasets/insider_threat/events.json via the real
  replay.engine.ReplayEngine.load_dataset() — the same dataset
  YAROX_REALITY_AUDIT.md's D-5 finding and Phase 13's own regression test
  (tests/test_phase13_detection.py::test_real_insider_threat_dataset_now_produces_detections)
  are built against.
* Scenario C reuses evaluation/datasets/ground_truth.json's existing
  "benign_user_logon" scenario's telemetry_events verbatim — a real, already
  human-reviewed negative-control fixture from the Phase 4C evaluation
  system, not a new one invented for this phase.
"""
from scenarios.schemas import ExpectedDetection, ExpectedOutcome, ScenarioDefinition, ScenarioEventDef

SURICATA_INTRUSION_ALERT = ScenarioDefinition(
    scenario_id="suricata_intrusion_alert",
    name="Suricata NIDS signature match",
    description=(
        "A single Suricata EVE 'alert' record (a real NIDS signature match, "
        "'ET TROJAN Cobalt Strike Beaconing Detected') is ingested via the real "
        "POST /events/ingest/suricata endpoint. Verifies the full chain: ingestion, "
        "durable storage, the Phase 13 NetworkIntrusionAlert detection rule, case "
        "creation, the real Celery-dispatched multi-agent investigation reaching a "
        "terminal state, and a persisted investigation report."
    ),
    events=[
        ScenarioEventDef(
            connector="suricata",
            relative_offset_seconds=0.0,
            label="cobalt_strike_beacon_alert",
            payload={
                "timestamp": "2026-09-22T10:00:00.000000+0000",
                "event_type": "alert",
                "src_ip": "10.0.0.5",
                "dest_ip": "185.220.101.1",
                "dest_port": 443,
                "proto": "TCP",
                "host": "PHASE14-SURICATA-SENSOR",
                "alert": {
                    "action": "allowed",
                    "gid": 1,
                    "signature_id": 2024297,
                    "rev": 2,
                    "signature": "ET TROJAN Cobalt Strike Beaconing Detected",
                    "category": "A Network Trojan was detected",
                    "severity": 1,
                },
            },
        ),
    ],
    expected=ExpectedOutcome(
        should_create_case=True,
        min_case_count=1,
        max_case_count=1,
        expected_detections=[ExpectedDetection(evidence_type="NETWORK_INTRUSION_ALERT", min_count=1)],
        min_evidence_count=1,
        expect_investigation_to_run=True,
        expect_report=True,
    ),
    notes=(
        "The detection rule (detection/rules.py NetworkIntrusionAlert) surfaces Suricata's own "
        "signature match — it does not independently confirm C2 or attacker intent beyond what "
        "Suricata itself reported. See docs/PHASE_13_DETECTION_FOUNDATIONS.md."
    ),
)


async def build_insider_threat_scenario() -> ScenarioDefinition:
    """Async constructor (ReplayEngine.load_dataset is a coroutine) — call this from
    async test/CLI code rather than relying on a module-level constant, since dataset
    loading is real file I/O the scenario contract's own definition shouldn't hide."""
    from replay.engine import ReplayEngine

    engine = ReplayEngine(event_bus=None)
    raw_events = await engine.load_dataset("insider_threat")

    events = [
        ScenarioEventDef(connector="replay", relative_offset_seconds=float(i), label=ev.get("event_type", f"event_{i}"), payload=ev)
        for i, ev in enumerate(raw_events)
    ]

    return ScenarioDefinition(
        scenario_id="insider_threat_archive_and_transfer",
        name="Insider-threat-style archive staging + external transfer",
        description=(
            "Replays datasets/insider_threat/events.json (a login, two file-access events, a "
            "7z.exe archive-staging event, and a 15 MB network transfer) via the real replay "
            "path used internally by replay.engine.ReplayEngine.stream_events(). Verifies the "
            "Phase 13 DataStagingViaArchiveUtility and LargeExternalDataTransfer rules both "
            "fire and correlate into a single case."
        ),
        events=events,
        expected=ExpectedOutcome(
            should_create_case=True,
            min_case_count=1,
            expect_correlated_single_case=True,
            expected_detections=[
                ExpectedDetection(evidence_type="DATA_STAGING", min_count=1),
                ExpectedDetection(evidence_type="POSSIBLE_DATA_EXFILTRATION", min_count=1),
            ],
            min_evidence_count=2,
            expect_investigation_to_run=True,
            expect_report=True,
        ),
        notes=(
            "Demonstrates a suspicious activity PATTERN (archive-utility invocation followed by a "
            "large external transfer) — not proof of malicious intent or confirmed data "
            "exfiltration. Both detection rules explicitly hedge this in their own evidence text; "
            "see detection/rules.py DataStagingViaArchiveUtility and LargeExternalDataTransfer."
        ),
    )


BENIGN_NEGATIVE_CONTROL = ScenarioDefinition(
    scenario_id="benign_negative_control",
    name="Benign interactive logon (negative control)",
    description=(
        "Reuses evaluation/datasets/ground_truth.json's existing 'benign_user_logon' scenario "
        "verbatim: a single routine interactive console logon (Windows EventID 4624, logon_type "
        "2). Verifies that ordinary, non-matching telemetry does not create a detection or case."
    ),
    events=[
        ScenarioEventDef(
            connector="generic",
            relative_offset_seconds=0.0,
            label="routine_interactive_logon",
            payload={
                "timestamp": "2026-09-22T10:00:00Z",
                "source": "yarox-synthetic-lab",
                "event_type": "User Logon",
                "hostname": "DEV-WS-01",
                "user_name": "developer",
                "severity": "INFO",
                "raw_log": {
                    "EventID": 4624,
                    "logon_type": 2,
                    "description": "Successful interactive console logon",
                },
                "metadata": {
                    "telemetry_type": "SYNTHETIC_TEST",
                    "lab": True,
                },
            },
        ),
    ],
    expected=ExpectedOutcome(
        should_create_case=False,
        min_case_count=0,
        max_case_count=0,
        expected_detections=[],
        min_evidence_count=0,
        expect_investigation_to_run=False,
        expect_report=False,
    ),
    notes="Negative control — asserts the ABSENCE of a detection, not merely the absence of an assertion.",
)
