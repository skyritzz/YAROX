"""
Unit tests for the agent evidence contract.
"""
import uuid
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace

from agents.evidence import (
    MAX_PROMPT_EVIDENCE_ITEMS,
    evidence_for_prompt,
    validate_cited_entries,
    validate_findings,
)

E1, E2 = str(uuid.uuid4()), str(uuid.uuid4())
ALLOWED = {E1, E2}


def test_valid_finding_is_accepted_with_normalized_fields():
    accepted, rejected = validate_findings([{
        "finding": "  Encoded PowerShell executed on FINANCE-PC-04  ",
        "kind": "observation",
        "evidence_ids": [E1, E1.upper(), E2],
        "reasoning_summary": "Command line contains -enc.",
        "mitre_techniques": ["T1059.001", "T9999", "t1027"],
        "confidence": 0.8,
    }], "Triage Analyst", ALLOWED)
    assert rejected == []
    f = accepted[0]
    assert f.finding == "Encoded PowerShell executed on FINANCE-PC-04"
    assert [str(e) for e in f.evidence_ids] == [E1, E2]
    assert f.mitre_techniques == ["T1059.001", "T1027"]
    assert f.kind == "observation"
    assert f.confidence == 0.8
    assert f.agent == "Triage Analyst"


def test_finding_citing_unknown_evidence_is_rejected_entirely():
    fabricated = str(uuid.uuid4())
    accepted, rejected = validate_findings([{
        "finding": "Lateral movement to DC-01", "kind": "observation", "evidence_ids": [E1, fabricated],
    }], "SOC Lead", ALLOWED)
    assert accepted == []
    assert "not in this investigation" in rejected[0].reason


def test_finding_without_evidence_is_rejected():
    accepted, rejected = validate_findings([
        {"finding": "PowerShell execution was detected", "kind": "observation", "evidence_ids": []},
        {"finding": "PowerShell execution was detected", "kind": "observation"},
    ], "Triage Analyst", ALLOWED)
    assert accepted == []
    assert len(rejected) == 2


def test_malformed_findings_are_rejected_and_unknown_kind_becomes_hypothesis():
    accepted, rejected = validate_findings([
        "not an object",
        {"finding": "", "evidence_ids": [E1]},
        {"finding": "Possible credential theft", "kind": "certain", "evidence_ids": [E2], "confidence": "high"},
    ], "Triage Analyst", ALLOWED)
    assert len(rejected) == 2
    assert accepted[0].kind == "hypothesis"
    assert accepted[0].confidence is None


def test_non_list_findings_rejected():
    accepted, rejected = validate_findings({"finding": "x"}, "Triage Analyst", ALLOWED)
    assert accepted == [] and len(rejected) == 1


def test_cited_entries_validation():
    accepted, rejected = validate_cited_entries([
        {"action": "Reset credentials", "evidence_ids": [E1]},
        {"action": "Block IP", "evidence_ids": []},
        {"action": "Isolate host", "evidence_ids": [str(uuid.uuid4())]},
        {"rationale": "missing action", "evidence_ids": [E1]},
    ], ALLOWED, "action")
    assert [a["action"] for a in accepted] == ["Reset credentials"]
    assert accepted[0]["evidence_ids"] == [E1]
    assert len(rejected) == 3


def _evidence(i, artifact="x"):
    return SimpleNamespace(
        id=uuid.uuid4(), timestamp=datetime(2026, 9, 17, tzinfo=timezone.utc) + timedelta(seconds=i),
        evidence_type="PROCESS_EXECUTION", source="Sysmon", artifact=artifact, reason="r",
    )


def test_prompt_evidence_keeps_ids_when_fields_are_long():
    items = [_evidence(0, artifact="A" * 5000)]
    block = evidence_for_prompt(items)
    entry = block["evidence_items"][0]
    assert entry["evidence_id"] == str(items[0].id)
    assert entry["artifact"].endswith("...[TRUNCATED]")
    assert len(entry["artifact"]) < 500


def test_prompt_evidence_states_omitted_items():
    items = [_evidence(i) for i in range(MAX_PROMPT_EVIDENCE_ITEMS + 5)]
    block = evidence_for_prompt(list(reversed(items)))
    assert len(block["evidence_items"]) == MAX_PROMPT_EVIDENCE_ITEMS
    assert block["omitted_item_count"] == 5
    assert block["evidence_items"][0]["evidence_id"] == str(items[0].id)  # earliest first
