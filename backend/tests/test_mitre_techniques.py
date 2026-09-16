"""
MITRE ATT&CK identifiers must be preserved exactly, including sub-techniques.
"""
import uuid
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from agents.threat_intel import ThreatIntelAgent
from database.session import AsyncSessionLocal
from models.investigation import EvidenceItem, InvestigationCase, InvestigationStatus, Severity
from models.mitre import AttackTechnique
from security.mitre.knowledge_base import mitre_kb
from datetime import datetime, timezone


def test_technique_is_validated():
    info = mitre_kb.validate("T1059")
    assert info["technique_id"] == "T1059"
    assert info["name"] == "Command and Scripting Interpreter"
    assert info["parent_technique_id"] is None


def test_sub_technique_is_preserved_not_truncated():
    info = mitre_kb.validate("T1059.001")
    assert info["technique_id"] == "T1059.001"
    assert info["name"] == "PowerShell"
    assert info["parent_technique_id"] == "T1059"


def test_normalization_keeps_sub_technique():
    assert mitre_kb.validate(" t1218.011 ")["technique_id"] == "T1218.011"


@pytest.mark.parametrize("bad", ["T9999_FAKE", "T105", "T1059.1", "1059.001", "", None, 1059])
def test_malformed_ids_are_rejected(bad):
    assert mitre_kb.validate(bad) is None


def test_unknown_sub_technique_is_not_silently_accepted():
    assert mitre_kb.validate("T1059.999") is None


@pytest.mark.asyncio
async def test_threat_intel_persists_full_sub_technique_ids():
    case_id = uuid.uuid4()
    async with AsyncSessionLocal() as session:
        session.add(InvestigationCase(id=case_id, title="Encoded PowerShell", status=InvestigationStatus.OPEN, severity=Severity.HIGH))
        session.add(EvidenceItem(
            case_id=case_id, evidence_type="PROCESS_EXECUTION", source="Sysmon",
            timestamp=datetime.now(timezone.utc), artifact="powershell.exe -enc AAA", reason="encoded command",
        ))
        await session.commit()

    llm_output = """{
        "mitre_mapping": [
            {"technique_id": "T1059.001", "technique_name": "x", "tactic": "x", "reason": "encoded powershell"},
            {"technique_id": "T1027", "technique_name": "x", "tactic": "x", "reason": "base64 payload"},
            {"technique_id": "T1059.999", "technique_name": "x", "tactic": "x", "reason": "made-up sub-technique"},
            {"technique_id": "T9999", "technique_name": "x", "tactic": "x", "reason": "hallucinated"}
        ],
        "historical_insight": "none"
    }"""

    async with AsyncSessionLocal() as session:
        from sqlalchemy.orm import selectinload
        case = (await session.execute(
            select(InvestigationCase).options(selectinload(InvestigationCase.mitre_techniques)).where(InvestigationCase.id == case_id)
        )).scalar_one()
        evidence = (await session.execute(select(EvidenceItem).where(EvidenceItem.case_id == case_id))).scalars().all()
        with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock, return_value=llm_output), \
             patch("memory.service.memory_service.find_similar_cases", new_callable=AsyncMock, return_value=[]):
            result = await ThreatIntelAgent().analyze(session, case, list(evidence))

    ids = [m["technique_id"] for m in result["mitre_mapping"]]
    assert ids == ["T1059.001", "T1027", "T1059"]
    substituted = result["mitre_mapping"][2]
    assert "T1059.999" in substituted["reason"] and "parent technique T1059" in substituted["reason"]

    async with AsyncSessionLocal() as session:
        stored = sorted(t.technique_id for t in (await session.execute(
            select(AttackTechnique).where(AttackTechnique.case_id == case_id)
        )).scalars().all())
    assert stored == ["T1027", "T1059", "T1059.001"]
