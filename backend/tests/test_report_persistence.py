"""
Integration: real event -> real detection -> case -> orchestrator -> persisted report,
with every finding traceable to evidence and source events, and the API and PDF
reading the same persisted report.
"""
import uuid
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select

from agents.orchestrator import AgentOrchestrator
from api.main import app
from consumers.db_writer import handle_event_normalized
from core.auth import get_current_user
from database.session import AsyncSessionLocal
from detection.engine import detection_engine
from export.report_generator import report_generator
from models.event import Event
from models.investigation import (
    AgentFinding,
    AgentReasoningStep,
    AgentExecution,
    EvidenceItem,
    InvestigationReport,
    InvestigationStatus,
)
from models.user import User, UserRole
from plugins.parsers.generic import generic_parser
from services.report_service import get_current_report, load_traced_findings
from tests.support.llm_double import EvidenceCitingLLM


def _powershell_event(host: str):
    return {
        "timestamp": "2026-09-17T10:01:00Z",
        "hostname": host,
        "user": f"asmith-{host.lower()}",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "MEDIUM",
        "metadata": {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -enc JABzAD0ATgBlAHcA",
        },
    }


async def _create_detected_case():
    """Stores a real event through the DB writer and runs the real detection engine on it."""
    host = f"FINANCE-PC-{uuid.uuid4().hex[:6].upper()}"
    data = generic_parser.parse(_powershell_event(host))
    event_id = uuid.uuid4()
    data["id"] = str(event_id)
    with patch("consumers.db_writer.event_bus.publish", new_callable=AsyncMock):
        await handle_event_normalized(data)

    async with AsyncSessionLocal() as session:
        event = await session.get(Event, event_id)
        case = await detection_engine.process_event(session, event)
        assert case is not None, "detection engine did not create a case"
        return case.id, event_id


@pytest_asyncio.fixture
async def viewer_client():
    user = User(id=uuid.uuid4(), email="report-viewer@test.local", hashed_password="x", role=UserRole.VIEWER, is_active=True)
    app.dependency_overrides[get_current_user] = lambda: user
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def _investigate(case_id, llm):
    orchestrator = AgentOrchestrator()
    with patch("services.llm_service.llm_service.generate", side_effect=llm.generate):
        async with AsyncSessionLocal() as session:
            await orchestrator.run_investigation(session, str(case_id))


@pytest.mark.asyncio
async def test_report_is_persisted_and_every_finding_traces_to_source_event(viewer_client):
    case_id, event_id = await _create_detected_case()

    # No report before investigation
    assert (await viewer_client.get(f"/investigations/{case_id}/report")).status_code == 404

    llm = EvidenceCitingLLM()
    await _investigate(case_id, llm)

    async with AsyncSessionLocal() as session:
        evidence = (await session.execute(select(EvidenceItem).where(EvidenceItem.case_id == case_id))).scalars().all()
        evidence_ids = {str(e.id) for e in evidence}
        event = await session.get(Event, event_id)
        report = await get_current_report(session, case_id)
        from models.investigation import InvestigationCase
        case = await session.get(InvestigationCase, case_id)

    # The real evidence IDs reached every LLM prompt
    for agent in ("triage", "timeline", "threat_intel", "soc_lead"):
        assert all(eid in llm.prompts[agent] for eid in evidence_ids), agent

    assert case.status == InvestigationStatus.WAITING_FOR_REVIEW
    assert report.version == 1 and report.is_current
    assert report.status == "complete"
    assert report.executive_summary.startswith("Verified: encoded PowerShell")
    assert report.timeline_source == "timeline_agent"
    assert [r["action"] for r in report.recommendations] == ["Isolate FINANCE-PC-04 pending forensic review"]
    assert all(set(r["evidence_ids"]) <= evidence_ids for r in report.recommendations)
    assert {m["technique_id"] for m in report.mitre_techniques} >= {"T1059.001"}
    assert set(report.evidence_ids) == evidence_ids
    assert len(report.finding_ids) == 4  # the fabricated-citation finding was rejected
    assert {run["status"] for run in report.agent_runs} == {"completed"}

    # The fabricated citation was rejected and the rejection is auditable
    async with AsyncSessionLocal() as session:
        stored_findings = (await session.execute(select(AgentFinding).where(AgentFinding.case_id == case_id))).scalars().all()
        assert all("DC-01" not in f.finding for f in stored_findings)
        rejection_steps = (await session.execute(
            select(AgentReasoningStep).join(AgentExecution, AgentExecution.id == AgentReasoningStep.execution_id)
            .where(AgentExecution.investigation_id == case_id, AgentReasoningStep.step_type == "findings_recorded")
        )).scalars().all()
        rejected = [r for s in rejection_steps for r in s.content["rejected"]]
        assert any("not in this investigation" in r["reason"] for r in rejected)
        assert all(s.evidence_ids for s in rejection_steps if s.content["findings"])

    # API returns the same report, with the full chain Finding -> Evidence -> Event -> Source -> Timestamp
    res = await viewer_client.get(f"/investigations/{case_id}/report")
    assert res.status_code == 200
    body = res.json()
    assert body["id"] == str(report.id)
    assert body["executive_summary"] == report.executive_summary
    assert len(body["findings"]) == 4
    for finding in body["findings"]:
        assert finding["evidence"], finding
        for citation in finding["evidence"]:
            assert citation["evidence_id"] in evidence_ids
            assert citation["event_id"] == str(event_id)
            assert citation["event_source"] == "Sysmon"
            assert citation["event_timestamp"].startswith("2026-09-17T10:01:00")
            assert citation["event_payload_sha256"] == event.payload_sha256

    findings_res = (await viewer_client.get(f"/investigations/{case_id}/findings")).json()
    assert {f["finding_id"] for f in findings_res} == set(report.finding_ids)

    # PDF is rendered from the same persisted report
    pdf_res = await viewer_client.get(f"/investigations/{case_id}/export")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    async with AsyncSessionLocal() as session:
        report = await get_current_report(session, case_id)
        findings = await load_traced_findings(session, case_id, finding_ids=report.finding_ids)
    uncompressed = report_generator.generate_pdf(report, findings, {}, compress=False)
    assert b"Verified: encoded PowerShell executed on FINANCE" in uncompressed
    assert b"Isolate FINANCE" in uncompressed
    assert b"Block all outbound" not in uncompressed


@pytest.mark.asyncio
async def test_reinvestigation_creates_new_current_report_version(viewer_client):
    case_id, _ = await _create_detected_case()
    await _investigate(case_id, EvidenceCitingLLM())
    await _investigate(case_id, EvidenceCitingLLM())

    async with AsyncSessionLocal() as session:
        reports = (await session.execute(
            select(InvestigationReport).where(InvestigationReport.case_id == case_id).order_by(InvestigationReport.version)
        )).scalars().all()
    assert [r.version for r in reports] == [1, 2]
    assert [r.is_current for r in reports] == [False, True]

    listing = (await viewer_client.get(f"/investigations/{case_id}/reports")).json()
    assert [r["version"] for r in listing] == [2, 1]
    assert (await viewer_client.get(f"/investigations/{case_id}/report")).json()["version"] == 2


@pytest.mark.asyncio
async def test_degraded_soc_lead_produces_degraded_report_without_invented_content(viewer_client):
    case_id, _ = await _create_detected_case()
    llm = EvidenceCitingLLM(overrides={
        "soc_lead": lambda ids: "this is not json",
        "timeline": lambda ids: '{"timeline": [{"time": "x", "action": "uncited", "evidence_ids": []}]}',
    })
    await _investigate(case_id, llm)

    body = (await viewer_client.get(f"/investigations/{case_id}/report")).json()
    assert body["status"] == "degraded"
    assert body["executive_summary"] is None
    assert body["recommendations"] == []
    runs = {r["agent"]: r for r in body["agent_runs"]}
    assert runs["SOC Lead"]["status"] == "degraded"
    assert "valid JSON" in runs["SOC Lead"]["error"]
    assert runs["Forensic Timeline Analyst"]["status"] == "degraded"
    # With no validated agent timeline, the report falls back to the deterministic evidence chronology
    assert body["timeline_source"] == "evidence_chronology"
    assert body["timeline"] and all(entry["evidence_ids"] for entry in body["timeline"])

    async with AsyncSessionLocal() as session:
        report = await get_current_report(session, uuid.UUID(str(case_id)))
    pdf = report_generator.generate_pdf(report, [], {}, compress=False)
    assert b"Not available: the SOC Lead did not produce a validated report" in pdf
    assert b"Isolate affected hosts" not in pdf
