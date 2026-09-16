"""
Canonical investigation report persistence.

The report is assembled only from persisted investigation state and validated agent
output. It is the single source of truth for the report API, the UI and the PDF export.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from models.investigation import (
    AgentFinding,
    AgentFindingEvidence,
    EvidenceItem,
    InvestigationCase,
    InvestigationReport,
)
from models.mitre import AttackTechnique
from schemas.findings import EvidenceCitation, TracedFinding


def evidence_chronology(evidence: List[EvidenceItem]) -> List[Dict[str, Any]]:
    """Deterministic timeline built directly from evidence items (no LLM involvement)."""
    ordered = sorted(evidence, key=lambda e: e.timestamp)
    return [
        {
            "time": e.timestamp.isoformat(),
            "action": e.evidence_type,
            "details": e.reason,
            "evidence_ids": [str(e.id)],
        }
        for e in ordered
    ]


def report_status(triage: Dict, timeline: Dict, threat: Dict, soc_lead: Dict) -> str:
    if soc_lead.get("status") != "completed":
        return "degraded"
    if any(part.get("status") != "completed" for part in (triage, timeline, threat)):
        return "partial"
    return "complete"


async def persist_investigation_report(
    session: AsyncSession,
    case_id: uuid.UUID,
    triage: Dict[str, Any],
    timeline: Dict[str, Any],
    threat: Dict[str, Any],
    soc_lead: Dict[str, Any],
) -> InvestigationReport:
    """
    Creates a new current report version for the case. The case row is locked so
    concurrent report writes for the same case are serialized.
    """
    case = (await session.execute(
        select(InvestigationCase).where(InvestigationCase.id == case_id).with_for_update()
    )).scalar_one()

    evidence = (await session.execute(
        select(EvidenceItem).where(EvidenceItem.case_id == case_id)
    )).scalars().all()
    techniques = (await session.execute(
        select(AttackTechnique).where(AttackTechnique.case_id == case_id)
    )).scalars().all()

    if timeline.get("status") == "completed" and timeline.get("timeline"):
        timeline_entries, timeline_source = timeline["timeline"], "timeline_agent"
    else:
        timeline_entries, timeline_source = evidence_chronology(list(evidence)), "evidence_chronology"

    mapped = {m["technique_id"]: m for m in threat.get("mitre_mapping", [])}
    mitre = []
    for t in sorted(techniques, key=lambda t: t.technique_id):
        mapping = mapped.get(t.technique_id)
        mitre.append({
            "technique_id": t.technique_id,
            "technique_name": t.technique_name,
            "tactic": t.tactic,
            "reason": t.reason,
            "source": "threat_intel_agent" if mapping else "detection_rule",
            "evidence_ids": mapping["evidence_ids"] if mapping else [],
        })

    finding_ids = [
        f["finding_id"]
        for part in (triage, timeline, threat, soc_lead)
        for f in part.get("findings", [])
    ]

    agent_runs = [
        {"agent": name, "execution_id": part.get("execution_id"), "status": part.get("status"), "error": part.get("error")}
        for name, part in (
            ("Triage Analyst", triage),
            ("Forensic Timeline Analyst", timeline),
            ("Threat Intel Analyst", threat),
            ("SOC Lead", soc_lead),
        )
    ]

    current_version = (await session.execute(
        select(func.max(InvestigationReport.version)).where(InvestigationReport.case_id == case_id)
    )).scalar_one_or_none() or 0
    await session.execute(
        update(InvestigationReport)
        .where(InvestigationReport.case_id == case_id, InvestigationReport.is_current.is_(True))
        .values(is_current=False)
    )

    soc_execution_id = soc_lead.get("execution_id")
    report = InvestigationReport(
        id=uuid.uuid4(),
        case_id=case_id,
        version=current_version + 1,
        is_current=True,
        status=report_status(triage, timeline, threat, soc_lead),
        generated_at=datetime.now(timezone.utc),
        soc_lead_execution_id=uuid.UUID(soc_execution_id) if soc_execution_id else None,
        title=case.title,
        severity=case.severity.value if case.severity else "MEDIUM",
        confidence_score=case.confidence_score,
        executive_summary=soc_lead.get("executive_summary"),
        finding_ids=finding_ids,
        recommendations=soc_lead.get("recommendations", []),
        mitre_techniques=mitre,
        timeline=timeline_entries,
        timeline_source=timeline_source,
        evidence_ids=[str(e.id) for e in sorted(evidence, key=lambda e: e.timestamp)],
        agent_runs=agent_runs,
    )
    session.add(report)
    await session.commit()
    return report


async def load_traced_findings(
    session: AsyncSession,
    case_id: uuid.UUID,
    finding_ids: Optional[List[str]] = None,
    execution_id: Optional[uuid.UUID] = None,
) -> List[Dict[str, Any]]:
    """
    Resolves findings through the full chain:
    Finding -> EvidenceItem -> Event (source, timestamp, payload hash).
    """
    stmt = (
        select(AgentFinding)
        .options(
            selectinload(AgentFinding.evidence_links)
            .selectinload(AgentFindingEvidence.evidence_item)
            .selectinload(EvidenceItem.event)
        )
        .where(AgentFinding.case_id == case_id)
        .order_by(AgentFinding.created_at)
    )
    if finding_ids is not None:
        stmt = stmt.where(AgentFinding.id.in_([uuid.UUID(str(f)) for f in finding_ids]))
    if execution_id is not None:
        stmt = stmt.where(AgentFinding.execution_id == execution_id)
    findings = (await session.execute(stmt)).scalars().all()

    traced = []
    for f in findings:
        citations = []
        for link in sorted(f.evidence_links, key=lambda l: l.evidence_item.timestamp):
            item = link.evidence_item
            event = item.event
            citations.append(EvidenceCitation(
                evidence_id=item.id,
                evidence_type=item.evidence_type,
                artifact=item.artifact,
                source=item.source,
                timestamp=item.timestamp,
                event_id=event.id if event else None,
                event_source=event.source if event else None,
                event_timestamp=event.timestamp if event else None,
                event_payload_sha256=event.payload_sha256 if event else None,
            ))
        traced.append(TracedFinding(
            finding_id=f.id,
            agent=f.agent_name,
            finding=f.finding,
            kind=f.kind,
            confidence=f.confidence,
            reasoning_summary=f.reasoning_summary,
            mitre_techniques=f.mitre_techniques or [],
            execution_id=f.execution_id,
            timestamp=f.created_at,
            evidence=citations,
        ).model_dump(mode="json"))
    return traced


async def get_current_report(session: AsyncSession, case_id: uuid.UUID) -> Optional[InvestigationReport]:
    return (await session.execute(
        select(InvestigationReport).where(
            InvestigationReport.case_id == case_id,
            InvestigationReport.is_current.is_(True),
        )
    )).scalar_one_or_none()
