"""
Collects confidence inputs from persisted investigation state.

Everything here is measured, not assumed: evidence rows, their source events and hashes,
agent execution outcomes, finding citations and the memory search result of this run.
"""
import uuid
from typing import Any, Dict, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from core.integrity import verify_event_integrity
from models.investigation import AgentFinding, AgentFindingEvidence, EvidenceItem
from scoring.confidence import ConfidenceInputs, ConfidenceResult, calculate_confidence

AGENT_NAMES = ("Triage Analyst", "Forensic Timeline Analyst", "Threat Intel Analyst", "SOC Lead")


async def collect_confidence_inputs(
    session: AsyncSession,
    case_id: uuid.UUID,
    severity: Optional[str],
    agent_statuses: Dict[str, Optional[str]],
    memory_top_similarity: Optional[float],
) -> ConfidenceInputs:
    evidence = (await session.execute(
        select(EvidenceItem).options(selectinload(EvidenceItem.event)).where(EvidenceItem.case_id == case_id)
    )).scalars().all()

    cited_ids = set((await session.execute(
        select(AgentFindingEvidence.evidence_item_id)
        .join(AgentFinding, AgentFinding.id == AgentFindingEvidence.finding_id)
        .where(AgentFinding.case_id == case_id)
    )).scalars().all())

    verified = 0
    for item in evidence:
        if item.event is not None and verify_event_integrity(item.event) is True:
            verified += 1

    return ConfidenceInputs(
        severity=severity,
        agents_total=len(AGENT_NAMES),
        agents_completed=sum(1 for name in AGENT_NAMES if agent_statuses.get(name) == "completed"),
        evidence_total=len(evidence),
        evidence_cited=len([e for e in evidence if e.id in cited_ids]),
        distinct_source_events=len({e.event_id for e in evidence if e.event_id}),
        distinct_sources=len({e.source for e in evidence if e.source}),
        evidence_with_verified_hash=verified,
        memory_top_similarity=memory_top_similarity,
    )


async def score_investigation(
    session: AsyncSession,
    case_id: uuid.UUID,
    severity: Optional[str],
    agent_statuses: Dict[str, Optional[str]],
    memory_top_similarity: Optional[float],
) -> ConfidenceResult:
    inputs = await collect_confidence_inputs(session, case_id, severity, agent_statuses, memory_top_similarity)
    return calculate_confidence(inputs)


def acceptance_confidence(accepted: int, rejected: int) -> Optional[float]:
    """
    Per-agent confidence: the share of an agent's proposed findings that survived
    evidence validation. ``None`` when the agent proposed nothing, because there is
    then nothing to be confident about.
    """
    total = accepted + rejected
    if total == 0:
        return None
    return round(accepted / total, 4)


def acceptance_explanation(accepted: int, rejected: int, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    explanation = {
        "basis": "share of proposed findings that passed evidence validation",
        "accepted_findings": accepted,
        "rejected_findings": rejected,
    }
    if extra:
        explanation.update(extra)
    return explanation
