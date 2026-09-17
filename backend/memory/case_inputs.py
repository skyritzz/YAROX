"""
Loads the persisted state of an investigation that memory indexing and memory
retrieval both work from, so the indexed side and the query side are built
identically.
"""
import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from memory.indicators import CaseIndicators, extract_case_indicators
from models.investigation import EvidenceItem, InvestigationCase, InvestigationReport
from schemas.memory import InvestigationFingerprint


@dataclass
class CaseMemoryInputs:
    case: InvestigationCase
    evidence: List[EvidenceItem]
    indicators: CaseIndicators
    report: Optional[InvestigationReport]

    @property
    def mitre_techniques(self) -> List[str]:
        return sorted({t.technique_id for t in (self.case.mitre_techniques or [])})


async def load_case_memory_inputs(session: AsyncSession, case_id: uuid.UUID | str) -> CaseMemoryInputs:
    case_uuid = uuid.UUID(str(case_id))
    case = (await session.execute(
        select(InvestigationCase)
        .options(selectinload(InvestigationCase.mitre_techniques))
        .where(InvestigationCase.id == case_uuid)
    )).scalar_one_or_none()
    if case is None:
        raise ValueError(f"Investigation {case_id} not found")

    evidence = list((await session.execute(
        select(EvidenceItem)
        .options(selectinload(EvidenceItem.event))
        .where(EvidenceItem.case_id == case_uuid)
        .order_by(EvidenceItem.timestamp)
    )).scalars().all())

    report = (await session.execute(
        select(InvestigationReport).where(
            InvestigationReport.case_id == case_uuid,
            InvestigationReport.is_current.is_(True),
        )
    )).scalar_one_or_none()

    return CaseMemoryInputs(case=case, evidence=evidence, indicators=extract_case_indicators(evidence), report=report)


def ioc_hash(indicators: CaseIndicators) -> Optional[str]:
    iocs = sorted(indicators.iocs())
    if not iocs:
        return None
    return hashlib.sha256("\n".join(iocs).encode("utf-8")).hexdigest()


def timeline_hash(entries: list) -> str:
    if not entries:
        return ""
    return hashlib.sha256(json.dumps(entries, sort_keys=True).encode("utf-8")).hexdigest()


def build_fingerprint(inputs: CaseMemoryInputs) -> InvestigationFingerprint:
    return InvestigationFingerprint(
        attack_type=None,
        campaign=None,
        mitre_techniques=inputs.mitre_techniques,
        risk_score=inputs.case.confidence_score or 0.0,
        ioc_hash=ioc_hash(inputs.indicators),
        timeline_hash=timeline_hash(inputs.report.timeline) if inputs.report else "",
    )


def semantic_text(inputs: CaseMemoryInputs) -> str:
    """
    Text embedded for semantic similarity. Uses fields available both before and after
    investigation (title, rule description, evidence reasons) plus the executive summary
    once a report exists.
    """
    parts = [inputs.case.title or "", inputs.case.description or ""]
    parts.extend(e.reason for e in inputs.evidence if e.reason)
    if inputs.report and inputs.report.executive_summary:
        parts.append(inputs.report.executive_summary)
    seen, unique = set(), []
    for part in parts:
        cleaned = " ".join(part.split())
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique.append(cleaned)
    return "\n".join(unique)[:4000]
