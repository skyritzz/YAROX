"""
Builds the long-term memory record for a resolved investigation.

Knowledge is assembled deterministically from persisted, analyst-reviewed case data.
No LLM is called at indexing time: memory must only contain content that existed in
the reviewed investigation, not new unreviewed model output.

Source precedence:
  * ``investigation_report`` — the current persisted report (summary, recommendations,
    evidence-cited timeline, MITRE mapping)
  * ``case_evidence`` — the case has no report; only detection evidence, rule description
    and rule MITRE techniques are stored, and summary fields say so explicitly
"""
import uuid
from datetime import datetime, timezone
from typing import Tuple

from sqlalchemy.ext.asyncio import AsyncSession

from memory.case_inputs import build_fingerprint, load_case_memory_inputs, semantic_text
from memory.indicators import sorted_list
from schemas.memory import InvestigationFingerprint, InvestigationKnowledgeObject, TimelineEvent


class KnowledgeBuilder:
    async def build(self, db: AsyncSession, case_id: str | uuid.UUID) -> Tuple[InvestigationKnowledgeObject, InvestigationFingerprint]:
        inputs = await load_case_memory_inputs(db, case_id)
        case, report, indicators = inputs.case, inputs.report, inputs.indicators
        severity = case.severity.value if hasattr(case.severity, "value") else str(case.severity)

        if report is not None:
            knowledge_source = "investigation_report"
            summary = report.executive_summary or f"{case.title}: report v{report.version} has no executive summary ({report.status})."
            executive_summary = report.executive_summary
            events = [
                TimelineEvent(time=e.get("time"), action=e.get("action"), details=e.get("details"))
                for e in report.timeline
            ]
            immediate_actions = [r["action"] for r in report.recommendations]
            mitre = [m["technique_id"] for m in report.mitre_techniques] or inputs.mitre_techniques
        else:
            knowledge_source = "case_evidence"
            summary = f"{case.title}: resolved without an investigation report. {case.description or ''}".strip()
            executive_summary = None
            events = [
                TimelineEvent(time=e.timestamp.isoformat(), action=e.evidence_type, details=e.reason)
                for e in inputs.evidence
            ]
            immediate_actions = []
            mitre = inputs.mitre_techniques

        knowledge_obj = InvestigationKnowledgeObject(
            investigation={
                "title": case.title,
                "summary": summary,
                "executive_summary": executive_summary,
                "severity": severity,
                "risk_score": case.confidence_score or 0.0,
            },
            attack={
                "attack_type": None,
                "malware_family": None,
                "campaign": None,
                "mitre_techniques": sorted(set(mitre)),
                "kill_chain": [],
            },
            evidence={
                "ips": sorted_list(indicators.ips),
                "domains": sorted_list(indicators.domains),
                "urls": [],
                "hashes": sorted_list(indicators.hashes),
                "filenames": [],
                "users": sorted_list(indicators.users),
                "hosts": sorted_list(indicators.hosts),
                "processes": sorted_list(indicators.processes),
                "registry_keys": [],
                "commands": sorted_list(indicators.commands),
            },
            timeline={
                "important_events": events,
                "attack_story": executive_summary,
            },
            recommendations={
                "immediate_actions": immediate_actions,
                "long_term_actions": [],
            },
            lessons_learned=None,
            metadata={
                "investigation_id": str(case.id),
                "created_at": case.created_at,
                "qdrant_id": "",  # assigned by the memory service
                "knowledge_version": 1,
                "llm_model": None,
                "generated_at": datetime.now(timezone.utc),
                "knowledge_source": knowledge_source,
                "source_report_id": str(report.id) if report else None,
                "source_report_version": report.version if report else None,
                "embedding_text": semantic_text(inputs),
            },
        )
        return knowledge_obj, build_fingerprint(inputs)


knowledge_builder = KnowledgeBuilder()
