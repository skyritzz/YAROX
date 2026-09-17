import asyncio
import logging

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload

from agents.memory import MemoryAgent
from agents.report import ReportAgent
from agents.threat_intel import ThreatIntelAgent
from agents.timeline import TimelineAgent
from agents.triage import TriageAgent
from core.case_state import INVESTIGATABLE_STATES, validate_transition
from core.config import settings
from core.locks import consume_rerun_request, investigation_lock, request_rerun
from models.investigation import EvidenceItem, InvestigationCase, InvestigationStatus
from services.confidence_service import score_investigation
from services.report_service import persist_investigation_report
from websocket.investigation_ws import manager as ws_manager

logger = logging.getLogger("yarox.orchestrator")


class AgentOrchestrator:
    def __init__(self):
        self.memory = MemoryAgent()
        self.triage = TriageAgent()
        self.timeline = TimelineAgent()
        self.threat_intel = ThreatIntelAgent()
        self.report = ReportAgent()

    async def run_investigation(self, db: AsyncSession, case_id: str, session_factory=None) -> dict:
        """
        Runs the investigation DAG for a case under a per-case distributed lock.

        Only one investigation may run per case at a time. A second attempt does not
        queue behind the first: it records a re-run request, which the holder performs
        after it finishes, so evidence that arrives mid-investigation is still analyzed.

        ``session_factory`` creates the sessions used by the agents. Callers running
        outside the API process (Celery workers) must pass a factory bound to an engine
        created inside their own event loop; the module-level engine's pooled connections
        belong to the loop that created them.
        """
        async with investigation_lock(case_id) as acquired:
            if not acquired:
                await request_rerun(case_id)
                logger.info("Investigation for case %s already running; re-run requested", case_id)
                return {"status": "skipped", "reason": "investigation already running for this case"}

            outcome = await self._run_locked(db, case_id, session_factory)
            passes = 0
            while await consume_rerun_request(case_id) and passes < settings.INVESTIGATION_MAX_RERUNS:
                passes += 1
                logger.info("Re-running investigation for case %s (evidence arrived during pass %d)", case_id, passes)
                outcome = await self._run_locked(db, case_id, session_factory)
            return outcome

    async def _run_locked(self, db: AsyncSession, case_id: str, session_factory=None) -> dict:
        from database.session import AsyncSessionLocal

        make_session = session_factory or AsyncSessionLocal

        result = await db.execute(select(InvestigationCase).where(InvestigationCase.id == case_id))
        case = result.scalar_one_or_none()
        if not case:
            return {"status": "skipped", "reason": "investigation not found"}

        if case.status not in INVESTIGATABLE_STATES:
            logger.info("Case %s is %s; not investigating a closed case", case_id, case.status.value)
            return {"status": "skipped", "reason": f"case status is {case.status.value}"}

        previous_status = case.status
        if case.status != InvestigationStatus.ANALYZING:
            validate_transition(case.status, InvestigationStatus.ANALYZING)
            case.status = InvestigationStatus.ANALYZING
            await db.commit()
        await ws_manager.broadcast({"event": "AGENT_STARTED", "event_type": "AGENT_STARTED", "case_id": str(case_id), "investigation_id": str(case_id), "agent": "Orchestrator"})

        ev_result = await db.execute(select(EvidenceItem).where(EvidenceItem.case_id == case_id))
        evidence = ev_result.scalars().all()

        try:
            async def run_agent(agent, c_id, **kwargs):
                async with make_session() as session:
                    c_res = await session.execute(
                        select(InvestigationCase)
                        .where(InvestigationCase.id == c_id)
                        .options(selectinload(InvestigationCase.mitre_techniques))
                    )
                    c = c_res.scalar_one_or_none()
                    ev_res = await session.execute(select(EvidenceItem).where(EvidenceItem.case_id == c_id))
                    ev = ev_res.scalars().all()
                    await ws_manager.broadcast({"event": "AGENT_THINKING", "event_type": "AGENT_THINKING", "case_id": str(c_id), "investigation_id": str(c_id), "agent": agent.name})
                    return await agent.analyze(session, c, list(ev), **kwargs)

            # 1. Run Memory Agent First
            memory_context = await run_agent(self.memory, case.id)

            # 2. Run Triage, Timeline, and Threat Intel concurrently
            triage_task = asyncio.create_task(run_agent(self.triage, case.id, memory_context=memory_context))
            timeline_task = asyncio.create_task(run_agent(self.timeline, case.id, memory_context=memory_context))
            threat_task = asyncio.create_task(run_agent(self.threat_intel, case.id, memory_context=memory_context))

            triage_data, timeline_data, threat_data = await asyncio.gather(triage_task, timeline_task, threat_task)

            # 3. Report Generation
            report_data = await run_agent(
                self.report, case.id,
                triage_data=triage_data, timeline_data=timeline_data, threat_data=threat_data
            )

            # 4. Confidence derived from what this investigation actually produced
            memory_similarity = None
            if getattr(memory_context, "top_similar_cases", None):
                memory_similarity = memory_context.top_similar_cases[0].similarity_score
            agent_statuses = {
                "Triage Analyst": triage_data.get("status"),
                "Forensic Timeline Analyst": timeline_data.get("status"),
                "Threat Intel Analyst": threat_data.get("status"),
                "SOC Lead": report_data.get("status"),
            }
            async with make_session() as scoring_session:
                confidence = await score_investigation(
                    scoring_session, case.id,
                    severity=case.severity.value if case.severity else None,
                    agent_statuses=agent_statuses,
                    memory_top_similarity=memory_similarity,
                )
            case.confidence_score = confidence.score
            case.confidence_breakdown = confidence.breakdown()
            await db.commit()

            # 5. Persist the canonical report (single source for API, UI and PDF)
            async with make_session() as report_session:
                report = await persist_investigation_report(
                    report_session, case.id, triage_data, timeline_data, threat_data, report_data
                )

            # Priority 9: Case moves to WAITING_FOR_REVIEW. Memory indexing is human-gated upon RESOLVED status.
            validate_transition(case.status, InvestigationStatus.WAITING_FOR_REVIEW)
            case.status = InvestigationStatus.WAITING_FOR_REVIEW
            await db.commit()

            await ws_manager.broadcast({
                "event": "REPORT_READY", "event_type": "REPORT_READY",
                "case_id": str(case_id), "investigation_id": str(case_id),
                "report_id": str(report.id), "report_version": report.version, "report_status": report.status,
            })
            return {"status": "completed", "report_id": str(report.id), "report_status": report.status}

        except Exception as e:
            logger.exception("Orchestrator failed for case %s: %s", case_id, e)
            # Return the case to the queue so the failure is visible and the case can be retried
            case.status = InvestigationStatus.OPEN if previous_status != InvestigationStatus.WAITING_FOR_REVIEW else previous_status
            await db.commit()
            await ws_manager.broadcast({
                "event": "INVESTIGATION_FAILED", "event_type": "INVESTIGATION_FAILED",
                "case_id": str(case_id), "investigation_id": str(case_id), "error": str(e),
            })
            return {"status": "failed", "error": str(e)}


orchestrator = AgentOrchestrator()
