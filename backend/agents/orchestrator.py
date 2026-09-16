from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from models.investigation import InvestigationCase, EvidenceItem, InvestigationStatus
from agents.triage import TriageAgent
from agents.timeline import TimelineAgent
from agents.threat_intel import ThreatIntelAgent
from agents.report import ReportAgent
from agents.memory import MemoryAgent
from websocket.investigation_ws import manager as ws_manager
from scoring.confidence import ConfidenceEngine
import traceback

class AgentOrchestrator:
    def __init__(self):
        self.memory = MemoryAgent()
        self.triage = TriageAgent()
        self.timeline = TimelineAgent()
        self.threat_intel = ThreatIntelAgent()
        self.report = ReportAgent()

    async def run_investigation(self, db: AsyncSession, case_id: str):
        result = await db.execute(select(InvestigationCase).where(InvestigationCase.id == case_id))
        case = result.scalar_one_or_none()
        if not case:
            return

        case.status = InvestigationStatus.ANALYZING
        await db.commit()
        await ws_manager.broadcast({"event": "AGENT_STARTED", "event_type": "AGENT_STARTED", "case_id": str(case_id), "investigation_id": str(case_id), "agent": "Orchestrator"})

        ev_result = await db.execute(select(EvidenceItem).where(EvidenceItem.case_id == case_id))
        evidence = ev_result.scalars().all()

        try:
            import asyncio
            from database.session import AsyncSessionLocal
            
            async def run_agent(agent, c_id, **kwargs):
                async with AsyncSessionLocal() as session:
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
            await ws_manager.broadcast({"event": "AGENT_THINKING", "event_type": "AGENT_THINKING", "case_id": str(case_id), "investigation_id": str(case_id), "agent": self.report.name})
            report_data = await self.report.analyze(db, case, list(evidence), triage_data, timeline_data, threat_data)
            
            # 4. Assign Confidence Score
            p_score = sum(ev.importance_score for ev in evidence) / max(len(evidence), 1) if evidence else 0.5
            final_score, breakdown = ConfidenceEngine.calculate_score(0.8, 0.7, p_score, 0.6)
            case.confidence_score = final_score
            case.confidence_breakdown = breakdown
            
            # Priority 9: Case moves to WAITING_FOR_REVIEW. Memory indexing is human-gated upon RESOLVED status.
            case.status = InvestigationStatus.WAITING_FOR_REVIEW
            await db.commit()
            
            await ws_manager.broadcast({"event": "REPORT_READY", "event_type": "REPORT_READY", "case_id": str(case_id), "investigation_id": str(case_id)})
            
        except Exception as e:
            print(f"Orchestrator failed: {e}")
            traceback.print_exc()
            case.status = InvestigationStatus.OPEN
            await db.commit()
            
orchestrator = AgentOrchestrator()
