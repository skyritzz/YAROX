from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase, EvidenceItem
from agents.base import BaseAgent
from schemas.memory import MemoryContext, InvestigationFingerprint
from memory.service import memory_service
import hashlib

class MemoryAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Memory Agent",
            role="Historical Intelligence Retriever",
            goal="Identify similar past investigations to provide historical context."
        )

    async def analyze(self, db: AsyncSession, case: InvestigationCase, evidence: List[EvidenceItem]) -> MemoryContext:
        execution = await self.start_execution(db, case.id)
        
        try:
            await self.emit_step(db, execution, "observation_started", {
                "text": "Extracting current case fingerprint to search historical memory."
            })

            # Extract fingerprint
            ips, domains, hashes = set(), set(), set()
            for ev in evidence:
                if ev.evidence_type == 'ip': ips.add(ev.artifact)
                elif ev.evidence_type == 'domain': domains.add(ev.artifact)
                elif ev.evidence_type == 'hash': hashes.add(ev.artifact)

            ioc_str = "".join(sorted(list(ips) + list(domains) + list(hashes)))
            mitre_techs = [mt.technique_id for mt in case.mitre_techniques] if case.mitre_techniques else []
            
            fingerprint = InvestigationFingerprint(
                attack_type=None,
                mitre_techniques=mitre_techs,
                campaign=None,
                risk_score=case.confidence_score or 0.0,
                ioc_hash=hashlib.sha256(ioc_str.encode()).hexdigest(),
                timeline_hash=""
            )

            await self.emit_step(db, execution, "reasoning_started", {
                "text": "Querying Investigation Memory Service for similar past cases using Hybrid Search."
            })

            current_summary = f"{case.title} {case.description or ''}"
            await memory_service.initialize()
            similar_cases = await memory_service.find_similar_cases(db, fingerprint, current_summary)

            # Priority 10: Truthful Memory Results (No fabricated historical matches)
            if not similar_cases:
                empty_context = MemoryContext(
                    top_similar_cases=[],
                    shared_mitre_techniques=[],
                    shared_iocs=[],
                    shared_assets=[],
                    shared_campaigns=[],
                    previous_resolutions=[],
                    previous_recommendations=[],
                    confidence_score=0.0
                )

                await self.emit_step(db, execution, "decision_made", {
                    "text": "No matching historical investigations found in verified memory.",
                    "similar_cases_count": 0,
                    "top_score": 0.0
                })

                await self.finish_execution(db, execution, status="completed", confidence=1.0)
                return empty_context

            # Build Memory Context for verified historical cases
            shared_mitre = set()
            shared_iocs = set()
            shared_assets = set()
            shared_campaigns = set()
            previous_resolutions = []
            previous_recommendations = []
            
            for sim in similar_cases:
                if not sim.knowledge_object: 
                    continue
                past_ko = sim.knowledge_object
                
                shared_mitre.update(set(mitre_techs) & set(past_ko.attack.mitre_techniques))
                
                # Check shared IOCs
                current_iocs = ips | domains | hashes
                past_iocs = set(past_ko.evidence.ips + past_ko.evidence.domains + past_ko.evidence.hashes)
                shared_iocs.update(current_iocs & past_iocs)
                
                if past_ko.attack.campaign:
                    shared_campaigns.add(past_ko.attack.campaign)
                    
                if past_ko.investigation.executive_summary:
                    previous_resolutions.append(past_ko.investigation.executive_summary)
                    
                previous_recommendations.extend(past_ko.recommendations.immediate_actions)

            context = MemoryContext(
                top_similar_cases=similar_cases,
                shared_mitre_techniques=list(shared_mitre),
                shared_iocs=list(shared_iocs),
                shared_assets=list(shared_assets),
                shared_campaigns=list(shared_campaigns),
                previous_resolutions=previous_resolutions[:3],
                previous_recommendations=list(set(previous_recommendations))[:5],
                confidence_score=similar_cases[0].similarity_score if similar_cases else 0.0
            )

            await self.emit_step(db, execution, "decision_made", {
                "text": f"Found {len(similar_cases)} verified similar historical cases in memory.",
                "similar_cases_count": len(similar_cases),
                "top_score": round(context.confidence_score, 2)
            })

            await self.finish_execution(db, execution, status="completed", confidence=1.0)
            return context

        except Exception as e:
            await self.emit_step(db, execution, "step_failed", {
                "text": f"Failed to retrieve memory context: {str(e)}"
            })
            await self.finish_execution(db, execution, status="failed", confidence=0.0)
            return MemoryContext()
