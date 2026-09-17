from typing import Dict, Any, List
from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase, EvidenceItem
from agents.base import BaseAgent
from schemas.memory import MemoryContext
from memory.service import memory_service
from memory.case_inputs import build_fingerprint, load_case_memory_inputs, semantic_text

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

            # Fingerprint and indicators are derived from persisted case state, exactly
            # as they are when a resolved case is indexed into memory.
            inputs = await load_case_memory_inputs(db, case.id)
            fingerprint = build_fingerprint(inputs)
            indicators = inputs.indicators
            mitre_techs = fingerprint.mitre_techniques

            await self.emit_step(db, execution, "reasoning_started", {
                "text": "Querying Investigation Memory Service for similar past cases using Hybrid Search."
            })

            async def _memory_search():
                await memory_service.initialize()
                return await memory_service.find_similar_cases(
                    db, fingerprint, indicators, semantic_text(inputs),
                    exclude_investigation_id=str(case.id),
                )

            similar_cases = await self.run_tool(
                db, execution, "memory_search",
                tool_input={
                    "collection": memory_service.vector_repo.collection_name,
                    "limit": 5,
                    "mitre_technique_count": len(mitre_techs),
                    "ioc_count": len(indicators.iocs()),
                    "asset_count": len(indicators.assets()),
                },
                operation=_memory_search,
                summarize_output=lambda results: {
                    "result_count": len(results),
                    "investigation_ids": [r.investigation_id for r in results],
                    "top_similarity": round(results[0].similarity_score, 4) if results else None,
                },
            )

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
                
                shared_mitre.update(sim.shared_mitre_techniques)
                
                # Shared indicators computed by the memory service against this case's indicators
                shared_iocs.update(sim.shared_iocs)
                shared_assets.update(sim.shared_assets)
                
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
