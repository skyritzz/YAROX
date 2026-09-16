from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase
from agents.base import BaseAgent
from services.llm_service import llm_service
from core.utils import sanitize_evidence, build_sandboxed_agent_prompt
import json

class TimelineAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Forensic Timeline Analyst",
            role="Incident reconstructor",
            goal="Build a chronological timeline of the attack from the evidence."
        )

    async def analyze(self, db: AsyncSession, case: InvestigationCase, evidence: list, memory_context=None) -> dict:
        execution = await self.start_execution(db, case.id)
        
        try:
            # Observation
            await self.emit_step(db, execution, "observation_started", {
                "text": f"Analyzing {len(evidence)} artifacts to construct sequence of events."
            })
            
            raw_evidence = [
                {"timestamp": str(e.timestamp), "artifact": e.artifact, "type": e.evidence_type, "reason": e.reason}
                for e in evidence
            ]
            evidence_block = sanitize_evidence(raw_evidence)
            
            role_desc = "You are a Forensic Timeline Analyst reconstructing an incident chronology."
            task_desc = f"Case: {case.title}\nReconstruct the chronological timeline strictly from verified evidence."
            format_desc = """Return a JSON object with:
"timeline": A list of chronological objects, each with:
  - "time": ISO or formatted timestamp string from evidence
  - "action": What action occurred
  - "details": Specific factual details from evidence
Return ONLY valid JSON. Do not invent events not present in the evidence."""

            full_prompt = build_sandboxed_agent_prompt(
                role_instruction=role_desc,
                task_instruction=task_desc,
                evidence_block=evidence_block,
                output_format_instruction=format_desc
            )
            
            # Reasoning
            await self.emit_step(db, execution, "reasoning_started", {
                "text": "Extracting temporal relationships and chronological order within sandboxed boundary."
            })
            
            response_text = await self.call_llm_with_timeout(
                llm_service.generate(full_prompt, "", json_format=True),
                timeout_seconds=120,
                execution=execution
            )
            
            try:
                result = json.loads(response_text)
                if not isinstance(result, dict) or "timeline" not in result or not isinstance(result["timeline"], list):
                    raise Exception("Invalid timeline JSON structure.")
                    
                await self.emit_step(db, execution, "reasoning_complete", {
                    "text": f"Timeline reconstructed with {len(result.get('timeline', []))} events.",
                    "raw": result
                })
            except Exception:
                raise Exception("LLM failed to return valid JSON timeline.")
                
            # Decision
            await self.emit_step(db, execution, "decision_made", {
                "text": "Finalized attack story timeline.",
                "timeline_count": len(result.get("timeline", []))
            })
            
            # Handoff
            await self.emit_step(db, execution, "handoff", {
                "text": "Passing timeline to Threat Intel Analyst for MITRE mapping.",
                "next_agent": "Threat Intel Analyst"
            })
            
            await self.finish_execution(db, execution, status="completed", confidence=0.9)
            return result
            
        except Exception as e:
            fallback_result = {"timeline": []}
            
            await self.emit_step(db, execution, "step_failed", {
                "text": f"Error during timeline generation: {str(e)}. Degraded to empty timeline.",
                "error": str(e)
            })
            
            await self.emit_step(db, execution, "handoff", {
                "text": "Passing degraded timeline context to Threat Intel Analyst.",
                "next_agent": "Threat Intel Analyst"
            })
            
            await self.finish_execution(db, execution, status="degraded", confidence=0.5)
            return fallback_result
