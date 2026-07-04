from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase
from agents.base import BaseAgent
from services.llm_service import llm_service
import json

class TimelineAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Forensic Timeline Analyst",
            role="Incident reconstructor",
            goal="Build a chronological timeline of the attack from the evidence."
        )

    async def analyze(self, db: AsyncSession, case: InvestigationCase, evidence: list) -> dict:
        context = [{"timestamp": str(e.timestamp), "artifact": e.artifact, "type": e.evidence_type} for e in evidence]
        
        prompt = """
        You are a Timeline Analyst. Reconstruct the attacker journey from the evidence provided.
        Return a JSON object with a single key "timeline" containing a list of objects, each with "time", "action", and "details".
        Return ONLY valid JSON.
        """
        
        await self._log_action(db, case.id, "Reconstructing event timeline.", "Calling LLM for timeline generation.", context, None)
        
        response_text = await llm_service.generate(prompt, json.dumps(context), json_format=True)
        try:
            result = json.loads(response_text)
        except Exception:
            result = {"timeline": []}
            
        await self._log_action(db, case.id, "Timeline construction complete.", "Generated chronological timeline.", None, result)
        return result
