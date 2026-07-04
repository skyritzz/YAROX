from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase
from agents.base import BaseAgent
from services.llm_service import llm_service
import json

class TriageAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Triage Analyst",
            role="First responder",
            goal="Analyze initial detection, assess severity, and provide a summary."
        )

    async def analyze(self, db: AsyncSession, case: InvestigationCase, evidence: list) -> dict:
        context = {
            "title": case.title,
            "description": case.description,
            "evidence": [{"artifact": e.artifact, "type": e.evidence_type, "reason": e.reason} for e in evidence]
        }
        
        prompt = """
        You are a Triage Analyst. Review the security detection context and return a JSON object with:
        1. "severity": (LOW, MEDIUM, HIGH, CRITICAL)
        2. "summary": A 2-sentence summary of what occurred.
        3. "priority_score": A float between 0.0 and 1.0 indicating urgency.
        Return ONLY valid JSON.
        """
        
        await self._log_action(db, case.id, "Reviewing detection evidence to assess severity.", "Calling LLM for triage analysis.", context, None)
        
        response_text = await llm_service.generate(prompt, json.dumps(context), json_format=True)
        try:
            result = json.loads(response_text)
        except Exception:
            result = {"severity": "HIGH", "summary": "LLM failed to provide valid output.", "priority_score": 0.8}
            
        await self._log_action(db, case.id, "Triage complete.", "Generated triage assessment.", None, result)
        return result
