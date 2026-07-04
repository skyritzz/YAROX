from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase
from agents.base import BaseAgent
from services.llm_service import llm_service
import json

class ReportAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="SOC Lead",
            role="Report Generator",
            goal="Synthesize all findings into a final investigation report."
        )

    async def analyze(self, db: AsyncSession, case: InvestigationCase, evidence: list, triage_data: dict, timeline_data: dict, threat_data: dict) -> dict:
        context = {
            "case": case.title,
            "triage": triage_data,
            "timeline": timeline_data,
            "threat_intel": threat_data
        }
        
        prompt = """
        You are the SOC Lead. Synthesize the provided agent findings into a final executive summary and recommendations.
        IMPORTANT: If the threat_intel data mentions similarities to past cases, you MUST explicitly mention this historical trend in your executive summary.
        Return a JSON object with:
        "executive_summary": A one paragraph summary of the incident.
        "recommendations": A list of 3 actionable remediation steps (strings).
        Return ONLY valid JSON.
        """
        
        await self._log_action(db, case.id, "Synthesizing final report.", "Calling LLM for report generation.", context, None)
        
        response_text = await llm_service.generate(prompt, json.dumps(context), json_format=True)
        try:
            result = json.loads(response_text)
        except Exception:
            result = {"executive_summary": "Error generating summary.", "recommendations": []}
            
        await self._log_action(db, case.id, "Report generation complete.", "Generated final SOC report.", None, result)
        return result
