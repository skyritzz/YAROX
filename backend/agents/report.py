from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase
from agents.base import BaseAgent
from services.llm_service import llm_service
from core.utils import sanitize_evidence, build_sandboxed_agent_prompt
from websocket.investigation_ws import manager as ws_manager
import json

class ReportAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="SOC Lead",
            role="Report Generator",
            goal="Synthesize all findings into a final investigation report."
        )

    async def analyze(self, db: AsyncSession, case: InvestigationCase, evidence: list, triage_data: dict, timeline_data: dict, threat_data: dict) -> dict:
        execution = await self.start_execution(db, case.id)
        
        try:
            # Observation
            await self.emit_step(db, execution, "observation_started", {
                "text": "Reviewing findings from Triage, Timeline, and Threat Intel agents."
            })
            
            structured_context = {
                "case_title": case.title,
                "case_description": case.description,
                "triage_summary": triage_data.get("summary", ""),
                "triage_severity": triage_data.get("severity", "MEDIUM"),
                "timeline_events_count": len(timeline_data.get("timeline", [])),
                "mitre_techniques": [m.get("technique_name") for m in threat_data.get("mitre_mapping", [])],
                "historical_insight": threat_data.get("historical_insight", "")
            }
            
            evidence_block = sanitize_evidence(structured_context)
            
            role_desc = "You are the SOC Lead responsible for synthesizing agent investigation findings into an executive incident report."
            task_desc = "Synthesize the provided findings into an executive summary and actionable, defensive recommendations."
            format_desc = """Return a JSON object with:
"executive_summary": A one-paragraph executive summary of the verified facts.
"recommendations": A list of exactly 3 specific, actionable defensive remediation steps (strings).
Return ONLY valid JSON."""

            full_prompt = build_sandboxed_agent_prompt(
                role_instruction=role_desc,
                task_instruction=task_desc,
                evidence_block=evidence_block,
                output_format_instruction=format_desc
            )
            
            # Reasoning
            await self.emit_step(db, execution, "reasoning_started", {
                "text": "Drafting executive summary and formulating remediation recommendations within sandboxed boundary."
            })
            
            response_text = await self.call_llm_with_timeout(
                llm_service.generate(full_prompt, "", json_format=True),
                timeout_seconds=120
            )
            
            try:
                result = json.loads(response_text)
                if not isinstance(result, dict) or "executive_summary" not in result:
                    raise Exception("Invalid report JSON structure.")
                    
                await self.emit_step(db, execution, "reasoning_complete", {
                    "text": "Report drafted successfully.",
                    "raw": result
                })
            except Exception:
                raise Exception("LLM failed to return valid JSON report.")
                
            # Decision
            await self.emit_step(db, execution, "decision_made", {
                "text": "Finalized executive summary and recommended actions.",
                "executive_summary": result.get("executive_summary")
            })
            
            # Handoff
            await self.emit_step(db, execution, "handoff", {
                "text": "Investigation complete. Report ready for human review.",
                "next_agent": None
            })
            
            await self.finish_execution(db, execution, status="completed", confidence=0.95)
            
            # Broadcast REPORT_READY to scoped case and global listeners
            await ws_manager.broadcast({
                "case_id": str(case.id),
                "investigation_id": str(case.id),
                "event": "REPORT_READY",
                "event_type": "REPORT_READY"
            })
            
            return result
            
        except Exception as e:
            fallback_result = {
                "executive_summary": f"Incident '{case.title}' analyzed. Manual SOC review recommended.", 
                "recommendations": [
                    "Isolate affected hosts if unauthorized activity is confirmed",
                    "Rotate credentials for compromised user accounts",
                    "Review endpoint telemetry for lateral movement"
                ]
            }
            
            await self.emit_step(db, execution, "step_failed", {
                "text": f"Error during report generation: {str(e)}. Degraded to structured fallback report.",
                "error": str(e)
            })
            
            await self.emit_step(db, execution, "handoff", {
                "text": "Investigation completed with degraded status. Manual review required.",
                "next_agent": None
            })
            
            await self.finish_execution(db, execution, status="degraded", confidence=0.5)
            
            await ws_manager.broadcast({
                "case_id": str(case.id),
                "investigation_id": str(case.id),
                "event": "REPORT_READY",
                "event_type": "REPORT_READY"
            })
            
            return fallback_result
