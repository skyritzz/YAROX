from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase, Severity
from agents.base import BaseAgent
from services.llm_service import llm_service
from core.utils import sanitize_evidence, build_sandboxed_agent_prompt
import json

class TriageAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Triage Analyst",
            role="First responder",
            goal="Analyze initial detection, assess severity, and provide a summary."
        )

    async def analyze(self, db: AsyncSession, case: InvestigationCase, evidence: list, memory_context=None) -> dict:
        execution = await self.start_execution(db, case.id)
        
        try:
            # Observation
            await self.emit_step(db, execution, "observation_started", {
                "text": f"Reviewing {len(evidence)} pieces of evidence for case: {case.title}",
                "evidence_count": len(evidence)
            })
            
            raw_evidence_list = [
                {"artifact": e.artifact, "type": e.evidence_type, "reason": e.reason, "importance": e.importance_score}
                for e in evidence
            ]
            evidence_block = sanitize_evidence(raw_evidence_list)
            
            role_desc = "You are a Triage Analyst evaluating security telemetry."
            task_desc = f"Case Title: {case.title}\nInitial Rule Description: {case.description or ''}\nEvaluate the provided security evidence."
            format_desc = """Return a JSON object with:
1. "severity": ("LOW", "MEDIUM", "HIGH", "CRITICAL")
2. "summary": A concise factual summary of the incident (max 3 sentences).
3. "priority_score": A float between 0.0 and 1.0 indicating urgency.
Return ONLY valid JSON."""

            full_prompt = build_sandboxed_agent_prompt(
                role_instruction=role_desc,
                task_instruction=task_desc,
                evidence_block=evidence_block,
                output_format_instruction=format_desc
            )
            
            # Reasoning
            await self.emit_step(db, execution, "reasoning_started", {
                "text": "Analyzing detection severity and formulating summary within sandboxed boundary."
            })
            
            response_text = await self.call_llm_with_timeout(
                llm_service.generate(full_prompt, "", json_format=True), 
                timeout_seconds=120,
                execution=execution
            )
            
            try:
                result = json.loads(response_text)
            except Exception:
                raise Exception("LLM failed to return valid JSON.")

            # Priority 7: Deterministic Security Guardrails
            proposed_severity = str(result.get("severity", "MEDIUM")).upper()
            if proposed_severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                proposed_severity = "MEDIUM"
                
            priority_score = float(result.get("priority_score", 0.5))
            priority_score = max(0.0, min(1.0, priority_score))
            
            # Guardrail: Prevent silent downgrade if a rule established CRITICAL / HIGH
            deterministic_severity = case.severity.value if case.severity else "MEDIUM"
            if deterministic_severity in ("CRITICAL", "HIGH") and proposed_severity == "LOW":
                # Enforce floor to prevent prompt-injection evasion
                proposed_severity = "MEDIUM"
                priority_score = max(priority_score, 0.6)
                result["guardrail_applied"] = "Prevented downgrade from deterministic high-severity trigger"

            result["severity"] = proposed_severity
            result["priority_score"] = priority_score

            await self.emit_step(db, execution, "reasoning_complete", {
                "text": "Triage analysis complete with guardrails verified.",
                "raw": result
            })
                
            # Decision
            await self.emit_step(db, execution, "decision_made", {
                "text": f"Assigned severity: {result.get('severity')}. Priority: {result.get('priority_score')}",
                "severity": result.get("severity")
            })
            
            # Handoff
            await self.emit_step(db, execution, "handoff", {
                "text": "Passing initial triage context to Timeline Agent for temporal reconstruction.",
                "next_agent": "Timeline Agent"
            })
            
            await self.finish_execution(db, execution, status="completed", confidence=result.get("priority_score"))
            return result
            
        except Exception as e:
            fallback_severity = case.severity.value if case.severity else "HIGH"
            fallback_result = {
                "severity": fallback_severity, 
                "summary": f"Triage fallback applied: {case.title}.", 
                "priority_score": 0.8 if fallback_severity in ("CRITICAL", "HIGH") else 0.5
            }
            
            await self.emit_step(db, execution, "step_failed", {
                "text": f"Error during analysis: {str(e)}. Degraded to rule-based fallback.",
                "error": str(e)
            })
            
            await self.emit_step(db, execution, "handoff", {
                "text": "Passing degraded triage context to Timeline Agent.",
                "next_agent": "Timeline Agent"
            })
            
            await self.finish_execution(db, execution, status="degraded", confidence=0.5)
            return fallback_result
