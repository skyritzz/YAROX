from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase, Severity
from agents.base import BaseAgent
from agents.evidence import evidence_for_prompt, FINDINGS_FORMAT_INSTRUCTION, PROMPT_EVIDENCE_MAX_CHARS
from core.utils import sanitize_evidence, build_sandboxed_agent_prompt
from schemas.agent_outputs import TriageLLMOutput

SEVERITY_RANK = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

class TriageAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Triage Analyst",
            role="First responder",
            goal="Analyze initial detection, assess severity, and provide a summary."
        )

    async def analyze(self, db: AsyncSession, case: InvestigationCase, evidence: list, memory_context=None) -> dict:
        execution = await self.start_execution(db, case.id)
        allowed_ids = {str(e.id) for e in evidence}
        deterministic_severity = case.severity.value if case.severity else "MEDIUM"

        try:
            # Observation
            await self.emit_step(db, execution, "observation_started", {
                "text": f"Reviewing {len(evidence)} pieces of evidence for case: {case.title}",
                "evidence_count": len(evidence)
            }, evidence_ids=sorted(allowed_ids))

            evidence_block = sanitize_evidence(evidence_for_prompt(evidence), max_length=PROMPT_EVIDENCE_MAX_CHARS)

            role_desc = "You are a Triage Analyst evaluating security telemetry."
            task_desc = f"Case Title: {case.title}\nInitial Rule Description: {case.description or ''}\nEvaluate the provided security evidence."
            format_desc = f"""Return a JSON object with:
"severity": ("LOW", "MEDIUM", "HIGH", "CRITICAL")
"summary": A concise factual summary of the incident (max 3 sentences).
"priority_score": A float between 0.0 and 1.0 indicating urgency.
{FINDINGS_FORMAT_INSTRUCTION}
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

            result = await self.generate_structured(execution, full_prompt, TriageLLMOutput)

            # Priority 7: Deterministic Security Guardrails
            proposed_severity = str(result.severity).upper()
            if proposed_severity not in SEVERITY_RANK:
                proposed_severity = "MEDIUM"

            priority_score = None if result.priority_score is None else max(0.0, min(1.0, float(result.priority_score)))

            # Guardrail: the deterministic rule severity is a floor the LLM cannot lower
            guardrail = None
            if SEVERITY_RANK[proposed_severity] < SEVERITY_RANK.get(deterministic_severity, 2):
                guardrail = f"Prevented downgrade from deterministic {deterministic_severity} to {proposed_severity}"
                proposed_severity = deterministic_severity

            summary = result.summary

            await self.emit_step(db, execution, "reasoning_complete", {
                "text": "Triage analysis complete with guardrails verified.",
                "raw": result.model_dump(mode="json")
            })

            findings = await self.record_findings(
                db, execution, case.id, [f.model_dump(mode="json") for f in result.findings], allowed_ids
            )

            triage = {
                "status": "completed",
                "execution_id": str(execution.id),
                "severity": proposed_severity,
                "proposed_severity": str(result.severity).upper() or None,
                "summary": summary,
                "priority_score": priority_score,
                "guardrail_applied": guardrail,
                "findings": findings,
            }

            # Decision
            await self.emit_step(db, execution, "decision_made", {
                "text": f"Assigned severity: {proposed_severity}. Priority: {priority_score}",
                "severity": proposed_severity,
                "guardrail_applied": guardrail,
            }, evidence_ids=sorted({eid for f in findings for eid in f["evidence_ids"]}))

            # Handoff
            await self.emit_step(db, execution, "handoff", {
                "text": "Passing initial triage context to SOC Lead.",
                "next_agent": "SOC Lead"
            })

            await self.finish_execution(db, execution, status="completed")
            return triage

        except Exception as e:
            await self.emit_step(db, execution, "step_failed", {
                "text": f"Error during analysis: {str(e)}. No triage assessment produced; rule severity {deterministic_severity} stands.",
                "error": str(e)
            })

            await self.emit_step(db, execution, "handoff", {
                "text": "Passing degraded triage context to SOC Lead.",
                "next_agent": "SOC Lead"
            })

            await self.finish_execution(db, execution, status="degraded")
            return {
                "status": "degraded",
                "execution_id": str(execution.id),
                "error": str(e),
                "severity": deterministic_severity,
                "proposed_severity": None,
                "summary": None,
                "priority_score": None,
                "guardrail_applied": None,
                "findings": [],
            }
