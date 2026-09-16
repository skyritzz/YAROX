from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase
from agents.base import BaseAgent
from agents.evidence import (
    evidence_for_prompt,
    validate_cited_entries,
    FINDINGS_FORMAT_INSTRUCTION,
    PROMPT_EVIDENCE_MAX_CHARS,
)
from services.llm_service import llm_service
from core.utils import sanitize_evidence, build_sandboxed_agent_prompt
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
        allowed_ids = {str(e.id) for e in evidence}

        try:
            # Observation
            await self.emit_step(db, execution, "observation_started", {
                "text": "Reviewing findings from Triage, Timeline, and Threat Intel agents."
            }, evidence_ids=sorted(allowed_ids))

            upstream_findings = [
                {k: f[k] for k in ("finding_id", "agent", "finding", "kind", "evidence_ids")}
                for data in (triage_data, timeline_data, threat_data)
                for f in data.get("findings", [])
            ]
            structured_context = {
                "case_title": case.title,
                "case_description": case.description,
                "agent_status": {
                    "triage": triage_data.get("status"),
                    "timeline": timeline_data.get("status"),
                    "threat_intel": threat_data.get("status"),
                },
                "triage_severity": triage_data.get("severity"),
                "triage_summary": triage_data.get("summary"),
                "timeline": timeline_data.get("timeline", []),
                "mitre_techniques": [
                    {"technique_id": m.get("technique_id"), "technique_name": m.get("technique_name"), "evidence_ids": m.get("evidence_ids")}
                    for m in threat_data.get("mitre_mapping", [])
                ],
                "historical_insight": threat_data.get("historical_insight"),
                "agent_findings": upstream_findings,
                "evidence": evidence_for_prompt(evidence),
            }

            evidence_block = sanitize_evidence(structured_context, max_length=PROMPT_EVIDENCE_MAX_CHARS)

            role_desc = "You are the SOC Lead responsible for synthesizing agent investigation findings into an executive incident report."
            task_desc = (
                "Synthesize the provided findings into an executive summary and actionable, defensive recommendations. "
                "Where agents were degraded, state that their analysis is unavailable rather than filling the gap."
            )
            format_desc = f"""Return a JSON object with:
"executive_summary": A one-paragraph executive summary distinguishing verified observations from hypotheses.
"recommendations": A list of specific, actionable defensive remediation steps, each an object with:
  - "action": The remediation step
  - "rationale": Why the evidence warrants it
  - "evidence_ids": List of evidence_id values that justify the action (at least one)
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
                "text": "Drafting executive summary and formulating remediation recommendations within sandboxed boundary."
            })

            response_text = await self.call_llm_with_timeout(
                llm_service.generate(full_prompt, "", json_format=True),
                timeout_seconds=120,
                execution=execution
            )

            try:
                result = json.loads(response_text)
            except Exception:
                raise Exception("LLM failed to return valid JSON report.")
            summary = result.get("executive_summary") if isinstance(result, dict) else None
            if not isinstance(summary, str) or not summary.strip():
                raise Exception("Invalid report JSON structure: missing executive_summary.")

            recommendations, rejected_recommendations = validate_cited_entries(result.get("recommendations"), allowed_ids, "action")

            await self.emit_step(db, execution, "reasoning_complete", {
                "text": f"Report drafted with {len(recommendations)} evidence-backed recommendations; rejected {len(rejected_recommendations)}.",
                "raw": result,
                "rejected_recommendations": rejected_recommendations,
            }, evidence_ids=sorted({eid for r in recommendations for eid in r["evidence_ids"]}))

            findings = await self.record_findings(db, execution, case.id, result.get("findings"), allowed_ids)

            # Decision
            await self.emit_step(db, execution, "decision_made", {
                "text": "Finalized executive summary and recommended actions.",
                "executive_summary": summary.strip()
            })

            # Handoff
            await self.emit_step(db, execution, "handoff", {
                "text": "Investigation complete. Report ready for human review.",
                "next_agent": None
            })

            await self.finish_execution(db, execution, status="completed")
            return {
                "status": "completed",
                "execution_id": str(execution.id),
                "executive_summary": summary.strip(),
                "recommendations": [
                    {"action": r["action"], "rationale": r.get("rationale"), "evidence_ids": r["evidence_ids"]}
                    for r in recommendations
                ],
                "findings": findings,
            }

        except Exception as e:
            await self.emit_step(db, execution, "step_failed", {
                "text": f"Error during report generation: {str(e)}. No executive summary or recommendations were produced; manual review required.",
                "error": str(e)
            })

            await self.emit_step(db, execution, "handoff", {
                "text": "Investigation completed with degraded status. Manual review required.",
                "next_agent": None
            })

            await self.finish_execution(db, execution, status="degraded")
            return {
                "status": "degraded",
                "error": str(e),
                "execution_id": str(execution.id),
                "executive_summary": None,
                "recommendations": [],
                "findings": [],
            }
