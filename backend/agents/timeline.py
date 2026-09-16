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

class TimelineAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Forensic Timeline Analyst",
            role="Incident reconstructor",
            goal="Build a chronological timeline of the attack from the evidence."
        )

    async def analyze(self, db: AsyncSession, case: InvestigationCase, evidence: list, memory_context=None) -> dict:
        execution = await self.start_execution(db, case.id)
        allowed_ids = {str(e.id) for e in evidence}

        try:
            # Observation
            await self.emit_step(db, execution, "observation_started", {
                "text": f"Analyzing {len(evidence)} artifacts to construct sequence of events."
            }, evidence_ids=sorted(allowed_ids))

            evidence_block = sanitize_evidence(evidence_for_prompt(evidence), max_length=PROMPT_EVIDENCE_MAX_CHARS)

            role_desc = "You are a Forensic Timeline Analyst reconstructing an incident chronology."
            task_desc = f"Case: {case.title}\nReconstruct the chronological timeline strictly from verified evidence."
            format_desc = f"""Return a JSON object with:
"timeline": A list of chronological objects, each with:
  - "time": ISO timestamp taken from the cited evidence
  - "action": What action occurred
  - "details": Specific factual details from evidence
  - "evidence_ids": List of evidence_id values the entry is based on (at least one)
{FINDINGS_FORMAT_INSTRUCTION}
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
            except Exception:
                raise Exception("LLM failed to return valid JSON timeline.")
            if not isinstance(result, dict) or not isinstance(result.get("timeline"), list):
                raise Exception("Invalid timeline JSON structure.")

            timeline, rejected_entries = validate_cited_entries(result["timeline"], allowed_ids, "action")
            if evidence and not timeline:
                raise Exception(
                    f"No timeline entry cited evidence from this investigation ({len(rejected_entries)} rejected)."
                )

            await self.emit_step(db, execution, "reasoning_complete", {
                "text": f"Timeline reconstructed with {len(timeline)} evidence-backed events; rejected {len(rejected_entries)}.",
                "raw": result,
                "rejected_timeline_entries": rejected_entries,
            }, evidence_ids=sorted({eid for t in timeline for eid in t["evidence_ids"]}))

            findings = await self.record_findings(db, execution, case.id, result.get("findings"), allowed_ids)

            # Decision
            await self.emit_step(db, execution, "decision_made", {
                "text": "Finalized attack story timeline.",
                "timeline_count": len(timeline)
            })

            # Handoff
            await self.emit_step(db, execution, "handoff", {
                "text": "Passing timeline to SOC Lead.",
                "next_agent": "SOC Lead"
            })

            await self.finish_execution(db, execution, status="completed")
            return {"status": "completed", "execution_id": str(execution.id), "timeline": timeline, "findings": findings}

        except Exception as e:
            await self.emit_step(db, execution, "step_failed", {
                "text": f"Error during timeline generation: {str(e)}. No agent timeline produced.",
                "error": str(e)
            })

            await self.emit_step(db, execution, "handoff", {
                "text": "Passing degraded timeline context to SOC Lead.",
                "next_agent": "SOC Lead"
            })

            await self.finish_execution(db, execution, status="degraded")
            return {"status": "degraded", "execution_id": str(execution.id), "error": str(e), "timeline": [], "findings": []}
