from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from models.investigation import InvestigationCase
from models.mitre import AttackTechnique
from agents.base import BaseAgent
from agents.evidence import (
    evidence_for_prompt,
    validate_cited_entries,
    FINDINGS_FORMAT_INSTRUCTION,
    PROMPT_EVIDENCE_MAX_CHARS,
)
from services.llm_service import llm_service
from memory.service import memory_service
from schemas.memory import InvestigationFingerprint
from security.mitre.knowledge_base import mitre_kb
from core.utils import sanitize_evidence, build_sandboxed_agent_prompt
import json
import hashlib

class ThreatIntelAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Threat Intel Analyst",
            role="MITRE ATT&CK Mapper",
            goal="Map attacker behavior to known techniques and search historical incidents."
        )

    async def analyze(self, db: AsyncSession, case: InvestigationCase, evidence: list, memory_context=None) -> dict:
        execution = await self.start_execution(db, case.id)
        allowed_ids = {str(e.id) for e in evidence}

        try:
            # Observation
            await self.emit_step(db, execution, "observation_started", {
                "text": "Reviewing evidence and timeline to identify adversary techniques."
            }, evidence_ids=sorted(allowed_ids))

            ips, domains, hashes = set(), set(), set()
            for ev in evidence:
                if ev.evidence_type == 'ip': ips.add(ev.artifact)
                elif ev.evidence_type == 'domain': domains.add(ev.artifact)
                elif ev.evidence_type == 'hash': hashes.add(ev.artifact)

            ioc_str = "".join(sorted(list(ips) + list(domains) + list(hashes)))
            mitre_techs = [mt.technique_id for mt in case.mitre_techniques] if case.mitre_techniques else []

            fingerprint = InvestigationFingerprint(
                attack_type=None,
                mitre_techniques=mitre_techs,
                campaign=None,
                risk_score=case.confidence_score or 0.0,
                ioc_hash=hashlib.sha256(ioc_str.encode()).hexdigest(),
                timeline_hash=""
            )

            summary_str = f"{case.title} {case.description or ''}"

            async def _memory_search():
                await memory_service.initialize()
                return await memory_service.find_similar_cases(db, fingerprint, summary_str, limit=3)

            similar_cases = await self.run_tool(
                db, execution, "memory_search",
                tool_input={
                    "collection": memory_service.vector_repo.collection_name,
                    "limit": 3,
                    "mitre_technique_count": len(mitre_techs),
                    "ioc_count": len(ips) + len(domains) + len(hashes),
                },
                operation=_memory_search,
                summarize_output=lambda results: {
                    "result_count": len(results),
                    "investigation_ids": [r.investigation_id for r in results],
                    "top_similarity": round(results[0].similarity_score, 4) if results else None,
                },
            )

            evidence_block = sanitize_evidence(evidence_for_prompt(evidence), max_length=PROMPT_EVIDENCE_MAX_CHARS)

            similar_summaries = []
            for sc in similar_cases:
                if sc.knowledge_object:
                    similar_summaries.append({
                        "case_id": sc.investigation_id,
                        "title": sc.knowledge_object.investigation.title,
                        "summary": sc.knowledge_object.investigation.summary,
                        "similarity_score": round(sc.similarity_score, 2)
                    })

            role_desc = "You are a Threat Intel Analyst mapping evidence to the MITRE ATT&CK framework."
            task_desc = f"Case: {case.title}\nDescription: {case.description or ''}\nHistorical Matches: {json.dumps(similar_summaries)}"
            format_desc = f"""Return a JSON object with:
"mitre_mapping": A list of objects, each with:
  - "technique_id": The most specific standard MITRE Technique or Sub-technique ID supported by the evidence (e.g. "T1059.001", "T1110", "T1021", "T1068")
  - "technique_name": Standard MITRE Technique name
  - "tactic": Standard MITRE Tactic
  - "reason": Factual rationale from evidence
  - "evidence_ids": List of evidence_id values supporting the mapping (at least one)
"historical_insight": A factual statement comparing this to the historical matches listed in the task, or null if there are none.
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
                "text": "Correlating behavior with MITRE ATT&CK framework within sandboxed boundary."
            })

            response_text = await self.call_llm_with_timeout(
                llm_service.generate(full_prompt, "", json_format=True),
                timeout_seconds=120,
                execution=execution
            )

            try:
                result = json.loads(response_text)
            except Exception:
                raise Exception("LLM failed to return valid JSON MITRE mapping.")
            if not isinstance(result, dict):
                raise Exception("LLM MITRE mapping output is not a JSON object.")

            cited_mappings, rejected_mappings = validate_cited_entries(result.get("mitre_mapping", []), allowed_ids, "technique_id")

            # Deterministic MITRE validation
            validated_mappings = []
            for mapping in cited_mappings:
                t_id = mapping.get("technique_id")
                reason = mapping.get("reason", "Mapped by Threat Intel AI")
                valid_info = mitre_kb.validate(t_id)
                if not valid_info:
                    # A well-formed sub-technique missing from the local knowledge base is recorded
                    # at its parent technique, and the substitution is stated in the stored reason.
                    normalized = mitre_kb.normalize_id(t_id)
                    parent = mitre_kb.parent_id(normalized) if normalized else None
                    valid_info = mitre_kb.validate(parent) if parent else None
                    if valid_info:
                        reason = (
                            f"{reason} (proposed sub-technique {normalized} is not in the local ATT&CK "
                            f"knowledge base; recorded at parent technique {parent})"
                        )
                if valid_info:
                    validated_mappings.append({
                        "technique_id": valid_info["technique_id"],
                        "technique_name": valid_info["name"],
                        "tactic": valid_info["tactic"],
                        "reason": reason,
                        "evidence_ids": mapping["evidence_ids"],
                    })
                else:
                    rejected_mappings.append({"reason": f"unknown MITRE technique '{t_id}'", "submitted": mapping})

            await self.emit_step(db, execution, "reasoning_complete", {
                "text": f"Mapped {len(validated_mappings)} evidence-backed techniques; rejected {len(rejected_mappings)}.",
                "raw": result,
                "rejected_mappings": rejected_mappings,
            }, evidence_ids=sorted({eid for m in validated_mappings for eid in m["evidence_ids"]}))

            similar_case_ids = [sc.investigation_id for sc in similar_cases if sc.investigation_id != str(case.id)]

            for mapping in validated_mappings:
                tech_id = mapping.get("technique_id")
                existing = await db.execute(
                    select(AttackTechnique).where(
                        AttackTechnique.case_id == case.id,
                        AttackTechnique.technique_id == tech_id
                    )
                )
                if not existing.scalars().first():
                    db.add(AttackTechnique(
                        case_id=case.id,
                        technique_id=tech_id,
                        technique_name=mapping.get("technique_name"),
                        tactic=mapping.get("tactic"),
                        confidence=0.9,
                        reason=mapping.get("reason")
                    ))
            await db.commit()

            findings = await self.record_findings(db, execution, case.id, result.get("findings"), allowed_ids)

            # Historical insight is only reported when memory actually returned matches
            historical_insight = result.get("historical_insight") if similar_summaries and isinstance(result.get("historical_insight"), str) else None
            memory_statement = historical_insight or (
                "No similar cases were returned by the memory search." if not similar_cases else None
            )

            # Decision
            await self.emit_step(db, execution, "decision_made", {
                "text": memory_statement or "Historical matches returned, but no insight was produced.",
                "historical_insight": historical_insight,
                "similar_case_ids": similar_case_ids,
            })

            # Handoff
            await self.emit_step(db, execution, "handoff", {
                "text": "Passing mappings and historical context to SOC Lead Agent.",
                "next_agent": "SOC Lead"
            })

            await self.finish_execution(db, execution, status="completed")
            return {
                "status": "completed",
                "execution_id": str(execution.id),
                "mitre_mapping": validated_mappings,
                "historical_insight": historical_insight,
                "similar_case_ids": similar_case_ids,
                "findings": findings,
            }

        except Exception as e:
            await self.emit_step(db, execution, "step_failed", {
                "text": f"Error during threat intelligence mapping: {str(e)}. No mapping or historical comparison produced.",
                "error": str(e)
            })

            await self.emit_step(db, execution, "handoff", {
                "text": "Passing degraded threat intel context to SOC Lead Agent.",
                "next_agent": "SOC Lead"
            })

            await self.finish_execution(db, execution, status="degraded")
            return {
                "status": "degraded",
                "execution_id": str(execution.id),
                "error": str(e),
                "mitre_mapping": [],
                "historical_insight": None,
                "similar_case_ids": [],
                "findings": [],
            }
