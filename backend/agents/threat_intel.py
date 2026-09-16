from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase
from models.mitre import AttackTechnique
from agents.base import BaseAgent
from services.llm_service import llm_service
from memory.service import memory_service
from schemas.memory import InvestigationFingerprint
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
        
        try:
            # Observation
            await self.emit_step(db, execution, "observation_started", {
                "text": "Reviewing evidence and timeline to identify adversary techniques."
            })
            
            # Tool call: memory search using authoritative memory service
            await self.emit_step(db, execution, "tool_call_started", {
                "text": "Searching Qdrant for similar historical patterns using hybrid search.",
                "tool": "memory_search"
            })
            
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
            await memory_service.initialize()
            similar_cases = await memory_service.find_similar_cases(db, fingerprint, summary_str, limit=3)
            
            await self.emit_step(db, execution, "tool_call_complete", {
                "text": f"Found {len(similar_cases)} verified historical cases in memory.",
                "tool": "memory_search"
            })
            
            raw_evidence = [{"artifact": e.artifact, "type": e.evidence_type, "reason": e.reason} for e in evidence]
            evidence_block = sanitize_evidence(raw_evidence)
            
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
            format_desc = """Return a JSON object with:
"mitre_mapping": A list of objects, each with:
  - "technique_id": The standard MITRE Technique ID (e.g. "T1059", "T1110", "T1021", "T1068")
  - "technique_name": Standard MITRE Technique name
  - "tactic": Standard MITRE Tactic
  - "reason": Factual rationale from evidence
"historical_insight": A factual statement comparing this to verified historical cases (or state "No prior matching incidents in verified investigation memory." if none matched).
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
                timeout_seconds=120
            )
            
            try:
                result = json.loads(response_text)
                await self.emit_step(db, execution, "reasoning_complete", {
                    "text": f"Mapped {len(result.get('mitre_mapping', []))} techniques.",
                    "raw": result
                })
            except Exception:
                raise Exception("LLM failed to return valid JSON MITRE mapping.")
                
            # Deterministic MITRE validation
            from security.mitre.knowledge_base import mitre_kb
            validated_mappings = []
            for mapping in result.get("mitre_mapping", []):
                t_id = mapping.get("technique_id")
                valid_info = mitre_kb.validate(t_id) if t_id else None
                if valid_info:
                    validated_mappings.append({
                        "technique_id": valid_info["technique_id"],
                        "technique_name": valid_info["name"],
                        "tactic": valid_info["tactic"],
                        "reason": mapping.get("reason", "Mapped by Threat Intel AI")
                    })
                    
            result["mitre_mapping"] = validated_mappings
            result["similar_case_ids"] = [sc.investigation_id for sc in similar_cases if sc.investigation_id != str(case.id)]
            
            from sqlalchemy.future import select
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
            
            # Truthful historical insight
            if not similar_cases and not result.get("historical_insight"):
                result["historical_insight"] = "No prior matching incidents in verified investigation memory."
            
            # Decision
            await self.emit_step(db, execution, "decision_made", {
                "text": result.get("historical_insight", "No historical insight available."),
                "historical_insight": result.get("historical_insight")
            })
            
            # Handoff
            await self.emit_step(db, execution, "handoff", {
                "text": "Passing mappings and historical context to SOC Lead Agent.",
                "next_agent": "SOC Lead"
            })
            
            await self.finish_execution(db, execution, status="completed", confidence=0.85)
            return result
            
        except Exception as e:
            fallback_result = {
                "mitre_mapping": [],
                "historical_insight": "No prior matching incidents in verified investigation memory.",
                "similar_case_ids": []
            }
            
            await self.emit_step(db, execution, "step_failed", {
                "text": f"Error during threat intelligence mapping: {str(e)}. Degraded to empty mapping.",
                "error": str(e)
            })
            
            await self.emit_step(db, execution, "handoff", {
                "text": "Passing degraded threat intel context to SOC Lead Agent.",
                "next_agent": "SOC Lead"
            })
            
            await self.finish_execution(db, execution, status="degraded", confidence=0.5)
            return fallback_result
