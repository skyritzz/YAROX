from sqlalchemy.ext.asyncio import AsyncSession
from models.investigation import InvestigationCase
from models.mitre import AttackTechnique
from agents.base import BaseAgent
from services.llm_service import llm_service
from services.memory_service import memory_service
import json

class ThreatIntelAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Threat Intel Analyst",
            role="MITRE ATT&CK Mapper",
            goal="Map attacker behavior to known techniques and search historical incidents."
        )

    async def analyze(self, db: AsyncSession, case: InvestigationCase, evidence: list) -> dict:
        pattern = f"{case.title} - {case.description}"
        similar_cases = await memory_service.similar_cases(pattern)
        
        context = {
            "evidence": [{"artifact": e.artifact, "type": e.evidence_type} for e in evidence],
            "similar_past_cases": similar_cases
        }
        
        prompt = """
        You are a Threat Intel Analyst. Map the provided evidence to MITRE ATT&CK techniques.
        Consider similar past cases if provided.
        Return a JSON object with:
        "mitre_mapping": A list of objects, each with "technique_id", "technique_name", "tactic", and "reason".
        "historical_insight": A brief sentence comparing this to similar cases (if any).
        Return ONLY valid JSON.
        """
        
        await self._log_action(db, case.id, "Searching memory and mapping MITRE techniques.", "Calling LLM for threat intel.", context, None)
        
        response_text = await llm_service.generate(prompt, json.dumps(context), json_format=True)
        try:
            result = json.loads(response_text)
            from security.mitre.knowledge_base import mitre_kb
            
            validated_mappings = []
            for mapping in result.get("mitre_mapping", []):
                t_id = mapping.get("technique_id")
                valid_info = mitre_kb.validate(t_id)
                if valid_info:
                    # Use official names and tactics
                    validated_mappings.append({
                        "technique_id": valid_info["technique_id"],
                        "technique_name": valid_info["name"],
                        "tactic": valid_info["tactic"],
                        "reason": mapping.get("reason", "Mapped by Threat Intel AI")
                    })
                    
            result["mitre_mapping"] = validated_mappings
            
            # Extract case IDs from the memory search context, excluding the current case
            case_ids = [c.get("case_id") for c in similar_cases if c.get("case_id") and c.get("case_id") != str(case.id)]
            result["similar_case_ids"] = list(set(case_ids))
            
            for mapping in result.get("mitre_mapping", []):
                db.add(AttackTechnique(
                    case_id=case.id,
                    technique_id=mapping.get("technique_id"),
                    technique_name=mapping.get("technique_name"),
                    tactic=mapping.get("tactic"),
                    confidence=0.9,
                    reason=mapping.get("reason")
                ))
            await db.commit()
            
        except Exception:
            result = {"mitre_mapping": [], "historical_insight": "Failed to map."}
            
        await self._log_action(db, case.id, "Threat Intel complete.", "Generated MITRE mappings.", None, result)
        return result
