"""
Deterministic LLM test double.

It does not fabricate evidence: it reads the evidence IDs that the real agents placed
in the real prompt and cites those, so tests prove that evidence IDs actually reach the
model and that the persistence/trace chain works. It says nothing about LLM quality;
live-LLM verification is done separately.
"""
import json
import re
from typing import Callable, Dict, Optional

EVIDENCE_ID_PATTERN = re.compile(r'"evidence_id":\s*"([0-9a-f\-]{36})"')

AGENT_MARKERS = {
    "triage": "You are a Triage Analyst",
    "timeline": "You are a Forensic Timeline Analyst",
    "threat_intel": "You are a Threat Intel Analyst",
    "soc_lead": "You are the SOC Lead",
}


def agent_for_prompt(prompt: str) -> Optional[str]:
    for agent, marker in AGENT_MARKERS.items():
        if marker in prompt:
            return agent
    return None


def evidence_ids_in_prompt(prompt: str):
    seen = []
    for match in EVIDENCE_ID_PATTERN.findall(prompt):
        if match not in seen:
            seen.append(match)
    return seen


def default_response(agent: str, ids, fabricated_id: str) -> Dict:
    first = ids[:1]
    if agent == "triage":
        return {
            "severity": "HIGH",
            "summary": "Encoded PowerShell executed on FINANCE-PC-04 by asmith.",
            "priority_score": 0.9,
            "findings": [
                {"finding": "Encoded PowerShell command executed", "kind": "observation", "evidence_ids": first,
                 "reasoning_summary": "Command line contains -enc.", "mitre_techniques": ["T1059.001"], "confidence": 0.9},
                {"finding": "Attacker also accessed DC-01", "kind": "observation", "evidence_ids": [fabricated_id],
                 "reasoning_summary": "Fabricated citation that must be rejected.", "mitre_techniques": [], "confidence": 0.9},
            ],
        }
    if agent == "timeline":
        return {
            "timeline": [{"time": "2026-09-17T10:01:00Z", "action": "Encoded PowerShell execution", "details": "powershell.exe -enc", "evidence_ids": first}],
            "findings": [{"finding": "Execution occurred at 10:01 UTC", "kind": "observation", "evidence_ids": first,
                          "reasoning_summary": "Evidence timestamp.", "mitre_techniques": [], "confidence": 0.95}],
        }
    if agent == "threat_intel":
        return {
            "mitre_mapping": [{"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution",
                               "reason": "Encoded PowerShell", "evidence_ids": first}],
            "historical_insight": None,
            "findings": [{"finding": "Obfuscation suggests intent to evade detection", "kind": "hypothesis", "evidence_ids": first,
                          "reasoning_summary": "Base64 encoded command.", "mitre_techniques": ["T1027"], "confidence": 0.6}],
        }
    if agent == "soc_lead":
        return {
            "executive_summary": "Verified: encoded PowerShell executed on FINANCE-PC-04. Hypothesis: obfuscation to evade detection.",
            "recommendations": [
                {"action": "Isolate FINANCE-PC-04 pending forensic review", "rationale": "Encoded execution observed", "evidence_ids": first},
                {"action": "Block all outbound traffic company-wide", "rationale": "No supporting evidence", "evidence_ids": []},
            ],
            "findings": [{"finding": "Host FINANCE-PC-04 requires containment", "kind": "hypothesis", "evidence_ids": first,
                          "reasoning_summary": "Based on execution evidence.", "mitre_techniques": [], "confidence": 0.7}],
        }
    raise AssertionError(f"Unexpected prompt for agent {agent}")


class EvidenceCitingLLM:
    def __init__(self, overrides: Optional[Dict[str, Callable[[list], str]]] = None):
        self.overrides = overrides or {}
        self.fabricated_id = "00000000-0000-4000-8000-000000000000"
        self.prompts: Dict[str, str] = {}

    async def generate(self, prompt: str, context: str = "", json_format: bool = False) -> str:
        agent = agent_for_prompt(prompt)
        ids = evidence_ids_in_prompt(prompt)
        self.prompts[agent] = prompt
        if agent in self.overrides:
            return self.overrides[agent](ids)
        return json.dumps(default_response(agent, ids, self.fabricated_id))
