"""
Evidence contract enforcement for agent output.

Agents receive evidence with explicit ``evidence_id`` values and must cite them.
Anything an LLM returns is untrusted: citations are checked against the evidence
of the investigation being analyzed before a finding, timeline entry or
recommendation can be persisted.
"""
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from security.mitre.knowledge_base import mitre_kb
from schemas.findings import (
    AgentFindingRecord,
    MAX_FINDING_CHARS,
    MAX_REASONING_CHARS,
    RejectedFinding,
)

VALID_KINDS = ("observation", "hypothesis")


MAX_PROMPT_EVIDENCE_ITEMS = 40
MAX_PROMPT_FIELD_CHARS = 400
# Budget for the sanitized evidence block. Per-field truncation keeps every item's
# evidence_id intact instead of cutting the serialized block mid-item.
PROMPT_EVIDENCE_MAX_CHARS = 20000


def _clip(value: Optional[str]) -> Optional[str]:
    if value is None or len(value) <= MAX_PROMPT_FIELD_CHARS:
        return value
    return value[:MAX_PROMPT_FIELD_CHARS] + "...[TRUNCATED]"


def evidence_for_prompt(evidence: Sequence[Any]) -> Dict[str, Any]:
    """
    Evidence as presented to agents; every item carries the ID agents must cite.
    At most MAX_PROMPT_EVIDENCE_ITEMS items (earliest first) are included, and the
    number omitted is stated explicitly.
    """
    ordered = sorted(evidence, key=lambda e: (e.timestamp is None, e.timestamp))
    included = ordered[:MAX_PROMPT_EVIDENCE_ITEMS]
    return {
        "evidence_items": [
            {
                "evidence_id": str(e.id),
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "type": e.evidence_type,
                "source": e.source,
                "artifact": _clip(e.artifact),
                "reason": _clip(e.reason),
            }
            for e in included
        ],
        "omitted_item_count": len(ordered) - len(included),
    }


FINDINGS_FORMAT_INSTRUCTION = """"findings": A list of evidence-backed findings, each with:
  - "finding": One concise statement (max 1000 characters)
  - "kind": "observation" if directly visible in the cited evidence, otherwise "hypothesis"
  - "evidence_ids": List of evidence_id values from the evidence block that support the finding (at least one)
  - "reasoning_summary": One or two sentences explaining how the evidence supports the finding
  - "mitre_techniques": List of MITRE ATT&CK technique IDs relevant to the finding (may be empty)
  - "confidence": A number between 0 and 1
Only cite evidence_id values that appear in the evidence block. Findings without valid citations are discarded."""


def parse_evidence_ids(value: Any, allowed_ids: Set[str]) -> Tuple[List[uuid.UUID], List[str]]:
    """
    Returns (valid citation UUIDs in order without duplicates, invalid citations).
    ``allowed_ids`` contains the string form of the investigation's EvidenceItem IDs.
    """
    if not isinstance(value, list):
        return [], [repr(value)]
    valid: List[uuid.UUID] = []
    invalid: List[str] = []
    for raw in value:
        text = str(raw).strip().lower() if raw is not None else ""
        if text in allowed_ids:
            candidate = uuid.UUID(text)
            if candidate not in valid:
                valid.append(candidate)
        else:
            invalid.append(str(raw))
    return valid, invalid


def _optional_confidence(value: Any) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if 0.0 <= float(value) <= 1.0 else None


def validate_findings(
    raw_findings: Any,
    agent_name: str,
    allowed_evidence_ids: Iterable[str],
) -> Tuple[List[AgentFindingRecord], List[RejectedFinding]]:
    """
    Validates LLM-proposed findings against the evidence contract.

    A finding is rejected when: it is not an object, its text is empty, it cites no
    evidence, or it cites any evidence ID that does not belong to the investigation
    (a fabricated citation invalidates the whole finding). Unknown MITRE IDs are dropped.
    """
    allowed = {str(i).lower() for i in allowed_evidence_ids}
    accepted: List[AgentFindingRecord] = []
    rejected: List[RejectedFinding] = []

    if raw_findings is None:
        return accepted, rejected
    if not isinstance(raw_findings, list):
        rejected.append(RejectedFinding(agent=agent_name, reason="findings is not a list", submitted={"value": repr(raw_findings)[:200]}))
        return accepted, rejected

    for item in raw_findings:
        if not isinstance(item, dict):
            rejected.append(RejectedFinding(agent=agent_name, reason="finding is not an object", submitted={"value": repr(item)[:200]}))
            continue
        text = item.get("finding")
        if not isinstance(text, str) or not text.strip():
            rejected.append(RejectedFinding(agent=agent_name, reason="empty finding text", submitted=item))
            continue
        evidence_ids, invalid = parse_evidence_ids(item.get("evidence_ids"), allowed)
        if invalid:
            rejected.append(RejectedFinding(agent=agent_name, reason=f"cites evidence not in this investigation: {invalid[:5]}", submitted=item))
            continue
        if not evidence_ids:
            rejected.append(RejectedFinding(agent=agent_name, reason="no evidence cited", submitted=item))
            continue

        kind = item.get("kind") if item.get("kind") in VALID_KINDS else "hypothesis"
        techniques = []
        for tid in item.get("mitre_techniques") or []:
            info = mitre_kb.validate(tid)
            if info and info["technique_id"] not in techniques:
                techniques.append(info["technique_id"])
        reasoning = item.get("reasoning_summary")
        reasoning = reasoning.strip()[:MAX_REASONING_CHARS] if isinstance(reasoning, str) else ""

        accepted.append(AgentFindingRecord(
            finding_id=uuid.uuid4(),
            agent=agent_name,
            finding=text.strip()[:MAX_FINDING_CHARS],
            kind=kind,
            confidence=_optional_confidence(item.get("confidence")),
            evidence_ids=evidence_ids,
            reasoning_summary=reasoning,
            mitre_techniques=techniques,
            timestamp=datetime.now(timezone.utc),
        ))
    return accepted, rejected


def validate_cited_entries(
    raw_entries: Any,
    allowed_evidence_ids: Iterable[str],
    required_text_field: str,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Validates list entries (timeline events, recommendations, MITRE mappings) that must cite
    evidence. Accepted entries get ``evidence_ids`` normalized to string UUIDs.
    """
    allowed = {str(i).lower() for i in allowed_evidence_ids}
    accepted: List[Dict[str, Any]] = []
    rejected: List[Dict[str, Any]] = []
    if not isinstance(raw_entries, list):
        return accepted, ([{"reason": "not a list", "submitted": repr(raw_entries)[:200]}] if raw_entries is not None else [])
    for entry in raw_entries:
        if not isinstance(entry, dict):
            rejected.append({"reason": "entry is not an object", "submitted": repr(entry)[:200]})
            continue
        text = entry.get(required_text_field)
        if not isinstance(text, str) or not text.strip():
            rejected.append({"reason": f"missing '{required_text_field}'", "submitted": entry})
            continue
        evidence_ids, invalid = parse_evidence_ids(entry.get("evidence_ids"), allowed)
        if invalid or not evidence_ids:
            reason = f"cites evidence not in this investigation: {invalid[:5]}" if invalid else "no evidence cited"
            rejected.append({"reason": reason, "submitted": entry})
            continue
        accepted.append({**entry, "evidence_ids": [str(i) for i in evidence_ids]})
    return accepted, rejected
