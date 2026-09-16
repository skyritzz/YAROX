import json
import os
import re
from typing import Optional, Dict, Any

# ATT&CK technique identifiers: T#### or T####.### (sub-technique)
TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


class MitreKnowledgeBase:
    """
    Local ATT&CK reference used to validate technique identifiers.

    Identifiers are validated exactly as given: a sub-technique such as
    ``T1059.001`` is preserved as ``T1059.001`` and never truncated to its
    parent. Coverage is limited to the entries in ``attack_map.json``.
    """

    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        map_path = os.path.join(current_dir, 'attack_map.json')
        with open(map_path, 'r') as f:
            self.attack_map: Dict[str, Dict[str, str]] = json.load(f)

    @staticmethod
    def normalize_id(technique_id: Any) -> Optional[str]:
        if not isinstance(technique_id, str):
            return None
        candidate = technique_id.strip().upper()
        return candidate if TECHNIQUE_ID_PATTERN.match(candidate) else None

    @staticmethod
    def parent_id(technique_id: str) -> Optional[str]:
        return technique_id.split('.')[0] if '.' in technique_id else None

    def validate(self, technique_id: Any) -> Optional[Dict[str, Any]]:
        """
        Returns the knowledge-base entry for an exact technique or sub-technique ID,
        or None if the ID is malformed or not present in the local knowledge base.
        """
        normalized = self.normalize_id(technique_id)
        if normalized is None or normalized not in self.attack_map:
            return None
        entry = self.attack_map[normalized]
        return {
            "technique_id": normalized,
            "name": entry["name"],
            "tactic": entry["tactic"],
            "parent_technique_id": self.parent_id(normalized),
        }


mitre_kb = MitreKnowledgeBase()
