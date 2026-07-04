import json
import os

class MitreKnowledgeBase:
    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        map_path = os.path.join(current_dir, 'attack_map.json')
        try:
            with open(map_path, 'r') as f:
                self.attack_map = json.load(f)
        except Exception:
            self.attack_map = {}

    def validate(self, technique_id: str):
        """
        Validates if a technique ID exists and returns its correct name and tactic.
        """
        # Normalize ID (e.g. T1059.001 -> T1059)
        base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
        base_id = base_id.upper().strip()
        
        if base_id in self.attack_map:
            return {
                "technique_id": base_id,
                "name": self.attack_map[base_id]["name"],
                "tactic": self.attack_map[base_id]["tactic"]
            }
        return None

mitre_kb = MitreKnowledgeBase()
