import os
import yaml
import glob
from typing import List, Dict, Any

class SigmaRule:
    def __init__(self, filepath: str):
        with open(filepath, 'r') as f:
            self.data = yaml.safe_load(f)
        self.title = self.data.get('title', 'Unknown Rule')
        self.level = self.data.get('level', 'medium')
        
    def match(self, event_metadata: Dict[str, Any]) -> bool:
        """
        Simple matcher for demo purposes. Evaluates the 'selection' criteria.
        """
        try:
            selection = self.data['detection']['selection']
            # All conditions in selection must match (AND logic)
            for field, expected in selection.items():
                if '|' in field:
                    actual_field, modifier = field.split('|', 1)
                else:
                    actual_field, modifier = field, 'exact'
                
                actual_val = str(event_metadata.get(actual_field, '')).lower()
                expected_val = str(expected).lower()
                
                if modifier == 'contains' and expected_val not in actual_val:
                    return False
                elif modifier == 'exact' and expected_val != actual_val:
                    return False
            return True
        except KeyError:
            return False

class SigmaEngine:
    def __init__(self):
        self.rules: List[SigmaRule] = []
        self._load_rules()

    def _load_rules(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        yaml_files = glob.glob(os.path.join(current_dir, '*.yml'))
        for yf in yaml_files:
            try:
                self.rules.append(SigmaRule(yf))
            except Exception:
                pass

    def evaluate(self, event_metadata: Dict[str, Any]) -> List[SigmaRule]:
        matches = []
        for rule in self.rules:
            if rule.match(event_metadata):
                matches.append(rule)
        return matches

sigma_engine = SigmaEngine()
