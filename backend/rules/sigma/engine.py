"""
Sigma rule loading and matching (Phase 16 / D-3).

Rewrite of the pre-Phase-16 engine, which supported only a single flat
``selection`` block with ``contains``/``exact`` modifiers, no ``condition``
expression logic, and no field-name mapping to YAROX's own schema (see
docs/PHASE_16_SIGMA_ENGINE.md for the full before/after and the
compatibility subset this implements).

Uses PyYAML's ``safe_load`` (already a project dependency, per the
instruction to reuse an existing YAML-capable dependency rather than write
a parser) — never ``yaml.load`` with the default/unsafe loader, so a
malicious or malformed rule file cannot execute arbitrary Python objects
via YAML tags.

A rule that fails to load (malformed YAML, missing required fields,
unsupported condition syntax, an invalid modifier) is recorded with its
failure reason and excluded from evaluation — it is never silently treated
as always-matching, always-failing, or ignored without a trace. See
``SigmaEngine.load_errors``.
"""
import glob
import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import yaml

from rules.sigma.condition import (
    ConditionNode,
    SigmaConditionError,
    evaluate_condition,
    parse_condition,
)
from rules.sigma.field_mapping import LOGSOURCE_CATEGORY_TO_CANONICAL_TYPE, resolve_field

logger = logging.getLogger("yarox.sigma")

_SUPPORTED_COMPARISON_MODIFIERS = {"contains", "startswith", "endswith", "re"}
_SUPPORTED_COMBINABLE_MODIFIERS = {"all", "cased"}
_ALL_SUPPORTED_MODIFIERS = _SUPPORTED_COMPARISON_MODIFIERS | _SUPPORTED_COMBINABLE_MODIFIERS

_ATTACK_TAG_RE = re.compile(r"^attack\.t(\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

# MITRE ATT&CK's own published tactic names — a fixed, finite, public taxonomy
# (not a judgment call), safe to hardcode here the same way severity/status enums
# are hardcoded elsewhere in this codebase. Used only to label a tactic tag when
# present; technique *names* are never fabricated this way (see _mitre_from_tags).
_ATTACK_TACTIC_TAG_TO_NAME = {
    "reconnaissance": "Reconnaissance",
    "resource-development": "Resource Development",
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


class SigmaRuleLoadError(ValueError):
    """Raised (and caught by the engine, never propagated to crash the pipeline)
    when a rule file cannot be turned into a usable SigmaRule."""


@dataclass
class SigmaMitreMapping:
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactic: Optional[str] = None


def _mitre_from_tags(tags: List[str]) -> SigmaMitreMapping:
    """Extracts a MITRE mapping from a Sigma rule's own `tags` field, reusing the
    existing local ATT&CK reference (security/mitre/knowledge_base.py) rather than
    a second copy of technique names. If the tagged technique isn't in that local
    reference, no technique_name is fabricated — the mapping is left without one
    (detection/engine.py skips AttackTechnique creation in that case; see its own
    comment). Tactic labels are drawn from MITRE's own fixed public tactic-name
    list (_ATTACK_TACTIC_TAG_TO_NAME above), which is not domain judgment."""
    from security.mitre.knowledge_base import mitre_kb  # local import: avoids a hard

    mapping = SigmaMitreMapping()
    tactic_tag = None
    for tag in tags or []:
        tag_l = str(tag).strip().lower()
        m = _ATTACK_TAG_RE.match(tag_l)
        if m:
            candidate_id = f"T{m.group(1)}".upper()
            entry = mitre_kb.validate(candidate_id)
            if entry:
                mapping.technique_id = entry["technique_id"]
                mapping.technique_name = entry["name"]
                mapping.tactic = entry["tactic"]
                return mapping  # a validated technique is authoritative; stop here
            elif mapping.technique_id is None:
                mapping.technique_id = candidate_id  # keep the real (if unverified) ID
        elif tag_l in _ATTACK_TACTIC_TAG_TO_NAME and tactic_tag is None:
            tactic_tag = tag_l
    if mapping.tactic is None and tactic_tag:
        mapping.tactic = _ATTACK_TACTIC_TAG_TO_NAME[tactic_tag]
    return mapping


_LEVEL_TO_SEVERITY = {"informational": "LOW", "low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}


def _parse_field_key(field_key: str) -> "tuple[str, str, bool, bool]":
    """'Image|contains|cased' -> ('Image', 'contains', False, True). Raises
    SigmaRuleLoadError on an unrecognized or conflicting modifier combination
    (e.g. two comparison modifiers, or a completely unknown modifier name) —
    an invalid modifier makes the whole rule unsupported, not a silent no-op."""
    parts = field_key.split("|")
    name = parts[0]
    modifiers = parts[1:]
    comparison = "exact"
    seen_comparison = False
    require_all = False
    cased = False
    for m in modifiers:
        m_l = m.lower()
        if m_l not in _ALL_SUPPORTED_MODIFIERS:
            raise SigmaRuleLoadError(f"unsupported modifier '{m}' on field '{field_key}'")
        if m_l in _SUPPORTED_COMPARISON_MODIFIERS:
            if seen_comparison:
                raise SigmaRuleLoadError(f"conflicting comparison modifiers on field '{field_key}' (only one of {sorted(_SUPPORTED_COMPARISON_MODIFIERS)} allowed)")
            comparison = m_l
            seen_comparison = True
        elif m_l == "all":
            require_all = True
        elif m_l == "cased":
            cased = True
    return name, comparison, require_all, cased


def _compare_one(actual: str, expected: str, comparison: str, cased: bool) -> bool:
    if comparison == "re":
        try:
            return re.search(expected, actual, 0 if cased else re.IGNORECASE) is not None
        except re.error as e:
            raise SigmaRuleLoadError(f"invalid regular expression {expected!r}: {e}")
    a = actual if cased else actual.lower()
    e = expected if cased else expected.lower()
    if comparison == "contains":
        return e in a
    if comparison == "startswith":
        return a.startswith(e)
    if comparison == "endswith":
        return a.endswith(e)
    return a == e  # exact


class SigmaRule:
    def __init__(self, filepath: str):
        self.filepath = filepath
        try:
            with open(filepath, "r") as f:
                self.data = yaml.safe_load(f)  # safe_load only — never yaml.load()
        except yaml.YAMLError as e:
            raise SigmaRuleLoadError(f"malformed YAML: {e}")
        if not isinstance(self.data, dict):
            raise SigmaRuleLoadError("rule file does not contain a YAML mapping at the top level")

        self.title: str = self.data.get("title")
        if not self.title:
            raise SigmaRuleLoadError("missing required field 'title'")

        detection = self.data.get("detection")
        if not isinstance(detection, dict) or not detection:
            raise SigmaRuleLoadError("missing or empty required field 'detection'")
        condition_str = detection.get("condition")
        if not condition_str:
            raise SigmaRuleLoadError("missing required field 'detection.condition'")

        self.selections: Dict[str, Any] = {k: v for k, v in detection.items() if k != "condition"}
        if not self.selections:
            raise SigmaRuleLoadError("detection block defines no selections")

        try:
            self.condition_ast: ConditionNode = parse_condition(condition_str)
        except SigmaConditionError as e:
            raise SigmaRuleLoadError(f"condition parse error: {e}")

        # Validate every field-key's modifiers eagerly at load time, not at match
        # time, so a rule with an invalid modifier is reported once, clearly, up
        # front (see _parse_field_key) rather than failing unpredictably per-event.
        for block in self.selections.values():
            for sub in (block if isinstance(block, list) else [block]):
                if not isinstance(sub, dict):
                    raise SigmaRuleLoadError(f"selection value must be a mapping (or list of mappings), got {type(sub).__name__}")
                for field_key in sub:
                    _parse_field_key(field_key)

        logsource = self.data.get("logsource") or {}
        self.logsource_category: Optional[str] = logsource.get("category")
        self.logsource_product: Optional[str] = logsource.get("product")

        self.level: str = str(self.data.get("level", "medium")).lower()
        self.severity: str = _LEVEL_TO_SEVERITY.get(self.level, "MEDIUM")

        self.id: Optional[str] = self.data.get("id")
        self.description: Optional[str] = self.data.get("description")
        self.tags: List[str] = self.data.get("tags") or []
        self.mitre: SigmaMitreMapping = _mitre_from_tags(self.tags)

    @property
    def canonical_event_type_restriction(self) -> Optional[str]:
        """None means "no restriction" (unrecognized/absent logsource.category) —
        the rule is still evaluated against every event, exactly as the pre-
        Phase-16 engine always did, just with correct field mapping/condition
        logic now applied."""
        return LOGSOURCE_CATEGORY_TO_CANONICAL_TYPE.get(self.logsource_category or "")

    def _evaluate_selection(self, block: Any, fields: Dict[str, Any]) -> bool:
        if isinstance(block, list):
            return any(self._evaluate_selection_map(sub, fields) for sub in block)
        return self._evaluate_selection_map(block, fields)

    def _evaluate_selection_map(self, mapping: Dict[str, Any], fields: Dict[str, Any]) -> bool:
        for field_key, expected in mapping.items():
            if not self._evaluate_field(field_key, expected, fields):
                return False
        return True

    def _evaluate_field(self, field_key: str, expected: Any, fields: Dict[str, Any]) -> bool:
        sigma_field_name, comparison, require_all, cased = _parse_field_key(field_key)
        mapping_info = resolve_field(self.logsource_category, sigma_field_name)
        actual = fields.get(mapping_info.yarox_field)
        if actual is None:
            return False  # missing field: no match, never a crash, never a false positive
        actual_str = str(actual)

        expected_values = expected if isinstance(expected, list) else [expected]
        results = []
        for ev in expected_values:
            ev_str = str(ev)
            if mapping_info.normalize_expected:
                ev_str = mapping_info.normalize_expected(ev_str)
            results.append(_compare_one(actual_str, ev_str, comparison, cased))
        return all(results) if require_all else any(results)

    def match(self, fields: Dict[str, Any], canonical_event_type: Optional[str] = None) -> bool:
        restriction = self.canonical_event_type_restriction
        if restriction and canonical_event_type and restriction != canonical_event_type:
            return False
        selection_results = {name: self._evaluate_selection(block, fields) for name, block in self.selections.items()}
        try:
            return evaluate_condition(self.condition_ast, selection_results)
        except SigmaConditionError as e:
            # Selections referenced by name are validated at load time against the
            # keys actually present, so this should not happen in practice; if it
            # does (e.g. a quantifier pattern matching zero selections due to a
            # rule authored oddly), fail closed rather than raise into the event
            # processing pipeline.
            logger.warning("Sigma rule '%s' condition evaluation error: %s", self.title, e)
            return False


@dataclass
class SigmaLoadError:
    filepath: str
    reason: str


class SigmaEngine:
    def __init__(self, rules_dir: Optional[str] = None):
        self.rules: List[SigmaRule] = []
        self.load_errors: List[SigmaLoadError] = []
        self._rules_dir = rules_dir or os.path.dirname(os.path.abspath(__file__))
        self._load_rules()

    def _load_rules(self):
        self.rules = []
        self.load_errors = []
        yaml_files = sorted(glob.glob(os.path.join(self._rules_dir, "*.yml")))
        for yf in yaml_files:
            try:
                self.rules.append(SigmaRule(yf))
            except SigmaRuleLoadError as e:
                self.load_errors.append(SigmaLoadError(filepath=yf, reason=str(e)))
                logger.warning("Sigma rule failed to load from %s: %s", yf, e)
            except Exception as e:  # a truly unexpected error must not take down rule loading
                self.load_errors.append(SigmaLoadError(filepath=yf, reason=f"unexpected error: {e}"))
                logger.exception("Unexpected error loading Sigma rule from %s", yf)

    def evaluate(self, fields: Dict[str, Any], canonical_event_type: Optional[str] = None) -> List[SigmaRule]:
        """Never raises: a single rule's match() failing unexpectedly is logged and
        skipped (fail closed for that rule), not allowed to break evaluation of the
        remaining rules or propagate into the event-processing pipeline."""
        matches = []
        for rule in self.rules:
            try:
                if rule.match(fields, canonical_event_type):
                    matches.append(rule)
            except Exception as e:
                logger.exception("Sigma rule '%s' raised during match(): %s", rule.title, e)
        return matches


sigma_engine = SigmaEngine()
