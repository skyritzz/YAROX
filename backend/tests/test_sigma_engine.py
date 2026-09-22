"""
Phase 16 / D-3: Sigma condition parser, field mapping, and rule/engine unit
tests. No real Postgres/Redis/Celery/Ollama here — pure parsing and matching
against constructed dicts and temp rule files. Real detection-pipeline
integration is covered separately in
tests/test_phase16_sigma_integration.py.
"""
import tempfile
import os

import pytest

from rules.sigma.condition import (
    SigmaConditionError,
    UnsupportedConditionError,
    evaluate_condition,
    parse_condition,
)
from rules.sigma.engine import SigmaEngine, SigmaRule, SigmaRuleLoadError
from rules.sigma.field_mapping import resolve_field


def _write_rule(content: str) -> str:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(content)
        return f.name


# ============================================================= condition parser

@pytest.mark.parametrize("expr,selections,expected", [
    ("selection", {"selection": True}, True),
    ("selection", {"selection": False}, False),
    ("selection1 and selection2", {"selection1": True, "selection2": True}, True),
    ("selection1 and selection2", {"selection1": True, "selection2": False}, False),
    ("selection1 or selection2", {"selection1": False, "selection2": True}, True),
    ("selection1 or selection2", {"selection1": False, "selection2": False}, False),
    ("not selection", {"selection": True}, False),
    ("not selection", {"selection": False}, True),
    ("selection1 and not filter", {"selection1": True, "filter": True}, False),
    ("selection1 and not filter", {"selection1": True, "filter": False}, True),
    ("(selection1 or selection2) and not filter", {"selection1": True, "selection2": False, "filter": False}, True),
    ("(selection1 or selection2) and not filter", {"selection1": True, "selection2": False, "filter": True}, False),
    ("1 of selection*", {"selection1": False, "selection2": True}, True),
    ("1 of selection*", {"selection1": False, "selection2": False}, False),
    ("all of selection*", {"selection1": True, "selection2": True}, True),
    ("all of selection*", {"selection1": True, "selection2": False}, False),
    ("1 of them", {"selection": False, "filter": True}, True),
    ("all of them", {"selection": True, "filter": True}, True),
    ("all of them", {"selection": True, "filter": False}, False),
])
def test_condition_evaluates_correctly(expr, selections, expected):
    assert evaluate_condition(parse_condition(expr), selections) is expected


def test_condition_reference_to_undefined_selection_raises():
    with pytest.raises(SigmaConditionError):
        evaluate_condition(parse_condition("selection_that_does_not_exist"), {"selection": True})


def test_condition_quantifier_matching_zero_selections_raises():
    with pytest.raises(SigmaConditionError):
        evaluate_condition(parse_condition("1 of nomatch*"), {"selection": True})


@pytest.mark.parametrize("bad_expr", [
    "",
    "selection and",
    "and selection",
    "((selection)",
    "selection near other",
    "selection | count() > 5",
])
def test_malformed_or_unsupported_condition_raises(bad_expr):
    with pytest.raises(SigmaConditionError):
        parse_condition(bad_expr)


def test_unsupported_construct_raises_the_specific_subclass():
    with pytest.raises(UnsupportedConditionError):
        parse_condition("selection | count() > 5")


# ============================================================= field mapping

def test_image_maps_to_process_name_with_path_normalization():
    mapping = resolve_field("process_creation", "Image")
    assert mapping.yarox_field == "process_name"
    assert mapping.normalize_expected(r"\powershell.exe") == "powershell.exe"


def test_commandline_maps_to_command_line_unchanged():
    mapping = resolve_field("process_creation", "CommandLine")
    assert mapping.yarox_field == "command_line"
    assert mapping.normalize_expected is None


def test_unmapped_field_passes_through_unchanged():
    mapping = resolve_field("process_creation", "SomeFieldNotInTheTable")
    assert mapping.yarox_field == "SomeFieldNotInTheTable"


def test_common_fields_available_regardless_of_category():
    assert resolve_field(None, "Computer").yarox_field == "hostname"
    assert resolve_field("network_connection", "User").yarox_field == "user_name"


# ============================================================= rule loading: valid

def test_valid_rule_loads_successfully():
    path = _write_rule("""
title: Test Rule
logsource:
  category: process_creation
detection:
  selection:
    Image|contains: 'powershell'
  condition: selection
level: high
""")
    try:
        rule = SigmaRule(path)
        assert rule.title == "Test Rule"
        assert rule.severity == "HIGH"
        assert rule.logsource_category == "process_creation"
    finally:
        os.unlink(path)


def test_rule_with_tags_extracts_mitre_mapping_from_local_kb():
    path = _write_rule("""
title: Test Rule With Tags
detection:
  selection:
    CommandLine|contains: 'x'
  condition: selection
tags:
  - attack.execution
  - attack.t1059
""")
    try:
        rule = SigmaRule(path)
        assert rule.mitre.technique_id == "T1059"
        assert rule.mitre.technique_name == "Command and Scripting Interpreter"
        assert rule.mitre.tactic == "Execution"
    finally:
        os.unlink(path)


def test_rule_with_unverified_technique_tag_keeps_id_without_fabricating_name():
    """A tag referencing a real ATT&CK-shaped ID not present in our local,
    curated knowledge base must not get an invented technique name."""
    path = _write_rule("""
title: Test Rule Unverified Technique
detection:
  selection:
    CommandLine|contains: 'x'
  condition: selection
tags:
  - attack.t9999
""")
    try:
        rule = SigmaRule(path)
        assert rule.mitre.technique_id == "T9999"
        assert rule.mitre.technique_name is None
    finally:
        os.unlink(path)


# ============================================================= rule loading: missing required fields

@pytest.mark.parametrize("content,expected_snippet", [
    ("detection:\n  selection:\n    a: b\n  condition: selection\n", "title"),
    ("title: t\n", "detection"),
    ("title: t\ndetection: {}\n", "detection"),
    ("title: t\ndetection:\n  selection:\n    a: b\n", "condition"),
])
def test_missing_required_fields_raise_load_error(content, expected_snippet):
    path = _write_rule(content)
    try:
        with pytest.raises(SigmaRuleLoadError, match=expected_snippet):
            SigmaRule(path)
    finally:
        os.unlink(path)


# ============================================================= rule loading: malformed YAML

def test_malformed_yaml_raises_load_error():
    path = _write_rule("title: t\n  bad indentation: [\n")
    try:
        with pytest.raises(SigmaRuleLoadError, match="malformed YAML"):
            SigmaRule(path)
    finally:
        os.unlink(path)


def test_non_mapping_top_level_raises_load_error():
    path = _write_rule("- just\n- a\n- list\n")
    try:
        with pytest.raises(SigmaRuleLoadError):
            SigmaRule(path)
    finally:
        os.unlink(path)


# ============================================================= rule loading: invalid modifiers

def test_unknown_modifier_raises_load_error():
    path = _write_rule("""
title: t
detection:
  selection:
    CommandLine|totallyfakemodifier: 'x'
  condition: selection
""")
    try:
        with pytest.raises(SigmaRuleLoadError, match="unsupported modifier"):
            SigmaRule(path)
    finally:
        os.unlink(path)


def test_conflicting_comparison_modifiers_raise_load_error():
    path = _write_rule("""
title: t
detection:
  selection:
    CommandLine|contains|startswith: 'x'
  condition: selection
""")
    try:
        with pytest.raises(SigmaRuleLoadError, match="conflicting comparison modifiers"):
            SigmaRule(path)
    finally:
        os.unlink(path)


# ============================================================= matching: modifiers

@pytest.mark.parametrize("field_key,expected,fields,should_match", [
    ("CommandLine", "cmd.exe", {"command_line": "cmd.exe"}, True),
    ("CommandLine", "cmd.exe", {"command_line": "cmd.exe /c dir"}, False),  # exact, not substring
    ("CommandLine|contains", "-enc", {"command_line": "powershell.exe -enc AAA"}, True),
    ("CommandLine|contains", "-enc", {"command_line": "powershell.exe -File x.ps1"}, False),
    ("CommandLine|startswith", "powershell", {"command_line": "powershell.exe -enc AAA"}, True),
    ("CommandLine|startswith", "powershell", {"command_line": "cmd.exe powershell"}, False),
    ("CommandLine|endswith", "AAA", {"command_line": "powershell.exe -enc AAA"}, True),
    ("CommandLine|endswith", "AAA", {"command_line": "AAA -enc powershell.exe"}, False),
    ("CommandLine|re", r"-enc\s+\w+", {"command_line": "powershell.exe -enc AAA"}, True),
    ("CommandLine|re", r"-enc\s+\w+", {"command_line": "powershell.exe -File x.ps1"}, False),
    # Sigma's 're' modifier is case-insensitive by default too, same as every other
    # modifier, unless '|cased' is added — [A-Z] matching lowercase 'aaa' here is
    # correct Sigma behavior, not a bug (see test_cased_modifier_... below for the
    # explicit case-sensitive variant).
    ("CommandLine|re", r"-enc\s+[A-Z]+", {"command_line": "powershell.exe -enc aaa"}, True),
])
def test_modifiers_match_correctly(field_key, expected, fields, should_match):
    path = _write_rule(f"""
title: t
logsource:
  category: process_creation
detection:
  selection:
    {field_key}: '{expected}'
  condition: selection
""")
    try:
        rule = SigmaRule(path)
        assert rule.match(fields) is should_match
    finally:
        os.unlink(path)


def test_case_insensitive_by_default():
    path = _write_rule("""
title: t
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'POWERSHELL'
  condition: selection
""")
    try:
        rule = SigmaRule(path)
        assert rule.match({"command_line": "powershell.exe -enc AAA"}) is True
    finally:
        os.unlink(path)


def test_cased_modifier_makes_matching_case_sensitive():
    path = _write_rule("""
title: t
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|cased: 'POWERSHELL'
  condition: selection
""")
    try:
        rule = SigmaRule(path)
        assert rule.match({"command_line": "powershell.exe -enc AAA"}) is False
        assert rule.match({"command_line": "POWERSHELL.exe -enc AAA"}) is True
    finally:
        os.unlink(path)


def test_re_cased_modifier_combination_is_case_sensitive():
    path = _write_rule(r"""
title: t
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|re|cased: '-enc\s+[A-Z]+'
  condition: selection
""")
    try:
        rule = SigmaRule(path)
        assert rule.match({"command_line": "powershell.exe -enc AAA"}) is True
        assert rule.match({"command_line": "powershell.exe -enc aaa"}) is False
    finally:
        os.unlink(path)


def test_list_valued_field_is_or_semantics_by_default():
    path = _write_rule("""
title: t
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains:
      - 'mimikatz'
      - 'lsass'
  condition: selection
""")
    try:
        rule = SigmaRule(path)
        assert rule.match({"command_line": "run mimikatz.exe"}) is True
        assert rule.match({"command_line": "dump lsass memory"}) is True
        assert rule.match({"command_line": "nothing suspicious"}) is False
    finally:
        os.unlink(path)


def test_all_modifier_requires_every_listed_value():
    path = _write_rule("""
title: t
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains|all:
      - 'net'
      - 'user'
  condition: selection
""")
    try:
        rule = SigmaRule(path)
        assert rule.match({"command_line": "net user administrator /active:yes"}) is True
        assert rule.match({"command_line": "net localgroup"}) is False
    finally:
        os.unlink(path)


# ============================================================= matching: missing fields

def test_missing_event_field_does_not_match_and_does_not_crash():
    path = _write_rule("""
title: t
detection:
  selection:
    CommandLine|contains: 'x'
  condition: selection
""")
    try:
        rule = SigmaRule(path)
        assert rule.match({}) is False
        assert rule.match({"hostname": "H1"}) is False
    finally:
        os.unlink(path)


# ============================================================= matching: multiple selections

def test_multiple_selections_with_and():
    path = _write_rule("""
title: t
logsource:
  category: process_creation
detection:
  selection1:
    Image|endswith: 'powershell.exe'
  selection2:
    CommandLine|contains: '-enc'
  condition: selection1 and selection2
""")
    try:
        rule = SigmaRule(path)
        assert rule.match({"process_name": "powershell.exe", "command_line": "powershell.exe -enc AAA"}) is True
        assert rule.match({"process_name": "powershell.exe", "command_line": "powershell.exe -File x.ps1"}) is False
        assert rule.match({"process_name": "cmd.exe", "command_line": "cmd.exe -enc AAA"}) is False
    finally:
        os.unlink(path)


def test_selection_with_filter_exclusion():
    path = _write_rule("""
title: t
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'powershell'
  filter:
    CommandLine|contains: 'known-good-script'
  condition: selection and not filter
""")
    try:
        rule = SigmaRule(path)
        assert rule.match({"command_line": "powershell.exe -File random.ps1"}) is True
        assert rule.match({"command_line": "powershell.exe -File known-good-script.ps1"}) is False
    finally:
        os.unlink(path)


# ============================================================= matching: logsource filtering

def test_logsource_category_restricts_evaluation():
    path = _write_rule("""
title: t
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'x'
  condition: selection
""")
    try:
        rule = SigmaRule(path)
        fields = {"command_line": "contains x"}
        assert rule.match(fields, canonical_event_type="PROCESS_EXECUTION") is True
        assert rule.match(fields, canonical_event_type="NETWORK_TRAFFIC") is False
        assert rule.match(fields, canonical_event_type=None) is True  # no restriction applied when caller doesn't supply one
    finally:
        os.unlink(path)


# ============================================================= engine: load-error tracking

def test_engine_tracks_load_errors_without_crashing_on_other_rules():
    with tempfile.TemporaryDirectory() as d:
        good = os.path.join(d, "good.yml")
        with open(good, "w") as f:
            f.write("title: Good Rule\ndetection:\n  selection:\n    CommandLine|contains: 'x'\n  condition: selection\n")
        bad = os.path.join(d, "bad.yml")
        with open(bad, "w") as f:
            f.write("title: Bad Rule\ndetection:\n  selection:\n    CommandLine|badmod: 'x'\n  condition: selection\n")

        engine = SigmaEngine(rules_dir=d)
        assert len(engine.rules) == 1
        assert engine.rules[0].title == "Good Rule"
        assert len(engine.load_errors) == 1
        assert "badmod" in engine.load_errors[0].reason
        assert engine.load_errors[0].filepath == bad


def test_engine_evaluate_never_raises_even_if_a_rule_errors_internally():
    """Defense in depth: evaluate() must not propagate an exception into the
    event-processing pipeline even for a pathological rule."""
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "ok.yml")
        with open(path, "w") as f:
            f.write("title: t\ndetection:\n  selection:\n    CommandLine|contains: 'x'\n  condition: selection\n")
        engine = SigmaEngine(rules_dir=d)
        # Pass a non-dict to provoke an internal error and confirm evaluate() degrades gracefully.
        result = engine.evaluate(fields=None)  # type: ignore[arg-type]
        assert result == []
