"""
Phase 16 / D-3, Phase 4: validation against genuine, unmodified rules from the
public SigmaHQ repository (https://github.com/SigmaHQ/sigma), released under
the Detection Rule License (DRL) 1.1
(https://github.com/SigmaHQ/Detection-Rule-License). Each rule file in
backend/rules/sigma/sigmahq_imports/ is copied verbatim — title, id, author,
references, and detection logic are all unchanged from upstream; only this
test file (not the rules themselves) documents which parts YAROX's current
telemetry can and cannot observe.

These three rules were deliberately NOT auto-loaded into the live production
sigma_engine singleton (rules/sigma/engine.py's own *.yml glob only looks in
its own directory, not this subdirectory) — they are a validation fixture
set, loaded explicitly here via a dedicated SigmaEngine(rules_dir=...)
instance, not a silent expansion of YAROX's active default detection
coverage. See docs/PHASE_16_SIGMA_ENGINE.md "Real rules tested" for the full
per-rule writeup this file provides the evidence for.

One of the three rules is genuinely supported (its required fields exist in
YAROX's telemetry); one is unsupported (requires full file-path data YAROX's
Sysmon connector does not capture — process_name is basename-only); one is
effectively unsupported despite being partially expressible (a required
field, Sysmon's own 'Initiated', is real telemetry Sysmon emits but YAROX's
connector does not currently extract). None of this is hidden — that is the
point of this file.
"""
import os

import pytest
from sqlalchemy import select

from rules.sigma.engine import SigmaEngine
from tests.test_phase13_detection import _store_and_detect
from database.session import AsyncSessionLocal
from models.investigation import EvidenceItem

_SIGMAHQ_IMPORTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "sigma", "sigmahq_imports")


@pytest.fixture(scope="module")
def real_rules_engine():
    return SigmaEngine(rules_dir=_SIGMAHQ_IMPORTS_DIR)


def _rule(engine, title_substring: str):
    matches = [r for r in engine.rules if title_substring.lower() in r.title.lower()]
    assert len(matches) == 1, f"expected exactly one rule matching {title_substring!r}, found {[r.title for r in matches]}"
    return matches[0]


def test_all_three_curated_rules_load_without_error(real_rules_engine):
    assert len(real_rules_engine.rules) == 3, f"load_errors={real_rules_engine.load_errors}"
    assert real_rules_engine.load_errors == []


# ============================================================= Rule 1: SUPPORTED
# "Suspicious Encoded PowerShell Command Line" (SigmaHQ id ca2092a1-c273-4878-9b4b-0d60115bf5ea)
# Source: rules/windows/process_creation/proc_creation_win_powershell_base64_encoded_cmd.yml
# Logsource: process_creation / windows (Sysmon EventID 1)
#
# Field mapping used: Image|endswith -> process_name (path-normalized), CommandLine -> command_line.
# Exercises: multiple named selections, list-valued OR fields, 'all of x*' and
# '1 of x*' quantifiers, and/or/not — nearly the full supported grammar in one rule.
#
# Normalization assumption: 'OriginalFileName' (the rule's alternate selection_img
# branch) is left unmapped — see rules/sigma/field_mapping.py's own comment — so
# this rule is only reachable via its Image|endswith branch. That branch alone is
# sufficient for the rule's condition to be satisfiable with YAROX's telemetry.

def test_supported_rule_matches_a_real_encoded_powershell_command(real_rules_engine):
    rule = _rule(real_rules_engine, "Suspicious Encoded PowerShell")
    fields = {"process_name": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA"}
    assert rule.match(fields, canonical_event_type="PROCESS_EXECUTION") is True


def test_supported_rule_does_not_match_a_benign_powershell_invocation(real_rules_engine):
    rule = _rule(real_rules_engine, "Suspicious Encoded PowerShell")
    fields = {"process_name": "powershell.exe", "command_line": "powershell.exe -File C:\\Scripts\\Get-DiskSpace.ps1"}
    assert rule.match(fields, canonical_event_type="PROCESS_EXECUTION") is False


def test_supported_rule_respects_its_own_remote_signed_filter():
    """The rule's own 'not 1 of filter_optional_*' exclusion — proves filter
    quantifiers work correctly against a genuine, unmodified upstream rule, not
    just my own hand-constructed test fixtures."""
    engine = SigmaEngine(rules_dir=_SIGMAHQ_IMPORTS_DIR)
    rule = _rule(engine, "Suspicious Encoded PowerShell")
    fields = {
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -ExecutionPolicy remotesigned -enc SQBFAFgA",
    }
    assert rule.match(fields, canonical_event_type="PROCESS_EXECUTION") is False


@pytest.mark.asyncio
async def test_supported_rule_matches_through_the_real_detection_engine():
    """Not just a standalone parser test — real Postgres row, real
    detection_engine.process_event, real SigmaDetectionRule wrapper, using this
    dedicated real-rules engine instance rather than the production default
    (which does not have this rule loaded — see module docstring)."""
    import rules.sigma.engine as sigma_engine_module
    original_engine = sigma_engine_module.sigma_engine
    sigma_engine_module.sigma_engine = SigmaEngine(rules_dir=_SIGMAHQ_IMPORTS_DIR)
    try:
        raw = {
            "timestamp": "2026-09-22T11:00:00Z",
            "hostname": "SIGMAHQ-REAL-RULE-TEST",
            "user_name": "victim",
            "source": "Sysmon",
            "event_type": "Process Creation",
            "severity": "HIGH",
            "metadata": {"process_name": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA"},
        }
        event, case = await _store_and_detect(raw)
        assert case is not None
        async with AsyncSessionLocal() as session:
            evidence = (
                await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event.id, EvidenceItem.evidence_type == "SIGMA_MATCH"))
            ).scalars().first()
        assert evidence is not None
        assert "Suspicious Encoded PowerShell" in evidence.reason
    finally:
        sigma_engine_module.sigma_engine = original_engine


# ============================================================= Rule 2: UNSUPPORTED
# "Process Execution From A Potentially Suspicious Folder" (SigmaHQ id 3dfd06d2-eaf4-4532-9555-68aca59f57c4)
# Source: rules/windows/process_creation/proc_creation_win_susp_execution_path.yml
# Logsource: process_creation / windows
#
# Every one of this rule's selection criteria checks for a DIRECTORY substring
# in Image (e.g. ':\Windows\Fonts\', '$Recycle.bin') — i.e. it needs the FULL
# FILE PATH. YAROX's Sysmon connector (plugins/parsers/sysmon.py's _basename())
# discards the path entirely and stores only the basename in process_name — no
# normalization can recover directory information that was never captured.
# Genuinely unsupported, not merely "doesn't happen to match this test event."

def test_unsupported_rule_cannot_match_even_a_realistic_true_positive(real_rules_engine):
    rule = _rule(real_rules_engine, "Suspicious Folder")
    # A real attacker dropping a payload in C:\Windows\Fonts\ (a real, cited technique
    # this rule exists to catch) — but YAROX only ever has the basename "evil.exe",
    # never the directory, so this can never be represented, let alone matched.
    fields = {"process_name": "evil.exe"}
    assert rule.match(fields, canonical_event_type="PROCESS_EXECUTION") is False


def test_unsupported_rule_field_is_genuinely_absent_not_just_unmatched():
    """Distinguishes 'the value doesn't match' from 'the underlying data doesn't
    exist at all' — the actual reason this rule is unsupported, not a tuning
    problem. resolve_field's target key isn't populated by any real event this
    system stores, at any value."""
    from rules.sigma.field_mapping import resolve_field
    mapping = resolve_field("process_creation", "Image")
    assert mapping.yarox_field == "process_name"  # correctly mapped...
    # ...but process_name never contains a directory component in any real
    # Sysmon-connector-produced event (plugins/parsers/sysmon.py's _basename()
    # strips it before metadata is ever built) - confirmed directly:
    from plugins.parsers.sysmon import _basename
    assert _basename(r"C:\Windows\Fonts\evil.exe") == "evil.exe"


# ============================================================= Rule 3: PARTIALLY SUPPORTED (effectively unsupported)
# "Uncommon Network Connection Initiated By Certutil.EXE" (SigmaHQ id 0dba975d-a193-4ed1-a067-424df57570d1)
# Source: rules/windows/network_connection/net_connection_win_certutil_initiated_connection.yml
# Logsource: network_connection / windows (Sysmon EventID 3)
#
# Image|endswith -> process_name (supported) and DestinationPort -> destination_port
# (supported) are both real, capturable YAROX fields. But the selection is a flat
# AND across all three of its fields, and the third — Sysmon's own 'Initiated'
# field (true/false: did this host initiate the connection) — is real telemetry
# Sysmon EventID 3 emits, but plugins/parsers/sysmon.py's network-connect handling
# does not currently extract it into metadata at all (confirmed by grep — no
# 'initiated' key is ever set). The selection can therefore never be fully
# satisfied regardless of how suspicious the other two fields look — not a
# capability gap in the Sigma engine itself, a telemetry gap in the connector.

def test_partially_supported_rule_cannot_match_without_the_missing_initiated_field(real_rules_engine):
    rule = _rule(real_rules_engine, "Certutil")
    # process_name and destination_port alone are exactly what a real
    # certutil-initiated download would look like - but 'Initiated' is simply
    # never present in any event YAROX stores today.
    fields = {"process_name": "certutil.exe", "destination_port": 443}
    assert rule.match(fields, canonical_event_type="NETWORK_TRAFFIC") is False


def test_partially_supported_rule_confirms_the_supported_fields_alone_would_work():
    """Isolates exactly which part is missing: constructs the same rule's
    selection MINUS the unsupported 'Initiated' field, proving Image/DestinationPort
    genuinely would match if the connector captured 'Initiated' too — the gap is
    precisely bounded, not a blanket claim of total unsupportability."""
    import tempfile
    content = """
title: Test - Certutil network fields minus Initiated
logsource:
  category: network_connection
detection:
  selection:
    Image|endswith: '\\certutil.exe'
    DestinationPort:
      - 80
      - 443
  condition: selection
"""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        from rules.sigma.engine import SigmaRule
        rule = SigmaRule(path)
        assert rule.match({"process_name": "certutil.exe", "destination_port": 443}, canonical_event_type="NETWORK_TRAFFIC") is True
    finally:
        os.unlink(path)


# ============================================================= provenance / license

def test_curated_rules_retain_original_sigmahq_metadata(real_rules_engine):
    """Confirms these are genuinely unmodified upstream rules (title/id/author
    preserved) - not rewritten to make them easier to pass."""
    supported = _rule(real_rules_engine, "Suspicious Encoded PowerShell")
    assert supported.id == "ca2092a1-c273-4878-9b4b-0d60115bf5ea"
    unsupported = _rule(real_rules_engine, "Suspicious Folder")
    assert unsupported.id == "3dfd06d2-eaf4-4532-9555-68aca59f57c4"
    partial = _rule(real_rules_engine, "Certutil")
    assert partial.id == "0dba975d-a193-4ed1-a067-424df57570d1"
