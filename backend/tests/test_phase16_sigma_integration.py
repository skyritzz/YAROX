"""
Phase 16 / D-3: real detection-engine integration tests.

No mocks of the systems under test: every test here stores a real Event row
through a real Postgres session and runs the real detection_engine.process_event
— the same pattern established in tests/test_phase13_detection.py. These
tests exist specifically to prove what tests/test_sigma_engine.py's pure
unit tests cannot: that a Sigma rule genuinely participates in YAROX's real
detection pipeline (case creation/correlation, evidence persistence, MITRE
technique recording), not just that the standalone parser/matcher works in
isolation.

Regression coverage for Phase 13/14/15 is intentionally NOT duplicated here
— those phases' own existing test suites (tests/test_phase13_detection.py,
tests/test_scenario_orchestration.py, tests/test_phase15_detection_quality.py)
are re-run as-is against the Phase 16 changes (see docs/PHASE_16_SIGMA_ENGINE.md
"Test commands and actual results"), which is the genuine regression proof —
rewriting them here would test nothing an existing, already-verified suite
doesn't already cover.
"""
import os
import tempfile
import uuid

import pytest
from sqlalchemy import select

from database.session import AsyncSessionLocal
from models.investigation import EvidenceItem
from models.mitre import AttackTechnique
from tests.test_phase13_detection import _store_and_detect


@pytest.fixture
def temp_sigma_rule():
    """Yields a helper to drop a rule file into the real rules/sigma/ directory
    (where the production sigma_engine singleton actually looks) and reload the
    engine, cleaning up afterward — used to prove behavior against the real,
    importable module-level singleton detection/engine.py actually uses, not a
    parallel test-only instance."""
    written_paths = []

    def _write(content: str, name: str = None) -> str:
        rules_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules", "sigma")
        filename = name or f"_tmp_test_{uuid.uuid4().hex[:8]}.yml"
        path = os.path.join(rules_dir, filename)
        with open(path, "w") as f:
            f.write(content)
        written_paths.append(path)
        import rules.sigma.engine as engine_module
        engine_module.sigma_engine = engine_module.SigmaEngine()
        return path

    yield _write

    for p in written_paths:
        if os.path.exists(p):
            os.remove(p)
    import rules.sigma.engine as engine_module
    engine_module.sigma_engine = engine_module.SigmaEngine()  # reload back to the real, permanent rule set


# ============================================================= Sigma-only match creates a case

@pytest.mark.asyncio
async def test_sigma_only_match_independently_creates_a_case(temp_sigma_rule):
    """The core D-3 requirement: an event that no native Python detection rule
    (detection/rules.py) matches at all, but that a Sigma rule does, must still
    produce a real case — not just decorate a pre-existing native-rule match
    (the pre-Phase-16 architecture's only integration point). parent_process is
    checked by no native rule in this codebase."""
    temp_sigma_rule("""
title: Suspicious Office Spawning Shell (Phase 16 test)
logsource:
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\\winword.exe'
    Image|endswith: '\\cmd.exe'
  condition: selection
level: critical
tags:
  - attack.execution
  - attack.t1059
""")
    host = f"SIGMA-ONLY-{uuid.uuid4().hex[:8]}"
    raw = {
        "timestamp": "2026-09-22T11:10:00Z",
        "hostname": host,
        "user_name": "victim",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "MEDIUM",
        "metadata": {"process_name": "cmd.exe", "parent_process": "winword.exe", "command_line": "cmd.exe /c whoami"},
    }
    event, case = await _store_and_detect(raw)
    assert case is not None
    assert case.severity == "CRITICAL"  # from the Sigma rule's own 'level', not fabricated

    async with AsyncSessionLocal() as session:
        evidence = (
            await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event.id))
        ).scalars().first()
        technique = (
            await session.execute(select(AttackTechnique).where(AttackTechnique.case_id == case.id))
        ).scalars().first()

    assert evidence.evidence_type == "SIGMA_MATCH"
    assert "Suspicious Office Spawning Shell" in evidence.reason
    assert technique.technique_id == "T1059"
    assert technique.technique_name == "Command and Scripting Interpreter"  # from the real local ATT&CK reference, not fabricated
    assert technique.tactic == "Execution"


@pytest.mark.asyncio
async def test_sigma_rule_without_mitre_tags_creates_no_fabricated_technique(temp_sigma_rule):
    """A Sigma rule with no 'tags' at all must still create a case and evidence,
    but must NOT fabricate an AttackTechnique row — detection/engine.py's own
    'if tech_id:' guard (Phase 16 addition) must actually be exercised, not just
    present in the code."""
    temp_sigma_rule("""
title: Untagged Test Rule (Phase 16 test)
logsource:
  category: process_creation
detection:
  selection:
    ParentImage|endswith: '\\excel.exe'
    Image|endswith: '\\cmd.exe'
  condition: selection
level: medium
""")
    host = f"SIGMA-NOTAG-{uuid.uuid4().hex[:8]}"
    raw = {
        "timestamp": "2026-09-22T11:11:00Z",
        "hostname": host,
        "user_name": "victim2",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "MEDIUM",
        "metadata": {"process_name": "cmd.exe", "parent_process": "excel.exe", "command_line": "cmd.exe /c whoami"},
    }
    event, case = await _store_and_detect(raw)
    assert case is not None

    async with AsyncSessionLocal() as session:
        techniques = (
            await session.execute(select(AttackTechnique).where(AttackTechnique.case_id == case.id))
        ).scalars().all()
    assert techniques == [], "no MITRE tag was present on this rule — no technique should have been fabricated"


# ============================================================= the hostname/user_name field-merge fix

@pytest.mark.asyncio
async def test_sigma_rule_can_reference_user_field_previously_unreachable(temp_sigma_rule):
    """Regression test for a real, confirmed pre-Phase-16 gap: the inline
    sigma_engine.evaluate() call in detection/engine.py passed only
    _event_metadata(event), so a Sigma rule referencing 'User' (an Event ORM
    column, not a metadata_ key) could never match — that field simply was not
    in the dict being searched, regardless of engine correctness."""
    temp_sigma_rule("""
title: Suspicious User Test Rule (Phase 16 test)
logsource:
  category: process_creation
detection:
  selection:
    User: 'known-bad-actor'
    Image|endswith: '\\cmd.exe'
  condition: selection
level: high
""")
    host = f"SIGMA-USER-{uuid.uuid4().hex[:8]}"
    raw = {
        "timestamp": "2026-09-22T11:12:00Z",
        "hostname": host,
        "user_name": "known-bad-actor",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "MEDIUM",
        "metadata": {"process_name": "cmd.exe", "command_line": "cmd.exe /c whoami"},
    }
    event, case = await _store_and_detect(raw)
    assert case is not None, "a Sigma rule referencing the User field must be able to match — this field is a real Event column, not missing data"


# ============================================================= malformed rule safety

@pytest.mark.asyncio
async def test_malformed_rule_file_does_not_crash_event_processing(temp_sigma_rule):
    """A genuinely broken rule file dropped alongside good ones must not prevent
    other rules (Sigma or native) from evaluating, and must not raise into
    detection_engine.process_event — confirmed by processing a real event
    end-to-end with the broken file present."""
    temp_sigma_rule("""
title: Broken Rule (Phase 16 test)
detection:
  selection:
    CommandLine|totallyinvalidmodifier: 'x'
  condition: selection
""", name="_tmp_test_broken_rule.yml")

    from rules.sigma.engine import sigma_engine
    assert any("_tmp_test_broken_rule" in e.filepath for e in sigma_engine.load_errors)

    # A real, unrelated event must still process normally (native rule fires, no crash).
    host = f"MALFORMED-SIGMA-{uuid.uuid4().hex[:8]}"
    raw = {
        "timestamp": "2026-09-22T11:13:00Z",
        "hostname": host,
        "user_name": "someone",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "HIGH",
        "metadata": {"process_name": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA"},
    }
    event, case = await _store_and_detect(raw)
    assert case is not None  # SuspiciousProcessExecution (native) still fired despite the broken Sigma rule alongside it


@pytest.mark.asyncio
async def test_event_with_no_metadata_at_all_does_not_crash_sigma_evaluation():
    """A bare-minimum event (no metadata_, minimal raw_log) must not crash Sigma
    matching — every field lookup must fail safe (no match), never raise."""
    raw = {
        "timestamp": "2026-09-22T11:14:00Z",
        "hostname": "unknown",
        "source": "test",
        "event_type": "unknown",
        "severity": "INFO",
        "raw_log": {},
        "metadata": {},
    }
    event, case = await _store_and_detect(raw)
    assert case is None  # nothing should match a genuinely empty event
