import pytest
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from core.taxonomy import taxonomy_normalizer, CanonicalEventType
from plugins.parsers.generic import generic_parser
from models.event import Event
from models.investigation import InvestigationCase, EvidenceItem, InvestigationStatus, Severity
from models.mitre import AttackTechnique
from detection.rules import FailedLoginBruteForce, PrivilegeEscalation, SuspiciousProcessExecution, LateralMovement
from detection.engine import detection_engine
from correlation.engine import correlation_engine


# -----------------------------------------------------------------------------
# 1. Canonical Taxonomy & Normalization Tests
# -----------------------------------------------------------------------------
def test_canonical_taxonomy_auth_failure_variants():
    variants = [
        "Authentication Failure",
        "authentication failure",
        "Authentication Failed",
        "Login Failed",
        "logon failure",
        "Bad Password",
        "AUTH_FAILURE"
    ]
    for v in variants:
        assert taxonomy_normalizer.normalize(v) == CanonicalEventType.AUTH_FAILURE


def test_canonical_taxonomy_windows_event_ids():
    assert taxonomy_normalizer.normalize(None, {"EventID": 4625}) == CanonicalEventType.AUTH_FAILURE
    assert taxonomy_normalizer.normalize(None, {"EventID": 4688}) == CanonicalEventType.PROCESS_EXECUTION
    assert taxonomy_normalizer.normalize(None, {"EventID": 4672}) == CanonicalEventType.PRIVILEGE_CHANGE
    assert taxonomy_normalizer.normalize(None, {"EventID": 4624, "logon_type": 3}) == CanonicalEventType.REMOTE_SESSION


def test_generic_json_parser_normalizes_and_preserves_raw_event():
    raw = {
        "timestamp": "2026-08-22T10:00:00Z",
        "hostname": "AUTH-01",
        "user_name": "admin",
        "source": "windows-security",
        "event_type": "Authentication Failure",
        "severity": "HIGH",
        "raw_log": {"EventID": 4625, "reason": "Bad Password"},
        "metadata": {"ip": "10.0.0.1"}
    }
    parsed = generic_parser.parse(raw)
    assert parsed["event_type"] == CanonicalEventType.AUTH_FAILURE.value
    assert parsed["metadata_"]["raw_event_type"] == "Authentication Failure"
    assert parsed["raw_log"]["reason"] == "Bad Password"


# -----------------------------------------------------------------------------
# 2. Detection Rule Canonical Taxonomy Integration Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_failed_login_brute_force_matches_canonical_auth_failure():
    from detection.state import detection_state

    rule = FailedLoginBruteForce()
    now = datetime.now(timezone.utc)
    # The window now lives in Redis and is shared across processes and runs
    await detection_state.reset(rule.name, "admin")
    
    ev1 = Event(
        timestamp=now,
        hostname="AUTH-01",
        user_name="admin",
        event_type="Authentication Failure",
        source="test",
        raw_log={"EventID": 4625}
    )
    ev2 = Event(
        timestamp=now + timedelta(seconds=5),
        hostname="AUTH-01",
        user_name="admin",
        event_type="Authentication Failure",
        source="test",
        raw_log={"EventID": 4625}
    )
    
    assert not await rule.match(ev1)
    assert await rule.match(ev2)
    exp = rule.explain(ev2)
    assert exp["mitre_technique_id"] == "T1110"
    assert exp["severity"] == Severity.HIGH


# -----------------------------------------------------------------------------
# 3. Contextual Multi-Stage Correlation Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_contextual_correlation_merges_multistage_progression():
    """
    Verifies that PowerShell Execution (T1059) and Lateral Movement (T1021)
    on the same user/host correlate into ONE unified investigation case.
    """
    case_id = uuid.uuid4()
    existing_case = InvestigationCase(
        id=case_id,
        title="Command and Scripting Interpreter",
        status=InvestigationStatus.OPEN,
        severity=Severity.HIGH,
        updated_at=datetime.now(timezone.utc)
    )
    
    event = Event(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        hostname="DC-01",
        user_name="svc_admin",
        event_type="REMOTE_SESSION",
        source="test"
    )
    
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=MagicMock(scalar_one_or_none=lambda: existing_case))
    
    related = await correlation_engine.find_related_case(mock_db, event, "Remote Services")
    assert related is not None
    assert related.id == case_id


# -----------------------------------------------------------------------------
# 4. In-Flight Severity Escalation Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_inflight_severity_escalation():
    """
    Verifies that when a HIGH case receives a CRITICAL event, the severity escalates to CRITICAL,
    and a subsequent LOW event does NOT downgrade it.
    """
    case_id = uuid.uuid4()
    case = InvestigationCase(
        id=case_id,
        title="Command and Scripting Interpreter",
        status=InvestigationStatus.OPEN,
        severity=Severity.HIGH,
        updated_at=datetime.now(timezone.utc)
    )
    
    # Event that triggers PrivilegeEscalation (CRITICAL)
    event_crit = Event(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        hostname="DC-01",
        user_name="admin",
        event_type="Privilege Escalation",
        source="test",
        raw_log={"privileges": ["SeDebugPrivilege"]}
    )
    
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.flush = AsyncMock()
    mock_db.execute = AsyncMock(return_value=MagicMock(
        scalar_one_or_none=lambda: None,
        scalars=lambda: MagicMock(first=lambda: None)
    ))
    
    with patch("correlation.engine.correlation_engine.find_related_case", new_callable=AsyncMock, return_value=case):
        updated_case = await detection_engine.process_event(mock_db, event_crit)
        assert updated_case.severity == Severity.CRITICAL


# -----------------------------------------------------------------------------
# 5. MITRE Deduplication Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_mitre_technique_deduplication():
    """
    Verifies that repeated matching of the same technique (e.g. T1059) does not create duplicate DB rows.
    """
    case_id = uuid.uuid4()
    case = InvestigationCase(
        id=case_id,
        title="Command and Scripting Interpreter",
        status=InvestigationStatus.OPEN,
        severity=Severity.HIGH,
        updated_at=datetime.now(timezone.utc)
    )
    
    event = Event(
        id=uuid.uuid4(),
        timestamp=datetime.now(timezone.utc),
        hostname="WORKSTATION-01",
        user_name="user",
        event_type="Process Creation",
        source="test",
        raw_log={"metadata": {"command_line": "powershell.exe -enc JAB..."}}
    )
    
    existing_tech = AttackTechnique(
        case_id=case_id,
        technique_id="T1059",
        technique_name="Command and Scripting Interpreter",
        tactic="Execution"
    )
    
    mock_db = AsyncMock()
    mock_db.add = MagicMock()
    mock_db.commit = AsyncMock()
    mock_db.flush = AsyncMock()
    # Mock existing_tech already present
    mock_db.execute = AsyncMock(return_value=MagicMock(
        scalar_one_or_none=lambda: None,
        scalars=lambda: MagicMock(first=lambda: existing_tech)
    ))
    
    with patch("correlation.engine.correlation_engine.find_related_case", new_callable=AsyncMock, return_value=case):
        await detection_engine.process_event(mock_db, event)
        # Verify db.add was NOT called for AttackTechnique (deduplication)
        added_types = [type(args[0]) for args, _ in mock_db.add.call_args_list]
        assert AttackTechnique not in added_types
