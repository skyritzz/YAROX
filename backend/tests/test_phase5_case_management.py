import pytest
import pytest_asyncio
import uuid
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch

from sqlalchemy.pool import NullPool
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.future import select

from api.main import app
from core.config import settings
from core.auth import get_current_user
from database.session import get_db
from models.user import User, UserRole
from models.investigation import (
    InvestigationCase,
    InvestigationStatus,
    Severity,
    CaseNote,
    AuditLog
)

# Use NullPool for testing to prevent connection sharing across concurrent async tasks
test_engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool, echo=False)
TestSessionLocal = async_sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)

async def override_get_db():
    async with TestSessionLocal() as session:
        yield session

@pytest.fixture(autouse=True)
def cleanup_overrides():
    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()

def make_test_user(role: UserRole, email: str = None) -> User:
    u_id = uuid.uuid4()
    return User(
        id=u_id,
        email=email or f"{role.value.lower()}_{u_id.hex[:6]}@yarox.local",
        hashed_password="hash",
        full_name=f"Test {role.value.title()}",
        role=role,
        is_active=True
    )

@pytest_asyncio.fixture
async def seeded_case():
    case_id = uuid.uuid4()
    async with TestSessionLocal() as session:
        case = InvestigationCase(
            id=case_id,
            title="Phase 5.1 Test Security Case",
            description="Case for testing notes, assignment, severity, reopening, and audit trail",
            status=InvestigationStatus.WAITING_FOR_REVIEW,
            severity=Severity.MEDIUM,
            confidence_score=0.88
        )
        session.add(case)
        await session.commit()
    yield case_id

    # Cleanup case and its children
    async with TestSessionLocal() as session:
        c = await session.get(InvestigationCase, case_id)
        if c:
            await session.delete(c)
            await session.commit()

@pytest_asyncio.fixture
async def seeded_users():
    admin = make_test_user(UserRole.ADMIN)
    analyst = make_test_user(UserRole.ANALYST)
    viewer = make_test_user(UserRole.VIEWER)

    async with TestSessionLocal() as session:
        session.add_all([admin, analyst, viewer])
        await session.commit()
    yield {"admin": admin, "analyst": analyst, "viewer": viewer}

    # Cleanup users after test and case cleanup
    async with TestSessionLocal() as session:
        for u in [admin, analyst, viewer]:
            await session.execute(select(AuditLog).where(AuditLog.user_id == u.id))
            # Delete audit logs and notes referencing this test user
            from sqlalchemy import delete
            await session.execute(delete(AuditLog).where(AuditLog.user_id == u.id))
            await session.execute(delete(CaseNote).where(CaseNote.user_id == u.id))
            db_u = await session.get(User, u.id)
            if db_u:
                await session.delete(db_u)
        await session.commit()


# =============================================================================
# 1. Notes: Create and Read Note with Attribution
# =============================================================================
@pytest.mark.asyncio
async def test_create_and_read_case_notes(seeded_case, seeded_users):
    analyst = seeded_users["analyst"]
    app.dependency_overrides[get_current_user] = lambda: analyst

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Create a note
        payload = {"content": "Initial forensic review complete: Attacker used LOLBins."}
        res = await ac.post(f"/investigations/{seeded_case}/notes", json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["content"] == payload["content"]
        assert data["user_id"] == str(analyst.id)
        assert data["user"]["email"] == analyst.email
        assert "created_at" in data

        # Read back notes
        get_res = await ac.get(f"/investigations/{seeded_case}/notes")
        assert get_res.status_code == 200
        notes = get_res.json()
        assert len(notes) >= 1
        assert notes[0]["content"] == payload["content"]
        assert notes[0]["user"]["role"] == "ANALYST"

# =============================================================================
# 2. Notes: RBAC and Empty Content Validation
# =============================================================================
@pytest.mark.asyncio
async def test_case_note_rbac_and_validation(seeded_case, seeded_users):
    viewer = seeded_users["viewer"]
    app.dependency_overrides[get_current_user] = lambda: viewer

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Viewer attempting to create a note -> 403 Forbidden
        res = await ac.post(f"/investigations/{seeded_case}/notes", json={"content": "Viewer note"})
        assert res.status_code == 403

        # Viewer can read notes -> 200 OK
        read_res = await ac.get(f"/investigations/{seeded_case}/notes")
        assert read_res.status_code == 200

    # Analyst attempting empty note -> 422 Unprocessable Entity
    analyst = seeded_users["analyst"]
    app.dependency_overrides[get_current_user] = lambda: analyst
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        empty_res = await ac.post(f"/investigations/{seeded_case}/notes", json={"content": "   "})
        assert empty_res.status_code == 422

# =============================================================================
# 3. Assignment: Assign to User, Change Assignee, Unassign & Audit
# =============================================================================
@pytest.mark.asyncio
async def test_case_assignment_and_audit(seeded_case, seeded_users):
    admin = seeded_users["admin"]
    analyst = seeded_users["analyst"]
    app.dependency_overrides[get_current_user] = lambda: admin

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Assign to analyst
        res = await ac.patch(f"/investigations/{seeded_case}/assign", json={"assigned_to_user_id": str(analyst.id)})
        assert res.status_code == 200
        assert res.json()["assigned_to_user_id"] == str(analyst.id)

        # 2. Reject non-existent user
        fake_uuid = str(uuid.uuid4())
        bad_res = await ac.patch(f"/investigations/{seeded_case}/assign", json={"assigned_to_user_id": fake_uuid})
        assert bad_res.status_code == 404
        assert "Assigned user not found" in bad_res.json()["detail"]

        # 3. Unassign case
        unassign_res = await ac.patch(f"/investigations/{seeded_case}/assign", json={"assigned_to_user_id": None})
        assert unassign_res.status_code == 200
        assert unassign_res.json()["assigned_to_user_id"] is None

        # 4. Verify audit trail contains CASE_ASSIGNED entries
        audit_res = await ac.get(f"/investigations/{seeded_case}/audit")
        assert audit_res.status_code == 200
        logs = audit_res.json()
        assign_logs = [l for l in logs if l["action"] == "CASE_ASSIGNED"]
        assert len(assign_logs) == 2
        assert assign_logs[0]["details"]["new_assigned_to"] == str(analyst.id)
        assert assign_logs[1]["details"]["new_assigned_to"] is None

# =============================================================================
# 4. Severity Override: Require Mandatory Reason & Record Audit
# =============================================================================
@pytest.mark.asyncio
async def test_severity_override_requires_reason_and_audits(seeded_case, seeded_users):
    analyst = seeded_users["analyst"]
    app.dependency_overrides[get_current_user] = lambda: analyst

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Missing/empty reason -> Rejected (422)
        bad_res = await ac.patch(f"/investigations/{seeded_case}/severity", json={"severity": "CRITICAL", "reason": "  "})
        assert bad_res.status_code == 422

        # Valid severity override
        payload = {
            "severity": "CRITICAL",
            "reason": "Host contains sensitive customer PII; elevating from MEDIUM to CRITICAL."
        }
        res = await ac.patch(f"/investigations/{seeded_case}/severity", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["previous_severity"] == "MEDIUM"
        assert data["severity"] == "CRITICAL"
        assert data["reason"] == payload["reason"]

        # Verify DB and Audit Log
        audit_res = await ac.get(f"/investigations/{seeded_case}/audit")
        logs = audit_res.json()
        sev_log = next(l for l in logs if l["action"] == "SEVERITY_OVERRIDDEN")
        assert sev_log["details"]["previous_severity"] == "MEDIUM"
        assert sev_log["details"]["new_severity"] == "CRITICAL"
        assert sev_log["details"]["reason"] == payload["reason"]
        assert sev_log["user"]["email"] == analyst.email

# =============================================================================
# 5. Status Resolution: Attribution & Memory Celery Dispatch
# =============================================================================
@pytest.mark.asyncio
async def test_resolve_status_records_attribution_and_dispatches_memory(seeded_case, seeded_users):
    analyst = seeded_users["analyst"]
    app.dependency_overrides[get_current_user] = lambda: analyst

    with patch("api.investigations.index_resolved_investigation_task.delay") as mock_delay:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.patch(f"/investigations/{seeded_case}/status", json={"status": "RESOLVED", "reason": "Contained threat and reset creds."})
            assert res.status_code == 200
            assert res.json()["status"] == "RESOLVED"

            # Verify memory indexing task was dispatched with case ID
            mock_delay.assert_called_once_with(str(seeded_case))

            # Verify resolution attribution in DB
            get_res = await ac.get(f"/investigations/{seeded_case}")
            case_data = get_res.json()
            assert case_data["status"] == "RESOLVED"
            assert case_data["resolved_by_user_id"] == str(analyst.id)
            assert case_data["resolved_at"] is not None
            assert case_data["resolved_by"]["email"] == analyst.email

            # Verify audit trail
            audit_res = await ac.get(f"/investigations/{seeded_case}/audit")
            logs = audit_res.json()
            resolve_log = next(l for l in logs if l["action"] == "CASE_RESOLVED")
            assert resolve_log["details"]["new_status"] == "RESOLVED"
            assert resolve_log["details"]["reason"] == "Contained threat and reset creds."

# =============================================================================
# 6. Status False Positive: Attribution & Memory Indexing Aborted
# =============================================================================
@pytest.mark.asyncio
async def test_false_positive_records_attribution_without_memory_indexing(seeded_case, seeded_users):
    analyst = seeded_users["analyst"]
    app.dependency_overrides[get_current_user] = lambda: analyst

    with patch("api.investigations.index_resolved_investigation_task.delay") as mock_delay:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.patch(f"/investigations/{seeded_case}/status", json={"status": "FALSE_POSITIVE", "reason": "Authorized red team exercise."})
            assert res.status_code == 200
            assert res.json()["status"] == "FALSE_POSITIVE"

            # Memory indexing must NOT be called for false positives
            mock_delay.assert_not_called()

            # Verify attribution
            get_res = await ac.get(f"/investigations/{seeded_case}")
            case_data = get_res.json()
            assert case_data["status"] == "FALSE_POSITIVE"
            assert case_data["resolved_by_user_id"] == str(analyst.id)
            assert case_data["resolved_at"] is not None

            # Verify audit trail
            audit_res = await ac.get(f"/investigations/{seeded_case}/audit")
            logs = audit_res.json()
            fp_log = next(l for l in logs if l["action"] == "CASE_MARKED_FALSE_POSITIVE")
            assert fp_log["details"]["new_status"] == "FALSE_POSITIVE"
            assert fp_log["details"]["reason"] == "Authorized red team exercise."

# =============================================================================
# 7. Case Reopening: Valid Reopen from Terminal States & Rejection from Non-Terminal
# =============================================================================
@pytest.mark.asyncio
async def test_reopen_case_lifecycle(seeded_case, seeded_users):
    analyst = seeded_users["analyst"]
    app.dependency_overrides[get_current_user] = lambda: analyst

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Case is initially WAITING_FOR_REVIEW -> Reopen must be rejected (400)
        bad_reopen = await ac.post(f"/investigations/{seeded_case}/reopen", json={"reason": "Should fail"})
        assert bad_reopen.status_code == 400
        assert "Reopening is only allowed from terminal states" in bad_reopen.json()["detail"]

        # Resolve the case
        await ac.patch(f"/investigations/{seeded_case}/status", json={"status": "RESOLVED"})

        # Reopen from RESOLVED -> Succeeded (200)
        reopen_res = await ac.post(f"/investigations/{seeded_case}/reopen", json={"reason": "New telemetry observed on compromised host."})
        assert reopen_res.status_code == 200
        assert reopen_res.json()["status"] == "OPEN"

        # Verify DB: Status is OPEN, resolution attribution is cleared
        get_res = await ac.get(f"/investigations/{seeded_case}")
        case_data = get_res.json()
        assert case_data["status"] == "OPEN"
        assert case_data["resolved_by_user_id"] is None
        assert case_data["resolved_at"] is None

        # Verify audit trail
        audit_res = await ac.get(f"/investigations/{seeded_case}/audit")
        logs = audit_res.json()
        reopen_log = next(l for l in logs if l["action"] == "CASE_REOPENED")
        assert reopen_log["details"]["previous_status"] == "RESOLVED"
        assert reopen_log["details"]["new_status"] == "OPEN"
        assert reopen_log["details"]["reason"] == "New telemetry observed on compromised host."

# =============================================================================
# 8. Audit Trail: Immutable Chronological Ordering & User Details
# =============================================================================
@pytest.mark.asyncio
async def test_audit_trail_chronological_immutability(seeded_case, seeded_users):
    admin = seeded_users["admin"]
    analyst = seeded_users["analyst"]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Analyst creates note
        app.dependency_overrides[get_current_user] = lambda: analyst
        await ac.post(f"/investigations/{seeded_case}/notes", json={"content": "Step 1: Check logs."})

        # 2. Admin overrides severity
        app.dependency_overrides[get_current_user] = lambda: admin
        await ac.patch(f"/investigations/{seeded_case}/severity", json={"severity": "HIGH", "reason": "Step 2: Escalating."})

        # 3. Admin assigns to analyst
        await ac.patch(f"/investigations/{seeded_case}/assign", json={"assigned_to_user_id": str(analyst.id)})

        # 4. Retrieve audit trail
        app.dependency_overrides[get_current_user] = lambda: analyst
        res = await ac.get(f"/investigations/{seeded_case}/audit")
        assert res.status_code == 200
        logs = res.json()

        assert len(logs) >= 3
        actions = [l["action"] for l in logs]
        assert "NOTE_CREATED" in actions
        assert "SEVERITY_OVERRIDDEN" in actions
        assert "CASE_ASSIGNED" in actions

        # Verify timestamps are strictly monotonically non-decreasing (chronological)
        timestamps = [datetime.fromisoformat(l["timestamp"].replace("Z", "+00:00")) for l in logs]
        for i in range(len(timestamps) - 1):
            assert timestamps[i] <= timestamps[i + 1]

        # Verify user attribution is loaded
        for log in logs:
            assert log["user"] is not None
            assert "email" in log["user"]
            assert "role" in log["user"]
