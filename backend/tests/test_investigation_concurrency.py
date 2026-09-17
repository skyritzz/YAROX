"""
Per-case investigation locking, lock expiry/crash safety, status transitions and
background session safety.
"""
import asyncio
import uuid
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
import redis.asyncio as aioredis
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from api.main import app
from core.auth import get_current_user
from core.case_state import (
    ALLOWED_TRANSITIONS,
    InvalidStatusTransition,
    can_transition,
    validate_transition,
)
from core.config import settings
from core.locks import RedisLock, investigation_lock_key, rerun_flag_key
from database.session import AsyncSessionLocal
from models.investigation import InvestigationCase, InvestigationReport, InvestigationStatus, Severity
from models.user import User, UserRole
from services.investigation_runner import run_investigation_in_background

S = InvestigationStatus


async def _make_case(status=S.OPEN) -> uuid.UUID:
    case_id = uuid.uuid4()
    async with AsyncSessionLocal() as session:
        session.add(InvestigationCase(id=case_id, title="Concurrency case", status=status, severity=Severity.HIGH))
        await session.commit()
    return case_id


@pytest_asyncio.fixture
async def redis_client():
    client = aioredis.from_url(settings.REDIS_URL)
    yield client
    await client.aclose()


@pytest_asyncio.fixture
async def analyst_client():
    analyst = User(id=uuid.uuid4(), email=f"concurrency-{uuid.uuid4().hex[:8]}@test.local", hashed_password="x", role=UserRole.ANALYST, is_active=True)
    async with AsyncSessionLocal() as session:
        session.add(analyst)
        await session.commit()
    app.dependency_overrides[get_current_user] = lambda: analyst
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


# ---------------------------------------------------------------- locking

@pytest.mark.asyncio
async def test_concurrent_investigations_of_same_case_run_once(redis_client):
    case_id = await _make_case()
    started = []

    async def slow_run(db, cid):
        started.append(cid)
        await asyncio.sleep(0.4)
        return {"status": "completed"}

    with patch("agents.orchestrator.AgentOrchestrator._run_locked", side_effect=slow_run, autospec=False):
        first, second, third = await asyncio.gather(
            run_investigation_in_background(str(case_id)),
            run_investigation_in_background(str(case_id)),
            run_investigation_in_background(str(case_id)),
        )

    outcomes = [first, second, third]
    assert sum(1 for o in outcomes if o["status"] == "completed") == 1
    assert sum(1 for o in outcomes if o["status"] == "skipped") == 2
    assert all("already running" in o["reason"] for o in outcomes if o["status"] == "skipped")
    # The single holder ran once for the original request, then once more because a
    # concurrent attempt requested a re-run
    assert len(started) == 2
    assert await redis_client.get(investigation_lock_key(case_id)) is None  # lock released


@pytest.mark.asyncio
async def test_two_different_cases_are_not_blocked_by_each_other():
    case_a, case_b = await _make_case(), await _make_case()
    running = []

    async def slow_run(db, cid):
        running.append(cid)
        await asyncio.sleep(0.2)
        return {"status": "completed"}

    with patch("agents.orchestrator.AgentOrchestrator._run_locked", side_effect=slow_run):
        results = await asyncio.gather(
            run_investigation_in_background(str(case_a)),
            run_investigation_in_background(str(case_b)),
        )
    assert [r["status"] for r in results] == ["completed", "completed"]
    assert set(running) == {str(case_a), str(case_b)}


@pytest.mark.asyncio
async def test_rerun_request_is_recorded_and_consumed(redis_client):
    case_id = await _make_case()
    passes = []

    async def run_once(db, cid):
        passes.append(cid)
        if len(passes) == 1:
            # Another worker tries while this one holds the lock
            await run_investigation_in_background(str(case_id))
        return {"status": "completed"}

    with patch("agents.orchestrator.AgentOrchestrator._run_locked", side_effect=run_once):
        await run_investigation_in_background(str(case_id))

    assert len(passes) == 2  # the re-run request was consumed by the holder
    assert await redis_client.get(rerun_flag_key(case_id)) is None


@pytest.mark.asyncio
async def test_expired_lock_from_a_crashed_holder_is_reclaimed(redis_client):
    case_id = await _make_case()
    # Simulate a crashed holder: a lock key with a short TTL and nobody refreshing it
    await redis_client.set(investigation_lock_key(case_id), "crashed-holder-token", px=300)

    async def run(db, cid):
        return {"status": "completed"}

    with patch("agents.orchestrator.AgentOrchestrator._run_locked", side_effect=run):
        blocked = await run_investigation_in_background(str(case_id))
        await asyncio.sleep(0.5)  # let the stale lock expire
        reclaimed = await run_investigation_in_background(str(case_id))

    assert blocked["status"] == "skipped"
    assert reclaimed["status"] == "completed"


@pytest.mark.asyncio
async def test_lock_is_refreshed_while_work_runs_and_not_released_by_a_stale_holder(redis_client):
    key = f"yarox:test:lock:{uuid.uuid4()}"
    lock = RedisLock(key=key, ttl_seconds=0.6, refresh_interval=0.15)
    assert await lock.acquire() is True
    await asyncio.sleep(1.2)  # longer than the TTL; the heartbeat must keep it alive
    assert await redis_client.get(key) is not None
    assert await lock.is_held_by_us() is True

    # A different holder must not be able to release our lock
    other = RedisLock(key=key, ttl_seconds=0.6)
    other._redis = aioredis.from_url(settings.REDIS_URL)
    assert await other.release() is False
    assert await redis_client.get(key) is not None

    assert await lock.release() is True
    assert await redis_client.get(key) is None


# ---------------------------------------------------------------- status machine

@pytest.mark.parametrize("current,target", [
    (S.OPEN, S.ANALYZING), (S.OPEN, S.FALSE_POSITIVE), (S.OPEN, S.RESOLVED),
    (S.ANALYZING, S.WAITING_FOR_REVIEW), (S.ANALYZING, S.OPEN),
    (S.WAITING_FOR_REVIEW, S.RESOLVED), (S.WAITING_FOR_REVIEW, S.FALSE_POSITIVE),
    (S.WAITING_FOR_REVIEW, S.ANALYZING), (S.RESOLVED, S.OPEN), (S.FALSE_POSITIVE, S.OPEN),
])
def test_valid_transitions(current, target):
    validate_transition(current, target)
    assert can_transition(current, target)


@pytest.mark.parametrize("current,target", [
    (S.OPEN, S.WAITING_FOR_REVIEW),      # cannot skip analysis
    (S.OPEN, S.OPEN),                    # no-op is not a transition
    (S.RESOLVED, S.ANALYZING),           # closed case must be reopened first
    (S.RESOLVED, S.WAITING_FOR_REVIEW),
    (S.FALSE_POSITIVE, S.RESOLVED),
    (S.ANALYZING, S.RESOLVED),           # review gate cannot be bypassed
])
def test_invalid_transitions(current, target):
    assert not can_transition(current, target)
    with pytest.raises(InvalidStatusTransition):
        validate_transition(current, target)


def test_every_status_has_an_explicit_transition_set():
    assert set(ALLOWED_TRANSITIONS) == set(S)


@pytest.mark.asyncio
async def test_status_api_rejects_invalid_transition_and_records_nothing(analyst_client):
    case_id = await _make_case(status=S.OPEN)
    res = await analyst_client.patch(f"/investigations/{case_id}/status", json={"status": "WAITING_FOR_REVIEW"})
    assert res.status_code == 409
    assert "Invalid status transition OPEN -> WAITING_FOR_REVIEW" in res.json()["detail"]

    async with AsyncSessionLocal() as session:
        case = await session.get(InvestigationCase, case_id)
        assert case.status == S.OPEN
    audit = (await analyst_client.get(f"/investigations/{case_id}/audit")).json()
    assert audit == []


@pytest.mark.asyncio
async def test_status_api_accepts_valid_transition(analyst_client):
    case_id = await _make_case(status=S.WAITING_FOR_REVIEW)
    with patch("api.investigations.index_resolved_investigation_task.delay"):
        res = await analyst_client.patch(f"/investigations/{case_id}/status", json={"status": "RESOLVED", "reason": "verified"})
    assert res.status_code == 200
    async with AsyncSessionLocal() as session:
        case = await session.get(InvestigationCase, case_id)
        assert case.status == S.RESOLVED


@pytest.mark.asyncio
async def test_closed_case_is_not_investigated(analyst_client):
    case_id = await _make_case(status=S.RESOLVED)
    res = await analyst_client.post(f"/investigations/{case_id}/analyze")
    assert res.status_code == 409
    assert "Reopen it first" in res.json()["detail"]

    # Even called directly, the orchestrator refuses a closed case
    outcome = await run_investigation_in_background(str(case_id))
    assert outcome == {"status": "skipped", "reason": "case status is RESOLVED"}


# ---------------------------------------------------------------- background session safety

@pytest.mark.asyncio
async def test_analyze_endpoint_does_not_use_the_request_session(analyst_client):
    case_id = await _make_case(status=S.OPEN)
    sessions = []

    async def capture(db, cid):
        sessions.append(db)
        assert db.is_active
        await db.execute(select(InvestigationCase).where(InvestigationCase.id == uuid.UUID(cid)))
        return {"status": "completed"}

    with patch("agents.orchestrator.AgentOrchestrator._run_locked", side_effect=capture):
        res = await analyst_client.post(f"/investigations/{case_id}/analyze")
    assert res.status_code == 200
    # The background task ran with a session it created and that session works
    assert len(sessions) == 1
    assert sessions[0].is_active
