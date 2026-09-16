import pytest
import pytest_asyncio
import uuid
import json
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch, MagicMock

from api.main import app
from core.config import settings, validate_production_settings, DEV_JWT_PLACEHOLDER, DEV_INGEST_KEY_PLACEHOLDER
from core.events import event_bus
from core.rate_limiter import ingestion_rate_limiter
from models.user import User, UserRole
from models.event import Event
from schemas.ingest import IngestEventRequest
from security.lab.telemetry_generator import SyntheticTelemetryGenerator, SYNTHETIC_SOURCE
from replay.engine import ReplayEngine


@pytest.fixture
def valid_ingest_headers():
    return {
        "Content-Type": "application/json",
        "X-API-Key": settings.INGESTION_API_KEY
    }


# -----------------------------------------------------------------------------
# 1. Ingestion API Key Authentication Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ingest_missing_api_key():
    payload = {
        "source": "sysmon",
        "event_type": "Process Creation",
        "raw_log": {"process_name": "cmd.exe"}
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest", json=payload)
        assert res.status_code == 401
        assert "Missing required 'X-API-Key'" in res.json().get("detail", "")


@pytest.mark.asyncio
async def test_ingest_invalid_api_key():
    payload = {
        "source": "sysmon",
        "event_type": "Process Creation",
        "raw_log": {"process_name": "cmd.exe"}
    }
    headers = {"Content-Type": "application/json", "X-API-Key": "invalid_forged_api_key_123"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest", json=payload, headers=headers)
        assert res.status_code == 401
        assert "Invalid 'X-API-Key'" in res.json().get("detail", "")


@pytest.mark.asyncio
async def test_ingest_valid_api_key(valid_ingest_headers):
    payload = {
        "source": "yarox-synthetic-lab",
        "event_type": "Process Creation",
        "hostname": "TEST-HOST-01",
        "user_name": "test_user",
        "severity": "MEDIUM",
        "raw_log": {"process_name": "powershell.exe", "command_line": "-enc JAB..."},
        "metadata": {"telemetry_type": "SYNTHETIC_TEST", "lab": True}
    }
    with patch("core.rate_limiter.ingestion_rate_limiter.check_rate_limit", new_callable=AsyncMock, return_value=(True, 0)):
        with patch("core.events.event_bus.publish", new_callable=AsyncMock) as mock_publish:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
                res = await ac.post("/events/ingest", json=payload, headers=valid_ingest_headers)
                assert res.status_code == 202
                data = res.json()
                assert data["status"] == "accepted"
                assert data["source"] == "yarox-synthetic-lab"
                assert data["ingest_mode"] == "LIVE"
                mock_publish.assert_awaited_once()


# -----------------------------------------------------------------------------
# 2. Ingestion Key Authorization Isolation (Adjustment 5)
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ingestion_key_cannot_access_user_endpoints():
    """
    Ensures that the Ingestion API key cannot be used as a general-purpose credential to access user REST endpoints.
    """
    headers = {"Authorization": f"Bearer {settings.INGESTION_API_KEY}"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.get("/investigations/", headers=headers)
        assert res.status_code == 401


# -----------------------------------------------------------------------------
# 3. Rate Limiting Tests (Adjustment 1 - Fail Closed on Redis Failure)
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ingest_rate_limiting_exceeded(valid_ingest_headers):
    payload = {
        "source": "sysmon",
        "event_type": "Process Creation",
        "raw_log": {"cmd": "test"}
    }
    # Simulate rate limiter returning exceeded status
    with patch("core.rate_limiter.ingestion_rate_limiter.check_rate_limit", new_callable=AsyncMock, return_value=(False, 45)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post("/events/ingest", json=payload, headers=valid_ingest_headers)
            assert res.status_code == 429
            assert "rate limit exceeded" in res.json().get("detail", "").lower()
            assert res.headers.get("Retry-After") == "45"


@pytest.mark.asyncio
async def test_ingest_rate_limiter_fail_closed_on_redis_error(valid_ingest_headers):
    """
    Adjustment 1: If Redis is unavailable, rate limiter must fail closed (HTTP 503) rather than allowing unthrottled floods.
    """
    payload = {
        "source": "sysmon",
        "event_type": "Process Creation",
        "raw_log": {"cmd": "test"}
    }
    from fastapi import HTTPException
    with patch("core.rate_limiter.ingestion_rate_limiter.get_redis", side_effect=Exception("Redis connection refused")):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            res = await ac.post("/events/ingest", json=payload, headers=valid_ingest_headers)
            assert res.status_code == 503
            assert "fail-closed" in res.json().get("detail", "").lower()


# -----------------------------------------------------------------------------
# 4. Input Validation & Payload Bounds Tests
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_ingest_oversized_payload_rejected(valid_ingest_headers):
    # 70 KB payload exceeds 64 KB limit
    oversized_raw_log = {"huge_blob": "A" * 70000}
    payload = {
        "source": "sysmon",
        "event_type": "Process Creation",
        "raw_log": oversized_raw_log
    }
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest", json=payload, headers=valid_ingest_headers)
        assert res.status_code == 422
        assert "exceeds maximum allowable limit" in res.text


@pytest.mark.asyncio
async def test_ingest_missing_required_fields_rejected(valid_ingest_headers):
    # Missing event_type and raw_log
    payload = {"source": "sysmon"}
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post("/events/ingest", json=payload, headers=valid_ingest_headers)
        assert res.status_code == 422


# -----------------------------------------------------------------------------
# 5. Synthetic Telemetry Marker Tests (Adjustment 3)
# -----------------------------------------------------------------------------
def test_synthetic_telemetry_generator_markers():
    generator = SyntheticTelemetryGenerator()
    events = generator.generate_scenario("brute_force_auth")
    
    assert len(events) >= 5
    for ev in events:
        assert ev["source"] == SYNTHETIC_SOURCE
        assert ev["metadata"]["telemetry_type"] == "SYNTHETIC_TEST"
        assert ev["metadata"]["lab"] is True
        assert ev["metadata"]["scenario"] == "brute_force_auth"


# -----------------------------------------------------------------------------
# 6. KnowledgeBuilder Prompt Sandboxing (Part 13)
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_knowledge_builder_prompt_sandboxing():
    from memory.knowledge_builder import KnowledgeBuilder
    from models.investigation import InvestigationCase, Severity, InvestigationStatus
    
    builder = KnowledgeBuilder()
    case = InvestigationCase(
        id=uuid.uuid4(),
        title="Hostile Injection Attack",
        description="Matched Rule",
        severity=Severity.HIGH,
        status=InvestigationStatus.RESOLVED,
        created_at=datetime.now(timezone.utc)
    )
    
    mock_db = AsyncMock()
    mock_db.execute = AsyncMock(return_value=MagicMock(
        scalar_one_or_none=lambda: case,
        scalars=lambda: MagicMock(all=lambda: [])
    ))
    
    # Verify that llm_service.generate receives sandboxed prompt containing <untrusted_security_evidence>
    with patch("services.llm_service.llm_service.generate", new_callable=AsyncMock) as mock_llm:
        mock_llm.return_value = json.dumps({
            "summary": "Verified attack summary",
            "executive_summary": "Exec summary",
            "important_events": []
        })
        
        ko, fp = await builder.build(mock_db, str(case.id))
        
        prompt_called = mock_llm.call_args[0][0]
        assert "<system_instruction>" in prompt_called
        assert "<untrusted_security_evidence>" in prompt_called
        assert "CRITICAL SECURITY RULES" in prompt_called
        assert ko.investigation.title == "Hostile Injection Attack"


# -----------------------------------------------------------------------------
# 7. Production Secret Safety Test (Part 14 / Adjustment 2)
# -----------------------------------------------------------------------------
def test_production_secret_validation_rejects_default_placeholder():
    with patch.object(settings, "ENVIRONMENT", "production"):
        with patch.object(settings, "JWT_SECRET_KEY", DEV_JWT_PLACEHOLDER):
            with pytest.raises(ValueError) as excinfo:
                validate_production_settings()
            assert "Default development JWT_SECRET_KEY detected in PRODUCTION" in str(excinfo.value)
            
        with patch.object(settings, "JWT_SECRET_KEY", "custom-production-secret-123"):
            with patch.object(settings, "INGESTION_API_KEY", DEV_INGEST_KEY_PLACEHOLDER):
                with pytest.raises(ValueError) as excinfo2:
                    validate_production_settings()
                assert "Default development INGESTION_API_KEY detected in PRODUCTION" in str(excinfo2.value)


# -----------------------------------------------------------------------------
# 8. ReplayEngine Simulation Regression Test (Adjustment 4)
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_replay_engine_simulation_regression():
    """
    Adjustment 4: Proves that ReplayEngine continues to publish to EventNormalized and downstream pipeline works alongside live ingestion.
    """
    mock_bus = MagicMock()
    mock_bus.publish = AsyncMock()
    
    engine = ReplayEngine(mock_bus)
    engine.speed_multiplier = 100.0  # Fast replay for test
    
    # Stream simulated events from credential_theft scenario
    published_events = []
    async def capture_publish(topic, payload):
        if topic == "EventNormalized":
            published_events.append(payload)
            
    mock_bus.publish.side_effect = capture_publish
    
    await engine.stream_events("credential_theft", str(uuid.uuid4()))
    
    assert len(published_events) > 0
    first_event = published_events[0]
    assert "event_type" in first_event
    assert "raw_log" in first_event
