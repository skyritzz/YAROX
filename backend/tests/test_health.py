"""
/health must report live probe results, never static values.
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import patch

from api.main import app
from core.config import settings
from core.events import event_bus


@pytest_asyncio.fixture
async def running_event_bus():
    event_bus.start()
    yield
    event_bus.stop()


async def _get_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        return await ac.get("/health")


@pytest.mark.asyncio
async def test_health_reports_live_component_probes(running_event_bus):
    res = await _get_health()
    body = res.json()

    assert "infrastructure" not in body  # legacy hardcoded block is gone
    components = body["components"]
    assert set(components) == {"postgres", "redis", "qdrant", "event_bus", "llm", "celery_worker", "minio"}
    for component in components.values():
        assert component["status"] in ("up", "degraded", "down")
        assert isinstance(component["latency_ms"], float)
        assert component["detail"]

    # Test infrastructure is running, so the required data stores must be reachable
    assert components["postgres"]["status"] == "up"
    assert "migration head" in components["postgres"]["detail"]
    assert components["redis"]["status"] == "up"
    assert components["qdrant"]["status"] in ("up", "degraded")
    assert components["event_bus"]["status"] == "up"
    assert res.status_code == 200
    assert body["status"] in ("ok", "degraded")


@pytest.mark.asyncio
async def test_health_returns_503_when_required_redis_is_unreachable(running_event_bus):
    with patch.object(settings, "REDIS_URL", "redis://127.0.0.1:1/15"):
        res = await _get_health()
    body = res.json()
    assert res.status_code == 503
    assert body["status"] == "down"
    assert body["components"]["redis"]["status"] == "down"
    assert body["components"]["redis"]["required"] is True


@pytest.mark.asyncio
async def test_health_marks_event_bus_down_when_not_started():
    event_bus.stop()
    res = await _get_health()
    body = res.json()
    assert body["components"]["event_bus"]["status"] == "down"
    assert res.status_code == 503


@pytest.mark.asyncio
async def test_health_llm_unreachable_is_reported_but_not_fatal(running_event_bus):
    with patch.object(settings, "OLLAMA_BASE_URL", "http://127.0.0.1:1"):
        res = await _get_health()
    body = res.json()
    assert body["components"]["llm"]["status"] == "down"
    assert body["components"]["llm"]["required"] is False
    assert res.status_code == 200
    assert body["status"] == "degraded"


@pytest.mark.asyncio
async def test_health_llm_missing_model_is_degraded(running_event_bus):
    with patch.object(settings, "OLLAMA_MODEL", "yarox-model-that-does-not-exist"):
        res = await _get_health()
    llm = res.json()["components"]["llm"]
    # Either Ollama is unreachable from this environment (down) or it reports the model missing
    assert llm["status"] in ("degraded", "down")
    if llm["status"] == "degraded":
        assert "not installed" in llm["detail"]
