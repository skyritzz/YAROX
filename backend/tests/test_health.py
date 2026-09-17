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
from websocket.investigation_ws import investigation_event_bridge
import asyncio


@pytest_asyncio.fixture
async def running_event_bus():
    """Starts the in-process components that /health requires."""
    event_bus.start()
    await investigation_event_bridge.start()
    await asyncio.wait_for(investigation_event_bridge.subscribed.wait(), timeout=5)
    yield
    event_bus.stop()
    await investigation_event_bridge.stop()


async def _get_health():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        return await ac.get("/health")


@pytest.mark.asyncio
async def test_health_reports_live_component_probes(running_event_bus):
    res = await _get_health()
    body = res.json()

    assert "infrastructure" not in body  # legacy hardcoded block is gone
    components = body["components"]
    assert set(components) == {"postgres", "redis", "qdrant", "event_bus", "ws_event_bridge", "llm", "celery_worker", "minio"}
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
    assert components["ws_event_bridge"]["status"] == "up"
    # No Celery worker runs alongside the test process, and investigations cannot run
    # without one, so the required component is reported down and the API says so.
    assert components["celery_worker"]["status"] == "down"
    assert "investigations cannot run" in components["celery_worker"]["detail"]
    assert res.status_code == 503
    assert body["status"] == "down"


@pytest.mark.asyncio
async def test_health_is_ok_when_a_worker_is_running(running_event_bus):
    from tests.support.celery import running_test_worker

    with running_test_worker():
        res = await _get_health()
    body = res.json()
    assert body["components"]["celery_worker"]["status"] == "up"
    assert "worker(s)" in body["components"]["celery_worker"]["detail"]
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
    with patch.object(settings, "LLM_BASE_URL", "http://127.0.0.1:1"):
        res = await _get_health()
    body = res.json()
    assert body["components"]["llm"]["status"] == "down"
    assert body["components"]["llm"]["required"] is False
    # The LLM is not required for the API to serve; the failing required component here
    # is the absent Celery worker, so this asserts only the LLM reporting itself.
    assert body["components"]["llm"]["detail"]


@pytest.mark.asyncio
async def test_health_llm_missing_model_is_degraded(running_event_bus):
    with patch.object(settings, "LLM_MODEL", "yarox-model-that-does-not-exist"):
        res = await _get_health()
    llm = res.json()["components"]["llm"]
    # Either Ollama is unreachable from this environment (down) or it reports the model missing
    assert llm["status"] in ("degraded", "down")
    if llm["status"] == "degraded":
        assert "is not installed" in llm["detail"]
        assert "yarox-model-that-does-not-exist" in llm["detail"]
