"""
Investigation events must reach browsers from whatever process produced them:

    producer (other loop/process) -> Redis pub/sub -> bridge -> WebSocket client
"""
import asyncio
import json
import uuid

import pytest
import pytest_asyncio

from core.event_stream import INVESTIGATION_EVENT_CHANNEL, InvestigationEventBridge, publish_investigation_event
from core.config import settings
from websocket.investigation_ws import ScopedConnectionManager, investigation_event_bridge, manager


class FakeWebSocket:
    """Stands in for a browser connection; records what was written to the socket."""

    def __init__(self):
        self.sent = []

    async def accept(self):
        pass

    async def send_text(self, text: str):
        self.sent.append(json.loads(text))


@pytest_asyncio.fixture
async def running_bridge():
    await investigation_event_bridge.start()
    await asyncio.wait_for(investigation_event_bridge.subscribed.wait(), timeout=5)
    yield investigation_event_bridge
    await investigation_event_bridge.stop()


async def _wait_for(condition, timeout=5.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if condition():
            return True
        await asyncio.sleep(0.05)
    return False


@pytest.mark.asyncio
async def test_event_published_from_another_process_reaches_the_websocket_client(running_bridge):
    case_id = str(uuid.uuid4())
    client = FakeWebSocket()
    await manager.connect(client, user_id="u1", case_id=case_id)
    try:
        # Publish from a separate thread with its own event loop and its own Redis
        # connection, the way a Celery worker process does.
        message = {
            "event_type": "investigation_event", "investigation_id": case_id,
            "agent_name": "Triage Analyst", "step_type": "decision_made",
            "payload": {"text": "Severity confirmed"}, "evidence_ids": [],
        }

        def publish_from_worker():
            asyncio.run(publish_investigation_event(message))

        await asyncio.to_thread(publish_from_worker)
        assert await _wait_for(lambda: len(client.sent) >= 1), "event never reached the WebSocket client"
    finally:
        manager.disconnect(client, case_id=case_id)

    delivered = client.sent[0]
    assert delivered["investigation_id"] == case_id
    assert delivered["agent_name"] == "Triage Analyst"
    assert delivered["payload"]["text"] == "Severity confirmed"


@pytest.mark.asyncio
async def test_agent_broadcast_goes_through_redis_and_reaches_clients(running_bridge):
    """An agent calling ws_manager.broadcast() must reach clients via the bridge."""
    case_id = str(uuid.uuid4())
    client = FakeWebSocket()
    await manager.connect(client, user_id="u1", case_id=case_id)
    try:
        published = await publish_investigation_event(
            {"event_type": "investigation_event", "investigation_id": case_id, "step_type": "handoff", "payload": {}},
            deliver_local=manager.deliver_local,
        )
        assert published is True  # went through Redis, not the local fallback
        assert await _wait_for(lambda: len(client.sent) >= 1)
    finally:
        manager.disconnect(client, case_id=case_id)


@pytest.mark.asyncio
async def test_local_fallback_delivers_when_redis_is_unreachable():
    case_id = str(uuid.uuid4())
    client = FakeWebSocket()
    await manager.connect(client, user_id="u1", case_id=case_id)
    try:
        original = settings.REDIS_URL
        object.__setattr__(settings, "REDIS_URL", "redis://127.0.0.1:1/15")
        try:
            published = await publish_investigation_event(
                {"event_type": "investigation_event", "investigation_id": case_id, "payload": {"text": "fallback"}},
                deliver_local=manager.deliver_local,
            )
        finally:
            object.__setattr__(settings, "REDIS_URL", original)
    finally:
        manager.disconnect(client, case_id=case_id)

    assert published is False  # Redis was unreachable
    assert client.sent[0]["payload"]["text"] == "fallback"  # but the event was not lost locally


@pytest.mark.asyncio
async def test_case_scoping_is_preserved_across_the_bridge(running_bridge):
    case_a, case_b = str(uuid.uuid4()), str(uuid.uuid4())
    client_a, client_b, global_client = FakeWebSocket(), FakeWebSocket(), FakeWebSocket()
    await manager.connect(client_a, user_id="a", case_id=case_a)
    await manager.connect(client_b, user_id="b", case_id=case_b)
    await manager.connect(global_client, user_id="g")
    try:
        await publish_investigation_event({
            "event_type": "investigation_event", "investigation_id": case_a,
            "step_type": "reasoning_complete", "payload": {"text": "case A detail"},
        })
        await publish_investigation_event({
            "event_type": "REPORT_READY", "investigation_id": case_a, "case_id": case_a,
        })
        assert await _wait_for(lambda: len(client_a.sent) >= 2)
        await asyncio.sleep(0.2)
    finally:
        for c, cid in ((client_a, case_a), (client_b, case_b), (global_client, None)):
            manager.disconnect(c, case_id=cid)

    # Detailed reasoning stays inside its case room; lifecycle events also reach global listeners
    assert [m.get("step_type") for m in client_a.sent] == ["reasoning_complete", None]
    assert client_b.sent == []
    assert [m.get("event_type") for m in global_client.sent] == ["REPORT_READY"]


@pytest.mark.asyncio
async def test_health_reports_bridge_state(running_bridge):
    from core.health import probe_ws_event_bridge

    status, detail = await probe_ws_event_bridge()
    assert status == "up"
    assert INVESTIGATION_EVENT_CHANNEL in detail

    await investigation_event_bridge.stop()
    status, detail = await probe_ws_event_bridge()
    assert status == "down"
    assert "cannot reach browsers" in detail
    await investigation_event_bridge.start()
    await asyncio.wait_for(investigation_event_bridge.subscribed.wait(), timeout=5)
