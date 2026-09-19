"""
Durable event bus (Redis Streams) and shared detection state.

These tests run against the real Redis test database and simulate two backend replicas
by creating two bus instances with different consumer names.
"""
import asyncio
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from core.config import settings
from core.events import CONSUMER_GROUP, InMemoryEventBus, RedisStreamEventBus, build_event_bus
from detection.rules import FailedLoginBruteForce, LateralMovement
from detection.state import detection_state
from models.event import Event


@pytest_asyncio.fixture
async def redis_client():
    client = aioredis.from_url(settings.REDIS_URL)
    yield client
    await client.aclose()


def unique_topic() -> str:
    return f"TestTopic_{uuid.uuid4().hex[:8]}"


async def _wait_for(condition, timeout=5.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        if condition():
            return True
        await asyncio.sleep(0.05)
    return False


# ---------------------------------------------------------------- durability

@pytest.mark.asyncio
async def test_event_published_before_any_consumer_starts_is_not_lost(redis_client):
    """A restart must not drop events: the stream holds them until a consumer acks."""
    topic = unique_topic()
    producer = RedisStreamEventBus(consumer_name="producer")
    try:
        # Publish while nothing is consuming (the in-memory bus would lose this)
        await producer.publish(topic, {"id": "first"})
        await producer.publish(topic, {"id": "second"})

        received = []
        consumer = RedisStreamEventBus(consumer_name="consumer-after-restart", block_ms=100)
        consumer.subscribe(topic, lambda data: received.append(data))
        consumer.start()
        try:
            assert await _wait_for(lambda: len(received) == 2)
        finally:
            consumer.stop()
    finally:
        await redis_client.delete(RedisStreamEventBus.stream_key(topic))

    assert [r["id"] for r in received] == ["first", "second"]


@pytest.mark.asyncio
async def test_each_event_is_handled_once_across_two_replicas(redis_client):
    topic = unique_topic()
    handled_a, handled_b = [], []

    replica_a = RedisStreamEventBus(consumer_name="replica-a", block_ms=100)
    replica_b = RedisStreamEventBus(consumer_name="replica-b", block_ms=100)
    replica_a.subscribe(topic, lambda d: handled_a.append(d["id"]))
    replica_b.subscribe(topic, lambda d: handled_b.append(d["id"]))
    replica_a.start()
    replica_b.start()
    try:
        for index in range(6):
            await replica_a.publish(topic, {"id": index})
        assert await _wait_for(lambda: len(handled_a) + len(handled_b) == 6)
        await asyncio.sleep(0.3)  # allow any duplicate delivery to show up
    finally:
        replica_a.stop()
        replica_b.stop()
        await redis_client.delete(RedisStreamEventBus.stream_key(topic))

    assert sorted(handled_a + handled_b) == list(range(6))  # exactly once, no duplicates


@pytest.mark.asyncio
async def test_failed_handler_leaves_the_event_unacknowledged_for_retry(redis_client):
    topic = unique_topic()
    attempts = []

    async def failing_handler(data):
        attempts.append(data["id"])
        raise RuntimeError("handler exploded")

    bus = RedisStreamEventBus(consumer_name="failing-consumer", block_ms=100)
    bus.subscribe(topic, failing_handler)
    bus.start()
    try:
        await bus.publish(topic, {"id": "needs-retry"})
        assert await _wait_for(lambda: attempts)
        await asyncio.sleep(0.2)
        pending = await bus.pending_count(topic)
    finally:
        bus.stop()

    assert pending == 1, "a failed handler must not acknowledge the event"

    # A later consumer can reclaim it (idle time 0 for the test) and complete the work
    recovered = []
    client = await bus._client()
    _, reclaimed, _ = await client.xautoclaim(
        RedisStreamEventBus.stream_key(topic), CONSUMER_GROUP, "recovery-consumer", min_idle_time=0, count=10
    )
    for message_id, fields in reclaimed:
        recovered.append(fields[b"payload"].decode())
        await client.xack(RedisStreamEventBus.stream_key(topic), CONSUMER_GROUP, message_id)

    assert len(recovered) == 1 and "needs-retry" in recovered[0]
    assert await bus.pending_count(topic) == 0
    await redis_client.delete(RedisStreamEventBus.stream_key(topic))


@pytest.mark.asyncio
async def test_successful_handler_acknowledges_the_event(redis_client):
    topic = unique_topic()
    handled = []
    bus = RedisStreamEventBus(consumer_name="acking-consumer", block_ms=100)
    bus.subscribe(topic, lambda d: handled.append(d))
    bus.start()
    try:
        await bus.publish(topic, {"id": "ok"})
        assert await _wait_for(lambda: handled)
        await asyncio.sleep(0.2)
        assert await bus.pending_count(topic) == 0
    finally:
        bus.stop()
        await redis_client.delete(RedisStreamEventBus.stream_key(topic))


def test_bus_selection_and_descriptions():
    assert settings.EVENT_BUS == "redis"
    assert isinstance(build_event_bus(), RedisStreamEventBus)
    assert build_event_bus().describe()["durable"] is True
    memory = InMemoryEventBus()
    assert memory.describe() == {"type": "memory", "durable": False, "topics": []}


# ---------------------------------------------------------------- shared detection state

def _auth_failure_event(user: str, moment: datetime) -> Event:
    return Event(
        id=uuid.uuid4(), timestamp=moment, hostname="WS-1", user_name=user, source="Windows Security",
        event_type="Login Failed", severity="LOW", raw_log={"metadata": {"reason": "Bad Password"}},
    )


def _logon_event(user: str, host: str, moment: datetime) -> Event:
    return Event(
        id=uuid.uuid4(), timestamp=moment, hostname=host, user_name=user, source="Windows Security",
        event_type="Remote Session", severity="INFO", raw_log={"metadata": {}},
    )


@pytest.mark.asyncio
async def test_brute_force_window_is_shared_between_two_instances():
    """
    Two rule instances stand in for two backend replicas. With process-local counters
    each would see one failure and neither would fire.
    """
    user = f"svc_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    replica_a, replica_b = FailedLoginBruteForce(), FailedLoginBruteForce()

    assert await replica_a.match(_auth_failure_event(user, now)) is False
    # The second failure arrives at the other replica and still trips the threshold
    assert await replica_b.match(_auth_failure_event(user, now + timedelta(seconds=5))) is True

    # The window was reset after firing, so a single later failure does not re-fire
    assert await replica_a.match(_auth_failure_event(user, now + timedelta(seconds=10))) is False


@pytest.mark.asyncio
async def test_brute_force_ignores_failures_outside_the_window():
    user = f"svc_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    rule = FailedLoginBruteForce()
    assert await rule.match(_auth_failure_event(user, now)) is False
    # 10 minutes later: outside the 5 minute window, so the earlier failure is dropped
    assert await rule.match(_auth_failure_event(user, now + timedelta(minutes=10))) is False


@pytest.mark.asyncio
async def test_lateral_movement_counts_distinct_hosts_across_instances():
    user = f"user_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    replica_a, replica_b = LateralMovement(), LateralMovement()

    assert await replica_a.match(_logon_event(user, "host-1", now)) is False
    assert await replica_b.match(_logon_event(user, "host-2", now + timedelta(seconds=30))) is False
    # Third distinct host, seen by the first replica, exceeds the threshold
    assert await replica_a.match(_logon_event(user, "host-3", now + timedelta(seconds=60))) is True


@pytest.mark.asyncio
async def test_repeated_host_does_not_inflate_the_count():
    user = f"user_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    rule = LateralMovement()
    for index in range(5):
        fired = await rule.match(_logon_event(user, "same-host", now + timedelta(seconds=index)))
        assert fired is False  # one host, however many logons


@pytest.mark.asyncio
async def test_detection_state_expires_and_is_inspectable(redis_client):
    entity = f"entity_{uuid.uuid4().hex[:8]}"
    now = datetime.now(timezone.utc)
    count = await detection_state.observe("TestRule", entity, member="e1", moment=now, window_seconds=60)
    assert count == 1
    key = detection_state.key("TestRule", entity)
    assert await redis_client.exists(key) == 1
    assert 0 < await redis_client.ttl(key) <= 120  # window + grace, so idle entities clean up
    await detection_state.reset("TestRule", entity)
    assert await redis_client.exists(key) == 0


# --------------------------------------------------------- real consumer, real JSON round trip

@pytest.mark.asyncio
async def test_event_normalized_survives_the_real_bus_round_trip_and_is_stored(redis_client):
    """
    Regression test. RedisStreamEventBus.publish() JSON-encodes the payload
    (json.dumps(data, default=str)), which turns ``timestamp`` into a string on the
    wire; consumers.db_writer.handle_event_normalized used to pass that string
    straight into compute_event_hash()/Event(), which requires a real datetime and
    raised - but because the handler swallowed its own exceptions, the bus still
    acknowledged the message and the event was silently lost forever. Every other
    test that exercises handle_event_normalized calls it directly as a plain Python
    function with a real datetime already in the dict, which never round-trips
    through JSON and so never exercised this path - that is how the bug shipped
    with a fully green suite. This test publishes through the real bus's publish()
    and lets the real consume loop deliver it, the same as a live backend restart
    proved live against the running stack (see docs/YAROX_REALITY_AUDIT.md Phase 10).
    """
    import uuid as uuid_mod

    from sqlalchemy import select

    from consumers.db_writer import handle_event_normalized
    from database.session import AsyncSessionLocal
    from models.event import Event

    topic = unique_topic()
    event_id = uuid_mod.uuid4()
    payload = {
        "id": str(event_id),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "hostname": "EVENT-BUS-ROUNDTRIP-TEST",
        "user_name": "roundtrip_user",
        "source": "sysmon",
        "event_type": "PROCESS_EXECUTION",
        "severity": "INFO",
        "raw_log": {"EventID": 4688},
        "metadata_": {},
    }

    bus = RedisStreamEventBus(consumer_name="roundtrip-consumer", block_ms=100)
    bus.subscribe(topic, handle_event_normalized)
    bus.start()
    try:
        await bus.publish(topic, payload)

        async def _is_stored() -> bool:
            async with AsyncSessionLocal() as session:
                result = await session.execute(select(Event).where(Event.id == event_id))
                return result.scalar_one_or_none() is not None

        stored = False
        for _ in range(50):
            if await _is_stored():
                stored = True
                break
            await asyncio.sleep(0.1)

        assert stored, "an event published through the real bus must be durably stored, not silently dropped"
        await asyncio.sleep(0.2)
        assert await bus.pending_count(topic) == 0, "must only be acknowledged after it is actually stored"
    finally:
        bus.stop()
        await redis_client.delete(RedisStreamEventBus.stream_key(topic))


@pytest.mark.asyncio
async def test_handle_event_normalized_deserializes_a_string_timestamp():
    """Narrower unit-level regression for the same bug, independent of Redis timing."""
    import uuid as uuid_mod

    from sqlalchemy import select

    from consumers.db_writer import handle_event_normalized
    from database.session import AsyncSessionLocal
    from models.event import Event

    event_id = uuid_mod.uuid4()
    data = {
        "id": str(event_id),
        "timestamp": "2026-09-19T06:30:00+00:00",  # string, as it arrives after a JSON round trip
        "hostname": "H1",
        "user_name": "u1",
        "source": "sysmon",
        "event_type": "PROCESS_EXECUTION",
        "severity": "INFO",
        "raw_log": {},
        "metadata_": {},
    }
    await handle_event_normalized(data)
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Event).where(Event.id == event_id))
        stored = result.scalar_one_or_none()
    assert stored is not None
    assert stored.timestamp.isoformat() == "2026-09-19T06:30:00+00:00"
