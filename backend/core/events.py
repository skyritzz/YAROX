"""
Event bus.

Two implementations share one interface:

* ``InMemoryEventBus`` — an ``asyncio.Queue`` inside one process. Events are lost on
  restart and are never seen by other processes. Kept for single-process use and tests.
* ``RedisStreamEventBus`` — a Redis Stream per topic with a consumer group. Events are
  durable, survive a restart, and can be consumed by any backend replica. Messages are
  acknowledged only after a handler succeeds, and entries left pending by a crashed
  consumer are reclaimed on startup.

Selected by ``settings.EVENT_BUS`` ("redis" by default).
"""
import asyncio
import json
import logging
import os
import socket
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

import redis.asyncio as aioredis

from core.config import settings

logger = logging.getLogger("yarox.events")

STREAM_PREFIX = "yarox:events:"
CONSUMER_GROUP = "yarox-consumers"


class EventBus(ABC):
    @abstractmethod
    def subscribe(self, topic: str, callback: Callable):
        pass

    @abstractmethod
    async def publish(self, topic: str, data: Any):
        pass


async def _invoke(callback: Callable, data: Any) -> None:
    if asyncio.iscoroutinefunction(callback):
        await callback(data)
    else:
        callback(data)


class InMemoryEventBus(EventBus):
    """Process-local bus. Events do not survive a restart and stay in this process."""

    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
        self._queue = asyncio.Queue()
        self._worker_task = None

    def subscribe(self, topic: str, callback: Callable):
        self._subscribers.setdefault(topic, []).append(callback)

    async def publish(self, topic: str, data: Any):
        await self._queue.put((topic, data))

    async def _worker(self):
        while True:
            topic, data = await self._queue.get()
            for callback in self._subscribers.get(topic, []):
                try:
                    await _invoke(callback, data)
                except Exception as e:
                    logger.exception("Error in subscriber for %s: %s", topic, e)
            self._queue.task_done()

    def start(self):
        if not self._worker_task:
            self._worker_task = asyncio.create_task(self._worker())

    def stop(self):
        if self._worker_task:
            self._worker_task.cancel()
            self._worker_task = None

    @property
    def running(self) -> bool:
        return self._worker_task is not None and not self._worker_task.done()

    def describe(self) -> Dict[str, Any]:
        return {"type": "memory", "durable": False, "topics": sorted(self._subscribers)}


class RedisStreamEventBus(EventBus):
    """
    Durable bus backed by Redis Streams.

    One stream per topic, one consumer group shared by all backend replicas: each event
    is handled by exactly one consumer, and an event survives a restart because it is
    only acknowledged after its handlers succeeded.
    """

    def __init__(self, redis_url: Optional[str] = None, consumer_name: Optional[str] = None, block_ms: int = 1000):
        self.redis_url = redis_url or settings.REDIS_URL
        self.consumer_name = consumer_name or f"{socket.gethostname()}-{os.getpid()}"
        self.block_ms = block_ms
        self._subscribers: Dict[str, List[Callable]] = {}
        self._tasks: Dict[str, asyncio.Task] = {}
        self._redis: Optional[aioredis.Redis] = None
        self._started = asyncio.Event()

    @staticmethod
    def stream_key(topic: str) -> str:
        return f"{STREAM_PREFIX}{topic}"

    async def _client(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(self.redis_url)
        return self._redis

    def subscribe(self, topic: str, callback: Callable):
        self._subscribers.setdefault(topic, []).append(callback)

    async def publish(self, topic: str, data: Any):
        client = await self._client()
        await client.xadd(self.stream_key(topic), {"payload": json.dumps(data, default=str)})

    async def _ensure_group(self, client: aioredis.Redis, topic: str) -> None:
        try:
            await client.xgroup_create(self.stream_key(topic), CONSUMER_GROUP, id="0", mkstream=True)
        except Exception as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def _handle(self, topic: str, payload: str) -> None:
        data = json.loads(payload)
        for callback in self._subscribers.get(topic, []):
            await _invoke(callback, data)

    async def _consume(self, topic: str) -> None:
        client = await self._client()
        await self._ensure_group(client, topic)
        stream = self.stream_key(topic)

        # Reclaim entries a crashed consumer left unacknowledged
        try:
            _, reclaimed, _ = await client.xautoclaim(stream, CONSUMER_GROUP, self.consumer_name, min_idle_time=60_000, count=100)
            for message_id, fields in reclaimed:
                await self._process(client, stream, topic, message_id, fields)
        except Exception as e:
            logger.warning("Could not reclaim pending events for %s: %s", topic, e)

        self._started.set()
        while True:
            try:
                response = await client.xreadgroup(
                    CONSUMER_GROUP, self.consumer_name, {stream: ">"}, count=10, block=self.block_ms
                )
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error("Event stream read failed for %s: %s", topic, e)
                await asyncio.sleep(1)
                continue
            for _stream_key, messages in response or []:
                for message_id, fields in messages:
                    await self._process(client, stream, topic, message_id, fields)

    async def _process(self, client, stream: str, topic: str, message_id, fields) -> None:
        payload = fields.get(b"payload") or fields.get("payload")
        if isinstance(payload, bytes):
            payload = payload.decode()
        try:
            await self._handle(topic, payload)
        except Exception as e:
            # Leave the entry pending so it can be reclaimed and retried instead of lost
            logger.exception("Handler failed for %s (%s): %s", topic, message_id, e)
            return
        await client.xack(stream, CONSUMER_GROUP, message_id)

    def start(self):
        for topic in self._subscribers:
            if topic not in self._tasks or self._tasks[topic].done():
                self._tasks[topic] = asyncio.create_task(self._consume(topic))

    def stop(self):
        for task in self._tasks.values():
            task.cancel()
        self._tasks = {}
        self._started.clear()

    async def wait_until_consuming(self, timeout: float = 5.0) -> bool:
        try:
            await asyncio.wait_for(self._started.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    @property
    def running(self) -> bool:
        return bool(self._tasks) and any(not t.done() for t in self._tasks.values())

    async def pending_count(self, topic: str) -> int:
        client = await self._client()
        try:
            info = await client.xpending(self.stream_key(topic), CONSUMER_GROUP)
            return int(info.get("pending", 0)) if isinstance(info, dict) else int(info[0])
        except Exception:
            return 0

    def describe(self) -> Dict[str, Any]:
        return {
            "type": "redis_streams",
            "durable": True,
            "consumer": self.consumer_name,
            "group": CONSUMER_GROUP,
            "topics": sorted(self._subscribers),
        }


def build_event_bus() -> EventBus:
    if (settings.EVENT_BUS or "redis").strip().lower() == "memory":
        return InMemoryEventBus()
    return RedisStreamEventBus()


# Global instance for the application
event_bus = build_event_bus()
