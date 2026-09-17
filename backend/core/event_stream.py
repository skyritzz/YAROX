"""
Cross-process delivery of investigation events.

The WebSocket connections live in the API process, but investigations run elsewhere
(a background task today, a Celery worker from Phase 7). Events are therefore published
to a Redis pub/sub channel, and every API process subscribes and fans the messages out
to its own connected clients:

    agent (any process) -> publish_investigation_event -> Redis channel
                        -> InvestigationEventBridge (each API process)
                        -> ScopedConnectionManager.deliver_local -> browser

If Redis cannot be reached the event is delivered to local connections directly, so a
single-process deployment keeps working, and the health report shows the bridge as down.
"""
import asyncio
import json
import logging
from typing import Awaitable, Callable, Optional

import redis.asyncio as aioredis

from core.config import settings

logger = logging.getLogger("yarox.events")

INVESTIGATION_EVENT_CHANNEL = "yarox:ws:investigations"


async def publish_investigation_event(message: dict, deliver_local: Optional[Callable[[dict], Awaitable[None]]] = None) -> bool:
    """
    Publishes an investigation event. Returns True when it went through Redis.
    On failure the message is delivered to local connections (if a delivery callback is
    given) so events are not silently lost in a single-process deployment.
    """
    client = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=2.0, socket_timeout=2.0)
    try:
        await client.publish(INVESTIGATION_EVENT_CHANNEL, json.dumps(message))
        return True
    except Exception as e:
        logger.warning("Could not publish investigation event to Redis: %s", e)
        if deliver_local is not None:
            await deliver_local(message)
        return False
    finally:
        try:
            await client.aclose()
        except Exception:
            pass


class InvestigationEventBridge:
    """Subscribes to the investigation event channel and delivers messages locally."""

    def __init__(self, deliver: Callable[[dict], Awaitable[None]]):
        self.deliver = deliver
        self._task: Optional[asyncio.Task] = None
        self._redis: Optional[aioredis.Redis] = None
        self._pubsub = None
        self.subscribed = asyncio.Event()

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    async def start(self) -> None:
        if self.running:
            return
        self.subscribed.clear()
        self._task = asyncio.create_task(self._run())

    async def _run(self) -> None:
        try:
            self._redis = aioredis.from_url(settings.REDIS_URL)
            self._pubsub = self._redis.pubsub()
            await self._pubsub.subscribe(INVESTIGATION_EVENT_CHANNEL)
            self.subscribed.set()
            logger.info("Investigation event bridge subscribed to %s", INVESTIGATION_EVENT_CHANNEL)
            async for message in self._pubsub.listen():
                if message.get("type") != "message":
                    continue
                try:
                    await self.deliver(json.loads(message["data"]))
                except Exception as e:
                    logger.warning("Failed to deliver investigation event: %s", e)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Investigation event bridge stopped: %s", e)
        finally:
            self.subscribed.clear()
            await self._cleanup()

    async def _cleanup(self) -> None:
        try:
            if self._pubsub is not None:
                await self._pubsub.unsubscribe(INVESTIGATION_EVENT_CHANNEL)
                await self._pubsub.aclose()
        except Exception:
            pass
        try:
            if self._redis is not None:
                await self._redis.aclose()
        except Exception:
            pass
        self._pubsub = None
        self._redis = None

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        await self._cleanup()
