"""
Shared detection state.

Stateful rules (failed-login bursts, lateral movement) count events across a time
window. Keeping those counters in process memory meant two backend or worker replicas
each saw half the events and neither reached the threshold, and a restart silently reset
every window. The counters live in Redis instead, so every replica sees the same state.

Each window is a Redis sorted set scored by event time:
  * entries older than the window are trimmed on every observation
  * the key expires after the window, so idle entities leave nothing behind
  * ``reset`` clears a window after a rule fires, matching the previous behaviour
"""
import logging
from datetime import datetime, timezone
from typing import Optional

import redis.asyncio as aioredis

from core.config import settings

logger = logging.getLogger("yarox.detection")

KEY_PREFIX = "yarox:detection:"


def _epoch(moment: datetime) -> float:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


class DetectionStateStore:
    """Sliding-window counters shared by all processes."""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.REDIS_URL
        self._redis: Optional[aioredis.Redis] = None

    async def _client(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(self.redis_url, socket_connect_timeout=2.0, socket_timeout=2.0)
        return self._redis

    @staticmethod
    def key(rule: str, entity: str) -> str:
        return f"{KEY_PREFIX}{rule}:{entity}"

    async def observe(self, rule: str, entity: str, member: str, moment: datetime, window_seconds: float) -> int:
        """
        Records an observation and returns how many observations fall inside the window.
        """
        client = await self._client()
        key = self.key(rule, entity)
        now = _epoch(moment)
        pipe = client.pipeline()
        pipe.zremrangebyscore(key, "-inf", now - window_seconds)
        pipe.zadd(key, {member: now})
        pipe.zcard(key)
        pipe.expire(key, int(window_seconds) + 60)
        results = await pipe.execute()
        return int(results[2])

    async def distinct_values(self, rule: str, entity: str, value: str, moment: datetime, window_seconds: float) -> int:
        """
        Records ``value`` for an entity and returns how many distinct values fall inside
        the window (used for "same user, several hosts" style rules).
        """
        return await self.observe(rule, entity, value, moment, window_seconds)

    async def reset(self, rule: str, entity: str) -> None:
        client = await self._client()
        await client.delete(self.key(rule, entity))

    async def close(self) -> None:
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None


detection_state = DetectionStateStore()
