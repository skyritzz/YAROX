"""
Distributed per-case locking.

A lock is a Redis key holding a unique token, set with ``SET NX PX``:

  * Only one holder can own a case at a time, across processes and containers.
  * The key carries a TTL, so a crashed holder's lock expires instead of blocking
    the case forever.
  * While the work runs, the holder refreshes the TTL (heartbeat), so a long but
    healthy investigation never loses its lock.
  * Release is compare-and-delete on the token, so a holder can never release a
    lock that has already expired and been taken by someone else.
"""
import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Optional

import redis.asyncio as aioredis

from core.config import settings

logger = logging.getLogger("yarox.locks")

# Delete the key only if it still holds our token
_RELEASE_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
else
    return 0
end
"""

# Extend the TTL only if we still hold the lock
_REFRESH_SCRIPT = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('pexpire', KEYS[1], ARGV[2])
else
    return 0
end
"""


class LockNotAcquired(Exception):
    """Raised when a lock is already held by someone else."""


class RedisLock:
    def __init__(self, key: str, ttl_seconds: float, refresh_interval: Optional[float] = None, redis_url: Optional[str] = None):
        self.key = key
        self.ttl_seconds = ttl_seconds
        self.refresh_interval = refresh_interval if refresh_interval is not None else max(ttl_seconds / 3.0, 1.0)
        self.redis_url = redis_url or settings.REDIS_URL
        self.token = str(uuid.uuid4())
        self._redis: Optional[aioredis.Redis] = None
        self._heartbeat: Optional[asyncio.Task] = None

    async def acquire(self) -> bool:
        self._redis = aioredis.from_url(self.redis_url, socket_connect_timeout=2.0, socket_timeout=2.0)
        acquired = await self._redis.set(self.key, self.token, nx=True, px=int(self.ttl_seconds * 1000))
        if not acquired:
            await self._redis.aclose()
            self._redis = None
            return False
        self._heartbeat = asyncio.create_task(self._refresh_loop())
        return True

    async def _refresh_loop(self):
        try:
            while True:
                await asyncio.sleep(self.refresh_interval)
                extended = await self._redis.eval(_REFRESH_SCRIPT, 1, self.key, self.token, int(self.ttl_seconds * 1000))
                if not extended:
                    logger.warning("Lock %s was lost before the work finished", self.key)
                    return
        except asyncio.CancelledError:
            raise
        except Exception as e:  # a failing heartbeat must not kill the work
            logger.warning("Lock heartbeat for %s failed: %s", self.key, e)

    async def release(self) -> bool:
        if self._heartbeat is not None:
            self._heartbeat.cancel()
            try:
                await self._heartbeat
            except (asyncio.CancelledError, Exception):
                pass
            self._heartbeat = None
        if self._redis is None:
            return False
        try:
            released = await self._redis.eval(_RELEASE_SCRIPT, 1, self.key, self.token)
            return bool(released)
        finally:
            await self._redis.aclose()
            self._redis = None

    async def is_held_by_us(self) -> bool:
        if self._redis is None:
            return False
        value = await self._redis.get(self.key)
        return value is not None and value.decode() == self.token


def investigation_lock_key(case_id) -> str:
    return f"yarox:lock:investigation:{case_id}"


def rerun_flag_key(case_id) -> str:
    return f"yarox:investigation:rerun_requested:{case_id}"


@asynccontextmanager
async def investigation_lock(case_id, ttl_seconds: Optional[float] = None):
    """
    Context manager yielding True when the case lock was acquired, False otherwise.
    Callers must not start an investigation when it yields False.
    """
    lock = RedisLock(
        key=investigation_lock_key(case_id),
        ttl_seconds=ttl_seconds if ttl_seconds is not None else settings.INVESTIGATION_LOCK_TTL_SECONDS,
    )
    acquired = await lock.acquire()
    try:
        yield acquired
    finally:
        if acquired:
            await lock.release()


async def request_rerun(case_id) -> None:
    """Records that evidence arrived while an investigation was already running."""
    client = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=2.0, socket_timeout=2.0)
    try:
        await client.set(rerun_flag_key(case_id), "1", ex=3600)
    finally:
        await client.aclose()


async def consume_rerun_request(case_id) -> bool:
    """Returns True (and clears the flag) when a re-run was requested."""
    client = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=2.0, socket_timeout=2.0)
    try:
        return bool(await client.delete(rerun_flag_key(case_id)))
    finally:
        await client.aclose()
