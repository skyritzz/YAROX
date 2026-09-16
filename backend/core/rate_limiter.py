import time
import hashlib
from typing import Tuple, Optional
import redis.asyncio as aioredis
from fastapi import HTTPException, status
from core.config import settings

class IngestionRateLimiter:
    def __init__(self):
        self._redis: Optional[aioredis.Redis] = None

    async def get_redis(self) -> aioredis.Redis:
        if self._redis is None:
            self._redis = aioredis.from_url(
                settings.REDIS_URL,
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0
            )
        return self._redis

    async def check_rate_limit(self, client_identifier: str) -> Tuple[bool, int]:
        """
        Enforces rate limiting using Redis with a fail-closed policy.
        
        Returns:
            (is_allowed: bool, retry_after: int)
            
        Raises:
            HTTPException(503): When Redis is unavailable (Fail-Closed to protect YAROX from unthrottled floods).
        """
        key_hash = hashlib.sha256(client_identifier.encode()).hexdigest()[:16]
        current_minute = int(time.time() // 60)
        redis_key = f"ratelimit:ingest:{key_hash}:{current_minute}"
        
        try:
            r = await self.get_redis()
            # Atomic increment and expire
            pipe = r.pipeline()
            pipe.incr(redis_key)
            pipe.expire(redis_key, 90)  # 90 second TTL
            results = await pipe.execute()
            
            current_count = results[0]
            if current_count > settings.RATE_LIMIT_INGEST_PER_MINUTE:
                retry_after = 60 - int(time.time() % 60)
                return False, max(1, retry_after)
                
            return True, 0
            
        except Exception as e:
            # Adjustment 1: Fail Closed when Redis is unavailable to protect YAROX ingestion
            print(f"[SECURITY AUDIT] Redis rate limiter connection failed: {e}. Failing closed with 503.")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Telemetry ingestion rate limiter is temporarily unavailable. Request rejected under fail-closed security policy."
            )

    async def close(self):
        if self._redis:
            await self._redis.close()
            self._redis = None

ingestion_rate_limiter = IngestionRateLimiter()
