"""
Component health probes.

Every component status is derived from a live probe executed at request time.
A probe returns ``up``, ``degraded`` (reachable but not fully usable) or ``down``.

Overall status:
  * ``down``     — at least one *required* component is down (HTTP 503)
  * ``degraded`` — every required component is reachable, but something is not ``up``
  * ``ok``       — every component is ``up``
"""
import asyncio
import os
import time
from dataclasses import dataclass, asdict
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

import httpx
import redis.asyncio as aioredis
from sqlalchemy import text

from core.config import settings

UP, DEGRADED, DOWN = "up", "degraded", "down"

ProbeResult = Tuple[str, str]  # (status, detail)


@dataclass
class ComponentHealth:
    name: str
    status: str
    required: bool
    latency_ms: float
    detail: str


def _alembic_head() -> Optional[str]:
    from alembic.config import Config
    from alembic.script import ScriptDirectory

    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    cfg = Config(os.path.join(backend_dir, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(backend_dir, "alembic"))
    return ScriptDirectory.from_config(cfg).get_current_head()


async def probe_postgres() -> ProbeResult:
    from database.session import engine

    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
        version = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar_one_or_none()
    head = _alembic_head()
    if version != head:
        return DEGRADED, f"connected; schema revision {version} does not match migration head {head}"
    return UP, f"connected; schema at migration head {head}"


async def probe_redis() -> ProbeResult:
    client = aioredis.from_url(settings.REDIS_URL, socket_connect_timeout=2.0, socket_timeout=2.0)
    try:
        await client.ping()
    finally:
        await client.aclose()
    return UP, "PING ok"


async def probe_qdrant() -> ProbeResult:
    from memory.service import memory_service

    collection = memory_service.vector_repo.collection_name
    exists = await memory_service.vector_repo.qdrant.collection_exists(collection)
    if not exists:
        return DEGRADED, f"reachable; collection '{collection}' does not exist"
    info = await memory_service.vector_repo.qdrant.get_collection(collection)
    return UP, f"collection '{collection}' has {info.points_count} points"


async def probe_minio() -> ProbeResult:
    async with httpx.AsyncClient(timeout=2.0) as client:
        response = await client.get(f"{settings.MINIO_URL.rstrip('/')}/minio/health/live")
    if response.status_code != 200:
        return DOWN, f"health endpoint returned HTTP {response.status_code}"
    return UP, "live; note: no application code stores artifacts in MinIO yet"


async def probe_llm() -> ProbeResult:
    async with httpx.AsyncClient(timeout=2.5) as client:
        response = await client.get(f"{settings.OLLAMA_BASE_URL.rstrip('/')}/api/tags")
    response.raise_for_status()
    names = {m.get("name", "") for m in response.json().get("models", [])}
    model = settings.OLLAMA_MODEL
    available = model in names or (":" not in model and f"{model}:latest" in names)
    if not available:
        return DEGRADED, f"Ollama reachable; configured model '{model}' is not installed"
    return UP, f"Ollama reachable; model '{model}' installed"


async def probe_celery_worker() -> ProbeResult:
    from workers.celery_app import celery_app

    replies = await asyncio.to_thread(celery_app.control.ping, timeout=1.0)
    if not replies:
        return DOWN, "no Celery worker replied to ping"
    workers = sorted(name for reply in replies for name in reply)
    return UP, f"{len(workers)} worker(s): {', '.join(workers)}"


async def probe_event_bus() -> ProbeResult:
    from core.events import event_bus

    task = event_bus._worker_task
    if task is None:
        return DOWN, "in-process event bus worker not started"
    if task.done():
        return DOWN, "in-process event bus worker has stopped"
    return UP, "in-process event bus worker running (single process only)"


# name -> (probe, required)
PROBES: Dict[str, Tuple[Callable[[], Awaitable[ProbeResult]], bool]] = {
    "postgres": (probe_postgres, True),
    "redis": (probe_redis, True),
    "qdrant": (probe_qdrant, True),
    "event_bus": (probe_event_bus, True),
    "llm": (probe_llm, False),
    "celery_worker": (probe_celery_worker, False),
    "minio": (probe_minio, False),
}


async def _run_probe(name: str, probe: Callable[[], Awaitable[ProbeResult]], required: bool) -> ComponentHealth:
    start = time.perf_counter()
    timeout = settings.HEALTH_PROBE_TIMEOUT_SECONDS
    try:
        status, detail = await asyncio.wait_for(probe(), timeout=timeout)
    except asyncio.TimeoutError:
        status, detail = DOWN, f"probe timed out after {timeout:.1f}s"
    except Exception as e:
        status, detail = DOWN, f"{type(e).__name__}: {e}"
    return ComponentHealth(
        name=name,
        status=status,
        required=required,
        latency_ms=round((time.perf_counter() - start) * 1000.0, 1),
        detail=detail,
    )


def overall_status(components: List[ComponentHealth]) -> str:
    if any(c.required and c.status == DOWN for c in components):
        return DOWN
    if any(c.status != UP for c in components):
        return DEGRADED
    return "ok"


async def check_health() -> Dict:
    components = await asyncio.gather(*(
        _run_probe(name, probe, required) for name, (probe, required) in PROBES.items()
    ))
    return {
        "status": overall_status(components),
        "components": {c.name: asdict(c) for c in components},
    }
