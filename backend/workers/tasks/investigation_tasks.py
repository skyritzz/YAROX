"""
Investigation execution on Celery workers.

Investigations previously ran inside the FastAPI process, so a restart lost in-flight
work and concurrent alerts competed with request handling. The task below runs the same
orchestrator in a worker process:

  * the orchestrator is imported at module scope: the worker parent imports this module
    at startup, so forked task processes inherit it. A lazy import inside the task body
    failed with ``ModuleNotFoundError`` in the forked child on the live worker.
  * a fresh ``create_async_engine`` with ``NullPool`` is created inside the task's event
    loop, so asyncpg connections are never shared across loops or forks
  * the per-case lock (Phase 5) still applies, so API-triggered and detection-triggered
    runs cannot collide
  * agent events reach browsers through Redis pub/sub (Phase 6)
"""
import asyncio
import logging

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from agents.orchestrator import orchestrator
from core.config import settings
from workers.celery_app import celery_app

logger = logging.getLogger("yarox.orchestrator")


@celery_app.task(
    name="workers.tasks.investigation_tasks.run_investigation_task",
    bind=True,
    autoretry_for=(Exception,),
    retry_backoff=2,
    retry_backoff_max=120,
    retry_jitter=True,
    max_retries=3,
    acks_late=True,
)
def run_investigation_task(self, case_id: str) -> dict:
    """
    Runs the multi-agent investigation for a case. Returns the orchestrator outcome
    (``completed`` / ``skipped`` / ``failed``). Infrastructure failures propagate so the
    task is retried and ends visibly in FAILURE rather than silently doing nothing.
    """
    async def _run():
        engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool, echo=False)
        SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        try:
            async with SessionLocal() as session:
                logger.info("Worker starting investigation for case %s", case_id)
                # Agents must use this task's NullPool engine, not the module-level engine
                outcome = await orchestrator.run_investigation(session, case_id, session_factory=SessionLocal)
                logger.info("Worker finished investigation for case %s: %s", case_id, outcome)
                return outcome
        finally:
            await engine.dispose()

    return asyncio.run(_run())
