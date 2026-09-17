"""
Background execution of investigations from the API process.

A background task must never use the request-scoped database session: that session is
closed once the response has been returned. Each run creates and owns its own session.

This is the in-process runner; Phase 7 moves execution to a Celery worker.
"""
import logging

from agents.orchestrator import orchestrator
from database.session import AsyncSessionLocal

logger = logging.getLogger("yarox.orchestrator")


async def run_investigation_in_background(case_id: str) -> dict:
    async with AsyncSessionLocal() as session:
        outcome = await orchestrator.run_investigation(session, case_id)
    logger.info("Background investigation for case %s finished: %s", case_id, outcome)
    return outcome
