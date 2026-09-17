"""
Dispatching investigations.

Investigations execute on Celery workers (``workers.tasks.investigation_tasks``), not in
the API process. Callers dispatch and return immediately; progress reaches browsers over
the WebSocket bridge.

``run_investigation_in_background`` remains for in-process execution (used by tests and
as an explicit fallback): it never uses a request-scoped session, because that session is
closed once the response has been returned.
"""
import logging
from typing import Optional

from agents.orchestrator import orchestrator
from database.session import AsyncSessionLocal
from workers.tasks.investigation_tasks import run_investigation_task

logger = logging.getLogger("yarox.orchestrator")


class InvestigationDispatchError(Exception):
    """Raised when an investigation could not be handed to a worker."""


def dispatch_investigation(case_id: str) -> str:
    """Queues the investigation on a Celery worker and returns the task id."""
    try:
        task = run_investigation_task.delay(str(case_id))
    except Exception as e:  # broker unreachable
        logger.error("Could not dispatch investigation for case %s: %s", case_id, e)
        raise InvestigationDispatchError(str(e)) from e
    logger.info("Dispatched investigation for case %s as task %s", case_id, task.id)
    return task.id


async def run_investigation_in_background(case_id: str) -> dict:
    """Runs an investigation in this process using a session it owns."""
    async with AsyncSessionLocal() as session:
        outcome = await orchestrator.run_investigation(session, case_id)
    logger.info("In-process investigation for case %s finished: %s", case_id, outcome)
    return outcome
