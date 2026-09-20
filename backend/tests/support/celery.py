"""
In-process Celery worker for tests.

Tasks dispatched in tests go to the isolated test broker (Redis DB 15, set by
the root conftest). Nothing consumes that broker unless a test explicitly runs
a worker with :func:`running_test_worker`, so dispatch never reaches the
development worker and never executes against development data.
"""
from contextlib import contextmanager

from celery.contrib.testing.worker import start_worker

from workers.celery_app import celery_app


@contextmanager
def running_test_worker(shutdown_timeout: float = 30):
    """``shutdown_timeout`` is how long the worker thread gets to exit cleanly once the
    `with` block ends — raised above the default 30s by real-LLM-backed callers (Phase 14's
    scenario orchestration tests), where a task can still be finishing housekeeping
    (autoretry bookkeeping, ack) shortly after the polling caller already observed success."""
    with start_worker(
        celery_app,
        pool="solo",
        concurrency=1,
        perform_ping_check=False,
        shutdown_timeout=shutdown_timeout,
    ) as worker:
        yield worker
