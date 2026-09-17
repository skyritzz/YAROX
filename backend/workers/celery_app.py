import os
import sys

from celery import Celery

# The backend packages (agents, memory, services, ...) have no __init__.py, so they are
# namespace packages resolved through sys.path. A Celery worker process does not
# necessarily run with the backend directory as its working directory, which made lazy
# imports inside tasks fail with ModuleNotFoundError. Make the path explicit.
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from core.config import settings  # noqa: E402

celery_app = Celery(
    "yarox_worker",
    broker=os.getenv("CELERY_BROKER_URL", settings.REDIS_URL),
    backend=os.getenv("CELERY_RESULT_BACKEND", settings.REDIS_URL),
    include=['workers.tasks.memory_tasks', 'workers.tasks.investigation_tasks']
)

# Investigations and memory indexing both run on the default queue; keep task routing
# explicit so queues can be split later without changing call sites.
celery_app.conf.task_routes = {}
