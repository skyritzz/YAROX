from celery import Celery
import os
from core.config import settings

celery_app = Celery(
    "yarox_worker",
    broker=os.getenv("CELERY_BROKER_URL", settings.REDIS_URL),
    backend=os.getenv("CELERY_RESULT_BACKEND", settings.REDIS_URL)
)

celery_app.conf.task_routes = {
    "workers.*": "main-queue"
}
