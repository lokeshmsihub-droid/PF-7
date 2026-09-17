from celery import Celery
from app.core.config import settings

celery_app = Celery(
    "compliance_scanner_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.scan_worker"]
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=settings.EXECUTION_TIMEOUT_SECONDS,
    worker_concurrency=4
)
