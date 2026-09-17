import logging
from app.workers.celery_app import celery_app
from app.database.session import SessionLocal
from app.orchestrator.orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, name="app.workers.scan_worker.run_scan_task", max_retries=1)
def run_scan_task(self, scan_job_id: str):
    """
    Celery background worker task for running an isolated security scan job.
    """
    logger.info(f"Starting Celery scan task for ScanJob {scan_job_id}")
    db = SessionLocal()
    try:
        orchestrator = ScanOrchestrator(db=db)
        completed_job = orchestrator.execute_scan(scan_job_id=scan_job_id)
        logger.info(f"ScanJob {scan_job_id} successfully completed. Findings: {completed_job.finding_count}")
        return {
            "status": "COMPLETED",
            "scan_id": scan_job_id,
            "findings_count": completed_job.finding_count
        }
    except Exception as exc:
        logger.error(f"ScanJob {scan_job_id} failed: {exc}", exc_info=True)
        try:
            from app.database.models import ScanJob, ScanStatus
            job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            if job and job.status != ScanStatus.FAILED.value:
                job.status = ScanStatus.FAILED.value
                job.error_message = f"Celery worker error: {str(exc)}"
                db.commit()
        except Exception:
            pass
        return {
            "status": "FAILED",
            "scan_id": scan_job_id,
            "error": str(exc)
        }
    finally:
        db.close()
