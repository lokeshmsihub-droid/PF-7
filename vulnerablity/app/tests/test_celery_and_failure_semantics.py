import uuid
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.database.session import get_db
from app.database.models import ScanJob, ScanStatus, CanonicalSecurityFinding
from app.core.config import settings

def test_celery_enqueue_returns_202_and_queued(db_session):
    """
    Verify that in celery execution mode, POST /scans/ enqueues to worker,
    returns HTTP 202 immediately with status QUEUED without executing in-process.
    """
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)

    with patch("app.core.config.settings.SCAN_EXECUTION_MODE", "celery"), \
         patch("app.workers.scan_worker.run_scan_task.delay") as mock_delay:
        mock_delay.return_value = MagicMock(id="task-celery-12345")

        resp = client.post(
            "/api/v1/scans/",
            json={
                "repository_id": "repo-celery-mode-1",
                "repository_name": "org/repo-celery",
                "branch": "main",
                "commit_sha": "abc111222333444555",
                "scan_type": "SAST"
            },
            headers={"X-Tenant-ID": "1"}
        )

        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "QUEUED"
        scan_id = data["id"]

        # Celery .delay must be called with scan_id
        mock_delay.assert_called_once_with(scan_id)

        # Database state must be QUEUED
        job = db_session.query(ScanJob).filter(ScanJob.id == scan_id).first()
        assert job is not None
        assert job.status == ScanStatus.QUEUED.value

    app.dependency_overrides.clear()

def test_redis_offline_returns_503_and_no_sync_fallback(db_session):
    """
    CRITICAL PRODUCTION REQUIREMENT:
    When Redis is offline in celery mode, API MUST NOT silently execute scans in-process!
    It must return HTTP 503 and mark the ScanJob as FAILED.
    """
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)

    with patch("app.core.config.settings.SCAN_EXECUTION_MODE", "celery"), \
         patch("app.workers.scan_worker.run_scan_task.delay", side_effect=ConnectionRefusedError("Error 61 connecting to localhost:6379")):
        
        resp = client.post(
            "/api/v1/scans/",
            json={
                "repository_id": "repo-broker-down",
                "repository_name": "org/broker-down",
                "branch": "main",
                "commit_sha": "deadbeef00000000000000000000000000000000",
                "scan_type": "SAST"
            },
            headers={"X-Tenant-ID": "1"}
        )

        # Must return HTTP 503
        assert resp.status_code == 503
        detail = resp.json()["detail"]
        assert "broker offline" in detail or "broker error" in detail

        # Verify job is recorded as FAILED in DB and not completed
        failed_job = db_session.query(ScanJob).filter(
            ScanJob.repository_id == "repo-broker-down"
        ).first()
        assert failed_job is not None
        assert failed_job.status == ScanStatus.FAILED.value
        assert "Redis broker" in failed_job.error_message

    app.dependency_overrides.clear()

def test_malformed_sarif_results_in_failed_scan(db_session):
    """
    CRITICAL REQUIREMENT #10 & #31:
    Malformed SARIF or scanner crash must result in FAILED status, never a clean scan with 0 findings.
    """
    from app.scanners.semgrep.adapter import SemgrepAdapter
    adapter = SemgrepAdapter()

    # Normalizing malformed SARIF must raise ValueError
    with pytest.raises(ValueError) as exc:
        adapter.normalize("Not valid JSON at all", {"tenant_id": 1})
    assert "Malformed SARIF" in str(exc.value)

    # Missing runs array must raise ValueError
    with pytest.raises(ValueError) as exc:
        adapter.normalize('{"version": "2.1.0"}', {"tenant_id": 1})
    assert "missing top-level 'runs' array" in str(exc.value)

def test_invalid_repository_fails_scan(db_session):
    """
    ScanOrchestrator must transition ScanJob to FAILED when repository is non-existent.
    """
    from app.orchestrator.orchestrator import ScanOrchestrator
    orchestrator = ScanOrchestrator(db=db_session)

    scan_id = str(uuid.uuid4())
    scan_job = ScanJob(
        id=scan_id,
        tenant_id=1,
        repository_id="repo-non-existent",
        repository_name="/non/existent/path/to/repo/12345",
        branch="main",
        commit_sha="HEAD",
        scan_type="SAST",
        status=ScanStatus.PENDING.value
    )
    db_session.add(scan_job)
    db_session.commit()

    with pytest.raises(Exception):
        orchestrator.execute_scan(scan_id)

    db_session.refresh(scan_job)
    assert scan_job.status == ScanStatus.FAILED.value
    assert scan_job.error_message is not None
