import uuid
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Query, BackgroundTasks
from sqlalchemy.orm import Session

from app.database.session import get_db, SessionLocal
from app.database.models import (
    ScanJob, ScanStatus, CanonicalSecurityFinding, ScanEvidence, 
    ComplianceEvaluation, Tenant
)
from app.schemas.scan import CreateScanRequest, ScanJobResponse
from app.schemas.finding import CanonicalSecurityFindingSchema
from app.orchestrator.orchestrator import ScanOrchestrator

router = APIRouter(prefix="/scans", tags=["Security Scanning"])

def run_scan_in_background(scan_job_id: str):
    """Executes scan pipeline asynchronously in a background thread."""
    db = SessionLocal()
    try:
        orchestrator = ScanOrchestrator(db=db)
        orchestrator.execute_scan(scan_job_id=scan_job_id)
    except Exception as e:
        print(f"Background scan {scan_job_id} error: {e}")
        try:
            job = db.query(ScanJob).filter(ScanJob.id == scan_job_id).first()
            if job and job.status != "COMPLETED":
                job.status = "FAILED"
                job.error_message = str(e)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()

def get_current_tenant_id(x_tenant_id: Optional[str] = Header(None)) -> int:
    """
    Extracts authenticated tenant ID from context/headers with fallback for dev.
    """
    if x_tenant_id and x_tenant_id.isdigit():
        return int(x_tenant_id)
    return 1

@router.post("/", response_model=ScanJobResponse, status_code=202)
def create_scan_job(
    request: CreateScanRequest,
    background_tasks: BackgroundTasks,
    tenant_id: int = Depends(get_current_tenant_id),
    sync: bool = Query(False, description="Run synchronously for testing/scripts"),
    db: Session = Depends(get_db)
):
    """
    Creates and enqueues an asynchronous security scan job.
    """
    # Ensure tenant exists
    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()
    if not tenant:
        tenant = Tenant(id=tenant_id, name=f"Tenant-{tenant_id}")
        db.add(tenant)
        db.commit()

    scan_id = str(uuid.uuid4())
    scan_job = ScanJob(
        id=scan_id,
        tenant_id=tenant_id,
        repository_id=request.repository_id,
        repository_name=request.repository_name,
        branch=request.branch or "main",
        commit_sha=request.commit_sha or "HEAD",
        scan_type=request.scan_type.value,
        status=ScanStatus.QUEUED.value,
        current_phase="CREATED",
        state_progress_percentage=5.0,
        current_phase_description="Scan job queued for multi-engine fleet"
    )
    db.add(scan_job)
    db.commit()
    db.refresh(scan_job)

    from app.core.config import settings

    if sync:
        orchestrator = ScanOrchestrator(db=db)
        try:
            scan_job = orchestrator.execute_scan(scan_job_id=scan_id)
        except Exception as e:
            db.rollback()
            scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
            if scan_job:
                scan_job.status = ScanStatus.FAILED.value
                scan_job.error_message = str(e)
                db.commit()
            raise HTTPException(status_code=400, detail=f"Scan execution failed: {str(e)}")
        return scan_job

    # Seamlessly dispatch scan in background thread
    background_tasks.add_task(run_scan_in_background, scan_id)
    return scan_job

@router.get("/{scan_id}", response_model=ScanJobResponse)
def get_scan_status(
    scan_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    scan_job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.tenant_id == tenant_id
    ).first()
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan job not found.")
    return scan_job

@router.get("/{scan_id}/progress")
def get_scan_progress(
    scan_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    """Returns live state machine progress, percentage, current phase description, and scanner execution statuses."""
    from app.database.models import ScannerExecution
    scan_job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.tenant_id == tenant_id
    ).first()
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    scanners = db.query(ScannerExecution).filter(
        ScannerExecution.scan_id == scan_id,
        ScannerExecution.tenant_id == tenant_id
    ).all()

    return {
        "scan_id": scan_job.id,
        "status": scan_job.status,
        "current_phase": scan_job.current_phase or scan_job.status,
        "progress_percentage": scan_job.state_progress_percentage or 0.0,
        "current_phase_description": scan_job.current_phase_description or "",
        "repository_name": scan_job.repository_name,
        "branch": scan_job.branch,
        "commit_sha": scan_job.commit_sha,
        "finding_count": scan_job.finding_count or 0,
        "files_scanned": scan_job.files_scanned or 0,
        "error_message": scan_job.error_message,
        "scanners": [
            {
                "scanner": s.scanner,
                "scanner_type": s.scanner_type,
                "status": s.status,
                "duration": s.execution_duration_seconds,
                "finding_count": s.finding_count,
                "rules_executed": s.rules_executed,
                "error_message": s.error_message
            }
            for s in scanners
        ]
    }


@router.get("/", response_model=List[ScanJobResponse])
def list_scans(
    tenant_id: int = Depends(get_current_tenant_id),
    skip: int = 0,
    limit: int = 50,
    db: Session = Depends(get_db)
):
    return db.query(ScanJob).filter(
        ScanJob.tenant_id == tenant_id
    ).order_by(ScanJob.created_at.desc()).offset(skip).limit(limit).all()

@router.get("/{scan_id}/findings", response_model=List[CanonicalSecurityFindingSchema])
def get_scan_findings(
    scan_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    # Verify scan belongs to tenant
    scan_job = db.query(ScanJob).filter(
        ScanJob.id == scan_id,
        ScanJob.tenant_id == tenant_id
    ).first()
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    findings = db.query(CanonicalSecurityFinding).filter(
        CanonicalSecurityFinding.scan_id == scan_id,
        CanonicalSecurityFinding.tenant_id == tenant_id
    ).all()
    return findings

@router.get("/{scan_id}/evidence")
def get_scan_evidence(
    scan_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    evidence = db.query(ScanEvidence).filter(
        ScanEvidence.scan_id == scan_id,
        ScanEvidence.tenant_id == tenant_id
    ).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found for scan.")
    return {
        "id": evidence.id,
        "scan_id": evidence.scan_id,
        "scanner": evidence.scanner,
        "repository": evidence.repository,
        "commit_sha": evidence.commit_sha,
        "files_scanned": evidence.files_scanned,
        "rules_executed": evidence.rules_executed,
        "finding_count": evidence.finding_count,
        "raw_result_hash": evidence.raw_result_hash,
        "result_hash": evidence.result_hash,
        "created_at": evidence.created_at
    }

@router.get("/{scan_id}/compliance")
def get_scan_compliance(
    scan_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    evals = db.query(ComplianceEvaluation).filter(
        ComplianceEvaluation.scan_id == scan_id,
        ComplianceEvaluation.tenant_id == tenant_id
    ).all()
    return [
        {
            "id": ev.id,
            "control_id": ev.control_id,
            "result": ev.result,
            "reason": ev.reason,
            "input_evidence": ev.input_evidence,
            "created_at": ev.created_at
        }
        for ev in evals
    ]

@router.get("/{scan_id}/raw")
def get_raw_scan_result(
    scan_id: str,
    scanner: Optional[str] = None,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    from app.services.raw_storage_service import RawResultStorageService
    storage = RawResultStorageService()
    doc = storage.get_raw_result(tenant_id=tenant_id, scan_id=scan_id, scanner=scanner)
    if not doc:
        # Fallback to general lookup
        doc = storage.get_raw_result(tenant_id=tenant_id, scan_id=scan_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Raw scanner artifact not found in document store.")
    return doc

@router.get("/{scan_id}/scanners")
def get_scan_scanners(
    scan_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    """Returns execution status and telemetry for each scanner engine in this scan."""
    from app.database.models import ScannerExecution
    records = db.query(ScannerExecution).filter(
        ScannerExecution.scan_id == scan_id,
        ScannerExecution.tenant_id == tenant_id
    ).all()
    return [
        {
            "id": r.id,
            "scanner": r.scanner,
            "scanner_version": r.scanner_version,
            "scanner_type": r.scanner_type,
            "status": r.status,
            "execution_duration_seconds": r.execution_duration_seconds,
            "rules_loaded": r.rules_loaded,
            "rules_executed": r.rules_executed,
            "rules_skipped": r.rules_skipped,
            "finding_count": r.finding_count,
            "exit_code": r.exit_code,
            "error_message": r.error_message,
            "started_at": r.started_at,
            "completed_at": r.completed_at
        }
        for r in records
    ]

@router.get("/{scan_id}/rules")
def get_scan_rules(
    scan_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    """Returns rule validation details, rules loaded vs executed vs skipped, and language coverage."""
    from app.database.models import RuleValidationResult
    records = db.query(RuleValidationResult).filter(
        RuleValidationResult.scan_id == scan_id,
        RuleValidationResult.tenant_id == tenant_id
    ).all()
    return [
        {
            "id": r.id,
            "scanner": r.scanner,
            "ruleset_id": r.ruleset_id,
            "ruleset_version": r.ruleset_version,
            "ruleset_hash": r.ruleset_hash,
            "rules_loaded": r.rules_loaded,
            "rules_executed": r.rules_executed,
            "rules_skipped": r.rules_skipped,
            "applicable_languages": r.applicable_languages,
            "applicable_targets": r.applicable_targets,
            "validation_status": r.validation_status,
            "validation_errors": r.validation_errors,
            "rule_details": r.rule_details
        }
        for r in records
    ]

@router.get("/{scan_id}/profile")
def get_scan_repository_profile(
    scan_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    """Returns the detected repository profile (languages, frameworks, targets, manifests, coverage)."""
    from app.database.models import RepositoryProfileModel
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.tenant_id == tenant_id).first()
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    profile = db.query(RepositoryProfileModel).filter(
        RepositoryProfileModel.repository_id == scan_job.repository_id,
        RepositoryProfileModel.commit_sha == scan_job.commit_sha
    ).first()

    if not profile:
        # Fallback to any profile for this repository
        profile = db.query(RepositoryProfileModel).filter(
            RepositoryProfileModel.repository_id == scan_job.repository_id
        ).order_by(RepositoryProfileModel.created_at.desc()).first()

    if not profile:
        return {
            "repository_id": scan_job.repository_id,
            "commit_sha": scan_job.commit_sha,
            "languages": [],
            "frameworks": [],
            "package_managers": [],
            "source_targets": [],
            "dependency_targets": [],
            "iac_targets": [],
            "container_targets": [],
            "manifests": [],
            "coverage_percentage": 100.0
        }

    return {
        "repository_id": profile.repository_id,
        "repository_name": profile.repository_name,
        "commit_sha": profile.commit_sha,
        "languages": profile.languages,
        "frameworks": profile.frameworks,
        "package_managers": profile.package_managers,
        "source_targets": profile.source_targets,
        "dependency_targets": profile.dependency_targets,
        "iac_targets": profile.iac_targets,
        "container_targets": profile.container_targets,
        "manifests": profile.manifests,
        "files_discovered": profile.files_discovered,
        "files_scannable": profile.files_scannable,
        "files_excluded": profile.files_excluded,
        "coverage_percentage": profile.coverage_percentage
    }

@router.get("/{scan_id}/summary")
def get_scan_summary(
    scan_id: str,
    tenant_id: int = Depends(get_current_tenant_id),
    db: Session = Depends(get_db)
):
    """Returns full consolidated summary of scan job, scanners, findings breakdown, and compliance."""
    from app.database.models import ScannerExecution, RuleValidationResult
    scan_job = db.query(ScanJob).filter(ScanJob.id == scan_id, ScanJob.tenant_id == tenant_id).first()
    if not scan_job:
        raise HTTPException(status_code=404, detail="Scan job not found.")

    scanners = db.query(ScannerExecution).filter(ScannerExecution.scan_id == scan_id).all()
    findings = db.query(CanonicalSecurityFinding).filter(CanonicalSecurityFinding.scan_id == scan_id).all()
    evals = db.query(ComplianceEvaluation).filter(ComplianceEvaluation.scan_id == scan_id).all()

    sev_breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    type_breakdown = {"SAST": 0, "SCA": 0, "IAC": 0}
    for f in findings:
        s = f.severity.upper() if f.severity else "MEDIUM"
        sev_breakdown[s] = sev_breakdown.get(s, 0) + 1
        t = (f.finding_type or "SAST").upper()
        type_breakdown[t] = type_breakdown.get(t, 0) + 1

    return {
        "scan": {
            "id": scan_job.id,
            "status": scan_job.status,
            "repository_name": scan_job.repository_name,
            "branch": scan_job.branch,
            "commit_sha": scan_job.commit_sha,
            "scan_type": scan_job.scan_type,
            "finding_count": scan_job.finding_count,
            "files_scanned": scan_job.files_scanned,
            "rules_executed": scan_job.rules_executed,
            "started_at": scan_job.started_at,
            "completed_at": scan_job.completed_at
        },
        "severity_breakdown": sev_breakdown,
        "type_breakdown": type_breakdown,
        "scanners": [
            {
                "scanner": s.scanner,
                "status": s.status,
                "duration": s.execution_duration_seconds,
                "finding_count": s.finding_count,
                "rules_executed": s.rules_executed
            }
            for s in scanners
        ],
        "compliance_summary": {
            "total": len(evals),
            "passed": len([e for e in evals if e.result == "PASS"]),
            "failed": len([e for e in evals if e.result == "FAIL"])
        }
    }

