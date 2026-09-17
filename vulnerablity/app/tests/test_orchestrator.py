import pytest
import uuid
from app.database.models import ScanJob, ScanStatus, CanonicalSecurityFinding, ScanEvidence, ComplianceEvaluation
from app.orchestrator.orchestrator import ScanOrchestrator

def test_scan_orchestrator_execution(db_session, mock_repo_workspace):
    # 1. Create a ScanJob record pointing to mock repo
    scan_job = ScanJob(
        id=str(uuid.uuid4()),
        tenant_id=1,
        repository_id="repo-local-001",
        repository_name=mock_repo_workspace,
        branch="main",
        commit_sha="a1b2c3d4e5f678901234567890abcdef12345678",
        scan_type="SAST",
        status=ScanStatus.PENDING.value
    )
    db_session.add(scan_job)
    db_session.commit()

    # 2. Run Orchestrator
    orchestrator = ScanOrchestrator(db=db_session)
    completed_job = orchestrator.execute_scan(scan_job.id)

    # 3. Verify Job completed
    assert completed_job.status == ScanStatus.COMPLETED.value
    assert completed_job.files_scanned > 0
    assert completed_job.finding_count > 0
    assert "semgrep" in completed_job.scanners

    # 4. Verify Canonical Findings persisted
    findings = db_session.query(CanonicalSecurityFinding).filter(
        CanonicalSecurityFinding.scan_id == scan_job.id
    ).all()
    assert len(findings) == completed_job.finding_count
    for f in findings:
        assert f.tenant_id == 1
        assert f.fingerprint is not None
        assert f.status == "OPEN"

    # 5. Verify Scan Evidence persisted
    evidence = db_session.query(ScanEvidence).filter(
        ScanEvidence.scan_id == scan_job.id
    ).first()
    assert evidence is not None
    assert evidence.raw_result_hash is not None
    assert evidence.execution_status == "SUCCESS"

    # 6. Verify Deterministic Compliance Evaluations generated
    evals = db_session.query(ComplianceEvaluation).filter(
        ComplianceEvaluation.scan_id == scan_job.id
    ).all()
    control_ids = [e.control_id for e in evals]
    assert "VM-001" in control_ids
    assert "VM-002" in control_ids
    assert "VM-004" in control_ids

def test_scan_deduplication(db_session, mock_repo_workspace):
    scan_id_1 = str(uuid.uuid4())
    job_1 = ScanJob(
        id=scan_id_1,
        tenant_id=1,
        repository_id="repo-dedup",
        repository_name=mock_repo_workspace,
        branch="main",
        commit_sha="1111111111111111111111111111111111111111",
        scan_type="SAST",
        status=ScanStatus.PENDING.value
    )
    db_session.add(job_1)
    db_session.commit()

    orchestrator = ScanOrchestrator(db=db_session)
    orchestrator.execute_scan(scan_id_1)
    initial_finding_count = db_session.query(CanonicalSecurityFinding).count()

    # Second scan on the same repository
    scan_id_2 = str(uuid.uuid4())
    job_2 = ScanJob(
        id=scan_id_2,
        tenant_id=1,
        repository_id="repo-dedup",
        repository_name=mock_repo_workspace,
        branch="main",
        commit_sha="2222222222222222222222222222222222222222",
        scan_type="SAST",
        status=ScanStatus.PENDING.value
    )
    db_session.add(job_2)
    db_session.commit()

    orchestrator.execute_scan(scan_id_2)
    new_finding_count = db_session.query(CanonicalSecurityFinding).count()

    # Because fingerprints match, findings should update rather than duplicate
    assert new_finding_count == initial_finding_count
