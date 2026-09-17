import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, Header, Body
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.database.session import get_db
from app.database.models import CanonicalSecurityFinding, ComplianceEvaluation, ScanEvidence
from app.schemas.finding import CanonicalSecurityFindingSchema
from app.services.remediation_service import RemediationService
from app.engines.compliance_engine import ComplianceEngine

router = APIRouter(prefix="/security", tags=["Security Findings & Remediation"])
compliance_engine = ComplianceEngine()

def get_tenant_id(x_tenant_id: Optional[str] = Header(None)) -> int:
    if x_tenant_id and x_tenant_id.isdigit():
        return int(x_tenant_id)
    return 1

class RemediationRequest(BaseModel):
    project_key: str = "SEC"
    summary: Optional[str] = None
    assignee: Optional[str] = None

class CorrelatePRRequest(BaseModel):
    pr_url: str
    branch: str
    commit_sha: str

class VerificationScanRequest(BaseModel):
    fix_commit_sha: str
    fixed_workspace_path: Optional[str] = None

@router.get("/findings", response_model=List[CanonicalSecurityFindingSchema])
def list_all_findings(
    tenant_id: int = Depends(get_tenant_id),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    repository_name: Optional[str] = None,
    repository_id: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(CanonicalSecurityFinding).filter(CanonicalSecurityFinding.tenant_id == tenant_id)
    if repository_name:
        query = query.filter(CanonicalSecurityFinding.repository_name.ilike(f"%{repository_name}%"))
    if repository_id:
        query = query.filter(CanonicalSecurityFinding.repository_id == repository_id)
    if status:
        query = query.filter(CanonicalSecurityFinding.status == status)
    if severity:
        query = query.filter(CanonicalSecurityFinding.severity == severity)
    return query.order_by(CanonicalSecurityFinding.risk_score.desc()).all()

@router.get("/findings/{finding_id}", response_model=CanonicalSecurityFindingSchema)
def get_finding(
    finding_id: str,
    tenant_id: int = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    finding = db.query(CanonicalSecurityFinding).filter(
        CanonicalSecurityFinding.id == finding_id,
        CanonicalSecurityFinding.tenant_id == tenant_id
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    return finding

@router.get("/findings/{finding_id}/compliance")
def get_finding_compliance(
    finding_id: str,
    tenant_id: int = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    finding = db.query(CanonicalSecurityFinding).filter(
        CanonicalSecurityFinding.id == finding_id,
        CanonicalSecurityFinding.tenant_id == tenant_id
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    dynamic_eval = compliance_engine.evaluate_finding_compliance(finding)
    evals = db.query(ComplianceEvaluation).filter(
        ComplianceEvaluation.tenant_id == tenant_id,
        ComplianceEvaluation.scan_id == finding.scan_id
    ).all()
    scan_evals = [
        {
            "control_id": e.control_id,
            "result": e.result,
            "reason": e.reason,
            "input_evidence": e.input_evidence,
            "created_at": e.created_at
        }
        for e in evals
    ]
    return {
        "finding_id": finding.id,
        "primary_category": dynamic_eval["primary_category"],
        "controls": dynamic_eval["controls"],
        "scan_evaluations": scan_evals
    }

@router.get("/findings/{finding_id}/evidence")
def get_finding_evidence(
    finding_id: str,
    tenant_id: int = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    finding = db.query(CanonicalSecurityFinding).filter(
        CanonicalSecurityFinding.id == finding_id,
        CanonicalSecurityFinding.tenant_id == tenant_id
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")

    evidence = db.query(ScanEvidence).filter(
        ScanEvidence.scan_id == finding.scan_id,
        ScanEvidence.tenant_id == tenant_id
    ).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    return {
        "scan_id": evidence.scan_id,
        "scanner": evidence.scanner,
        "scanner_version": evidence.scanner_version,
        "ruleset_id": evidence.ruleset_id,
        "configuration_hash": evidence.configuration_hash,
        "repository": evidence.repository,
        "branch": evidence.branch,
        "commit_sha": evidence.commit_sha,
        "files_discovered": evidence.files_discovered,
        "files_scanned": evidence.files_scanned,
        "files_excluded": evidence.files_excluded,
        "coverage_percentage": evidence.coverage_percentage,
        "finding_count": evidence.finding_count,
        "raw_result_hash": evidence.raw_result_hash,
        "result_hash": evidence.result_hash,
        "exit_code": evidence.exit_code,
        "created_at": evidence.created_at
    }

@router.post("/findings/{finding_id}/remediation")
def create_finding_remediation(
    finding_id: str,
    req: RemediationRequest,
    tenant_id: int = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    remediation_svc = RemediationService(db=db)
    try:
        res = remediation_svc.create_jira_remediation(
            finding_id=finding_id,
            tenant_id=tenant_id,
            project_key=req.project_key,
            summary=req.summary,
            assignee=req.assignee
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        from app.services.jira_service import JiraNotConfiguredError, JiraIntegrationError
        if isinstance(e, JiraNotConfiguredError):
            raise HTTPException(status_code=503, detail=str(e))
        elif isinstance(e, JiraIntegrationError):
            raise HTTPException(status_code=502, detail=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/findings/{finding_id}/correlate-pr")
def correlate_finding_pr(
    finding_id: str,
    req: CorrelatePRRequest,
    tenant_id: int = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    remediation_svc = RemediationService(db=db)
    try:
        res = remediation_svc.correlate_github_pr(
            finding_id=finding_id,
            tenant_id=tenant_id,
            pr_url=req.pr_url,
            branch=req.branch,
            commit_sha=req.commit_sha
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

@router.post("/findings/{finding_id}/verification")
def execute_finding_verification(
    finding_id: str,
    req: VerificationScanRequest,
    tenant_id: int = Depends(get_tenant_id),
    db: Session = Depends(get_db)
):
    remediation_svc = RemediationService(db=db)
    try:
        res = remediation_svc.execute_verification_scan(
            finding_id=finding_id,
            tenant_id=tenant_id,
            fix_commit_sha=req.fix_commit_sha,
            fixed_workspace_path=req.fixed_workspace_path
        )
        return res
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
