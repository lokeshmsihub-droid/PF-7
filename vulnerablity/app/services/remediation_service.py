import uuid
import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from app.database.models import (
    CanonicalSecurityFinding, ScanJob, FindingStatus, ComplianceEvaluation
)
from app.services.jira_service import JiraService, JiraNotConfiguredError, JiraIntegrationError
from app.services.audit_service import AuditService
from app.orchestrator.orchestrator import ScanOrchestrator

class RemediationService:
    """
    Coordinates vulnerability remediation, Jira Cloud issue creation,
    GitHub PR correlation, and automated verification scanning with complete audit logging.
    """

    def __init__(
        self,
        db: Session,
        jira_service: Optional[JiraService] = None,
        audit_service: Optional[AuditService] = None
    ):
        self.db = db
        self.jira_service = jira_service or JiraService()
        self.audit_service = audit_service or AuditService(db=db)

    def create_jira_remediation(
        self,
        finding_id: str,
        tenant_id: int,
        project_key: Optional[str] = None,
        summary: Optional[str] = None,
        assignee: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validates finding, builds Jira Cloud payload, calls REST API, updates finding,
        records compliance evaluation, and logs audit event.
        Raises JiraNotConfiguredError if Jira credentials are not present (does NOT fabricate fake keys).
        """
        finding = self.db.query(CanonicalSecurityFinding).filter(
            CanonicalSecurityFinding.id == finding_id,
            CanonicalSecurityFinding.tenant_id == tenant_id
        ).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found.")

        # Check configuration
        if not self.jira_service.is_configured():
            raise JiraNotConfiguredError(
                "Jira integration is not configured. JIRA_URL, JIRA_EMAIL, and JIRA_API_TOKEN environment variables must be set."
            )

        issue_summary = summary or f"[{finding.severity}] {finding.rule_id} in {finding.file_path}"
        issue_desc = (
            f"Security Finding ID: {finding.id}\n"
            f"Repository: {finding.repository_name}\n"
            f"Branch: {finding.branch}\n"
            f"Commit: {finding.commit_sha}\n"
            f"File: {finding.file_path}:{finding.start_line}\n"
            f"Severity: {finding.severity} (Risk: {finding.risk_score})\n"
            f"Rule: {finding.rule_id}\n\n"
            f"Description:\n{finding.description or finding.message}\n\n"
            f"Remediation Guidance:\n{finding.remediation or 'Review identified code pattern.'}"
        )

        jira_res = self.jira_service.create_issue(
            project_key=project_key,
            summary=issue_summary,
            description=issue_desc,
            priority=finding.severity.capitalize() if finding.severity in ("High", "Medium", "Low") else "Medium"
        )
        jira_key = jira_res["key"]
        jira_url = jira_res["url"]

        finding.jira_issue_key = jira_key
        finding.jira_issue_url = jira_url
        finding.status = FindingStatus.IN_REMEDIATION.value
        if assignee:
            finding.owner = assignee

        # Update VM-007 compliance state
        self.db.add(ComplianceEvaluation(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            control_id="VM-007",
            evaluation_id=str(uuid.uuid4()),
            result="PASS",
            reason=f"Jira remediation issue {jira_key} created and linked to finding {finding.rule_id}.",
            scan_id=finding.scan_id,
            finding_ids=[finding.id],
            input_evidence={"jira_issue_key": jira_key, "jira_issue_url": jira_url, "owner": finding.owner}
        ))

        # Log audit event
        self.audit_service.log_event(
            tenant_id=tenant_id,
            action="REMEDIATION_CREATED",
            resource_type="finding",
            resource_id=finding.id,
            details={
                "jira_issue_key": jira_key,
                "jira_issue_url": jira_url,
                "project_key": project_key or self.jira_service.default_project_key,
                "owner": finding.owner
            }
        )

        self.db.commit()
        return {
            "finding_id": finding.id,
            "jira_issue_key": jira_key,
            "jira_issue_url": jira_url,
            "status": finding.status,
            "owner": finding.owner,
            "remediation_due_at": finding.remediation_due_at.isoformat() if finding.remediation_due_at else None
        }

    def correlate_github_pr(
        self,
        finding_id: str,
        tenant_id: int,
        pr_url: str,
        branch: str,
        commit_sha: str
    ) -> Dict[str, Any]:
        finding = self.db.query(CanonicalSecurityFinding).filter(
            CanonicalSecurityFinding.id == finding_id,
            CanonicalSecurityFinding.tenant_id == tenant_id
        ).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found.")

        finding.pr_url = pr_url
        finding.branch = branch
        finding.remediation_commit_sha = commit_sha
        finding.verification_status = "PENDING_VERIFICATION"

        # Evaluate VM-009: Verification pending
        self.db.add(ComplianceEvaluation(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            control_id="VM-009",
            evaluation_id=str(uuid.uuid4()),
            result="PENDING",
            reason=f"Fix submitted in PR {pr_url} (commit {commit_sha[:8]}); awaiting verification scan.",
            scan_id=finding.scan_id,
            finding_ids=[finding.id],
            input_evidence={"pr_url": pr_url, "commit_sha": commit_sha}
        ))

        # Audit REMEDIATION_UPDATED
        self.audit_service.log_event(
            tenant_id=tenant_id,
            action="REMEDIATION_UPDATED",
            resource_type="finding",
            resource_id=finding.id,
            details={
                "pr_url": pr_url,
                "branch": branch,
                "commit_sha": commit_sha,
                "verification_status": finding.verification_status
            }
        )

        self.db.commit()
        return {
            "finding_id": finding.id,
            "pr_url": finding.pr_url,
            "remediation_commit_sha": finding.remediation_commit_sha,
            "verification_status": finding.verification_status
        }

    def execute_verification_scan(
        self,
        finding_id: str,
        tenant_id: int,
        fix_commit_sha: str,
        fixed_workspace_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Runs verification scan against fixed commit.
        If finding fingerprint is eliminated, transitions finding to FIXED -> VERIFIED -> RESOLVED.
        Records audit events: VERIFICATION_STARTED, VERIFICATION_COMPLETED, and FINDING_RESOLVED.
        """
        finding = self.db.query(CanonicalSecurityFinding).filter(
            CanonicalSecurityFinding.id == finding_id,
            CanonicalSecurityFinding.tenant_id == tenant_id
        ).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found.")

        # Log VERIFICATION_STARTED
        self.audit_service.log_event(
            tenant_id=tenant_id,
            action="VERIFICATION_STARTED",
            resource_type="finding",
            resource_id=finding.id,
            details={"fix_commit_sha": fix_commit_sha, "target_repo": finding.repository_name}
        )

        target_repo = fixed_workspace_path or finding.repository_name

        # 1. Trigger verification scan job
        verification_job = ScanJob(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            repository_id=finding.repository_id,
            repository_name=target_repo,
            branch=finding.branch,
            commit_sha=fix_commit_sha,
            scan_type="SAST",
            status="PENDING"
        )
        self.db.add(verification_job)
        self.db.commit()

        # Execute scan
        orchestrator = ScanOrchestrator(db=self.db)
        completed_job = orchestrator.execute_scan(verification_job.id)

        # 2. Check if the specific finding fingerprint exists in new scan
        active_same_finding = self.db.query(CanonicalSecurityFinding).filter(
            CanonicalSecurityFinding.scan_id == completed_job.id,
            CanonicalSecurityFinding.fingerprint == finding.fingerprint
        ).first()

        now = datetime.datetime.now(datetime.timezone.utc)
        finding.remediation_commit_sha = fix_commit_sha
        finding.verification_scan_id = completed_job.id

        if not active_same_finding:
            # Finding successfully resolved and verified!
            finding.status = FindingStatus.RESOLVED.value
            finding.verification_status = "VERIFIED"
            finding.resolved_at = now

            # If Jira issue is linked and Jira is configured, comment on ticket
            if self.jira_service.is_configured() and finding.jira_issue_key:
                try:
                    self.jira_service.add_comment(
                        finding.jira_issue_key,
                        f"Automated verification passed on commit {fix_commit_sha[:8]}. Finding resolved."
                    )
                except Exception:
                    pass

            # Compliance re-evaluation: VM-009 & VM-010 become PASS
            self.db.add(ComplianceEvaluation(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                control_id="VM-009",
                evaluation_id=str(uuid.uuid4()),
                result="PASS",
                reason=f"Verification scan on commit {fix_commit_sha[:8]} confirmed finding {finding.rule_id} is eliminated.",
                scan_id=completed_job.id,
                finding_ids=[finding.id],
                input_evidence={"fix_commit_sha": fix_commit_sha, "verification_scan_id": completed_job.id}
            ))
            self.db.add(ComplianceEvaluation(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                control_id="VM-010",
                evaluation_id=str(uuid.uuid4()),
                result="PASS",
                reason=f"Vulnerability closed with cryptographic scan evidence {completed_job.raw_result_hash[:12] if completed_job.raw_result_hash else 'N/A'}.",
                scan_id=completed_job.id,
                finding_ids=[finding.id]
            ))

            # Audit FINDING_RESOLVED & VERIFICATION_COMPLETED
            self.audit_service.log_event(
                tenant_id=tenant_id,
                action="FINDING_RESOLVED",
                resource_type="finding",
                resource_id=finding.id,
                details={
                    "verification_scan_id": completed_job.id,
                    "fix_commit_sha": fix_commit_sha,
                    "resolved_at": now.isoformat()
                }
            )
            self.audit_service.log_event(
                tenant_id=tenant_id,
                action="VERIFICATION_COMPLETED",
                resource_type="finding",
                resource_id=finding.id,
                details={
                    "result": "VERIFIED_RESOLVED",
                    "verification_scan_id": completed_job.id
                }
            )
            result_status = "VERIFIED_RESOLVED"
        else:
            # Finding still present!
            finding.status = FindingStatus.OPEN.value
            finding.verification_status = "FAILED_VERIFICATION"

            # VM-013: Reopening detection
            self.db.add(ComplianceEvaluation(
                id=str(uuid.uuid4()),
                tenant_id=tenant_id,
                control_id="VM-013",
                evaluation_id=str(uuid.uuid4()),
                result="FAIL",
                reason=f"Verification scan on commit {fix_commit_sha[:8]} detected finding {finding.rule_id} is still present.",
                scan_id=completed_job.id,
                finding_ids=[finding.id]
            ))

            # Audit VERIFICATION_COMPLETED (FAILED)
            self.audit_service.log_event(
                tenant_id=tenant_id,
                action="VERIFICATION_COMPLETED",
                resource_type="finding",
                resource_id=finding.id,
                details={
                    "result": "FAILED_VERIFICATION",
                    "verification_scan_id": completed_job.id,
                    "fix_commit_sha": fix_commit_sha
                },
                result="FAIL"
            )
            result_status = "FAILED_VERIFICATION"

        self.db.commit()
        return {
            "finding_id": finding.id,
            "verification_status": finding.verification_status,
            "status": finding.status,
            "verification_scan_id": completed_job.id,
            "remediation_commit_sha": finding.remediation_commit_sha,
            "result": result_status
        }
