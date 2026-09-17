import uuid
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.orm import (
    ChangeORM, EvidenceMetadataORM, CheckResultORM, FindingORM,
    RemediationTaskORM, AuditLogORM, TestORM, ComplianceCheckORM,
    ORMCheckResultType
)
from app.services.audit_service import AuditLogService
from app.services.trace_service import TraceService

class EvidencePackageService:
    """Generates complete, structured, and integrity-verifiable compliance evidence packages for audit purposes."""

    def __init__(self, db: Session):
        self.db = db
        self.trace_service = TraceService(db)

    def generate_evidence_package(self, tenant_id: str, change_id: str) -> Dict[str, Any]:
        """Construct the full evidence package for a Change, verifying conflicts, completeness, and audit trails."""
        # 1. Fetch trace data
        trace = self.trace_service.get_change_trace(tenant_id, change_id)
        if trace.get("error"):
            return {
                "completeness": "BROKEN",
                "error": trace["error"]
            }

        # 2. Query check results, findings, and evidence records directly
        evidence_records = self.db.query(EvidenceMetadataORM).filter_by(
            change_id=change_id,
            tenant_id=tenant_id
        ).all()

        check_results = self.db.query(CheckResultORM).filter_by(
            change_id=change_id,
            tenant_id=tenant_id
        ).all()

        # 3. Detect contradictions / conflicts
        conflicts = []
        tests = self.db.query(TestORM).filter_by(
            change_id=change_id,
            tenant_id=tenant_id
        ).all()

        commit_statuses: Dict[str, set] = {}
        for t in tests:
            commit_statuses.setdefault(t.commit_id, set()).add(t.status.value)

        for commit, statuses in commit_statuses.items():
            if "PASS" in statuses and "FAIL" in statuses:
                conflicts.append(f"Contradictory test results for commit {commit}")
                
                # Update status of these evidence records to CONFLICT
                test_evs = self.db.query(EvidenceMetadataORM).filter(
                    EvidenceMetadataORM.change_id == change_id,
                    EvidenceMetadataORM.tenant_id == tenant_id,
                    EvidenceMetadataORM.evidence_type == "TEST_LOG",
                    EvidenceMetadataORM.source_record_id.in_([t.test_id for t in tests if t.commit_id == commit])
                ).all()
                for ev in test_evs:
                    ev.status = "CONFLICT"
                self.db.commit()

                # Log audit action
                AuditLogService.log_action(
                    db=self.db,
                    tenant_id=tenant_id,
                    actor_id="system-package-builder",
                    actor_type="SYSTEM",
                    action="evidence_conflict_detected",
                    entity_type="CHANGE",
                    entity_id=change_id,
                    details={"commit_id": commit}
                )
                self.db.commit()

        # 4. Assess package completeness
        # COMPLETE: All checks are evaluated, no FAILED checks, no INSUFFICIENT_DATA, no CONFLICTS, no INTEGRITY_FAILURE
        # BROKEN: Any check failed, any integrity failure, any conflicts, or any check result is INSUFFICIENT_DATA when required
        # PARTIAL: Default fallback, e.g. checks not fully evaluated or some optional data missing
        completeness = "COMPLETE"

        if conflicts:
            completeness = "BROKEN"
        else:
            has_fail = any(c.result == ORMCheckResultType.FAIL for c in check_results)
            has_insufficient = any(c.result == ORMCheckResultType.INSUFFICIENT_DATA for c in check_results)
            has_integrity_failure = any(e.integrity_status == "INTEGRITY_FAILURE" for e in evidence_records)
            has_invalid = any(e.status == "INVALID" for e in evidence_records)

            if has_integrity_failure or has_invalid or has_fail or has_insufficient:
                completeness = "BROKEN"
            elif not check_results:
                completeness = "PARTIAL"

        package_id = str(uuid.uuid4())
        
        # Log package creation action
        AuditLogService.log_action(
            db=self.db,
            tenant_id=tenant_id,
            actor_id="system-package-builder",
            actor_type="SYSTEM",
            action="evidence_package_created",
            entity_type="CHANGE",
            entity_id=change_id,
            details={"package_id": package_id, "completeness": completeness}
        )
        self.db.commit()

        # Build output structure
        return {
            "package_id": package_id,
            "completeness": completeness,
            "conflicts": conflicts,
            "change": trace.get("change"),
            "authorization": trace.get("authorization"),
            "approval": trace.get("approval"),
            "github": trace.get("github"),
            "cicd": trace.get("cicd"),
            "deployments": trace.get("deployments"),
            "relationships": trace.get("relationships"),
            "check_results": [
                {
                    "result_id": cr.result_id,
                    "check_id": cr.check_id,
                    "result": cr.result.name,
                    "evaluated_at": cr.evaluated_at.isoformat() if cr.evaluated_at else None,
                    "details": cr.details,
                    "rule_version": cr.rule_version,
                    "evidence_ids": [ev.evidence_id for ev in cr.evidences]
                }
                for cr in check_results
            ],
            "findings": trace.get("findings"),
            "remediation": trace.get("remediation"),
            "evidence": [
                {
                    "evidence_id": er.evidence_id,
                    "source": er.source,
                    "source_record_id": er.source_record_id,
                    "evidence_type": er.evidence_type,
                    "status": er.status,
                    "freshness_status": er.freshness_status,
                    "integrity_status": er.integrity_status,
                    "version": er.version,
                    "hash": er.hash,
                    "content_hash": er.content_hash,
                    "source_hash": er.source_hash,
                    "observed_at": er.observed_at.isoformat() if er.observed_at else None,
                    "validated_at": er.validated_at.isoformat() if er.validated_at else None,
                    "verified_at": er.verified_at.isoformat() if er.verified_at else None,
                    "event_id": er.event_id,
                    "metadata": er.metadata_json
                }
                for er in evidence_records
            ],
            "audit": trace.get("audit")
        }
