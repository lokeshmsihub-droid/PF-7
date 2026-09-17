from sqlalchemy.orm import Session
from app.models.orm import (
    ChangeORM, AuthorizationORM, ApprovalORM, TestORM, DeploymentORM,
    ChangeRelationshipORM, CheckResultORM, FindingORM, RemediationTaskORM,
    EvidenceMetadataORM, AuditLogORM, EntityType
)
from typing import Dict, Any, List

class TraceService:
    """Reconstructs the complete lifecycle of a change request with all evidence and relationships."""

    def __init__(self, db: Session):
        self.db = db

    def _orm_to_dict(self, obj) -> Dict[str, Any]:
        """Convert a SQLAlchemy ORM object into a dictionary safely."""
        if not obj:
            return {}
        res = {}
        for col in obj.__table__.columns:
            val = getattr(obj, col.name)
            if hasattr(val, "isoformat"):
                res[col.name] = val.isoformat()
            elif hasattr(val, "value"):
                res[col.name] = val.value
            else:
                res[col.name] = val
        return res

    def get_change_trace(self, tenant_id: str, change_id: str) -> Dict[str, Any]:
        """Fetch the change and all of its related entities across the SDLC pipeline."""
        # 1. Fetch main change
        main_change = self.db.query(ChangeORM).filter_by(change_id=change_id, tenant_id=tenant_id).first()
        if not main_change:
            return {
                "status": "PARTIAL",
                "error": f"Change {change_id} not found."
            }

        # Find linked changes (Jira <-> GitHub link)
        change_ids = {change_id}
        linked_rels = self.db.query(ChangeRelationshipORM).filter(
            ChangeRelationshipORM.tenant_id == tenant_id,
            (ChangeRelationshipORM.source_id == change_id) | (ChangeRelationshipORM.target_id == change_id)
        ).all()

        for rel in linked_rels:
            if rel.source_type == EntityType.CHANGE:
                change_ids.add(rel.source_id)
            if rel.target_type == EntityType.CHANGE:
                change_ids.add(rel.target_id)

        change_ids_list = list(change_ids)

        # Fetch all changes involved
        changes = self.db.query(ChangeORM).filter(
            ChangeORM.tenant_id == tenant_id,
            ChangeORM.change_id.in_(change_ids_list)
        ).all()

        # Fetch authorizations, approvals, tests, deployments
        authorizations = self.db.query(AuthorizationORM).filter(
            AuthorizationORM.tenant_id == tenant_id,
            AuthorizationORM.change_id.in_(change_ids_list)
        ).all()

        approvals = self.db.query(ApprovalORM).filter(
            ApprovalORM.tenant_id == tenant_id,
            ApprovalORM.change_id.in_(change_ids_list)
        ).all()

        tests = self.db.query(TestORM).filter(
            TestORM.tenant_id == tenant_id,
            TestORM.change_id.in_(change_ids_list)
        ).all()

        deployments = self.db.query(DeploymentORM).filter(
            DeploymentORM.tenant_id == tenant_id,
            DeploymentORM.change_id.in_(change_ids_list)
        ).all()

        # Build list of all entity IDs to pull relationships
        entity_ids = change_ids_list + [t.test_id for t in tests] + [d.deployment_id for d in deployments]
        relationships = self.db.query(ChangeRelationshipORM).filter(
            ChangeRelationshipORM.tenant_id == tenant_id,
            (ChangeRelationshipORM.source_id.in_(entity_ids)) | (ChangeRelationshipORM.target_id.in_(entity_ids))
        ).all()

        check_results = self.db.query(CheckResultORM).filter(
            CheckResultORM.tenant_id == tenant_id,
            CheckResultORM.change_id.in_(change_ids_list)
        ).all()

        findings = self.db.query(FindingORM).filter(
            FindingORM.tenant_id == tenant_id,
            FindingORM.change_id.in_(change_ids_list)
        ).all()

        finding_ids = [f.finding_id for f in findings]
        remediations = self.db.query(RemediationTaskORM).filter(
            RemediationTaskORM.tenant_id == tenant_id,
            RemediationTaskORM.finding_id.in_(finding_ids)
        ).all() if finding_ids else []

        evidence = self.db.query(EvidenceMetadataORM).filter(
            EvidenceMetadataORM.tenant_id == tenant_id,
            EvidenceMetadataORM.change_id.in_(change_ids_list)
        ).all()

        # Fetch audit events
        audit_events = self.db.query(AuditLogORM).filter(
            AuditLogORM.tenant_id == tenant_id,
            (AuditLogORM.entity_id.in_(entity_ids)) | (AuditLogORM.entity_id == change_id)
        ).all()

        # Deduplicate relationships and audit events by ID/log_id
        relationships_dict = {r.relationship_id: self._orm_to_dict(r) for r in relationships}
        audit_events_dict = {a.log_id: self._orm_to_dict(a) for a in audit_events}

        # Reconstruct logical groupings
        jira_changes = [self._orm_to_dict(c) for c in changes if c.source == "jira"]
        github_prs = [self._orm_to_dict(c) for c in changes if c.source == "github"]

        # Status logic:
        # COMPLETE: Jira Change + GitHub PR + CI Test (PASS) + Deployment (all present and correlated)
        # BROKEN: Any relationship state is CONFLICT
        # PARTIAL: Otherwise
        status = "COMPLETE"
        
        has_jira = len(jira_changes) > 0
        has_github = len(github_prs) > 0
        has_test = len(tests) > 0 and any(t.status.value == "PASS" for t in tests)
        has_deploy = len(deployments) > 0

        # Check for conflicts
        has_conflict = any(r.relationship_state == "CONFLICT" for r in relationships)

        if has_conflict:
            status = "BROKEN"
        elif not (has_jira and has_github and has_test and has_deploy):
            status = "PARTIAL"

        return {
            "status": status,
            "change": self._orm_to_dict(main_change),
            "authorization": [self._orm_to_dict(a) for a in authorizations],
            "approval": [self._orm_to_dict(a) for a in approvals],
            "github": {
                "pull_requests": github_prs,
                "commits": [c.get("commit_id") for c in github_prs if c.get("commit_id")]
            },
            "cicd": {
                "pipelines": [self._orm_to_dict(t) for t in tests],
                "tests": [self._orm_to_dict(t) for t in tests]
            },
            "deployments": [self._orm_to_dict(d) for d in deployments],
            "relationships": list(relationships_dict.values()),
            "checks": [self._orm_to_dict(c) for c in check_results],
            "findings": [self._orm_to_dict(f) for f in findings],
            "remediation": [self._orm_to_dict(r) for r in remediations],
            "evidence": [self._orm_to_dict(e) for e in evidence],
            "audit": list(audit_events_dict.values())
        }
