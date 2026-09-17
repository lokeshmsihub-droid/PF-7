import json
import hashlib
from datetime import datetime, UTC
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.models.orm import (
    EvidenceMetadataORM, ChangeORM, AuthorizationORM, ApprovalORM,
    TestORM, DeploymentORM, ChangeRollbackORM, AuditLogORM
)
from app.db.mongodb import MongoDBClient
from app.services.audit_service import AuditLogService

class EvidenceValidationService:
    """Validates the source provenance, tenant context, content integrity, and freshness of compliance evidence."""

    def __init__(self, db: Session):
        self.db = db

    def validate_source(self, evidence: EvidenceMetadataORM) -> bool:
        """Verify that the evidence has a known and valid source definition."""
        allowed_sources = {"github", "jira", "github_actions", "deployment", "system", "manual"}
        return evidence.source in allowed_sources

    def validate_association(self, evidence: EvidenceMetadataORM) -> bool:
        """Verify that the evidence matches its target tenant and refers to a valid change request."""
        if not evidence.change_id:
            return True
        change = self.db.query(ChangeORM).filter_by(
            change_id=evidence.change_id,
            tenant_id=evidence.tenant_id
        ).first()
        return change is not None

    def validate_integrity(self, evidence: EvidenceMetadataORM) -> bool:
        """Verify that the underlying source record has not been modified using SHA-256 validation."""
        # 1. Resolve target ORM class and primary key
        target_obj = None
        if evidence.evidence_type == "AUTHORIZATION_RECORD":
            target_obj = self.db.query(AuthorizationORM).filter_by(
                authorization_id=evidence.source_record_id,
                tenant_id=evidence.tenant_id
            ).first()
        elif evidence.evidence_type == "APPROVAL_RECORD":
            target_obj = self.db.query(ApprovalORM).filter_by(
                approval_id=evidence.source_record_id,
                tenant_id=evidence.tenant_id
            ).first()
        elif evidence.evidence_type == "TEST_LOG":
            target_obj = self.db.query(TestORM).filter_by(
                test_id=evidence.source_record_id,
                tenant_id=evidence.tenant_id
            ).first()
        elif evidence.evidence_type == "DEPLOY_AUTH":
            target_obj = self.db.query(DeploymentORM).filter_by(
                deployment_id=evidence.source_record_id,
                tenant_id=evidence.tenant_id
            ).first()
        elif evidence.evidence_type == "ROLLBACK_PLAN":
            target_obj = self.db.query(ChangeRollbackORM).filter_by(
                rollback_id=evidence.source_record_id,
                tenant_id=evidence.tenant_id
            ).first()

        if not target_obj:
            # Fall back to checking metadata_json serialization if no ORM class matches
            if evidence.metadata_json:
                serialized = json.dumps(evidence.metadata_json, sort_keys=True, default=str)
                computed = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
                return computed == evidence.hash
            return True

        # 2. Compute canonical ORM hash
        data = {}
        for col in target_obj.__table__.columns:
            if col.name in [
                "created_at", "updated_at", "last_observed_at", 
                "last_evaluated_at", "observed_at", "validated_at", 
                "verified_at", "resolved_at"
            ]:
                continue
            val = getattr(target_obj, col.name)
            if hasattr(val, "isoformat"):
                data[col.name] = val.isoformat()
            elif hasattr(val, "value"):
                data[col.name] = val.value
            else:
                data[col.name] = val
                
        serialized = json.dumps(data, sort_keys=True, default=str)
        computed_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        
        # Verify content_hash/hash matches
        expected_hash = evidence.content_hash or evidence.hash
        return computed_hash == expected_hash

    def validate_freshness(self, evidence: EvidenceMetadataORM) -> str:
        """Determine if evidence remains current, or if changes in state have rendered it stale."""
        if not evidence.change_id:
            return "UNKNOWN"

        change = self.db.query(ChangeORM).filter_by(
            change_id=evidence.change_id,
            tenant_id=evidence.tenant_id
        ).first()
        if not change:
            return "UNKNOWN"

        # Resolve change's active commit
        active_commit = None
        if change.tests:
            # Sort by completed_at/started_at to get latest
            latest_test = sorted(
                change.tests,
                key=lambda t: t.completed_at or t.started_at,
                reverse=True
            )[0]
            active_commit = latest_test.commit_id
        elif change.deployments:
            latest_deploy = sorted(
                change.deployments,
                key=lambda d: d.deployed_at,
                reverse=True
            )[0]
            active_commit = latest_deploy.commit_id

        if not active_commit:
            return "CURRENT"

        # Check evidence's commit SHA
        evidence_commit = None
        if evidence.evidence_type == "TEST_LOG":
            test = self.db.query(TestORM).filter_by(
                test_id=evidence.source_record_id,
                tenant_id=evidence.tenant_id
            ).first()
            if test:
                evidence_commit = test.commit_id
        elif evidence.evidence_type == "DEPLOY_AUTH":
            deploy = self.db.query(DeploymentORM).filter_by(
                deployment_id=evidence.source_record_id,
                tenant_id=evidence.tenant_id
            ).first()
            if deploy:
                evidence_commit = deploy.commit_id

        if evidence_commit and active_commit != evidence_commit:
            return "STALE"

        return "CURRENT"

    def validate_event_exists(self, evidence: EvidenceMetadataORM) -> bool:
        """Verify that the raw event triggering this evidence exists in MongoDB."""
        if not evidence.event_id:
            return True
        mongo = MongoDBClient()
        try:
            mongo.connect()
            col = mongo.raw_events_collection
            evt = col.find_one({"event_id": evidence.event_id})
            return evt is not None
        except Exception:
            return False
        finally:
            mongo.disconnect()

    def validate_evidence(self, evidence: EvidenceMetadataORM) -> Dict[str, Any]:
        """Perform comprehensive lifecycle validations and persist status updates."""
        # 1. Source check
        if not self.validate_source(evidence):
            evidence.status = "INVALID"
            self.db.commit()
            return {"valid": False, "error": "Invalid source provider"}

        # 2. Association check
        if not self.validate_association(evidence):
            evidence.status = "INVALID"
            self.db.commit()
            return {"valid": False, "error": "Invalid change association"}

        # 3. Raw Event check
        if not self.validate_event_exists(evidence):
            evidence.status = "INVALID"
            self.db.commit()
            return {"valid": False, "error": "Raw event missing"}

        # 4. Integrity check
        if not self.validate_integrity(evidence):
            evidence.status = "INVALID"
            evidence.integrity_status = "INTEGRITY_FAILURE"
            self.db.commit()
            
            # Log tamper-evidence alert
            AuditLogService.log_action(
                db=self.db,
                tenant_id=evidence.tenant_id,
                actor_id="system-validator",
                actor_type="SYSTEM",
                action="evidence_integrity_failure",
                entity_type="EVIDENCE",
                entity_id=evidence.evidence_id,
                details={"expected_hash": evidence.hash, "source_record_id": evidence.source_record_id}
            )
            self.db.commit()
            return {"valid": False, "error": "Cryptographic integrity failure"}

        # 5. Freshness check
        freshness = self.validate_freshness(evidence)
        evidence.freshness_status = freshness
        if freshness == "STALE":
            evidence.status = "STALE"
            AuditLogService.log_action(
                db=self.db,
                tenant_id=evidence.tenant_id,
                actor_id="system-validator",
                actor_type="SYSTEM",
                action="evidence_marked_stale",
                entity_type="EVIDENCE",
                entity_id=evidence.evidence_id,
                details={"reason": "Drift in active commit hash detected."}
            )
            self.db.commit()

        # Update metadata timestamp
        evidence.validated_at = datetime.now(UTC).replace(tzinfo=None)
        if evidence.status not in ["INVALID", "STALE"]:
            evidence.status = "VALIDATED"
            
        self.db.commit()
        return {
            "valid": evidence.status == "VALIDATED",
            "status": evidence.status,
            "freshness": evidence.freshness_status,
            "integrity": evidence.integrity_status
        }
