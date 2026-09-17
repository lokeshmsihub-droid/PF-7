import json
import hashlib
from datetime import datetime, UTC
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.db.mongodb import MongoDBClient
from app.models.orm import (
    ChangeORM, AuthorizationORM, ApprovalORM, TestORM, DeploymentORM,
    ChangeRelationshipORM, EntityType, RelationshipType, ComplianceCheckORM, FindingORM
)
from app.services.correlation_service import CorrelationService
from app.services.evaluation_service import EvaluationService
from app.services.finding_service import FindingService
from app.services.recheck_service import RecheckService
from app.services.audit_service import AuditLogService

class ChangeMonitoringService:
    """Monitors SDLC and ITSM entities for compliance-relevant changes and automates re-evaluation."""

    def __init__(self, db: Session):
        self.db = db
        self.mongo = MongoDBClient()

    def _get_mongo_col(self):
        self.mongo.connect()
        return self.mongo.db.change_states

    def _close_mongo(self):
        self.mongo.disconnect()

    def _build_state_dict(self, tenant_id: str, change_id: str) -> Dict[str, Any]:
        """Builds a deterministic, complete dictionary representation of a change's compliance state."""
        change = self.db.query(ChangeORM).filter_by(change_id=change_id, tenant_id=tenant_id).first()
        if not change:
            return {}

        # Fetch tests and deployments
        tests = self.db.query(TestORM).filter_by(change_id=change_id, tenant_id=tenant_id).all()
        deployments = self.db.query(DeploymentORM).filter_by(change_id=change_id, tenant_id=tenant_id).all()
        
        # Fetch rollbacks
        rollbacks = change.rollbacks if hasattr(change, "rollbacks") else []

        # Fetch relationships involving this change, its tests, and its deployments
        test_ids = [t.test_id for t in tests]
        deploy_ids = [d.deployment_id for d in deployments]
        involved_ids = [change_id] + test_ids + deploy_ids
        
        relationships = self.db.query(ChangeRelationshipORM).filter(
            ChangeRelationshipORM.tenant_id == tenant_id,
            (ChangeRelationshipORM.source_id.in_(involved_ids)) | (ChangeRelationshipORM.target_id.in_(involved_ids))
        ).all()

        return {
            "change_id": change_id,
            "tenant_id": tenant_id,
            "change": {
                "status": change.status,
                "change_type": change.change_type.value if hasattr(change.change_type, "value") else change.change_type,
                "requester_id": change.requester_id,
                "owner_id": change.owner_id,
                "title": change.title,
                "description": change.description,
                "is_emergency": change.is_emergency,
                "risk_level": change.risk_level
            },
            "authorizations": sorted([
                {
                    "authorization_id": a.authorization_id,
                    "status": a.status,
                    "authorized_by": a.authorized_by,
                    "authorized_at": a.authorized_at.isoformat() if a.authorized_at else None
                }
                for a in change.authorizations
            ], key=lambda x: x["authorization_id"]),
            "approvals": sorted([
                {
                    "approval_id": a.approval_id,
                    "decision": a.decision,
                    "approver_id": a.approver_id,
                    "approved_at": a.approved_at.isoformat() if a.approved_at else None
                }
                for a in change.approvals
            ], key=lambda x: x["approval_id"]),
            "tests": sorted([
                {
                    "test_id": t.test_id,
                    "pipeline_id": t.pipeline_id,
                    "commit_id": t.commit_id,
                    "status": t.status.value if hasattr(t.status, "value") else t.status,
                    "completed_at": t.completed_at.isoformat() if t.completed_at else None,
                    "started_at": t.started_at.isoformat() if t.started_at else None
                }
                for t in tests
            ], key=lambda x: x["test_id"]),
            "deployments": sorted([
                {
                    "deployment_id": d.deployment_id,
                    "commit_id": d.commit_id,
                    "status": d.status,
                    "deployed_at": d.deployed_at.isoformat() if d.deployed_at else None
                }
                for d in deployments
            ], key=lambda x: x["deployment_id"]),
            "rollbacks": sorted([
                {
                    "rollback_id": r.rollback_id,
                    "rollback_tested": r.rollback_tested,
                    "rollback_reference": r.rollback_reference
                }
                for r in rollbacks
            ], key=lambda x: x["rollback_id"]),
            "relationships": sorted([
                {
                    "source_id": r.source_id,
                    "target_id": r.target_id,
                    "relationship_state": r.relationship_state
                }
                for r in relationships
            ], key=lambda x: (x["source_id"], x["target_id"]))
        }

    def compute_state_hash(self, state_dict: Dict[str, Any]) -> str:
        """Deterministic SHA-256 state hashing of the change configuration."""
        if not state_dict:
            return ""
        # Remove MongoDB _id if present
        state_copy = {k: v for k, v in state_dict.items() if k != "_id"}
        state_str = json.dumps(state_copy, sort_keys=True, default=str)
        return hashlib.sha256(state_str.encode("utf-8")).hexdigest()

    def compare_state(self, prev: Dict[str, Any], curr: Dict[str, Any]) -> List[str]:
        """Compares previous and current states to produce a list of detected change flags."""
        if not prev:
            return ["CHANGE_CREATED"]

        changes = []

        # 1. Compare core Change fields
        pc, cc = prev.get("change", {}), curr.get("change", {})
        if pc.get("status") != cc.get("status"):
            changes.append("STATUS_CHANGED")
        if pc.get("change_type") != cc.get("change_type"):
            changes.append("CHANGE_TYPE_CHANGED")
        if pc.get("requester_id") != cc.get("requester_id") or pc.get("owner_id") != cc.get("owner_id"):
            changes.append("OWNERSHIP_CHANGED")
        if pc.get("risk_level") != cc.get("risk_level") or pc.get("is_emergency") != cc.get("is_emergency"):
            changes.append("RISK_OR_EMERGENCY_CHANGED")

        # 2. Compare authorizations & approvals
        pa, ca = prev.get("authorizations", []), curr.get("authorizations", [])
        if pa != ca:
            changes.append("AUTHORIZATION_STATUS_CHANGED")

        pap, cap = prev.get("approvals", []), curr.get("approvals", [])
        if pap != cap:
            changes.append("APPROVAL_STATUS_CHANGED")

        # 3. Compare tests
        pt, ct = prev.get("tests", []), curr.get("tests", [])
        if len(pt) != len(ct):
            changes.append("TEST_COUNT_CHANGED")
        else:
            for old_t, new_t in zip(pt, ct):
                if old_t.get("status") != new_t.get("status"):
                    changes.append("TEST_STATUS_CHANGED")
                if old_t.get("commit_id") != new_t.get("commit_id"):
                    changes.append("COMMIT_CHANGED")
                    changes.append("APPROVED_CHANGE_MODIFIED")
                if old_t.get("completed_at") != new_t.get("completed_at") or old_t.get("started_at") != new_t.get("started_at"):
                    changes.append("TEST_TEMPORAL_CHANGED")

        if not pt and ct:
            # Transition from no test to having tests
            changes.append("TEST_STATUS_CHANGED")
            changes.append("COMMIT_CHANGED")

        # 4. Compare deployments
        pd, cd = prev.get("deployments", []), curr.get("deployments", [])
        if len(pd) != len(cd):
            changes.append("DEPLOYMENT_COUNT_CHANGED")
            changes.append("DEPLOYMENT_CHANGED")
        else:
            for old_d, new_d in zip(pd, cd):
                if old_d.get("commit_id") != new_d.get("commit_id"):
                    changes.append("DEPLOYMENT_CHANGED")
                    changes.append("COMMIT_CHANGED")
                if old_d.get("deployed_at") != new_d.get("deployed_at"):
                    changes.append("DEPLOYMENT_CHANGED")
                    changes.append("DEPLOYMENT_TEMPORAL_CHANGED")
                if old_d.get("status") != new_d.get("status"):
                    changes.append("DEPLOYMENT_CHANGED")

        if not pd and cd:
            changes.append("DEPLOYMENT_CHANGED")

        # Check rollback
        prb, crb = prev.get("rollbacks", []), curr.get("rollbacks", [])
        if prb != crb:
            changes.append("ROLLBACK_DETECTED")

        # Check relationships
        prel, crel = prev.get("relationships", []), curr.get("relationships", [])
        if prel != crel:
            changes.append("RELATIONSHIP_CHANGED")

        # Detect commit drift (approved/head commit vs deployment commit)
        # If head commit of PR is known, and deployment commit doesn't match
        pr_commit = None
        for t in ct:
            pr_commit = t.get("commit_id")
            if pr_commit:
                break
        # Or look at deployment matching
        for d in cd:
            dep_commit = d.get("commit_id")
            if pr_commit and dep_commit and pr_commit != dep_commit:
                changes.append("COMMIT_DRIFT_DETECTED")

        # If any relationship is in CONFLICT
        has_conflict = any(r.get("relationship_state") == "CONFLICT" for r in crel)
        was_conflict = any(r.get("relationship_state") == "CONFLICT" for r in prel)
        if has_conflict and not was_conflict:
            changes.append("COMMIT_DRIFT_DETECTED")

        return list(set(changes))

    def determine_impact(self, changes: List[str]) -> str:
        """Classify changes into compliance impact categories."""
        if not changes:
            return "NO_COMPLIANCE_IMPACT"

        # Correlation-relevant changes: change of commit, deployment change, relationship updates
        corr_relevant = {
            "CHANGE_CREATED", "COMMIT_CHANGED", "DEPLOYMENT_CHANGED", "DEPLOYMENT_COUNT_CHANGED",
            "RELATIONSHIP_CHANGED", "APPROVED_CHANGE_MODIFIED", "COMMIT_DRIFT_DETECTED"
        }
        if any(c in corr_relevant for c in changes):
            return "CORRELATION_RELEVANT_CHANGE"

        # Evaluation-relevant changes: test status change, approvals status, rollback changes, etc.
        eval_relevant = {
            "TEST_STATUS_CHANGED", "TEST_TEMPORAL_CHANGED", "AUTHORIZATION_STATUS_CHANGED",
            "APPROVAL_STATUS_CHANGED", "ROLLBACK_DETECTED", "STATUS_CHANGED",
            "CHANGE_TYPE_CHANGED", "OWNERSHIP_CHANGED", "RISK_OR_EMERGENCY_CHANGED",
            "DEPLOYMENT_TEMPORAL_CHANGED"
        }
        if any(c in eval_relevant for c in changes):
            return "EVALUATION_RELEVANT_CHANGE"

        return "NO_COMPLIANCE_IMPACT"

    def detect_change(self, tenant_id: str, change_id: str) -> Dict[str, Any]:
        """Detects if compliance-relevant fields changed, updates database hashes, and returns changes list."""
        change = self.db.query(ChangeORM).filter_by(change_id=change_id, tenant_id=tenant_id).first()
        if not change:
            return {"changes": [], "impact": "NO_COMPLIANCE_IMPACT"}

        curr_state = self._build_state_dict(tenant_id, change_id)
        new_hash = self.compute_state_hash(curr_state)

        # 1. Fetch previous state from MongoDB
        col = self._get_mongo_col()
        prev_record = col.find_one({"change_id": change_id, "tenant_id": tenant_id})
        prev_state = prev_record.get("state") if prev_record else {}

        # 2. Compare
        changes = self.compare_state(prev_state, curr_state)
        impact = self.determine_impact(changes)

        # 3. Update hashes in SQL if hash changed
        if new_hash != change.state_hash:
            change.previous_state_hash = change.state_hash
            change.state_hash = new_hash
            change.last_observed_at = datetime.now(UTC).replace(tzinfo=None)
            self.db.commit()

            # Save state to MongoDB for next comparison
            col.update_one(
                {"change_id": change_id, "tenant_id": tenant_id},
                {"$set": {"state": curr_state, "updated_at": datetime.now(UTC)}},
                upsert=True
            )

        self._close_mongo()
        return {"changes": changes, "impact": impact, "prev_state": prev_state, "curr_state": curr_state}

    def trigger_reprocessing(self, tenant_id: str, change_id: str, impact: str, source_event_id: Optional[str] = None):
        """Runs correlation and/or evaluation and findings resolution based on impact classification."""
        if impact == "NO_COMPLIANCE_IMPACT":
            # Audit ignored monitoring event
            AuditLogService.log_action(
                db=self.db,
                tenant_id=tenant_id,
                actor_id="system-monitor",
                actor_type="SYSTEM",
                action="monitoring_event_ignored",
                entity_type="CHANGE",
                entity_id=change_id,
                details={"details": "No compliance relevant changes detected."}
            )
            self.db.commit()
            return

        # Record start of re-evaluation
        AuditLogService.log_action(
            db=self.db,
            tenant_id=tenant_id,
            actor_id="system-monitor",
            actor_type="SYSTEM",
            action="compliance_change_detected",
            entity_type="CHANGE",
            entity_id=change_id,
            details={"impact": impact, "source_event_id": source_event_id}
        )
        self.db.commit()

        # 1. Run Correlation if correlation relevant
        if impact == "CORRELATION_RELEVANT_CHANGE":
            AuditLogService.log_action(
                db=self.db,
                tenant_id=tenant_id,
                actor_id="system-monitor",
                actor_type="SYSTEM",
                action="correlation_retriggered",
                entity_type="CHANGE",
                entity_id=change_id,
                details={"source_event_id": source_event_id}
            )
            corr = CorrelationService(self.db)
            corr.correlate_sync_run_entities(tenant_id)

        # 2. Run Re-evaluation
        AuditLogService.log_action(
            db=self.db,
            tenant_id=tenant_id,
            actor_id="system-monitor",
            actor_type="SYSTEM",
            action="re_evaluation_triggered",
            entity_type="CHANGE",
            entity_id=change_id,
            details={"source_event_id": source_event_id}
        )
        self.db.commit()

        # Delegate evaluation and decision aggregation to ChangeControlOrchestrator
        from app.services.change_control_orchestrator import ChangeControlOrchestrator
        orchestrator = ChangeControlOrchestrator(self.db)

        # Update last evaluated timestamp on the change request
        change = self.db.query(ChangeORM).filter_by(change_id=change_id, tenant_id=tenant_id).first()
        if change:
            change.last_evaluated_at = datetime.now(UTC).replace(tzinfo=None)
            self.db.commit()

        # Resolve raw event type to mapped control event type
        mapped_event_type = None
        if source_event_id:
            try:
                from app.db.mongodb import MongoDBClient
                mongo = MongoDBClient()
                mongo.connect()
                raw_ev = mongo.db.raw_events.find_one({"event_id": source_event_id})
                if raw_ev:
                    raw_type = raw_ev.get("event_type")
                    if raw_type in ["pull_request", "pull_request_review"]:
                        mapped_event_type = "github_pr_changed"
                    elif raw_type == "workflow_run":
                        mapped_event_type = "ci_test_changed"
                    elif raw_type == "deployment":
                        mapped_event_type = "deployment_changed"
                    elif raw_type == "jira_issue":
                        mapped_event_type = "jira_approval_changed"
                mongo.disconnect()
            except Exception:
                pass

        if mapped_event_type:
            orchestrator.evaluate_affected_controls(tenant_id, change_id, mapped_event_type, event_id=source_event_id)
        else:
            orchestrator.evaluate_change(tenant_id, change_id, event_id=source_event_id)

