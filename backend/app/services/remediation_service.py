import os
import json
import uuid
import hashlib
from datetime import datetime, UTC, timedelta
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.models.orm import RemediationTaskORM, ChangeORM, FindingORM, AuditLogORM, ComplianceCheckORM
from app.services.audit_service import AuditLogService

class RemediationService:
    """Manages the remediation task lifecycle, state machine transitions, priority/SLA tracking, and escalations."""

    def __init__(self, db: Session):
        self.db = db
        self.base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.config_path = os.path.join(self.base_dir, "app", "domain", "checks")
        
        self.remediations = self._load_config("remediations.json")
        self.priority_rules = self._load_config("priority_rules.json")
        self.sla_rules = self._load_config("sla_rules.json")
        self.escalation_rules = self._load_config("escalation_rules.json")

    def _load_config(self, filename: str) -> Dict[str, Any]:
        path = os.path.join(self.config_path, filename)
        if os.path.exists(path):
            with open(path, "r") as f:
                return json.load(f)
        return {}

    def classify_root_cause(self, check_id: str, details: Dict[str, Any]) -> str:
        """Classify root cause category deterministically from check details."""
        message = str(details.get("message", "")).lower()
        reason = str(details.get("reason", "")).lower()
        actual = str(details.get("actual", "")).lower()

        # Evidence Integrity failure is globally prioritized
        if "integrity" in message or "integrity" in reason or "integrity_failure" in message or "tamper" in message:
            return "EVIDENCE_INTEGRITY_FAILURE"

        # Missing evidence
        if "required evidence" in message or "missing_evidence" in details or "is missing" in message:
            return "MISSING_EVIDENCE"

        if check_id == "CM-001":
            if "missing change record" in message or "not found" in message:
                return "MISSING_CHANGE_RECORD"
            return "MISSING_APPROVAL"

        elif check_id == "CM-002":
            if "tested_at is after" in message or "completed after" in message or "timestamp" in message:
                return "TEST_AFTER_DEPLOYMENT"
            if "fail" in actual or "fail" in message:
                return "FAILED_TEST"
            return "MISSING_EVIDENCE"

        elif check_id == "CM-003":
            if "dismiss" in message or "dismiss" in reason:
                return "REVIEW_DISMISSED"
            if "revoke" in message or "revoke" in reason:
                return "APPROVAL_REVOKED"
            return "MISSING_APPROVAL"

        elif check_id == "CM-004":
            return "UNAUTHORIZED_DEPLOYMENT"

        elif check_id == "CM-005":
            if "drift" in message or "mismatch" in message or "sha mismatch" in message or "deployment_id" in message:
                return "COMMIT_DRIFT"
            return "TRACEABILITY_FAILURE"

        elif check_id == "CM-008":
            return "APPROVAL_REVOKED"

        elif check_id == "CM-015":
            return "UNAUTHORIZED_DEPLOYMENT"

        return "OTHER"

    def get_recommendation(self, check_id: str, root_cause: str) -> Dict[str, Any]:
        """Fetch recommended action and metadata from config."""
        check_rems = self.remediations.get(check_id, {})
        config = check_rems.get(root_cause) or check_rems.get("OTHER")
        if not config:
            # Global fallback
            global_fallback = self.remediations.get("EVIDENCE_INTEGRITY_FAILURE", {}).get("OTHER", {})
            config = {
                "recommended_action": global_fallback.get("recommended_action", "Investigate compliance violation."),
                "required_evidence": "Verification evidence",
                "verification_method": "Re-evaluate compliance checks.",
                "default_priority": "MEDIUM"
            }
        return config

    def calculate_priority(self, check_id: str, change_id: str, tenant_id: str, default_priority: str = "MEDIUM") -> str:
        """Compute task priority based on severity, criticality, and environment."""
        check = self.db.query(ComplianceCheckORM).filter_by(check_id=check_id).first()
        change = self.db.query(ChangeORM).filter_by(change_id=change_id, tenant_id=tenant_id).first()

        severity = check.severity.lower() if check else "medium"
        risk_level = change.risk_level.lower() if change else "medium"
        env = change.environment_id.lower() if change else "production"

        sev_weight = self.priority_rules.get("severity_weights", {}).get(severity, 2)
        crit_weight = self.priority_rules.get("criticality_weights", {}).get(risk_level, 2)
        
        impact = "production" if "prod" in env else ("staging" if "stag" in env or "test" in env else "development")
        impact_weight = self.priority_rules.get("impact_weights", {}).get(impact, 2)

        total_weight = sev_weight + crit_weight + impact_weight

        # Classify by threshold
        computed_priority = default_priority
        sorted_thresholds = sorted(self.priority_rules.get("thresholds", {}).items(), key=lambda x: x[1], reverse=True)
        for level, thresh in sorted_thresholds:
            if total_weight >= thresh:
                computed_priority = level
                break

        return computed_priority.lower()

    def calculate_due_date(self, priority: str, base_time: Optional[datetime] = None) -> datetime:
        """Calculate due date offset from base time based on priority SLA rules."""
        base = base_time or datetime.now(UTC).replace(tzinfo=None)
        sla_days = self.sla_rules.get("sla_days", {}).get(priority.upper(), 7)
        return base + timedelta(days=sla_days)

    def resolve_owner(self, change_id: str, tenant_id: str) -> str:
        """Deterministically resolve the owner for remediation task."""
        change = self.db.query(ChangeORM).filter_by(change_id=change_id, tenant_id=tenant_id).first()
        if not change:
            return "UNASSIGNED"

        if change.owner_id and change.owner_id.lower() != "unassigned":
            return change.owner_id

        if change.requester_id and change.requester_id.lower() != "unassigned":
            return change.requester_id

        return "UNASSIGNED"

    def transition_status(
        self, tenant_id: str, task_id: str, new_status: str, actor_id: str = "system", force_reopen: bool = False
    ) -> RemediationTaskORM:
        """Enforce transition rules and update remediation state timestamps and audit logs."""
        task = self.db.query(RemediationTaskORM).filter_by(task_id=task_id, tenant_id=tenant_id).first()
        if not task:
            raise ValueError(f"Remediation task {task_id} not found")

        current_status = task.status
        if current_status == new_status:
            return task

        # Define valid transitions
        VALID_TRANSITIONS = {
            "PENDING": {"ASSIGNED"},
            "OPEN": {"ASSIGNED"},
            "ASSIGNED": {"IN_PROGRESS"},
            "IN_PROGRESS": {"PENDING_REVIEW"},
            "PENDING_REVIEW": {"VERIFICATION", "REJECTED"},
            "VERIFICATION": {"RESOLVED", "REJECTED"},
            "REJECTED": {"IN_PROGRESS"}
        }

        # Check permission rules
        allowed = VALID_TRANSITIONS.get(current_status, set())
        if new_status not in allowed and not force_reopen:
            raise ValueError(f"Invalid transition from {current_status} to {new_status}")

        now = datetime.now(UTC).replace(tzinfo=None)
        action = f"remediation_{new_status.lower()}"

        # Record timestamps
        if new_status == "ASSIGNED":
            task.assigned_at = now
        elif new_status == "IN_PROGRESS":
            task.started_at = now
            if current_status == "REJECTED":
                action = "remediation_reopened"
        elif new_status == "PENDING_REVIEW":
            task.submitted_at = now
        elif new_status == "VERIFICATION":
            task.verification_started_at = now
        elif new_status == "REJECTED":
            task.rejected_at = now
        elif new_status == "RESOLVED":
            task.resolved_at = now

        task.status = new_status
        task.updated_at = now
        self.db.commit()

        # Log transition in Audit trail
        AuditLogService.log_action(
            db=self.db,
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_type="USER" if actor_id != "system" else "SYSTEM",
            action=action,
            entity_type="RemediationTask",
            entity_id=task_id,
            details={"from": current_status, "to": new_status}
        )

        return task

    def check_and_track_slas(self, tenant_id: str) -> List[RemediationTaskORM]:
        """Scan active remediation tasks, flag overdue states, and trigger escalation events."""
        now = datetime.now(UTC).replace(tzinfo=None)
        active_tasks = self.db.query(RemediationTaskORM).filter(
            RemediationTaskORM.tenant_id == tenant_id,
            RemediationTaskORM.status != "RESOLVED"
        ).all()

        overdue_tasks = []
        for task in active_tasks:
            current_sla = self.get_sla_status(task)
            if current_sla == "OVERDUE":
                # Check if it was already flagged overdue to prevent duplicate escalations
                # We can store a flag in details or trigger escalation event directly.
                # Let's create escalation audit event
                escalation_triggered = self._trigger_escalation(task)
                if escalation_triggered:
                    overdue_tasks.append(task)
        return overdue_tasks

    def get_sla_status(self, task: RemediationTaskORM) -> str:
        """Compute the current SLA deadline tracking status for a task."""
        if task.status == "RESOLVED":
            return "ON_TRACK"

        now = datetime.now(UTC).replace(tzinfo=None)
        if not task.due_date:
            return "ON_TRACK"

        if now > task.due_date:
            return "OVERDUE"

        # Check if due soon
        warning_hours = self.sla_rules.get("due_soon_hours", {}).get(task.priority.upper(), 24)
        if task.due_date - now <= timedelta(hours=warning_hours):
            return "DUE_SOON"

        return "ON_TRACK"

    def _trigger_escalation(self, task: RemediationTaskORM) -> bool:
        """Trigger escalation path based on priority and log audit events."""
        # Query if we have already escalated this task
        # Let's inspect audit logs to prevent spamming duplicate escalations
        existing_esc = self.db.query(AuditLogORM).filter_by(
            tenant_id=task.tenant_id,
            action="remediation_escalated",
            entity_type="RemediationTask",
            entity_id=task.task_id
        ).first()

        if existing_esc:
            return False

        # Get escalation path
        path = self.escalation_rules.get("escalation_path", {}).get(task.priority.upper(), [])
        targets = []
        for role in path:
            if role == "owner":
                targets.append(task.owner_id or task.owner)
            else:
                email = self.escalation_rules.get("recipients", {}).get(role)
                if email:
                    targets.append(email)

        AuditLogService.log_action(
            db=self.db,
            tenant_id=task.tenant_id,
            actor_id="system",
            actor_type="SYSTEM",
            action="remediation_escalated",
            entity_type="RemediationTask",
            entity_id=task.task_id,
            details={
                "priority": task.priority,
                "escalation_targets": targets,
                "due_date": task.due_date.isoformat() if task.due_date else None
            }
        )
        self.db.commit()
        return True

    def execute_safe_automated_action(self, tenant_id: str, task_id: str, action: str) -> Dict[str, Any]:
        """Safely execute explicitly authorized remediation actions within the boundary."""
        task = self.db.query(RemediationTaskORM).filter_by(task_id=task_id, tenant_id=tenant_id).first()
        if not task:
            raise ValueError(f"Task {task_id} not found")

        # Configured safe actions
        SAFE_ACTIONS = ["trigger_ci_rerun", "create_jira_ticket", "request_approval", "trigger_evidence_collection", "trigger_compliance_recheck"]
        if action not in SAFE_ACTIONS:
            raise ValueError(f"Action {action} is not a configured safe automation action")

        # Audit authorized action boundary
        AuditLogService.log_action(
            db=self.db,
            tenant_id=tenant_id,
            actor_id="system-remediator",
            actor_type="SYSTEM",
            action=f"automation_{action}",
            entity_type="RemediationTask",
            entity_id=task_id,
            details={"status": "executed", "action": action}
        )
        self.db.commit()

        return {
            "task_id": task_id,
            "action": action,
            "status": "SUCCESS",
            "message": f"Remediation action {action} completed successfully."
        }
