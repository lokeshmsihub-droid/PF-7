import uuid
from datetime import datetime, UTC, timedelta
from typing import Optional
from sqlalchemy.orm import Session
from app.models.orm import (
    CheckResultORM, FindingORM, RemediationTaskORM, ComplianceCheckORM, ChangeORM,
    ORMCheckResultType
)
from app.services.remediation_service import RemediationService
from app.services.audit_service import AuditLogService

class FindingService:
    """Manages creation, deduplication, and lifecycle tracking of compliance findings and remediations."""

    def __init__(self, db: Session):
        self.db = db
        self.remedy_service = RemediationService(db)

    def process_check_result(self, result: CheckResultORM) -> Optional["FindingORM"]:
        """Create finding and remediation tasks if check fails, or resolve if it passes."""
        tenant_id = result.tenant_id
        check_id = result.check_id
        change_id = result.change_id

        # 1. Fetch check specification to get severity/metadata
        check = self.db.query(ComplianceCheckORM).filter_by(check_id=check_id).first()
        if not check:
            raise ValueError(f"Check definition {check_id} not found")

        # 2. Check if an active finding already exists
        existing_finding = self.db.query(FindingORM).filter_by(
            tenant_id=tenant_id,
            check_id=check_id,
            change_id=change_id,
            status="OPEN"
        ).first()

        # If PASS/NOT_APPLICABLE/INSUFFICIENT, do not trigger a new finding
        if result.result != ORMCheckResultType.FAIL:
            return None

        # Determine root cause and recommended action
        root_cause = self.remedy_service.classify_root_cause(check_id, result.details)
        remediation_meta = self.remedy_service.get_recommendation(check_id, root_cause)

        recommended_action = remediation_meta.get("recommended_action", "Fix compliance violation.")
        default_priority = remediation_meta.get("default_priority", "MEDIUM")

        # Calculate priority & due date
        priority = self.remedy_service.calculate_priority(check_id, change_id, tenant_id, default_priority)
        due_date = self.remedy_service.calculate_due_date(priority)
        severity = getattr(check, "severity", "medium")

        # Resolve owner
        owner_id = self.remedy_service.resolve_owner(change_id, tenant_id)

        # 3. If FAIL and finding exists, update timestamps, check results, and check active tasks
        if existing_finding:
            existing_finding.updated_at = datetime.now(UTC).replace(tzinfo=None)
            existing_finding.check_result_id = result.result_id
            ev_ids = [ev.evidence_id for ev in result.evidences]
            existing_finding.evidence_ids = ev_ids
            for ev in result.evidences:
                ev.finding_id = existing_finding.finding_id
            self.db.commit()

            # Find active task (not RESOLVED)
            active_task = self.db.query(RemediationTaskORM).filter(
                RemediationTaskORM.finding_id == existing_finding.finding_id,
                RemediationTaskORM.status != "RESOLVED",
                RemediationTaskORM.tenant_id == tenant_id
            ).first()

            if active_task:
                # Update existing remediation metadata
                active_task.priority = priority
                active_task.severity = severity
                active_task.due_date = due_date
                active_task.root_cause = root_cause
                active_task.recommended_action = recommended_action
                active_task.updated_at = datetime.now(UTC).replace(tzinfo=None)
                self.db.commit()

                # Link new evidence
                for ev in result.evidences:
                    ev.remediation_id = active_task.task_id
                self.db.commit()
            
            return existing_finding

        # 4. If FAIL and finding does not exist, create new Finding
        finding_id = str(uuid.uuid4())
        title = f"Compliance Failure: {check.name}"
        guidance = getattr(check, "reremediation_guidance", None) or getattr(check, "remediation_guidance", "Fix compliance check failure")

        ev_refs = [f"{ev.evidence_type}:{ev.source_record_id}" for ev in result.evidences]
        
        # Append active evidence references to description (from Phase 2.9)
        description = (
            f"Compliance check {check_id} ({check.name}) failed for change request {change_id}.\n"
            f"Details: {result.details.get('message', 'No details provided.')}\n"
            f"Active Evidence: {', '.join(ev_refs)}\n"
            f"Guidance: {guidance}"
        )

        ev_ids = [ev.evidence_id for ev in result.evidences]
        finding = FindingORM(
            finding_id=finding_id,
            tenant_id=tenant_id,
            check_id=check_id,
            control_id=check.control_id,
            change_id=change_id,
            severity=severity,
            title=title,
            description=description,
            status="OPEN",
            check_result_id=result.result_id,
            evidence_ids=ev_ids,
            created_at=datetime.now(UTC).replace(tzinfo=None),
            updated_at=datetime.now(UTC).replace(tzinfo=None)
        )
        self.db.add(finding)
        self.db.commit()

        # 5. Create Remediation Task
        task_id = str(uuid.uuid4())

        # Support MANUAL/AUTOMATED configuration mapping
        action_type = "MANUAL"
        if root_cause in ["FAILED_TEST", "MISSING_APPROVAL", "TRACEABILITY_FAILURE"]:
            action_type = "AUTOMATED" if check_id in ["CM-002", "CM-001", "CM-005"] else "MANUAL"

        task = RemediationTaskORM(
            task_id=task_id,
            remediation_id=task_id,
            tenant_id=tenant_id,
            finding_id=finding_id,
            change_id=change_id,
            check_id=check_id,
            title=f"Remediate: {check.name} violation on {change_id}",
            description=f"Follow check CM library guidance:\n{guidance}",
            owner=owner_id,
            owner_id=owner_id,
            severity=severity,
            priority=priority,
            root_cause=root_cause,
            recommended_action=recommended_action,
            action_type=action_type,
            due_date=due_date,
            status="PENDING",
            created_at=datetime.now(UTC).replace(tzinfo=None),
            updated_at=datetime.now(UTC).replace(tzinfo=None)
        )
        self.db.add(task)
        self.db.commit()

        # Log remediation_created in audit trail
        AuditLogService.log_action(
            db=self.db,
            tenant_id=tenant_id,
            actor_id="system",
            actor_type="SYSTEM",
            action="remediation_created",
            entity_type="RemediationTask",
            entity_id=task_id,
            details={"priority": priority, "root_cause": root_cause}
        )

        if owner_id != "UNASSIGNED":
            # Log remediation_assigned
            AuditLogService.log_action(
                db=self.db,
                tenant_id=tenant_id,
                actor_id="system",
                actor_type="SYSTEM",
                action="remediation_assigned",
                entity_type="RemediationTask",
                entity_id=task_id,
                details={"owner_id": owner_id}
            )

        # Link evidence to finding and remediation task
        for ev in result.evidences:
            ev.finding_id = finding_id
            ev.remediation_id = task_id
        self.db.commit()

        return finding

Optional_Finding_Task = Optional[FindingORM]
