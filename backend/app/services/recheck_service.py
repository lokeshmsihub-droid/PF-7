from datetime import datetime, UTC
from typing import Dict, Any
from sqlalchemy.orm import Session
from app.services.evaluation_service import EvaluationService
from app.models.orm import FindingORM, RemediationTaskORM, ORMCheckResultType
from app.services.remediation_service import RemediationService

class RecheckService:
    """Handles verification and auto-resolution of findings after recheck evaluations pass."""

    def __init__(self, db: Session):
        self.db = db
        self.evaluator = EvaluationService(db)

    def recheck_finding(self, tenant_id: str, finding_id: str) -> Dict[str, Any]:
        """Run recheck on a finding. If evaluation passes, resolve finding and remediation task."""
        # 1. Fetch Finding
        finding = self.db.query(FindingORM).filter_by(finding_id=finding_id, tenant_id=tenant_id).first()
        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        # 2. Run new check evaluation
        result_orm = self.evaluator.evaluate_change(tenant_id, finding.change_id, finding.check_id)

        # 3. Handle status transitions depending on result
        remedy_service = RemediationService(self.db)
        tasks = self.db.query(RemediationTaskORM).filter_by(finding_id=finding_id, tenant_id=tenant_id).all()

        if result_orm.result == ORMCheckResultType.PASS:
            finding.status = "RESOLVED"
            finding.resolved_at = datetime.now(UTC).replace(tzinfo=None)
            finding.check_result_id = result_orm.result_id

            # Link resolution evidences
            existing_ev_ids = list(finding.evidence_ids or [])
            for ev in result_orm.evidences:
                ev.finding_id = finding_id
                if ev.evidence_id not in existing_ev_ids:
                    existing_ev_ids.append(ev.evidence_id)
            finding.evidence_ids = existing_ev_ids

            # Resolve associated remediation tasks
            for task in tasks:
                remedy_service.transition_status(tenant_id, task.task_id, "RESOLVED", actor_id="system", force_reopen=True)
                for ev in result_orm.evidences:
                    ev.remediation_id = task.task_id
            
            self.db.commit()

        elif result_orm.result == ORMCheckResultType.FAIL:
            # Recheck failed!
            # For any tasks in PENDING_REVIEW or VERIFICATION, transition to REJECTED and then to IN_PROGRESS
            for task in tasks:
                if task.status in ["PENDING_REVIEW", "VERIFICATION"]:
                    # Transition to REJECTED
                    remedy_service.transition_status(tenant_id, task.task_id, "REJECTED", actor_id="system")
                    # Transition to IN_PROGRESS (Reopened)
                    remedy_service.transition_status(tenant_id, task.task_id, "IN_PROGRESS", actor_id="system")
                    
                    # Link failure evidence
                    for ev in result_orm.evidences:
                        ev.remediation_id = task.task_id
            
            self.db.commit()

        else: # INSUFFICIENT_DATA
            # For any tasks in PENDING_REVIEW, transition to VERIFICATION
            for task in tasks:
                if task.status == "PENDING_REVIEW":
                    remedy_service.transition_status(tenant_id, task.task_id, "VERIFICATION", actor_id="system")
            self.db.commit()

        return {
            "finding_id": finding_id,
            "new_result_id": result_orm.result_id,
            "new_result": result_orm.result.name,
            "finding_status": finding.status
        }

Dict_Recheck_Result = dict
