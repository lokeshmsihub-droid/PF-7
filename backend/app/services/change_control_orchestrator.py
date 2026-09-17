import uuid
import os
import json
from datetime import datetime, UTC
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models.orm import (
    ChangeORM, CheckResultORM, ORMCheckResultType, FindingORM,
    RemediationTaskORM, ComplianceCheckORM, ChangeDecisionORM, AuditLogORM
)
from app.services.evaluation_service import EvaluationService
from app.services.finding_service import FindingService
from app.services.remediation_service import RemediationService
from app.services.recheck_service import RecheckService
from app.services.audit_service import AuditLogService

class ChangeControlOrchestrator:
    """Centralized, deterministic orchestrator for Change Management decisions and control flows."""

    def __init__(self, db: Session):
        self.db = db
        self.evaluator = EvaluationService(db)
        self.finder = FindingService(db)
        self.remedy_service = RemediationService(db)
        self.rechecker = RecheckService(db)
        self.control_mapping = self._load_control_mapping()

    def _load_control_mapping(self) -> Dict[str, List[str]]:
        """Load event-to-control mapping from JSON configuration."""
        path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "domain", "checks", "control_mapping.json"
        )
        if os.path.exists(path):
            try:
                with open(path, "r") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _get_active_checks(self) -> List[ComplianceCheckORM]:
        """Fetch all active compliance checks."""
        return self.db.query(ComplianceCheckORM).filter_by(status="ACTIVE").all()

    def _verify_tenant_boundary(self, tenant_id: str, change_id: str) -> ChangeORM:
        """Enforce tenant isolation boundaries for Change records."""
        change = self.db.query(ChangeORM).filter_by(change_id=change_id).first()
        if not change or change.tenant_id != tenant_id:
            raise ValueError(f"Access denied or change request {change_id} not found under tenant {tenant_id}")
        return change

    def get_current_decision(self, tenant_id: str, change_id: str) -> Optional[ChangeDecisionORM]:
        """Retrieve the latest compliance decision for a change request with tenant isolation."""
        self._verify_tenant_boundary(tenant_id, change_id)
        return self.db.query(ChangeDecisionORM).filter_by(
            tenant_id=tenant_id, change_id=change_id
        ).order_by(ChangeDecisionORM.evaluated_at.desc()).first()

    def get_decision_history(self, tenant_id: str, change_id: str) -> List[ChangeDecisionORM]:
        """Retrieve all historical compliance decisions for a change request with tenant isolation."""
        self._verify_tenant_boundary(tenant_id, change_id)
        return self.db.query(ChangeDecisionORM).filter_by(
            tenant_id=tenant_id, change_id=change_id
        ).order_by(ChangeDecisionORM.evaluated_at.desc()).all()

    def get_decision_explanation(self, tenant_id: str, change_id: str) -> Dict[str, Any]:
        """Generate a queryable structured explanation of the latest compliance decision."""
        self._verify_tenant_boundary(tenant_id, change_id)
        decision = self.get_current_decision(tenant_id, change_id)
        if not decision:
            return {
                "change_id": change_id,
                "overall_status": "NOT_EVALUATED",
                "explanation": "No compliance evaluation decision has been recorded yet."
            }

        # Query all active check definitions
        active_checks = self._get_active_checks()
        check_map = {c.check_id: c for c in active_checks}

        # Gather the latest check results for this change
        latest_results = {}
        for check_id in check_map.keys():
            res = self.db.query(CheckResultORM).filter_by(
                tenant_id=tenant_id, change_id=change_id, check_id=check_id
            ).order_by(CheckResultORM.evaluated_at.desc()).first()
            if res:
                latest_results[check_id] = res

        failed_controls = []
        for check_id, res in latest_results.items():
            if res.result == ORMCheckResultType.FAIL:
                chk = check_map.get(check_id)
                check_name = chk.name if chk else "Unknown Control"
                
                # Retrieve associated finding
                finding = self.db.query(FindingORM).filter_by(
                    tenant_id=tenant_id, change_id=change_id, check_id=check_id
                ).order_by(FindingORM.created_at.desc()).first()

                # Retrieve associated remediation task
                remediation = None
                if finding:
                    remediation = self.db.query(RemediationTaskORM).filter_by(
                        tenant_id=tenant_id, finding_id=finding.finding_id
                    ).order_by(RemediationTaskORM.created_at.desc()).first()

                ev_refs = [f"{ev.evidence_type} (ID: {ev.evidence_id})" for ev in res.evidences]

                failed_controls.append({
                    "check_id": check_id,
                    "name": check_name,
                    "result": res.result.name,
                    "expected": res.details.get("expected") or "Valid compliance proof matching control rules.",
                    "observed": res.details.get("reason") or res.details.get("message") or "Control validation failure.",
                    "evidence": ev_refs or ["No evidence associated."],
                    "finding_id": finding.finding_id if finding else None,
                    "finding_status": finding.status if finding else None,
                    "remediation_id": remediation.task_id if remediation else None,
                    "remediation_status": remediation.status if remediation else None
                })

        return {
            "change_id": change_id,
            "overall_status": decision.decision_status,
            "policy_version": decision.policy_version,
            "evaluated_at": decision.evaluated_at.isoformat(),
            "applicable_check_count": decision.applicable_check_count,
            "pass_count": decision.pass_count,
            "fail_count": decision.fail_count,
            "insufficient_data_count": decision.insufficient_data_count,
            "not_applicable_count": decision.not_applicable_count,
            "critical_failure_count": decision.critical_failure_count,
            "finding_count": decision.finding_count,
            "remediation_count": decision.remediation_count,
            "failed_controls": failed_controls
        }

    def _log_orchestrator(self, tenant_id: str, change_id: str, stage: str) -> None:
        """Helper to write a generic orchestrator audit log entry.
        `stage` should be "start" or "complete".
        """
        AuditLogService.log_action(
            db=self.db,
            tenant_id=tenant_id,
            actor_id="system-orchestrator",
            actor_type="SYSTEM",
            action=f"orchestrator_{stage}",
            entity_type="CHANGE",
            entity_id=change_id,
            details={"stage": stage},
        )
        self.db.commit()

    def evaluate_change(self, tenant_id: str, change_id: str, event_id: Optional[str] = None) -> ChangeDecisionORM:
        """Evaluate all active compliance checks for the change request and write historical decision."""
        self.db.expire_all()
        self._verify_tenant_boundary(tenant_id, change_id)
        # Log orchestrator start
        self._log_orchestrator(tenant_id, change_id, "start")
        active_checks = self._get_active_checks()
        check_ids = [c.check_id for c in active_checks]
        decision = self._orchestrate_evaluations(tenant_id, change_id, check_ids, event_id=event_id)
        # Log orchestrator completion
        self._log_orchestrator(tenant_id, change_id, "complete")
        return decision

    def evaluate_affected_controls(self, tenant_id: str, change_id: str, event_type: str, event_id: Optional[str] = None) -> ChangeDecisionORM:
        """Evaluate only controls affected by the event type, merging results with previous evaluations."""
        self.db.expire_all()
        self._verify_tenant_boundary(tenant_id, change_id)
        
        affected_checks = self.control_mapping.get(event_type)
        if not affected_checks:
            # Fall back to evaluating all active checks if affected checks cannot be determined
            return self.evaluate_change(tenant_id, change_id, event_id=event_id)

        # Log control evaluation started audit log for affected controls
        AuditLogService.log_action(
            db=self.db,
            tenant_id=tenant_id,
            actor_id="system-orchestrator",
            actor_type="SYSTEM",
            action="control_evaluation_started",
            entity_type="CHANGE",
            entity_id=change_id,
            details={"affected_checks": affected_checks, "event_type": event_type, "event_id": event_id}
        )
        self.db.commit()

        # Run re-evaluations for affected checks
        results = []
        for check_id in affected_checks:
            res = self.evaluator.evaluate_change(tenant_id, change_id, check_id, event_id=event_id)
            results.append(res)
            self._process_single_check_remediation_cycle(tenant_id, change_id, res)

        # Load latest previous results for unaffected controls
        active_checks = self._get_active_checks()
        for chk in active_checks:
            if chk.check_id not in affected_checks:
                prev_res = self.db.query(CheckResultORM).filter_by(
                    tenant_id=tenant_id, change_id=change_id, check_id=chk.check_id
                ).order_by(CheckResultORM.evaluated_at.desc()).first()

                if prev_res:
                    results.append(prev_res)
                else:
                    # Fallback to evaluate control if no previous result exists
                    res = self.evaluator.evaluate_change(tenant_id, change_id, chk.check_id, event_id=event_id)
                    results.append(res)
                    self._process_single_check_remediation_cycle(tenant_id, change_id, res)

        # Complete evaluations logic
        return self._finalize_decision(tenant_id, change_id, results)

    def _orchestrate_evaluations(self, tenant_id: str, change_id: str, check_ids: List[str], event_id: Optional[str] = None) -> ChangeDecisionORM:
        """Internal helper to execute evaluations for a list of check IDs."""
        AuditLogService.log_action(
            db=self.db,
            tenant_id=tenant_id,
            actor_id="system-orchestrator",
            actor_type="SYSTEM",
            action="control_evaluation_started",
            entity_type="CHANGE",
            entity_id=change_id,
            details={"check_ids": check_ids, "event_id": event_id}
        )
        self.db.commit()

        results = []
        for check_id in check_ids:
            res = self.evaluator.evaluate_change(tenant_id, change_id, check_id, event_id=event_id)
            results.append(res)
            self._process_single_check_remediation_cycle(tenant_id, change_id, res)

        return self._finalize_decision(tenant_id, change_id, results)

    def _process_single_check_remediation_cycle(self, tenant_id: str, change_id: str, result: CheckResultORM):
        """Processes the finding, remediation, and recheck cycle for a single check result."""
        # 1. Process finding via FindingService
        finding = self.finder.process_check_result(result)
        
        # 2. If PASS or NOT_APPLICABLE, verify if there was a previous OPEN finding to trigger resolution
        if result.result in [ORMCheckResultType.PASS, ORMCheckResultType.NOT_APPLICABLE]:
            open_finding = self.db.query(FindingORM).filter_by(
                tenant_id=tenant_id, change_id=change_id, check_id=result.check_id, status="OPEN"
            ).first()
            if open_finding:
                # Trigger recheck resolution path
                self.rechecker.recheck_finding(tenant_id, open_finding.finding_id)

    def _finalize_decision(self, tenant_id: str, change_id: str, results: List[CheckResultORM]) -> ChangeDecisionORM:
        """Aggregates check results, handles state transitions, and persists the new ChangeDecision."""
        # Log evaluation completed in audit trail
        AuditLogService.log_action(
            db=self.db,
            tenant_id=tenant_id,
            actor_id="system-orchestrator",
            actor_type="SYSTEM",
            action="control_evaluation_completed",
            entity_type="CHANGE",
            entity_id=change_id,
            details={"check_result_ids": [r.result_id for r in results]}
        )
        self.db.commit()

        # Log overall decision started in audit trail
        AuditLogService.log_action(
            db=self.db,
            tenant_id=tenant_id,
            actor_id="system-orchestrator",
            actor_type="SYSTEM",
            action="overall_decision_started",
            entity_type="CHANGE",
            entity_id=change_id
        )
        self.db.commit()

        # Aggregate counts
        pass_cnt = 0
        fail_cnt = 0
        insufficient_cnt = 0
        na_cnt = 0
        critical_fail_cnt = 0

        # Load active check definitions to query severities
        checks_map = {c.check_id: c for c in self._get_active_checks()}

        # Load required checks from requirements.json
        req_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "domain", "checks", "requirements.json"
        )
        required_check_ids = ["CM-001", "CM-002", "CM-003", "CM-004", "CM-005"]
        if os.path.exists(req_path):
            try:
                with open(req_path, "r") as f:
                    required_check_ids = list(json.load(f).keys())
            except Exception:
                pass

        for res in results:
            if res.result == ORMCheckResultType.PASS:
                pass_cnt += 1
            elif res.result == ORMCheckResultType.FAIL:
                fail_cnt += 1
                chk = checks_map.get(res.check_id)
                if chk and chk.severity.lower() == "critical":
                    critical_fail_cnt += 1
            elif res.result == ORMCheckResultType.INSUFFICIENT_DATA:
                if res.check_id in required_check_ids:
                    insufficient_cnt += 1
                else:
                    # Non-required checks returning INSUFFICIENT_DATA should be tracked as insufficient but not block compliance
                    pass
            elif res.result == ORMCheckResultType.NOT_APPLICABLE:
                na_cnt += 1

        applicable_cnt = len(results) - na_cnt

        # Calculate finding and remediation counts
        finding_cnt = self.db.query(FindingORM).filter_by(
            tenant_id=tenant_id, change_id=change_id, status="OPEN"
        ).count()

        remediation_cnt = self.db.query(RemediationTaskORM).filter(
            RemediationTaskORM.tenant_id == tenant_id,
            RemediationTaskORM.change_id == change_id,
            RemediationTaskORM.status != "RESOLVED"
        ).count()

        # Determine decision status based on severity, findings, and remediation status
        if fail_cnt > 0:
            # Query active remediation tasks to check for VERIFICATION or REMEDIATION_REQUIRED
            active_tasks = self.db.query(RemediationTaskORM).filter(
                RemediationTaskORM.tenant_id == tenant_id,
                RemediationTaskORM.change_id == change_id,
                RemediationTaskORM.status != "RESOLVED"
            ).all()

            if any(t.status == "VERIFICATION" for t in active_tasks):
                status = "VERIFYING"
            elif active_tasks:
                status = "REMEDIATION_REQUIRED"
            else:
                status = "NON_COMPLIANT"
        elif insufficient_cnt > 0:
            status = "INSUFFICIENT_DATA"
        else:
            status = "COMPLIANT"

        # Fetch previous latest decision to detect meaningful transitions
        prev_dec = self.get_current_decision(tenant_id, change_id)
        
        # Persist historical ChangeDecisionORM
        dec_id = str(uuid.uuid4())
        decision = ChangeDecisionORM(
            decision_id=dec_id,
            tenant_id=tenant_id,
            change_id=change_id,
            decision_status=status,
            evaluated_at=datetime.utcnow(),
            policy_version="1.0.0",
            applicable_check_count=applicable_cnt,
            pass_count=pass_cnt,
            fail_count=fail_cnt,
            insufficient_data_count=insufficient_cnt,
            not_applicable_count=na_cnt,
            critical_failure_count=critical_fail_cnt,
            finding_count=finding_cnt,
            remediation_count=remediation_cnt
        )
        self.db.add(decision)
        self.db.commit()

        # Audit decision logging
        if not prev_dec:
            AuditLogService.log_action(
                db=self.db,
                tenant_id=tenant_id,
                actor_id="system-orchestrator",
                actor_type="SYSTEM",
                action="overall_decision_created",
                entity_type="ChangeDecision",
                entity_id=dec_id,
                details={"status": status}
            )
            self.db.commit()
        else:
            if prev_dec.decision_status != status:
                AuditLogService.log_action(
                    db=self.db,
                    tenant_id=tenant_id,
                    actor_id="system-orchestrator",
                    actor_type="SYSTEM",
                    action="overall_decision_changed",
                    entity_type="ChangeDecision",
                    entity_id=dec_id,
                    details={"from": prev_dec.decision_status, "to": status}
                )
                self.db.commit()

                # If transition is back to COMPLIANT from a non-compliant state, log compliance_restored
                if status == "COMPLIANT" and prev_dec.decision_status in ["NON_COMPLIANT", "REMEDIATION_REQUIRED", "VERIFYING"]:
                    AuditLogService.log_action(
                        db=self.db,
                        tenant_id=tenant_id,
                        actor_id="system-orchestrator",
                        actor_type="SYSTEM",
                        action="compliance_restored",
                        entity_type="ChangeDecision",
                        entity_id=dec_id,
                        details={"from": prev_dec.decision_status, "to": "COMPLIANT"}
                    )
                    self.db.commit()

        # Broadcast SSE events
        try:
            from app.services.event_broker import event_broker
            event_broker.broadcast("COMPLIANCE_EVALUATED", tenant_id, {
                "change_id": change_id,
                "decision_status": status,
                "evaluated_at": decision.evaluated_at.isoformat()
            })
            if prev_dec and prev_dec.decision_status != status:
                event_broker.broadcast("DECISION_CHANGED", tenant_id, {
                    "change_id": change_id,
                    "from_status": prev_dec.decision_status,
                    "to_status": status
                })
        except Exception:
            pass

        return decision
