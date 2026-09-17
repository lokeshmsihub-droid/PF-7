import uuid
import traceback
from datetime import datetime, UTC
from typing import Optional
from sqlalchemy.orm import Session
from app.db.postgres import SessionLocal
from app.db.mongodb import MongoDBClient
from app.services.normalization_service import NormalizationService
from app.services.correlation_service import CorrelationService
from app.services.evaluation_service import EvaluationService
from app.services.finding_service import FindingService
from app.services.audit_service import AuditLogService
from app.models.orm import ComplianceCheckORM

# Strictly defined raw-event state machine transitions
VALID_TRANSITIONS = {
    "RECEIVED": ["PROCESSING", "FAILED"],
    "PROCESSING": ["NORMALIZED", "FAILED"],
    "NORMALIZED": ["CORRELATED", "FAILED"],
    "CORRELATED": ["EVALUATED", "COMPLETED", "FAILED"], # EVALUATED or COMPLETED (if no check evaluation applies)
    "EVALUATED": ["COMPLETED", "FAILED"],
    "FAILED": ["PROCESSING"],
    "COMPLETED": [] # Terminal state
}

def transition_event_status(col, event_id: str, target_status: str, error_message: str = None):
    """Enforces the strict raw-event state machine validation and updates corresponding lifecycle timestamps."""
    event = col.find_one({"event_id": event_id})
    if not event:
        raise ValueError(f"Event {event_id} not found")
        
    current_status = event.get("processing_status", "RECEIVED")
    
    # Validate transition
    allowed = VALID_TRANSITIONS.get(current_status, [])
    if target_status not in allowed:
        raise ValueError(f"Invalid transition from {current_status} to {target_status}")
        
    updates = {"processing_status": target_status}
    now = datetime.now(UTC).replace(tzinfo=None)
    
    if target_status == "PROCESSING":
        if event.get("retry_count", 0) >= 3:
            raise ValueError(f"Retry limit of 3 attempts exceeded for event {event_id}")
        updates["processing_started_at"] = now
    elif target_status == "NORMALIZED":
        updates["normalized_at"] = now
    elif target_status == "CORRELATED":
        updates["correlated_at"] = now
    elif target_status == "EVALUATED":
        updates["evaluated_at"] = now
    elif target_status == "COMPLETED":
        updates["completed_at"] = now
    elif target_status == "FAILED":
        updates["failed_at"] = now
        updates["last_error"] = error_message
        
    col.update_one({"event_id": event_id}, {"$set": updates})

def process_webhook_event_async(tenant_id: str, event_id: str, db: Optional[Session] = None):
    """Processes a raw webhook event asynchronously, enforcing validation transitions and logging audit trails."""
    mongo = MongoDBClient()
    mongo.connect()
    col = mongo.raw_events_collection
    
    event = col.find_one({"event_id": event_id, "tenant_id": tenant_id})
    if not event:
        mongo.disconnect()
        return

    own_session = False
    if db is None:
        db = SessionLocal()
        own_session = True

    try:
        # Move state: RECEIVED -> PROCESSING
        transition_event_status(col, event_id, "PROCESSING")
        
        # 1. Normalization
        norm_service = NormalizationService(db)
        ev_type = event.get("event_type")
        payload = event.get("payload")
        
        # Ensure default environment/application structures
        norm_service._ensure_baseline_entities(tenant_id)
        
        # Normalize event payload
        from app.normalization.github_adapter import GitHubNormalizer
        if ev_type == "pull_request":
            change = GitHubNormalizer.normalize_pull_request(payload, tenant_id)
            norm_service._ensure_user_exists(tenant_id, change.requester_id)
            db.merge(change)
        elif ev_type == "pull_request_review":
            review = GitHubNormalizer.normalize_review(payload, tenant_id)
            norm_service._ensure_user_exists(tenant_id, review.approver_id)
            norm_service._ensure_stub_change_exists(tenant_id, review.change_id)
            db.merge(review)
        elif ev_type == "workflow_run":
            test_run = GitHubNormalizer.normalize_workflow_run(payload, tenant_id)
            db.merge(test_run)
        elif ev_type == "deployment":
            deploy = GitHubNormalizer.normalize_deployment(payload, tenant_id)
            deploy.repository_id = "repo-default"
            norm_service._ensure_user_exists(tenant_id, deploy.deployed_by)
            db.merge(deploy)
        elif ev_type == "jira_issue":
            from app.normalization.jira_adapter import JiraNormalizer
            change = JiraNormalizer.normalize_issue(payload, tenant_id)
            norm_service._ensure_user_exists(tenant_id, change.requester_id)
            norm_service._ensure_user_exists(tenant_id, change.owner_id)
            db.merge(change)
            
            approvals = JiraNormalizer.extract_approvals(payload, tenant_id)
            for approval in approvals:
                norm_service._ensure_user_exists(tenant_id, approval.approver_id)
                db.merge(approval)
            
        db.commit()
        # Move state: PROCESSING -> NORMALIZED
        transition_event_status(col, event_id, "NORMALIZED")

        # 2. Correlation
        corr_service = CorrelationService(db)
        corr_service.correlate_sync_run_entities(tenant_id)
        # Move state: NORMALIZED -> CORRELATED
        transition_event_status(col, event_id, "CORRELATED")

        # 3. Continuous Monitoring, Change Detection & Re-evaluation
        from app.services.change_monitoring_service import ChangeMonitoringService
        
        # Identify affected change_ids
        change_ids = []
        if ev_type == "pull_request":
            pr_num = payload.get("pull_request", {}).get("number") or payload.get("number")
            if pr_num:
                change_ids.append(f"chg-pr-{pr_num}")
        elif ev_type == "pull_request_review":
            pr_num = payload.get("pull_request_number") or payload.get("pull_request", {}).get("number")
            if pr_num:
                change_ids.append(f"chg-pr-{pr_num}")
        elif ev_type == "workflow_run":
            head_sha = payload.get("head_sha")
            if head_sha:
                change_ids.extend(corr_service._find_change_ids_by_commit_in_mongodb(tenant_id, head_sha))
        elif ev_type == "deployment":
            deploy_sha = payload.get("deployment", {}).get("sha") or payload.get("sha")
            if deploy_sha:
                change_ids.extend(corr_service._find_change_ids_by_commit_in_mongodb(tenant_id, deploy_sha))
        elif ev_type == "jira_issue":
            key = payload.get("key")
            if key:
                change_ids.append(f"chg-jira-{key}")

        change_ids = list(set(change_ids))

        evaluated = False
        monitor_service = ChangeMonitoringService(db)
        for cid in change_ids:
            detect_res = monitor_service.detect_change(tenant_id, cid)
            changes_detected = detect_res.get("changes", [])
            impact = detect_res.get("impact", "NO_COMPLIANCE_IMPACT")
            
            # Reprocess, re-correlate, re-evaluate and recheck as needed
            monitor_service.trigger_reprocessing(tenant_id, cid, impact, source_event_id=event_id)
            if impact != "NO_COMPLIANCE_IMPACT":
                evaluated = True

        if evaluated:
            # Move state: CORRELATED -> EVALUATED
            transition_event_status(col, event_id, "EVALUATED")
            # Move state: EVALUATED -> COMPLETED
            transition_event_status(col, event_id, "COMPLETED")
        else:
            # Move state: CORRELATED -> COMPLETED
            transition_event_status(col, event_id, "COMPLETED")
        
        # Audit Log for Webhook completed processing
        AuditLogService.log_action(
            db=db,
            tenant_id=tenant_id,
            actor_id="system-pipeline",
            actor_type="SYSTEM",
            action="PROCESS_WEBHOOK_EVENT",
            entity_type="RAW_EVENT",
            entity_id=event_id,
            details={"status": "COMPLETED", "event_type": ev_type}
        )
        db.commit()
        
    except Exception as e:
        db.rollback()
        err_msg = f"{str(e)}\n{traceback.format_exc()}"
        # Move state to FAILED
        try:
            transition_event_status(col, event_id, "FAILED", error_message=err_msg)
        except Exception:
            col.update_one(
                {"event_id": event_id},
                {"$set": {
                    "processing_status": "FAILED",
                    "failed_at": datetime.now(UTC).replace(tzinfo=None),
                    "last_error": err_msg
                }}
            )
        
        # Log failure audit
        try:
            AuditLogService.log_action(
                db=db,
                tenant_id=tenant_id,
                actor_id="system-pipeline",
                actor_type="SYSTEM",
                action="PROCESS_WEBHOOK_EVENT_FAILED",
                entity_type="RAW_EVENT",
                entity_id=event_id,
                details={"error": str(e)}
            )
            db.commit()
        except Exception:
            pass
    finally:
        if own_session:
            db.close()
        mongo.disconnect()
