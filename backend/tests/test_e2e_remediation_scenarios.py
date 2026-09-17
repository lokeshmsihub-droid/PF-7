import pytest
import uuid
import json
import hashlib
from datetime import datetime, timedelta, UTC
from sqlalchemy.orm import Session
from app.db.mongodb import MongoDBClient as MongoDB
from app.services.normalization_service import NormalizationService
from app.services.correlation_service import CorrelationService
from app.services.evaluation_service import EvaluationService
from app.services.finding_service import FindingService
from app.services.recheck_service import RecheckService
from app.services.remediation_service import RemediationService
from app.services.change_monitoring_service import ChangeMonitoringService
from app.services.evidence_association_service import EvidenceAssociationService
from app.services.evidence_validation_service import EvidenceValidationService
from app.models.orm import (
    ORMChangeType, ORMTestStatus, ORMCheckResultType, FindingORM, RemediationTaskORM,
    ChangeORM, DeploymentORM, TestORM, ApprovalORM, AuditLogORM
)

@pytest.fixture(autouse=True)
def clean_mongo():
    """Ensure raw_events MongoDB collection is cleared before and after tests."""
    mongo = MongoDB()
    col = mongo.db.raw_events
    col.delete_many({})
    yield
    col.delete_many({})
    mongo.disconnect()

def seed_checks_and_controls(db_session):
    """Seed framework, controls, and compliance checks (CM-001 through CM-015) in PostgreSQL."""
    import os
    from app.models import orm

    # 1. Seed Framework
    fw = db_session.query(orm.FrameworkORM).filter_by(framework_id="SOC2").first()
    if not fw:
        fw = orm.FrameworkORM(
            framework_id="SOC2",
            name="SOC 2",
            description="SOC 2 Compliance Framework",
            status="ACTIVE"
        )
        db_session.add(fw)
        db_session.commit()

    # 2. Seed Controls and Checks from library.json
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    path = os.path.join(base_dir, "app", "domain", "checks", "library.json")
    with open(path, "r") as f:
        checks_data = json.load(f)
        for cdata in checks_data:
            num = int(cdata["check_id"].split("-")[1])
            ctrl_id = f"CM-CONTROL-{num:02d}"
            if num > 11:
                ctrl_id = "CM-CONTROL-01"
            
            ctrl = db_session.query(orm.ControlORM).filter_by(control_id=ctrl_id).first()
            if not ctrl:
                ctrl = orm.ControlORM(
                    control_id=ctrl_id,
                    framework_id="SOC2",
                    criterion="CC8.1",
                    name=f"Control {ctrl_id}",
                    objective="Ensure compliance control",
                    description="Control description",
                    lifecycle_stage="Authorization",
                    status="ACTIVE",
                    version="1.0.0"
                )
                db_session.add(ctrl)
                db_session.commit()

            check_id = cdata["check_id"]
            chk = db_session.query(orm.ComplianceCheckORM).filter_by(check_id=check_id).first()
            if not chk:
                chk = orm.ComplianceCheckORM(
                    check_id=check_id,
                    control_id=ctrl_id,
                    name=cdata["name"],
                    description=cdata["description"],
                    category=cdata["category"],
                    severity=cdata["severity"],
                    lifecycle_stage="Testing",
                    required_data=cdata["required_fields"],
                    evaluation_logic=cdata["logic"],
                    evidence_requirements=cdata.get("evidence_requirements", []),
                    result_types=["PASS", "FAIL", "INSUFFICIENT_DATA", "NOT_APPLICABLE", "ERROR"],
                    status="ACTIVE",
                    version=cdata.get("version", "1.0.0"),
                    reremediation_guidance="Fix compliance check violation."
                )
                db_session.add(chk)
        db_session.commit()

def create_raw_event_in_mongo(tenant_id: str, sync_run_id: str, event_type: str, external_id: str, payload: dict) -> str:
    """Helper to insert raw events directly into MongoDB."""
    mongo = MongoDB()
    col = mongo.db.raw_events
    event_id = str(uuid.uuid4())
    pl_str = json.dumps(payload, sort_keys=True, default=str)
    pl_hash = hashlib.sha256(pl_str.encode("utf-8")).hexdigest()
    col.insert_one({
        "event_id": event_id,
        "tenant_id": tenant_id,
        "connector_account_id": "acc-e2e-test",
        "source": "github",
        "provider": "github",
        "event_type": event_type,
        "external_id": external_id,
        "received_at": datetime.now(UTC),
        "sync_run_id": sync_run_id,
        "payload": payload,
        "payload_hash": pl_hash
    })
    mongo.disconnect()
    return event_id

def setup_identity_mappings(db_session, tenant_id: str):
    """Seed users and identity link mapping records."""
    from app.models import orm
    norm_service = NormalizationService(db_session)
    norm_service._ensure_baseline_entities(tenant_id)
    
    users = [
        ("usr-alice", "Alice E2E", "alice@acme.com", "developer"),
        ("usr-bob", "Bob E2E", "bob@acme.com", "qa"),
        ("usr-charlie", "Charlie E2E", "charlie@acme.com", "ops")
    ]
    for uid, name, email, role in users:
        u = db_session.query(orm.UserORM).filter_by(internal_user_id=uid, tenant_id=tenant_id).first()
        if not u:
            db_session.add(orm.UserORM(
                internal_user_id=uid, tenant_id=tenant_id, name=name, email=email, role=role, status="ACTIVE"
            ))
            
    links = [
        ("usr-alice", "alice-git"),
        ("usr-bob", "bob-git"),
        ("usr-charlie", "charlie-git")
    ]
    for uid, handle in links:
        link = db_session.query(orm.IdentityLinkORM).filter_by(
            tenant_id=tenant_id, source="github", external_user_id=handle
        ).first()
        if not link:
            db_session.add(orm.IdentityLinkORM(
                internal_user_id=uid, tenant_id=tenant_id, source="github",
                external_user_id=handle, external_username=handle, status="ACTIVE"
            ))
    db_session.commit()

def seed_mock_finding_and_task(db_session, tenant_id: str, task_id: str, finding_id: str, change_id: str, check_id: str = "CM-002") -> RemediationTaskORM:
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    
    # 1. Seed Change
    change = db_session.query(ChangeORM).filter_by(change_id=change_id, tenant_id=tenant_id).first()
    if not change:
        change = ChangeORM(
            change_id=change_id, tenant_id=tenant_id, external_id=change_id, source="jira",
            title="Mock Change", change_type=ORMChangeType.STANDARD,
            requester_id="usr-alice", owner_id="usr-bob",
            environment_id="env-prod", application_id="app-default", status="OPEN"
        )
        db_session.add(change)
        db_session.commit()
        
    # 2. Seed Finding
    finding = db_session.query(FindingORM).filter_by(finding_id=finding_id, tenant_id=tenant_id).first()
    if not finding:
        finding = FindingORM(
            finding_id=finding_id, tenant_id=tenant_id, check_id=check_id, control_id="CM-CONTROL-02",
            change_id=change_id, severity="high", title="Mock Failure", description="Fails",
            status="OPEN", created_at=datetime.utcnow(), updated_at=datetime.utcnow()
        )
        db_session.add(finding)
        db_session.commit()
        
    # 3. Seed Task
    task = db_session.query(RemediationTaskORM).filter_by(task_id=task_id, tenant_id=tenant_id).first()
    if not task:
        task = RemediationTaskORM(
            task_id=task_id, remediation_id=task_id, tenant_id=tenant_id, finding_id=finding_id,
            change_id=change_id, check_id=check_id, title="Mock Remediation Task", description="Follow guidance",
            owner="usr-bob", status="OPEN", created_at=datetime.utcnow(), updated_at=datetime.utcnow()
        )
        db_session.add(task)
        db_session.commit()
        
    return task

# =====================================================================
# UNIT TESTS
# =====================================================================

def test_remediation_state_machine_transitions(db_session):
    """Verify validity of the remediation state machine transitions, invalid states, and timestamps."""
    tenant_id = "tenant-sm-test"
    remedy_service = RemediationService(db_session)

    # Seed finding & task using helper
    task = seed_mock_finding_and_task(db_session, tenant_id, "t-1", "f-1", "chg-1")

    # Valid transitions: OPEN -> ASSIGNED -> IN_PROGRESS -> PENDING_REVIEW -> VERIFICATION -> RESOLVED
    task = remedy_service.transition_status(tenant_id, "t-1", "ASSIGNED")
    assert task.status == "ASSIGNED"
    assert task.assigned_at is not None

    task = remedy_service.transition_status(tenant_id, "t-1", "IN_PROGRESS")
    assert task.status == "IN_PROGRESS"
    assert task.started_at is not None

    task = remedy_service.transition_status(tenant_id, "t-1", "PENDING_REVIEW")
    assert task.status == "PENDING_REVIEW"
    assert task.submitted_at is not None

    task = remedy_service.transition_status(tenant_id, "t-1", "VERIFICATION")
    assert task.status == "VERIFICATION"
    assert task.verification_started_at is not None

    task = remedy_service.transition_status(tenant_id, "t-1", "RESOLVED")
    assert task.status == "RESOLVED"
    assert task.resolved_at is not None

    # Invalid transitions rejected
    task.status = "OPEN"
    db_session.commit()
    with pytest.raises(ValueError, match="Invalid transition"):
        remedy_service.transition_status(tenant_id, "t-1", "PENDING_REVIEW")

    # Failure path: PENDING_REVIEW -> REJECTED -> IN_PROGRESS
    task.status = "PENDING_REVIEW"
    db_session.commit()
    task = remedy_service.transition_status(tenant_id, "t-1", "REJECTED")
    assert task.status == "REJECTED"
    assert task.rejected_at is not None

    task = remedy_service.transition_status(tenant_id, "t-1", "IN_PROGRESS")
    assert task.status == "IN_PROGRESS"

def test_remediation_configurations(db_session):
    """Verify owner, priority, root cause, SLA, and escalation mappings."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-config-test"
    setup_identity_mappings(db_session, tenant_id)
    remedy_service = RemediationService(db_session)

    # 1. Root cause classification
    rc1 = remedy_service.classify_root_cause("CM-002", {"message": "CI pipeline failed", "actual": "FAIL"})
    assert rc1 == "FAILED_TEST"

    rc2 = remedy_service.classify_root_cause("CM-002", {"message": "tested_at is after deployed_at"})
    assert rc2 == "TEST_AFTER_DEPLOYMENT"

    rc3 = remedy_service.classify_root_cause("CM-003", {"message": "review was dismissed by user"})
    assert rc3 == "REVIEW_DISMISSED"

    rc4 = remedy_service.classify_root_cause("CM-005", {"message": "deployment sha mismatch"})
    assert rc4 == "COMMIT_DRIFT"

    rc5 = remedy_service.classify_root_cause("CM-002", {"message": "Evidence integrity check failed"})
    assert rc5 == "EVIDENCE_INTEGRITY_FAILURE"

    # 2. Recommendation Mapping
    rec = remedy_service.get_recommendation("CM-002", "FAILED_TEST")
    assert "CI pipeline" in rec["recommended_action"]
    assert rec["default_priority"] == "HIGH"

    # 3. Ownership resolution
    change = ChangeORM(
        change_id="chg-own-1", tenant_id=tenant_id, external_id="1", source="jira",
        title="Owner test", change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice", owner_id="usr-bob",
        environment_id="env-prod", application_id="app-default", status="OPEN"
    )
    db_session.add(change)
    db_session.commit()
    owner = remedy_service.resolve_owner("chg-own-1", tenant_id)
    assert owner == "usr-bob"

    # 4. Priority weights and due date calculation
    # severity high(3) + risk high(3) + env prod(3) = total weight 9 >= threshold CRITICAL(8)
    change.risk_level = "HIGH"
    change.environment_id = "env-prod"
    db_session.commit()
    pri = remedy_service.calculate_priority("CM-002", "chg-own-1", tenant_id)
    assert pri == "critical"

    due = remedy_service.calculate_due_date("CRITICAL")
    assert due > datetime.utcnow()

    # 5. SLA Due Soon / Overdue tracking
    task = seed_mock_finding_and_task(db_session, tenant_id, "t-sla-1", "f-2", "chg-own-1")
    task.priority = "CRITICAL"
    task.due_date = datetime.utcnow() - timedelta(minutes=5)
    task.status = "IN_PROGRESS"
    db_session.commit()

    sla = remedy_service.get_sla_status(task)
    assert sla == "OVERDUE"

    # Escalation
    overdue_tasks = remedy_service.check_and_track_slas(tenant_id)
    assert len(overdue_tasks) == 1
    assert overdue_tasks[0].task_id == "t-sla-1"

    # Audit log entry for escalation
    audit = db_session.query(AuditLogORM).filter_by(
        tenant_id=tenant_id, action="remediation_escalated", entity_id="t-sla-1"
    ).first()
    assert audit is not None
    assert "compliance-officer@acme.com" in audit.details["escalation_targets"]

# =====================================================================
# E2E SCENARIOS
# =====================================================================

def test_scenario_a_normal_remediation(db_session):
    """Scenario A — Normal remediation (FAIL -> Finding -> Remediation -> Fix -> New evidence -> PASS -> RESOLVED)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-a"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Seed raw events for failed CI test
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 2001,
            "title": "Auth updates",
            "body": "Fixes 2001",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-scen-a"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-2001", pr_payload)

    workflow_payload = {
        "id": 88101,
        "status": "completed",
        "conclusion": "failure",
        "head_sha": "sha-scen-a",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88101", workflow_payload)

    deploy_payload = {
        "id": 99101,
        "deployment": {
            "id": 99101,
            "sha": "sha-scen-a",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99101", deploy_payload)

    # Ingest events
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Evaluate CM-002 -> FAIL -> create finding and task
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-2001", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    finder = FindingService(db_session)
    finding = finder.process_check_result(res)
    assert finding is not None
    assert finding.status == "OPEN"

    task = db_session.query(RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()
    assert task is not None
    assert task.status == "PENDING"
    assert task.root_cause == "FAILED_TEST"

    # Simulate developer work: OPEN -> ASSIGNED -> IN_PROGRESS -> PENDING_REVIEW
    remedy_service = RemediationService(db_session)
    remedy_service.transition_status(tenant_id, task.task_id, "ASSIGNED", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "IN_PROGRESS", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "PENDING_REVIEW", actor_id="usr-alice")
    assert task.status == "PENDING_REVIEW"

    # Simulate Fix: push passing CI run
    sync_run_id_2 = f"sync-{uuid.uuid4()}"
    workflow_payload_pass = {
        "id": 88102,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "sha-scen-a",
        "run_started_at": (now - timedelta(minutes=7)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=6)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id_2, "workflow_run", "run-88102", workflow_payload_pass)
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id_2)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Perform Verification: transition to VERIFICATION
    remedy_service.transition_status(tenant_id, task.task_id, "VERIFICATION", actor_id="usr-alice")
    assert task.status == "VERIFICATION"

    # Recheck finding -> PASS -> RESOLVED
    rechecker = RecheckService(db_session)
    summary = rechecker.recheck_finding(tenant_id, finding.finding_id)
    assert summary["new_result"] == "PASS"
    assert summary["finding_status"] == "RESOLVED"
    assert task.status == "RESOLVED"

def test_scenario_b_verification_failure(db_session):
    """Scenario B — Verification failure (FAIL -> Remediation -> Fix -> Evidence -> FAIL -> REJECTED -> IN_PROGRESS)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-b"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Seed raw events for failed CI test
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 2002,
            "title": "Auth updates",
            "body": "Fixes 2002",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-scen-b"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-2002", pr_payload)

    workflow_payload = {
        "id": 88201,
        "status": "completed",
        "conclusion": "failure",
        "head_sha": "sha-scen-b",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88201", workflow_payload)

    deploy_payload = {
        "id": 99201,
        "deployment": {
            "id": 99201,
            "sha": "sha-scen-b",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99201", deploy_payload)

    # Ingest
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Evaluate CM-002 -> FAIL
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-2002", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    finding = FindingService(db_session).process_check_result(res)
    task = db_session.query(RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()

    # Move to PENDING_REVIEW -> VERIFICATION
    remedy_service = RemediationService(db_session)
    remedy_service.transition_status(tenant_id, task.task_id, "ASSIGNED", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "IN_PROGRESS", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "PENDING_REVIEW", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "VERIFICATION", actor_id="usr-alice")

    # Run verification (evaluates CM-002, which still fails since no new passing test is uploaded)
    rechecker = RecheckService(db_session)
    summary = rechecker.recheck_finding(tenant_id, finding.finding_id)
    
    assert summary["new_result"] == "FAIL"
    # Verification failure -> Transitions status to REJECTED then back to IN_PROGRESS
    assert task.status == "IN_PROGRESS"
    assert task.rejected_at is not None

def test_scenario_c_missing_resolution_evidence(db_session):
    """Scenario C — Missing resolution evidence (Remediation marked complete -> No valid evidence -> INSUFFICIENT_DATA -> Remain unresolved)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-c"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Failed deploy with failed test run
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 2003, "title": "Auth updates", "body": "Fixes 2003",
            "user": {"login": "alice-git"}, "merged": True, "head": {"sha": "sha-scen-c"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-2003", pr_payload)

    workflow_payload = {
        "id": 88301, "status": "completed", "conclusion": "failure", "head_sha": "sha-scen-c",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88301", workflow_payload)

    deploy_payload = {
        "id": 99301,
        "deployment": {
            "id": 99301, "sha": "sha-scen-c", "ref": "main", "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z", "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99301", deploy_payload)

    # Ingest
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Evaluate -> FAIL
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-2003", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    finding = FindingService(db_session).process_check_result(res)
    task = db_session.query(RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()

    # Transition task to PENDING_REVIEW
    remedy_service = RemediationService(db_session)
    remedy_service.transition_status(tenant_id, task.task_id, "ASSIGNED", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "IN_PROGRESS", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "PENDING_REVIEW", actor_id="usr-alice")

    # Delete the test runs from PostgreSQL to simulate missing/unavailable test evidence
    db_session.query(TestORM).filter_by(change_id="chg-pr-2003").delete()
    db_session.commit()

    # Recheck -> INSUFFICIENT_DATA because test is missing
    rechecker = RecheckService(db_session)
    summary = rechecker.recheck_finding(tenant_id, finding.finding_id)
    assert summary["new_result"] == "INSUFFICIENT_DATA"
    # Transitioned to VERIFICATION, remains unresolved
    assert task.status == "VERIFICATION"

def test_scenario_d_stale_evidence(db_session):
    """Scenario D — Stale evidence (Old resolution evidence -> STALE -> Cannot resolve finding)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-d"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # PR link
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 2004, "title": "Auth updates", "body": "Fixes 2004",
            "user": {"login": "alice-git"}, "merged": True, "head": {"sha": "sha-scen-d"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-2004", pr_payload)

    # Failed CI run
    workflow_payload = {
        "id": 88401, "status": "completed", "conclusion": "failure", "head_sha": "sha-scen-d",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88401", workflow_payload)

    # Deployment
    deploy_payload = {
        "id": 99401,
        "deployment": {
            "id": 99401, "sha": "sha-scen-d", "ref": "main", "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z", "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99401", deploy_payload)

    # Ingest
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Evaluate CM-002 -> FAIL -> Finding & task created
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-2004", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    finding = FindingService(db_session).process_check_result(res)
    task = db_session.query(RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()

    # Move task to VERIFICATION
    remedy_service = RemediationService(db_session)
    remedy_service.transition_status(tenant_id, task.task_id, "ASSIGNED", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "IN_PROGRESS", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "PENDING_REVIEW", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "VERIFICATION", actor_id="usr-alice")

    # Seed a passing test but mark its evidence status as STALE
    # Get the evidence record
    from app.models.orm import EvidenceMetadataORM
    stale_test_ev = db_session.query(EvidenceMetadataORM).filter_by(
        tenant_id=tenant_id, change_id="chg-pr-2004", evidence_type="TEST_LOG"
    ).first()
    if stale_test_ev:
        stale_test_ev.freshness_status = "STALE"
        db_session.commit()

    # Recheck should evaluate to FAIL/INSUFFICIENT because there's no CURRENT passing evidence
    rechecker = RecheckService(db_session)
    summary = rechecker.recheck_finding(tenant_id, finding.finding_id)
    assert summary["new_result"] != "PASS"
    assert task.status != "RESOLVED"

def test_scenario_e_ci_failure_fixed(db_session):
    """Scenario E — CI failure fixed (CI FAIL -> Finding -> Remediation -> CI PASS -> Monitoring -> Recheck -> RESOLVED)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-e"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Seed raw events for failed CI test
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 2005, "title": "Auth updates", "body": "Fixes 2005",
            "user": {"login": "alice-git"}, "merged": True, "head": {"sha": "sha-scen-e"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-2005", pr_payload)

    workflow_payload = {
        "id": 88501, "status": "completed", "conclusion": "failure", "head_sha": "sha-scen-e",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88501", workflow_payload)

    deploy_payload = {
        "id": 99501,
        "deployment": {
            "id": 99501, "sha": "sha-scen-e", "ref": "main", "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z", "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99501", deploy_payload)

    # Ingest
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Run Monitoring (Evaluates CM-002 -> FAIL)
    monitor = ChangeMonitoringService(db_session)
    det1 = monitor.detect_change(tenant_id, "chg-pr-2005")
    monitor.trigger_reprocessing(tenant_id, "chg-pr-2005", det1["impact"])

    finding = db_session.query(FindingORM).filter_by(tenant_id=tenant_id, change_id="chg-pr-2005", check_id="CM-002").first()
    assert finding is not None
    assert finding.status == "OPEN"

    task = db_session.query(RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()
    assert task is not None
    assert task.status == "PENDING"

    # Simulate CI fix: pass CI run
    sync_run_id_2 = f"sync-{uuid.uuid4()}"
    workflow_payload_pass = {
        "id": 88502, "status": "completed", "conclusion": "success", "head_sha": "sha-scen-e",
        "run_started_at": (now - timedelta(minutes=7)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=6)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id_2, "workflow_run", "run-88502", workflow_payload_pass)
    
    # Ingest fixes
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id_2)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Monitoring detects change and runs Recheck automatically -> PASS -> RESOLVED
    det2 = monitor.detect_change(tenant_id, "chg-pr-2005")
    monitor.trigger_reprocessing(tenant_id, "chg-pr-2005", det2["impact"])

    assert finding.status == "RESOLVED"
    assert task.status == "RESOLVED"

def test_scenario_f_commit_drift_fixed(db_session):
    """Scenario F — Commit drift fixed (Approved commit: abc123, Deployment: xyz789 -> FAIL. Correct deployment: abc123 -> Recheck -> PASS)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-f"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # PR Approved with commit abc123
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 2006, "title": "Auth updates", "body": "Fixes 2006",
            "user": {"login": "alice-git"}, "merged": True, "head": {"sha": "abc123"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-2006", pr_payload)

    # Review Approval
    review_payload = {
        "id": 201, "pull_request_number": 2006, "state": "approved",
        "submitted_at": (now - timedelta(minutes=30)).isoformat() + "Z", "user": {"login": "bob-git"}
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request_review", "rev-201", review_payload)

    # Deployment of different commit xyz789 (Drift!)
    deploy_payload = {
        "id": 99601,
        "deployment": {
            "id": 99601, "sha": "xyz789", "ref": "main", "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z", "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99601", deploy_payload)

    # Ingest
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Seed manual authorization record to satisfy CM-005
    from app.models.orm import AuthorizationORM
    auth_orm = AuthorizationORM(
        authorization_id="auth-scen-f",
        tenant_id=tenant_id,
        change_id="chg-pr-2006",
        authorized_by="usr-bob",
        status="APPROVED",
        authorized_at=now - timedelta(minutes=70),
        source="jira"
    )
    db_session.add(auth_orm)
    db_session.commit()

    # Evaluate CM-005 -> FAIL
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-2006", "CM-005")
    assert res.result == ORMCheckResultType.FAIL

    finding = FindingService(db_session).process_check_result(res)
    task = db_session.query(RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()
    assert task.root_cause == "COMMIT_DRIFT"

    # Simulate Fix: deploy correct commit abc123
    sync_run_id_2 = f"sync-{uuid.uuid4()}"
    deploy_payload_fix = {
        "id": 99602,
        "deployment": {
            "id": 99602, "sha": "abc123", "ref": "main", "environment": "production",
            "created_at": (now + timedelta(minutes=10)).isoformat() + "Z", "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id_2, "deployment", "dep-99602", deploy_payload_fix)
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id_2)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Recheck -> PASS -> RESOLVED
    rechecker = RecheckService(db_session)
    summary = rechecker.recheck_finding(tenant_id, finding.finding_id)
    assert summary["new_result"] == "PASS"
    assert summary["finding_status"] == "RESOLVED"
    assert task.status == "RESOLVED"

def test_scenario_g_duplicate_remediation(db_session):
    """Scenario G — Duplicate remediation (Same failure evaluated repeatedly -> 1 Finding, 1 Remediation)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-g"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Seed failure events
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 2007, "title": "Auth updates", "body": "Fixes 2007",
            "user": {"login": "alice-git"}, "merged": True, "head": {"sha": "sha-scen-g"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-2007", pr_payload)

    workflow_payload = {
        "id": 88701, "status": "completed", "conclusion": "failure", "head_sha": "sha-scen-g",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88701", workflow_payload)

    deploy_payload = {
        "id": 99701,
        "deployment": {
            "id": 99701, "sha": "sha-scen-g", "ref": "main", "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z", "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99701", deploy_payload)

    # Ingest
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Evaluate first time
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-2007", "CM-002")
    
    finder = FindingService(db_session)
    finder.process_check_result(res)

    # Evaluate 4 more times
    for _ in range(4):
        res_dup = evaluator.evaluate_change(tenant_id, "chg-pr-2007", "CM-002")
        finder.process_check_result(res_dup)

    # Verify only 1 finding and 1 remediation task exist
    findings = db_session.query(FindingORM).filter_by(tenant_id=tenant_id, change_id="chg-pr-2007").all()
    tasks = db_session.query(RemediationTaskORM).filter_by(tenant_id=tenant_id, change_id="chg-pr-2007").all()
    assert len(findings) == 1
    assert len(tasks) == 1

def test_scenario_h_cross_tenant_isolation(db_session):
    """Scenario H — Cross-tenant isolation (Tenant A remediation -> Tenant B attempts access -> 404 / exception)"""
    tenant_id_a = "tenant-a"
    tenant_id_b = "tenant-b"
    remedy_service = RemediationService(db_session)

    # Seed task in Tenant A
    task = seed_mock_finding_and_task(db_session, tenant_id_a, "t-ten-a", "f-a", "chg-ten-a")

    # Attempt transition using Tenant B -> Should raise ValueError
    with pytest.raises(ValueError, match="not found"):
        remedy_service.transition_status(tenant_id_b, "t-ten-a", "ASSIGNED")

def test_scenario_i_overdue_remediation(db_session):
    """Scenario I — Overdue remediation (Due date passes -> OVERDUE -> Escalation event)"""
    tenant_id = "tenant-scenario-i"
    remedy_service = RemediationService(db_session)

    # Create task overdue
    task = seed_mock_finding_and_task(db_session, tenant_id, "t-sla-i", "f-i", "chg-sla-i")
    task.priority = "HIGH"
    task.due_date = datetime.utcnow() - timedelta(days=1)
    task.status = "IN_PROGRESS"
    task.created_at = datetime.utcnow() - timedelta(days=4)
    db_session.commit()

    sla = remedy_service.get_sla_status(task)
    assert sla == "OVERDUE"

    # Trigger escalation
    overdue_tasks = remedy_service.check_and_track_slas(tenant_id)
    assert len(overdue_tasks) == 1

    # Verify audit trail escalation record exists
    audit = db_session.query(AuditLogORM).filter_by(
        tenant_id=tenant_id, action="remediation_escalated", entity_id="t-sla-i"
    ).first()
    assert audit is not None

def test_scenario_j_manual_remediation(db_session):
    """Scenario J — Manual remediation (Finding -> Manual remediation -> Human marks action complete -> Verification -> Evidence -> Recheck -> PASS -> RESOLVED)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-j"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Seed raw events for failed CI test
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 2010, "title": "Auth updates", "body": "Fixes 2010",
            "user": {"login": "alice-git"}, "merged": True, "head": {"sha": "sha-scen-j"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-2010", pr_payload)

    workflow_payload = {
        "id": 88901, "status": "completed", "conclusion": "failure", "head_sha": "sha-scen-j",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88901", workflow_payload)

    deploy_payload = {
        "id": 99901,
        "deployment": {
            "id": 99901, "sha": "sha-scen-j", "ref": "main", "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z", "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99901", deploy_payload)

    # Ingest
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Evaluate CM-002 -> FAIL
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-2010", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    finding = FindingService(db_session).process_check_result(res)
    task = db_session.query(RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()

    # Move to PENDING_REVIEW -> VERIFICATION manually
    remedy_service = RemediationService(db_session)
    remedy_service.transition_status(tenant_id, task.task_id, "ASSIGNED", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "IN_PROGRESS", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "PENDING_REVIEW", actor_id="usr-alice")
    remedy_service.transition_status(tenant_id, task.task_id, "VERIFICATION", actor_id="usr-alice")

    # Simulate Fix: pass CI run
    sync_run_id_2 = f"sync-{uuid.uuid4()}"
    workflow_payload_pass = {
        "id": 88902, "status": "completed", "conclusion": "success", "head_sha": "sha-scen-j",
        "run_started_at": (now - timedelta(minutes=7)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=6)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id_2, "workflow_run", "run-88902", workflow_payload_pass)
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id_2)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Recheck -> PASS -> RESOLVED
    rechecker = RecheckService(db_session)
    summary = rechecker.recheck_finding(tenant_id, finding.finding_id)
    assert summary["new_result"] == "PASS"
    assert summary["finding_status"] == "RESOLVED"
    assert task.status == "RESOLVED"

def test_scenario_k_automated_safe_action(db_session):
    """Scenario K — Automated safe action (Finding -> Configured automated action -> Authorization check -> Action executed -> Evidence collected -> Recheck -> PASS / FAIL)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-k"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Failed CI run
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 2011, "title": "Auth updates", "body": "Fixes 2011",
            "user": {"login": "alice-git"}, "merged": True, "head": {"sha": "sha-scen-k"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-2011", pr_payload)

    workflow_payload = {
        "id": 88911, "status": "completed", "conclusion": "failure", "head_sha": "sha-scen-k",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88911", workflow_payload)

    deploy_payload = {
        "id": 99911,
        "deployment": {
            "id": 99911, "sha": "sha-scen-k", "ref": "main", "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z", "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99911", deploy_payload)

    # Ingest
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Evaluate CM-002 -> FAIL
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-2011", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    finding = FindingService(db_session).process_check_result(res)
    task = db_session.query(RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()
    assert task.action_type == "AUTOMATED"

    # Trigger safe action: trigger_ci_rerun
    remedy_service = RemediationService(db_session)
    act_res = remedy_service.execute_safe_automated_action(tenant_id, task.task_id, "trigger_ci_rerun")
    assert act_res["status"] == "SUCCESS"

    # Verify audit trail contains action log
    audit = db_session.query(AuditLogORM).filter_by(
        tenant_id=tenant_id, action="automation_trigger_ci_rerun", entity_id=task.task_id
    ).first()
    assert audit is not None
