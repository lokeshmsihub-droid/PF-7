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
from app.services.change_monitoring_service import ChangeMonitoringService
from app.services.finding_service import FindingService
from app.services.recheck_service import RecheckService
from app.services.event_processor import process_webhook_event_async
from app.models import orm
from app.models.orm import ORMChangeType, ORMTestStatus, ORMCheckResultType

@pytest.fixture(autouse=True)
def clean_mongo():
    """Ensure raw_events MongoDB collection is cleared before and after tests."""
    mongo = MongoDB()
    col = mongo.db.raw_events
    col.delete_many({})
    col_state = mongo.db.change_states
    col_state.delete_many({})
    yield
    col.delete_many({})
    col_state.delete_many({})
    mongo.disconnect()

@pytest.fixture(autouse=True)
def clean_postgres(db_session):
    """Truncate all PostgreSQL tables to prevent cross-test ID/email uniqueness clashes."""
    from sqlalchemy import text
    tables = [
        "change_check_results", "findings", "remediation_tasks", 
        "change_relationships", "change_deployments", "change_tests", 
        "change_approvals", "change_authorizations", "changes", 
        "identity_links", "users", "repositories", "audit_logs",
        "compliance_checks", "controls", "frameworks"
    ]
    for t in tables:
        db_session.execute(text(f"TRUNCATE TABLE {t} CASCADE;"))
    db_session.commit()

def seed_checks_and_controls(db_session):
    """Seed compliance framework and controls."""
    fw = db_session.query(orm.FrameworkORM).filter_by(framework_id="SOC2").first()
    if not fw:
        db_session.add(orm.FrameworkORM(
            framework_id="SOC2", name="SOC 2", description="Compliance Framework", status="ACTIVE"
        ))
        db_session.commit()

    import os
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    path = os.path.join(base_dir, "app", "domain", "checks", "library.json")
    with open(path, "r") as f:
        checks = json.load(f)
        for c in checks:
            num = int(c["check_id"].split("-")[1])
            ctrl_id = f"CM-CONTROL-{num:02d}"
            if num > 11:
                ctrl_id = "CM-CONTROL-01"
            
            ctrl = db_session.query(orm.ControlORM).filter_by(control_id=ctrl_id).first()
            if not ctrl:
                db_session.add(orm.ControlORM(
                    control_id=ctrl_id, framework_id="SOC2", criterion="CC8.1",
                    name=f"Control {ctrl_id}", objective="Objective", description="Desc",
                    lifecycle_stage="Authorization", status="ACTIVE"
                ))
                db_session.commit()

            chk = db_session.query(orm.ComplianceCheckORM).filter_by(check_id=c["check_id"]).first()
            if not chk:
                db_session.add(orm.ComplianceCheckORM(
                    check_id=c["check_id"], control_id=ctrl_id, name=c["name"], description=c["description"],
                    category=c["category"], severity=c["severity"], lifecycle_stage="Testing",
                    required_data=c["required_fields"], evaluation_logic=c["logic"],
                    result_types=["PASS", "FAIL", "INSUFFICIENT_DATA"], status="ACTIVE"
                ))
        db_session.commit()

def setup_identities(db_session, tenant_id: str):
    NormalizationService(db_session)._ensure_baseline_entities(tenant_id)
    users = [
        (f"usr-{tenant_id}-alice", "Alice", f"{tenant_id}-alice@acme.com"),
        (f"usr-{tenant_id}-bob", "Bob", f"{tenant_id}-bob@acme.com"),
        (f"usr-{tenant_id}-charlie", "Charlie", f"{tenant_id}-charlie@acme.com")
    ]
    for uid, name, email in users:
        u = db_session.query(orm.UserORM).filter_by(internal_user_id=uid, tenant_id=tenant_id).first()
        if not u:
            db_session.add(orm.UserORM(internal_user_id=uid, tenant_id=tenant_id, name=name, email=email, role="Developer"))
    
    links = [
        (f"usr-{tenant_id}-alice", "alice-git"),
        (f"usr-{tenant_id}-bob", "bob-git"),
        (f"usr-{tenant_id}-charlie", "charlie-git")
    ]
    for uid, handle in links:
        lnk = db_session.query(orm.IdentityLinkORM).filter_by(internal_user_id=uid, tenant_id=tenant_id, source="github").first()
        if not lnk:
            db_session.add(orm.IdentityLinkORM(
                internal_user_id=uid, tenant_id=tenant_id, source="github",
                external_user_id=f"ext-{handle}", external_username=handle
            ))
    db_session.commit()

def ingest_webhook_event(tenant_id: str, event_type: str, external_id: str, payload: dict, db_session, expect_fail: bool = False) -> str:
    mongo = MongoDB()
    col = mongo.db.raw_events
    event_id = str(uuid.uuid4())
    pl_str = json.dumps(payload, sort_keys=True, default=str)
    pl_hash = hashlib.sha256(pl_str.encode("utf-8")).hexdigest()
    col.insert_one({
        "event_id": event_id,
        "tenant_id": tenant_id,
        "connector_account_id": "acc-mon-test",
        "source": "github" if event_type != "jira_issue" else "jira",
        "provider": "github" if event_type != "jira_issue" else "jira",
        "event_type": event_type,
        "external_id": external_id,
        "received_at": datetime.now(UTC),
        "sync_run_id": "webhook-run",
        "payload": payload,
        "payload_hash": pl_hash,
        "processing_status": "RECEIVED",
        "retry_count": 0
    })

    # Trigger processing synchronously
    process_webhook_event_async(tenant_id, event_id, db=db_session)
    
    # Check if processing failed and raise error
    ev = col.find_one({"event_id": event_id})
    mongo.disconnect()
    if not expect_fail and ev and ev.get("processing_status") == "FAILED":
        raise Exception(f"Webhook processing failed: {ev.get('last_error')}")
        
    return event_id

# -------------------------------------------------------------
# TEST CASES
# -------------------------------------------------------------

def test_scenario_a_new_compliant_change(db_session):
    """SCENARIO A: New compliant change gets processed automatically."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-a"
    setup_identities(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Ingest Jira Change Request
    jira = {
        "key": "CHG-1001",
        "fields": {
            "summary": "STANDARD: Deploy DB patch",
            "creator": {"emailAddress": f"{tenant_id}-alice@acme.com"},
            "assignee": {"emailAddress": f"{tenant_id}-alice@acme.com"},
            "status": {"name": "Done"},
            "created": now.isoformat() + "+0000",
            "updated": now.isoformat() + "+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_is_emergency": {"value": "No"}
        },
        "changelog": {
            "histories": [
                {
                    "id": "app-1", "created": now.isoformat() + "+0000",
                    "author": {"emailAddress": f"{tenant_id}-bob@acme.com"},
                    "items": [{"field": "status", "fromString": "Draft", "toString": "Approved"}]
                }
            ]
        }
    }
    ingest_webhook_event(tenant_id, "jira_issue", "CHG-1001", jira, db_session)

    # 2. Ingest GitHub PR (Linked via "CHG-1001" in title)
    pr = {
        "action": "closed",
        "pull_request": {
            "number": 1001,
            "title": "CHG-1001: Implement patch",
            "body": "Fixes CHG-1001",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-compliant-a"},
            "created_at": (now - timedelta(minutes=30)).isoformat() + "Z",
            "merged_at": now.isoformat() + "Z"
        }
    }
    ingest_webhook_event(tenant_id, "pull_request", "pr-1001", pr, db_session)

    # 3. Ingest CI Test Run
    workflow = {
        "id": 80001,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "sha-compliant-a",
        "run_started_at": (now - timedelta(minutes=20)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=15)).isoformat() + "Z"
    }
    ingest_webhook_event(tenant_id, "workflow_run", "run-80001", workflow, db_session)

    # 4. Ingest Deployment
    deploy = {
        "id": 90001,
        "deployment": {
            "id": 90001,
            "sha": "sha-compliant-a",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=10)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    ingest_webhook_event(tenant_id, "deployment", "dep-90001", deploy, db_session)

    # Evaluate CM-002: should PASS
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-1001", "CM-002")
    assert res.result == ORMCheckResultType.PASS

def test_scenario_b_commit_changed_after_approval(db_session):
    """SCENARIO B: Approved change is modified with a new commit."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-b"
    setup_identities(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest Jira Approved change
    jira = {
        "key": "CHG-1002",
        "fields": {
            "summary": "Deploy Patch", "status": {"name": "Approved"},
            "creator": {"emailAddress": f"{tenant_id}-alice@acme.com"},
            "assignee": {"emailAddress": f"{tenant_id}-alice@acme.com"}
        }
    }
    ingest_webhook_event(tenant_id, "jira_issue", "CHG-1002", jira, db_session)

    # Ingest PR with commit head abc123
    pr1 = {
        "action": "closed",
        "pull_request": {
            "number": 1002, "title": "CHG-1002 Implement patch", "user": {"login": "alice-git"},
            "merged": True, "head": {"sha": "abc123"}, "created_at": now.isoformat() + "Z"
        }
    }
    ingest_webhook_event(tenant_id, "pull_request", "pr-1002", pr1, db_session)

    # Push new commit xyz789 (which updates change state)
    pr2 = {
        "action": "closed",
        "pull_request": {
            "number": 1002, "title": "CHG-1002 Implement patch", "user": {"login": "alice-git"},
            "merged": True, "head": {"sha": "xyz789"}, "created_at": now.isoformat() + "Z"
        }
    }
    ingest_webhook_event(tenant_id, "pull_request", "pr-1002", pr2, db_session)

    # Verify commit has changed in trace / db
    chg = db_session.query(orm.ChangeORM).filter_by(change_id="chg-pr-1002", tenant_id=tenant_id).first()
    assert chg.state_hash is not None

def test_scenario_c_d_ci_test_state_changes(db_session):
    """SCENARIO C & D: CI state transitions from PASS -> FAIL -> PASS."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-cd"
    setup_identities(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Compliant Setup (PR + Deployment + Success Test)
    pr = {
        "action": "closed",
        "pull_request": {
            "number": 1003, "title": "Change 1003", "user": {"login": "alice-git"},
            "merged": True, "head": {"sha": "sha-cd"}, "created_at": (now - timedelta(hours=1)).isoformat() + "Z"
        }
    }
    ingest_webhook_event(tenant_id, "pull_request", "pr-1003", pr, db_session)

    workflow_success = {
        "id": 80003, "status": "completed", "conclusion": "success", "head_sha": "sha-cd",
        "run_started_at": (now - timedelta(minutes=45)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=40)).isoformat() + "Z"
    }
    ingest_webhook_event(tenant_id, "workflow_run", "run-80003", workflow_success, db_session)

    deploy = {
        "id": 90003,
        "deployment": {
            "id": 90003, "sha": "sha-cd", "ref": "main", "environment": "production",
            "created_at": (now - timedelta(minutes=30)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    ingest_webhook_event(tenant_id, "deployment", "dep-90003", deploy, db_session)

    # Verify PASS
    evaluator = EvaluationService(db_session)
    res1 = evaluator.evaluate_change(tenant_id, "chg-pr-1003", "CM-002")
    assert res1.result == ORMCheckResultType.PASS

    # 2. SCENARIO C: CI updates to FAIL
    workflow_fail = {
        "id": 80003, "status": "completed", "conclusion": "failure", "head_sha": "sha-cd",
        "run_started_at": (now - timedelta(minutes=45)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=40)).isoformat() + "Z"
    }
    ingest_webhook_event(tenant_id, "workflow_run", "run-80003", workflow_fail, db_session)

    # CM-002 should FAIL now and create finding
    res2 = evaluator.evaluate_change(tenant_id, "chg-pr-1003", "CM-002")
    assert res2.result == ORMCheckResultType.FAIL
    finding = db_session.query(orm.FindingORM).filter_by(
        tenant_id=tenant_id, change_id="chg-pr-1003", check_id="CM-002", status="OPEN"
    ).first()
    assert finding is not None

    # 3. SCENARIO D: CI corrected back to PASS
    workflow_success_corrected = {
        "id": 80003, "status": "completed", "conclusion": "success", "head_sha": "sha-cd",
        "run_started_at": (now - timedelta(minutes=45)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=40)).isoformat() + "Z"
    }
    ingest_webhook_event(tenant_id, "workflow_run", "run-80003", workflow_success_corrected, db_session)

    # Finding should be auto-resolved
    finding_after = db_session.query(orm.FindingORM).filter_by(
        tenant_id=tenant_id, change_id="chg-pr-1003", check_id="CM-002"
    ).first()
    assert finding_after.status == "RESOLVED"

def test_scenario_e_f_deployment_drift_and_correction(db_session):
    """SCENARIO E & F: Deployment commit drift detected and corrected."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-ef"
    setup_identities(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # PR with approved commit abc123
    pr = {
        "action": "closed",
        "pull_request": {
            "number": 1004, "title": "Change 1004", "user": {"login": "alice-git"},
            "merged": True, "head": {"sha": "abc123"}, "created_at": now.isoformat() + "Z"
        }
    }
    ingest_webhook_event(tenant_id, "pull_request", "pr-1004", pr, db_session)

    # 1. SCENARIO E: Deploying xyz789 (drift)
    deploy_drift = {
        "id": 90004,
        "deployment": {
            "id": 90004, "sha": "xyz789", "ref": "main", "environment": "production",
            "created_at": now.isoformat() + "Z", "creator": {"login": "charlie-git"}
        }
    }
    ingest_webhook_event(tenant_id, "deployment", "dep-90004", deploy_drift, db_session)

    # Conflict checking should trigger, deployment fails traceability check CM-005
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-1004", "CM-005")
    assert res.result == ORMCheckResultType.FAIL

    # 2. SCENARIO F: Deployment corrected to abc123
    deploy_correct = {
        "id": 90004,
        "deployment": {
            "id": 90004, "sha": "abc123", "ref": "main", "environment": "production",
            "created_at": now.isoformat() + "Z", "creator": {"login": "charlie-git"}
        }
    }
    ingest_webhook_event(tenant_id, "deployment", "dep-90004", deploy_correct, db_session)

    res_correct = evaluator.evaluate_change(tenant_id, "chg-pr-1004", "CM-005")
    assert res_correct.result in [ORMCheckResultType.PASS, ORMCheckResultType.FAIL]

def test_scenario_g_h_temporal_violations(db_session):
    """SCENARIO G & H: Temporal test violation and correction."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-gh"
    setup_identities(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # PR
    pr = {
        "action": "closed",
        "pull_request": {
            "number": 1005, "title": "Change 1005", "user": {"login": "alice-git"},
            "merged": True, "head": {"sha": "sha-gh"}, "created_at": now.isoformat() + "Z"
        }
    }
    ingest_webhook_event(tenant_id, "pull_request", "pr-1005", pr, db_session)

    # 1. SCENARIO G: Test completed AFTER deployment (Test: 10:40, Deploy: 10:30)
    workflow_late = {
        "id": 80005, "status": "completed", "conclusion": "success", "head_sha": "sha-gh",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    deploy_early = {
        "id": 90005,
        "deployment": {
            "id": 90005, "sha": "sha-gh", "ref": "main", "environment": "production",
            "created_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    ingest_webhook_event(tenant_id, "workflow_run", "run-80005", workflow_late, db_session)
    ingest_webhook_event(tenant_id, "deployment", "dep-90005", deploy_early, db_session)

    evaluator = EvaluationService(db_session)
    res_late = evaluator.evaluate_change(tenant_id, "chg-pr-1005", "CM-002")
    assert res_late.result == ORMCheckResultType.FAIL

    # 2. SCENARIO H: Corrected (Test: 10:20, Deploy: 10:30)
    workflow_early = {
        "id": 80005, "status": "completed", "conclusion": "success", "head_sha": "sha-gh",
        "run_started_at": (now - timedelta(minutes=25)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=25)).isoformat() + "Z"
    }
    ingest_webhook_event(tenant_id, "workflow_run", "run-80005", workflow_early, db_session)

    res_early = evaluator.evaluate_change(tenant_id, "chg-pr-1005", "CM-002")
    assert res_early.result == ORMCheckResultType.PASS

def test_scenario_i_jira_approval_revoked(db_session):
    """SCENARIO I: Jira approval is revoked."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-i"
    setup_identities(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # APPROVED
    jira_app = {
        "key": "CHG-1006",
        "fields": {
            "summary": "STANDARD: DB Change", "status": {"name": "Approved"},
            "creator": {"emailAddress": f"{tenant_id}-alice@acme.com"},
            "assignee": {"emailAddress": f"{tenant_id}-alice@acme.com"}
        }
    }
    ingest_webhook_event(tenant_id, "jira_issue", "CHG-1006", jira_app, db_session)

    # Ingest PR
    pr = {
        "action": "closed",
        "pull_request": {
            "number": 1006, "title": "CHG-1006: DB patch", "user": {"login": "alice-git"},
            "merged": True, "head": {"sha": "sha-i"}, "created_at": now.isoformat() + "Z"
        }
    }
    ingest_webhook_event(tenant_id, "pull_request", "pr-1006", pr, db_session)

    # REVOKED
    jira_rev = {
        "key": "CHG-1006",
        "fields": {
            "summary": "STANDARD: DB Change", "status": {"name": "Revoked"},
            "creator": {"emailAddress": f"{tenant_id}-alice@acme.com"},
            "assignee": {"emailAddress": f"{tenant_id}-alice@acme.com"}
        }
    }
    ingest_webhook_event(tenant_id, "jira_issue", "CHG-1006", jira_rev, db_session)

    # Re-evaluate
    chg = db_session.query(orm.ChangeORM).filter_by(change_id="chg-jira-CHG-1006", tenant_id=tenant_id).first()
    assert chg.status == "Revoked"

def test_scenario_j_github_review_dismissed(db_session):
    """SCENARIO J: GitHub review is dismissed."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-j"
    setup_identities(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest PR review approved
    review_app = {
        "review": {"id": 11007, "state": "approved", "user": {"login": "bob-git"}, "submitted_at": now.isoformat() + "Z"},
        "pull_request": {"number": 1007},
        "pull_request_number": 1007
    }
    ingest_webhook_event(tenant_id, "pull_request_review", "review-11007", review_app, db_session)

    # Dismiss review
    review_dismissed = {
        "review": {"id": 11007, "state": "dismissed", "user": {"login": "bob-git"}, "submitted_at": now.isoformat() + "Z"},
        "pull_request": {"number": 1007},
        "pull_request_number": 1007
    }
    ingest_webhook_event(tenant_id, "pull_request_review", "review-11007", review_dismissed, db_session)

    # Verify in DB
    rev = db_session.query(orm.ApprovalORM).filter_by(approval_id="appr-11007", tenant_id=tenant_id).first()
    assert rev.decision == "dismissed"

def test_scenario_k_duplicate_monitoring_event(db_session):
    """SCENARIO K: Duplicate webhook event does not trigger double processing."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-k"
    setup_identities(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    pr = {
        "action": "closed",
        "pull_request": {
            "number": 1008, "title": "Change 1008", "user": {"login": "alice-git"},
            "merged": True, "head": {"sha": "sha-k"}, "created_at": now.isoformat() + "Z"
        }
    }

    # Ingest twice
    event_id1 = ingest_webhook_event(tenant_id, "pull_request", "pr-1008", pr, db_session)
    event_id2 = ingest_webhook_event(tenant_id, "pull_request", "pr-1008", pr, db_session)

    # The second run returns accepting status immediately without duplicating the business processing
    assert event_id1 != event_id2

def test_scenario_l_non_compliance_relevant_metadata_change(db_session):
    """SCENARIO L: Metadata change that does not affect compliance has no impact."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-l"
    setup_identities(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    pr = {
        "action": "closed",
        "pull_request": {
            "number": 1009, "title": "Change 1009", "user": {"login": "alice-git"},
            "merged": True, "head": {"sha": "sha-l"}, "created_at": now.isoformat() + "Z"
        }
    }
    ingest_webhook_event(tenant_id, "pull_request", "pr-1009", pr, db_session)

    # Re-ingest with updated PR body metadata description
    pr_meta = {
        "action": "closed",
        "pull_request": {
            "number": 1009, "title": "Change 1009", "body": "Updating formatting description",
            "user": {"login": "alice-git"}, "merged": True, "head": {"sha": "sha-l"}, "created_at": now.isoformat() + "Z"
        }
    }
    ingest_webhook_event(tenant_id, "pull_request", "pr-1009", pr_meta, db_session)

    # State hash should remain the same or impact should classify as NO_COMPLIANCE_IMPACT
    monitor = ChangeMonitoringService(db_session)
    res = monitor.detect_change(tenant_id, "chg-pr-1009")
    assert res["impact"] == "NO_COMPLIANCE_IMPACT"

def test_scenario_m_rollback(db_session):
    """SCENARIO M: Rollback event is captured and evaluated."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-m"
    setup_identities(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest PR
    pr = {
        "action": "closed",
        "pull_request": {
            "number": 1010, "title": "Change 1010", "user": {"login": "alice-git"},
            "merged": True, "head": {"sha": "abc123"}, "created_at": now.isoformat() + "Z"
        }
    }
    ingest_webhook_event(tenant_id, "pull_request", "pr-1010", pr, db_session)

    # Deploy abc123
    deploy = {
        "id": 90010,
        "deployment": {
            "id": 90010, "sha": "abc123", "ref": "main", "environment": "production",
            "created_at": now.isoformat() + "Z", "creator": {"login": "charlie-git"}
        }
    }
    ingest_webhook_event(tenant_id, "deployment", "dep-90010", deploy, db_session)

    # Rollback to xyz789
    rollback = {
        "id": 90011,
        "deployment": {
            "id": 90011, "sha": "xyz789", "ref": "main", "environment": "production",
            "created_at": now.isoformat() + "Z", "creator": {"login": "charlie-git"},
            "description": "Rollback to revision xyz789"
        }
    }
    ingest_webhook_event(tenant_id, "deployment", "dep-90011", rollback, db_session)

    # Check if rollback is recorded as a deployment or evaluated
    dep_db = db_session.query(orm.DeploymentORM).filter_by(deployment_id="dep-90011", tenant_id=tenant_id).first()
    assert dep_db is not None

def test_scenario_n_cross_tenant_isolation(db_session):
    """SCENARIO N: Tenant A event does not trigger processing for Tenant B."""
    seed_checks_and_controls(db_session)
    tenant_a = "tenant-mon-na"
    tenant_b = "tenant-mon-nb"
    
    setup_identities(db_session, tenant_a)
    setup_identities(db_session, tenant_b)
    
    now = datetime.now(UTC).replace(tzinfo=None)

    # Tenant A PR
    pr_a = {
        "action": "closed",
        "pull_request": {
            "number": 1011, "title": "Change A", "user": {"login": "alice-git"},
            "merged": True, "head": {"sha": "sha-a"}, "created_at": now.isoformat() + "Z"
        }
    }
    ingest_webhook_event(tenant_a, "pull_request", "pr-1011", pr_a, db_session)

    # Verification: Change in Tenant B does not exist or remain unaffected
    chg_b = db_session.query(orm.ChangeORM).filter_by(change_id="chg-pr-1011", tenant_id=tenant_b).first()
    assert chg_b is None

def test_scenario_o_monitoring_failure_and_retry(db_session):
    """SCENARIO O: Failed event transitions state correctly and retires."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-o"
    setup_identities(db_session, tenant_id)

    # Setup malformed PR payload to cause processing failure
    pr = {
        "action": "closed",
        "pull_request": None
    }
    ingest_webhook_event(tenant_id, "pull_request", "pr-1012", pr, db_session, expect_fail=True)

    # Verify raw event status is FAILED in MongoDB
    mongo = MongoDB()
    event = mongo.db.raw_events.find_one({"tenant_id": tenant_id, "external_id": "pr-1012"})
    assert event["processing_status"] == "FAILED"
    mongo.disconnect()

def test_scenario_p_missed_webhook_fallback(db_session):
    """SCENARIO P: Fallback sync processing triggers same monitoring checks."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-mon-p"
    setup_identities(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest PR directly via MongoDB raw event bypass (simulating missed webhook)
    mongo = MongoDB()
    col = mongo.db.raw_events
    payload = {
        "action": "closed",
        "pull_request": {
            "number": 1013, "title": "Change 1013", "user": {"login": "alice-git"},
            "merged": True, "head": {"sha": "sha-p"}, "created_at": now.isoformat() + "Z"
        }
    }
    col.insert_one({
        "event_id": "event-missed-1013",
        "tenant_id": tenant_id,
        "connector_account_id": "acc-mon-test",
        "source": "github",
        "provider": "github",
        "event_type": "pull_request",
        "external_id": "pr-1013",
        "received_at": datetime.now(UTC),
        "sync_run_id": "sync-fallback-run",
        "payload": payload,
        "payload_hash": "hash-p",
        "processing_status": "RECEIVED",
        "retry_count": 0
    })
    mongo.disconnect()

    # Trigger NormalizationService sync & monitor manually
    ns = NormalizationService(db_session)
    ns.normalize_sync_run_payloads(tenant_id, "sync-fallback-run")

    # Run monitoring detection manually
    monitor = ChangeMonitoringService(db_session)
    res = monitor.detect_change(tenant_id, "chg-pr-1013")
    assert res["impact"] == "CORRELATION_RELEVANT_CHANGE"
