import pytest
import uuid
import json
import hashlib
from datetime import datetime, timedelta, UTC
from app.db.mongodb import MongoDBClient as MongoDB
from app.services.normalization_service import NormalizationService
from app.services.correlation_service import CorrelationService
from app.services.evaluation_service import EvaluationService
from app.services.finding_service import FindingService
from app.services.recheck_service import RecheckService
from app.models import orm
from app.models.orm import ORMChangeType, ORMTestStatus, ORMCheckResultType

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
    mongo = MongoDB()
    col = mongo.db.raw_events
    event_id = str(uuid.uuid4())
    pl_str = json.dumps(payload, sort_keys=True, default=str)
    pl_hash = hashlib.sha256(pl_str.encode("utf-8")).hexdigest()
    col.insert_one({
        "event_id": event_id,
        "tenant_id": tenant_id,
        "connector_account_id": "acc-e2e-test",
        "source": "jira" if event_type == "jira_issue" else "github",
        "provider": "jira" if event_type == "jira_issue" else "github",
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
        lnk = db_session.query(orm.IdentityLinkORM).filter_by(internal_user_id=uid, tenant_id=tenant_id, source="github").first()
        if not lnk:
            db_session.add(orm.IdentityLinkORM(
                internal_user_id=uid, tenant_id=tenant_id, source="github",
                external_user_id=f"ext-{handle}", external_username=handle, status="ACTIVE"
            ))
    db_session.commit()

# -------------------------------------------------------------
# SCENARIOS
# -------------------------------------------------------------

def test_scenario_a_fully_compliant_change(db_session):
    """Scenario A: Fully compliant change (Jira -> GitHub -> CI PASS -> Deployment same commit)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-a"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Jira Issue (CHG-1001)
    jira_payload = {
        "key": "CHG-1001",
        "fields": {
            "summary": "STANDARD: CM-002 Compliant Auth Update",
            "description": "Compliant update",
            "creator": {"emailAddress": "alice@acme.com"},
            "assignee": {"emailAddress": "alice@acme.com"},
            "status": {"name": "Done"},
            "created": (now - timedelta(hours=2)).isoformat() + "+0000",
            "updated": (now - timedelta(minutes=65)).isoformat() + "+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_is_emergency": {"value": "No"}
        },
        "changelog": {
            "histories": [
                {
                    "id": "appr-a",
                    "created": (now - timedelta(minutes=70)).isoformat() + "+0000",
                    "author": {"emailAddress": "manager@acme.com"},
                    "items": [{"field": "status", "fromString": "In Review", "toString": "Approved"}]
                }
            ]
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "jira_issue", "CHG-1001", jira_payload)

    # 2. GitHub PR linked to CHG-1001
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 1001,
            "title": "CHG-1001: Implement Auth Changes",
            "body": "Fixes CHG-1001",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-itsm-compliant"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-1001", pr_payload)

    # 3. GitHub Review (Code Review)
    review_payload = {
        "id": 201,
        "pull_request_number": 1001,
        "state": "approved",
        "submitted_at": (now - timedelta(minutes=30)).isoformat() + "Z",
        "user": {"login": "bob-git"}
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request_review", "rev-201", review_payload)

    # 4. CI Test PASS
    workflow_payload = {
        "id": 88001,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "sha-itsm-compliant",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88001", workflow_payload)

    # 5. Deployment same commit
    deploy_payload = {
        "id": 99001,
        "deployment": {
            "id": 99001,
            "sha": "sha-itsm-compliant",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99001", deploy_payload)

    # Run
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    evaluator = EvaluationService(db_session)
    for check_id in ["CM-001", "CM-002", "CM-003", "CM-004", "CM-005"]:
        res = evaluator.evaluate_change(tenant_id, "chg-pr-1001", check_id)
        assert res.result == ORMCheckResultType.PASS

def test_scenario_b_failed_ci_test(db_session):
    """Scenario B: Failed CI test (CI = FAILED -> CM-002 FAIL -> Finding & Remediation generated)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-b"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Jira Issue (CHG-1002)
    jira_payload = {
        "key": "CHG-1002",
        "fields": {
            "summary": "STANDARD: CM-002 Failed CI Auth Update",
            "description": "Auth update",
            "creator": {"emailAddress": "alice@acme.com"},
            "assignee": {"emailAddress": "alice@acme.com"},
            "status": {"name": "Done"},
            "created": (now - timedelta(hours=2)).isoformat() + "+0000",
            "updated": (now - timedelta(minutes=65)).isoformat() + "+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_is_emergency": {"value": "No"}
        },
        "changelog": {
            "histories": [
                {
                    "id": "appr-b",
                    "created": (now - timedelta(minutes=70)).isoformat() + "+0000",
                    "author": {"emailAddress": "manager@acme.com"},
                    "items": [{"field": "status", "fromString": "In Review", "toString": "Approved"}]
                }
            ]
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "jira_issue", "CHG-1002", jira_payload)

    # 2. GitHub PR linked to CHG-1002
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 1002,
            "title": "CHG-1002: Implement Auth Changes",
            "body": "Fixes CHG-1002",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-itsm-fail"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-1002", pr_payload)

    # 3. CI Test FAIL
    workflow_payload = {
        "id": 88002,
        "status": "completed",
        "conclusion": "failure",
        "head_sha": "sha-itsm-fail",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88002", workflow_payload)

    # 4. Deployment same commit
    deploy_payload = {
        "id": 99002,
        "deployment": {
            "id": 99002,
            "sha": "sha-itsm-fail",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99002", deploy_payload)

    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-1002", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    # Ingest finding and remediation
    find_service = FindingService(db_session)
    finding = find_service.process_check_result(res)
    assert finding is not None
    assert finding.status == "OPEN"

    task = db_session.query(orm.RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()
    assert task is not None
    assert task.status == "PENDING"

def test_scenario_c_deployment_before_test(db_session):
    """Scenario C: Deployment before test (Temporal violation -> CM-002 FAIL)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-c"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Jira Issue (CHG-1003)
    jira_payload = {
        "key": "CHG-1003",
        "fields": {
            "summary": "STANDARD: CM-002 Temporal Late Test",
            "description": "Late test",
            "creator": {"emailAddress": "alice@acme.com"},
            "assignee": {"emailAddress": "alice@acme.com"},
            "status": {"name": "Done"},
            "created": (now - timedelta(hours=2)).isoformat() + "+0000",
            "updated": (now - timedelta(minutes=65)).isoformat() + "+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_is_emergency": {"value": "No"}
        },
        "changelog": {
            "histories": [
                {
                    "id": "appr-c",
                    "created": (now - timedelta(minutes=70)).isoformat() + "+0000",
                    "author": {"emailAddress": "manager@acme.com"},
                    "items": [{"field": "status", "fromString": "In Review", "toString": "Approved"}]
                }
            ]
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "jira_issue", "CHG-1003", jira_payload)

    # 2. GitHub PR linked to CHG-1003
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 1003,
            "title": "CHG-1003: Implement Auth Changes",
            "body": "Fixes CHG-1003",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-itsm-late"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-1003", pr_payload)

    # 3. Deployment first (10:30, i.e., now - 20m)
    deploy_payload = {
        "id": 99003,
        "deployment": {
            "id": 99003,
            "sha": "sha-itsm-late",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99003", deploy_payload)

    # 4. CI Test completes later (10:40, i.e., now - 10m)
    workflow_payload = {
        "id": 88003,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "sha-itsm-late",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88003", workflow_payload)

    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-1003", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

def test_scenario_d_commit_mismatch(db_session):
    """Scenario D: Commit mismatch (PR commit abc123, deployment commit xyz789 -> Correlation rejected -> CM-005 FAIL)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-d"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Jira Issue (CHG-1004)
    jira_payload = {
        "key": "CHG-1004",
        "fields": {
            "summary": "STANDARD: CM-005 Mismatched Commits",
            "description": "Commit mismatch",
            "creator": {"emailAddress": "alice@acme.com"},
            "assignee": {"emailAddress": "alice@acme.com"},
            "status": {"name": "Done"},
            "created": (now - timedelta(hours=2)).isoformat() + "+0000",
            "updated": (now - timedelta(minutes=65)).isoformat() + "+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_is_emergency": {"value": "No"}
        },
        "changelog": {
            "histories": [
                {
                    "id": "appr-d",
                    "created": (now - timedelta(minutes=70)).isoformat() + "+0000",
                    "author": {"emailAddress": "manager@acme.com"},
                    "items": [{"field": "status", "fromString": "In Review", "toString": "Approved"}]
                }
            ]
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "jira_issue", "CHG-1004", jira_payload)

    # 2. GitHub PR with commit abc123
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 1004,
            "title": "CHG-1004: Implement Auth Changes",
            "body": "Fixes CHG-1004",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "abc123"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-1004", pr_payload)

    # 3. Deployment with commit xyz789
    deploy_payload = {
        "id": 99004,
        "deployment": {
            "id": 99004,
            "sha": "xyz789",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99004", deploy_payload)

    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Verify that deployment commit "xyz789" was NOT correlated to PR "chg-pr-1004"
    deploy_db = db_session.query(orm.DeploymentORM).filter_by(deployment_id="dep-99004", tenant_id=tenant_id).first()
    assert deploy_db is not None
    assert deploy_db.change_id is None

    # Evaluate CM-005 for chg-pr-1004 -> Expect FAIL since no deployment is linked
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-1004", "CM-005")
    assert res.result == ORMCheckResultType.FAIL

def test_scenario_e_no_ci_evidence(db_session):
    """Scenario E: No CI evidence (Deployment exists, no test evidence -> CM-002 INSUFFICIENT_DATA)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-e"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Jira Issue (CHG-1005)
    jira_payload = {
        "key": "CHG-1005",
        "fields": {
            "summary": "STANDARD: CM-002 Missing CI Evidence",
            "description": "No CI evidence",
            "creator": {"emailAddress": "alice@acme.com"},
            "assignee": {"emailAddress": "alice@acme.com"},
            "status": {"name": "Done"},
            "created": (now - timedelta(hours=2)).isoformat() + "+0000",
            "updated": (now - timedelta(minutes=65)).isoformat() + "+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_is_emergency": {"value": "No"}
        },
        "changelog": {
            "histories": [
                {
                    "id": "appr-e",
                    "created": (now - timedelta(minutes=70)).isoformat() + "+0000",
                    "author": {"emailAddress": "manager@acme.com"},
                    "items": [{"field": "status", "fromString": "In Review", "toString": "Approved"}]
                }
            ]
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "jira_issue", "CHG-1005", jira_payload)

    # 2. GitHub PR
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 1005,
            "title": "CHG-1005: Implement Auth Changes",
            "body": "Fixes CHG-1005",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-itsm-missing-test"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-1005", pr_payload)

    # 3. Deployment (no test events seeded)
    deploy_payload = {
        "id": 99005,
        "deployment": {
            "id": 99005,
            "sha": "sha-itsm-missing-test",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99005", deploy_payload)

    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-1005", "CM-002")
    assert res.result == ORMCheckResultType.INSUFFICIENT_DATA

def test_scenario_f_unauthorized_deployment(db_session):
    """Scenario F: Unauthorized deployment (Deployment exists, no Jira authorization -> CM-005 FAIL)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-f"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. GitHub PR with no Jira link
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 1006,
            "title": "Untracked changes",
            "body": "No CHG code in title",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-itsm-unauthorized"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-1006", pr_payload)

    # 2. Deployment
    deploy_payload = {
        "id": 99006,
        "deployment": {
            "id": 99006,
            "sha": "sha-itsm-unauthorized",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99006", deploy_payload)

    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-1006", "CM-005")
    # Should fail due to missing Jira authorization
    assert res.result == ORMCheckResultType.FAIL

def test_scenario_g_duplicate_ci_event(db_session):
    """Scenario G: Duplicate CI event (Same pipeline event received twice -> 1 normalized record)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-g"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    workflow_payload = {
        "id": 88007,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "sha-dup-test",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }

    # Ingest twice
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88007", workflow_payload)
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88007", workflow_payload)

    norm_service = NormalizationService(db_session)
    # Deduplication in collection prevents duplicate mongo raw events, but if they exist in mongo (e.g. from webhook retries),
    # self.db.merge(test_run) must resolve to a single test record.
    norm_service.normalize_sync_run_payloads(tenant_id, sync_run_id)

    test_runs = db_session.query(orm.TestORM).filter_by(test_id="run-88007", tenant_id=tenant_id).all()
    assert len(test_runs) == 1

def test_scenario_h_duplicate_deployment(db_session):
    """Scenario H: Duplicate deployment (Same deployment event received twice -> 1 deployment)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-h"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    deploy_payload = {
        "id": 99008,
        "deployment": {
            "id": 99008,
            "sha": "sha-dup-deploy",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }

    # Ingest twice
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99008", deploy_payload)
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99008", deploy_payload)

    norm_service = NormalizationService(db_session)
    norm_service.normalize_sync_run_payloads(tenant_id, sync_run_id)

    deployments = db_session.query(orm.DeploymentORM).filter_by(deployment_id="dep-99008", tenant_id=tenant_id).all()
    assert len(deployments) == 1

def test_scenario_i_recheck(db_session):
    """Scenario I: Recheck (FAIL -> fix test status -> Recheck resolves finding)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-i"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Jira Issue (CHG-1009)
    jira_payload = {
        "key": "CHG-1009",
        "fields": {
            "summary": "STANDARD: CM-002 Recheck Auth Update",
            "description": "Auth update",
            "creator": {"emailAddress": "alice@acme.com"},
            "assignee": {"emailAddress": "alice@acme.com"},
            "status": {"name": "Done"},
            "created": (now - timedelta(hours=2)).isoformat() + "+0000",
            "updated": (now - timedelta(minutes=65)).isoformat() + "+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_is_emergency": {"value": "No"}
        },
        "changelog": {
            "histories": [
                {
                    "id": "appr-i",
                    "created": (now - timedelta(minutes=70)).isoformat() + "+0000",
                    "author": {"emailAddress": "manager@acme.com"},
                    "items": [{"field": "status", "fromString": "In Review", "toString": "Approved"}]
                }
            ]
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "jira_issue", "CHG-1009", jira_payload)

    # 2. GitHub PR linked to CHG-1009
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 1009,
            "title": "CHG-1009: Implement Auth Changes",
            "body": "Fixes CHG-1009",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-itsm-recheck"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-1009", pr_payload)

    # 3. CI Test FAIL initially
    workflow_payload = {
        "id": 88009,
        "status": "completed",
        "conclusion": "failure",
        "head_sha": "sha-itsm-recheck",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88009", workflow_payload)

    # 4. Deployment
    deploy_payload = {
        "id": 99009,
        "deployment": {
            "id": 99009,
            "sha": "sha-itsm-recheck",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99009", deploy_payload)

    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-1009", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    find_service = FindingService(db_session)
    finding = find_service.process_check_result(res)
    assert finding is not None
    assert finding.status == "OPEN"

    task = db_session.query(orm.RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()
    assert task is not None
    assert task.status == "PENDING"

    # Fix the test run in DB (simulate re-running pipeline successfully)
    test_run = db_session.query(orm.TestORM).filter_by(test_id="run-88009", tenant_id=tenant_id).first()
    test_run.status = ORMTestStatus.PASS
    db_session.commit()

    recheck_service = RecheckService(db_session)
    recheck_summary = recheck_service.recheck_finding(tenant_id, finding.finding_id)
    assert recheck_summary["new_result"] == "PASS"
    assert recheck_summary["finding_status"] == "RESOLVED"

    assert finding.status == "RESOLVED"
    assert task.status == "RESOLVED"
