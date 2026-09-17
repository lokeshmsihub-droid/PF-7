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
from app.services.evidence_service import EvidenceService
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
            # Upsert control
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

            # Upsert check
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
    # Ensure baseline entities exist
    norm_service = NormalizationService(db_session)
    norm_service._ensure_baseline_entities(tenant_id)
    
    # Standard Users
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
            
    # Identity mappings (GitHub handle to internal user ID)
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
# 1. SCENARIOS TESTS
# -------------------------------------------------------------

def test_scenario_a_compliant_change(db_session):
    """Scenario A: Standard Compliant Change (Passes all checks)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-a"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)

    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest Webhook events in Mongo
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 101,
            "title": "STANDARD: CM-005 Auth Token Refactoring",
            "body": "Fixes auth token generation issues",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-compliant"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=15)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=15)).isoformat() + "Z"
        }
    }
    pr_evt_id = create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-101", pr_payload)

    review_payload = {
        "id": 201,
        "pull_request_number": 101,
        "state": "approved",
        "submitted_at": (now - timedelta(minutes=30)).isoformat() + "Z",
        "user": {"login": "bob-git"}
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request_review", "rev-201", review_payload)

    workflow_payload = {
        "id": 88001,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "sha-compliant",
        "run_started_at": (now - timedelta(minutes=50)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=40)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88001", workflow_payload)

    deploy_payload = {
        "id": 99001,
        "deployment": {
            "id": 99001,
            "sha": "sha-compliant",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=10)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99001", deploy_payload)

    # 1. Normalize
    norm_service = NormalizationService(db_session)
    count = norm_service.normalize_sync_run_payloads(tenant_id, sync_run_id)
    assert count == 4

    # 2. Correlate
    corr_service = CorrelationService(db_session)
    summary = corr_service.correlate_sync_run_entities(tenant_id)
    assert summary["tests_correlated"] == 1
    assert summary["deployments_correlated"] == 1

    # Seed manual authorization record to satisfy authorization required CM-001/015
    auth_orm = orm.AuthorizationORM(
        authorization_id="auth-scen-a",
        tenant_id=tenant_id,
        change_id="chg-pr-101",
        authorized_by="usr-bob",
        status="APPROVED",
        authorized_at=now - timedelta(minutes=70),
        source="jira"
    )
    db_session.add(auth_orm)
    db_session.commit()

    # 3. Store Evidence
    evidence_service = EvidenceService(db_session)
    ev = evidence_service.store_evidence(
        tenant_id=tenant_id,
        change_id="chg-pr-101",
        file_name=pr_evt_id, # Set file name to raw event ID for trace
        content=b"pr payload evidence",
        content_type="application/json"
    )

    # 4. Evaluate
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-101", "CM-002")
    assert res.result == ORMCheckResultType.PASS

    res_auth = evaluator.evaluate_change(tenant_id, "chg-pr-101", "CM-001")
    print("\n[DEBUG] res_auth.details =", res_auth.details)
    print("[DEBUG] res_auth.evaluation_inputs =", res_auth.evaluation_inputs)
    assert res_auth.result == ORMCheckResultType.PASS

    # Verify Segregation of Duties (CM-004): requester(alice) != approver(bob) != deployer(charlie)
    res_sod = evaluator.evaluate_change(tenant_id, "chg-pr-101", "CM-004")
    assert res_sod.result == ORMCheckResultType.PASS

    # Verify Evidence trace: Compliance Result -> Evidence Metadata -> Raw Event ID
    db_session.refresh(res)
    assert len(res.evidences) >= 1
    assert any(e.evidence_id == ev.evidence_id for e in res.evidences)
    assert any(e.source_record_id == pr_evt_id for e in res.evidences)


def test_scenario_b_testing_failure(db_session):
    """Scenario B: Testing Failure (Fails CM-002) -> Generates Remediation Task"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-b"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)

    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest Webhook events in Mongo
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 102,
            "title": "NORMAL: CM-002 Auth Token Refactoring",
            "body": "Fixes auth token generation issues",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-test-fail"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=15)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=15)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-102", pr_payload)

    review_payload = {
        "id": 202,
        "pull_request_number": 102,
        "state": "approved",
        "submitted_at": (now - timedelta(minutes=30)).isoformat() + "Z",
        "user": {"login": "bob-git"}
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request_review", "rev-202", review_payload)

    # Workflow Run FAIL
    workflow_payload = {
        "id": 88002,
        "status": "completed",
        "conclusion": "failure",
        "head_sha": "sha-test-fail",
        "run_started_at": (now - timedelta(minutes=50)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=40)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88002", workflow_payload)

    deploy_payload = {
        "id": 99002,
        "deployment": {
            "id": 99002,
            "sha": "sha-test-fail",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=10)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99002", deploy_payload)

    # Run pipeline
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Evaluate CM-002 -> Fail
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-102", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    # Ingest finding and remediation
    find_service = FindingService(db_session)
    finding = find_service.process_check_result(res)
    assert finding is not None
    assert finding.status == "OPEN"
    assert finding.severity == "high"

    task = db_session.query(orm.RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()
    assert task is not None
    assert task.status == "PENDING"
    assert task.owner == "usr-alice" # change owner
    assert task.priority == "critical"
    assert task.due_date is not None

    # Test Deduplication: process again, should NOT create duplicate finding
    finding_dup = find_service.process_check_result(res)
    assert finding_dup.finding_id == finding.finding_id
    total_findings = db_session.query(orm.FindingORM).filter_by(
        tenant_id=tenant_id, check_id="CM-002", change_id="chg-pr-102", status="OPEN"
    ).count()
    assert total_findings == 1


def test_scenario_c_deployment_before_testing(db_session):
    """Scenario C: Deployment Before Testing (Temporal Failure -> Fails CM-002)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-c"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)

    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest Webhook events in Mongo
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 103,
            "title": "NORMAL: CM-002 Auth Token Refactoring",
            "body": "Fixes auth token generation issues",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-test-late"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=15)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=15)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-103", pr_payload)

    review_payload = {
        "id": 203,
        "pull_request_number": 103,
        "state": "approved",
        "submitted_at": (now - timedelta(minutes=30)).isoformat() + "Z",
        "user": {"login": "bob-git"}
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request_review", "rev-203", review_payload)

    # Deployment first (now-20m)
    deploy_payload = {
        "id": 99003,
        "deployment": {
            "id": 99003,
            "sha": "sha-test-late",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99003", deploy_payload)

    # Workflow Run completes later (now-10m)
    workflow_payload = {
        "id": 88003,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "sha-test-late",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88003", workflow_payload)

    # Run pipeline
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Evaluate CM-002 -> Fail because tested_at (now-10m) is NOT before deployed_at (now-20m)
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-103", "CM-002")
    assert res.result == ORMCheckResultType.FAIL
    assert "Rule Failed" in res.details["message"]


def test_scenario_d_deployment_without_change(db_session):
    """Scenario D: Deployment Without Change / Bypass (Fails CM-005)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-d"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)

    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest ONLY Deployment event
    deploy_payload = {
        "id": 99004,
        "deployment": {
            "id": 99004,
            "sha": "sha-orphaned-deployment",
            "ref": "main",
            "environment": "production",
            "created_at": now.isoformat() + "Z",
            "updated_at": now.isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99004", deploy_payload)

    # Run pipeline
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Deployment in DB has no change_id (orphaned)
    deploy_db = db_session.query(orm.DeploymentORM).filter_by(deployment_id="dep-99004", tenant_id=tenant_id).first()
    assert deploy_db is not None
    assert deploy_db.change_id is None

    # Simulate evaluation: we create a Change stub representing the untracked deploy
    # (or evaluating it directly via normal check evaluating unlinked data)
    # If we evaluate it with a stub change lacking authorizations, CM-005/015 must fail
    stub_change = orm.ChangeORM(
        change_id="chg-bypass-stub",
        tenant_id=tenant_id,
        external_id="untracked-1",
        source="github",
        title="Untracked Deploy Stub",
        description="",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-charlie",
        owner_id="usr-charlie",
        environment_id="env-prod",
        application_id="app-default",
        status="OPEN"
    )
    db_session.add(stub_change)
    deploy_db.change_id = "chg-bypass-stub"
    db_session.commit()

    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-bypass-stub", "CM-005")
    assert res.result == ORMCheckResultType.FAIL


def test_scenario_e_missing_data(db_session):
    """Scenario E: Missing Data (CM-003 resolves to INSUFFICIENT_DATA due to missing review approvals)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-scenario-e"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)

    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest PR & Deploy events but NO approval review event
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 105,
            "title": "NORMAL: CM-003 Auth Token Refactoring",
            "body": "Fixes auth token generation issues",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-missing-approval"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=15)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=15)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-105", pr_payload)

    deploy_payload = {
        "id": 99005,
        "deployment": {
            "id": 99005,
            "sha": "sha-missing-approval",
            "ref": "main",
            "environment": "production",
            "created_at": now.isoformat() + "Z",
            "updated_at": now.isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99005", deploy_payload)

    # Run pipeline
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Evaluate CM-003 -> INSUFFICIENT_DATA because approval table has no records for this change
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-105", "CM-003")
    assert res.result == ORMCheckResultType.INSUFFICIENT_DATA
    assert "Required" in res.details["message"]


# -------------------------------------------------------------
# 2. ADDITIONAL LIFE CYCLE VERIFICATIONS
# -------------------------------------------------------------

def test_correlation_valid_invalid_missing(db_session):
    """Validate correlation engine mapping: Valid link, Invalid link, and Missing link."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-corr-val"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)

    now = datetime.now(UTC).replace(tzinfo=None)

    # PR 106 - HEAD SHA: sha-corr-valid
    pr_valid_payload = {
        "action": "closed",
        "pull_request": {
            "number": 106,
            "title": "NORMAL: PR Valid",
            "body": "",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-corr-valid"},
            "merged_at": (now - timedelta(minutes=15)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-106", pr_valid_payload)

    # PR 107 - HEAD SHA: sha-corr-mismatched
    pr_invalid_payload = {
        "action": "closed",
        "pull_request": {
            "number": 107,
            "title": "NORMAL: PR Invalid",
            "body": "",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-corr-mismatched"},
            "merged_at": (now - timedelta(minutes=15)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-107", pr_invalid_payload)

    # Deploy 106: SHA matches PR 106 -> Correlated
    deploy_valid_payload = {
        "id": 99006,
        "deployment": {
            "id": 99006,
            "sha": "sha-corr-valid",
            "ref": "main",
            "environment": "production",
            "created_at": now.isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99006", deploy_valid_payload)

    # Deploy 107: SHA matches nothing -> NOT Correlated
    deploy_invalid_payload = {
        "id": 99007,
        "deployment": {
            "id": 99007,
            "sha": "sha-some-other-commit",
            "ref": "main",
            "environment": "production",
            "created_at": now.isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99007", deploy_invalid_payload)

    # Run Normalizer
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)

    # Run Correlation
    corr_service = CorrelationService(db_session)
    corr_service.correlate_sync_run_entities(tenant_id)

    # Verify matching deploy correlated
    deploy_v = db_session.query(orm.DeploymentORM).filter_by(deployment_id="dep-99006", tenant_id=tenant_id).first()
    assert deploy_v.change_id == "chg-pr-106"

    # Verify mismatched deploy NOT correlated
    deploy_inv = db_session.query(orm.DeploymentORM).filter_by(deployment_id="dep-99007", tenant_id=tenant_id).first()
    assert deploy_inv.change_id is None


def test_remediation_linkage_and_recheck_flow(db_session):
    """Validate detect -> Explain -> Fix -> Verify (Recheck) lifecycle."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-recheck-flow"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)

    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest Webhook events in Mongo (Failing test initially)
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 108,
            "title": "NORMAL: CM-002 Refactor",
            "body": "",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-recheck"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=15)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=15)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-108", pr_payload)

    # Workflow Run FAIL
    workflow_payload = {
        "id": 88008,
        "status": "completed",
        "conclusion": "failure",
        "head_sha": "sha-recheck",
        "run_started_at": (now - timedelta(minutes=50)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=40)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88008", workflow_payload)

    deploy_payload = {
        "id": 99008,
        "deployment": {
            "id": 99008,
            "sha": "sha-recheck",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=10)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99008", deploy_payload)

    # Ingest, Normalize, Correlate
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # 1. Detect Failure (Evaluate)
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-pr-108", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    # Ingest finding and remediation task
    find_service = FindingService(db_session)
    finding = find_service.process_check_result(res)
    assert finding is not None
    assert finding.status == "OPEN"

    task = db_session.query(orm.RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()
    assert task is not None
    assert task.status == "PENDING"

    # 2. Fix the violation: update test run completion to PASS in DB
    test_run = db_session.query(orm.TestORM).filter_by(test_id="run-88008", tenant_id=tenant_id).first()
    test_run.status = ORMTestStatus.PASS
    db_session.commit()

    # 3. Verify/Verify via Recheck
    recheck_service = RecheckService(db_session)
    recheck_summary = recheck_service.recheck_finding(tenant_id, finding.finding_id)
    assert recheck_summary["new_result"] == "PASS"
    assert recheck_summary["finding_status"] == "RESOLVED"

    # Verify final statuses are resolved
    assert finding.status == "RESOLVED"
    assert task.status == "RESOLVED"
