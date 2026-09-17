import pytest
import uuid
import json
import hashlib
from datetime import datetime, timedelta, UTC
from app.db.mongodb import MongoDBClient as MongoDB
from app.services.normalization_service import NormalizationService
from app.services.correlation_service import CorrelationService
from app.services.evaluation_service import EvaluationService
from app.services.trace_service import TraceService
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
        (f"usr-{tenant_id}-alice", "Alice E2E", f"{tenant_id}-alice@acme.com", "developer"),
        (f"usr-{tenant_id}-bob", "Bob E2E", f"{tenant_id}-bob@acme.com", "qa"),
        (f"usr-{tenant_id}-charlie", "Charlie E2E", f"{tenant_id}-charlie@acme.com", "ops")
    ]
    for uid, name, email, role in users:
        u = db_session.query(orm.UserORM).filter_by(internal_user_id=uid, tenant_id=tenant_id).first()
        if not u:
            db_session.add(orm.UserORM(
                internal_user_id=uid, tenant_id=tenant_id, name=name, email=email, role=role, status="ACTIVE"
            ))
            
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
                external_user_id=f"ext-{handle}", external_username=handle, status="ACTIVE"
            ))
    db_session.commit()

# -------------------------------------------------------------
# TEST CASES
# -------------------------------------------------------------

def test_scenario_a_complete_valid_chain(db_session):
    """Scenario A: Complete valid chain (Jira -> PR -> Commit -> CI -> Deployment)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-trace-a"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Jira Issue
    jira_payload = {
        "key": "CHG-1001",
        "fields": {
            "summary": "STANDARD: DB Auth Patch",
            "description": "Auth changes",
            "creator": {"emailAddress": f"{tenant_id}-alice@acme.com"},
            "assignee": {"emailAddress": f"{tenant_id}-alice@acme.com"},
            "status": {"name": "Done"},
            "created": (now - timedelta(hours=2)).isoformat() + "+0000",
            "updated": now.isoformat() + "+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_is_emergency": {"value": "No"}
        },
        "changelog": {
            "histories": [
                {
                    "id": "appr-a",
                    "created": (now - timedelta(minutes=70)).isoformat() + "+0000",
                    "author": {"emailAddress": f"{tenant_id}-bob@acme.com"},
                    "items": [{"field": "status", "fromString": "In Review", "toString": "Approved"}]
                }
            ]
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "jira_issue", "CHG-1001", jira_payload)

    # 2. GitHub PR
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 1001,
            "title": "CHG-1001: Implement Auth Changes",
            "body": "Fixes CHG-1001",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-trace-compliant"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-1001", pr_payload)

    # 3. CI Test
    workflow_payload = {
        "id": 88001,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "sha-trace-compliant",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88001", workflow_payload)

    # 4. Deployment
    deploy_payload = {
        "id": 99001,
        "deployment": {
            "id": 99001,
            "sha": "sha-trace-compliant",
            "ref": "main",
            "environment": "production",
            "created_at": (now - timedelta(minutes=5)).isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99001", deploy_payload)

    # Execute Sync & Correlate
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Reconstruct trace
    trace_service = TraceService(db_session)
    trace = trace_service.get_change_trace(tenant_id, "chg-pr-1001")

    assert trace["status"] == "COMPLETE"
    assert len(trace["relationships"]) >= 3

    # Verify relationship provenance details are stored
    for rel in trace["relationships"]:
        assert rel["correlation_method"] is not None
        assert rel["correlation_evidence"] is not None
        assert rel["relationship_state"] == "CORRELATED"

def test_scenario_bc_orphan_detection(db_session):
    """Scenario B/C: Jira without GitHub / GitHub without Jira (Orphan changes)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-trace-bc"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest Jira ticket only
    jira_payload = {
        "key": "CHG-2002",
        "fields": {
            "summary": "STANDARD: Orphan Jira Issue",
            "creator": {"emailAddress": f"{tenant_id}-alice@acme.com"},
            "assignee": {"emailAddress": f"{tenant_id}-alice@acme.com"},
            "status": {"name": "Done"},
            "created": now.isoformat() + "+0000",
            "updated": now.isoformat() + "+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_is_emergency": {"value": "No"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "jira_issue", "CHG-2002", jira_payload)

    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Reconstruct trace for CHG-2002 -> Should be PARTIAL (missing GitHub, CI, Deploy)
    trace_service = TraceService(db_session)
    trace = trace_service.get_change_trace(tenant_id, "chg-jira-CHG-2002")
    assert trace["status"] == "PARTIAL"
    assert len(trace["github"]["pull_requests"]) == 0

def test_scenario_de_commit_mismatch(db_session):
    """Scenario D/E: CI / Deployment commit mismatch (no relationship, rejected)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-trace-de"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest PR with commit abc123
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 2003,
            "title": "Mismatched Commits PR",
            "body": "",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "abc123"},
            "created_at": now.isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-2003", pr_payload)

    # Ingest Workflow Run with commit xyz789
    workflow_payload = {
        "id": 88003,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "xyz789",
        "run_started_at": now.isoformat() + "Z",
        "updated_at": now.isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88003", workflow_payload)

    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Verify that no relationship was created between pr-2003 and workflow-88003
    rel = db_session.query(orm.ChangeRelationshipORM).filter_by(
        tenant_id=tenant_id, source_id="chg-pr-2003", target_id="run-88003"
    ).first()
    assert rel is None

def test_scenario_f_cross_tenant_guards(db_session):
    """Scenario F: Cross-tenant same commit (Tenant A commit does NOT correlate to Tenant B deployment)"""
    seed_checks_and_controls(db_session)
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"
    sync_run_id = f"sync-{uuid.uuid4()}"
    
    setup_identity_mappings(db_session, tenant_a)
    setup_identity_mappings(db_session, tenant_b)
    
    now = datetime.now(UTC).replace(tzinfo=None)

    # Tenant A PR with commit sha-shared
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 4001,
            "title": "Tenant A PR",
            "body": "",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-shared"},
            "created_at": now.isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_a, sync_run_id, "pull_request", "pr-4001", pr_payload)

    # Tenant B Deployment with SAME commit sha-shared
    deploy_payload = {
        "id": 99004,
        "deployment": {
            "id": 99004,
            "sha": "sha-shared",
            "ref": "main",
            "environment": "production",
            "created_at": now.isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_b, sync_run_id, "deployment", "dep-99004", deploy_payload)

    NormalizationService(db_session).normalize_sync_run_payloads(tenant_a, sync_run_id)
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_b, sync_run_id)
    
    CorrelationService(db_session).correlate_sync_run_entities(tenant_a)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_b)

    # Verification: Deployment in Tenant B should remain unlinked
    deploy_db = db_session.query(orm.DeploymentORM).filter_by(deployment_id="dep-99004", tenant_id=tenant_b).first()
    assert deploy_db is not None
    assert deploy_db.change_id is None

def test_scenario_g_duplicate_correlation_idempotency(db_session):
    """Scenario G: Duplicate correlation idempotency (Running correlation twice yields 1 relationship)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-trace-g"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest PR & Workflow run
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 5001,
            "title": "Dup PR",
            "body": "",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-dup-correlate"},
            "created_at": now.isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-5001", pr_payload)

    workflow_payload = {
        "id": 88005,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "sha-dup-correlate",
        "run_started_at": now.isoformat() + "Z",
        "updated_at": now.isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88005", workflow_payload)

    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    
    # Run correlation twice
    corr = CorrelationService(db_session)
    corr.correlate_sync_run_entities(tenant_id)
    corr.correlate_sync_run_entities(tenant_id)

    # Verify only ONE relationship exists
    rels = db_session.query(orm.ChangeRelationshipORM).filter_by(
        tenant_id=tenant_id, source_id="chg-pr-5001", target_id="run-88005"
    ).all()
    assert len(rels) == 1

def test_scenario_h_ambiguous_candidate_changes(db_session):
    """Scenario H: Ambiguous candidate changes (Deployment matches multiple changes)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-trace-h"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Two GitHub PRs with same head SHA
    pr1 = {
        "action": "closed",
        "pull_request": {
            "number": 6001,
            "title": "PR 1",
            "body": "",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-ambig"},
            "created_at": now.isoformat() + "Z"
        }
    }
    pr2 = {
        "action": "closed",
        "pull_request": {
            "number": 6002,
            "title": "PR 2",
            "body": "",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-ambig"},
            "created_at": now.isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-6001", pr1)
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-6002", pr2)

    # Deploy event
    deploy_payload = {
        "id": 99006,
        "deployment": {
            "id": 99006,
            "sha": "sha-ambig",
            "ref": "main",
            "environment": "production",
            "created_at": now.isoformat() + "Z",
            "creator": {"login": "charlie-git"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "deployment", "dep-99006", deploy_payload)

    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Deployment should remain unlinked (change_id = None)
    deploy_db = db_session.query(orm.DeploymentORM).filter_by(deployment_id="dep-99006", tenant_id=tenant_id).first()
    assert deploy_db is not None
    assert deploy_db.change_id is None

    # Relationship should be flagged as AMBIGUOUS
    rels = db_session.query(orm.ChangeRelationshipORM).filter_by(
        tenant_id=tenant_id, target_id="dep-99006", relationship_state="AMBIGUOUS"
    ).all()
    assert len(rels) == 2

def test_scenario_i_conflicting_deployment(db_session):
    """Scenario I: Conflicting deployment (Commit mismatch with associated change)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-trace-i"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Seed PR with commit abc123
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 7001,
            "title": "PR 7001",
            "body": "",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "abc123"},
            "created_at": now.isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-7001", pr_payload)

    # Seed deployment with commit xyz789 but linked to PR 7001
    NormalizationService(db_session).normalize_sync_run_payloads(tenant_id, sync_run_id)
    
    deploy = orm.DeploymentORM(
        deployment_id="dep-7001",
        tenant_id=tenant_id,
        change_id="chg-pr-7001",
        application_id="app-default",
        environment_id="env-prod",
        repository_id="repo-default",
        version="v1.0",
        commit_id="xyz789",
        deployed_by=f"usr-{tenant_id}-charlie",
        status="SUCCESS",
        source="github"
    )
    db_session.add(deploy)
    db_session.commit()

    # Run correlation
    CorrelationService(db_session).correlate_sync_run_entities(tenant_id)

    # Relationship should be flagged as CONFLICT
    rel = db_session.query(orm.ChangeRelationshipORM).filter_by(
        tenant_id=tenant_id, source_id="chg-pr-7001", target_id="dep-7001"
    ).first()
    assert rel is not None
    assert rel.relationship_state == "CONFLICT"

    # Trace completeness status should be BROKEN
    trace_service = TraceService(db_session)
    trace = trace_service.get_change_trace(tenant_id, "chg-pr-7001")
    assert trace["status"] == "BROKEN"

def test_scenario_l_remediation_and_recheck(db_session):
    """Scenario L: Remediation and recheck flow"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-trace-l"
    sync_run_id = f"sync-{uuid.uuid4()}"
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC).replace(tzinfo=None)

    # Ingest Jira
    jira_payload = {
        "key": "CHG-9009",
        "fields": {
            "summary": "STANDARD: Compliance Test",
            "creator": {"emailAddress": f"{tenant_id}-alice@acme.com"},
            "assignee": {"emailAddress": f"{tenant_id}-alice@acme.com"},
            "status": {"name": "Done"},
            "created": now.isoformat() + "+0000",
            "updated": now.isoformat() + "+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_is_emergency": {"value": "No"}
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "jira_issue", "CHG-9009", jira_payload)

    # Ingest PR linked to CHG-9009
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 9009,
            "title": "CHG-9009 Implement Patch",
            "body": "",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-itsm-recheck"},
            "created_at": now.isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-9009", pr_payload)

    # Workflow Run FAIL initially (Make sure tested_at is before deployment time!)
    workflow_payload = {
        "id": 88009,
        "status": "completed",
        "conclusion": "failure",
        "head_sha": "sha-itsm-recheck",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88009", workflow_payload)

    # Deployment (at now - 5m)
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
    res = evaluator.evaluate_change(tenant_id, "chg-pr-9009", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    find_service = FindingService(db_session)
    finding = find_service.process_check_result(res)
    assert finding is not None
    assert finding.status == "OPEN"

    # Remediate by setting CI Test run to PASS in DB
    test_run = db_session.query(orm.TestORM).filter_by(test_id="run-88009", tenant_id=tenant_id).first()
    test_run.status = ORMTestStatus.PASS
    db_session.commit()

    # Recheck
    recheck_service = RecheckService(db_session)
    summary = recheck_service.recheck_finding(tenant_id, finding.finding_id)
    assert summary["new_result"] == "PASS"
    assert summary["finding_status"] == "RESOLVED"

def test_security_cross_tenant_isolation(db_session):
    """Verify trace service prevents cross-tenant access to change traces"""
    seed_checks_and_controls(db_session)
    tenant_a = "tenant-a"
    tenant_b = "tenant-b"
    
    setup_identity_mappings(db_session, tenant_a)
    
    # Seed change in Tenant A
    chg = orm.ChangeORM(
        change_id="chg-pr-9999",
        tenant_id=tenant_a,
        external_id="9999",
        source="github",
        title="Secret Change",
        change_type=ORMChangeType.NORMAL,
        requester_id=f"usr-{tenant_a}-alice",
        owner_id=f"usr-{tenant_a}-alice",
        environment_id="env-prod",
        application_id="app-default",
        status="OPEN"
    )
    db_session.add(chg)
    db_session.commit()

    trace_service = TraceService(db_session)
    
    # Tenant B tries to load Tenant A change trace -> Should not return it (returns error/PARTIAL status)
    trace = trace_service.get_change_trace(tenant_b, "chg-pr-9999")
    assert trace["status"] == "PARTIAL"
    assert "error" in trace
