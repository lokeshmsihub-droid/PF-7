import pytest
import uuid
import json
import hashlib
from datetime import datetime, timedelta, UTC
from app.db.mongodb import MongoDBClient as MongoDB
from app.services.normalization_service import NormalizationService
from app.services.correlation_service import CorrelationService
from app.services.evaluation_service import EvaluationService
from app.models import orm
from app.models.orm import ORMChangeType, ORMTestStatus, ORMCheckResultType

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

def test_itsm_combined_scenario_compliant(db_session):
    """Scenario 1: Perfect combined change (Jira Governance + GitHub Technical)"""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-itsm-compliant"
    sync_run_id = f"sync-{uuid.uuid4()}"

    now = datetime.now(UTC).replace(tzinfo=None)

    # 1. Jira Issue (CHG-1025)
    jira_payload = {
        "key": "CHG-1025",
        "fields": {
            "summary": "STANDARD: Database optimization",
            "description": "Fix performance issue",
            "creator": {"emailAddress": "alice@acme.com"},
            "assignee": {"emailAddress": "alice@acme.com"},
            "status": {"name": "Done"},
            "created": (now - timedelta(hours=2)).isoformat() + "+0000",
            "updated": (now).isoformat() + "+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_is_emergency": {"value": "No"}
        },
        "changelog": {
            "histories": [
                {
                    "id": "appr1",
                    "created": (now - timedelta(minutes=50)).isoformat() + "+0000",
                    "author": {"emailAddress": "manager@acme.com"},
                    "items": [{"field": "status", "fromString": "In Review", "toString": "Approved"}]
                }
            ]
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "jira_issue", "CHG-1025", jira_payload)

    # 2. GitHub PR linked to CHG-1025
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 501,
            "title": "CHG-1025: Optimize database queries",
            "body": "Implements CHG-1025",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-itsm-compliant"},
            "created_at": (now - timedelta(minutes=60)).isoformat() + "Z",
            "updated_at": (now - timedelta(minutes=20)).isoformat() + "Z",
            "merged_at": (now - timedelta(minutes=20)).isoformat() + "Z"
        }
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request", "pr-501", pr_payload)

    # GitHub Review (Code Review) - acts as CM-003 Approval
    review_payload = {
        "id": 201,
        "pull_request_number": 501,
        "state": "approved",
        "submitted_at": (now - timedelta(minutes=30)).isoformat() + "Z",
        "user": {"login": "bob-git"}
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "pull_request_review", "rev-201", review_payload)

    # CI Test
    workflow_payload = {
        "id": 88001,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "sha-itsm-compliant",
        "run_started_at": (now - timedelta(minutes=15)).isoformat() + "Z",
        "updated_at": (now - timedelta(minutes=10)).isoformat() + "Z"
    }
    create_raw_event_in_mongo(tenant_id, sync_run_id, "workflow_run", "run-88001", workflow_payload)

    # Deployment
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

    # Execute
    norm_service = NormalizationService(db_session)
    norm_service.normalize_sync_run_payloads(tenant_id, sync_run_id)
    
    corr_service = CorrelationService(db_session)
    summary = corr_service.correlate_sync_run_entities(tenant_id)
    assert summary["governance_changes_correlated"] == 1

    evaluator = EvaluationService(db_session)
    
    # Evaluate CM-001 (Governance Authorization)
    res_001 = evaluator.evaluate_change(tenant_id, "chg-pr-501", "CM-001")
    assert res_001.result == ORMCheckResultType.PASS

    # Evaluate CM-002 (Testing)
    res_002 = evaluator.evaluate_change(tenant_id, "chg-pr-501", "CM-002")
    assert res_002.result == ORMCheckResultType.PASS

    # Evaluate CM-003 (Deployment Approval / Code Review)
    res_003 = evaluator.evaluate_change(tenant_id, "chg-pr-501", "CM-003")
    assert res_003.result == ORMCheckResultType.PASS
