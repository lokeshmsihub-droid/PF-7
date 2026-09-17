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

def test_complete_e2e_compliance_pipeline(db_session):
    tenant_id = "tenant-e2e"
    sync_run_id = f"sync-{uuid.uuid4()}"

    # -------------------------------------------------------------
    # 1. SETUP SEED DATA
    # -------------------------------------------------------------
    # Seed Framework, Control, and Checks
    framework = orm.FrameworkORM(framework_id="SOC2", name="SOC 2")
    control = orm.ControlORM(
        control_id="CM-CONTROL-03",
        framework_id="SOC2",
        criterion="CC8.1",
        name="Change Control Verification",
        objective="Verify testing",
        description="Verify tests pass before deploy",
        lifecycle_stage="Testing"
    )
    check = orm.ComplianceCheckORM(
        check_id="CM-005",
        control_id="CM-CONTROL-03",
        name="Testing Before Production Deployment",
        description="Ensure tests pass prior to production deployment.",
        category="testing",
        severity="high",
        lifecycle_stage="Testing",
        required_data=["change", "test", "deployment"],
        evaluation_logic={
            "rules": [
                {"subject": "test", "field": "status", "operator": "EQUALS", "value": "PASS"}
            ],
            "relationships": [
                {
                    "subject": "test",
                    "related_subject": "deployment",
                    "operator": "BEFORE",
                    "source_field": "completed_at",
                    "target_field": "deployed_at"
                }
            ]
        },
        evidence_requirements={},
        result_types=[],
        applicability="PRODUCTION",
        status="ACTIVE",
        reremediation_guidance="Fix test pipeline execution timing."
    )
    prod_env = orm.EnvironmentORM(
        environment_id="env-prod",
        tenant_id=tenant_id,
        name="Production",
        type=orm.ORMEnvType.PRODUCTION,
        criticality="HIGH"
    )
    app_orm = orm.ApplicationORM(
        application_id="app-default",
        tenant_id=tenant_id,
        name="Acme Platform",
        owner="Security Team",
        environment_id="env-prod",
        status="ACTIVE"
    )
    user = orm.UserORM(
        internal_user_id="usr-alice-e2e",
        tenant_id=tenant_id,
        name="Alice E2E",
        email="alice.e2e@acme.com",
        role="Developer",
        status="ACTIVE"
    )
    link = orm.IdentityLinkORM(
        internal_user_id="usr-alice-e2e",
        tenant_id=tenant_id,
        source="github",
        external_user_id="git-alice-e2e",
        external_username="alice-git",
        status="ACTIVE"
    )

    db_session.add(framework)
    db_session.add(prod_env)
    db_session.add(user)
    db_session.commit()

    db_session.add(control)
    db_session.add(app_orm)
    db_session.commit()

    db_session.add(check)
    db_session.add(link)
    db_session.commit()

    # -------------------------------------------------------------
    # 2. INGEST RAW GITHUB EVENTS INTO MONGODB
    # -------------------------------------------------------------
    mongo = MongoDB()
    col = mongo.db.raw_events
    col.delete_many({}) # Clear for E2E

    now_time = datetime.utcnow()

    # Case A: Pull Request event
    pr_payload = {
        "action": "closed",
        "pull_request": {
            "number": 42,
            "title": "CM-005: Auth Token Refactoring",
            "body": "Fixes auth token generation issues",
            "user": {"login": "alice-git"},
            "merged": True,
            "head": {"sha": "sha-e2e-commit-1"},
            "merged_at": (now_time - timedelta(minutes=15)).isoformat() + "Z"
        }
    }

    # Case B: Workflow Run completed event
    workflow_payload = {
        "id": 88001,
        "status": "completed",
        "conclusion": "success",
        "head_sha": "sha-e2e-commit-1",
        "updated_at": (now_time - timedelta(minutes=20)).isoformat() + "Z"
    }

    # Case C: Deployment completed event
    deploy_payload = {
        "id": 99001,
        "action": "completed",
        "workflow_run": {
            "head_sha": "sha-e2e-commit-1",
            "actor": {"login": "alice-git"}
        },
        "deployment": {
            "environment": "production",
            "updated_at": (now_time - timedelta(minutes=10)).isoformat() + "Z",
            "sha": "sha-e2e-commit-1"
        }
    }

    # Insert into MongoDB
    for ev_type, pl, ext_id in [
        ("pull_request", pr_payload, "pr-42"),
        ("workflow_run", workflow_payload, "run-88001"),
        ("deployment", deploy_payload, "dep-99001")
    ]:
        pl_str = json.dumps(pl, sort_keys=True, default=str)
        pl_hash = hashlib.sha256(pl_str.encode("utf-8")).hexdigest()
        col.insert_one({
            "event_id": str(uuid.uuid4()),
            "tenant_id": tenant_id,
            "connector_account_id": "acc-e2e",
            "source": "github",
            "provider": "github",
            "event_type": ev_type,
            "external_id": ext_id,
            "received_at": datetime.now(UTC),
            "sync_run_id": sync_run_id,
            "payload": pl,
            "payload_hash": pl_hash
        })

    mongo.disconnect()

    # -------------------------------------------------------------
    # 3. RUN NORMALIZATION
    # -------------------------------------------------------------
    norm_service = NormalizationService(db_session)
    # Norm baseline structures
    norm_service._ensure_baseline_entities(tenant_id)
    normalized_count = norm_service.normalize_sync_run_payloads(tenant_id, sync_run_id)
    assert normalized_count == 3

    # Check change request was inserted in Postgres
    pr_change = db_session.query(orm.ChangeORM).filter_by(change_id="chg-pr-42").first()
    assert pr_change is not None
    assert pr_change.requester_id == "usr-alice-git" # Raw stub handle

    # -------------------------------------------------------------
    # 4. RUN CORRELATION
    # -------------------------------------------------------------
    corr_service = CorrelationService(db_session)
    summary = corr_service.correlate_sync_run_entities(tenant_id)
    assert summary["tests_correlated"] == 1
    assert summary["deployments_correlated"] == 1

    # Verify user resolution worked after correlation
    assert pr_change.requester_id == "usr-alice-e2e"

    # -------------------------------------------------------------
    # 5. RUN COMPLIANCE EVALUATION
    # -------------------------------------------------------------
    eval_service = EvaluationService(db_session)
    res = eval_service.evaluate_change(tenant_id, "chg-pr-42", "CM-005")
    # Result must PASS because test run completed (now-20m) BEFORE deployment (now-10m)
    assert res.result == orm.ORMCheckResultType.PASS

    # -------------------------------------------------------------
    # 6. SIMULATE PIPELINE BREAKAGE AND REMEDIATION
    # -------------------------------------------------------------
    # Update test run completed timestamp to make it complete AFTER deployment
    test_run = db_session.query(orm.TestORM).filter_by(test_id="run-88001").first()
    test_run.completed_at = now_time # Test completes now, which is after deployment (now-10m)
    db_session.commit()
    db_session.expire_all()

    # Re-evaluate -> Result must FAIL now
    res_fail = eval_service.evaluate_change(tenant_id, "chg-pr-42", "CM-005")
    assert res_fail.result == orm.ORMCheckResultType.FAIL

    # Ingest failing finding and remediation task
    find_service = FindingService(db_session)
    finding = find_service.process_check_result(res_fail)
    assert finding is not None
    assert finding.status == "OPEN"

    task = db_session.query(orm.RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()
    assert task is not None
    assert task.status == "PENDING"

    # Fix the pipeline breakage: restore test completion time to be before deploy
    test_run.completed_at = now_time - timedelta(minutes=20)
    db_session.commit()
    db_session.expire_all()

    # Run Recheck -> Auto-resolves finding and remediation task!
    recheck_service = RecheckService(db_session)
    recheck_summary = recheck_service.recheck_finding(tenant_id, finding.finding_id)
    assert recheck_summary["new_result"] == "PASS"
    assert recheck_summary["finding_status"] == "RESOLVED"

    # Verify final statuses in DB
    assert finding.status == "RESOLVED"
    assert task.status == "RESOLVED"
