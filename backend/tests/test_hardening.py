import pytest
import uuid
import json
import hashlib
from datetime import datetime, UTC
from fastapi.testclient import TestClient
from app.main import app
from app.db.mongodb import MongoDBClient
from app.services.correlation_service import CorrelationService
from app.services.event_processor import process_webhook_event_async
from app.models.orm import (
    IdentityLinkORM, UserORM, ChangeORM, TestORM, DeploymentORM,
    ConnectorAccountORM, ConnectorORM, ChangeRelationshipORM, AuditLogORM, ORMChangeType,
    EnvironmentORM, ApplicationORM, ORMEnvType
)

client = TestClient(app)

@pytest.fixture
def hardening_seeded_context(db_session):
    tenant_id = "tenant-hardening"
    
    # Clear MongoDB raw events database for isolation
    mongo = MongoDBClient()
    mongo.connect()
    mongo.raw_events_collection.delete_many({"tenant_id": tenant_id})
    mongo.disconnect()

    # Seed framework, controls, and compliance checks from library.json
    import os
    from app.models.orm import FrameworkORM, ControlORM, ComplianceCheckORM
    fw = db_session.query(FrameworkORM).filter_by(framework_id="SOC2").first()
    if not fw:
        fw = FrameworkORM(framework_id="SOC2", name="SOC 2", description="SOC 2", status="ACTIVE", version="1.0.0")
        db_session.add(fw)
        db_session.commit()

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    path = os.path.join(base_dir, "app", "domain", "checks", "library.json")
    with open(path, "r") as f:
        checks_data = json.load(f)
        for cdata in checks_data:
            num = int(cdata["check_id"].split("-")[1])
            ctrl_id = f"CM-CONTROL-{num:02d}"
            if num > 11:
                ctrl_id = "CM-CONTROL-01"
            
            ctrl = db_session.query(ControlORM).filter_by(control_id=ctrl_id).first()
            if not ctrl:
                ctrl = ControlORM(
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
            chk = db_session.query(ComplianceCheckORM).filter_by(check_id=check_id).first()
            if not chk:
                chk = ComplianceCheckORM(
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

    # Seed users
    u1 = UserORM(internal_user_id="usr-alice-e2e", tenant_id=tenant_id, name="Alice", email="a@co.com", role="Dev", status="ACTIVE")
    u2 = UserORM(internal_user_id="usr-bob-e2e", tenant_id=tenant_id, name="Bob", email="b@co.com", role="Dev", status="ACTIVE")
    
    env = EnvironmentORM(
        environment_id="env-hard",
        tenant_id=tenant_id,
        name="Production Hardening",
        type=ORMEnvType.PRODUCTION,
        criticality="HIGH"
    )
    app_orm = ApplicationORM(
        application_id="app-hard",
        tenant_id=tenant_id,
        name="Platform Service",
        owner="usr-alice-e2e",
        environment_id="env-hard"
    )
    
    db_session.add(u1)
    db_session.add(u2)
    db_session.add(env)
    db_session.commit()
    
    db_session.add(app_orm)
    db_session.commit()

    # Seed connector
    conn = db_session.query(ConnectorORM).filter_by(connector_id="github").first()
    if not conn:
        conn = ConnectorORM(connector_id="github", name="GitHub", type="source", status="ACTIVE")
        db_session.add(conn)
        db_session.commit()

    acc = ConnectorAccountORM(
        account_id="acc-hardening",
        tenant_id=tenant_id,
        connector_id="github",
        name="GitHub Hardening",
        auth_type="token",
        config={"mock": True},
        status="ACTIVE"
    )
    db_session.add(acc)
    db_session.commit()

    return {
        "tenant_id": tenant_id,
        "account_id": "acc-hardening"
    }


def test_unresolved_and_ambiguous_identities(db_session, hardening_seeded_context):
    tenant_id = hardening_seeded_context["tenant_id"]
    corr_service = CorrelationService(db_session)

    # 1. Unresolved handle: should return fallback stub
    res = corr_service.resolve_user_id(tenant_id, "git-charlie")
    assert res == "usr-git-charlie"

    # 2. Resolved handle: single active link maps to target user
    link1 = IdentityLinkORM(
        internal_user_id="usr-alice-e2e",
        tenant_id=tenant_id,
        source="github",
        external_user_id="git-id-alice",
        external_username="git-alice",
        status="ACTIVE"
    )
    db_session.add(link1)
    db_session.commit()

    res = corr_service.resolve_user_id(tenant_id, "git-alice")
    assert res == "usr-alice-e2e"

    # 3. Ambiguous handle: multiple active links point to different users -> DO NOT GUESS
    link2 = IdentityLinkORM(
        internal_user_id="usr-bob-e2e",
        tenant_id=tenant_id,
        source="github",
        external_user_id="git-id-alice-2",
        external_username="git-alice",
        status="ACTIVE"
    )
    db_session.add(link2)
    db_session.commit()

    # Now there are two links mapping git-alice. Resolve should fallback to stub and not guess!
    res = corr_service.resolve_user_id(tenant_id, "git-alice")
    assert res == "usr-git-alice"


def test_negative_correlations(db_session, hardening_seeded_context):
    from app.models.orm import ORMChangeType
    tenant_id = hardening_seeded_context["tenant_id"]
    corr_service = CorrelationService(db_session)

    # 1. Create target Change Request
    chg = ChangeORM(
        change_id="chg-h-1",
        tenant_id=tenant_id,
        external_id="102",
        source="github",
        title="CM-005: Fix logic bug",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-alice-e2e",
        owner_id="usr-alice-e2e",
        environment_id="env-hard",
        application_id="app-hard",
        status="OPEN"
    )
    db_session.add(chg)
    db_session.commit()

    # 2. Create mismatched Test Run
    from app.models.orm import ORMTestStatus
    t_run = TestORM(
        test_id="run-h-1",
        tenant_id=tenant_id,
        source="github_actions",
        pipeline_id="pipe-1",
        test_type="unit",
        commit_id="sha-mismatched", # Does not match any correlation triggers
        status=ORMTestStatus.PASS
    )
    db_session.add(t_run)
    db_session.commit()

    # 3. Run correlation
    summary = corr_service.correlate_sync_run_entities(tenant_id)
    assert summary["tests_correlated"] == 0

    # Test run must remain uncorrelated
    db_session.refresh(t_run)
    assert t_run.change_id is None


def test_webhook_async_and_mongodb_transitions(db_session, hardening_seeded_context, mocker):
    tenant_id = hardening_seeded_context["tenant_id"]
    account_id = hardening_seeded_context["account_id"]

    # Mock add_task to capture parameters but bypass thread pool execution
    mock_add_task = mocker.patch("fastapi.background.BackgroundTasks.add_task")

    # Ingest a PR webhook
    payload = {
        "number": 88,
        "pull_request": {
            "number": 88,
            "title": f"STANDARD: Simple refactoring {uuid.uuid4()}",
            "user": {"login": "git-alice"},
            "state": "open",
            "created_at": "2026-08-22T07:12:00Z",
            "updated_at": "2026-08-22T07:12:00Z"
        }
    }

    # Trigger webhook POST
    resp = client.post(
        f"/webhooks/github?tenant_id={tenant_id}&account_id={account_id}",
        json=payload,
        headers={"X-GitHub-Event": "pull_request"}
    )
    assert resp.status_code == 202
    event_id = resp.json()["event_id"]
    assert event_id is not None

    # Assert add_task was called with correct parameters
    mock_add_task.assert_called_once_with(process_webhook_event_async, tenant_id, event_id)

    # Execute the processing synchronously under the test's transactional db_session
    process_webhook_event_async(tenant_id, event_id, db=db_session)

    # Verify MongoDB status transitioned to COMPLETED
    mongo = MongoDBClient()
    mongo.connect()
    col = mongo.raw_events_collection
    try:
        event = col.find_one({"event_id": event_id})
        assert event is not None
        assert event["processing_status"] == "COMPLETED"
        assert "error_message" not in event or event["error_message"] is None
        
        # Verify the Change request was created and holds correct properties
        chg = db_session.query(ChangeORM).filter_by(change_id="chg-pr-88", tenant_id=tenant_id).first()
        assert chg is not None
        assert chg.title.startswith("STANDARD: Simple refactoring")
    finally:
        mongo.disconnect()


def test_idempotent_event_webhooks(hardening_seeded_context, mocker):
    # Mock background tasks to prevent async DB locks hanging the test
    mocker.patch("fastapi.background.BackgroundTasks.add_task")
    tenant_id = hardening_seeded_context["tenant_id"]
    account_id = hardening_seeded_context["account_id"]

    payload = {"unique_id": str(uuid.uuid4()), "action": "opened"}

    # 1. Post once
    resp1 = client.post(
        f"/webhooks/github?tenant_id={tenant_id}&account_id={account_id}",
        json=payload,
        headers={"X-GitHub-Event": "ping"}
    )
    assert resp1.status_code == 202
    ev_id1 = resp1.json()["event_id"]

    # 2. Post identical payload again (idempotency check)
    resp2 = client.post(
        f"/webhooks/github?tenant_id={tenant_id}&account_id={account_id}",
        json=payload,
        headers={"X-GitHub-Event": "ping"}
    )
    assert resp2.status_code == 202
    ev_id2 = resp2.json()["event_id"]
    assert resp2.json().get("duplicated") is True

    # Event ID must be identical (deduplicated)
    assert ev_id1 == ev_id2


def test_state_machine_validation_and_failures(db_session, hardening_seeded_context):
    tenant_id = hardening_seeded_context["tenant_id"]
    account_id = hardening_seeded_context["account_id"]
    
    mongo = MongoDBClient()
    mongo.connect()
    col = mongo.raw_events_collection
    try:
        # 1. Test valid and invalid transition validations directly
        event_id = str(uuid.uuid4())
        col.insert_one({
            "event_id": event_id,
            "tenant_id": tenant_id,
            "connector_account_id": account_id,
            "processing_status": "RECEIVED",
            "retry_count": 0
        })
        
        # Enforce invalid transition: RECEIVED -> COMPLETED should raise ValueError
        from app.services.event_processor import transition_event_status
        with pytest.raises(ValueError, match="Invalid transition from RECEIVED to COMPLETED"):
            transition_event_status(col, event_id, "COMPLETED")
            
        # Enforce valid transition RECEIVED -> PROCESSING
        transition_event_status(col, event_id, "PROCESSING")
        evt = col.find_one({"event_id": event_id})
        assert evt["processing_status"] == "PROCESSING"
        assert evt.get("processing_started_at") is not None
        
        # 2. Test error information and stack trace capture on failure
        fail_event_id = str(uuid.uuid4())
        col.insert_one({
            "event_id": fail_event_id,
            "tenant_id": tenant_id,
            "connector_account_id": account_id,
            "event_type": "pull_request",
            "payload": None, # Will raise AttributeError/TypeError during normalization
            "processing_status": "RECEIVED",
            "retry_count": 0
        })
        
        # Run processing synchronously - it will fail and transition to FAILED
        process_webhook_event_async(tenant_id, fail_event_id, db=db_session)
        
        failed_evt = col.find_one({"event_id": fail_event_id})
        assert failed_evt["processing_status"] == "FAILED"
        assert failed_evt.get("failed_at") is not None
        assert failed_evt.get("last_error") is not None
        assert "NoneType" in failed_evt.get("last_error", "") or "AttributeError" in failed_evt.get("last_error", "") or "TypeError" in failed_evt.get("last_error", "")
        
        # 3. Test retry limit rejection (max 3 retries)
        limit_event_id = str(uuid.uuid4())
        col.insert_one({
            "event_id": limit_event_id,
            "tenant_id": tenant_id,
            "connector_account_id": account_id,
            "processing_status": "FAILED",
            "retry_count": 3
        })
        
        # Triggering retry-failed sync endpoint should skip this event
        resp = client.post(
            f"/api/compliance/connectors/{account_id}/sync/retry-failed",
            headers={"X-Tenant-ID": tenant_id}
        )
        assert resp.status_code == 200
        assert limit_event_id not in resp.json()["retried_event_ids"]
        
        # Direct transition execution with retry_count >= 3 should raise ValueError
        with pytest.raises(ValueError, match="Retry limit of 3 attempts exceeded"):
            transition_event_status(col, limit_event_id, "PROCESSING")
            
    finally:
        mongo.disconnect()

