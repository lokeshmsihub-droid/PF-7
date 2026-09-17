import pytest
import io
from fastapi.testclient import TestClient
from app.main import app
from app.models.orm import (
    FrameworkORM, ControlORM, ComplianceCheckORM, UserORM, ChangeORM, EnvironmentORM,
    ApplicationORM, RepositoryORM, ORMChangeType, ORMEnvType
)

client = TestClient(app)

@pytest.fixture
def api_seeded_context(db_session):
    tenant_id = "tenant-abc"
    
    # 1. Seed models
    framework = FrameworkORM(framework_id="SOC2", name="SOC 2")
    control = ControlORM(
        control_id="CM-CONTROL-03",
        framework_id="SOC2",
        criterion="CC8.1",
        name="Testing",
        objective="Verify testing",
        description="Verify tests pass before deploy",
        lifecycle_stage="Testing"
    )
    check = ComplianceCheckORM(
        check_id="CM-005",
        control_id="CM-CONTROL-03",
        name="Testing Before Production Deployment",
        description="Ensure tests pass prior to production deployment.",
        category="testing",
        severity="high",
        lifecycle_stage="Testing",
        required_data=["change"],
        evaluation_logic={"rules": []}, # Simplified empty evaluation
        evidence_requirements={},
        result_types=[],
        applicability="PRODUCTION",
        status="ACTIVE"
    )
    prod_env = EnvironmentORM(
        environment_id="env-prod",
        tenant_id=tenant_id,
        name="Production",
        type=ORMEnvType.PRODUCTION,
        criticality="HIGH"
    )
    app_orm = ApplicationORM(
        application_id="app-default",
        tenant_id=tenant_id,
        name="Acme Platform",
        owner="Security Team",
        environment_id="env-prod",
        status="ACTIVE"
    )
    user = UserORM(
        internal_user_id="usr-developer-bob",
        tenant_id=tenant_id,
        name="Bob",
        email="bob@company.com",
        role="Developer",
        status="ACTIVE"
    )
    change = ChangeORM(
        change_id="chg-api-test",
        tenant_id=tenant_id,
        external_id="5001",
        source="github",
        title="CM-005 API testing",
        description="",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-developer-bob",
        owner_id="usr-developer-bob",
        environment_id="env-prod",
        application_id="app-default",
        status="OPEN"
    )

    db_session.add(framework)
    db_session.add(prod_env)
    db_session.add(user)
    db_session.commit()

    db_session.add(control)
    db_session.add(app_orm)
    db_session.commit()

    db_session.add(check)
    db_session.add(change)
    db_session.commit()

    return tenant_id


def test_list_changes_tenant_isolation(api_seeded_context):
    tenant_id = api_seeded_context

    # Case 1: Valid Tenant Header
    headers = {"X-Tenant-ID": tenant_id}
    res = client.get("/api/compliance/changes", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    assert data[0]["change_id"] == "chg-api-test"

    # Case 2: Missing Tenant Header -> Should return 422 Unprocessable Entity (FastAPI validation error)
    res_err = client.get("/api/compliance/changes")
    assert res_err.status_code == 422


def test_list_checks(api_seeded_context):
    # Global checks endpoint (no tenant scope needed, but needs seeded database)
    res = client.get("/api/compliance/checks")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1


def test_evaluate_endpoint(api_seeded_context):
    tenant_id = api_seeded_context
    headers = {"X-Tenant-ID": tenant_id}
    
    payload = {
        "change_id": "chg-api-test",
        "check_id": "CM-005"
    }
    res = client.post("/api/compliance/checks/evaluate", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert data["change_id"] == "chg-api-test"
    assert data["check_id"] == "CM-005"
    assert data["result"] == "PASS"


def test_evidence_upload_endpoint(api_seeded_context):
    tenant_id = api_seeded_context
    headers = {"X-Tenant-ID": tenant_id}

    file_content = b'{"commit": "123", "author": "bob"}'
    files = {"file": ("build_artifact.json", io.BytesIO(file_content), "application/json")}
    data = {"change_id": "chg-api-test"}

    res = client.post("/api/compliance/evidence/upload", files=files, data=data, headers=headers)
    assert res.status_code == 200
    res_data = res.json()
    assert res_data["change_id"] == "chg-api-test"
    assert res_data["source_record_id"] == "build_artifact.json"
    assert res_data["storage_reference"].startswith("file://")
