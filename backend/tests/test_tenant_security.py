import pytest
import io
from fastapi.testclient import TestClient
from app.main import app
from app.models.orm import (
    FrameworkORM, ControlORM, ComplianceCheckORM, UserORM, ChangeORM, EnvironmentORM,
    ApplicationORM, RepositoryORM, ORMChangeType, ORMEnvType, FindingORM,
    RemediationTaskORM, EvidenceMetadataORM, ConnectorAccountORM, ConnectorORM
)

client = TestClient(app)

@pytest.fixture
def security_seeded_context(db_session):
    # 1. Seed global framework & control
    fw = FrameworkORM(framework_id="SOC2", name="SOC 2")
    ctrl = ControlORM(
        control_id="CM-CONTROL-SEC",
        framework_id="SOC2",
        criterion="CC8.1",
        name="Security Isolation",
        objective="Verify isolation",
        description="Verify multi-tenancy isolation",
        lifecycle_stage="Testing"
    )
    check = ComplianceCheckORM(
        check_id="CM-SEC-01",
        control_id="CM-CONTROL-SEC",
        name="Tenant isolation check",
        description="Check tenant isolation",
        category="security",
        severity="high",
        lifecycle_stage="Testing",
        required_data=["change"],
        evaluation_logic={"rules": []},
        evidence_requirements={},
        result_types=[],
        applicability="PRODUCTION",
        status="ACTIVE"
    )
    db_session.add_all([fw, ctrl, check])
    db_session.commit()

    # 2. Seed Tenant B entities
    tenant_b = "tenant-b"
    user_b = UserORM(
        internal_user_id="usr-bob",
        tenant_id=tenant_b,
        name="Bob",
        email="bob@co.com",
        role="Dev",
        status="ACTIVE"
    )
    env_b = EnvironmentORM(
        environment_id="env-b",
        tenant_id=tenant_b,
        name="Production B",
        type=ORMEnvType.PRODUCTION,
        criticality="HIGH"
    )
    app_b = ApplicationORM(
        application_id="app-b",
        tenant_id=tenant_b,
        name="Auth Service B",
        owner="usr-bob",
        environment_id="env-b"
    )
    chg_b = ChangeORM(
        change_id="chg-tenant-b",
        tenant_id=tenant_b,
        external_id="101",
        source="github",
        title="CM-SEC: Patch vulnerability",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-bob",
        owner_id="usr-bob",
        status="OPEN",
        environment_id="env-b",
        application_id="app-b"
    )
    db_session.add(user_b)
    db_session.add(env_b)
    db_session.commit()
    
    db_session.add(app_b)
    db_session.add(chg_b)
    db_session.commit()

    find_b = FindingORM(
        finding_id="find-tenant-b",
        tenant_id=tenant_b,
        check_id="CM-SEC-01",
        control_id="CM-CONTROL-SEC",
        change_id="chg-tenant-b",
        title="Unauthorized modification",
        description="Tenant B security finding",
        severity="HIGH",
        status="OPEN"
    )
    db_session.add(find_b)
    db_session.commit()

    task_b = RemediationTaskORM(
        task_id="task-tenant-b",
        finding_id="find-tenant-b",
        tenant_id=tenant_b,
        title="Review logs",
        description="Verify and review system audit logs",
        owner="usr-bob",
        priority="HIGH",
        status="PENDING"
    )
    db_session.add(task_b)
    db_session.commit()

    evidence_b = EvidenceMetadataORM(
        evidence_id="evidence-tenant-b",
        tenant_id=tenant_b,
        change_id="chg-tenant-b",
        source="manual",
        source_record_id="screenshot.png",
        evidence_type="image/png",
        hash="abc123hash",
        storage_reference="file:///tmp/screenshot.png"
    )
    db_session.add(evidence_b)
    db_session.commit()

    # Seed connector account for Tenant B
    conn = db_session.query(ConnectorORM).filter_by(connector_id="github").first()
    if not conn:
        conn = ConnectorORM(connector_id="github", name="GitHub", type="source", status="ACTIVE")
        db_session.add(conn)
        db_session.commit()

    acc_b = ConnectorAccountORM(
        account_id="account-tenant-b",
        tenant_id=tenant_b,
        connector_id="github",
        name="GitHub Tenant B",
        auth_type="token",
        config={"mock": True},
        status="ACTIVE"
    )
    db_session.add(acc_b)
    db_session.commit()

    return {
        "tenant_b": tenant_b,
        "change_id": "chg-tenant-b",
        "finding_id": "find-tenant-b",
        "account_id": "account-tenant-b"
    }


def test_tenant_isolation_endpoints(security_seeded_context):
    headers_a = {"X-Tenant-ID": "tenant-a"}

    # 1. Changes API: list must not return Tenant B's change
    resp = client.get("/api/compliance/changes", headers=headers_a)
    assert resp.status_code == 200
    assert len(resp.json()) == 0

    # 2. Changes API: fetch Tenant B change directly must return 404
    resp = client.get("/api/compliance/changes/chg-tenant-b", headers=headers_a)
    assert resp.status_code == 404

    # 3. Evaluate Check API: evaluate Tenant B change must fail (raise 400/404)
    resp = client.post("/api/compliance/checks/evaluate", json={
        "change_id": "chg-tenant-b",
        "check_id": "CM-SEC-01"
    }, headers=headers_a)
    assert resp.status_code in [400, 404]

    # 4. Findings API: list must not return Tenant B's finding
    resp = client.get("/api/compliance/findings", headers=headers_a)
    assert resp.status_code == 200
    assert len(resp.json()) == 0

    # 5. Remediation API: list must not return Tenant B's tasks
    resp = client.get("/api/compliance/remediation", headers=headers_a)
    assert resp.status_code == 200
    assert len(resp.json()) == 0

    # 6. Recheck API: rechecking Tenant B's finding directly must return 400/404
    resp = client.post("/api/compliance/rerecheck", json={
        "finding_id": "find-tenant-b"
    }, headers=headers_a)
    # Note: recheck endpoint is mapped at /remediation/recheck
    resp = client.post("/api/compliance/remediation/recheck", json={
        "finding_id": "find-tenant-b"
    }, headers=headers_a)
    assert resp.status_code in [400, 404]

    # 7. Evidence API: list must not return Tenant B's evidence
    resp = client.get("/api/compliance/evidence", headers=headers_a)
    assert resp.status_code == 200
    assert len(resp.json()) == 0

    # 8. Upload Evidence: uploading evidence for Tenant B's change must fail (404)
    file_payload = {"file": ("test.png", io.BytesIO(b"dummycontent"), "image/png")}
    resp = client.post("/api/compliance/evidence/upload", data={
        "change_id": "chg-tenant-b"
    }, files=file_payload, headers=headers_a)
    assert resp.status_code == 404

    # 9. Retry Failed Events: retrying sync for Tenant B's account must fail/return zero retried
    resp = client.post("/api/compliance/connectors/account-tenant-b/sync/retry-failed", headers=headers_a)
    assert resp.status_code == 200
    assert resp.json()["retried_count"] == 0
