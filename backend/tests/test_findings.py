import pytest
from datetime import datetime, UTC
from app.services.finding_service import FindingService
from app.models.orm import (
    CheckResultORM, FindingORM, RemediationTaskORM, ComplianceCheckORM, ChangeORM,
    ORMCheckResultType, ORMChangeType, ORMEnvType, UserORM, ControlORM, FrameworkORM,
    ApplicationORM
)

@pytest.fixture
def seeded_finding_context(db_session):
    tenant_id = "tenant-abc"
    
    # Baseline setup
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
        required_data=["change", "test", "deployment"],
        evaluation_logic={},
        evidence_requirements={},
        result_types=[],
        applicability="PRODUCTION",
        status="ACTIVE",
        reremediation_guidance="Verify pipeline logs."
    )
    prod_env = EnvironmentORM(
        environment_id="env-prod",
        tenant_id=tenant_id,
        name="Production",
        type=ORMEnvType.PRODUCTION,
        criticality="HIGH"
    )
    app = ApplicationORM(
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
        change_id="chg-fail-find",
        tenant_id=tenant_id,
        external_id="2001",
        source="github",
        title="Failing Change Request",
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
    db_session.add(app)
    db_session.commit()

    db_session.add(check)
    db_session.add(change)
    db_session.commit()

    return tenant_id
from app.models.orm import EnvironmentORM

def test_finding_creation_and_deduplication(db_session, seeded_finding_context):
    tenant_id = seeded_finding_context
    service = FindingService(db_session)

    # 1. Create a failing check result
    res1 = CheckResultORM(
        result_id="res-fail-1",
        tenant_id=tenant_id,
        check_id="CM-005",
        change_id="chg-fail-find",
        result=ORMCheckResultType.FAIL,
        rule_version="1.0.0",
        evaluation_inputs={"test_status": "FAIL"},
        details={"message": "Deployment completed before test run finished"},
        evaluated_at=datetime.now(UTC)
    )
    db_session.add(res1)
    db_session.commit()

    # 2. Process check result to generate finding
    finding1 = service.process_check_result(res1)
    assert finding1 is not None
    assert finding1.status == "OPEN"
    assert finding1.severity == "high"
    assert "Verify pipeline logs" in finding1.description

    # Assert remediation task exists
    task1 = db_session.query(RemediationTaskORM).filter_by(finding_id=finding1.finding_id).first()
    assert task1 is not None
    assert task1.status == "PENDING"
    assert task1.priority == "critical"

    # 3. Simulate another sync run failing again
    res2 = CheckResultORM(
        result_id="res-fail-2",
        tenant_id=tenant_id,
        check_id="CM-005",
        change_id="chg-fail-find",
        result=ORMCheckResultType.FAIL,
        rule_version="1.0.0",
        evaluation_inputs={"test_status": "FAIL"},
        details={"message": "Deployment completed before test run finished"},
        evaluated_at=datetime.now(UTC)
    )
    db_session.add(res2)
    db_session.commit()

    # 4. Process again: check that it returns the same finding, and does NOT add a new finding record
    finding2 = service.process_check_result(res2)
    assert finding2.finding_id == finding1.finding_id
    
    findings_count = db_session.query(FindingORM).filter_by(
        tenant_id=tenant_id,
        check_id="CM-005",
        change_id="chg-fail-find"
    ).count()
    assert findings_count == 1
