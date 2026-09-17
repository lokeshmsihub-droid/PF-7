import pytest
from datetime import datetime, timedelta
from app.services.evaluation_service import EvaluationService
from app.models.orm import (
    UserORM, EnvironmentORM, ApplicationORM, RepositoryORM, ChangeORM, 
    TestORM, DeploymentORM, ComplianceCheckORM, ControlORM, FrameworkORM,
    ORMChangeType, ORMTestStatus, ORMEnvType, ORMCheckResultType
)

@pytest.fixture
def seeded_context(db_session):
    tenant_id = "tenant-abc"
    # Seed lookups
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
    # Check definition using dynamic logic rules
    check = ComplianceCheckORM(
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
        status="ACTIVE"
    )
    
    prod_env = EnvironmentORM(
        environment_id="env-prod",
        tenant_id=tenant_id,
        name="Production Environment",
        type=ORMEnvType.PRODUCTION,
        criticality="HIGH"
    )
    staging_env = EnvironmentORM(
        environment_id="env-staging",
        tenant_id=tenant_id,
        name="Staging Environment",
        type=ORMEnvType.STAGING,
        criticality="MEDIUM"
    )

    app = ApplicationORM(
        application_id="app-default",
        tenant_id=tenant_id,
        name="Acme Platform",
        owner="Security Team",
        environment_id="env-prod",
        status="ACTIVE"
    )

    repo = RepositoryORM(
        repository_id="repo-default",
        external_id="101",
        name="enterprise-auth-service",
        provider="github",
        organization="acme"
    )

    user = UserORM(
        internal_user_id="usr-developer-bob",
        tenant_id=tenant_id,
        name="Bob",
        email="bob@company.com",
        role="Developer",
        status="ACTIVE"
    )

    db_session.add(framework)
    db_session.add(prod_env)
    db_session.add(staging_env)
    db_session.add(user)
    db_session.commit()

    db_session.add(control)
    db_session.add(app)
    db_session.add(repo)
    db_session.commit()

    db_session.add(check)
    db_session.commit()
    return tenant_id


def test_evaluator_pass_state(db_session, seeded_context):
    tenant_id = seeded_context
    service = EvaluationService(db_session)

    # 1. Create Change
    change = ChangeORM(
        change_id="chg-pass",
        tenant_id=tenant_id,
        external_id="1001",
        source="github",
        title="CM-005 PR title",
        description="",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-developer-bob",
        owner_id="usr-developer-bob",
        environment_id="env-prod",
        application_id="app-default",
        status="CLOSED",
        implemented_at=datetime.utcnow()
    )
    db_session.add(change)
    db_session.commit()

    # 2. Add Test run passing BEFORE deploy
    t_base = datetime.utcnow()
    test = TestORM(
        test_id="run-pass-1",
        tenant_id=tenant_id,
        change_id="chg-pass",
        source="github_actions",
        pipeline_id="p-1",
        commit_id="sha-abc",
        test_type="INTEGRATION",
        status=ORMTestStatus.PASS,
        started_at=t_base - timedelta(minutes=30),
        completed_at=t_base - timedelta(minutes=20)
    )
    deploy = DeploymentORM(
        deployment_id="dep-pass-1",
        tenant_id=tenant_id,
        change_id="chg-pass",
        application_id="app-default",
        environment_id="env-prod",
        repository_id="repo-default",
        version="v1.0",
        commit_id="sha-abc",
        deployed_by="usr-developer-bob",
        status="SUCCESS",
        source="github",
        deployed_at=t_base - timedelta(minutes=10)
    )
    db_session.add_all([test, deploy])
    db_session.commit()

    # 3. Run evaluation
    res = service.evaluate_change(tenant_id, "chg-pass", "CM-005")
    assert res.result == ORMCheckResultType.PASS


def test_evaluator_fail_state(db_session, seeded_context):
    tenant_id = seeded_context
    service = EvaluationService(db_session)

    # 1. Create Change
    change = ChangeORM(
        change_id="chg-fail",
        tenant_id=tenant_id,
        external_id="1002",
        source="github",
        title="CM-005 PR title",
        description="",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-developer-bob",
        owner_id="usr-developer-bob",
        environment_id="env-prod",
        application_id="app-default",
        status="CLOSED",
        implemented_at=datetime.utcnow()
    )
    db_session.add(change)
    db_session.commit()

    # 2. Add Test run completed AFTER deploy
    t_base = datetime.utcnow()
    test = TestORM(
        test_id="run-fail-1",
        tenant_id=tenant_id,
        change_id="chg-fail",
        source="github_actions",
        pipeline_id="p-2",
        commit_id="sha-xyz",
        test_type="INTEGRATION",
        status=ORMTestStatus.PASS,
        started_at=t_base - timedelta(minutes=10),
        completed_at=t_base  # Test completes at t_base
    )
    deploy = DeploymentORM(
        deployment_id="dep-fail-1",
        tenant_id=tenant_id,
        change_id="chg-fail",
        application_id="app-default",
        environment_id="env-prod",
        repository_id="repo-default",
        version="v1.0",
        commit_id="sha-xyz",
        deployed_by="usr-developer-bob",
        status="SUCCESS",
        source="github",
        deployed_at=t_base - timedelta(minutes=20) # Deploy occurs BEFORE test completion
    )
    db_session.add_all([test, deploy])
    db_session.commit()

    res = service.evaluate_change(tenant_id, "chg-fail", "CM-005")
    assert res.result == ORMCheckResultType.FAIL


def test_evaluator_insufficient_data(db_session, seeded_context):
    tenant_id = seeded_context
    service = EvaluationService(db_session)

    # 1. Create Change
    change = ChangeORM(
        change_id="chg-insufficient",
        tenant_id=tenant_id,
        external_id="1003",
        source="github",
        title="CM-005 PR title",
        description="",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-developer-bob",
        owner_id="usr-developer-bob",
        environment_id="env-prod",
        application_id="app-default",
        status="CLOSED",
        implemented_at=datetime.utcnow()
    )
    db_session.add(change)
    db_session.commit()

    # 2. Add Deploy but NO test runs
    deploy = DeploymentORM(
        deployment_id="dep-ins-1",
        tenant_id=tenant_id,
        change_id="chg-insufficient",
        application_id="app-default",
        environment_id="env-prod",
        repository_id="repo-default",
        version="v1.0",
        commit_id="sha-mno",
        deployed_by="usr-developer-bob",
        status="SUCCESS",
        source="github",
        deployed_at=datetime.utcnow()
    )
    db_session.add(deploy)
    db_session.commit()

    res = service.evaluate_change(tenant_id, "chg-insufficient", "CM-005")
    assert res.result == ORMCheckResultType.INSUFFICIENT_DATA


def test_evaluator_not_applicable(db_session, seeded_context):
    tenant_id = seeded_context
    service = EvaluationService(db_session)

    # 1. Create Staging Change
    change = ChangeORM(
        change_id="chg-na",
        tenant_id=tenant_id,
        external_id="1004",
        source="github",
        title="CM-005 PR title",
        description="",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-developer-bob",
        owner_id="usr-developer-bob",
        environment_id="env-staging", # Staging environment scope
        application_id="app-default",
        status="CLOSED"
    )
    db_session.add(change)
    db_session.commit()

    res = service.evaluate_change(tenant_id, "chg-na", "CM-005")
    assert res.result == ORMCheckResultType.NOT_APPLICABLE
