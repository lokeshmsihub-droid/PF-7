import pytest
from datetime import datetime, timedelta, UTC
from app.services.evaluation_service import EvaluationService
from app.services.finding_service import FindingService
from app.services.recheck_service import RecheckService
from app.models.orm import (
    UserORM, EnvironmentORM, ApplicationORM, RepositoryORM, ChangeORM, 
    TestORM, DeploymentORM, ComplianceCheckORM, ControlORM, FrameworkORM,
    ORMChangeType, ORMTestStatus, ORMEnvType, ORMCheckResultType, FindingORM, RemediationTaskORM
)

@pytest.fixture
def seeded_recheck_context(db_session):
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
        internal_user_id="usr-bob",
        tenant_id=tenant_id,
        name="Bob",
        email="bob@company.com",
        role="Developer",
        status="ACTIVE"
    )
    db_session.add(framework)
    db_session.add(prod_env)
    db_session.add(user)
    db_session.commit()
    db_session.add(control)
    db_session.add(app)
    db_session.add(repo)
    db_session.commit()
    db_session.add(check)
    db_session.commit()
    return tenant_id

def test_recheck_flow_pass_resolves_finding(db_session, seeded_recheck_context):
    tenant_id = seeded_recheck_context
    eval_service = EvaluationService(db_session)
    find_service = FindingService(db_session)
    recheck_service = RecheckService(db_session)

    # 1. Create Change Request
    change = ChangeORM(
        change_id="chg-recheck-flow",
        tenant_id=tenant_id,
        external_id="3001",
        source="github",
        title="CM-005 PR title",
        description="",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-bob",
        owner_id="usr-bob",
        environment_id="env-prod",
        application_id="app-default",
        status="CLOSED"
    )
    db_session.add(change)
    db_session.commit()

    # 2. Seed failing test runs and deploy (Deploy before Test completed)
    t_base = datetime.utcnow()
    test = TestORM(
        test_id="run-rc-1",
        tenant_id=tenant_id,
        change_id="chg-recheck-flow",
        source="github_actions",
        pipeline_id="p-10",
        commit_id="sha-rc",
        test_type="INTEGRATION",
        status=ORMTestStatus.PASS,
        started_at=t_base - timedelta(minutes=10),
        completed_at=t_base + timedelta(minutes=10) # Completes AFTER deploy
    )
    deploy = DeploymentORM(
        deployment_id="dep-rc-1",
        tenant_id=tenant_id,
        change_id="chg-recheck-flow",
        application_id="app-default",
        environment_id="env-prod",
        repository_id="repo-default",
        version="v1.0",
        commit_id="sha-rc",
        deployed_by="usr-bob",
        status="SUCCESS",
        source="github",
        deployed_at=t_base
    )
    db_session.add_all([test, deploy])
    db_session.commit()

    # 3. Evaluate -> FAIL
    res1 = eval_service.evaluate_change(tenant_id, "chg-recheck-flow", "CM-005")
    assert res1.result == ORMCheckResultType.FAIL

    # 4. Generate Finding & Remediation task
    finding = find_service.process_check_result(res1)
    assert finding is not None
    assert finding.status == "OPEN"

    task = db_session.query(RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()
    assert task is not None
    assert task.status == "PENDING"

    # 5. REMEDIATE: Update test completed timestamp to be BEFORE deployment (Developer fix)
    test.completed_at = t_base - timedelta(minutes=5)
    db_session.commit()

    # 6. Run Recheck
    recheck_res = recheck_service.recheck_finding(tenant_id, finding.finding_id)
    assert recheck_res["new_result"] == "PASS"
    assert recheck_res["finding_status"] == "RESOLVED"

    # 7. Assert database states are resolved
    assert finding.status == "RESOLVED"
    assert finding.resolved_at is not None
    assert task.status == "RESOLVED"
    assert task.resolved_at is not None
