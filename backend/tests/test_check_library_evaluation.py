import pytest
import uuid
from datetime import datetime, timedelta
from app.models.orm import (
    ChangeORM, EnvironmentORM, ApplicationORM, UserORM,
    AuthorizationORM, ApprovalORM, TestORM, DeploymentORM,
    ORMChangeType, ORMTestStatus, ORMEnvType, ORMCheckResultType,
    ChangeRollbackORM
)
from app.services.evaluation_service import EvaluationService

@pytest.fixture
def eval_context(db_session):
    """Seed master lookup tables for evaluation environment."""
    tenant_id = "tenant-eval-test-" + str(uuid.uuid4())[:8]
    
    from app.models.orm import RepositoryORM, FrameworkORM, ControlORM, ComplianceCheckORM
    import json
    import os
    
    env = EnvironmentORM(
        environment_id="env-prod-eval",
        tenant_id=tenant_id,
        name="Production",
        type=ORMEnvType.PRODUCTION
    )
    repo = RepositoryORM(
        repository_id="repo-1",
        external_id="ext-repo-1",
        name="Backend",
        provider="github",
        organization="org",
        status="ACTIVE"
    )
    db_session.add(env)
    db_session.add(repo)
    db_session.commit()

    fw = FrameworkORM(
        framework_id="SOC 2",
        name="SOC 2",
        description="SOC 2 Framework",
        version="1.0.0",
        authority="AICPA",
        status="ACTIVE"
    )
    db_session.add(fw)
    db_session.commit()

    controls = []
    for i in range(1, 12):
        cid = f"CM-CONTROL-{i:02d}"
        c = ControlORM(
            control_id=cid,
            framework_id="SOC 2",
            criterion="CC8.1",
            name=f"Control {cid}",
            objective="Ensure compliance control",
            description="Control description",
            lifecycle_stage="Authorization",
            applicability="PRODUCTION",
            evidence_requirements=[],
            status="ACTIVE",
            version="1.0.0"
        )
        controls.append(c)
        db_session.add(c)
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

            check_orm = ComplianceCheckORM(
                check_id=cdata["check_id"],
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
                version=cdata.get("version", "1.0.0")
            )
            db_session.add(check_orm)
    db_session.commit()

    app = ApplicationORM(
        application_id="app-prod-eval",
        tenant_id=tenant_id,
        name="Security Platform",
        owner="sec-team",
        environment_id="env-prod-eval"
    )
    
    # Standard Users
    u1 = UserORM(internal_user_id="usr-alice", tenant_id=tenant_id, name="Alice", email="alice@test.com", role="developer")
    u2 = UserORM(internal_user_id="usr-bob", tenant_id=tenant_id, name="Bob", email="bob@test.com", role="qa")
    u3 = UserORM(internal_user_id="usr-charlie", tenant_id=tenant_id, name="Charlie", email="charlie@test.com", role="ops")
    
    db_session.add_all([app, u1, u2, u3])
    db_session.commit()
    
    return {
        "tenant_id": tenant_id,
        "env_id": "env-prod-eval",
        "app_id": "app-prod-eval",
        "alice": "usr-alice",
        "bob": "usr-bob",
        "charlie": "usr-charlie"
    }

def test_cm002_testing_before_deployment_pass(db_session, eval_context):
    tenant_id = eval_context["tenant_id"]
    change_id = "chg-test-002-pass"
    now = datetime.utcnow()
    
    # 1. Create Change
    change = ChangeORM(
        change_id=change_id, tenant_id=tenant_id, external_id="1", source="github",
        title="Valid E2E Change", description="Complete tests", change_type=ORMChangeType.NORMAL,
        requester_id=eval_context["alice"], owner_id=eval_context["alice"],
        environment_id=eval_context["env_id"], application_id=eval_context["app_id"],
        status="OPEN"
    )
    db_session.add(change)
    
    # 2. Add passing test RUN completed BEFORE deployment
    test_run = TestORM(
        test_id="test-run-002", tenant_id=tenant_id, change_id=change_id,
        source="github_actions", pipeline_id="101", commit_id="sha123",
        test_type="INTEGRATION", status=ORMTestStatus.PASS,
        started_at=now - timedelta(minutes=20), completed_at=now - timedelta(minutes=10)
    )
    db_session.add(test_run)
    
    # 3. Add deployment deployed AFTER testing
    deploy = DeploymentORM(
        deployment_id="dep-002", tenant_id=tenant_id, change_id=change_id,
        application_id=eval_context["app_id"], environment_id=eval_context["env_id"],
        repository_id="repo-1", version="1.0.0", commit_id="sha123",
        deployed_by=eval_context["charlie"], deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(deploy)
    db_session.commit()
    
    evaluator = EvaluationService(db_session)
    result = evaluator.evaluate_change(tenant_id, change_id, "CM-002")
    assert result.result == ORMCheckResultType.PASS
    assert "Rule Passed" in result.details["message"]

def test_cm002_testing_before_deployment_fail_failed_test(db_session, eval_context):
    tenant_id = eval_context["tenant_id"]
    change_id = "chg-test-002-fail-test"
    now = datetime.utcnow()
    
    change = ChangeORM(
        change_id=change_id, tenant_id=tenant_id, external_id="2", source="github",
        title="Failed Test Change", description="Tests failed", change_type=ORMChangeType.NORMAL,
        requester_id=eval_context["alice"], owner_id=eval_context["alice"],
        environment_id=eval_context["env_id"], application_id=eval_context["app_id"],
        status="OPEN"
    )
    db_session.add(change)
    
    test_run = TestORM(
        test_id="test-run-002-fail", tenant_id=tenant_id, change_id=change_id,
        source="github_actions", pipeline_id="102", commit_id="sha123",
        test_type="INTEGRATION", status=ORMTestStatus.FAIL,
        started_at=now - timedelta(minutes=20), completed_at=now - timedelta(minutes=10)
    )
    db_session.add(test_run)
    
    deploy = DeploymentORM(
        deployment_id="dep-002-fail", tenant_id=tenant_id, change_id=change_id,
        application_id=eval_context["app_id"], environment_id=eval_context["env_id"],
        repository_id="repo-1", version="1.0.0", commit_id="sha123",
        deployed_by=eval_context["charlie"], deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(deploy)
    db_session.commit()
    
    evaluator = EvaluationService(db_session)
    result = evaluator.evaluate_change(tenant_id, change_id, "CM-002")
    assert result.result == ORMCheckResultType.FAIL
    assert "Rule Failed" in result.details["message"]

def test_cm002_testing_before_deployment_fail_late_test(db_session, eval_context):
    tenant_id = eval_context["tenant_id"]
    change_id = "chg-test-002-late"
    now = datetime.utcnow()
    
    change = ChangeORM(
        change_id=change_id, tenant_id=tenant_id, external_id="3", source="github",
        title="Late Test Change", description="Tests run late", change_type=ORMChangeType.NORMAL,
        requester_id=eval_context["alice"], owner_id=eval_context["alice"],
        environment_id=eval_context["env_id"], application_id=eval_context["app_id"],
        status="OPEN"
    )
    db_session.add(change)
    
    test_run = TestORM(
        test_id="test-run-002-late", tenant_id=tenant_id, change_id=change_id,
        source="github_actions", pipeline_id="103", commit_id="sha123",
        test_type="INTEGRATION", status=ORMTestStatus.PASS,
        started_at=now + timedelta(minutes=10), completed_at=now + timedelta(minutes=20)
    )
    db_session.add(test_run)
    
    deploy = DeploymentORM(
        deployment_id="dep-002-late", tenant_id=tenant_id, change_id=change_id,
        application_id=eval_context["app_id"], environment_id=eval_context["env_id"],
        repository_id="repo-1", version="1.0.0", commit_id="sha123",
        deployed_by=eval_context["charlie"], deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(deploy)
    db_session.commit()
    
    evaluator = EvaluationService(db_session)
    result = evaluator.evaluate_change(tenant_id, change_id, "CM-002")
    assert result.result == ORMCheckResultType.FAIL

def test_cm002_testing_missing_test_insufficient(db_session, eval_context):
    tenant_id = eval_context["tenant_id"]
    change_id = "chg-test-002-missing-test"
    now = datetime.utcnow()
    
    change = ChangeORM(
        change_id=change_id, tenant_id=tenant_id, external_id="4", source="github",
        title="No Test Change", description="No tests", change_type=ORMChangeType.NORMAL,
        requester_id=eval_context["alice"], owner_id=eval_context["alice"],
        environment_id=eval_context["env_id"], application_id=eval_context["app_id"],
        status="OPEN"
    )
    db_session.add(change)
    
    deploy = DeploymentORM(
        deployment_id="dep-002-no-test", tenant_id=tenant_id, change_id=change_id,
        application_id=eval_context["app_id"], environment_id=eval_context["env_id"],
        repository_id="repo-1", version="1.0.0", commit_id="sha123",
        deployed_by=eval_context["charlie"], deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(deploy)
    db_session.commit()
    
    evaluator = EvaluationService(db_session)
    result = evaluator.evaluate_change(tenant_id, change_id, "CM-002")
    assert result.result == ORMCheckResultType.INSUFFICIENT_DATA
    assert "Required" in result.details["message"]

def test_cm002_testing_not_required_na(db_session, eval_context):
    tenant_id = eval_context["tenant_id"]
    change_id = "chg-test-002-na"
    
    # We do NOT seed any tests or deployments, but we map required=False by default (when tests list is empty, it skips testing)
    # Wait, the applicability is set when testing.required is false.
    # In our adapter, if there are no tests, required defaults to false if not explicitly set. Let's make sure it evaluates to NOT_APPLICABLE
    # Wait! If required is False, applicability says:
    # "field": "testing.required", "operator": "equals", "value": false -> NOT_APPLICABLE
    # Let's seed a change with no tests
    change = ChangeORM(
        change_id=change_id, tenant_id=tenant_id, external_id="5", source="github",
        title="NA Change", description="No tests required", change_type=ORMChangeType.STANDARD,
        requester_id=eval_context["alice"], owner_id=eval_context["alice"],
        environment_id=eval_context["env_id"], application_id=eval_context["app_id"],
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()
    
    evaluator = EvaluationService(db_session)
    result = evaluator.evaluate_change(tenant_id, change_id, "CM-002")
    assert result.result == ORMCheckResultType.NOT_APPLICABLE
    assert "applicability rule" in result.details["message"]

def test_cm003_approval_before_deployment_pass(db_session, eval_context):
    tenant_id = eval_context["tenant_id"]
    change_id = "chg-appr-003-pass"
    now = datetime.utcnow()
    
    change = ChangeORM(
        change_id=change_id, tenant_id=tenant_id, external_id="11", source="github",
        title="Approved Change", description="Good to go", change_type=ORMChangeType.NORMAL,
        requester_id=eval_context["alice"], owner_id=eval_context["alice"],
        environment_id=eval_context["env_id"], application_id=eval_context["app_id"],
        status="OPEN"
    )
    db_session.add(change)
    
    approval = ApprovalORM(
        approval_id="appr-003", tenant_id=tenant_id, change_id=change_id,
        approver_id=eval_context["bob"], role="QA lead", decision="APPROVED",
        approved_at=now - timedelta(minutes=5), source="github"
    )
    db_session.add(approval)
    
    deploy = DeploymentORM(
        deployment_id="dep-003", tenant_id=tenant_id, change_id=change_id,
        application_id=eval_context["app_id"], environment_id=eval_context["env_id"],
        repository_id="repo-1", version="1.0.0", commit_id="sha123",
        deployed_by=eval_context["charlie"], deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(deploy)
    db_session.commit()
    
    evaluator = EvaluationService(db_session)
    result = evaluator.evaluate_change(tenant_id, change_id, "CM-003")
    assert result.result == ORMCheckResultType.PASS

def test_cm003_approval_before_deployment_fail_late(db_session, eval_context):
    tenant_id = eval_context["tenant_id"]
    change_id = "chg-appr-003-late"
    now = datetime.utcnow()
    
    change = ChangeORM(
        change_id=change_id, tenant_id=tenant_id, external_id="12", source="github",
        title="Late Approved Change", description="Bad workflow", change_type=ORMChangeType.NORMAL,
        requester_id=eval_context["alice"], owner_id=eval_context["alice"],
        environment_id=eval_context["env_id"], application_id=eval_context["app_id"],
        status="OPEN"
    )
    db_session.add(change)
    
    approval = ApprovalORM(
        approval_id="appr-003-late", tenant_id=tenant_id, change_id=change_id,
        approver_id=eval_context["bob"], role="QA lead", decision="APPROVED",
        approved_at=now + timedelta(minutes=5), source="github"
    )
    db_session.add(approval)
    
    deploy = DeploymentORM(
        deployment_id="dep-003-late", tenant_id=tenant_id, change_id=change_id,
        application_id=eval_context["app_id"], environment_id=eval_context["env_id"],
        repository_id="repo-1", version="1.0.0", commit_id="sha123",
        deployed_by=eval_context["charlie"], deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(deploy)
    db_session.commit()
    
    evaluator = EvaluationService(db_session)
    result = evaluator.evaluate_change(tenant_id, change_id, "CM-003")
    assert result.result == ORMCheckResultType.FAIL

def test_cm004_segregation_of_duties_pass(db_session, eval_context):
    tenant_id = eval_context["tenant_id"]
    change_id = "chg-sod-pass"
    now = datetime.utcnow()
    
    change = ChangeORM(
        change_id=change_id, tenant_id=tenant_id, external_id="20", source="github",
        title="Sod Pass Change", description="All distinct", change_type=ORMChangeType.NORMAL,
        requester_id=eval_context["alice"], owner_id=eval_context["alice"],
        environment_id=eval_context["env_id"], application_id=eval_context["app_id"],
        status="OPEN"
    )
    db_session.add(change)
    
    approval = ApprovalORM(
        approval_id="appr-sod-pass", tenant_id=tenant_id, change_id=change_id,
        approver_id=eval_context["bob"], role="QA", decision="APPROVED",
        approved_at=now - timedelta(minutes=5), source="github"
    )
    db_session.add(approval)
    
    deploy = DeploymentORM(
        deployment_id="dep-sod-pass", tenant_id=tenant_id, change_id=change_id,
        application_id=eval_context["app_id"], environment_id=eval_context["env_id"],
        repository_id="repo-1", version="1.0.0", commit_id="sha123",
        deployed_by=eval_context["charlie"], deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(deploy)
    db_session.commit()
    
    evaluator = EvaluationService(db_session)
    result = evaluator.evaluate_change(tenant_id, change_id, "CM-004")
    assert result.result == ORMCheckResultType.PASS

def test_cm004_segregation_of_duties_fail_requester_equals_approver(db_session, eval_context):
    tenant_id = eval_context["tenant_id"]
    change_id = "chg-sod-fail-req-appr"
    now = datetime.utcnow()
    
    # Alice requests and Alice approves!
    change = ChangeORM(
        change_id=change_id, tenant_id=tenant_id, external_id="21", source="github",
        title="Sod Fail Change", description="Same actor", change_type=ORMChangeType.NORMAL,
        requester_id=eval_context["alice"], owner_id=eval_context["alice"],
        environment_id=eval_context["env_id"], application_id=eval_context["app_id"],
        status="OPEN"
    )
    db_session.add(change)
    
    approval = ApprovalORM(
        approval_id="appr-sod-fail", tenant_id=tenant_id, change_id=change_id,
        approver_id=eval_context["alice"], role="QA", decision="APPROVED",
        approved_at=now - timedelta(minutes=5), source="github"
    )
    db_session.add(approval)
    
    deploy = DeploymentORM(
        deployment_id="dep-sod-fail", tenant_id=tenant_id, change_id=change_id,
        application_id=eval_context["app_id"], environment_id=eval_context["env_id"],
        repository_id="repo-1", version="1.0.0", commit_id="sha123",
        deployed_by=eval_context["charlie"], deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(deploy)
    db_session.commit()
    
    evaluator = EvaluationService(db_session)
    result = evaluator.evaluate_change(tenant_id, change_id, "CM-004")
    assert result.result == ORMCheckResultType.FAIL
    assert "Rule Failed" in result.details["message"]

def test_cm005_traceability_pass(db_session, eval_context):
    tenant_id = eval_context["tenant_id"]
    change_id = "chg-trace-pass"
    now = datetime.utcnow()
    
    change = ChangeORM(
        change_id=change_id, tenant_id=tenant_id, external_id="30", source="github",
        title="Trace Pass", description="Authorized change", change_type=ORMChangeType.NORMAL,
        requester_id=eval_context["alice"], owner_id=eval_context["alice"],
        environment_id=eval_context["env_id"], application_id=eval_context["app_id"],
        status="OPEN"
    )
    db_session.add(change)
    
    # Authorized
    auth = AuthorizationORM(
        authorization_id="auth-trace-pass", tenant_id=tenant_id, change_id=change_id,
        authorized_by=eval_context["bob"], status="APPROVED", authorized_at=now - timedelta(minutes=10),
        source="jira"
    )
    db_session.add(auth)
    
    deploy = DeploymentORM(
        deployment_id="dep-trace-pass", tenant_id=tenant_id, change_id=change_id,
        application_id=eval_context["app_id"], environment_id=eval_context["env_id"],
        repository_id="repo-1", version="1.0.0", commit_id="sha123",
        deployed_by=eval_context["charlie"], deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(deploy)
    db_session.commit()
    
    evaluator = EvaluationService(db_session)
    result = evaluator.evaluate_change(tenant_id, change_id, "CM-005")
    assert result.result == ORMCheckResultType.PASS

def test_cm005_traceability_fail_missing_change_id(db_session, eval_context):
    tenant_id = eval_context["tenant_id"]
    change_id = "chg-trace-fail-missing"
    now = datetime.utcnow()
    
    # Seeding a change, but since we are simulating deployment without a change context
    # If the deployment change_id is missing, or the mapping lacks a change_id, it is a bypass
    # Let's seed a change with NO authorizations at all. It will result in DataAvailability.UNKNOWN for authorization.authorized, which will trigger FAIL
    change = ChangeORM(
        change_id=change_id, tenant_id=tenant_id, external_id="31", source="github",
        title="No Auth Change", description="Bypass change", change_type=ORMChangeType.NORMAL,
        requester_id=eval_context["alice"], owner_id=eval_context["alice"],
        environment_id=eval_context["env_id"], application_id=eval_context["app_id"],
        status="OPEN"
    )
    db_session.add(change)
    
    deploy = DeploymentORM(
        deployment_id="dep-trace-fail-missing", tenant_id=tenant_id, change_id=change_id,
        application_id=eval_context["app_id"], environment_id=eval_context["env_id"],
        repository_id="repo-1", version="1.0.0", commit_id="sha123",
        deployed_by=eval_context["charlie"], deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(deploy)
    db_session.commit()
    
    evaluator = EvaluationService(db_session)
    result = evaluator.evaluate_change(tenant_id, change_id, "CM-005")
    assert result.result == ORMCheckResultType.FAIL
    # Ensure missing authorization results in FAIL (bypass) instead of INSUFFICIENT_DATA
    assert "Required fields" in result.details["message"]
