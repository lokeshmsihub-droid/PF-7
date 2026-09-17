import pytest
import uuid
import json
import hashlib
from datetime import datetime, timedelta, UTC
from sqlalchemy.orm import Session
from app.db.mongodb import MongoDBClient as MongoDB
from app.services.normalization_service import NormalizationService
from app.services.correlation_service import CorrelationService
from app.services.evaluation_service import EvaluationService
from app.services.finding_service import FindingService
from app.services.recheck_service import RecheckService
from app.services.remediation_service import RemediationService
from app.services.change_monitoring_service import ChangeMonitoringService
from app.services.evidence_association_service import EvidenceAssociationService
from app.services.evidence_validation_service import EvidenceValidationService
from app.services.change_control_orchestrator import ChangeControlOrchestrator
from app.models.orm import (
    ORMChangeType, ORMTestStatus, ORMCheckResultType, FindingORM, RemediationTaskORM,
    ChangeORM, DeploymentORM, TestORM, ApprovalORM, AuditLogORM, ChangeDecisionORM,
    AuthorizationORM, ComplianceCheckORM, CheckResultORM
)

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
    from app.models import orm

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
    """Helper to insert raw events directly into MongoDB."""
    mongo = MongoDB()
    col = mongo.db.raw_events
    event_id = str(uuid.uuid4())
    pl_str = json.dumps(payload, sort_keys=True, default=str)
    pl_hash = hashlib.sha256(pl_str.encode("utf-8")).hexdigest()
    col.insert_one({
        "event_id": event_id,
        "tenant_id": tenant_id,
        "connector_account_id": "acc-e2e-test",
        "source": "github",
        "provider": "github",
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
    """Seed users and identity link mapping records."""
    from app.models import orm
    norm_service = NormalizationService(db_session)
    norm_service._ensure_baseline_entities(tenant_id)
    
    users = [
        ("usr-alice", "Alice E2E", "alice@acme.com", "developer"),
        ("usr-bob", "Bob E2E", "bob@acme.com", "qa"),
        ("usr-charlie", "Charlie E2E", "charlie@acme.com", "ops")
    ]
    for uid, name, email, role in users:
        u = db_session.query(orm.UserORM).filter_by(internal_user_id=uid).first()
        if not u:
            db_session.add(orm.UserORM(
                internal_user_id=uid, tenant_id=tenant_id, name=name, email=email, role=role, status="ACTIVE"
            ))
            
    links = [
        ("usr-alice", "alice-git"),
        ("usr-bob", "bob-git"),
        ("usr-charlie", "charlie-git")
    ]
    for uid, handle in links:
        link = db_session.query(orm.IdentityLinkORM).filter_by(
            tenant_id=tenant_id, source="github", external_user_id=handle
        ).first()
        if not link:
            db_session.add(orm.IdentityLinkORM(
                internal_user_id=uid, tenant_id=tenant_id, source="github",
                external_user_id=handle, external_username=handle, status="ACTIVE"
            ))
    db_session.commit()

# --- SCENARIO TESTS ---

def test_scenario_a_fully_compliant(db_session):
    """Scenario A: All controls pass -> COMPLIANT overall decision."""
    tenant_id = "tenant-scen-a"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    # Create change request
    change = ChangeORM(
        change_id="chg-scen-a",
        tenant_id=tenant_id,
        external_id="pr-1001",
        source="github",
        title="Valid Compliant Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    # Seed Passing test, Approved reviews, deployments, authorizations
    auth = AuthorizationORM(
        authorization_id="auth-scen-a", tenant_id=tenant_id, change_id="chg-scen-a",
        authorized_by="usr-bob", status="APPROVED", authorized_at=now - timedelta(minutes=60), source="jira"
    )
    db_session.add(auth)

    apprv = ApprovalORM(
        approval_id="apprv-scen-a", tenant_id=tenant_id, change_id="chg-scen-a",
        approver_id="usr-bob", role="qa", decision="APPROVED", approved_at=now - timedelta(minutes=45), source="github"
    )
    db_session.add(apprv)

    test = TestORM(
        test_id="test-scen-a", tenant_id=tenant_id, change_id="chg-scen-a",
        source="github_actions", pipeline_id="pipe-1", commit_id="sha-a",
        test_type="unit", status=ORMTestStatus.PASS, started_at=now - timedelta(minutes=55), completed_at=now - timedelta(minutes=50)
    )
    db_session.add(test)

    deploy = DeploymentORM(
        deployment_id="deploy-scen-a", tenant_id=tenant_id, change_id="chg-scen-a",
        source="github", application_id="app-default", environment_id="env-prod", repository_id="repo-default", version="1.0.0", commit_id="sha-a",
        status="SUCCESS", deployed_at=now - timedelta(minutes=30), deployed_by="usr-charlie"
    )
    db_session.add(deploy)
    db_session.commit()

    # Run orchestration
    orchestrator = ChangeControlOrchestrator(db_session)
    dec = orchestrator.evaluate_change(tenant_id, "chg-scen-a")

    assert dec.decision_status == "COMPLIANT"
    assert dec.pass_count > 0
    assert dec.fail_count == 0

def test_scenario_b_single_failed_control(db_session):
    """Scenario B: Testing check fails -> NON_COMPLIANT / REMEDIATION_REQUIRED, creates Finding and task."""
    tenant_id = "tenant-scen-b"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    change = ChangeORM(
        change_id="chg-scen-b",
        tenant_id=tenant_id,
        external_id="pr-1002",
        source="github",
        title="Failed Testing Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    auth = AuthorizationORM(
        authorization_id="auth-scen-b", tenant_id=tenant_id, change_id="chg-scen-b",
        authorized_by="usr-bob", status="APPROVED", authorized_at=now - timedelta(minutes=60), source="jira"
    )
    db_session.add(auth)

    apprv = ApprovalORM(
        approval_id="apprv-scen-b", tenant_id=tenant_id, change_id="chg-scen-b",
        approver_id="usr-bob", role="qa", decision="APPROVED", approved_at=now - timedelta(minutes=45), source="github"
    )
    db_session.add(apprv)

    # Failed test status
    test = TestORM(
        test_id="test-scen-b", tenant_id=tenant_id, change_id="chg-scen-b",
        source="github_actions", pipeline_id="pipe-1", commit_id="sha-b",
        test_type="unit", status=ORMTestStatus.FAIL, started_at=now - timedelta(minutes=55), completed_at=now - timedelta(minutes=50)
    )
    db_session.add(test)

    deploy = DeploymentORM(
        deployment_id="deploy-scen-b", tenant_id=tenant_id, change_id="chg-scen-b",
        source="github", application_id="app-default", environment_id="env-prod", repository_id="repo-default", version="1.0.0", commit_id="sha-b",
        status="SUCCESS", deployed_at=now - timedelta(minutes=30), deployed_by="usr-charlie"
    )
    db_session.add(deploy)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    dec = orchestrator.evaluate_change(tenant_id, "chg-scen-b")

    assert dec.decision_status == "REMEDIATION_REQUIRED"
    assert dec.fail_count > 0

    # Verify Finding & Remediation Task exist
    finding = db_session.query(FindingORM).filter_by(tenant_id=tenant_id, change_id="chg-scen-b", check_id="CM-002").first()
    assert finding is not None
    assert finding.status == "OPEN"

    task = db_session.query(RemediationTaskORM).filter_by(finding_id=finding.finding_id).first()
    assert task is not None
    assert task.status == "PENDING"

def test_scenario_c_multiple_failed_controls(db_session):
    """Scenario C: Multiple controls fail -> REMEDIATION_REQUIRED/NON_COMPLIANT with multiple open findings."""
    tenant_id = "tenant-scen-c"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    # Change with failed testing and missing peer reviews (CM-002 & CM-003 fails)
    change = ChangeORM(
        change_id="chg-scen-c",
        tenant_id=tenant_id,
        external_id="pr-1003",
        source="github",
        title="Multiple Failures Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    auth = AuthorizationORM(
        authorization_id="auth-scen-c", tenant_id=tenant_id, change_id="chg-scen-c",
        authorized_by="usr-bob", status="APPROVED", authorized_at=now - timedelta(minutes=60), source="jira"
    )
    db_session.add(auth)

    apprv = ApprovalORM(
        approval_id="apprv-scen-c", tenant_id=tenant_id, change_id="chg-scen-c",
        approver_id="usr-bob", role="qa", decision="REJECTED", approved_at=now - timedelta(minutes=45), source="github"
    )
    db_session.add(apprv)

    test = TestORM(
        test_id="test-scen-c", tenant_id=tenant_id, change_id="chg-scen-c",
        source="github_actions", pipeline_id="pipe-1", commit_id="sha-c",
        test_type="unit", status=ORMTestStatus.FAIL, started_at=now - timedelta(minutes=55), completed_at=now - timedelta(minutes=50)
    )
    db_session.add(test)

    deploy = DeploymentORM(
        deployment_id="deploy-scen-c", tenant_id=tenant_id, change_id="chg-scen-c",
        source="github", application_id="app-default", environment_id="env-prod", repository_id="repo-default", version="1.0.0", commit_id="sha-c",
        status="SUCCESS", deployed_at=now - timedelta(minutes=30), deployed_by="usr-charlie"
    )
    db_session.add(deploy)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    dec = orchestrator.evaluate_change(tenant_id, "chg-scen-c")

    assert dec.decision_status == "REMEDIATION_REQUIRED"
    assert dec.fail_count >= 2

    # Check both findings
    f2 = db_session.query(FindingORM).filter_by(tenant_id=tenant_id, change_id="chg-scen-c", check_id="CM-002").first()
    f3 = db_session.query(FindingORM).filter_by(tenant_id=tenant_id, change_id="chg-scen-c", check_id="CM-003").first()
    assert f2 is not None and f3 is not None

def test_scenario_d_missing_evidence(db_session):
    """Scenario D: Required check evidence missing -> INSUFFICIENT_DATA overall status (no false FAIL)."""
    tenant_id = "tenant-scen-d"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    # Change with missing test run evidence (CM-002 has no tests seeded at all)
    change = ChangeORM(
        change_id="chg-scen-d",
        tenant_id=tenant_id,
        external_id="pr-1004",
        source="github",
        title="Missing Evidence Change",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    auth = AuthorizationORM(
        authorization_id="auth-scen-d", tenant_id=tenant_id, change_id="chg-scen-d",
        authorized_by="usr-bob", status="APPROVED", authorized_at=now - timedelta(minutes=60), source="jira"
    )
    db_session.add(auth)

    apprv = ApprovalORM(
        approval_id="apprv-scen-d", tenant_id=tenant_id, change_id="chg-scen-d",
        approver_id="usr-bob", role="qa", decision="APPROVED", approved_at=now - timedelta(minutes=45), source="github"
    )
    db_session.add(apprv)

    # Deployment exists but no TestORM is seeded!
    deploy = DeploymentORM(
        deployment_id="deploy-scen-d", tenant_id=tenant_id, change_id="chg-scen-d",
        source="github", application_id="app-default", environment_id="env-prod", repository_id="repo-default", version="1.0.0", commit_id="sha-d",
        status="SUCCESS", deployed_at=now - timedelta(minutes=30), deployed_by="usr-charlie"
    )
    db_session.add(deploy)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    dec = orchestrator.evaluate_change(tenant_id, "chg-scen-d")

    assert dec.decision_status == "INSUFFICIENT_DATA"
    assert dec.fail_count == 0
    assert dec.insufficient_data_count > 0

def test_scenario_e_not_applicable(db_session):
    """Scenario E: Staging environment checks should result in NOT_APPLICABLE and not be aggregated."""
    tenant_id = "tenant-scen-e"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    # Change on env-staging (type STAGING)
    # Ensure environment is seeded as STAGING
    from app.models.orm import EnvironmentORM, ORMEnvType
    env_stag = db_session.query(EnvironmentORM).filter_by(environment_id="env-staging").first()
    if not env_stag:
        env_stag = EnvironmentORM(environment_id="env-staging", tenant_id=tenant_id, name="staging", type=ORMEnvType.STAGING)
        db_session.add(env_stag)
        db_session.commit()

    change = ChangeORM(
        change_id="chg-scen-e",
        tenant_id=tenant_id,
        external_id="pr-1005",
        source="github",
        title="Staging Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-staging",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    dec = orchestrator.evaluate_change(tenant_id, "chg-scen-e")

    # Since it is staging, checks like CM-002 applicable to PRODUCTION should return NOT_APPLICABLE.
    # Therefore, overall decision can be COMPLIANT (if no fails/insufficient)
    assert dec.not_applicable_count > 0

def test_scenario_f_jira_approval_changed(db_session):
    """Scenario F: Jira approval event -> Evaluates only affected checks."""
    tenant_id = "tenant-scen-f"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    change = ChangeORM(
        change_id="chg-scen-f",
        tenant_id=tenant_id,
        external_id="pr-1006",
        source="github",
        title="Jira Event Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    
    # Run evaluation with event mapping
    dec = orchestrator.evaluate_affected_controls(tenant_id, "chg-scen-f", "jira_approval_changed")
    
    # Check that audit log has affected_checks in details
    audit = db_session.query(AuditLogORM).filter_by(
        tenant_id=tenant_id, action="control_evaluation_started", entity_id="chg-scen-f"
    ).first()
    assert audit is not None
    assert "affected_checks" in audit.details
    assert "CM-001" in audit.details["affected_checks"]

def test_scenario_g_ci_test_correction(db_session):
    """Scenario G: CI Failure -> Remediation -> CI PASS -> Recheck -> overall COMPLIANT."""
    tenant_id = "tenant-scen-g"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    change = ChangeORM(
        change_id="chg-scen-g",
        tenant_id=tenant_id,
        external_id="pr-1007",
        source="github",
        title="CI Correction Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    # Seeding prerequisites except test passes (test status FAIL)
    auth = AuthorizationORM(
        authorization_id="auth-scen-g", tenant_id=tenant_id, change_id="chg-scen-g",
        authorized_by="usr-bob", status="APPROVED", authorized_at=now - timedelta(minutes=60), source="jira"
    )
    db_session.add(auth)

    apprv = ApprovalORM(
        approval_id="apprv-scen-g", tenant_id=tenant_id, change_id="chg-scen-g",
        approver_id="usr-bob", role="qa", decision="APPROVED", approved_at=now - timedelta(minutes=45), source="github"
    )
    db_session.add(apprv)

    test = TestORM(
        test_id="test-scen-g", tenant_id=tenant_id, change_id="chg-scen-g",
        source="github_actions", pipeline_id="pipe-1", commit_id="sha-g",
        test_type="unit", status=ORMTestStatus.FAIL, started_at=now - timedelta(minutes=55), completed_at=now - timedelta(minutes=50)
    )
    db_session.add(test)

    deploy = DeploymentORM(
        deployment_id="deploy-scen-g", tenant_id=tenant_id, change_id="chg-scen-g",
        source="github", application_id="app-default", environment_id="env-prod", repository_id="repo-default", version="1.0.0", commit_id="sha-g",
        status="SUCCESS", deployed_at=now - timedelta(minutes=30), deployed_by="usr-charlie"
    )
    db_session.add(deploy)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    dec1 = orchestrator.evaluate_change(tenant_id, "chg-scen-g")
    assert dec1.decision_status == "REMEDIATION_REQUIRED"

    # Simulate developer fix: update test status to PASS
    test.status = ORMTestStatus.PASS
    db_session.commit()

    # Re-evaluate
    dec2 = orchestrator.evaluate_change(tenant_id, "chg-scen-g")
    assert dec2.decision_status == "COMPLIANT"

def test_scenario_h_deployment_commit_correction(db_session):
    """Scenario H: Bad deployment SHA -> NON_COMPLIANT -> Correct deployment SHA -> recheck -> COMPLIANT."""
    tenant_id = "tenant-scen-h"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    change = ChangeORM(
        change_id="chg-scen-h",
        tenant_id=tenant_id,
        external_id="pr-1008",
        source="github",
        title="Commit Correction Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    auth = AuthorizationORM(
        authorization_id="auth-scen-h", tenant_id=tenant_id, change_id="chg-scen-h",
        authorized_by="usr-bob", status="APPROVED", authorized_at=now - timedelta(minutes=60), source="jira"
    )
    db_session.add(auth)

    apprv = ApprovalORM(
        approval_id="apprv-scen-h", tenant_id=tenant_id, change_id="chg-scen-h",
        approver_id="usr-bob", role="qa", decision="APPROVED", approved_at=now - timedelta(minutes=45), source="github"
    )
    db_session.add(apprv)

    # Test commit is sha-correct
    test = TestORM(
        test_id="test-scen-h", tenant_id=tenant_id, change_id="chg-scen-h",
        source="github_actions", pipeline_id="pipe-1", commit_id="sha-correct",
        test_type="unit", status=ORMTestStatus.PASS, started_at=now - timedelta(minutes=55), completed_at=now - timedelta(minutes=50)
    )
    db_session.add(test)

    # Bad deployment SHA (commit drift!) - not correlated to change initially
    deploy = DeploymentORM(
        deployment_id="deploy-scen-h", tenant_id=tenant_id, change_id=None,
        source="github", application_id="app-default", environment_id="env-prod", repository_id="repo-default", version="1.0.0", commit_id="sha-bad-drift",
        status="SUCCESS", deployed_at=now - timedelta(minutes=30), deployed_by="usr-charlie"
    )
    db_session.add(deploy)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    dec1 = orchestrator.evaluate_change(tenant_id, "chg-scen-h")
    # Commit drift should fail CM-005 because deployment is not correlated to change
    assert dec1.decision_status == "REMEDIATION_REQUIRED"

    # Simulate Fix: deploy correct commit which now correlates
    deploy.change_id = "chg-scen-h"
    deploy.commit_id = "sha-correct"
    db_session.commit()

    # Recheck
    dec2 = orchestrator.evaluate_change(tenant_id, "chg-scen-h")
    assert dec2.decision_status == "COMPLIANT"

def test_scenario_i_duplicate_event(db_session):
    """Scenario I: Same event processed multiple times does not create duplicates."""
    tenant_id = "tenant-scen-i"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    change = ChangeORM(
        change_id="chg-scen-i",
        tenant_id=tenant_id,
        external_id="pr-1009",
        source="github",
        title="Duplicate Event Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    # Seeding failed test and a deployment so CM-002 can evaluate to FAIL
    test = TestORM(
        test_id="test-scen-i", tenant_id=tenant_id, change_id="chg-scen-i",
        source="github_actions", pipeline_id="pipe-1", commit_id="sha-i",
        test_type="unit", status=ORMTestStatus.FAIL, started_at=now - timedelta(minutes=55), completed_at=now - timedelta(minutes=50)
    )
    db_session.add(test)

    deploy = DeploymentORM(
        deployment_id="deploy-scen-i", tenant_id=tenant_id, change_id="chg-scen-i",
        source="github", application_id="app-default", environment_id="env-prod", repository_id="repo-default", version="1.0.0", commit_id="sha-i",
        status="SUCCESS", deployed_at=now - timedelta(minutes=30), deployed_by="usr-charlie"
    )
    db_session.add(deploy)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    
    # Process check result multiple times through the orchestrator's cycle
    evaluator = EvaluationService(db_session)
    res1 = evaluator.evaluate_change(tenant_id, "chg-scen-i", "CM-002")
    
    orchestrator._process_single_check_remediation_cycle(tenant_id, "chg-scen-i", res1)
    orchestrator._process_single_check_remediation_cycle(tenant_id, "chg-scen-i", res1)
    orchestrator._process_single_check_remediation_cycle(tenant_id, "chg-scen-i", res1)

    # Assert only 1 finding & 1 task exist
    fcnt = db_session.query(FindingORM).filter_by(tenant_id=tenant_id, change_id="chg-scen-i", check_id="CM-002").count()
    tcnt = db_session.query(RemediationTaskORM).filter_by(tenant_id=tenant_id, change_id="chg-scen-i", check_id="CM-002").count()
    
    assert fcnt == 1
    assert tcnt == 1

def test_scenario_j_decision_history(db_session):
    """Scenario J: Querying history yields separate records and doesn't overwrite decisions."""
    tenant_id = "tenant-scen-j"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    change = ChangeORM(
        change_id="chg-scen-j",
        tenant_id=tenant_id,
        external_id="pr-1010",
        source="github",
        title="History Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    
    # 1. Run first evaluation (will fail/insufficient -> INSUFFICIENT_DATA)
    orchestrator.evaluate_change(tenant_id, "chg-scen-j")
    
    # 2. Run second evaluation
    orchestrator.evaluate_change(tenant_id, "chg-scen-j")

    history = orchestrator.get_decision_history(tenant_id, "chg-scen-j")
    assert len(history) == 2
    assert history[0].decision_id != history[1].decision_id

def test_scenario_k_explanation(db_session):
    """Scenario K: Retriving decision explanation matches all structured properties."""
    tenant_id = "tenant-scen-k"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    change = ChangeORM(
        change_id="chg-scen-k",
        tenant_id=tenant_id,
        external_id="pr-1011",
        source="github",
        title="Explain Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    # Fail CM-002 by seeding failing test and a deployment
    test = TestORM(
        test_id="test-scen-k", tenant_id=tenant_id, change_id="chg-scen-k",
        source="github_actions", pipeline_id="pipe-1", commit_id="sha-k",
        test_type="unit", status=ORMTestStatus.FAIL, started_at=now - timedelta(minutes=55), completed_at=now - timedelta(minutes=50)
    )
    db_session.add(test)

    deploy = DeploymentORM(
        deployment_id="deploy-scen-k", tenant_id=tenant_id, change_id="chg-scen-k",
        source="github", application_id="app-default", environment_id="env-prod", repository_id="repo-default", version="1.0.0", commit_id="sha-k",
        status="SUCCESS", deployed_at=now - timedelta(minutes=30), deployed_by="usr-charlie"
    )
    db_session.add(deploy)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    orchestrator.evaluate_change(tenant_id, "chg-scen-k")

    exp = orchestrator.get_decision_explanation(tenant_id, "chg-scen-k")
    assert exp["change_id"] == "chg-scen-k"
    assert exp["overall_status"] == "REMEDIATION_REQUIRED"
    assert len(exp["failed_controls"]) > 0
    assert exp["failed_controls"][0]["check_id"] == "CM-002"
    assert exp["failed_controls"][0]["remediation_status"] == "PENDING"

def test_scenario_l_cross_tenant_isolation(db_session):
    """Scenario L: Tenant B cannot retrieve or evaluate Tenant A's decisions."""
    tenant_id_a = "tenant-scen-l-a"
    tenant_id_b = "tenant-scen-l-b"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id_a)
    setup_identity_mappings(db_session, tenant_id_b)

    # Create change in Tenant A
    change_a = ChangeORM(
        change_id="chg-scen-l-a",
        tenant_id=tenant_id_a,
        external_id="pr-1012",
        source="github",
        title="Tenant A Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change_a)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    
    # Evaluate as Tenant A should pass
    orchestrator.evaluate_change(tenant_id_a, "chg-scen-l-a")

    # Evaluate or query as Tenant B should raise ValueError
    with pytest.raises(ValueError, match="Access denied"):
        orchestrator.evaluate_change(tenant_id_b, "chg-scen-l-a")

    with pytest.raises(ValueError, match="Access denied"):
        orchestrator.get_current_decision(tenant_id_b, "chg-scen-l-a")

def test_scenario_m_audit_chain(db_session):
    """Scenario M: Orchestrator evaluation logs are saved in cryptographic chain."""
    tenant_id = "tenant-scen-m"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)

    change = ChangeORM(
        change_id="chg-scen-m",
        tenant_id=tenant_id,
        external_id="pr-1013",
        source="github",
        title="Audit Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    orchestrator.evaluate_change(tenant_id, "chg-scen-m")

    # Verify audit log exists
    started_log = db_session.query(AuditLogORM).filter_by(
        tenant_id=tenant_id, action="control_evaluation_started", entity_id="chg-scen-m"
    ).first()
    
    completed_log = db_session.query(AuditLogORM).filter_by(
        tenant_id=tenant_id, action="control_evaluation_completed", entity_id="chg-scen-m"
    ).first()

    assert started_log is not None
    assert completed_log is not None
    assert started_log.event_hash is not None

    # Verify cryptographic chaining of all log entries for this tenant
    logs = db_session.query(AuditLogORM).filter_by(tenant_id=tenant_id).order_by(AuditLogORM.sequence_number.asc()).all()
    assert len(logs) >= 2
    for i in range(1, len(logs)):
        assert logs[i].previous_hash == logs[i-1].event_hash


def test_scenario_n_insufficient_data_recovery(db_session):
    """Scenario N: INSUFFICIENT_DATA -> Missing evidence arrives -> Recheck -> COMPLIANT."""
    tenant_id = "tenant-scen-n"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    change = ChangeORM(
        change_id="chg-scen-n",
        tenant_id=tenant_id,
        external_id="pr-1014",
        source="github",
        title="Evidence Recovery Change",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    auth = AuthorizationORM(
        authorization_id="auth-scen-n", tenant_id=tenant_id, change_id="chg-scen-n",
        authorized_by="usr-bob", status="APPROVED", authorized_at=now - timedelta(minutes=60), source="jira"
    )
    db_session.add(auth)

    apprv = ApprovalORM(
        approval_id="apprv-scen-n", tenant_id=tenant_id, change_id="chg-scen-n",
        approver_id="usr-bob", role="qa", decision="APPROVED", approved_at=now - timedelta(minutes=45), source="github"
    )
    db_session.add(apprv)

    # Seed the deployment initially so CM-005 passes
    deploy = DeploymentORM(
        deployment_id="deploy-scen-n", tenant_id=tenant_id, change_id="chg-scen-n",
        source="github", application_id="app-default", environment_id="env-prod", repository_id="repo-default", version="1.0.0", commit_id="sha-n",
        status="SUCCESS", deployed_at=now - timedelta(minutes=30), deployed_by="usr-charlie"
    )
    db_session.add(deploy)
    db_session.commit()

    # Missing TestORM -> CM-002 returns INSUFFICIENT_DATA
    orchestrator = ChangeControlOrchestrator(db_session)
    dec1 = orchestrator.evaluate_change(tenant_id, "chg-scen-n")
    assert dec1.decision_status == "INSUFFICIENT_DATA"

    # Seed the test evidence (recovery!)
    test = TestORM(
        test_id="test-scen-n", tenant_id=tenant_id, change_id="chg-scen-n",
        source="github_actions", pipeline_id="pipe-1", commit_id="sha-n",
        test_type="unit", status=ORMTestStatus.PASS, started_at=now - timedelta(minutes=55), completed_at=now - timedelta(minutes=50)
    )
    db_session.add(test)
    db_session.commit()

    # Re-evaluate
    dec2 = orchestrator.evaluate_change(tenant_id, "chg-scen-n")
    assert dec2.decision_status == "COMPLIANT"

def test_scenario_o_finding_resolution(db_session):
    """Scenario O: FAIL -> Finding OPEN -> Remediation -> Fix -> Recheck -> Finding RESOLVED -> Overall COMPLIANT."""
    tenant_id = "tenant-scen-o"
    seed_checks_and_controls(db_session)
    setup_identity_mappings(db_session, tenant_id)
    now = datetime.now(UTC)

    change = ChangeORM(
        change_id="chg-scen-o",
        tenant_id=tenant_id,
        external_id="pr-1015",
        source="github",
        title="Resolution Change",
        change_type=ORMChangeType.STANDARD,
        requester_id="usr-alice",
        owner_id="usr-bob",
        application_id="app-default",
        environment_id="env-prod",
        status="COMPLETED"
    )
    db_session.add(change)
    db_session.commit()

    # Prerequisites except test (test is FAIL)
    auth = AuthorizationORM(
        authorization_id="auth-scen-o", tenant_id=tenant_id, change_id="chg-scen-o",
        authorized_by="usr-bob", status="APPROVED", authorized_at=now - timedelta(minutes=60), source="jira"
    )
    db_session.add(auth)

    apprv = ApprovalORM(
        approval_id="apprv-scen-o", tenant_id=tenant_id, change_id="chg-scen-o",
        approver_id="usr-bob", role="qa", decision="APPROVED", approved_at=now - timedelta(minutes=45), source="github"
    )
    db_session.add(apprv)

    test = TestORM(
        test_id="test-scen-o", tenant_id=tenant_id, change_id="chg-scen-o",
        source="github_actions", pipeline_id="pipe-1", commit_id="sha-o",
        test_type="unit", status=ORMTestStatus.FAIL, started_at=now - timedelta(minutes=55), completed_at=now - timedelta(minutes=50)
    )
    db_session.add(test)

    deploy = DeploymentORM(
        deployment_id="deploy-scen-o", tenant_id=tenant_id, change_id="chg-scen-o",
        source="github", application_id="app-default", environment_id="env-prod", repository_id="repo-default", version="1.0.0", commit_id="sha-o",
        status="SUCCESS", deployed_at=now - timedelta(minutes=30), deployed_by="usr-charlie"
    )
    db_session.add(deploy)
    db_session.commit()

    orchestrator = ChangeControlOrchestrator(db_session)
    dec1 = orchestrator.evaluate_change(tenant_id, "chg-scen-o")
    assert dec1.decision_status == "REMEDIATION_REQUIRED"

    finding = db_session.query(FindingORM).filter_by(tenant_id=tenant_id, change_id="chg-scen-o", check_id="CM-002").first()
    assert finding.status == "OPEN"

    # Fix test status to PASS
    test.status = ORMTestStatus.PASS
    db_session.commit()

    # Recheck will run evaluate_change and resolve findings/remediations
    dec2 = orchestrator.evaluate_change(tenant_id, "chg-scen-o")
    
    assert dec2.decision_status == "COMPLIANT"
    assert finding.status == "RESOLVED"
