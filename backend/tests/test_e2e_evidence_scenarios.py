import pytest
import os
import json
import uuid
import hashlib
from datetime import datetime, UTC, timedelta
from sqlalchemy import text
from app.db.base import Base
from app.models import orm
from app.models.orm import (
    ChangeORM, AuthorizationORM, ApprovalORM, TestORM, DeploymentORM,
    ChangeRollbackORM, EvidenceMetadataORM, CheckResultORM, FindingORM,
    RemediationTaskORM, AuditLogORM, ORMChangeType, ORMTestStatus,
    ORMCheckResultType
)
from app.services.normalization_service import NormalizationService
from app.services.evidence_association_service import EvidenceAssociationService
from app.services.evidence_validation_service import EvidenceValidationService
from app.services.evidence_package_service import EvidencePackageService
from app.services.evaluation_service import EvaluationService
from app.services.finding_service import FindingService
from app.services.recheck_service import RecheckService

@pytest.fixture(autouse=True)
def clean_postgres(db_session):
    """Truncate tables before each test to guarantee complete test isolation."""
    tables = [
        "change_evidence", "change_check_results", "findings",
        "remediation_tasks", "change_deployments", "change_tests",
        "change_approvals", "change_authorizations", "change_relationships",
        "changes", "users", "identity_links", "environments",
        "applications", "repositories", "audit_logs",
        "compliance_checks", "controls", "frameworks"
    ]
    for t in tables:
        db_session.execute(text(f"TRUNCATE TABLE {t} CASCADE;"))
    db_session.commit()

def seed_checks_and_controls(db_session):
    fw = db_session.query(orm.FrameworkORM).filter_by(framework_id="SOC2").first()
    if not fw:
        db_session.add(orm.FrameworkORM(
            framework_id="SOC2", name="SOC 2", description="Compliance Framework", status="ACTIVE"
        ))
        db_session.commit()

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    path = os.path.join(base_dir, "app", "domain", "checks", "library.json")
    with open(path, "r") as f:
        checks = json.load(f)
        for c in checks:
            num = int(c["check_id"].split("-")[1])
            ctrl_id = f"CM-CONTROL-{num:02d}"
            if num > 11:
                ctrl_id = "CM-CONTROL-01"
            
            ctrl = db_session.query(orm.ControlORM).filter_by(control_id=ctrl_id).first()
            if not ctrl:
                db_session.add(orm.ControlORM(
                    control_id=ctrl_id, framework_id="SOC2", criterion="CC8.1",
                    name=f"Control {ctrl_id}", objective="Objective", description="Desc",
                    lifecycle_stage="Authorization", status="ACTIVE"
                ))
                db_session.commit()

            chk = db_session.query(orm.ComplianceCheckORM).filter_by(check_id=c["check_id"]).first()
            if not chk:
                db_session.add(orm.ComplianceCheckORM(
                    check_id=c["check_id"], control_id=ctrl_id, name=c["name"], description=c["description"],
                    category=c["category"], severity=c["severity"], lifecycle_stage="Testing",
                    required_data=c["required_fields"], evaluation_logic=c["logic"],
                    evidence_requirements=c.get("evidence_requirements", []),
                    result_types=["PASS", "FAIL", "INSUFFICIENT_DATA"], status="ACTIVE",
                    applicability=c.get("applicability", {}).get("result")
                ))
        db_session.commit()

def setup_identities(db_session, tenant_id: str):
    NormalizationService(db_session)._ensure_baseline_entities(tenant_id)
    users = [
        (f"usr-{tenant_id}-alice", "Alice", f"{tenant_id}-alice@acme.com"),
        (f"usr-{tenant_id}-bob", "Bob", f"{tenant_id}-bob@acme.com")
    ]
    for uid, name, email in users:
        u = db_session.query(orm.UserORM).filter_by(internal_user_id=uid, tenant_id=tenant_id).first()
        if not u:
            db_session.add(orm.UserORM(internal_user_id=uid, tenant_id=tenant_id, name=name, email=email, role="Developer"))
    
    links = [
        (f"usr-{tenant_id}-alice", "alice-git"),
        (f"usr-{tenant_id}-bob", "bob-git")
    ]
    for uid, handle in links:
        lnk = db_session.query(orm.IdentityLinkORM).filter_by(internal_user_id=uid, tenant_id=tenant_id, source="github").first()
        if not lnk:
            db_session.add(orm.IdentityLinkORM(
                internal_user_id=uid, tenant_id=tenant_id, source="github",
                external_user_id=f"ext-{handle}", external_username=handle
            ))
    db_session.commit()

def test_scenario_a_valid_evidence(db_session):
    """SCENARIO A: Valid harvested evidence leads to compliance check PASS."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-a"
    setup_identities(db_session, tenant_id)

    # 1. Setup Change Request
    change = ChangeORM(
        change_id="chg-a", tenant_id=tenant_id, external_id="101", source="jira",
        title="Change A", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_id}-alice",
        owner_id=f"usr-{tenant_id}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()

    # 2. Add Valid, Correctly Correlated SDLC Evidence
    now = datetime.now(UTC).replace(tzinfo=None)
    test = TestORM(
        test_id="test-a", tenant_id=tenant_id, change_id="chg-a", source="github_actions",
        pipeline_id="pipe-a", commit_id="sha-a", test_type="integration",
        status=ORMTestStatus.PASS, started_at=now - timedelta(minutes=10),
        completed_at=now - timedelta(minutes=5)
    )
    deploy = DeploymentORM(
        deployment_id="dep-a", tenant_id=tenant_id, change_id="chg-a",
        application_id="app-default", environment_id="env-prod", repository_id="repo-default",
        version="1.0.0", commit_id="sha-a", deployed_by=f"usr-{tenant_id}-alice",
        deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(test)
    db_session.add(deploy)
    db_session.commit()

    # 3. Evaluate Check
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-a", "CM-002")

    assert res.result == ORMCheckResultType.PASS
    assert len(res.evidences) >= 2
    # Verify collected and validated statuses
    for ev in res.evidences:
        assert ev.status == "VALIDATED"
        assert ev.freshness_status == "CURRENT"
        assert ev.integrity_status != "INTEGRITY_FAILURE"

def test_scenario_b_missing_evidence(db_session):
    """SCENARIO B: Missing required evidence triggers INSUFFICIENT_DATA compliance result."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-b"
    setup_identities(db_session, tenant_id)

    change = ChangeORM(
        change_id="chg-b", tenant_id=tenant_id, external_id="102", source="jira",
        title="Change B", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_id}-alice",
        owner_id=f"usr-{tenant_id}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()

    # Evaluation with NO testing evidence
    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-b", "CM-002")

    assert res.result == ORMCheckResultType.INSUFFICIENT_DATA
    assert "missing_evidence_type" in res.evaluation_inputs
    assert res.details["missing_fields"] == ["evidence:TEST_LOG"]

def test_scenario_c_invalid_evidence(db_session):
    """SCENARIO C: Invalid evidence prevents a PASS result and yields INSUFFICIENT_DATA."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-c"
    setup_identities(db_session, tenant_id)

    change = ChangeORM(
        change_id="chg-c", tenant_id=tenant_id, external_id="103", source="jira",
        title="Change C", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_id}-alice",
        owner_id=f"usr-{tenant_id}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()

    # Add Test record
    test = TestORM(
        test_id="test-c", tenant_id=tenant_id, change_id="chg-c", source="github_actions",
        pipeline_id="pipe-c", commit_id="sha-c", test_type="integration",
        status=ORMTestStatus.PASS, started_at=datetime.now(UTC).replace(tzinfo=None)
    )
    db_session.add(test)
    db_session.commit()

    # Harvest evidence
    association_service = EvidenceAssociationService(db_session)
    harvested = association_service.harvest_change_evidence(tenant_id, "chg-c")
    
    # Manually invalidate evidence record
    for ev in harvested:
        if ev.evidence_type == "TEST_LOG":
            ev.status = "INVALID"
    db_session.commit()

    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-c", "CM-002")

    assert res.result == ORMCheckResultType.INSUFFICIENT_DATA

def test_scenario_d_evidence_integrity_failure(db_session):
    """SCENARIO D: Modifying database rows directly triggers INTEGRITY_FAILURE status."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-d"
    setup_identities(db_session, tenant_id)

    change = ChangeORM(
        change_id="chg-d", tenant_id=tenant_id, external_id="104", source="jira",
        title="Change D", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_id}-alice",
        owner_id=f"usr-{tenant_id}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()

    approval = ApprovalORM(
        approval_id="appr-d", tenant_id=tenant_id, change_id="chg-d",
        approver_id=f"usr-{tenant_id}-alice", role="Security", decision="APPROVED",
        source="github"
    )
    db_session.add(approval)
    db_session.commit()

    association_service = EvidenceAssociationService(db_session)
    harvested = association_service.harvest_change_evidence(tenant_id, "chg-d")

    # Manually modify Approval column values directly in the database to break hash match
    approval.decision = "REJECTED"
    db_session.commit()

    # Validate evidence
    validation_service = EvidenceValidationService(db_session)
    for ev in harvested:
        if ev.evidence_type == "APPROVAL_RECORD":
            val_res = validation_service.validate_evidence(ev)
            assert val_res["valid"] is False
            assert ev.integrity_status == "INTEGRITY_FAILURE"

    # Verify audit event for integrity failure was recorded
    audit = db_session.query(AuditLogORM).filter_by(
        tenant_id=tenant_id,
        action="evidence_integrity_failure"
    ).first()
    assert audit is not None

def test_scenario_e_f_freshness_fresh_and_stale(db_session):
    """SCENARIOS E/F: Evidence commit SHA matches active state (CURRENT) or drifts (STALE)."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-e"
    setup_identities(db_session, tenant_id)

    change = ChangeORM(
        change_id="chg-e", tenant_id=tenant_id, external_id="105", source="jira",
        title="Change E", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_id}-alice",
        owner_id=f"usr-{tenant_id}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()

    # Add Test record for sha-old
    now = datetime.now(UTC).replace(tzinfo=None)
    test_old = TestORM(
        test_id="test-e-old", tenant_id=tenant_id, change_id="chg-e", source="github_actions",
        pipeline_id="pipe-e", commit_id="sha-old", test_type="integration",
        status=ORMTestStatus.PASS, started_at=now - timedelta(minutes=10),
        completed_at=now - timedelta(minutes=9)
    )
    db_session.add(test_old)
    db_session.commit()

    association_service = EvidenceAssociationService(db_session)
    validation_service = EvidenceValidationService(db_session)

    # Harvest and validate
    harvested = association_service.harvest_change_evidence(tenant_id, "chg-e")
    for ev in harvested:
        validation_service.validate_evidence(ev)
        if ev.evidence_type == "TEST_LOG":
            assert ev.freshness_status == "CURRENT"

    # Drift commit SHA by introducing a new test record with newer timestamp
    test_new = TestORM(
        test_id="test-e-new", tenant_id=tenant_id, change_id="chg-e", source="github_actions",
        pipeline_id="pipe-e", commit_id="sha-new", test_type="integration",
        status=ORMTestStatus.PASS, started_at=now, completed_at=now + timedelta(minutes=1)
    )
    db_session.add(test_new)
    db_session.commit()

    # Re-harvest and validate
    harvested2 = association_service.harvest_change_evidence(tenant_id, "chg-e")
    for ev in harvested2:
        validation_service.validate_evidence(ev)
        if ev.source_record_id == "test-e-old":
            # Verification: old commit evidence is now STALE!
            assert ev.freshness_status == "STALE"
            assert ev.status == "STALE"

def test_scenario_h_duplicate_evidence_idempotency(db_session):
    """SCENARIO H: Multiple harvest scans do not create duplicate evidence records."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-h"
    setup_identities(db_session, tenant_id)

    change = ChangeORM(
        change_id="chg-h", tenant_id=tenant_id, external_id="108", source="jira",
        title="Change H", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_id}-alice",
        owner_id=f"usr-{tenant_id}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()

    association_service = EvidenceAssociationService(db_session)
    
    # Invoke harvest twice
    association_service.harvest_change_evidence(tenant_id, "chg-h")
    association_service.harvest_change_evidence(tenant_id, "chg-h")

    count = db_session.query(EvidenceMetadataORM).filter_by(
        tenant_id=tenant_id,
        change_id="chg-h",
        evidence_type="DOCUMENTATION_METADATA"
    ).count()

    assert count == 1

def test_scenario_i_finding_evidence(db_session):
    """SCENARIO I: Failed check result links evidence references directly into Findings."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-i"
    setup_identities(db_session, tenant_id)

    change = ChangeORM(
        change_id="chg-i", tenant_id=tenant_id, external_id="109", source="jira",
        title="Change I", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_id}-alice",
        owner_id=f"usr-{tenant_id}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()

    # Fail test record to trigger FAIL result
    test = TestORM(
        test_id="test-i", tenant_id=tenant_id, change_id="chg-i", source="github_actions",
        pipeline_id="pipe-i", commit_id="sha-i", test_type="integration",
        status=ORMTestStatus.FAIL, started_at=datetime.now(UTC).replace(tzinfo=None)
    )
    deploy = DeploymentORM(
        deployment_id="dep-i", tenant_id=tenant_id, change_id="chg-i",
        application_id="app-default", environment_id="env-prod", repository_id="repo-default",
        version="1.0.0", commit_id="sha-i", deployed_by=f"usr-{tenant_id}-alice",
        deployed_at=datetime.now(UTC).replace(tzinfo=None), status="SUCCESS", source="github"
    )
    db_session.add_all([test, deploy])
    db_session.commit()

    evaluator = EvaluationService(db_session)
    res = evaluator.evaluate_change(tenant_id, "chg-i", "CM-002")
    assert res.result == ORMCheckResultType.FAIL

    finder = FindingService(db_session)
    finding = finder.process_check_result(res)

    assert finding is not None
    assert finding.status == "OPEN"
    assert res.result_id in finding.check_result_id
    assert "test-i" in finding.description
    
    # Assert that evidence reference was propagated
    test_ev = db_session.query(EvidenceMetadataORM).filter_by(
        tenant_id=tenant_id,
        source_record_id="test-i"
    ).first()
    assert test_ev is not None
    assert test_ev.evidence_id in finding.evidence_ids
    assert test_ev.finding_id == finding.finding_id

def test_scenario_j_remediation_resolution_evidence(db_session):
    """SCENARIO J: Verification of resolved finding preserves failure evidence and appends resolution evidence."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-j"
    setup_identities(db_session, tenant_id)

    change = ChangeORM(
        change_id="chg-j", tenant_id=tenant_id, external_id="110", source="jira",
        title="Change J", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_id}-alice",
        owner_id=f"usr-{tenant_id}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()

    # 1. Failure state
    now = datetime.now(UTC).replace(tzinfo=None)
    test_fail = TestORM(
        test_id="test-j-fail", tenant_id=tenant_id, change_id="chg-j", source="github_actions",
        pipeline_id="pipe-j", commit_id="sha-fail", test_type="integration",
        status=ORMTestStatus.FAIL, started_at=now - timedelta(minutes=10)
    )
    deploy_fail = DeploymentORM(
        deployment_id="dep-j-fail", tenant_id=tenant_id, change_id="chg-j",
        application_id="app-default", environment_id="env-prod", repository_id="repo-default",
        version="1.0.0", commit_id="sha-fail", deployed_by=f"usr-{tenant_id}-alice",
        deployed_at=now - timedelta(minutes=8), status="SUCCESS", source="github"
    )
    db_session.add_all([test_fail, deploy_fail])
    db_session.commit()

    evaluator = EvaluationService(db_session)
    res_fail = evaluator.evaluate_change(tenant_id, "chg-j", "CM-002")
    assert res_fail.result == ORMCheckResultType.FAIL

    finder = FindingService(db_session)
    finding = finder.process_check_result(res_fail)
    assert finding.status == "OPEN"
    assert "test-j-fail" in finding.description

    # 2. Remediation occurs: new passing test log is recorded for newer state
    test_pass = TestORM(
        test_id="test-j-pass", tenant_id=tenant_id, change_id="chg-j", source="github_actions",
        pipeline_id="pipe-j", commit_id="sha-pass", test_type="integration",
        status=ORMTestStatus.PASS, started_at=now
    )
    db_session.add(test_pass)
    # Ensure deployment exists to prevent CM-002 failure due to missing deployment
    deploy = DeploymentORM(
        deployment_id="dep-j", tenant_id=tenant_id, change_id="chg-j",
        application_id="app-default", environment_id="env-prod", repository_id="repo-default",
        version="1.0.0", commit_id="sha-pass", deployed_by=f"usr-{tenant_id}-alice",
        deployed_at=now + timedelta(minutes=2), status="SUCCESS", source="github"
    )
    db_session.add(deploy)
    db_session.commit()

    # Recheck finding
    rechecker = RecheckService(db_session)
    recheck_res = rechecker.recheck_finding(tenant_id, finding.finding_id)

    assert recheck_res["finding_status"] == "RESOLVED"
    assert finding.status == "RESOLVED"

    # Both failure evidence and resolution evidence MUST be linked in evidence_ids
    fail_ev = db_session.query(EvidenceMetadataORM).filter_by(source_record_id="test-j-fail").first()
    pass_ev = db_session.query(EvidenceMetadataORM).filter_by(source_record_id="test-j-pass").first()

    assert fail_ev.evidence_id in finding.evidence_ids
    assert pass_ev.evidence_id in finding.evidence_ids

def test_scenario_k_evidence_conflict(db_session):
    """SCENARIO K: Conflicting evidence records for the same commit trigger EVIDENCE_CONFLICT."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-k"
    setup_identities(db_session, tenant_id)

    change = ChangeORM(
        change_id="chg-k", tenant_id=tenant_id, external_id="111", source="jira",
        title="Change K", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_id}-alice",
        owner_id=f"usr-{tenant_id}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()

    # Insert two conflicting tests for the same commit
    t1 = TestORM(
        test_id="test-k-1", tenant_id=tenant_id, change_id="chg-k", source="github_actions",
        pipeline_id="pipe-k", commit_id="sha-k", test_type="integration",
        status=ORMTestStatus.PASS, started_at=datetime.now(UTC).replace(tzinfo=None)
    )
    t2 = TestORM(
        test_id="test-k-2", tenant_id=tenant_id, change_id="chg-k", source="github_actions",
        pipeline_id="pipe-k", commit_id="sha-k", test_type="integration",
        status=ORMTestStatus.FAIL, started_at=datetime.now(UTC).replace(tzinfo=None)
    )
    db_session.add(t1)
    db_session.add(t2)
    db_session.commit()

    # Harvest and build evidence package
    association = EvidenceAssociationService(db_session)
    association.harvest_change_evidence(tenant_id, "chg-k")

    package_service = EvidencePackageService(db_session)
    pkg = package_service.generate_evidence_package(tenant_id, "chg-k")

    assert pkg["completeness"] == "BROKEN"
    assert any("Contradictory test results" in c for c in pkg["conflicts"])

    # Verify audit event logged
    audit = db_session.query(AuditLogORM).filter_by(
        tenant_id=tenant_id,
        action="evidence_conflict_detected"
    ).first()
    assert audit is not None

def test_scenario_l_tenant_isolation(db_session):
    """SCENARIO L: Tenant A evidence package and trace endpoints remain inaccessible to Tenant B."""
    seed_checks_and_controls(db_session)
    tenant_a = "tenant-l-a"
    tenant_b = "tenant-l-b"
    setup_identities(db_session, tenant_a)
    setup_identities(db_session, tenant_b)

    # Seeding Tenant A Change
    change_a = ChangeORM(
        change_id="chg-l-a", tenant_id=tenant_a, external_id="112", source="jira",
        title="Change L A", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_a}-alice",
        owner_id=f"usr-{tenant_a}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change_a)
    db_session.commit()

    # Harvest
    association = EvidenceAssociationService(db_session)
    association.harvest_change_evidence(tenant_a, "chg-l-a")

    package_service = EvidencePackageService(db_session)
    
    # Assert Tenant B gets an error or empty result querying Tenant A package
    pkg_b = package_service.generate_evidence_package(tenant_b, "chg-l-a")
    assert pkg_b["completeness"] == "BROKEN"
    assert "not found" in pkg_b["error"]

def test_scenario_o_p_q_evidence_packages(db_session):
    """SCENARIOS O/P/Q: Verifies completeness status: COMPLETE, PARTIAL, and BROKEN."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-opq"
    setup_identities(db_session, tenant_id)

    # 1. Partial: No SDLC evidence yet, check results not fully evaluated
    change = ChangeORM(
        change_id="chg-opq", tenant_id=tenant_id, external_id="115", source="jira",
        title="Change OPQ", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_id}-alice",
        owner_id=f"usr-{tenant_id}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()

    package_service = EvidencePackageService(db_session)
    pkg_partial = package_service.generate_evidence_package(tenant_id, "chg-opq")
    assert pkg_partial["completeness"] == "PARTIAL"

    # 2. Broken: Failing check or missing required evidence
    evaluator = EvaluationService(db_session)
    evaluator.evaluate_change(tenant_id, "chg-opq", "CM-002") # Fails on missing required data
    pkg_broken = package_service.generate_evidence_package(tenant_id, "chg-opq")
    assert pkg_broken["completeness"] == "BROKEN"

    # 3. Complete: Adding valid required evidence and passing
    now = datetime.now(UTC).replace(tzinfo=None)
    test = TestORM(
        test_id="test-opq", tenant_id=tenant_id, change_id="chg-opq", source="github_actions",
        pipeline_id="pipe-opq", commit_id="sha-opq", test_type="integration",
        status=ORMTestStatus.PASS, started_at=now - timedelta(minutes=10),
        completed_at=now - timedelta(minutes=5)
    )
    deploy = DeploymentORM(
        deployment_id="dep-opq", tenant_id=tenant_id, change_id="chg-opq",
        application_id="app-default", environment_id="env-prod", repository_id="repo-default",
        version="1.0.0", commit_id="sha-opq", deployed_by=f"usr-{tenant_id}-alice",
        deployed_at=now, status="SUCCESS", source="github"
    )
    db_session.add(test)
    db_session.add(deploy)
    db_session.commit()

    # Clear old results to prevent failures from lingering
    db_session.execute(text("TRUNCATE TABLE change_check_results CASCADE;"))
    db_session.commit()

    evaluator.evaluate_change(tenant_id, "chg-opq", "CM-002")
    pkg_complete = package_service.generate_evidence_package(tenant_id, "chg-opq")
    assert pkg_complete["completeness"] == "COMPLETE"

def test_scenario_r_historical_compliance_reconstruction(db_session):
    """SCENARIO R: Auditor can reconstruct previous compliance states after state changes."""
    seed_checks_and_controls(db_session)
    tenant_id = "tenant-r"
    setup_identities(db_session, tenant_id)

    change = ChangeORM(
        change_id="chg-r", tenant_id=tenant_id, external_id="116", source="jira",
        title="Change R", change_type=ORMChangeType.NORMAL, requester_id=f"usr-{tenant_id}-alice",
        owner_id=f"usr-{tenant_id}-alice", environment_id="env-prod", application_id="app-default",
        status="OPEN"
    )
    db_session.add(change)
    db_session.commit()

    # At T1: PASS state
    now = datetime.now(UTC).replace(tzinfo=None)
    test_t1 = TestORM(
        test_id="test-r-t1", tenant_id=tenant_id, change_id="chg-r", source="github_actions",
        pipeline_id="pipe-r", commit_id="sha-t1", test_type="integration",
        status=ORMTestStatus.PASS, started_at=now - timedelta(hours=1),
        completed_at=now - timedelta(minutes=50)
    )
    deploy_t1 = DeploymentORM(
        deployment_id="dep-r-t1", tenant_id=tenant_id, change_id="chg-r",
        application_id="app-default", environment_id="env-prod", repository_id="repo-default",
        version="1.0.0", commit_id="sha-t1", deployed_by=f"usr-{tenant_id}-alice",
        deployed_at=now - timedelta(minutes=45), status="SUCCESS", source="github"
    )
    db_session.add(test_t1)
    db_session.add(deploy_t1)
    db_session.commit()

    evaluator = EvaluationService(db_session)
    res_t1 = evaluator.evaluate_change(tenant_id, "chg-r", "CM-002")
    assert res_t1.result == ORMCheckResultType.PASS

    # Record the result ID
    result_id_t1 = res_t1.result_id

    # At T2: State changes to FAIL (commit drifts and fails)
    test_t2 = TestORM(
        test_id="test-r-t2", tenant_id=tenant_id, change_id="chg-r", source="github_actions",
        pipeline_id="pipe-r", commit_id="sha-t2", test_type="integration",
        status=ORMTestStatus.FAIL, started_at=now
    )
    db_session.add(test_t2)
    db_session.commit()

    res_t2 = evaluator.evaluate_change(tenant_id, "chg-r", "CM-002")
    assert res_t2.result == ORMCheckResultType.FAIL

    # Auditor retrieves T1 result directly by ID
    historical_res = db_session.query(CheckResultORM).filter_by(result_id=result_id_t1).first()
    assert historical_res is not None
    assert historical_res.result == ORMCheckResultType.PASS
    
    # Verify that the evidences linked to T1 check are correct (commit sha-t1)
    linked_ev_ids = [ev.source_record_id for ev in historical_res.evidences]
    assert "test-r-t1" in linked_ev_ids
    assert "test-r-t2" not in linked_ev_ids
