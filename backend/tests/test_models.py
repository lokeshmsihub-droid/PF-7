from datetime import datetime, timedelta
from app.models.orm import (
    UserORM, IdentityLinkORM, ChangeORM, AuthorizationORM, 
    ApprovalORM, TestORM, DeploymentORM, ControlORM, ComplianceCheckORM,
    EnvironmentORM, ApplicationORM, RepositoryORM, ChangeRelationshipORM,
    CheckResultORM, EntityType, RelationshipType,
    ORMChangeType, ORMTestStatus, ORMEnvType, ORMCheckResultType,
    EvidenceMetadataORM, AuditLogORM, FrameworkORM
)

def test_user_and_identity_link_relationships(db_session):
    # 1. Create a platform User
    user = UserORM(
        internal_user_id="usr-123",
        tenant_id="tenant-abc",
        name="Alice Compliance",
        email="alice@company.com",
        role="Security Engineer",
        status="ACTIVE"
    )
    db_session.add(user)
    db_session.commit()

    # 2. Link User to Github and Jira identities
    github_link = IdentityLinkORM(
        internal_user_id="usr-123",
        tenant_id="tenant-abc",
        source="github",
        external_user_id="git-999",
        external_username="alice-git",
        status="ACTIVE"
    )
    jira_link = IdentityLinkORM(
        internal_user_id="usr-123",
        tenant_id="tenant-abc",
        source="jira",
        external_user_id="jira-888",
        external_username="alice.compliance",
        status="ACTIVE"
    )
    db_session.add_all([github_link, jira_link])
    db_session.commit()

    # 3. Retrieve and assert relationships
    fetched_user = db_session.query(UserORM).filter_by(internal_user_id="usr-123").first()
    assert fetched_user is not None
    assert fetched_user.name == "Alice Compliance"
    assert len(fetched_user.identity_links) == 2
    sources = [link.source for link in fetched_user.identity_links]
    assert "github" in sources
    assert "jira" in sources


def test_change_and_related_entities(db_session):
    # 1. Create scoping entities
    env = EnvironmentORM(
        environment_id="env-prod",
        tenant_id="tenant-abc",
        name="Production Env",
        type=ORMEnvType.PRODUCTION,
        criticality="HIGH"
    )
    db_session.add(env)
    db_session.commit()

    app = ApplicationORM(
        application_id="app-auth",
        tenant_id="tenant-abc",
        name="Auth Service",
        owner="sec-ops@company.com",
        environment_id="env-prod",
        criticality="HIGH",
        status="ACTIVE"
    )
    repo = RepositoryORM(
        repository_id="repo-auth",
        external_id="gh-77665",
        name="auth-service-repo",
        provider="github",
        organization="enterprise-org",
        status="ACTIVE"
    )
    user_req = UserORM(
        internal_user_id="usr-requester",
        tenant_id="tenant-abc",
        name="Bob Requester",
        email="bob@company.com",
        role="Developer",
        status="ACTIVE"
    )
    user_appr = UserORM(
        internal_user_id="usr-approver",
        tenant_id="tenant-abc",
        name="Charlie Approver",
        email="charlie@company.com",
        role="QA lead",
        status="ACTIVE"
    )
    db_session.add_all([app, repo, user_req, user_appr])
    db_session.commit()

    # 2. Create a Change referencing canonical keys
    change = ChangeORM(
        change_id="chg-001",
        tenant_id="tenant-abc",
        external_id="JIRA-5566",
        source="jira",
        title="Deploy authentication service v2",
        description="Migrate auth session handler to redis",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-requester",
        owner_id="usr-requester",
        risk_level="HIGH",
        environment_id="env-prod",
        application_id="app-auth",
        status="APPROVED",
        planned_start=datetime.utcnow(),
        planned_end=datetime.utcnow() + timedelta(days=1)
    )
    db_session.add(change)
    db_session.commit()

    # 3. Add an Authorization
    auth = AuthorizationORM(
        authorization_id="auth-001",
        tenant_id="tenant-abc",
        change_id="chg-001",
        authorized_by="usr-approver",
        status="APPROVED",
        justification="Approved during planning meeting",
        source="jira"
    )
    # 4. Add an Approval
    approval = ApprovalORM(
        approval_id="appr-001",
        tenant_id="tenant-abc",
        change_id="chg-001",
        approver_id="usr-approver",
        role="CAB",
        decision="APPROVED",
        source="github_pr"
    )
    # 5. Add a Test Run
    test_run = TestORM(
        test_id="test-001",
        tenant_id="tenant-abc",
        change_id="chg-001",
        source="github_actions",
        pipeline_id="run-456",
        commit_id="sha-1a2b3c",
        test_type="INTEGRATION",
        status=ORMTestStatus.PASS
    )
    # 6. Add a Deployment linking repository and environment
    deploy = DeploymentORM(
        deployment_id="dep-001",
        tenant_id="tenant-abc",
        change_id="chg-001",
        application_id="app-auth",
        environment_id="env-prod",
        repository_id="repo-auth",
        version="v2.0.0",
        commit_id="sha-1a2b3c",
        deployed_by="usr-requester",
        status="SUCCESS",
        source="argo_cd"
    )

    db_session.add_all([auth, approval, test_run, deploy])
    db_session.commit()

    # 7. Query and check relationships
    fetched_change = db_session.query(ChangeORM).filter_by(change_id="chg-001").first()
    assert fetched_change is not None
    assert len(fetched_change.authorizations) == 1
    assert fetched_change.authorizations[0].justification == "Approved during planning meeting"
    assert fetched_change.authorizations[0].authorized_by == "usr-approver"
    
    assert len(fetched_change.approvals) == 1
    assert fetched_change.approvals[0].approver_id == "usr-approver"
    
    assert len(fetched_change.tests) == 1
    assert fetched_change.tests[0].status == ORMTestStatus.PASS
    
    assert len(fetched_change.deployments) == 1
    assert fetched_change.deployments[0].version == "v2.0.0"
    assert fetched_change.deployments[0].repository_id == "repo-auth"


def test_controlled_relationship_types(db_session):
    # Test change_relationships constraints
    rel = ChangeRelationshipORM(
        tenant_id="tenant-abc",
        source_id="chg-001",
        source_type=EntityType.CHANGE,
        target_id="test-001",
        target_type=EntityType.TEST,
        relationship_type=RelationshipType.TESTS
    )
    db_session.add(rel)
    db_session.commit()

    fetched = db_session.query(ChangeRelationshipORM).first()
    assert fetched is not None
    assert fetched.source_type == EntityType.CHANGE
    assert fetched.relationship_type == RelationshipType.TESTS


def test_multiple_evidences_per_check_result(db_session):
    # 1. Create a minimal Change
    user = UserORM(
        internal_user_id="usr-test",
        tenant_id="tenant-abc",
        name="Test",
        email="test@company.com",
        role="Dev",
        status="ACTIVE"
    )
    env = EnvironmentORM(
        environment_id="env-1",
        tenant_id="tenant-abc",
        name="Env 1",
        type=ORMEnvType.DEVELOPMENT,
        criticality="LOW"
    )
    app = ApplicationORM(
        application_id="app-1",
        tenant_id="tenant-abc",
        name="App 1",
        owner="owner",
        environment_id="env-1",
        status="ACTIVE"
    )
    change = ChangeORM(
        change_id="chg-val",
        tenant_id="tenant-abc",
        external_id="JIRA-12",
        source="jira",
        title="Change title",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-test",
        owner_id="usr-test",
        environment_id="env-1",
        application_id="app-1",
        status="OPEN"
    )
    db_session.add(user)
    db_session.add(env)
    db_session.commit()
    db_session.add(app)
    db_session.commit()
    db_session.add(change)
    db_session.commit()

    # 2. Create multiple Evidence records
    ev1 = EvidenceMetadataORM(
        evidence_id="ev-git",
        tenant_id="tenant-abc",
        change_id="chg-val",
        source="github",
        source_record_id="commit-1",
        evidence_type="COMMIT_LINK",
        hash="hash1",
        storage_reference="ref1"
    )
    ev2 = EvidenceMetadataORM(
        evidence_id="ev-qa",
        tenant_id="tenant-abc",
        change_id="chg-val",
        source="github_actions",
        source_record_id="run-2",
        evidence_type="TEST_REPORT",
        hash="hash2",
        storage_reference="ref2"
    )
    db_session.add_all([ev1, ev2])
    db_session.commit()

    # 3. Create a CheckResult linked to both evidences
    check = ComplianceCheckORM(
        check_id="CM-005",
        control_id="CM-CONTROL-03", # assuming seeded control exists or we FK to control_id directly
        name="Check Name",
        description="Desc",
        category="testing",
        lifecycle_stage="Testing",
        required_data={},
        evaluation_logic={},
        result_types=[],
        status="ACTIVE"
    )
    # Ensure ControlORM exists for FK constraints
    control = ControlORM(
        control_id="CM-CONTROL-03",
        framework_id="SOC2", # dynamically seed framework below
        criterion="CC8.1",
        name="Testing",
        objective="Verify testing",
        description="Verify testing desc",
        lifecycle_stage="Testing"
    )
    framework = FrameworkORM(framework_id="SOC2", name="SOC 2")
    db_session.add_all([framework, control, check])
    db_session.commit()

    res = CheckResultORM(
        result_id="res-1",
        tenant_id="tenant-abc",
        check_id="CM-005",
        change_id="chg-val",
        result=ORMCheckResultType.PASS,
        rule_version="1.0.0",
        evaluation_inputs={"test_status": "PASS"}
    )
    res.evidences.append(ev1)
    res.evidences.append(ev2)
    db_session.add(res)
    db_session.commit()

    # Assert relations
    fetched_res = db_session.query(CheckResultORM).filter_by(result_id="res-1").first()
    assert fetched_res is not None
    assert len(fetched_res.evidences) == 2
    ev_ids = [e.evidence_id for e in fetched_res.evidences]
    assert "ev-git" in ev_ids
    assert "ev-qa" in ev_ids


def test_audit_log_hash_chain_and_ordering(db_session):
    # Create two sequentially ordered audit logs
    log1 = AuditLogORM(
        tenant_id="tenant-abc",
        actor_id="usr-admin",
        actor_type="USER",
        action="CREATE_CHANGE",
        entity_type="CHANGE",
        entity_id="chg-1",
        event_id="evt-101",
        previous_hash=None,
        event_hash="hash-101",
        sequence_number=1
    )
    log2 = AuditLogORM(
        tenant_id="tenant-abc",
        actor_id="connector-jira",
        actor_type="CONNECTOR",
        action="SYNC_STATUS",
        entity_type="CHANGE",
        entity_id="chg-1",
        event_id="evt-102",
        previous_hash="hash-101",
        event_hash="hash-102",
        sequence_number=2
    )
    db_session.add_all([log1, log2])
    db_session.commit()

    logs = db_session.query(AuditLogORM).filter_by(tenant_id="tenant-abc").order_by(AuditLogORM.sequence_number).all()
    assert len(logs) == 2
    assert logs[0].actor_type == "USER"
    assert logs[1].actor_type == "CONNECTOR"
    assert logs[1].previous_hash == logs[0].event_hash

