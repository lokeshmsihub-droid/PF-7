import pytest
from app.services.correlation_service import CorrelationService
from app.models.orm import (
    UserORM, IdentityLinkORM, ChangeORM, TestORM, DeploymentORM, 
    ChangeRelationshipORM, EntityType, RelationshipType, ORMTestStatus
)
from datetime import datetime

def test_identity_resolution(db_session):
    tenant_id = "tenant-abc"
    # Seed identity link
    user = UserORM(
        internal_user_id="usr-alice-platform",
        tenant_id=tenant_id,
        name="Alice Tester",
        email="alice.tester@company.com",
        role="QAE",
        status="ACTIVE"
    )
    link = IdentityLinkORM(
        internal_user_id="usr-alice-platform",
        tenant_id=tenant_id,
        source="github",
        external_user_id="git-alice-id",
        external_username="alice-git",
        status="ACTIVE"
    )
    db_session.add_all([user, link])
    db_session.commit()

    service = CorrelationService(db_session)
    assert service.resolve_user_id(tenant_id, "alice-git") == "usr-alice-platform"
    assert service.resolve_user_id(tenant_id, "unknown-git") == "usr-unknown-git"


def test_change_correlation(db_session):
    tenant_id = "tenant-abc"
    service = CorrelationService(db_session)
    
    # Pre-populate lookup models
    from app.services.normalization_service import NormalizationService
    NormalizationService(db_session)._ensure_baseline_entities(tenant_id)

    # 1. Seed unlinked PR Change
    user = UserORM(
        internal_user_id="usr-bob",
        tenant_id=tenant_id,
        name="Bob",
        email="bob@company.com",
        role="Dev",
        status="ACTIVE"
    )
    change = ChangeORM(
        change_id="chg-pr-101",
        tenant_id=tenant_id,
        external_id="101",
        source="github",
        title="CM-005: Update token authentication",
        description="",
        change_type="NORMAL",
        requester_id="usr-bob",
        owner_id="usr-bob",
        risk_level="low",
        environment_id="env-prod",
        application_id="app-default",
        status="OPEN"
    )
    db_session.add(user)
    db_session.commit()
    db_session.add(change)
    db_session.commit()

    # 2. Seed unlinked Test run and Deployment
    test = TestORM(
        test_id="run-11",
        tenant_id=tenant_id,
        change_id=None,
        source="github_actions",
        pipeline_id="p-11",
        commit_id="sha-abc-123",
        test_type="INTEGRATION",
        status=ORMTestStatus.PASS
    )
    deploy = DeploymentORM(
        deployment_id="dep-22",
        tenant_id=tenant_id,
        change_id=None,
        application_id="app-default",
        environment_id="env-prod",
        repository_id="repo-default",
        version="v1.0",
        commit_id="sha-abc-123",
        deployed_by="usr-bob",
        status="SUCCESS",
        source="github"
    )
    db_session.add_all([test, deploy])
    db_session.commit()

    # 3. Run correlation
    result = service.correlate_sync_run_entities(tenant_id)
    assert result["tests_correlated"] == 1
    assert result["deployments_correlated"] == 1

    # 4. Verify entities are correlated and relationships created
    assert test.change_id == "chg-pr-101"
    assert deploy.change_id == "chg-pr-101"

    rel_test = db_session.query(ChangeRelationshipORM).filter_by(
        source_id="chg-pr-101",
        target_id="run-11",
        relationship_type=RelationshipType.TESTS
    ).first()
    assert rel_test is not None

    rel_dep = db_session.query(ChangeRelationshipORM).filter_by(
        source_id="chg-pr-101",
        target_id="dep-22",
        relationship_type=RelationshipType.ASSOCIATED_WITH
    ).first()
    assert rel_dep is not None
