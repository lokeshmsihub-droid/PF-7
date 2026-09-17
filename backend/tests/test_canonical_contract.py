import pytest
from datetime import datetime
from pydantic import ValidationError
import app.models.orm
from app.domain.canonical.models import (
    CanonicalChange, CanonicalChangeIdentity, CanonicalChangeBasicInfo,
    CanonicalChangeRequest, CanonicalChangeAuthorization, CanonicalChangeDevelopment,
    CanonicalChangeTesting, CanonicalChangeApproval, CanonicalChangeDeployment,
    CanonicalChangeRollback, CanonicalChangeEmergency, DataAvailability,
    CanonicalEvent, IdentityResolutionStatus
)

def make_valid_change_data() -> dict:
    """Helper to return a complete, valid dictionary mapping for CanonicalChange."""
    return {
        "identity": {
            "change_id": "chg-001",
            "tenant_id": "tenant-001",
            "source": "github",
            "external_id": "pr-42"
        },
        "basic_info": {
            "title": "Upgrade DB Schema",
            "description": "Upgrading tables to support multi-tenancy",
            "change_type": "NORMAL",
            "status": "APPROVED",
            "risk_level": "medium",
            "environment": "env-prod"
        },
        "request": {
            "requester_id": "usr-requester",
            "owner_id": "usr-owner",
            "created_at": datetime.now(),
            "requested_at": datetime.now()
        },
        "authorization": {
            "required": True,
            "authorized": True,
            "authorized_by": "usr-approver",
            "authorized_at": datetime.now(),
            "reference": "JIRA-99"
        },
        "development": {
            "repository": "enterprise-compliance",
            "branch": "main",
            "pull_request_id": "42",
            "commit_id": "abc123sha",
            "changed_components": ["backend/db"]
        },
        "testing": {
            "required": True,
            "test_id": "run-99",
            "test_type": "UNIT",
            "test_status": "PASS",
            "tested_at": datetime.now(),
            "evidence_reference": "https://ci/logs"
        },
        "approval": {
            "required": True,
            "approved": True,
            "approver_id": "usr-approver",
            "approved_at": datetime.now(),
            "reference": "CAB-decision"
        },
        "deployment": {
            "deployment_id": "dep-456",
            "environment": "env-prod",
            "deployed_by": "usr-deployer",
            "deployed_at": datetime.now(),
            "deployment_status": "SUCCESS",
            "version": "1.2.0"
        },
        "rollback": {
            "rollback_plan": "Revert commit and deploy previous version tag",
            "rollback_tested": True,
            "rollback_reference": "rollback-playbook"
        },
        "emergency": {
            "is_emergency": False,
            "reason": DataAvailability.UNAVAILABLE,
            "emergency_approved_by": DataAvailability.UNAVAILABLE,
            "retro_approval": DataAvailability.UNAVAILABLE
        },
        "evidence_ids": ["ev-1", "ev-2"]
    }

def test_valid_change_contract():
    data = make_valid_change_data()
    change = CanonicalChange(**data)
    assert change.identity.change_id == "chg-001"
    assert change.identity.tenant_id == "tenant-001"
    assert change.basic_info.change_type == "NORMAL"
    assert change.authorization.authorized is True
    assert change.rollback.rollback_tested is True

def test_missing_change_id():
    data = make_valid_change_data()
    del data["identity"]["change_id"]
    with pytest.raises(ValidationError):
        CanonicalChange(**data)

def test_missing_tenant_id():
    data = make_valid_change_data()
    del data["identity"]["tenant_id"]
    with pytest.raises(ValidationError):
        CanonicalChange(**data)

def test_invalid_change_type():
    # Test type check failure (must be string/enum)
    data = make_valid_change_data()
    data["basic_info"]["change_type"] = 12345
    with pytest.raises(ValidationError):
        # BasicInfo expects str type
        # In Pydantic 12345 gets coerced to "12345", so we pass an incompatible object or None
        data["basic_info"]["change_type"] = {"invalid": "object"}
        CanonicalChange(**data)

def test_invalid_status():
    data = make_valid_change_data()
    data["basic_info"]["status"] = {"invalid": "object"}
    with pytest.raises(ValidationError):
        CanonicalChange(**data)

def test_invalid_timestamp():
    data = make_valid_change_data()
    data["request"]["created_at"] = "not-a-timestamp"
    with pytest.raises(ValidationError):
        CanonicalChange(**data)

def test_authorization_data_availability_unions():
    # Test that fields allow DataAvailability enum values
    data = make_valid_change_data()
    data["authorization"] = {
        "required": DataAvailability.UNKNOWN,
        "authorized": DataAvailability.UNKNOWN,
        "authorized_by": DataAvailability.UNKNOWN,
        "authorized_at": DataAvailability.UNKNOWN,
        "reference": DataAvailability.UNKNOWN
    }
    change = CanonicalChange(**data)
    assert change.authorization.required == DataAvailability.UNKNOWN
    assert change.authorization.authorized == DataAvailability.UNKNOWN

def test_testing_data_availability_unions():
    data = make_valid_change_data()
    data["testing"] = {
        "required": DataAvailability.UNAVAILABLE,
        "test_id": DataAvailability.UNAVAILABLE,
        "test_type": DataAvailability.UNAVAILABLE,
        "test_status": DataAvailability.UNAVAILABLE,
        "tested_at": DataAvailability.UNAVAILABLE,
        "evidence_reference": DataAvailability.UNAVAILABLE
    }
    change = CanonicalChange(**data)
    assert change.testing.required == DataAvailability.UNAVAILABLE
    assert change.testing.test_id == DataAvailability.UNAVAILABLE

def test_approval_data_availability_unions():
    data = make_valid_change_data()
    data["approval"] = {
        "required": DataAvailability.UNKNOWN,
        "approved": DataAvailability.UNKNOWN,
        "approver_id": DataAvailability.UNKNOWN,
        "approved_at": DataAvailability.UNKNOWN,
        "reference": DataAvailability.UNKNOWN
    }
    change = CanonicalChange(**data)
    assert change.approval.approved == DataAvailability.UNKNOWN

def test_deployment_data_availability_unions():
    data = make_valid_change_data()
    data["deployment"] = {
        "deployment_id": DataAvailability.UNKNOWN,
        "environment": DataAvailability.UNKNOWN,
        "deployed_by": DataAvailability.UNKNOWN,
        "deployed_at": DataAvailability.UNKNOWN,
        "deployment_status": DataAvailability.UNKNOWN,
        "version": DataAvailability.UNKNOWN
    }
    change = CanonicalChange(**data)
    assert change.deployment.deployment_id == DataAvailability.UNKNOWN

def test_emergency_change_parsing():
    data = make_valid_change_data()
    data["emergency"] = {
        "is_emergency": True,
        "reason": "Production auth failure bypass required",
        "emergency_approved_by": "usr-cto",
        "retro_approval": True
    }
    change = CanonicalChange(**data)
    assert change.emergency.is_emergency is True
    assert change.emergency.emergency_approved_by == "usr-cto"
    assert change.emergency.retro_approval is True

def test_rollback_data_parsing():
    data = make_valid_change_data()
    data["rollback"] = {
        "rollback_plan": "Restore snapshot",
        "rollback_tested": False,
        "rollback_reference": "ref-snap-1"
    }
    change = CanonicalChange(**data)
    assert change.rollback.rollback_tested is False
    assert change.rollback.rollback_plan == "Restore snapshot"

def test_evidence_reference_parsing():
    data = make_valid_change_data()
    data["evidence_ids"] = ["ev-42", "ev-43", "ev-44"]
    change = CanonicalChange(**data)
    assert change.evidence_ids == ["ev-42", "ev-43", "ev-44"]

def test_identity_status_enum():
    assert IdentityResolutionStatus.RESOLVED.value == "RESOLVED"
    assert IdentityResolutionStatus.UNRESOLVED.value == "UNRESOLVED"
    assert IdentityResolutionStatus.AMBIGUOUS.value == "AMBIGUOUS"

def test_canonical_event_valid():
    event_data = {
        "event_id": "evt-001",
        "tenant_id": "tenant-001",
        "source": "github",
        "event_type": "pull_request",
        "external_event_id": "delivery-123",
        "entity_type": "change",
        "entity_id": "chg-001",
        "actor_id": "usr-001",
        "timestamp": datetime.now()
    }
    event = CanonicalEvent(**event_data)
    assert event.event_id == "evt-001"
    assert event.tenant_id == "tenant-001"

def test_tenant_id_mandatory_throughout():
    # 1. CanonicalEvent missing tenant_id
    with pytest.raises(ValidationError):
        CanonicalEvent(
            event_id="evt-001",
            source="github",
            event_type="pr",
            entity_type="change",
            entity_id="chg-1",
            actor_id="usr-1",
            timestamp=datetime.now()
        )
        
    # 2. CanonicalChangeIdentity missing tenant_id
    with pytest.raises(ValidationError):
        CanonicalChangeIdentity(
            change_id="chg-1",
            source="github",
            external_id="1"
        )


def test_canonical_mapper_github_mapping(db_session):
    # Seed a ChangeORM and check its mapping
    from app.models.orm import ChangeORM, ORMChangeType, TestORM, ORMTestStatus, ApprovalORM, DeploymentORM, ChangeRollbackORM, EvidenceMetadataORM
    from app.normalization.canonical_adapter import CanonicalMapper
    
    tenant_id = "tenant-mapping-test"
    change_id = "chg-map-123"
    
    from app.models.orm import EnvironmentORM, ApplicationORM, UserORM
    env = EnvironmentORM(environment_id="env-prod-map", tenant_id=tenant_id, name="Production", type="PRODUCTION")
    app_val = ApplicationORM(application_id="app-default-map", tenant_id=tenant_id, name="Default App", owner="owner", environment_id="env-prod-map")
    user = UserORM(internal_user_id="usr-bob-map", tenant_id=tenant_id, name="Bob", email="bob@company.com", role="developer")
    db_session.add(env)
    db_session.commit()
    db_session.add(app_val)
    db_session.add(user)
    db_session.commit()
    
    db_change = ChangeORM(
        change_id=change_id,
        tenant_id=tenant_id,
        external_id="42",
        source="github",
        title="Map pull request test",
        description="Verify canonical fields mapping works",
        change_type=ORMChangeType.NORMAL,
        requester_id="usr-bob-map",
        owner_id="usr-bob-map",
        risk_level="high",
        environment_id="env-prod-map",
        application_id="app-default-map",
        status="OPEN",
        is_emergency=False
    )
    db_session.add(db_change)
    db_session.commit()
    
    # Add rollback
    rollback = ChangeRollbackORM(
        rollback_id="roll-1",
        tenant_id=tenant_id,
        change_id=change_id,
        rollback_plan="Revert PR",
        rollback_tested=True,
        rollback_reference="https://revert"
    )
    db_session.add(rollback)
    
    # Add test
    test_run = TestORM(
        test_id="test-run-1",
        tenant_id=tenant_id,
        change_id=change_id,
        source="github_actions",
        pipeline_id="999",
        commit_id="commit-sha-123",
        test_type="SECURITY",
        status=ORMTestStatus.PASS
    )
    db_session.add(test_run)
    db_session.commit()
    
    # Map to canonical change
    canonical = CanonicalMapper.to_canonical_change(db_session, db_change)
    
    assert canonical.identity.change_id == change_id
    assert canonical.identity.tenant_id == tenant_id
    assert canonical.basic_info.title == "Map pull request test"
    assert canonical.basic_info.environment == "env-prod-map"
    assert canonical.request.requester_id == "usr-bob-map"
    assert canonical.testing.test_id == "test-run-1"
    assert canonical.testing.test_status == "PASS"
    assert canonical.testing.evidence_reference == DataAvailability.UNAVAILABLE
    assert canonical.rollback.rollback_plan == "Revert PR"
    assert canonical.rollback.rollback_tested is True
    assert canonical.authorization.authorized == DataAvailability.UNKNOWN

