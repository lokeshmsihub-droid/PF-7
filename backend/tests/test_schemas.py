import pytest
from datetime import datetime, timedelta
from pydantic import ValidationError
from app.domain.identity.models import User, IdentityLink
from app.domain.changes.models import (
    Change, ChangeType, Authorization, Approval, Test, TestStatus, Deployment
)
from app.domain.evidence.models import Evidence
from app.domain.raw.models import RawEvent
from app.domain.findings.models import Finding
from app.domain.exceptions.models import ExceptionModel

def test_user_schema_validation():
    # Valid user
    user_data = {
        "internal_user_id": "usr-1",
        "tenant_id": "tenant-xyz",
        "name": "Jane Doe",
        "email": "jane@example.com",
        "role": "Developer",
        "status": "ACTIVE"
    }
    user = User(**user_data)
    assert user.name == "Jane Doe"
    assert user.tenant_id == "tenant-xyz"

    # Invalid user (missing required field 'tenant_id')
    invalid_data = {
        "internal_user_id": "usr-1",
        "name": "Jane Doe",
        "email": "jane@example.com",
        "role": "Developer"
    }
    with pytest.raises(ValidationError):
        User(**invalid_data)


def test_change_schema_validation():
    # Valid change
    change_data = {
        "change_id": "chg-1",
        "tenant_id": "tenant-xyz",
        "external_id": "JIRA-1",
        "source": "jira",
        "title": "Migrate Database",
        "change_type": "NORMAL",
        "requester_id": "usr-requester",
        "owner_id": "usr-owner",
        "environment_id": "env-prod",
        "application_id": "app-api",
        "status": "OPEN"
    }
    change = Change(**change_data)
    assert change.change_type == ChangeType.NORMAL

    # Invalid change_type enum validation
    invalid_data = change_data.copy()
    invalid_data["change_type"] = "URGENT"  # Invalid enum value
    with pytest.raises(ValidationError):
        Change(**invalid_data)


def test_evidence_and_raw_event_schemas():
    # Valid evidence metadata
    evidence_data = {
        "evidence_id": "ev-1",
        "tenant_id": "tenant-xyz",
        "source": "github_actions",
        "source_record_id": "run-404",
        "evidence_type": "TEST_LOG",
        "hash": "a" * 64,
        "storage_reference": "s3://bucket/key",
        "collected_at": datetime.utcnow(),
        "created_at": datetime.utcnow()
    }
    evidence = Evidence(**evidence_data)
    assert len(evidence.hash) == 64

    # Valid RawEvent document representation
    event_data = {
        "event_id": "evt-1",
        "source": "github_webhook",
        "connector_type": "github",
        "event_type": "ping",
        "external_id": "ping_1",
        "received_at": datetime.utcnow(),
        "payload": {"zen": "Keep it simple"},
        "payload_hash": "b" * 64
    }
    event = RawEvent(**event_data)
    assert event.payload["zen"] == "Keep it simple"
