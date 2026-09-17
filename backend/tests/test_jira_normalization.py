import pytest
from app.normalization.jira_adapter import JiraNormalizer
from app.models.orm import ORMChangeType

def test_jira_normalize_standard_issue():
    payload = {
        "key": "CHG-101",
        "fields": {
            "summary": "STANDARD: Auth fix",
            "description": "Fixes auth token generation issues. PR #101.",
            "creator": {"emailAddress": "alice@acme.com"},
            "assignee": {"emailAddress": "bob@acme.com"},
            "status": {"name": "Done"},
            "created": "2026-08-24T00:00:00.000+0000",
            "updated": "2026-08-24T08:00:00.000+0000",
            "customfield_risk": {"value": "Low"},
            "customfield_environment": {"value": "Production"},
            "customfield_is_emergency": {"value": "No"}
        }
    }
    
    change = JiraNormalizer.normalize_issue(payload, "tenant-1")
    assert change.change_id == "chg-jira-CHG-101"
    assert change.source == "jira"
    assert change.change_type == ORMChangeType.STANDARD
    assert change.status == "CLOSED"
    assert change.risk_level == "low"
    assert change.requester_id == "usr-alice@acme.com"

def test_jira_extract_approvals():
    payload = {
        "key": "CHG-101",
        "changelog": {
            "histories": [
                {
                    "id": "12345",
                    "created": "2026-08-24T02:00:00.000+0000",
                    "author": {"emailAddress": "manager@acme.com"},
                    "items": [
                        {"field": "status", "fromString": "In Review", "toString": "Approved"}
                    ]
                }
            ]
        }
    }
    
    approvals = JiraNormalizer.extract_approvals(payload, "tenant-1")
    assert len(approvals) == 1
    assert approvals[0].approval_id == "appr-jira-CHG-101-12345"
    assert approvals[0].approver_id == "usr-manager@acme.com"
    assert approvals[0].decision == "APPROVED"
