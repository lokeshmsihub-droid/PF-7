import pytest
from app.services.change_monitoring_service import ChangeMonitoringService

def test_monitoring_state_fingerprint_deterministic():
    """Verify state hash is deterministic for same dictionary content."""
    service = ChangeMonitoringService(None)

    state1 = {
        "change_id": "chg-1",
        "tenant_id": "tenant-1",
        "change": {"status": "OPEN", "change_type": "NORMAL"},
        "tests": [{"test_id": "run-1", "status": "PASS"}],
        "deployments": []
    }
    
    # Same content but different key order
    state2 = {
        "tenant_id": "tenant-1",
        "change_id": "chg-1",
        "deployments": [],
        "tests": [{"status": "PASS", "test_id": "run-1"}],
        "change": {"change_type": "NORMAL", "status": "OPEN"}
    }

    hash1 = service.compute_state_hash(state1)
    hash2 = service.compute_state_hash(state2)
    assert hash1 == hash2
    assert hash1 != ""

def test_monitoring_state_comparison_no_op():
    """Verify no-op detection when previous state equals current state."""
    service = ChangeMonitoringService(None)

    state = {
        "change_id": "chg-1",
        "tenant_id": "tenant-1",
        "change": {"status": "OPEN", "change_type": "NORMAL"},
        "tests": [{"test_id": "run-1", "commit_id": "abc123", "status": "PASS"}],
        "deployments": [{"deployment_id": "dep-1", "commit_id": "abc123", "status": "SUCCESS"}]
    }

    changes = service.compare_state(state, state)
    assert len(changes) == 0
    assert service.determine_impact(changes) == "NO_COMPLIANCE_IMPACT"

def test_monitoring_state_comparison_changes():
    """Verify various change flags are correctly identified on state drift."""
    service = ChangeMonitoringService(None)

    prev = {
        "change_id": "chg-1",
        "tenant_id": "tenant-1",
        "change": {"status": "OPEN", "change_type": "NORMAL"},
        "tests": [{"test_id": "run-1", "commit_id": "abc123", "status": "PASS"}],
        "deployments": [{"deployment_id": "dep-1", "commit_id": "abc123", "status": "SUCCESS"}]
    }

    # Case 1: Status and commit changed
    curr1 = {
        "change_id": "chg-1",
        "tenant_id": "tenant-1",
        "change": {"status": "APPROVED", "change_type": "NORMAL"},
        "tests": [{"test_id": "run-1", "commit_id": "xyz789", "status": "PASS"}],
        "deployments": [{"deployment_id": "dep-1", "commit_id": "abc123", "status": "SUCCESS"}]
    }
    changes1 = service.compare_state(prev, curr1)
    assert "STATUS_CHANGED" in changes1
    assert "COMMIT_CHANGED" in changes1
    assert "APPROVED_CHANGE_MODIFIED" in changes1
    assert service.determine_impact(changes1) == "CORRELATION_RELEVANT_CHANGE"

    # Case 2: Test status changed (PASS -> FAIL)
    curr2 = {
        "change_id": "chg-1",
        "tenant_id": "tenant-1",
        "change": {"status": "OPEN", "change_type": "NORMAL"},
        "tests": [{"test_id": "run-1", "commit_id": "abc123", "status": "FAIL"}],
        "deployments": [{"deployment_id": "dep-1", "commit_id": "abc123", "status": "SUCCESS"}]
    }
    changes2 = service.compare_state(prev, curr2)
    assert "TEST_STATUS_CHANGED" in changes2
    assert service.determine_impact(changes2) == "EVALUATION_RELEVANT_CHANGE"

    # Case 3: Commit drift detected (Approved commit vs deployment commit mismatch)
    curr3 = {
        "change_id": "chg-1",
        "tenant_id": "tenant-1",
        "change": {"status": "OPEN", "change_type": "NORMAL"},
        "tests": [{"test_id": "run-1", "commit_id": "abc123", "status": "PASS"}],
        "deployments": [{"deployment_id": "dep-1", "commit_id": "xyz789", "status": "SUCCESS"}]
    }
    changes3 = service.compare_state(prev, curr3)
    assert "DEPLOYMENT_CHANGED" in changes3
    assert "COMMIT_CHANGED" in changes3
    assert "COMMIT_DRIFT_DETECTED" in changes3
    assert service.determine_impact(changes3) == "CORRELATION_RELEVANT_CHANGE"
