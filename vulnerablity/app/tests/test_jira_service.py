import pytest
import uuid
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.services.jira_service import (
    JiraService, JiraNotConfiguredError, JiraIntegrationError
)
from app.services.remediation_service import RemediationService
from app.database.models import CanonicalSecurityFinding, FindingStatus, AuditLog, ScanJob, ScanStatus

def test_jira_service_unconfigured_behavior():
    """Verify that unconfigured JiraService safely refuses operations without credentials."""
    svc = JiraService(base_url="", email="", api_token="")
    assert not svc.is_configured()

    with pytest.raises(JiraNotConfiguredError) as exc:
        svc.create_issue(summary="Test Bug", description="Detail")
    assert "not configured" in str(exc.value)

    with pytest.raises(JiraNotConfiguredError):
        svc.get_issue("SEC-100")

    with pytest.raises(JiraNotConfiguredError):
        svc.update_issue("SEC-100", {"summary": "New"})

    with pytest.raises(JiraNotConfiguredError):
        svc.transition_issue("SEC-100", "Done")

    with pytest.raises(JiraNotConfiguredError):
        svc.add_comment("SEC-100", "Resolved")

def test_jira_service_mocked_http_operations():
    """Verify Jira Cloud REST API operations with deterministic mocked HTTP layer."""
    svc = JiraService(
        base_url="https://compliance-org.atlassian.net",
        email="security-lead@compliance.org",
        api_token="mock-secret-api-token-xyz123",
        default_project_key="SEC"
    )
    assert svc.is_configured()

    # 1. create_issue
    with patch("httpx.Client.post") as mock_post:
        mock_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"id": "10050", "key": "SEC-555"}
        )
        res = svc.create_issue(
            project_key="SEC",
            summary="SQL Injection Vulnerability",
            description="Details of SQL injection finding...",
            priority="High",
            labels=["security", "sast"]
        )
        assert res["key"] == "SEC-555"
        assert res["id"] == "10050"
        assert res["url"] == "https://compliance-org.atlassian.net/browse/SEC-555"

    # 2. get_issue
    with patch("httpx.Client.get") as mock_get:
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"key": "SEC-555", "fields": {"status": {"name": "In Progress"}}}
        )
        issue = svc.get_issue("SEC-555")
        assert issue["key"] == "SEC-555"
        assert issue["fields"]["status"]["name"] == "In Progress"

    # 3. update_issue
    with patch("httpx.Client.put") as mock_put:
        mock_put.return_value = MagicMock(status_code=204)
        up_res = svc.update_issue("SEC-555", {"summary": "Updated SQL Injection"})
        assert up_res["updated"] is True

    # 4. transition_issue
    with patch("httpx.Client.get") as mock_trans_get, patch("httpx.Client.post") as mock_trans_post:
        mock_trans_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {"transitions": [{"id": "31", "name": "Done"}, {"id": "21", "name": "In Progress"}]}
        )
        mock_trans_post.return_value = MagicMock(status_code=204)
        t_res = svc.transition_issue("SEC-555", "Done")
        assert t_res["status"] == "TRANSITIONED"
        assert t_res["transition_id"] == "31"

    # 5. add_comment
    with patch("httpx.Client.post") as mock_comment_post:
        mock_comment_post.return_value = MagicMock(
            status_code=201,
            json=lambda: {"id": "comment-999", "body": "Fix confirmed"}
        )
        c_res = svc.add_comment("SEC-555", "Fix confirmed via automated verification scan")
        assert c_res["id"] == "comment-999"

def test_remediation_service_unconfigured_fails_explicitly(db_session):
    """Verify that attempting Jira remediation when unconfigured raises JiraNotConfiguredError."""
    mock_jira = JiraService(base_url="", email="", api_token="")
    remediation_svc = RemediationService(db=db_session, jira_service=mock_jira)

    scan_id = str(uuid.uuid4())
    scan_job = ScanJob(
        id=scan_id,
        tenant_id=1,
        repository_id="repo-jira-test",
        repository_name="test-repo",
        branch="main",
        commit_sha="c001",
        scan_type="SAST",
        status=ScanStatus.COMPLETED.value
    )
    db_session.add(scan_job)

    finding = CanonicalSecurityFinding(
        id=str(uuid.uuid4()),
        tenant_id=1,
        scan_id=scan_id,
        fingerprint="fp1234567890",
        scanner="semgrep",
        repository_id="repo-jira-test",
        repository_name="test-repo",
        branch="main",
        commit_sha="c001",
        file_path="app.py",
        start_line=10,
        rule_id="enterprise.security.sql-injection-format",
        title="SQL Injection",
        severity="HIGH",
        status=FindingStatus.OPEN.value
    )
    db_session.add(finding)
    db_session.commit()

    with pytest.raises(JiraNotConfiguredError):
        remediation_svc.create_jira_remediation(finding_id=finding.id, tenant_id=1)

    # Finding must NOT have fabricated issue key
    db_session.refresh(finding)
    assert finding.jira_issue_key is None
    assert finding.status == FindingStatus.OPEN.value

def test_remediation_api_endpoints(db_session):
    """Test the /api/v1/security/findings/{id}/remediation endpoint with unconfigured and configured Jira."""
    from app.main import app
    from app.database.session import get_db
    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)

    scan_id = str(uuid.uuid4())
    scan_job = ScanJob(
        id=scan_id,
        tenant_id=1,
        repository_id="repo-api-jira",
        repository_name="test-repo",
        branch="main",
        commit_sha="c002",
        scan_type="SAST",
        status=ScanStatus.COMPLETED.value
    )
    db_session.add(scan_job)

    finding = CanonicalSecurityFinding(
        id=str(uuid.uuid4()),
        tenant_id=1,
        scan_id=scan_id,
        fingerprint="fp_api_123",
        scanner="semgrep",
        repository_id="repo-api-jira",
        repository_name="test-repo",
        branch="main",
        commit_sha="c002",
        file_path="server.py",
        start_line=15,
        rule_id="enterprise.security.python.command-injection",
        title="Command Injection",
        severity="CRITICAL",
        status=FindingStatus.OPEN.value
    )
    db_session.add(finding)
    db_session.commit()

    # 1. When Jira is unconfigured -> HTTP 503 Service Unavailable
    with patch("app.services.jira_service.JiraService.is_configured", return_value=False):
        resp = client.post(
            f"/api/v1/security/findings/{finding.id}/remediation",
            json={"project_key": "SEC", "summary": "Fix Command Injection"},
            headers={"X-Tenant-ID": "1"}
        )
        assert resp.status_code == 503
        assert "not configured" in resp.json()["detail"]

    # 2. When Jira is configured -> HTTP 200 with real key and URL, audit event logged
    with patch("app.services.jira_service.JiraService.is_configured", return_value=True), \
         patch("app.services.jira_service.JiraService.create_issue") as mock_create:
        mock_create.return_value = {
            "key": "SEC-800",
            "id": "20000",
            "url": "https://company.atlassian.net/browse/SEC-800"
        }
        resp = client.post(
            f"/api/v1/security/findings/{finding.id}/remediation",
            json={"project_key": "SEC", "summary": "Fix Command Injection", "assignee": "alice@corp.com"},
            headers={"X-Tenant-ID": "1"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["jira_issue_key"] == "SEC-800"
        assert data["jira_issue_url"] == "https://company.atlassian.net/browse/SEC-800"
        assert data["status"] == "IN_REMEDIATION"

        # Check audit event
        audit = db_session.query(AuditLog).filter(
            AuditLog.resource_id == finding.id,
            AuditLog.action == "REMEDIATION_CREATED"
        ).first()
        assert audit is not None
        assert audit.details.get("jira_issue_key") == "SEC-800"

    app.dependency_overrides.clear()
