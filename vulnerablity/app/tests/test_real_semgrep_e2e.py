import pytest
import os
import shutil
import tempfile
import uuid
import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
from app.database.models import (
    Tenant, ScanJob, ScanStatus, CanonicalSecurityFinding, ScanEvidence,
    ComplianceEvaluation, AuditLog, FindingStatus
)
from app.orchestrator.orchestrator import ScanOrchestrator
from app.services.remediation_service import RemediationService
from app.scanners.semgrep.adapter import SemgrepAdapter

@pytest.fixture
def vulnerable_repo():
    """
    Creates a real local vulnerable repository with actual vulnerabilities.
    """
    temp_dir = tempfile.mkdtemp(prefix="vuln_repo_")
    
    # Python file with multiple real vulnerabilities
    py_code = """import os
import subprocess
import pickle
import hashlib

SECRET_KEY = "super-secret-token-abcdef1234567890"

def get_user(cursor, user_id):
    # SQL Injection
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")

def run_command(user_cmd):
    # Command Injection
    subprocess.Popen(user_cmd, shell=True)

def load_session(untrusted_payload):
    # Insecure Deserialization
    return pickle.loads(untrusted_payload)

def hash_password(password):
    # Weak Cryptography
    return hashlib.md5(password.encode()).hexdigest()

def read_file(user_path):
    # Path Traversal
    return open(f"/var/data/{user_path}").read()
"""
    with open(os.path.join(temp_dir, "server.py"), "w") as f:
        f.write(py_code)

    # JavaScript file with XSS and Hardcoded Secret
    js_code = """
const apiKey = "super-secret-token-abcdef1234567890";

function renderContent(untrusted_html) {
    document.getElementById('content').innerHTML = untrusted_html;
}
"""
    with open(os.path.join(temp_dir, "app.js"), "w") as f:
        f.write(js_code)

    # Valid package.json
    with open(os.path.join(temp_dir, "package.json"), "w") as f:
        f.write('{"name": "vulnerable-app", "version": "1.0.0"}')

    yield temp_dir

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)

@pytest.fixture
def clean_repo():
    """
    Creates a clean repository with no vulnerabilities.
    """
    temp_dir = tempfile.mkdtemp(prefix="clean_repo_")
    
    py_code = """import os

def get_greeting(name: str) -> str:
    return f"Hello, {name}!"

def safe_query(cursor, user_id: int):
    # Safe parameterized query
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
"""
    with open(os.path.join(temp_dir, "main.py"), "w") as f:
        f.write(py_code)

    with open(os.path.join(temp_dir, "package.json"), "w") as f:
        f.write('{"name": "clean-app", "version": "1.0.0"}')

    yield temp_dir

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)

def test_real_semgrep_e2e_pipeline(db_session, vulnerable_repo):
    """
    Tests the complete real Semgrep execution against a real vulnerable repository.
    Asserts real SARIF, real findings, risk calculation, compliance evaluation, and audit trail.
    """
    orchestrator = ScanOrchestrator(db=db_session)

    # 1. Create ScanJob
    scan_id = str(uuid.uuid4())
    scan_job = ScanJob(
        id=scan_id,
        tenant_id=1,
        repository_id="repo-enterprise-test",
        repository_name=vulnerable_repo,
        branch="main",
        commit_sha="e2e0000000000000000000000000000000000001",
        scan_type="SAST",
        status=ScanStatus.PENDING.value
    )
    db_session.add(scan_job)
    db_session.commit()

    # 2. Execute Real Scan
    completed_job = orchestrator.execute_scan(scan_job.id)

    # 3. Assert Real Scanner Execution
    assert completed_job.status == ScanStatus.COMPLETED.value
    assert completed_job.files_scanned >= 2
    assert completed_job.finding_count >= 5, f"Expected at least 5 findings, got {completed_job.finding_count}"
    assert completed_job.raw_result_hash is not None

    # 4. Assert Canonical Findings extracted from real SARIF
    findings = db_session.query(CanonicalSecurityFinding).filter(
        CanonicalSecurityFinding.scan_id == scan_job.id
    ).all()
    assert len(findings) == completed_job.finding_count

    rule_ids = [f.rule_id for f in findings]
    assert "enterprise.security.sql-injection-format" in rule_ids
    assert "enterprise.security.command-injection" in rule_ids
    assert "enterprise.security.insecure-deserialization" in rule_ids
    assert "enterprise.security.weak-cryptography-hash" in rule_ids
    assert "enterprise.security.hardcoded-secret-python" in rule_ids or "enterprise.security.hardcoded-secret-js" in rule_ids

    for f in findings:
        assert f.start_line > 0
        assert f.file_path in ("server.py", "app.js")
        assert len(f.fingerprint) == 64
        assert f.risk_score > 0.0
        assert f.risk_level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")

    # 5. Assert Compliance Engine Evaluated VM-001 through VM-015
    evals = db_session.query(ComplianceEvaluation).filter(
        ComplianceEvaluation.scan_id == scan_job.id
    ).all()
    eval_map = {e.control_id: e.result for e in evals}
    
    assert eval_map.get("VM-001") == "PASS" # Scanning enabled
    assert eval_map.get("VM-002") == "PASS" # SAST coverage
    assert eval_map.get("VM-004") in ("FAIL", "PENDING") # Critical vulnerability active
    assert eval_map.get("VM-015") == "PASS" # Scanner health

    # 6. Assert Audit Logs Created
    audit_events = db_session.query(AuditLog).filter(
        AuditLog.resource_id == scan_job.id
    ).all()
    actions = [a.action for a in audit_events]
    assert "SCAN_STARTED" in actions
    assert "SCAN_CHECKOUT" in actions
    assert "SEMGREP_STARTED" in actions
    assert "SEMGREP_COMPLETED" in actions
    assert "SCAN_COMPLETED" in actions

def test_remediation_and_verification_workflow(db_session, vulnerable_repo):
    """
    Tests the complete remediation lifecycle:
    Finding -> Jira Issue -> PR Correlation -> Verification Scan -> Compliance PASS.
    """
    from unittest.mock import MagicMock
    mock_jira = MagicMock()
    mock_jira.is_configured.return_value = True
    mock_jira.default_project_key = "SEC"
    mock_jira.create_issue.return_value = {
        "key": "SEC-101",
        "id": "10001",
        "url": "https://company.atlassian.net/browse/SEC-101"
    }
    mock_jira.add_comment.return_value = {"id": "comment-1"}

    orchestrator = ScanOrchestrator(db=db_session)
    remediation_svc = RemediationService(db=db_session, jira_service=mock_jira)

    # 1. Initial Scan on vulnerable repo
    scan_id = str(uuid.uuid4())
    scan_job = ScanJob(
        id=scan_id,
        tenant_id=1,
        repository_id="repo-rem-test",
        repository_name=vulnerable_repo,
        branch="main",
        commit_sha="c001111111111111111111111111111111111111",
        scan_type="SAST",
        status=ScanStatus.PENDING.value
    )
    db_session.add(scan_job)
    db_session.commit()
    orchestrator.execute_scan(scan_job.id)

    # Pick one SQL injection finding
    sqli_finding = db_session.query(CanonicalSecurityFinding).filter(
        CanonicalSecurityFinding.scan_id == scan_job.id,
        CanonicalSecurityFinding.rule_id == "enterprise.security.sql-injection-format"
    ).first()
    assert sqli_finding is not None

    # 2. Create Jira Remediation Task
    jira_res = remediation_svc.create_jira_remediation(
        finding_id=sqli_finding.id,
        tenant_id=1,
        project_key="SEC",
        summary="Fix SQL injection in server.py",
        assignee="developer@company.com"
    )
    assert sqli_finding.jira_issue_key == "SEC-101"
    assert sqli_finding.jira_issue_url == "https://company.atlassian.net/browse/SEC-101"
    assert sqli_finding.status == FindingStatus.IN_REMEDIATION.value

    # 3. Correlate GitHub PR
    pr_res = remediation_svc.correlate_github_pr(
        finding_id=sqli_finding.id,
        tenant_id=1,
        pr_url="https://github.com/org/repo/pull/42",
        branch="fix/sqli",
        commit_sha="fix9999999999999999999999999999999999999"
    )
    assert sqli_finding.verification_status == "PENDING_VERIFICATION"

    # 4. Create Fixed Repository Workspace (vulnerability resolved)
    fixed_workspace = tempfile.mkdtemp(prefix="fixed_repo_")
    try:
        # Copy files with SQLi fixed to parameterized query
        with open(os.path.join(fixed_workspace, "server.py"), "w") as f:
            f.write("""import os

def get_user(cursor, user_id):
    # Parameterized query - fixed!
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
""")
        with open(os.path.join(fixed_workspace, "package.json"), "w") as f:
            f.write('{"name": "vulnerable-app", "version": "1.0.0"}')

        # 5. Execute Verification Scan
        ver_res = remediation_svc.execute_verification_scan(
            finding_id=sqli_finding.id,
            tenant_id=1,
            fix_commit_sha="fix9999999999999999999999999999999999999",
            fixed_workspace_path=fixed_workspace
        )

        assert ver_res["verification_status"] == "VERIFIED"
        assert ver_res["status"] == FindingStatus.RESOLVED.value

        # 6. Verify Compliance Updated
        evals = db_session.query(ComplianceEvaluation).filter(
            ComplianceEvaluation.scan_id == ver_res["verification_scan_id"]
        ).all()
        eval_map = {e.control_id: e.result for e in evals}
        assert eval_map.get("VM-009") == "PASS" # Verification passed
        assert eval_map.get("VM-010") == "PASS" # Vulnerability closed

        # 7. Verify Finding Traceability and Audit Events
        assert sqli_finding.remediation_commit_sha == "fix9999999999999999999999999999999999999"
        assert sqli_finding.verification_scan_id == ver_res["verification_scan_id"]

        audit_events = db_session.query(AuditLog).filter(
            AuditLog.resource_id == sqli_finding.id
        ).all()
        act_set = {a.action for a in audit_events}
        assert "REMEDIATION_CREATED" in act_set
        assert "REMEDIATION_UPDATED" in act_set
        assert "VERIFICATION_STARTED" in act_set
        assert "FINDING_RESOLVED" in act_set
        assert "VERIFICATION_COMPLETED" in act_set
    finally:
        if os.path.exists(fixed_workspace):
            shutil.rmtree(fixed_workspace, ignore_errors=True)

def test_clean_scan_produces_zero_findings_not_failed(db_session, clean_repo):
    """
    Critical Requirement #10: Scan Failure != Zero Findings.
    A clean repo must complete with 0 findings and evaluate compliance PASS.
    """
    orchestrator = ScanOrchestrator(db=db_session)

    scan_job = ScanJob(
        id=str(uuid.uuid4()),
        tenant_id=1,
        repository_id="repo-clean-test",
        repository_name=clean_repo,
        branch="main",
        commit_sha="c1ea000000000000000000000000000000000000",
        scan_type="SAST",
        status=ScanStatus.PENDING.value
    )
    db_session.add(scan_job)
    db_session.commit()

    completed = orchestrator.execute_scan(scan_job.id)

    assert completed.status == ScanStatus.COMPLETED.value
    assert completed.finding_count == 0
    assert completed.files_scanned >= 1

    evals = db_session.query(ComplianceEvaluation).filter(
        ComplianceEvaluation.scan_id == scan_job.id
    ).all()
    eval_map = {e.control_id: e.result for e in evals}
    assert eval_map.get("VM-001") == "PASS"
    assert eval_map.get("VM-002") == "PASS"
    assert eval_map.get("VM-004") == "PASS" # Zero critical findings -> PASS!
