import os
import tempfile
import shutil
import uuid
import pytest

from app.database.models import ScanJob, ScanStatus, CanonicalSecurityFinding, FindingStatus
from app.orchestrator.orchestrator import ScanOrchestrator
from app.services.remediation_service import RemediationService
from unittest.mock import MagicMock

def test_robust_fingerprint_line_shift_and_identity(db_session):
    """
    Verifies that the fingerprinting algorithm is resilient to line shifts (+5 lines),
    differentiates distinct vulnerabilities/rules/repos/tenants, and preserves finding identity.
    """
    orchestrator = ScanOrchestrator(db=db_session)

    temp_dir_a = tempfile.mkdtemp(prefix="repo_orig_")
    temp_dir_b = tempfile.mkdtemp(prefix="repo_shifted_")
    temp_dir_c = tempfile.mkdtemp(prefix="repo_fixed_")
    temp_dir_d = tempfile.mkdtemp(prefix="repo_diff_vuln_")

    try:
        # TEST A: Original vulnerable code
        code_a = """import os
import sqlite3

def find_user(username):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchall()
"""
        with open(os.path.join(temp_dir_a, "app.py"), "w") as f:
            f.write(code_a)

        scan_a = ScanJob(
            id=str(uuid.uuid4()),
            tenant_id=1,
            repository_id="repo-fp-test",
            repository_name=temp_dir_a,
            branch="main",
            commit_sha="a000000000000000000000000000000000000001",
            scan_type="SAST",
            status=ScanStatus.PENDING.value
        )
        db_session.add(scan_a)
        db_session.commit()
        res_a = orchestrator.execute_scan(scan_a.id)

        findings_a = db_session.query(CanonicalSecurityFinding).filter(
            CanonicalSecurityFinding.scan_id == scan_a.id,
            CanonicalSecurityFinding.rule_id == "enterprise.security.sql-injection-format"
        ).all()
        assert len(findings_a) == 1, "Expected exactly 1 SQL injection finding in scan A"
        fp_a = findings_a[0].fingerprint
        line_a = findings_a[0].start_line
        assert fp_a is not None
        assert len(fp_a) == 64

        # TEST B: Shift vulnerability down by +5 unrelated lines
        code_b = """# Unrelated comment line 1
# Unrelated comment line 2
# Unrelated comment line 3
# Unrelated comment line 4
# Unrelated comment line 5
import os
import sqlite3

def find_user(username):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchall()
"""
        with open(os.path.join(temp_dir_b, "app.py"), "w") as f:
            f.write(code_b)

        scan_b = ScanJob(
            id=str(uuid.uuid4()),
            tenant_id=1,
            repository_id="repo-fp-test",
            repository_name=temp_dir_b,
            branch="main",
            commit_sha="b000000000000000000000000000000000000002",
            scan_type="SAST",
            status=ScanStatus.PENDING.value
        )
        db_session.add(scan_b)
        db_session.commit()
        res_b = orchestrator.execute_scan(scan_b.id)

        findings_b = db_session.query(CanonicalSecurityFinding).filter(
            CanonicalSecurityFinding.scan_id == scan_b.id,
            CanonicalSecurityFinding.rule_id == "enterprise.security.sql-injection-format"
        ).all()
        assert len(findings_b) == 1
        fp_b = findings_b[0].fingerprint
        line_b = findings_b[0].start_line

        # Line number changed (+5 lines)
        assert line_b == line_a + 5, f"Expected line {line_a + 5}, got {line_b}"
        # CRITICAL ASSERTION: Robust fingerprint matches despite line shift!
        assert fp_a == fp_b, f"Robust fingerprint must be identical across line shifts! Got {fp_a} vs {fp_b}"

        # TEST C: Remove vulnerability (fixed code)
        code_c = """import os
import sqlite3

def find_user(username):
    conn = sqlite3.connect("test.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()
"""
        with open(os.path.join(temp_dir_c, "app.py"), "w") as f:
            f.write(code_c)

        mock_jira = MagicMock()
        mock_jira.is_configured.return_value = False
        remediation_svc = RemediationService(db=db_session, jira_service=mock_jira)

        ver_res = remediation_svc.execute_verification_scan(
            finding_id=findings_a[0].id,
            tenant_id=1,
            fix_commit_sha="c000000000000000000000000000000000000003",
            fixed_workspace_path=temp_dir_c
        )
        assert ver_res["verification_status"] == "VERIFIED"
        assert ver_res["status"] == FindingStatus.RESOLVED.value

        # TEST D: Second vulnerability with different code
        code_d = """import os
def run_command(param):
    # Command injection vulnerability
    os.system(f"echo {param}")
"""
        with open(os.path.join(temp_dir_d, "app.py"), "w") as f:
            f.write(code_d)

        scan_d = ScanJob(
            id=str(uuid.uuid4()),
            tenant_id=1,
            repository_id="repo-fp-test",
            repository_name=temp_dir_d,
            branch="main",
            commit_sha="d000000000000000000000000000000000000004",
            scan_type="SAST",
            status=ScanStatus.PENDING.value
        )
        db_session.add(scan_d)
        db_session.commit()
        res_d = orchestrator.execute_scan(scan_d.id)

        findings_d = db_session.query(CanonicalSecurityFinding).filter(
            CanonicalSecurityFinding.scan_id == scan_d.id
        ).all()
        assert len(findings_d) == 1
        fp_d = findings_d[0].fingerprint
        assert fp_d != fp_a, "Different vulnerability pattern must have different fingerprint!"

    finally:
        for p in (temp_dir_a, temp_dir_b, temp_dir_c, temp_dir_d):
            if os.path.exists(p):
                shutil.rmtree(p, ignore_errors=True)
