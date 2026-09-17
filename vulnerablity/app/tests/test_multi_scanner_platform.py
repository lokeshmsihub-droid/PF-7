import os
import tempfile
import pytest
from app.scanners.registry import ScannerRegistry
from app.scanners.codeql.adapter import CodeQLAdapter
from app.scanners.trivy.adapter import TrivyAdapter
from app.scanners.osv.adapter import OSVAdapter
from app.services.correlation_service import FindingCorrelationService
from app.services.git_service import GitService

def test_scanner_registry_discovery():
    available = ScannerRegistry.list_available()
    scanner_names = [s["name"] for s in available]
    assert "semgrep" in scanner_names
    assert "codeql" in scanner_names
    assert "trivy" in scanner_names
    assert "osv" in scanner_names

    for s in available:
        assert s["available"] is True, f"Scanner {s['name']} reported unavailable: {s.get('error')}"
        assert len(s["supported_languages"]) > 0
        assert len(s["scan_types"]) > 0

def test_codeql_adapter_health_and_capabilities():
    adapter = CodeQLAdapter()
    assert adapter.validate() is True
    cap = adapter.detect_capabilities()
    assert cap.scanner_name == "codeql"
    assert "python" in cap.supported_languages
    assert "javascript" in cap.supported_languages
    assert "SAST" in cap.scan_types

    health = adapter.health_check()
    assert health["status"] == "HEALTHY"

def test_trivy_adapter_health_and_scan():
    adapter = TrivyAdapter()
    assert adapter.validate() is True
    cap = adapter.detect_capabilities()
    assert "SCA" in cap.scan_types
    assert "IAC" in cap.scan_types

    health = adapter.health_check()
    assert health["status"] == "HEALTHY"

    # Test real scan on a temp requirements.txt
    temp_dir = tempfile.mkdtemp(prefix="test_trivy_")
    try:
        req_path = os.path.join(temp_dir, "requirements.txt")
        with open(req_path, "w") as f:
            f.write("flask==0.12\nrequests==2.18.0\n")

        ctx = adapter.prepare(temp_dir, {"scan_id": "test-trivy-scan"})
        res = adapter.scan(temp_dir, ctx)
        adapter.cleanup(ctx)

        assert res.execution_successful is True
        assert res.finding_count > 0
        findings = res.normalized_findings
        assert any(f["package_name"] == "flask" for f in findings)
        assert any(f["finding_type"] == "SCA" for f in findings)
    finally:
        if os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

def test_osv_adapter_health_and_scan():
    adapter = OSVAdapter()
    assert adapter.validate() is True
    cap = adapter.detect_capabilities()
    assert "SCA" in cap.scan_types

    health = adapter.health_check()
    assert health["status"] == "HEALTHY"

    # Test scan with requirements.txt
    temp_dir = tempfile.mkdtemp(prefix="test_osv_")
    try:
        req_path = os.path.join(temp_dir, "requirements.txt")
        with open(req_path, "w") as f:
            f.write("flask==0.12\nrequests==2.18.0\n")

        ctx = adapter.prepare(temp_dir, {"scan_id": "test-osv-scan"})
        res = adapter.scan(temp_dir, ctx)
        adapter.cleanup(ctx)

        assert res.execution_successful is True
        assert res.finding_count > 0
        findings = res.normalized_findings
        assert any(f["package_name"] == "flask" for f in findings)
        assert any(f["finding_type"] == "SCA" for f in findings)
    finally:
        if os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

def test_osv_adapter_not_applicable_when_no_manifests():
    adapter = OSVAdapter()
    temp_dir = tempfile.mkdtemp(prefix="test_osv_empty_")
    try:
        with open(os.path.join(temp_dir, "dummy.txt"), "w") as f:
            f.write("no dependencies here\n")

        ctx = adapter.prepare(temp_dir, {"scan_id": "test-osv-na"})
        res = adapter.scan(temp_dir, ctx)
        adapter.cleanup(ctx)

        assert res.metadata.get("status") == "NOT_APPLICABLE"
        assert res.execution_successful is True
        assert res.finding_count == 0
    finally:
        if os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)

def test_cross_scanner_correlation_service():
    # 1. SAST Correlation: Semgrep + CodeQL reporting same vulnerability
    semgrep_f = {
        "fingerprint": "fp_semgrep_01",
        "finding_type": "SAST",
        "source": "semgrep",
        "scanner": "semgrep",
        "file_path": "server.py",
        "start_line": 36,
        "rule_id": "enterprise.security.sql-injection-format",
        "severity": "HIGH",
        "cwe": ["CWE-89"],
        "detected_by_scanners": ["semgrep"]
    }
    codeql_f = {
        "fingerprint": "fp_codeql_01",
        "finding_type": "SAST",
        "source": "codeql",
        "scanner": "codeql",
        "file_path": "server.py",
        "start_line": 38,
        "rule_id": "py/sql-injection",
        "severity": "CRITICAL",
        "cwe": ["CWE-89"],
        "detected_by_scanners": ["codeql"]
    }
    unrelated_f = {
        "fingerprint": "fp_semgrep_02",
        "finding_type": "SAST",
        "source": "semgrep",
        "scanner": "semgrep",
        "file_path": "server.py",
        "start_line": 80,
        "rule_id": "enterprise.security.hardcoded-secret",
        "severity": "HIGH",
        "cwe": ["CWE-798"],
        "detected_by_scanners": ["semgrep"]
    }

    raw_findings = [semgrep_f, codeql_f, unrelated_f]
    correlated = FindingCorrelationService.correlate(raw_findings)

    assert len(correlated) == 2, f"Expected 2 correlated findings, got {len(correlated)}"
    sqli = [c for c in correlated if "sql" in c["rule_id"].lower()][0]
    assert "semgrep" in sqli["detected_by_scanners"]
    assert "codeql" in sqli["detected_by_scanners"]
    assert sqli["severity"] == "CRITICAL"
    assert "fp_codeql_01" in sqli["correlated_finding_ids"]

    # 2. SCA Correlation: Trivy + OSV reporting same package vulnerability
    trivy_f = {
        "fingerprint": "fp_trivy_01",
        "finding_type": "SCA",
        "source": "trivy",
        "scanner": "trivy",
        "package_name": "flask",
        "package_version": "0.12",
        "cve": ["CVE-2018-1000656"],
        "severity": "HIGH",
        "detected_by_scanners": ["trivy"]
    }
    osv_f = {
        "fingerprint": "fp_osv_01",
        "finding_type": "SCA",
        "source": "osv",
        "scanner": "osv",
        "package_name": "flask",
        "package_version": "0.12",
        "cve": ["CVE-2018-1000656"],
        "severity": "HIGH",
        "detected_by_scanners": ["osv"]
    }

    sca_correlated = FindingCorrelationService.correlate([trivy_f, osv_f])
    assert len(sca_correlated) == 1
    assert "trivy" in sca_correlated[0]["detected_by_scanners"]
    assert "osv" in sca_correlated[0]["detected_by_scanners"]

def test_git_service_remote_repository_validation():
    git_svc = GitService()

    # Local repo validation
    local_path = os.path.abspath("demo_vulnerable_repo")
    res = git_svc.validate_remote_repository(local_path, "main")
    assert res.valid is True
    assert res.provider == "local"
    assert res.access_status == "accessible"
    assert res.resolved_commit_sha is not None
    assert "semgrep" in res.applicable_scanners
    assert "codeql" in res.applicable_scanners
    assert "trivy" in res.applicable_scanners

    # Public GitHub URL validation (e.g. torvalds/linux or git repository)
    remote_url = "https://github.com/octocat/Hello-World.git"
    res_remote = git_svc.validate_remote_repository(remote_url, "master")
    assert res_remote.valid is True
    assert res_remote.provider == "github"
    assert res_remote.repository_name == "Hello-World"
    assert res_remote.resolved_commit_sha is not None
