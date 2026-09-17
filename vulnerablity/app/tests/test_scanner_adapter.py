import pytest
import os
import json
from app.scanners.semgrep.adapter import SemgrepAdapter
from app.scanners.base import ScannerAdapter

def test_semgrep_adapter_implements_interface():
    adapter = SemgrepAdapter()
    assert isinstance(adapter, ScannerAdapter)

def test_semgrep_capabilities():
    adapter = SemgrepAdapter()
    caps = adapter.detect_capabilities()
    assert caps.scanner_name == "semgrep"
    assert "python" in caps.supported_languages
    assert "javascript" in caps.supported_languages
    assert "SAST" in caps.scan_types

def test_semgrep_health_check():
    adapter = SemgrepAdapter()
    health = adapter.health_check()
    assert health["status"] == "HEALTHY"
    assert health["scanner"] == "semgrep"

def test_semgrep_prepare_and_cleanup(mock_repo_workspace):
    adapter = SemgrepAdapter()
    ctx = adapter.prepare(mock_repo_workspace, {"scan_id": "test-123"})
    assert "temp_dir" in ctx
    assert os.path.exists(ctx["temp_dir"])
    
    adapter.cleanup(ctx)
    assert not os.path.exists(ctx["temp_dir"])

def test_semgrep_sarif_normalization():
    adapter = SemgrepAdapter()
    sample_sarif = json.dumps({
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "rules": [{
                        "id": "security.sqli",
                        "shortDescription": {"text": "SQL Injection Detected"},
                        "properties": {"tags": ["CWE-89", "OWASP-A03:2021-Injection"]}
                    }]
                }
            },
            "results": [{
                "ruleId": "security.sqli",
                "level": "error",
                "message": {"text": "Detected SQL string formatting"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "db/query.py"},
                        "region": {"startLine": 45, "endLine": 45}
                    }
                }]
            }]
        }]
    })

    findings = adapter.normalize(sample_sarif, {
        "tenant_id": 1,
        "scan_id": "scan-abc",
        "repository_id": "repo-xyz",
        "repository_name": "my-repo",
        "branch": "main",
        "commit_sha": "a1b2c3d4"
    })

    assert len(findings) == 1
    f = findings[0]
    assert f["rule_id"] == "security.sqli"
    assert f["severity"] == "HIGH"
    assert "CWE-89" in f["cwe"]
    assert f["file_path"] == "db/query.py"
    assert f["start_line"] == 45
    assert len(f["fingerprint"]) == 64
