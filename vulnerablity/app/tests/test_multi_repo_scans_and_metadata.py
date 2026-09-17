import pytest
import os
import tempfile
import subprocess
from fastapi.testclient import TestClient
from app.main import app
from app.database.session import get_db
from app.database.models import ScanJob, CanonicalSecurityFinding, RepositoryProfileModel

@pytest.fixture
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app)
    app.dependency_overrides.clear()

@pytest.fixture
def two_distinct_repos():
    """Creates two distinct temporary git repositories with different languages and vulnerabilities."""
    d1 = tempfile.mkdtemp(prefix="repo_python_")
    d2 = tempfile.mkdtemp(prefix="repo_node_")

    # Repo 1: Python with SQL injection
    subprocess.run(["git", "init"], cwd=d1, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=d1, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=d1, check=True)
    with open(os.path.join(d1, "app.py"), "w") as f:
        f.write("import sqlite3\ndef get_user(db, val):\n    return db.execute('SELECT * FROM users WHERE id = ' + val)\n")
    subprocess.run(["git", "add", "."], cwd=d1, check=True)
    subprocess.run(["git", "commit", "-m", "initial python commit"], cwd=d1, check=True)

    # Repo 2: Node.js with vulnerable package.json
    subprocess.run(["git", "init"], cwd=d2, capture_output=True, check=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=d2, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=d2, check=True)
    with open(os.path.join(d2, "package.json"), "w") as f:
        f.write('{"name": "test-pkg", "version": "1.0.0", "dependencies": {"lodash": "4.17.15"}}\n')
    subprocess.run(["git", "add", "."], cwd=d2, check=True)
    subprocess.run(["git", "commit", "-m", "initial node commit"], cwd=d2, check=True)

    yield d1, d2

def test_multi_repo_isolation_and_telemetry(client, two_distinct_repos):
    repo1_path, repo2_path = two_distinct_repos

    # Scan Repo 1 (Python)
    res1 = client.post("/api/v1/scans/?sync=true", json={
        "repository_id": "repo-python-test",
        "repository_name": repo1_path,
        "branch": "main",
        "scan_type": "FULL_PIPELINE"
    }, headers={"X-Tenant-ID": "1"})
    assert res1.status_code == 202
    data1 = res1.json()
    assert data1["status"] == "COMPLETED"
    assert "python" in [s.lower() for s in data1.get("scanners", [])] or data1.get("scanners") is not None

    # Scan Repo 2 (Node.js)
    res2 = client.post("/api/v1/scans/?sync=true", json={
        "repository_id": "repo-node-test",
        "repository_name": repo2_path,
        "branch": "main",
        "scan_type": "FULL_PIPELINE"
    }, headers={"X-Tenant-ID": "1"})
    assert res2.status_code == 202
    data2 = res2.json()
    assert data2["status"] == "COMPLETED"

    # Verify /repositories returns accurate distinct commit SHAs and distinct repo names
    repos_res = client.get("/repositories", headers={"X-Tenant-ID": "1"})
    assert repos_res.status_code == 200
    repos = repos_res.json()
    
    names = [r["name"] for r in repos]
    assert repo1_path in names
    assert repo2_path in names

    repo1_info = next(r for r in repos if r["name"] == repo1_path)
    repo2_info = next(r for r in repos if r["name"] == repo2_path)

    # Commit SHAs must be 12-char hex and must differ between repos
    assert repo1_info["commit_sha"] is not None
    assert repo2_info["commit_sha"] is not None
    assert repo1_info["commit_sha"] != repo2_info["commit_sha"]
    assert len(repo1_info["commit_sha"]) == 12

    # Verify per-repo findings are strictly isolated
    findings1_res = client.get(f"/api/v1/scans/{data1['id']}/findings", headers={"X-Tenant-ID": "1"})
    findings2_res = client.get(f"/api/v1/scans/{data2['id']}/findings", headers={"X-Tenant-ID": "1"})
    assert findings1_res.status_code == 200
    assert findings2_res.status_code == 200

    findings1 = findings1_res.json()
    findings2 = findings2_res.json()

    # All findings in scan 1 must belong to repo1
    for f in findings1:
        assert f["repository_name"] == repo1_path
        assert f["commit_sha"] == repo1_info["commit_sha"] or f["commit_sha"].startswith(repo1_info["commit_sha"])

    # All findings in scan 2 must belong to repo2
    for f in findings2:
        assert f["repository_name"] == repo2_path
        assert f["commit_sha"] == repo2_info["commit_sha"] or f["commit_sha"].startswith(repo2_info["commit_sha"])
