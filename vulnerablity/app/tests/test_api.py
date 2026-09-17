import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database.session import get_db

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

def test_api_health_check(client):
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

def test_api_create_and_get_scan(client, mock_repo_workspace):
    payload = {
        "repository_id": "repo-api-01",
        "repository_name": mock_repo_workspace,
        "branch": "main",
        "scan_type": "SAST"
    }

    # Trigger synchronous scan for testing
    res = client.post("/api/v1/scans/?sync=true", json=payload, headers={"X-Tenant-ID": "1"})
    assert res.status_code == 202
    data = res.json()
    scan_id = data["id"]
    assert data["status"] == "COMPLETED"
    assert data["finding_count"] > 0

    # Get scan status
    res2 = client.get(f"/api/v1/scans/{scan_id}", headers={"X-Tenant-ID": "1"})
    assert res2.status_code == 200
    assert res2.json()["id"] == scan_id

    # Get scan findings
    res_findings = client.get(f"/api/v1/scans/{scan_id}/findings", headers={"X-Tenant-ID": "1"})
    assert res_findings.status_code == 200
    findings = res_findings.json()
    assert len(findings) > 0
    assert "fingerprint" in findings[0]

    # Get scan evidence
    res_ev = client.get(f"/api/v1/scans/{scan_id}/evidence", headers={"X-Tenant-ID": "1"})
    assert res_ev.status_code == 200
    assert "raw_result_hash" in res_ev.json()

    # Get scan compliance
    res_comp = client.get(f"/api/v1/scans/{scan_id}/compliance", headers={"X-Tenant-ID": "1"})
    assert res_comp.status_code == 200
    evals = res_comp.json()
    assert len(evals) >= 3
