from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_liveness_check():
    """Verify health endpoint is online."""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "healthy", "timestamp": "OK"}

def test_readiness_check_success():
    """Verify readiness check succeeds when dependencies are online."""
    response = client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["dependencies"]["postgresql"] == "UP"
    assert data["dependencies"]["mongodb"] == "UP"
