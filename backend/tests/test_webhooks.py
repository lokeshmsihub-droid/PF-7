import json
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.models.orm import ConnectorORM, ConnectorAccountORM
from app.db.mongodb import MongoDBClient

client = TestClient(app)

def test_github_webhook_accepted(db_session):
    # 1. Register mock connector account in Postgres
    conn = ConnectorORM(
        connector_id="github-web",
        name="GitHub Service",
        type="github",
        status="ACTIVE"
    )
    db_session.add(conn)
    db_session.commit()

    account = ConnectorAccountORM(
        account_id="acc-web-123",
        tenant_id="tenant-abc",
        connector_id="github-web",
        name="ACME Account",
        auth_type="personal_access_token",
        config={"mock": True, "webhook_secret": "test_secret"},
        status="ACTIVE"
    )
    db_session.add(account)
    db_session.commit()

    # 2. Construct mock PR payload
    payload = {
        "action": "opened",
        "number": 101,
        "pull_request": {
            "id": 8888,
            "title": "Fix security vulnerability",
            "state": "open"
        }
    }

    # 3. Request POST webhook
    response = client.post(
        "/webhooks/github?tenant_id=tenant-abc&account_id=acc-web-123",
        json=payload,
        headers={
            "X-GitHub-Event": "pull_request",
            "X-Hub-Signature-256": "sha256=d3adb33f"  # Mock verification bypasses this
        }
    )

    assert response.status_code == 202
    res_data = response.json()
    assert res_data["status"] == "accepted"
    assert "event_id" in res_data

    # 4. Assert MongoDB contains raw payload
    mongo = MongoDBClient()
    mongo.connect()
    try:
        col = mongo.raw_events_collection
        stored = col.find_one({"event_id": res_data["event_id"]})
        assert stored is not None
        assert stored["event_type"] == "pull_request"
        assert stored["payload"]["pull_request"]["title"] == "Fix security vulnerability"
    finally:
        mongo.disconnect()
