import pytest
from app.services.collection_service import CollectionService
from app.models.orm import ConnectorORM, ConnectorAccountORM, SyncRunORM
from app.db.mongodb import MongoDBClient

def test_collection_sync_flow(db_session):
    # 1. Setup mock connector definitions in Postgres
    conn = ConnectorORM(
        connector_id="github",
        name="GitHub Service",
        type="github",
        status="ACTIVE"
    )
    db_session.add(conn)
    db_session.commit()

    account = ConnectorAccountORM(
        account_id="acc-test-123",
        tenant_id="tenant-abc",
        connector_id="github",
        name="ACME Account",
        auth_type="personal_access_token",
        config={"mock": True},
        status="ACTIVE"
    )
    db_session.add(account)
    db_session.commit()

    # 2. Run sync pipeline
    service = CollectionService(db_session)
    result = service.run_sync("tenant-abc", "acc-test-123", "acme/enterprise-auth-service")

    # 3. Assert sync runs successfully
    assert result["status"] == "SUCCESS"
    assert result["records_collected"] == 5  # Mock returns 5 records (1 PR, 1 review, 1 commit, 1 action run, 1 deploy)
    assert result["records_failed"] == 0

    # 4. Verify Postgres audit record
    db_run = db_session.query(SyncRunORM).filter_by(sync_run_id=result["sync_run_id"]).first()
    assert db_run is not None
    assert db_run.status == "SUCCESS"
    assert db_run.records_synced == 5

    # 5. Verify MongoDB storage
    mongo = MongoDBClient()
    mongo.connect()
    try:
        col = mongo.raw_events_collection
        db_records = list(col.find({"sync_run_id": result["sync_run_id"]}))
        assert len(db_records) == 5
        types = {r["event_type"] for r in db_records}
        assert "pull_request" in types
        assert "pull_request_review" in types
        assert "commit" in types
        assert "workflow_run" in types
        assert "deployment" in types
    finally:
        mongo.disconnect()
