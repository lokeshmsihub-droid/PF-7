import pytest
import uuid
import json
import hashlib
from datetime import datetime, UTC
from app.services.normalization_service import NormalizationService
from app.models.orm import ChangeORM, ApprovalORM, TestORM, DeploymentORM, UserORM
from app.db.mongodb import MongoDBClient

def test_normalization_pipeline(db_session):
    tenant_id = "tenant-abc"
    sync_run_id = "sync-norm-999"

    # 1. Seed raw payloads in MongoDB raw_events
    mongo = MongoDBClient()
    mongo.connect()
    try:
        col = mongo.raw_events_collection
        # Clean previous test run left-overs if any
        col.delete_many({"sync_run_id": sync_run_id})

        # Mock PR Payload
        pr_payload = {
            "number": 12,
            "title": "EMERGENCY: Fix auth vulnerability",
            "body": "Fixing production bug.",
            "state": "closed",
            "merged_at": "2026-08-22T07:12:00Z",
            "created_at": "2026-08-22T06:12:00Z",
            "updated_at": "2026-08-22T07:12:00Z",
            "user": {"login": "developer-bob"}
        }
        
        # Mock Review Payload
        review_payload = {
            "id": 8887,
            "pull_request_number": 12,
            "state": "approved",
            "submitted_at": "2026-08-22T07:00:00Z",
            "user": {"login": "reviewer-alice"}
        }

        # Mock Workflow run (Test) Payload
        test_payload = {
            "id": 9999,
            "head_sha": "sha-abc-123",
            "status": "completed",
            "conclusion": "success",
            "run_started_at": "2026-08-22T06:30:00Z",
            "updated_at": "2026-08-22T06:45:00Z",
            "html_url": "https://github.com/runs/9999"
        }

        # Mock Deployment Payload
        deploy_payload = {
            "id": 7777,
            "sha": "sha-abc-123",
            "ref": "v1.2.0",
            "environment": "production",
            "created_at": "2026-08-22T07:20:00Z",
            "creator": {"login": "ops-charles"}
        }

        events = [
            ("pull_request", pr_payload, "pr-12"),
            ("pull_request_review", review_payload, "review-8887"),
            ("workflow_run", test_payload, "run-9999"),
            ("deployment", deploy_payload, "deploy-7777")
        ]

        for ev_type, pl, ext_id in events:
            pl_str = json.dumps(pl, sort_keys=True, default=str)
            pl_hash = hashlib.sha256(pl_str.encode("utf-8")).hexdigest()
            col.insert_one({
                "event_id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "connector_account_id": "acc-999",
                "source": "github",
                "provider": "github",
                "event_type": ev_type,
                "external_id": ext_id,
                "received_at": datetime.now(UTC),
                "sync_run_id": sync_run_id,
                "payload": pl,
                "payload_hash": pl_hash
            })

    finally:
        mongo.disconnect()

    # 2. Run normalization
    service = NormalizationService(db_session)
    count = service.normalize_sync_run_payloads(tenant_id, sync_run_id)
    assert count == 4

    # 3. Verify PostgreSQL records
    # PR -> Change
    change = db_session.query(ChangeORM).filter_by(change_id="chg-pr-12").first()
    assert change is not None
    assert change.title == "EMERGENCY: Fix auth vulnerability"
    assert change.change_type.name == "EMERGENCY"
    assert change.status == "CLOSED"
    assert change.requester_id == "usr-developer-bob"

    # Review -> Approval
    approval = db_session.query(ApprovalORM).filter_by(approval_id="appr-8887").first()
    assert approval is not None
    assert approval.decision == "APPROVED"
    assert approval.approver_id == "usr-reviewer-alice"

    # Test
    test = db_session.query(TestORM).filter_by(test_id="run-9999").first()
    assert test is not None
    assert test.status.name == "PASS"
    assert test.commit_id == "sha-abc-123"

    # Deployment
    deploy = db_session.query(DeploymentORM).filter_by(deployment_id="dep-7777").first()
    assert deploy is not None
    assert deploy.deployed_by == "usr-ops-charles"
    assert deploy.commit_id == "sha-abc-123"

    # Verify lookups were auto-created
    alice = db_session.query(UserORM).filter_by(internal_user_id="usr-reviewer-alice").first()
    assert alice is not None
    assert alice.name == "Reviewer-alice"
