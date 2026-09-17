import os
import hmac
import hashlib
import json
import uuid
from datetime import datetime, UTC
from fastapi import APIRouter, Request, Header, HTTPException, status, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from app.api.dependencies import get_db
from app.db.mongodb import MongoDBClient
from app.models.orm import ConnectorAccountORM
from app.services.event_processor import process_webhook_event_async
from app.services.audit_service import AuditLogService

router = APIRouter()

def verify_github_signature(payload_bytes: bytes, secret: str, signature_header: str) -> bool:
    """Validate signature to verify request originated from GitHub."""
    if not signature_header:
        return False
    try:
        sha_name, signature = signature_header.split("=")
        if sha_name != "sha256":
            return False
        mac = hmac.new(secret.encode("utf-8"), msg=payload_bytes, digestmod=hashlib.sha256)
        return hmac.compare_digest(mac.hexdigest(), signature)
    except Exception:
        return False

@router.post("/webhooks/github", status_code=status.HTTP_202_ACCEPTED)
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(...),
    db: Session = Depends(get_db)
):
    """Receive and securely store raw webhook events from GitHub, triggering async processing."""
    # Read query parameters for scoping
    tenant_id = request.query_params.get("tenant_id")
    account_id = request.query_params.get("account_id")
    
    if not tenant_id or not account_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query parameters tenant_id and account_id are required"
        )

    # 1. Fetch connector account from Postgres to get webhook secret
    account = db.query(ConnectorAccountORM).filter_by(account_id=account_id, tenant_id=tenant_id).first()
    if not account:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Connector account not found"
        )

    body_bytes = await request.body()
    webhook_secret = account.config.get("webhook_secret", "test_secret")

    # 2. Verify signature in non-mock/production modes
    is_mock = account.config.get("mock") == True or os.environ.get("GITHUB_MOCK") == "true"
    if not is_mock and webhook_secret != "test_secret":
        if not x_hub_signature_256 or not verify_github_signature(body_bytes, webhook_secret, x_hub_signature_256):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid webhook signature payload"
            )

    # 3. Parse JSON body
    try:
        payload = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Malformed JSON body"
        )

    # 4. Generate SHA-256 payload hash
    payload_str = json.dumps(payload, sort_keys=True, default=str)
    payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

    event_id = str(uuid.uuid4())

    # 5. Save raw payload into MongoDB raw_events (with Idempotency check)
    mongo = MongoDBClient()
    try:
        mongo.connect()
        col = mongo.raw_events_collection
        
        # Deduplication check
        existing = col.find_one({"payload_hash": payload_hash, "tenant_id": tenant_id})
        if existing:
            # Idempotency return: already received and stored
            return {
                "status": "accepted",
                "event_id": existing["event_id"],
                "event_type": x_github_event,
                "duplicated": True
            }
            
        # Resolve external ID from webhook if possible
        external_id = str(
            payload.get("number") 
            or payload.get("id") 
            or payload.get("sha") 
            or payload.get("pull_request", {}).get("number")
            or "webhook-event"
        )
        
        col.insert_one({
            "event_id": event_id,
            "tenant_id": tenant_id,
            "connector_account_id": account_id,
            "source": "github",
            "provider": "github",
            "event_type": x_github_event,
            "external_id": external_id,
            "received_at": datetime.now(UTC),
            "sync_run_id": "webhook-run",
            "payload": payload,
            "payload_hash": payload_hash,
            "processing_status": "RECEIVED",
            "retry_count": 0
        })
    finally:
        mongo.disconnect()

    # 6. Audit webhook received action
    AuditLogService.log_action(
        db=db,
        tenant_id=tenant_id,
        actor_id=f"connector-{account_id}",
        actor_type="CONNECTOR",
        action="RECEIVE_WEBHOOK",
        entity_type="RAW_EVENT",
        entity_id=event_id,
        details={"event_type": x_github_event}
    )
    db.commit()

    # 7. Dispatch background task processing (normalization, correlation, evaluation)
    background_tasks.add_task(process_webhook_event_async, tenant_id, event_id)

    # Broadcast event
    try:
        from app.services.event_broker import event_broker
        event_broker.broadcast("EVIDENCE_ADDED", tenant_id, {
            "event_id": event_id,
            "event_type": x_github_event,
            "connector_account_id": account_id
        })
    except Exception:
        pass

    return {
        "status": "accepted",
        "event_id": event_id,
        "event_type": x_github_event
    }
