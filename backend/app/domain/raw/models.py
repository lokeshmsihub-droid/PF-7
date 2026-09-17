from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

class RawEvent(BaseModel):
    """Pydantic representation of the MongoDB raw_events collection document."""
    event_id: str = Field(..., description="Unique platform event ID (e.g. UUID)")
    source: str = Field(..., description="Source of the event, e.g. github_webhook, jira_sync")
    connector_type: str = Field(..., description="Type of connector: github, jira, aws, etc.")
    event_type: str = Field(..., description="Event action: pull_request.opened, issue.updated, etc.")
    external_id: str = Field(..., description="The unique ID from the external system")
    received_at: datetime = Field(default_factory=datetime.utcnow, description="Ingest timestamp")
    payload: Dict[str, Any] = Field(..., description="Unmodified original JSON payload from external source")
    sync_run_id: Optional[str] = Field(None, description="Linked sync run execution ID if sync-based")
    payload_hash: str = Field(..., description="SHA-256 hash of the raw payload for tamper-proofing")

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "event_id": "evt-77b31278-ca65-4fa3-90d2",
                "source": "github_webhook",
                "connector_type": "github",
                "event_type": "pull_request.closed",
                "external_id": "pr_102484",
                "received_at": "2026-08-22T11:56:00Z",
                "payload": {
                    "action": "closed",
                    "number": 102,
                    "pull_request": {
                        "id": 102484,
                        "title": "Fix memory leak in connector",
                        "user": {"login": "octocat"}
                    }
                },
                "sync_run_id": "sync-12345",
                "payload_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            }
        }
