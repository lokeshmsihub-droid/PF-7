import uuid
import hashlib
import json
from datetime import datetime, UTC
from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.db.mongodb import MongoDBClient
from app.models.orm import SyncRunORM, ConnectorAccountORM, ConnectorORM
from app.connectors.github.connector import GitHubConnector
from app.connectors.contract import ConnectionConfig, SyncRequest, SyncType, ConnectorType, AuthType

class CollectionService:
    """Orchestrates data extraction from connectors and loads raw events into MongoDB."""

    def __init__(self, db: Session):
        self.db = db
        self.mongo = MongoDBClient()

    def run_sync(self, tenant_id: str, account_id: str, repo_name: str, sync_type: SyncType = SyncType.INITIAL) -> Dict[str, Any]:
        # 1. Fetch connector account from Postgres
        account = self.db.query(ConnectorAccountORM).filter_by(account_id=account_id, tenant_id=tenant_id).first()
        if not account:
            raise ValueError(f"Connector account {account_id} not found for tenant {tenant_id}")

        # 2. Build ConnectionConfig
        connector_type_str = account.connector.type if account.connector else "github"
        try:
            conn_type = ConnectorType(connector_type_str.lower())
        except Exception:
            conn_type = ConnectorType.GITHUB

        try:
            auth_type = AuthType(account.auth_type)
        except Exception:
            auth_type = AuthType.PAT

        config = ConnectionConfig(
            connector_id=account.account_id,
            connector_type=conn_type,
            auth_type=auth_type,
            credentials=account.config,
            endpoint_url=None,
            rate_limit_concurrency=5,
            retry_attempts=3
        )

        # 3. Create SyncRun record in PostgreSQL
        sync_run_id = str(uuid.uuid4())
        sync_run = SyncRunORM(
            sync_run_id=sync_run_id,
            account_id=account_id,
            sync_type="INITIAL" if sync_type == SyncType.INITIAL else "INCREMENTAL",
            status="RUNNING",
            records_synced=0,
            started_at=datetime.now(UTC),
            completed_at=None,
            error_message=None
        )
        self.db.add(sync_run)
        self.db.commit()

        # 4. Instantiate Connector
        if conn_type == ConnectorType.JIRA:
            from app.connectors.jira.connector import JiraConnector
            connector = JiraConnector(config)
        else:
            connector = GitHubConnector(config)
        
        records_collected = 0
        records_failed = 0
        error_summary = None

        try:
            # Create SyncRequest parameters
            sync_req = SyncRequest(
                sync_run_id=sync_run_id,
                connector_id=account_id,
                sync_type=sync_type,
                parameters={"repository": repo_name}
            )

            # Retrieve payloads
            records = connector.collect(sync_req)

            # Store in MongoDB
            self.mongo.connect()
            col = self.mongo.raw_events_collection

            for rec in records:
                # Compute SHA-256 hash of unmodified payload
                payload_str = json.dumps(rec.payload, sort_keys=True, default=str)
                payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

                # Deduplicate check: look up in MongoDB
                existing = col.find_one({
                    "tenant_id": tenant_id,
                    "connector_account_id": account_id,
                    "external_id": rec.record_id,
                    "entity_type": rec.entity_type,
                    "payload_hash": payload_hash
                })

                if not existing:
                    event_id = str(uuid.uuid4())
                    col.insert_one({
                        "event_id": event_id,
                        "tenant_id": tenant_id,
                        "connector_account_id": account_id,
                        "source": "github",
                        "provider": "github",
                        "event_type": rec.entity_type,
                        "external_id": rec.record_id,
                        "received_at": datetime.now(UTC),
                        "sync_run_id": sync_run_id,
                        "payload": rec.payload,
                        "payload_hash": payload_hash
                    })
                    records_collected += 1
                else:
                    # Deduplicated, skip insertion but count as parsed
                    records_collected += 1

            # Update PostgreSQL sync run status to COMPLETED
            sync_run.status = "SUCCESS"
            sync_run.records_synced = records_collected
            sync_run.completed_at = datetime.now(UTC)
            self.db.commit()

        except Exception as e:
            records_failed = 1
            error_summary = str(e)
            
            sync_run.status = "FAILED"
            sync_run.error_message = error_summary
            sync_run.completed_at = datetime.now(UTC)
            self.db.commit()
        finally:
            self.mongo.disconnect()

        return {
            "sync_run_id": sync_run_id,
            "status": sync_run.status,
            "records_collected": records_collected,
            "records_failed": records_failed,
            "error_summary": error_summary
        }
