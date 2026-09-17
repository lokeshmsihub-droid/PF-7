import pytest
from app.connectors.contract import (
    BaseConnector, ConnectionConfig, ConnectionStatus, SyncRequest, SyncResult,
    CollectedRecord, ConnectorError, AuthType, ConnectorType
)
from app.domain.evidence.contract import EvidenceStorageProvider, StorageMetadata

# 1. Define concrete Mock classes for testing
class MockConnector(BaseConnector):
    def connect(self) -> bool:
        return True

    def disconnect(self) -> bool:
        return True

    def test_connection(self) -> ConnectionStatus:
        return ConnectionStatus(status="CONNECTED")

    def discover(self):
        return [{"id": "repo-1", "name": "app-repo"}]

    def collect(self, sync_request: SyncRequest):
        return [
            CollectedRecord(
                record_id="rec-1",
                connector_type=ConnectorType.GITHUB,
                entity_type="pull_request",
                payload={"id": 1, "title": "Mock PR"}
            )
        ]

    def sync(self, sync_request: SyncRequest) -> SyncResult:
        return SyncResult(
            sync_run_id=sync_request.sync_run_id,
            status="SUCCESS",
            records_synced=1,
            started_at=sync_request.since or sync_request.parameters.get("start")
        )

    def get_status(self) -> ConnectionStatus:
        return ConnectionStatus(status="CONNECTED")


class MockStorageProvider(EvidenceStorageProvider):
    def store_evidence(self, evidence_id: str, content: bytes, content_type: str, object_key: str) -> StorageMetadata:
        return StorageMetadata(
            evidence_id=evidence_id,
            storage_provider="local",
            storage_reference=f"local://{object_key}",
            object_key=object_key,
            content_type=content_type,
            file_hash="mock-hash",
            size=len(content)
        )

    def retrieve_evidence(self, storage_reference: str) -> bytes:
        return b"Mock Content"

    def delete_evidence(self, storage_reference: str) -> bool:
        return True


# 2. Test Cases
def test_connector_contract():
    config = ConnectionConfig(
        connector_id="conn-1",
        connector_type=ConnectorType.GITHUB,
        auth_type=AuthType.PAT,
        credentials={"token": "secret_pat_token"}
    )
    connector = MockConnector(config)
    
    # Verify connection test
    status = connector.test_connection()
    assert status.status == "CONNECTED"

    # Verify discovery
    res = connector.discover()
    assert len(res) == 1
    assert res[0]["name"] == "app-repo"

    # Verify collection
    req = SyncRequest(sync_run_id="sync-1", connector_id="conn-1")
    records = connector.collect(req)
    assert len(records) == 1
    assert records[0].record_id == "rec-1"
    assert records[0].payload["title"] == "Mock PR"


def test_evidence_storage_contract():
    provider = MockStorageProvider()
    metadata = provider.store_evidence(
        evidence_id="ev-123",
        content=b"Compliance evidence log content",
        content_type="text/plain",
        object_key="audit/ev-123.txt"
    )
    
    assert metadata.evidence_id == "ev-123"
    assert metadata.storage_provider == "local"
    assert metadata.storage_reference == "local://audit/ev-123.txt"
    assert metadata.size == 31
    
    content = provider.retrieve_evidence(metadata.storage_reference)
    assert content == b"Mock Content"
    
    deleted = provider.delete_evidence(metadata.storage_reference)
    assert deleted is True


def test_connector_error_raises():
    with pytest.raises(ConnectorError) as exc_info:
        raise ConnectorError("Authentication failed", connector_id="conn-1", retryable=False)
    assert exc_info.value.connector_id == "conn-1"
    assert exc_info.value.retryable is False
