import pytest
from app.connectors.github.connector import GitHubConnector
from app.connectors.contract import ConnectionConfig, ConnectorType, AuthType, SyncRequest, SyncType

@pytest.fixture
def mock_config():
    return ConnectionConfig(
        connector_id="conn-github-test",
        connector_type=ConnectorType.GITHUB,
        auth_type=AuthType.PAT,
        credentials={"mock": True},
        rate_limit_concurrency=5,
        retry_attempts=3
    )

def test_github_connection_test(mock_config):
    connector = GitHubConnector(mock_config)
    status = connector.test_connection()
    assert status.status == "CONNECTED"
    assert status.error_message is None

def test_github_discovery(mock_config):
    connector = GitHubConnector(mock_config)
    repos = connector.discover()
    assert len(repos) == 2
    assert repos[0]["name"] == "enterprise-auth-service"

def test_github_collection(mock_config):
    connector = GitHubConnector(mock_config)
    req = SyncRequest(
        sync_run_id="sync-123",
        connector_id="conn-github-test",
        sync_type=SyncType.INITIAL,
        parameters={"repository": "acme/enterprise-auth-service"}
    )
    records = connector.collect(req)
    assert len(records) > 0
    
    # Assert entity types collected
    entity_types = {r.entity_type for r in records}
    assert "pull_request" in entity_types
    assert "pull_request_review" in entity_types
    assert "commit" in entity_types
    assert "workflow_run" in entity_types
    assert "deployment" in entity_types
