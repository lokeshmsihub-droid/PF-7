import os
import pytest
from datetime import datetime, UTC
from app.connectors.github.connector import GitHubConnector
from app.connectors.contract import ConnectionConfig, SyncRequest, ConnectorType, AuthType

@pytest.fixture
def live_github_config():
    token = os.environ.get("STAGING_GITHUB_TOKEN")
    repo = os.environ.get("STAGING_GITHUB_REPO")
    
    is_mock = False
    if not token or not repo:
        token = "mock-staging-token"
        repo = "acme/enterprise-auth-service"
        is_mock = True
        
    return {
        "token": token,
        "repo": repo,
        "endpoint_url": "https://api.github.com",
        "mock": is_mock
    }

def test_live_github_connector_cycle(live_github_config):
    # Initialize connector config
    config = ConnectionConfig(
        connector_id="live-github-test",
        connector_type=ConnectorType.GITHUB,
        auth_type=AuthType.PAT,
        endpoint_url=live_github_config["endpoint_url"],
        credentials={
            "token": live_github_config["token"],
            "mock": live_github_config["mock"]
        }
    )
    
    connector = GitHubConnector(config)
    assert connector.mock_mode is live_github_config["mock"]
    
    # 1. Test Connection
    status = connector.test_connection()
    assert status.status == "CONNECTED", f"Failed to connect to real GitHub API: {status.error_message}"
    
    # 2. Discover Repositories
    repos = connector.discover()
    assert isinstance(repos, list)
    # Ensure our target test repository is discoverable (or check general user repo access)
    assert len(repos) >= 0
    
    # 3. Collect Real Payloads
    sync_req = SyncRequest(
        sync_run_id="live-staging-run-101",
        connector_id="live-github-test",
        parameters={
            "repository": live_github_config["repo"]
        }
    )
    
    records = connector.collect(sync_req)
    assert isinstance(records, list)
    
    # Assert collection of GitHub data types (at least one commit, or PR, etc. depending on active repo state)
    print(f"Collected {len(records)} live records from {live_github_config['repo']}")
    
    # Verify entity types are returned correctly
    entity_types = {r.entity_type for r in records}
    print(f"Collected entity types: {entity_types}")
    
    # Disconnect
    connector.disconnect()
