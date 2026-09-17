import pytest
from datetime import datetime
from app.connectors.jira.connector import JiraConnector
from app.connectors.contract import ConnectionConfig, ConnectorType, AuthType, SyncRequest, SyncType

@pytest.fixture
def mock_jira_config():
    return ConnectionConfig(
        connector_id="jira-test-1",
        connector_type=ConnectorType.JIRA,
        auth_type=AuthType.PAT,
        credentials={"mock": True}
    )

def test_jira_connector_mock_mode_connection(mock_jira_config):
    connector = JiraConnector(config=mock_jira_config)
    status = connector.test_connection()
    assert status.status == "CONNECTED"
    assert status.error_message is None

def test_jira_connector_discover(mock_jira_config):
    connector = JiraConnector(config=mock_jira_config)
    projects = connector.discover()
    assert len(projects) == 1
    assert projects[0]["key"] == "CHG"

def test_jira_connector_collect(mock_jira_config):
    connector = JiraConnector(config=mock_jira_config)
    req = SyncRequest(
        sync_run_id="run-1",
        connector_id="jira-test-1",
        sync_type=SyncType.INITIAL
    )
    records = connector.collect(req)
    assert len(records) == 2
    
    # Standard change
    assert records[0].record_id == "CHG-101"
    assert records[0].payload["fields"]["summary"].startswith("STANDARD:")
    assert records[0].payload["fields"]["customfield_risk"]["value"] == "Low"
    
    # Emergency change
    assert records[1].record_id == "CHG-104"
    assert records[1].payload["fields"]["summary"].startswith("EMERGENCY:")
    assert records[1].payload["fields"]["customfield_is_emergency"]["value"] == "Yes"
