from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

class ConnectorType(str, Enum):
    GITHUB = "github"
    JIRA = "jira"
    AWS = "aws"
    GITLAB = "gitlab"
    SERVICENOW = "servicenow"

class AuthType(str, Enum):
    PAT = "personal_access_token"
    OAUTH = "oauth2"
    OAUTH2 = "oauth2"
    ROLE_ARN = "aws_role_arn"
    BASIC = "basic_auth"


class ConnectionConfig(BaseModel):
    """Configuration required to connect to an external service."""
    connector_id: str = Field(..., description="Unique platform ID for this connection account")
    connector_type: ConnectorType = Field(..., description="E.g., github, jira, aws")
    auth_type: AuthType = Field(..., description="Authentication mechanism")
    credentials: Dict[str, Any] = Field(..., description="Credentials, tokens, keys, secrets")
    endpoint_url: Optional[str] = Field(None, description="Optional custom base URL for on-prem installations")
    rate_limit_concurrency: int = Field(5, description="Maximum concurrent requests to prevent rate limiting")
    retry_attempts: int = Field(3, description="Number of retries on network failures")

class ConnectionStatus(BaseModel):
    """The current health status of a connector link."""
    status: str = Field(..., description="CONNECTED, DISCONNECTED, ERROR")
    checked_at: datetime = Field(default_factory=datetime.utcnow)
    error_message: Optional[str] = Field(None, description="Details if status is ERROR")

class SyncType(str, Enum):
    INITIAL = "INITIAL"
    INCREMENTAL = "INCREMENTAL"

class SyncRequest(BaseModel):
    """Request payload triggering a data sync."""
    sync_run_id: str = Field(..., description="UUID for this sync execution")
    connector_id: str = Field(..., description="Target connection account ID")
    sync_type: SyncType = Field(SyncType.INCREMENTAL, description="Type of sync")
    since: Optional[datetime] = Field(None, description="Cursor for incremental sync")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Additional query parameters")

class SyncResult(BaseModel):
    """Result summary of a completed sync execution."""
    sync_run_id: str = Field(..., description="UUID for this sync execution")
    status: str = Field(..., description="SUCCESS, FAILED, RUNNING")
    records_synced: int = Field(0, description="Total records loaded")
    started_at: datetime = Field(..., description="Execution start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Execution end timestamp")
    error: Optional[str] = Field(None, description="Error message if sync failed")

class CollectedRecord(BaseModel):
    """Standardized wrapper for raw data pulled from connectors before storing in MongoDB."""
    record_id: str = Field(..., description="Unique ID assigned by external system")
    connector_type: ConnectorType = Field(..., description="System of origin")
    entity_type: str = Field(..., description="Type of external entity: pull_request, commit, issue, etc.")
    payload: Dict[str, Any] = Field(..., description="Unmodified raw payload from provider API")
    collected_at: datetime = Field(default_factory=datetime.utcnow)

class ConnectorError(Exception):
    """Base exception for connector operations."""
    def __init__(self, message: str, connector_id: Optional[str] = None, retryable: bool = False):
        super().__init__(message)
        self.message = message
        self.connector_id = connector_id
        self.retryable = retryable

class BaseConnector(ABC):
    """Abstract base class that all compliance data connectors must implement."""

    def __init__(self, config: ConnectionConfig):
        self.config = config

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection with the external API using connection config."""
        pass

    @abstractmethod
    def disconnect(self) -> bool:
        """Close external connections and release resources."""
        pass

    @abstractmethod
    def test_connection(self) -> ConnectionStatus:
        """Verify credentials and endpoint reachability."""
        pass

    @abstractmethod
    def discover(self) -> List[Dict[str, Any]]:
        """List accessible resources, e.g. repositories for GitHub, projects for Jira."""
        pass

    @abstractmethod
    def collect(self, sync_request: SyncRequest) -> List[CollectedRecord]:
        """Perform query to extract raw data according to request and return collected records."""
        pass

    @abstractmethod
    def sync(self, sync_request: SyncRequest) -> SyncResult:
        """High-level orchestration of initial or incremental sync."""
        pass

    @abstractmethod
    def get_status(self) -> ConnectionStatus:
        """Retrieve current connection status cache."""
        pass
