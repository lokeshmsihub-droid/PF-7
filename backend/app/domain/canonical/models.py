import enum
from datetime import datetime
from typing import List, Optional, Union
from pydantic import BaseModel, Field

class DataAvailability(str, enum.Enum):
    AVAILABLE = "AVAILABLE"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"

class IdentityResolutionStatus(str, enum.Enum):
    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"
    AMBIGUOUS = "AMBIGUOUS"

class CanonicalEvent(BaseModel):
    event_id: str = Field(..., description="Unique platform event ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    source: str = Field(..., description="Source connector system (e.g. github)")
    event_type: str = Field(..., description="Event type string (e.g. pull_request)")
    external_event_id: Optional[str] = Field(None, description="External provider-level delivery or message ID")
    entity_type: str = Field(..., description="Standard entity mapped (e.g. change)")
    entity_id: str = Field(..., description="Target platform entity identifier (e.g. change_id)")
    actor_id: str = Field(..., description="Enterprise platform user ID of actor executing trigger")
    timestamp: datetime = Field(..., description="Timestamp event was triggered/received in naive UTC")

class CanonicalChangeIdentity(BaseModel):
    change_id: str
    tenant_id: str
    source: str
    external_id: str

class CanonicalChangeBasicInfo(BaseModel):
    title: str
    description: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    change_type: str  # NORMAL, STANDARD, EMERGENCY
    status: str
    risk_level: str
    environment: str

class CanonicalChangeRequest(BaseModel):
    requester_id: str
    owner_id: str
    created_at: datetime
    requested_at: Optional[Union[datetime, DataAvailability]] = DataAvailability.UNKNOWN

class CanonicalChangeAuthorization(BaseModel):
    required: Union[bool, DataAvailability] = DataAvailability.UNKNOWN
    authorized: Optional[Union[bool, DataAvailability]] = DataAvailability.UNKNOWN
    authorized_by: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    authorized_at: Optional[Union[datetime, DataAvailability]] = DataAvailability.UNKNOWN
    reference: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN

class CanonicalChangeDevelopment(BaseModel):
    repository: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    branch: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    pull_request_id: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    commit_id: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    changed_components: Union[List[str], DataAvailability] = DataAvailability.UNKNOWN

class CanonicalChangeTesting(BaseModel):
    required: Union[bool, DataAvailability] = DataAvailability.UNKNOWN
    test_id: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    test_type: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    test_status: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    tested_at: Optional[Union[datetime, DataAvailability]] = DataAvailability.UNKNOWN
    evidence_reference: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    evidence_ref: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN

class CanonicalChangeApproval(BaseModel):
    required: Union[bool, DataAvailability] = DataAvailability.UNKNOWN
    approved: Optional[Union[bool, DataAvailability]] = DataAvailability.UNKNOWN
    approver_id: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    approved_at: Optional[Union[datetime, DataAvailability]] = DataAvailability.UNKNOWN
    reference: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN

class CanonicalChangeDeployment(BaseModel):
    deployment_id: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    environment: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    deployed_by: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    deployed_at: Optional[Union[datetime, DataAvailability]] = DataAvailability.UNKNOWN
    deployment_status: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    status: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    version: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN

class CanonicalChangeRollback(BaseModel):
    rollback_plan: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    rollback_tested: Optional[Union[bool, DataAvailability]] = DataAvailability.UNKNOWN
    rollback_reference: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN

class CanonicalChangeEmergency(BaseModel):
    is_emergency: Union[bool, DataAvailability] = DataAvailability.UNKNOWN
    reason: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    emergency_approved_by: Optional[Union[str, DataAvailability]] = DataAvailability.UNKNOWN
    retro_approval: Optional[Union[bool, DataAvailability]] = DataAvailability.UNKNOWN

class CanonicalChange(BaseModel):
    identity: CanonicalChangeIdentity
    basic_info: CanonicalChangeBasicInfo
    request: CanonicalChangeRequest
    authorization: CanonicalChangeAuthorization
    development: CanonicalChangeDevelopment
    testing: CanonicalChangeTesting
    approval: CanonicalChangeApproval
    deployment: CanonicalChangeDeployment
    rollback: CanonicalChangeRollback
    emergency: CanonicalChangeEmergency
    evidence_ids: List[str] = []
