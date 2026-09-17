from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field

class ChangeType(str, Enum):
    NORMAL = "NORMAL"
    STANDARD = "STANDARD"
    EMERGENCY = "EMERGENCY"

class TestStatus(str, Enum):
    __test__ = False
    PASS = "PASS"
    FAIL = "FAIL"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"

class EnvType(str, Enum):
    DEVELOPMENT = "DEVELOPMENT"
    TEST = "TEST"
    STAGING = "STAGING"
    PRODUCTION = "PRODUCTION"

class Environment(BaseModel):
    """Domain model for deployment environments."""
    environment_id: str = Field(..., description="Unique platform environment ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    name: str = Field(..., description="Friendly name, e.g., Production AWS US-East")
    type: EnvType = Field(..., description="Generic environment type")
    criticality: str = Field("HIGH", description="Tier or criticality level, e.g. HIGH, MEDIUM, LOW")

    class Config:
        from_attributes = True

class Application(BaseModel):
    """Domain model for systems/applications managed by the platform."""
    application_id: str = Field(..., description="Unique application ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    name: str = Field(..., description="Application name")
    owner: str = Field(..., description="Owner email or team ID")
    environment_id: str = Field(..., description="Target environment ID")
    criticality: str = Field("HIGH", description="Tier or criticality, e.g. TIER-1, TIER-2")
    status: str = Field("ACTIVE", description="Application status: ACTIVE, DECOMMISSIONED")

    class Config:
        from_attributes = True

class Repository(BaseModel):
    """Domain model for a source code repository, vendor-neutral."""
    repository_id: str = Field(..., description="Platform repository ID")
    external_id: str = Field(..., description="Provider's repository ID")
    name: str = Field(..., description="Repository name")
    provider: str = Field(..., description="Source code provider: github, gitlab, bitbucket")
    organization: str = Field(..., description="Org or user namespace")
    default_branch: str = Field("main", description="Default branch name")
    production_branch: str = Field("production", description="Production branch name")
    status: str = Field("ACTIVE", description="Repository sync status: ACTIVE, INACTIVE")

    class Config:
        from_attributes = True

class Change(BaseModel):
    """Canonical representation of a Change entity (from Jira, ServiceNow, etc.)."""
    change_id: str = Field(..., description="Internal platform compliance change ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    external_id: str = Field(..., description="External system change ID (e.g. ticket key JIRA-101)")
    source: str = Field(..., description="System of origin, e.g. jira, servicenow, github_pr")
    title: str = Field(..., description="Title of the change")
    description: Optional[str] = Field(None, description="Detailed description of the change")
    change_type: ChangeType = Field(..., description="NORMAL, STANDARD, or EMERGENCY")
    requester_id: str = Field(..., description="Platform User ID requesting the change")
    owner_id: str = Field(..., description="Platform User ID of the owner of the change execution")
    risk_level: str = Field("MEDIUM", description="Risk level: LOW, MEDIUM, HIGH")
    environment_id: str = Field(..., description="Target platform environment ID")
    application_id: str = Field(..., description="Target platform application ID")
    status: str = Field(..., description="Status of the change in its lifecycle")
    planned_start: Optional[datetime] = Field(None)
    planned_end: Optional[datetime] = Field(None)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    implemented_at: Optional[datetime] = Field(None)
    completed_at: Optional[datetime] = Field(None)

    class Config:
        from_attributes = True

class Authorization(BaseModel):
    """Domain model for an authorization to proceed with design/development of a change."""
    authorization_id: str = Field(..., description="Unique platform authorization ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    change_id: str = Field(..., description="Reference to the Change")
    authorized_by: str = Field(..., description="Platform User ID authorizing the change")
    status: str = Field(..., description="Status of authorization: APPROVED, DENIED, PENDING")
    authorized_at: datetime = Field(default_factory=datetime.utcnow)
    justification: Optional[str] = Field(None, description="Reasoning/justification for authorization")
    source: str = Field(..., description="Source system generating authorization, e.g., jira, slack")

    class Config:
        from_attributes = True

class Approval(BaseModel):
    """Domain model for post-testing release/deployment approval."""
    approval_id: str = Field(..., description="Unique platform approval ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    change_id: str = Field(..., description="Reference to the Change")
    approver_id: str = Field(..., description="Platform User ID who approved or rejected")
    role: str = Field(..., description="Role of the approver, e.g., QA, Manager, CAB")
    decision: str = Field(..., description="Decision: APPROVED, REJECTED")
    approved_at: datetime = Field(default_factory=datetime.utcnow)
    source: str = Field(..., description="Source of the approval action")

    class Config:
        from_attributes = True

class Test(BaseModel):
    """Domain model for test runs associated with the change."""
    __test__ = False
    test_id: str = Field(..., description="Unique platform test run ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    change_id: str = Field(..., description="Reference to the Change")
    source: str = Field(..., description="Testing tool source, e.g. github_actions, jenkins, sonar")
    pipeline_id: str = Field(..., description="CI pipeline or run identifier")
    commit_id: str = Field(..., description="Git commit hash being tested")
    test_type: str = Field(..., description="Type: UNIT, INTEGRATION, SECURITY, MANUAL")
    status: TestStatus = Field(..., description="PASS, FAIL, CANCELLED, UNKNOWN")
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = Field(None)
    evidence_reference: Optional[str] = Field(None, description="Link or reference to raw test results evidence")

    class Config:
        from_attributes = True

class Deployment(BaseModel):
    """Domain model for a code deployment event."""
    deployment_id: str = Field(..., description="Unique platform deployment ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    change_id: Optional[str] = Field(None, description="Linked Change ID. Can be null if unauthorized bypass change.")
    application_id: str = Field(..., description="Target platform application ID")
    environment_id: str = Field(..., description="Target environment ID")
    version: str = Field(..., description="Release version tag or label")
    commit_id: str = Field(..., description="Git commit hash deployed")
    repository_id: str = Field(..., description="Linked platform repository ID")
    deployed_by: str = Field(..., description="Platform User ID executing deployment")
    deployed_at: datetime = Field(default_factory=datetime.utcnow)
    status: str = Field(..., description="Deployment status: SUCCESS, FAILED, IN_PROGRESS")
    source: str = Field(..., description="Deployment origin tool: github_actions, argo_cd, aws_codedeploy")

    class Config:
        from_attributes = True
