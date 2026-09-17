from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class Evidence(BaseModel):
    """Domain model representing evidence metadata for compliance verification."""
    evidence_id: str = Field(..., description="Unique platform evidence ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    source: str = Field(..., description="Origin system of the evidence, e.g. github_actions, jira")
    source_record_id: str = Field(..., description="External system record ID from which evidence is gathered")
    evidence_type: str = Field(..., description="Type of evidence, e.g., TEST_REPORT, APPROVAL_LOG, COMMIT_HASH")
    description: Optional[str] = Field(None, description="Detailed description of what the evidence proves")
    hash: str = Field(..., description="SHA-256 hash of the evidence file payload")
    storage_reference: str = Field(..., description="Path/URI to evidence in object storage")
    collected_at: datetime = Field(default_factory=datetime.utcnow, description="When compliance tool collected it")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="When external system created it")

    class Config:
        from_attributes = True
