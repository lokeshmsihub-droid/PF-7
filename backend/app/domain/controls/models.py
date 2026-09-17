from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field

class EvidenceRequirement(BaseModel):
    """Structured representation of evidence required to satisfy a control or check."""
    evidence_type: str = Field(..., description="Type of evidence, e.g., TEST_REPORT, APPROVAL_LOG, COMMIT_LINK")
    required_source: str = Field(..., description="E.g., github_actions, jira, manual")
    required_fields: List[str] = Field(default_factory=list, description="Fields required in the evidence payload")
    retention_days: int = Field(365, description="Evidence retention policy in days")
    validation_method: str = Field("HASH", description="Method to validate evidence integrity: HASH, SIGNATURE, MANUAL")

class ControlDefinition(BaseModel):
    """Domain model for a compliance control in the Control Library."""
    control_id: str = Field(..., description="Internal platform control ID, e.g., CM-CONTROL-01")
    framework: str = Field("SOC 2", description="Compliance framework, e.g., SOC 2")
    criterion: str = Field("CC8.1", description="Target criterion, e.g., CC8.1")
    name: str = Field(..., description="Name of the control")
    objective: str = Field(..., description="Purpose/objective of this control")
    description: str = Field(..., description="Detailed description of the control requirements")
    lifecycle_stage: str = Field(..., description="Lifecycle stage, e.g., Authorization, Testing, Approval, etc.")
    applicability: str = Field("PRODUCTION", description="Where this control applies")
    evidence_requirements: List[EvidenceRequirement] = Field(default_factory=list, description="Structured evidence expectations")
    related_checks: List[str] = Field(default_factory=list, description="Internal check IDs implementing this control")
    status: str = Field("ACTIVE", description="Status of the control: ACTIVE, DRAFT, DEPRECATED")
    
    # Versioning
    version: str = Field("1.0.0", description="Version of control definition")
    effective_from: datetime = Field(default_factory=datetime.utcnow)
    effective_until: Optional[datetime] = Field(None, description="Expiration date of control version")
    
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True
