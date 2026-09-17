from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class Finding(BaseModel):
    """Domain model representing a compliance finding or violation."""
    finding_id: str = Field(..., description="Unique platform finding ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    check_id: str = Field(..., description="Check ID that failed and created this finding")
    control_id: str = Field(..., description="Control ID associated with the failed check")
    change_id: Optional[str] = Field(None, description="Linked Change ID if applicable")
    severity: str = Field(..., description="Severity level: low, medium, high, critical")
    title: str = Field(..., description="Summary of the compliance issue")
    description: str = Field(..., description="Detailed explanation of the failure and what triggered it")
    status: str = Field("OPEN", description="Status of the finding: OPEN, RESOLVED, SUPPRESSED")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = Field(None, description="When the finding was resolved")

    class Config:
        from_attributes = True
