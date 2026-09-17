from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class ExceptionModel(BaseModel):
    """Domain model for compliance policy exceptions."""
    exception_id: str = Field(..., description="Unique platform exception ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    control_id: str = Field(..., description="Control ID that is temporarily bypassed")
    change_id: Optional[str] = Field(None, description="Linked Change ID if exception is specific to a ticket")
    requested_by: str = Field(..., description="User ID requesting the exception")
    approved_by: str = Field(..., description="Authorized role/user who approved the exception")
    justification: str = Field(..., description="Justification explaining why control cannot be met")
    valid_from: datetime = Field(default_factory=datetime.utcnow)
    valid_until: datetime = Field(..., description="Expiration date of the policy exception")
    status: str = Field("ACTIVE", description="Status: ACTIVE, EXPIRED, REVOKED")

    class Config:
        from_attributes = True
        populate_by_name = True
