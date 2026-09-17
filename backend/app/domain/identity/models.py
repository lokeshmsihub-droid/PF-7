from typing import Optional
from pydantic import BaseModel, Field

class User(BaseModel):
    """Domain model for a platform user/actor."""
    internal_user_id: str = Field(..., description="Unique platform user ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    name: str = Field(..., description="User's full name")
    email: str = Field(..., description="User's email address")
    role: str = Field(..., description="User's organizational role, e.g. Developer, Admin")
    status: str = Field("ACTIVE", description="User status: ACTIVE, INACTIVE")

    class Config:
        from_attributes = True

class IdentityLink(BaseModel):
    """Domain model mapping internal users to external identities (GitHub, Jira, AWS, etc.)."""
    internal_user_id: str = Field(..., description="Platform user reference")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    source: str = Field(..., description="External system name, e.g., github, jira, aws")
    external_user_id: str = Field(..., description="External system user identifier")
    external_username: str = Field(..., description="External username (handle/email)")
    external_reference: Optional[str] = Field(None, description="Optional extra metadata reference")
    status: str = Field("ACTIVE", description="Link status: ACTIVE, DEPRECATED")

    class Config:
        from_attributes = True
