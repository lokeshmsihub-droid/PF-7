from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field

class RemediationTask(BaseModel):
    """Domain model representing a task assigned to fix a compliance finding."""
    task_id: str = Field(..., description="Unique platform task ID")
    tenant_id: str = Field(..., description="Enterprise organization tenant ID")
    finding_id: str = Field(..., description="ID of the finding that needs remediation")
    title: str = Field(..., description="Brief title of remediation work")
    description: str = Field(..., description="Details of steps to fix the issue")
    owner: str = Field(..., description="Assigned individual or team responsible for fix")
    priority: str = Field("medium", description="Priority level: low, medium, high, critical")
    due_date: Optional[datetime] = Field(None)
    status: str = Field("PENDING", description="Status: PENDING, IN_PROGRESS, RESOLVED, CANCELLED")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = Field(None)
    
    class Config:
        from_attributes = True
