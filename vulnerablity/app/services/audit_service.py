import uuid
import datetime
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from app.database.models import AuditLog

class AuditService:
    """
    Maintains an immutable audit trail for every security and compliance action.
    """

    def __init__(self, db: Session):
        self.db = db

    def log_event(
        self,
        tenant_id: int,
        action: str,
        resource_type: str,
        resource_id: str,
        details: Optional[Dict[str, Any]] = None,
        actor: str = "system",
        result: str = "SUCCESS"
    ) -> AuditLog:
        audit_entry = AuditLog(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            actor=actor,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            result=result,
            created_at=datetime.datetime.now(datetime.timezone.utc)
        )
        self.db.add(audit_entry)
        self.db.commit()
        return audit_entry
