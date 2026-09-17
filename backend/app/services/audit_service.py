import uuid
import hashlib
from datetime import datetime, UTC
from typing import Optional
from sqlalchemy.orm import Session
from app.models.orm import AuditLogORM

class AuditLogService:
    """Manages audit logging, sequence counting, and SHA-256 event chaining for log records."""

    @staticmethod
    def log_action(
        db: Session,
        tenant_id: str,
        actor_id: str,
        actor_type: str,
        action: str,
        entity_type: str,
        entity_id: str,
        details: Optional[dict] = None
    ) -> AuditLogORM:
        """Append an audit record to the log. Computes next sequence index and links event hash."""
        # 1. Fetch last log to determine previous link in chain
        last_log = db.query(AuditLogORM).filter_by(tenant_id=tenant_id).order_by(AuditLogORM.sequence_number.desc()).first()
        
        next_seq = (last_log.sequence_number + 1) if last_log else 1
        prev_hash = last_log.event_hash if last_log else None
        
        event_id = str(uuid.uuid4())
        
        # 2. Compute cryptographic block hash
        hash_payload = f"{tenant_id}:{actor_id}:{actor_type}:{action}:{entity_type}:{entity_id}:{prev_hash or ''}:{next_seq}"
        event_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()
        
        log = AuditLogORM(
            tenant_id=tenant_id,
            actor_id=actor_id,
            actor_type=actor_type,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            details=details or {},
            event_id=event_id,
            previous_hash=prev_hash,
            event_hash=event_hash,
            sequence_number=next_seq,
            timestamp=datetime.now(UTC).replace(tzinfo=None)
        )
        
        db.add(log)
        db.flush() # Force ID generation
        return log
