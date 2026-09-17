import os
import uuid
import hashlib
from datetime import datetime, UTC
from sqlalchemy.orm import Session
from app.models.orm import EvidenceMetadataORM
from app.core.config import settings

class EvidenceService:
    """Manages file storage, hash computation, and metadata records for compliance evidence objects."""

    def __init__(self, db: Session):
        self.db = db
        self.provider = settings.STORAGE_PROVIDER or "local"
        self.local_path = settings.LOCAL_STORAGE_PATH or "/tmp/compliance_evidence"
        self.bucket = settings.S3_BUCKET_NAME or "compliance-evidence-bucket"

    def store_evidence(
        self, tenant_id: str, change_id: str, file_name: str, content: bytes, content_type: str
    ) -> EvidenceMetadataORM:
        """Store raw evidence bytes to the active storage provider and record metadata in Postgres."""
        evidence_id = str(uuid.uuid4())
        
        # 1. Compute checksum
        sha256_hash = hashlib.sha256(content).hexdigest()
        file_size = len(content)

        # 2. Persist to storage provider
        storage_uri = ""
        if self.provider == "local":
            # Build tenant directory
            tenant_dir = os.path.join(self.local_path, tenant_id)
            os.makedirs(tenant_dir, exist_ok=True)
            
            # Write file
            file_path = os.path.join(tenant_dir, f"{evidence_id}_{file_name}")
            with open(file_path, "wb") as f:
                f.write(content)
            
            storage_uri = f"file://{file_path}"
        else:
            # Mock S3 storage provider
            storage_uri = f"s3://{self.bucket}/{tenant_id}/{evidence_id}_{file_name}"

        # 3. Save to database
        metadata = EvidenceMetadataORM(
            evidence_id=evidence_id,
            tenant_id=tenant_id,
            change_id=change_id,
            source="evaluation_engine",
            source_record_id=file_name,
            evidence_type=content_type,
            description=f"Evidence file {file_name}",
            hash=sha256_hash,
            storage_reference=storage_uri,
            collected_at=datetime.now(UTC)
        )
        self.db.add(metadata)
        self.db.commit()
        return metadata
