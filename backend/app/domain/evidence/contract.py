from abc import ABC, abstractmethod
from datetime import datetime
from pydantic import BaseModel, Field

class StorageMetadata(BaseModel):
    """Metadata representing stored evidence in object storage."""
    evidence_id: str = Field(..., description="Platform evidence reference")
    storage_provider: str = Field(..., description="Storage backend, e.g. s3, gcs, local")
    storage_reference: str = Field(..., description="Unique URI referencing the file")
    object_key: str = Field(..., description="Path or key inside bucket")
    content_type: str = Field(..., description="MIME type of file")
    file_hash: str = Field(..., description="SHA-256 hash of file contents")
    size: int = Field(..., description="File size in bytes")
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True

class EvidenceStorageProvider(ABC):
    """Abstract base class defining the contract for object storage operations."""

    @abstractmethod
    def store_evidence(
        self, 
        evidence_id: str, 
        content: bytes, 
        content_type: str,
        object_key: str
    ) -> StorageMetadata:
        """Upload evidence file to object storage and return metadata."""
        pass

    @abstractmethod
    def retrieve_evidence(self, storage_reference: str) -> bytes:
        """Download/retrieve evidence file contents from object storage."""
        pass

    @abstractmethod
    def delete_evidence(self, storage_reference: str) -> bool:
        """Delete evidence file from object storage."""
        pass
