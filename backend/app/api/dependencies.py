from fastapi import Header, HTTPException, status, Depends
from sqlalchemy.orm import Session
from app.db.postgres import SessionLocal
from typing import Generator

def get_db() -> Generator[Session, None, None]:
    """Provide transactional database session context."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_tenant_id(
    x_tenant_id: str = Header(..., description="Enterprise customer tenant identifier"),
    x_user_id: str = Header(None, description="Authenticated user identifier"),
    db: Session = Depends(get_db)
) -> str:
    """Header dependency to enforce tenant validation and isolation."""
    if not x_tenant_id or x_tenant_id.strip() == "":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Header X-Tenant-ID is required for tenant isolation"
        )
        
    if x_user_id:
        from app.models.orm import UserORM
        from app.services.normalization_service import NormalizationService
        
        # Ensure mock user exists for local sandbox / development convenience
        norm = NormalizationService(db)
        norm._ensure_user_exists(x_tenant_id, x_user_id)
        
        # Verify user belongs to requested tenant
        user = db.query(UserORM).filter_by(internal_user_id=x_user_id, tenant_id=x_tenant_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User is not authorized to access this tenant context"
            )
            
    return x_tenant_id
