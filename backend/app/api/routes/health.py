from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import text
from app.api.dependencies import get_db
from app.db.mongodb import MongoDBClient

router = APIRouter()

@router.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    """Simple Liveness probe."""
    return {"status": "healthy", "timestamp": "OK"}

@router.get("/ready", status_code=status.HTTP_200_OK)
def readiness_check(db: Session = Depends(get_db)):
    """Readiness probe checking relational and document databases health status."""
    postgres_ok = False
    mongodb_ok = False
    
    # 1. Verify PostgreSQL
    try:
        db.execute(text("SELECT 1"))
        postgres_ok = True
    except Exception as e:
        # Avoid exposing raw postgres errors in response
        postgres_ok = False

    # 2. Verify MongoDB
    try:
        mongo_client = MongoDBClient()
        mongo_client.connect()
        # Verify connectivity by running ping command
        mongo_client.db.command("ping")
        mongo_client.disconnect()
        mongodb_ok = True
    except Exception as e:
        mongodb_ok = False

    if not postgres_ok or not mongodb_ok:
        details = {
            "postgresql": "UP" if postgres_ok else "DOWN",
            "mongodb": "UP" if mongodb_ok else "DOWN"
        }
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"message": "Service dependencies not ready", "status": details}
        )

    return {
        "status": "ready",
        "dependencies": {
            "postgresql": "UP",
            "mongodb": "UP"
        }
    }
