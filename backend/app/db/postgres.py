from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings

# Construct the SQLAlchemy engine
# pool_pre_ping=True helps detect disconnected database connections
engine = create_engine(
    settings.database_url,
    pool_pre_ping=True,
    echo=False
)

# Session factory for generating independent database session instances
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

def get_db() -> Generator[Session, None, None]:
    """Dependency generator to retrieve DB session context."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
