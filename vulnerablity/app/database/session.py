from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
import os
from app.core.config import settings

db_url = settings.DATABASE_URL
# If PostgreSQL is not active or fallback requested, use SQLite for local developer velocity
if settings.USE_SQLITE_FALLBACK and ("localhost" in db_url or "127.0.0.1" in db_url):
    # Try connecting to PostgreSQL, else fallback to SQLite
    try:
        import psycopg2
        test_engine = create_engine(db_url, connect_args={"connect_timeout": 1})
        with test_engine.connect() as conn:
            pass
        engine = create_engine(db_url, pool_pre_ping=True)
    except Exception:
        engine = create_engine(settings.SQLITE_URL, connect_args={"check_same_thread": False})
else:
    engine = create_engine(db_url, pool_pre_ping=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, expire_on_commit=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
