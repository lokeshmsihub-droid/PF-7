import os
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.base import Base

# Force PostgreSQL test URL
TEST_DATABASE_URL = os.environ.get(
    "DATABASE_URL", 
    "postgresql://localhost/compliance_test_db"
)

@pytest.fixture(scope="session")
def engine():
    """Create a PostgreSQL test database engine."""
    engine = create_engine(TEST_DATABASE_URL)
    # Ensure tables are clean
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def db_session(engine):
    """Provide a transactional database session for each test function."""
    connection = engine.connect()
    transaction = connection.begin()
    Session = sessionmaker(bind=connection)
    session = Session()

    yield session

    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture(autouse=True)
def override_dependencies(db_session):
    """Override FastAPI's get_db dependency to use the test session."""
    from app.api.dependencies import get_db
    from app.main import app
    app.dependency_overrides[get_db] = lambda: db_session
    yield
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def mock_background_tasks(monkeypatch):
    """Automatically mock FastAPI BackgroundTasks to prevent async DB locks hanging the tests."""
    from fastapi.background import BackgroundTasks
    monkeypatch.setattr(BackgroundTasks, "add_task", lambda self, func, *args, **kwargs: None)

