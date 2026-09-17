import pytest
import os
import shutil
import tempfile
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from app.database.session import Base
from app.database.models import Tenant

@pytest.fixture(scope="session")
def test_db_engine():
    # In-memory SQLite for high-speed isolated testing
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    return engine

@pytest.fixture(scope="function")
def db_session(test_db_engine):
    Session = sessionmaker(bind=test_db_engine, expire_on_commit=False)
    session = Session()

    # Seed default tenant
    tenant = session.query(Tenant).filter(Tenant.id == 1).first()
    if not tenant:
        tenant = Tenant(id=1, name="Test Corporate Tenant")
        session.add(tenant)
        session.commit()

    yield session

    session.close()
    # Clean tables for next test
    for table in reversed(Base.metadata.sorted_tables):
        test_db_engine.execute(table.delete()) if hasattr(test_db_engine, 'execute') else None
    with test_db_engine.connect() as conn:
        for table in reversed(Base.metadata.sorted_tables):
            conn.execute(table.delete())
        conn.commit()

@pytest.fixture(scope="function")
def mock_repo_workspace():
    """
    Creates a temporary realistic code repository containing Python, JS, configs, and bad code.
    """
    temp_dir = tempfile.mkdtemp(prefix="mock_repo_")
    
    # Python source file
    py_code = """
import os

SECRET_KEY = "super-secret-token-12345"

def run_query(user_input):
    print("Executing query with " + user_input)
"""
    with open(os.path.join(temp_dir, "server.py"), "w") as f:
        f.write(py_code)

    # JS source file
    js_code = """
const express = require('express');
const app = express();
app.listen(3000);
"""
    with open(os.path.join(temp_dir, "index.js"), "w") as f:
        f.write(js_code)

    # Package json
    pkg_json = '{"name": "test-app", "dependencies": {"react": "^18.0.0", "express": "^4.18.0"}}'
    with open(os.path.join(temp_dir, "package.json"), "w") as f:
        f.write(pkg_json)

    # Requirements txt
    with open(os.path.join(temp_dir, "requirements.txt"), "w") as f:
        f.write("fastapi==0.100.0\nuvicorn==0.22.0\n")

    # Excluded directory (should be ignored)
    ignored_dir = os.path.join(temp_dir, "node_modules", "some_pkg")
    os.makedirs(ignored_dir, exist_ok=True)
    with open(os.path.join(ignored_dir, "ignored.js"), "w") as f:
        f.write("console.log('ignore me');")

    yield temp_dir

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir, ignore_errors=True)
