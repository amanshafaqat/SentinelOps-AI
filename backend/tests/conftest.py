"""Pytest configuration and shared fixtures for SentinelOps AI."""

import os
import sys
from pathlib import Path
from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Set test environment
os.environ["APP_NAME"] = "SentinelOps AI"
os.environ["APP_ENV"] = "testing"
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from backend.app.main import create_application
from backend.app.db.base import Base
from backend.app.db.session import get_db
from backend.app.models import SecurityEvent, Alert, AlertEvidence, Incident, IncidentAuditLog


@pytest.fixture(scope="session")
def test_engine():
    """Create in-memory SQLite engine for testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def db_session(test_engine) -> Generator[Session, None, None]:
    """Provides a transactional database session rolled back after every test."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session_factory = sessionmaker(bind=connection)
    session = session_factory()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture(scope="module")
def app(test_engine):
    """Create FastAPI application with database dependency override."""
    application = create_application()

    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    def override_get_db():
        db = TestingSessionLocal()
        try:
            yield db
        finally:
            db.close()

    application.dependency_overrides[get_db] = override_get_db
    yield application
    application.dependency_overrides.clear()


@pytest.fixture(scope="module")
def client(app) -> Generator[TestClient, None, None]:
    """FastAPI TestClient fixture."""
    with TestClient(app=app, base_url="http://testserver") as test_client:
        yield test_client
