"""Tests for Database Session, Engine, and Connectivity."""

from sqlalchemy import text, Column, Integer, String
from backend.app.db.base import Base, TimestampMixin
from backend.app.db.session import check_database_connection


class DummyIncident(Base, TimestampMixin):
    """Test model to verify declarative base and timestamp mixin."""
    __tablename__ = "test_incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    title = Column(String(100), nullable=False)


def test_declarative_base_and_mixin(db_session):
    """Verify model creation and timestamps."""
    Base.metadata.create_all(bind=db_session.get_bind())

    incident = DummyIncident(title="Suspicious Brute Force Attempt")
    db_session.add(incident)
    db_session.commit()
    db_session.refresh(incident)

    assert incident.id is not None
    assert incident.title == "Suspicious Brute Force Attempt"
    assert incident.created_at is not None
    assert incident.updated_at is not None

    as_dict = incident.to_dict()
    assert as_dict["title"] == "Suspicious Brute Force Attempt"
    assert "created_at" in as_dict


def test_database_connectivity_check():
    """Verify check_database_connection returns valid structured status."""
    result = check_database_connection()
    assert "status" in result
    assert "dialect" in result
    assert "latency_ms" in result
    assert result["status"] in ["connected", "disconnected", "error"]
