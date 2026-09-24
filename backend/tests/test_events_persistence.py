"""Tests for SecurityEvent SQLAlchemy Model and Database Persistence."""

from datetime import datetime, timezone
from backend.app.models.event import SecurityEvent


def test_security_event_persistence(db_session):
    """Verify persisting a SecurityEvent and querying by indexed fields."""
    now = datetime.now(timezone.utc)
    event = SecurityEvent(
        timestamp=now,
        event_type="authentication",
        source="linux_auth",
        source_ip="198.51.100.55",
        destination_ip="10.0.1.5",
        source_port=55123,
        destination_port=22,
        username="carol",
        hostname="bastion-02",
        action="login",
        status="failure",
        severity="medium",
        message="Failed password attempt",
        raw_event={"ip": "198.51.100.55", "user": "carol"},
        event_metadata={"auth_type": "ssh_password"},
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    assert event.id is not None
    assert len(event.id) == 36  # UUID v4 string
    assert event.username == "carol"
    assert event.source_ip == "198.51.100.55"
    assert event.raw_event["user"] == "carol"
    assert event.event_metadata["auth_type"] == "ssh_password"

    # Verify serialization
    as_dict = event.to_dict()
    assert as_dict["id"] == event.id
    assert as_dict["action"] == "login"
    assert as_dict["status"] == "failure"
