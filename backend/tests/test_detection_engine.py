"""Tests for DetectionEngine Orchestrator, Deduplication, and Evidence Persistence."""

import uuid
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select

from backend.app.detection.config import DetectionConfig
from backend.app.detection.engine import DetectionEngine
from backend.app.detection.rules import DEFAULT_RULES
from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent


def seed_test_events(db: Session) -> list[SecurityEvent]:
    """Seed a realistic set of security events into test database."""
    # Ensure clean state for deterministic counts
    db.query(AlertEvidence).delete()
    db.query(Alert).delete()
    db.query(SecurityEvent).delete()
    db.commit()

    now = datetime(2026, 9, 24, 10, 30, 0, tzinfo=timezone.utc)
    events = [
        # Scenario A & B: Brute force then success
        SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=now,
            event_type="authentication",
            source="windows_event",
            source_ip="198.51.100.101",
            destination_ip="10.0.1.100",
            username="Administrator",
            hostname="DC-PRIMARY-01",
            action="rdp_login",
            status="failure",
            severity="medium",
            message="Failed RDP logon attempt for user Administrator",
            raw_event={"test": 1},
            created_at=now,
        ),
        SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=15),
            event_type="authentication",
            source="windows_event",
            source_ip="198.51.100.101",
            destination_ip="10.0.1.100",
            username="Administrator",
            hostname="DC-PRIMARY-01",
            action="rdp_login",
            status="failure",
            severity="medium",
            message="Failed RDP logon attempt for user Administrator",
            raw_event={"test": 2},
            created_at=now,
        ),
        SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=now + timedelta(seconds=30),
            event_type="authentication",
            source="windows_event",
            source_ip="198.51.100.101",
            destination_ip="10.0.1.100",
            username="Administrator",
            hostname="DC-PRIMARY-01",
            action="rdp_login",
            status="failure",
            severity="medium",
            message="Failed RDP logon attempt for user Administrator",
            raw_event={"test": 3},
            created_at=now,
        ),
        # Scenario C: Privilege Escalation
        SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=now + timedelta(minutes=2),
            event_type="privilege_change",
            source="windows_event",
            source_ip="10.0.1.100",
            destination_ip="10.0.1.100",
            username="helpdesk_temp",
            hostname="DC-PRIMARY-01",
            action="group_membership_add",
            status="success",
            severity="critical",
            message="User helpdesk_temp added to Domain Admins security group",
            raw_event={"test": 4},
            created_at=now,
        ),
        # Benign routine event (must NOT trigger any alert)
        SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=now + timedelta(minutes=3),
            event_type="network",
            source="palo_alto_fw",
            source_ip="10.0.1.50",
            destination_ip="10.0.1.200",
            username=None,
            hostname="perimeter-fw-01",
            action="allow",
            status="success",
            severity="low",
            message="Permitted internal HTTPS traffic",
            raw_event={"test": 5},
            created_at=now,
        ),
    ]
    db.add_all(events)
    db.commit()
    return events


def test_detection_engine_execution_and_persistence(db_session: Session):
    """Verify detection engine runs, generates alerts, and stores evidence associations."""
    seed_test_events(db_session)
    engine = DetectionEngine()

    summary = engine.run_detection(db=db_session)

    assert summary.events_evaluated == 5
    assert summary.rules_executed == len(DEFAULT_RULES)
    assert summary.alerts_generated > 0
    assert summary.alerts_deduplicated == 0

    # Verify alerts exist in DB
    alerts = list(db_session.scalars(select(Alert)).all())
    assert len(alerts) == summary.alerts_generated

    # Verify evidence items exist and are linked
    for alert in alerts:
        assert len(alert.evidence) > 0
        for ev in alert.evidence:
            assert ev.event_id is not None
            assert ev.evidence_role is not None


def test_detection_engine_deduplication_on_second_run(db_session: Session):
    """Running detection twice against identical events produces ZERO duplicate alerts."""
    seed_test_events(db_session)
    engine = DetectionEngine()

    # First run
    run1 = engine.run_detection(db=db_session)
    initial_alerts_count = run1.alerts_generated
    assert initial_alerts_count > 0

    # Second run against the exact same data
    run2 = engine.run_detection(db=db_session)
    assert run2.alerts_generated == 0
    assert run2.alerts_deduplicated >= initial_alerts_count

    # Verify database count has not increased
    total_alerts_in_db = len(list(db_session.scalars(select(Alert)).all()))
    assert total_alerts_in_db == initial_alerts_count


def test_detection_engine_empty_event_set(db_session: Session):
    """Empty database produces 0 alerts safely without error."""
    db_session.query(AlertEvidence).delete()
    db_session.query(Alert).delete()
    db_session.query(SecurityEvent).delete()
    db_session.commit()

    engine = DetectionEngine()
    summary = engine.run_detection(db=db_session)

    assert summary.events_evaluated == 0
    assert summary.alerts_generated == 0
    assert summary.alerts_deduplicated == 0
