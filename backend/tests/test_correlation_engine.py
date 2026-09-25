"""Unit and integration tests for the deterministic Incident Correlation Engine."""

from datetime import datetime, timezone, timedelta
from typing import Optional
import uuid
import pytest
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent
from backend.app.models.incident import Incident, IncidentAuditLog
from backend.app.correlation.core import (
    IncidentSeverity,
    IncidentStatus,
    calculate_incident_severity,
    build_incident_narrative,
)
from backend.app.correlation.engine import CorrelationEngine, default_correlation_engine


@pytest.fixture(autouse=True)
def clean_database(db_session: Session):
    """Ensure clean table state before and after each test."""
    db_session.query(IncidentAuditLog).delete()
    db_session.query(AlertEvidence).delete()
    db_session.query(Alert).delete()
    db_session.query(Incident).delete()
    db_session.query(SecurityEvent).delete()
    db_session.commit()
    yield
    db_session.query(IncidentAuditLog).delete()
    db_session.query(AlertEvidence).delete()
    db_session.query(Alert).delete()
    db_session.query(Incident).delete()
    db_session.query(SecurityEvent).delete()
    db_session.commit()



def create_test_alert(
    rule_id: str = "RULE-001",
    rule_name: str = "Brute Force",
    title: str = "Brute Force Attack",
    severity: str = "medium",
    status: str = "new",
    affected_user: str = "Administrator",
    affected_ip: str = "198.51.100.42",
    affected_hostname: Optional[str] = None,
    detected_at: datetime = None,
    dedup_key: str = None,
) -> Alert:
    """Helper to instantiate an unpersisted Alert."""
    now = detected_at or datetime.now(timezone.utc)
    return Alert(
        id=str(uuid.uuid4()),
        rule_id=rule_id,
        rule_name=rule_name,
        title=title,
        description=f"Detection {rule_id} triggered for {affected_user}",
        severity=severity,
        status=status,
        dedup_key=dedup_key or str(uuid.uuid4()),
        affected_user=affected_user,
        affected_ip=affected_ip,
        affected_hostname=affected_hostname,
        detected_at=now,
        created_at=now,
    )


def test_severity_calculation_deterministic_rules():
    """Verify transparent severity logic across all conditions."""
    # 1. Critical alert present
    sev, reason = calculate_incident_severity(["medium", "critical"], ["RULE-001", "RULE-005"])
    assert sev == IncidentSeverity.CRITICAL.value
    assert "CRITICAL severity" in reason

    # 2. High alert + Attack progression -> elevated to Critical
    sev, reason = calculate_incident_severity(["high"], ["RULE-001", "RULE-002"], has_attack_progression=True)
    assert sev == IncidentSeverity.CRITICAL.value
    assert "attack progression" in reason

    # 3. High alert + >= 2 distinct rules -> elevated to Critical
    sev, reason = calculate_incident_severity(["high", "low"], ["RULE-001", "RULE-004"], has_attack_progression=False)
    assert sev == IncidentSeverity.CRITICAL.value
    assert "multiple distinct detection rules" in reason

    # 4. Standalone High alert -> High
    sev, reason = calculate_incident_severity(["high"], ["RULE-001"], has_attack_progression=False)
    assert sev == IncidentSeverity.HIGH.value

    # 5. Two Medium alerts -> compound elevated to High
    sev, reason = calculate_incident_severity(["medium", "medium"], ["RULE-001", "RULE-001"], has_attack_progression=False)
    assert sev == IncidentSeverity.HIGH.value
    assert "compound risk" in reason

    # 6. Single Medium alert -> Medium
    sev, reason = calculate_incident_severity(["medium"], ["RULE-001"], has_attack_progression=False)
    assert sev == IncidentSeverity.MEDIUM.value

    # 7. Low alerts -> Low
    sev, reason = calculate_incident_severity(["low", "low"], ["RULE-001"], has_attack_progression=False)
    assert sev == IncidentSeverity.LOW.value


def test_correlation_by_same_username(db_session: Session):
    """Alerts sharing the same username within the time window must correlate into one incident."""
    now = datetime(2026, 9, 24, 12, 0, 0, tzinfo=timezone.utc)
    a1 = create_test_alert(
        rule_id="RULE-001",
        affected_user="alice",
        affected_ip="192.168.1.10",
        detected_at=now,
    )
    a2 = create_test_alert(
        rule_id="RULE-002",
        affected_user="alice",
        affected_ip="192.168.1.20",  # Different IP, same user
        detected_at=now + timedelta(minutes=15),
    )
    db_session.add_all([a1, a2])
    db_session.commit()

    engine = CorrelationEngine(default_time_window_minutes=60)
    summary = engine.run_correlation(db_session, time_window_minutes=60)

    assert summary.incidents_created == 1
    assert summary.alerts_correlated == 2

    # Verify incident
    incident = db_session.query(Incident).filter(Incident.id == summary.created_incident_ids[0]).one()
    assert "alice" in incident.affected_users
    assert len(incident.alerts) == 2
    assert any("Targeted Identity: Common user account 'alice'" in r for r in incident.correlation_reasons)


def test_correlation_by_same_ip(db_session: Session):
    """Alerts sharing the same IP address within the time window must correlate even with different usernames."""
    now = datetime(2026, 9, 24, 13, 0, 0, tzinfo=timezone.utc)
    a1 = create_test_alert(
        rule_id="RULE-001",
        affected_user="root",
        affected_ip="198.51.100.99",
        detected_at=now,
    )
    a2 = create_test_alert(
        rule_id="RULE-001",
        affected_user="admin",
        affected_ip="198.51.100.99",  # Same IP, different user
        detected_at=now + timedelta(minutes=20),
    )
    db_session.add_all([a1, a2])
    db_session.commit()

    engine = CorrelationEngine(default_time_window_minutes=60)
    summary = engine.run_correlation(db_session, time_window_minutes=60)

    assert summary.incidents_created == 1
    assert summary.alerts_correlated == 2

    incident = db_session.query(Incident).filter(Incident.id == summary.created_incident_ids[0]).one()
    assert "198.51.100.99" in incident.affected_ips
    assert set(incident.affected_users) == {"admin", "root"}


def test_unrelated_alerts_remain_separate(db_session: Session):
    """Alerts with different usernames and different IPs must NOT correlate."""
    now = datetime(2026, 9, 24, 14, 0, 0, tzinfo=timezone.utc)
    a1 = create_test_alert(
        rule_id="RULE-001",
        affected_user="user_alpha",
        affected_ip="10.0.0.1",
        detected_at=now,
    )
    a2 = create_test_alert(
        rule_id="RULE-003",
        affected_user="user_beta",
        affected_ip="10.0.0.2",
        detected_at=now + timedelta(minutes=10),
    )
    db_session.add_all([a1, a2])
    db_session.commit()

    engine = CorrelationEngine(default_time_window_minutes=60)
    summary = engine.run_correlation(db_session, time_window_minutes=60)

    # 2 completely distinct clusters -> 2 separate incidents
    assert summary.incidents_created == 2
    assert summary.alerts_correlated == 2


def test_time_window_boundary_enforcement(db_session: Session):
    """Alerts sharing entities that occur outside the time window must NOT correlate."""
    base_time = datetime(2026, 9, 24, 10, 0, 0, tzinfo=timezone.utc)
    # Alert 1 at T=0
    a1 = create_test_alert(
        rule_id="RULE-001",
        affected_user="target_user",
        affected_ip="198.51.100.5",
        detected_at=base_time,
    )
    # Alert 2 at T=65 minutes (exceeds 60m window)
    a2 = create_test_alert(
        rule_id="RULE-001",
        affected_user="target_user",
        affected_ip="198.51.100.5",
        detected_at=base_time + timedelta(minutes=65),
    )
    db_session.add_all([a1, a2])
    db_session.commit()

    engine = CorrelationEngine(default_time_window_minutes=60)
    summary = engine.run_correlation(db_session, time_window_minutes=60)

    # Since delta is 65m > 60m, they should NOT be grouped together
    assert summary.incidents_created == 2
    assert summary.alerts_correlated == 2


def test_repeated_execution_idempotency(db_session: Session):
    """Running correlation repeatedly must NOT create duplicate incidents or re-correlate already linked alerts."""
    now = datetime(2026, 9, 24, 15, 0, 0, tzinfo=timezone.utc)
    a1 = create_test_alert(affected_user="charlie", affected_ip="192.168.5.5", detected_at=now)
    a2 = create_test_alert(affected_user="charlie", affected_ip="192.168.5.5", detected_at=now + timedelta(minutes=5))
    db_session.add_all([a1, a2])
    db_session.commit()

    engine = CorrelationEngine(default_time_window_minutes=60)

    # First run
    run1 = engine.run_correlation(db_session, time_window_minutes=60)
    assert run1.incidents_created == 1
    assert run1.alerts_correlated == 2

    incidents_count_1 = db_session.query(Incident).count()
    assert incidents_count_1 == 1

    # Second run immediately without new alerts
    run2 = engine.run_correlation(db_session, time_window_minutes=60)
    assert run2.incidents_created == 0
    assert run2.alerts_evaluated == 0
    assert run2.alerts_correlated == 0

    incidents_count_2 = db_session.query(Incident).count()
    assert incidents_count_2 == 1  # Exactly identical, no duplicate!


def test_incremental_correlation_merges_into_active_incident(db_session: Session):
    """A newly arrived alert matching an active incident should merge into that incident."""
    now = datetime(2026, 9, 24, 16, 0, 0, tzinfo=timezone.utc)
    a1 = create_test_alert(affected_user="david", affected_ip="10.10.10.10", detected_at=now)
    db_session.add(a1)
    db_session.commit()

    engine = CorrelationEngine(default_time_window_minutes=60)
    run1 = engine.run_correlation(db_session, time_window_minutes=60)
    assert run1.incidents_created == 1
    inc_id = run1.created_incident_ids[0]

    # Later, new alert arrives for same user within 20 minutes
    a2 = create_test_alert(affected_user="david", affected_ip="10.10.10.20", detected_at=now + timedelta(minutes=20))
    db_session.add(a2)
    db_session.commit()

    run2 = engine.run_correlation(db_session, time_window_minutes=60)
    assert run2.incidents_created == 0
    assert run2.incidents_updated == 1
    assert run2.alerts_correlated == 1

    # Verify incident now has 2 alerts
    incident = db_session.query(Incident).filter(Incident.id == inc_id).one()
    assert len(incident.alerts) == 2
    assert "10.10.10.20" in incident.affected_ips

    # Verify audit log recorded alert_added
    audits = db_session.query(IncidentAuditLog).filter(IncidentAuditLog.incident_id == inc_id).all()
    assert any(audit.action == "alert_added" for audit in audits)


def test_missing_optional_fields_resilience(db_session: Session):
    """Alerts with null username or null IP correlate gracefully if other signals match."""
    now = datetime(2026, 9, 24, 17, 0, 0, tzinfo=timezone.utc)
    # Alert with only IP (no user)
    a1 = create_test_alert(affected_user=None, affected_ip="198.51.100.77", detected_at=now)
    # Alert with IP and user
    a2 = create_test_alert(affected_user="eve", affected_ip="198.51.100.77", detected_at=now + timedelta(minutes=5))
    db_session.add_all([a1, a2])
    db_session.commit()

    engine = CorrelationEngine(default_time_window_minutes=60)
    summary = engine.run_correlation(db_session, time_window_minutes=60)

    assert summary.incidents_created == 1
    assert summary.alerts_correlated == 2

    incident = db_session.query(Incident).filter(Incident.id == summary.created_incident_ids[0]).one()
    assert incident.affected_ips == ["198.51.100.77"]
    assert incident.affected_users == ["eve"]
