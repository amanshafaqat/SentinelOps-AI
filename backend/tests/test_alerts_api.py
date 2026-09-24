"""API Integration Tests for Detection and Alerts Endpoints."""

import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent


def test_detection_run_endpoint(client: TestClient, db_session: Session):
    """POST /api/v1/detection/run executes detection and returns structured summary."""
    # Seed event
    now = datetime.now(timezone.utc)
    ev = SecurityEvent(
        id=str(uuid.uuid4()),
        timestamp=now,
        event_type="privilege_change",
        source="linux_auth",
        source_ip="192.168.1.1",
        destination_ip="10.0.0.1",
        username="root",
        hostname="server-01",
        action="sudo",
        status="success",
        severity="critical",
        message="COMMAND=/bin/bash executed with sudo privileges",
        raw_event={"sample": True},
        created_at=now,
    )
    db_session.add(ev)
    db_session.commit()

    resp = client.post("/api/v1/detection/run", json={"limit": 100})
    assert resp.status_code == 200
    data = resp.json()

    assert "events_evaluated" in data
    assert "alerts_generated" in data
    assert "alerts_deduplicated" in data
    assert "execution_duration_ms" in data
    assert "rule_breakdown" in data


def test_list_alerts_endpoint(client: TestClient, db_session: Session):
    """GET /api/v1/alerts lists alerts with pagination."""
    now = datetime.now(timezone.utc)
    alert = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-001",
        rule_name="Brute Force Authentication Attempt",
        title="Brute Force Detected: 3 Failed Logins",
        description="Repeated failed logins detected",
        severity="medium",
        status="new",
        dedup_key=f"test_dedup_{uuid.uuid4()}",
        affected_user="target_user",
        affected_ip="198.51.100.22",
        detected_at=now,
        created_at=now,
    )
    db_session.add(alert)
    db_session.commit()

    resp = client.get("/api/v1/alerts?page=1&page_size=10")
    assert resp.status_code == 200
    data = resp.json()

    assert data["total"] >= 1
    assert "alerts" in data
    assert len(data["alerts"]) >= 1
    item = data["alerts"][0]
    assert "title" in item
    assert "severity" in item
    assert "rule_id" in item


def test_filter_alerts_by_severity(client: TestClient, db_session: Session):
    """Filter alerts by severity level."""
    now = datetime.now(timezone.utc)
    critical_alert = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-003",
        rule_name="Suspicious Privilege Escalation",
        title="Critical Privilege Escalation",
        description="Escalation to Domain Admins",
        severity="critical",
        status="new",
        dedup_key=f"test_crit_{uuid.uuid4()}",
        detected_at=now,
        created_at=now,
    )
    db_session.add(critical_alert)
    db_session.commit()

    resp = client.get("/api/v1/alerts?severity=critical")
    assert resp.status_code == 200
    data = resp.json()
    for a in data["alerts"]:
        assert a["severity"] == "critical"


def test_alert_stats_endpoint(client: TestClient):
    """GET /api/v1/alerts/stats returns aggregated metrics."""
    resp = client.get("/api/v1/alerts/stats")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_alerts" in data
    assert "by_severity" in data
    assert "by_status" in data
    assert "by_rule" in data


def test_get_alert_by_id_with_evidence(client: TestClient, db_session: Session):
    """GET /api/v1/alerts/{alert_id} returns full alert details with evidence timeline."""
    now = datetime.now(timezone.utc)
    ev = SecurityEvent(
        id=str(uuid.uuid4()),
        timestamp=now,
        event_type="authentication",
        source="windows_event",
        action="login",
        status="failure",
        severity="medium",
        message="Invalid password",
        raw_event={"auth": False},
        created_at=now,
    )
    alert = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-001",
        rule_name="Brute Force",
        title="Test Alert With Evidence",
        description="Testing evidence relationship retrieval",
        severity="medium",
        status="new",
        dedup_key=f"test_ev_{uuid.uuid4()}",
        detected_at=now,
        created_at=now,
    )
    evidence = AlertEvidence(
        id=str(uuid.uuid4()),
        alert=alert,
        event=ev,
        evidence_role="trigger",
        description="Failed auth event triggering rule",
        created_at=now,
    )
    ev_id = str(ev.id)
    alert_id = str(alert.id)
    db_session.add_all([ev, alert, evidence])
    db_session.commit()

    resp = client.get(f"/api/v1/alerts/{alert_id}")
    assert resp.status_code == 200
    data = resp.json()

    assert data["id"] == alert_id
    assert len(data["evidence"]) == 1
    ev_item = data["evidence"][0]
    assert ev_item["evidence_role"] == "trigger"
    assert ev_item["event"] is not None
    assert ev_item["event"]["id"] == ev_id


def test_get_nonexistent_alert_returns_404(client: TestClient):
    """Querying a random UUID returns HTTP 404."""
    random_id = str(uuid.uuid4())
    resp = client.get(f"/api/v1/alerts/{random_id}")
    assert resp.status_code == 404


def test_update_alert_status(client: TestClient, db_session: Session):
    """PATCH /api/v1/alerts/{alert_id}/status transitions triage status."""
    now = datetime.now(timezone.utc)
    alert = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-001",
        rule_name="Brute Force",
        title="Status Transition Test",
        description="Testing status update endpoint",
        severity="low",
        status="new",
        dedup_key=f"test_status_{uuid.uuid4()}",
        detected_at=now,
        created_at=now,
    )
    db_session.add(alert)
    db_session.commit()

    resp = client.patch(f"/api/v1/alerts/{alert.id}/status", json={"status": "in_review"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_review"

    # Verify invalid status is rejected
    bad_resp = client.patch(f"/api/v1/alerts/{alert.id}/status", json={"status": "invalid_status"})
    assert bad_resp.status_code == 422
