"""API integration tests for Incident endpoints, timelines, triage, and stats."""

from datetime import datetime, timezone, timedelta
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent
from backend.app.models.incident import Incident, IncidentAuditLog


@pytest.fixture(scope="function")
def db(test_engine):
    """Provides a direct session bound to test_engine."""
    SessionLocal = sessionmaker(bind=test_engine)
    session = SessionLocal()
    yield session
    session.close()


@pytest.fixture(autouse=True)
def clean_database(test_engine):
    """Ensure clean table state before and after each test."""
    SessionLocal = sessionmaker(bind=test_engine)
    s = SessionLocal()
    s.query(IncidentAuditLog).delete()
    s.query(AlertEvidence).delete()
    s.query(Alert).delete()
    s.query(Incident).delete()
    s.query(SecurityEvent).delete()
    s.commit()
    s.close()
    yield
    s = SessionLocal()
    s.query(IncidentAuditLog).delete()
    s.query(AlertEvidence).delete()
    s.query(Alert).delete()
    s.query(Incident).delete()
    s.query(SecurityEvent).delete()
    s.commit()
    s.close()


def seed_incident_with_alerts(db: Session) -> Incident:
    """Helper fixture creating a correlated incident with alerts, evidence, and events."""
    now = datetime(2026, 9, 24, 18, 0, 0, tzinfo=timezone.utc)

    # 1. Telemetry Event
    event = SecurityEvent(
        id=str(uuid.uuid4()),
        timestamp=now,
        event_type="authentication",
        source="pam_unix",
        source_ip="198.51.100.42",
        username="Administrator",
        action="login_failed",
        status="failure",
        severity="medium",
        message="Failed password for Administrator from 198.51.100.42 port 44212 ssh2",
        raw_event={"ip": "198.51.100.42", "user": "Administrator"},
        event_metadata={"reason": "bad_password"},
    )
    db.add(event)
    db.flush()

    # 2. Correlated Incident
    incident = Incident(
        id=str(uuid.uuid4()),
        title="Credential Compromise Sequence: Brute Force against Administrator",
        description="Multiple failed logons detected against Administrator from 198.51.100.42",
        severity="high",
        status="new",
        first_seen=now,
        last_seen=now + timedelta(minutes=10),
        affected_users=["Administrator"],
        affected_ips=["198.51.100.42"],
        affected_hostnames=["prod-bastion-01"],
        correlation_reasons=[
            "Shared Identity: Account 'Administrator'",
            "Network Origin: Source IP 198.51.100.42",
        ],
        correlation_metadata={"window": 60, "rules": ["RULE-001"]},
    )
    db.add(incident)
    db.flush()

    # 3. Alert with Evidence linking to Event
    alert = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-001",
        rule_name="Brute Force Authentication",
        title="Multiple Failed Logins for Administrator",
        description="Detected 5 failed login attempts in 5 minutes",
        severity="high",
        status="new",
        dedup_key=f"rule001-admin-{uuid.uuid4()}",
        affected_user="Administrator",
        affected_ip="198.51.100.42",
        affected_hostname="prod-bastion-01",
        detected_at=now,
        incident_id=incident.id,
    )
    db.add(alert)
    db.flush()

    evidence = AlertEvidence(
        id=str(uuid.uuid4()),
        alert_id=alert.id,
        event_id=event.id,
        evidence_role="triggering_failure",
        description="Initial failed password attempt",
    )
    db.add(evidence)

    # 4. Audit Log
    audit = IncidentAuditLog(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        action="correlation_created",
        previous_value=None,
        new_value="Status: new | Severity: high",
        notes="Correlated by engine from initial detections.",
        actor="correlation_engine",
        created_at=now,
    )
    db.add(audit)

    db.commit()
    db.refresh(incident)
    return incident


def test_list_incidents_endpoint(client: TestClient, db: Session):
    """Test GET /api/v1/incidents pagination and listing."""
    incident = seed_incident_with_alerts(db)

    response = client.get("/api/v1/incidents?page=1&page_size=10")
    assert response.status_code == 200
    data = response.json()

    assert data["total"] >= 1
    assert data["page"] == 1
    assert len(data["incidents"]) >= 1

    item = next((i for i in data["incidents"] if i["id"] == incident.id), None)
    assert item is not None
    assert item["title"] == incident.title
    assert item["severity"] == "high"
    assert item["status"] == "new"
    assert "Administrator" in item["affected_users"]
    assert item["alert_count"] >= 1


def test_filter_incidents_by_severity_and_status(client: TestClient, db: Session):
    """Test filtering incidents by severity and lifecycle status."""
    incident = seed_incident_with_alerts(db)

    # Match high severity
    res_high = client.get("/api/v1/incidents?severity=high")
    assert res_high.status_code == 200
    assert any(i["id"] == incident.id for i in res_high.json()["incidents"])

    # No match for low severity
    res_low = client.get("/api/v1/incidents?severity=low")
    assert res_low.status_code == 200
    assert not any(i["id"] == incident.id for i in res_low.json()["incidents"])

    # Match status new
    res_new = client.get("/api/v1/incidents?status=new")
    assert res_new.status_code == 200
    assert any(i["id"] == incident.id for i in res_new.json()["incidents"])


def test_get_incident_by_id(client: TestClient, db: Session):
    """Test GET /api/v1/incidents/{incident_id} detail with alerts and audit trail."""
    incident = seed_incident_with_alerts(db)

    response = client.get(f"/api/v1/incidents/{incident.id}")
    assert response.status_code == 200
    data = response.json()

    assert data["id"] == incident.id
    assert data["title"] == incident.title
    assert len(data["alerts"]) >= 1
    assert data["alerts"][0]["rule_id"] == "RULE-001"
    assert len(data["audit_logs"]) >= 1
    assert data["audit_logs"][0]["action"] == "correlation_created"


def test_get_nonexistent_incident_returns_404(client: TestClient):
    """Querying a non-existent incident UUID must return 404."""
    fake_id = str(uuid.uuid4())
    response = client.get(f"/api/v1/incidents/{fake_id}")
    assert response.status_code == 404
    assert "not found" in response.text.lower()


def test_incident_timeline_endpoint(client: TestClient, db: Session):
    """Test GET /api/v1/incidents/{incident_id}/timeline returns ordered multi-type stream."""
    incident = seed_incident_with_alerts(db)

    response = client.get(f"/api/v1/incidents/{incident.id}/timeline")
    assert response.status_code == 200
    data = response.json()

    assert data["incident_id"] == incident.id
    assert data["total_items"] >= 3  # 1 event, 1 alert, 1 incident action

    types = {item["item_type"] for item in data["items"]}
    assert "event" in types
    assert "alert" in types
    assert "incident_action" in types

    # Chronologically sorted check
    timestamps = [item["timestamp"] for item in data["items"]]
    assert timestamps == sorted(timestamps)


def test_update_incident_status_and_audit(client: TestClient, db: Session):
    """Test PATCH /api/v1/incidents/{incident_id} updates status and writes audit log."""
    incident = seed_incident_with_alerts(db)

    payload = {
        "status": "investigating",
        "notes": "Analyst assigned to investigate bastion telemetry.",
        "actor": "soc_analyst_01",
    }
    response = client.patch(f"/api/v1/incidents/{incident.id}", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["status"] == "investigating"

    # Verify audit log in response
    status_change_log = next((l for l in data["audit_logs"] if l["action"] == "status_change"), None)
    assert status_change_log is not None
    assert status_change_log["previous_value"] == "new"
    assert status_change_log["new_value"] == "investigating"
    assert status_change_log["actor"] == "soc_analyst_01"


def test_update_incident_invalid_status_rejected(client: TestClient, db: Session):
    """Invalid status values must be rejected with 422."""
    incident = seed_incident_with_alerts(db)

    payload = {"status": "INVALID_STATE_FOR_SOC"}
    response = client.patch(f"/api/v1/incidents/{incident.id}", json=payload)
    assert response.status_code in [400, 422]


def test_incident_stats_summary_endpoint(client: TestClient, db: Session):
    """Test GET /api/v1/incidents/stats returns summary metrics."""
    seed_incident_with_alerts(db)

    response = client.get("/api/v1/incidents/stats")
    assert response.status_code == 200
    data = response.json()

    assert data["total_incidents"] >= 1
    assert data["open_incidents"] >= 1
    assert "high" in data["by_severity"]
    assert "new" in data["by_status"]
    assert data["average_alerts_per_incident"] >= 1.0


def test_correlate_api_execution(client: TestClient, db: Session):
    """Test POST /api/v1/incidents/correlate endpoint execution."""
    now = datetime(2026, 9, 24, 20, 0, 0, tzinfo=timezone.utc)
    # Create 2 unassociated alerts
    a1 = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-001",
        rule_name="Brute Force",
        title="Brute force test",
        description="desc",
        severity="medium",
        status="new",
        dedup_key=str(uuid.uuid4()),
        affected_user="svc-backup",
        affected_ip="10.0.1.5",
        detected_at=now,
    )
    a2 = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-002",
        rule_name="Login After Failures",
        title="Login success test",
        description="desc",
        severity="high",
        status="new",
        dedup_key=str(uuid.uuid4()),
        affected_user="svc-backup",
        affected_ip="10.0.1.5",
        detected_at=now + timedelta(minutes=5),
    )
    db.add_all([a1, a2])
    db.commit()

    response = client.post(
        "/api/v1/incidents/correlate",
        json={"time_window_minutes": 60, "force_recorrelate": False},
    )
    assert response.status_code == 200
    data = response.json()

    assert data["alerts_evaluated"] >= 2
    assert data["incidents_created"] >= 1
    assert data["alerts_correlated"] >= 2
    assert len(data["created_incident_ids"]) >= 1
