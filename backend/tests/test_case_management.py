"""Tests for Phase 6: Case Management, Analyst Notes, Controlled Status Workflow, and Evidence-Grounded Reports."""

from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from backend.app.models.incident import Incident, IncidentAuditLog, CaseNote, InvestigationReport
from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent


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
    s.query(InvestigationReport).delete()
    s.query(CaseNote).delete()
    s.query(IncidentAuditLog).delete()
    s.query(AlertEvidence).delete()
    s.query(Alert).delete()
    s.query(Incident).delete()
    s.query(SecurityEvent).delete()
    s.commit()
    s.close()
    yield
    s = SessionLocal()
    s.query(InvestigationReport).delete()
    s.query(CaseNote).delete()
    s.query(IncidentAuditLog).delete()
    s.query(AlertEvidence).delete()
    s.query(Alert).delete()
    s.query(Incident).delete()
    s.query(SecurityEvent).delete()
    s.commit()
    s.close()


def seed_incident_for_case_tests(db: Session) -> Incident:
    """Creates a realistic incident with linked alerts and telemetry events."""
    # 1. Telemetry Events
    event1 = SecurityEvent(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        event_type="authentication",
        severity="medium",
        status="failure",
        source="linux_auth",
        action="ssh_login",
        source_ip="198.51.100.42",
        destination_ip="10.0.0.15",
        username="Administrator",
        hostname="bastion-prod-01",
        message="Failed password for Administrator from 198.51.100.42 port 42812 ssh2",
        raw_event={"proto": "ssh"},
    )
    event2 = SecurityEvent(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        event_type="authentication",
        severity="high",
        status="success",
        source="linux_auth",
        action="ssh_login",
        source_ip="198.51.100.42",
        destination_ip="10.0.0.15",
        username="Administrator",
        hostname="bastion-prod-01",
        message="Accepted password for Administrator from 198.51.100.42 port 42814 ssh2",
        raw_event={"proto": "ssh"},
    )
    db.add_all([event1, event2])
    db.commit()

    # 2. Correlated Alert
    alert = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-001",
        rule_name="Brute Force Authentication",
        title="Multiple Failed SSH Logins Followed by Success",
        description="Repeated failed authentications observed on bastion-prod-01 from 198.51.100.42.",
        severity="high",
        status="new",
        dedup_key="rule-001-admin-198.51.100.42",
        affected_user="Administrator",
        affected_ip="198.51.100.42",
        affected_hostname="bastion-prod-01",
        detected_at=datetime.now(timezone.utc),
        created_at=datetime.now(timezone.utc),
    )
    db.add(alert)
    db.commit()

    # Evidence links
    ev1 = AlertEvidence(alert_id=alert.id, event_id=event1.id, evidence_role="triggering_failure")
    ev2 = AlertEvidence(alert_id=alert.id, event_id=event2.id, evidence_role="consequential_success")
    db.add_all([ev1, ev2])
    db.commit()

    # 3. Incident (Security Case)
    incident = Incident(
        id=str(uuid.uuid4()),
        title="Compromised Admin Credentials on Prod Bastion",
        description="Multi-stage authentication anomaly correlating brute force attempts with logon.",
        severity="high",
        status="new",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        affected_users=["Administrator"],
        affected_ips=["198.51.100.42"],
        affected_hostnames=["bastion-prod-01"],
        correlation_reasons=["Same IP address 198.51.100.42", "Targeting user Administrator within 5 minutes"],
        correlation_metadata={"window_minutes": 60, "attack_progression_detected": True},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(incident)
    db.commit()

    alert.incident_id = incident.id
    db.commit()

    # Initial audit entry
    initial_audit = IncidentAuditLog(
        incident_id=incident.id,
        action="INCIDENT_CREATED",
        previous_value=None,
        new_value=incident.id,
        notes="Correlation engine synthesized incident.",
        actor="system",
        created_at=datetime.now(timezone.utc),
    )
    db.add(initial_audit)
    db.commit()

    return incident


# ============================================================================
# 1. CASE NOTES TESTS
# ============================================================================

def test_add_case_note_success_and_audited(client: TestClient, db: Session):
    """Adding a valid case note succeeds, persists, and writes an audit log."""
    incident = seed_incident_for_case_tests(db)

    payload = {
        "author": "analyst_sarah",
        "content": "Contacted server administrator. Host was placed in containment VLAN pending triage.",
    }
    response = client.post(f"/api/v1/incidents/{incident.id}/notes", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["incident_id"] == incident.id
    assert data["author"] == "analyst_sarah"
    assert "containment VLAN" in data["content"]
    assert "id" in data
    assert "created_at" in data

    # Verify audit log was recorded
    audit_res = client.get(f"/api/v1/incidents/{incident.id}/history")
    assert audit_res.status_code == 200
    history = audit_res.json()
    note_added_audit = next((h for h in history if h["action"] == "NOTE_ADDED"), None)
    assert note_added_audit is not None
    assert note_added_audit["actor"] == "analyst_sarah"
    assert "containment VLAN" in note_added_audit["notes"]


def test_add_case_note_rejects_empty_content(client: TestClient, db: Session):
    """Empty or whitespace-only note content must be rejected with 422."""
    incident = seed_incident_for_case_tests(db)

    payload = {"author": "analyst_sarah", "content": "   \n\t  "}
    response = client.post(f"/api/v1/incidents/{incident.id}/notes", json=payload)
    assert response.status_code in [400, 422]


def test_add_case_note_rejects_excessive_length(client: TestClient, db: Session):
    """Notes exceeding 5000 characters must be rejected."""
    incident = seed_incident_for_case_tests(db)

    payload = {"author": "analyst_sarah", "content": "A" * 5005}
    response = client.post(f"/api/v1/incidents/{incident.id}/notes", json=payload)
    assert response.status_code in [400, 422]


def test_add_case_note_nonexistent_incident_returns_404(client: TestClient):
    """Adding note to nonexistent incident returns 404."""
    fake_id = str(uuid.uuid4())
    payload = {"author": "analyst_sarah", "content": "Triage note"}
    response = client.post(f"/api/v1/incidents/{fake_id}/notes", json=payload)
    assert response.status_code == 404


def test_list_case_notes(client: TestClient, db: Session):
    """Listing notes returns all notes ordered latest first."""
    incident = seed_incident_for_case_tests(db)

    client.post(f"/api/v1/incidents/{incident.id}/notes", json={"author": "analyst_1", "content": "First note"})
    client.post(f"/api/v1/incidents/{incident.id}/notes", json={"author": "analyst_2", "content": "Second note"})

    response = client.get(f"/api/v1/incidents/{incident.id}/notes")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["notes"]) == 2
    assert data["notes"][0]["content"] == "Second note"


def test_update_case_note_and_audit(client: TestClient, db: Session):
    """Updating a note modifies content and audits the edit."""
    incident = seed_incident_for_case_tests(db)

    create_res = client.post(
        f"/api/v1/incidents/{incident.id}/notes",
        json={"author": "soc_analyst", "content": "Initial preliminary findings."},
    )
    note_id = create_res.json()["id"]

    update_payload = {"author": "soc_analyst", "content": "Updated findings: IP belongs to VPN gateway."}
    update_res = client.put(f"/api/v1/incidents/{incident.id}/notes/{note_id}", json=update_payload)
    assert update_res.status_code == 200
    assert "VPN gateway" in update_res.json()["content"]

    # Verify audit
    history = client.get(f"/api/v1/incidents/{incident.id}/history").json()
    update_audit = next((h for h in history if h["action"] == "NOTE_UPDATED"), None)
    assert update_audit is not None


def test_update_case_note_unauthorized_author_rejected(client: TestClient, db: Session):
    """Editing another user's note without permission is rejected."""
    incident = seed_incident_for_case_tests(db)

    create_res = client.post(
        f"/api/v1/incidents/{incident.id}/notes",
        json={"author": "specialist_bob", "content": "Private specialist hypothesis."},
    )
    note_id = create_res.json()["id"]

    # Unauthorized third-party user attempts to overwrite bob's note
    malicious_res = client.put(
        f"/api/v1/incidents/{incident.id}/notes/{note_id}",
        json={"author": "unauthorized_attacker", "content": "Tampered note content."},
    )
    assert malicious_res.status_code in [400, 403, 422]


def test_delete_case_note_and_audit(client: TestClient, db: Session):
    """Deleting a note removes it and records audit log."""
    incident = seed_incident_for_case_tests(db)

    create_res = client.post(
        f"/api/v1/incidents/{incident.id}/notes",
        json={"author": "soc_analyst", "content": "Temporary note to be purged."},
    )
    note_id = create_res.json()["id"]

    del_res = client.delete(f"/api/v1/incidents/{incident.id}/notes/{note_id}")
    assert del_res.status_code == 200

    list_res = client.get(f"/api/v1/incidents/{incident.id}/notes").json()
    assert list_res["total"] == 0


# ============================================================================
# 2. STATUS WORKFLOW TRANSITIONS TESTS
# ============================================================================

def test_controlled_status_transitions(client: TestClient, db: Session):
    """Tests controlled status progression: NEW -> INVESTIGATING -> RESOLVED -> CLOSED."""
    incident = seed_incident_for_case_tests(db)
    assert incident.status == "new"

    # Step 1: new -> investigating (allowed)
    r1 = client.patch(
        f"/api/v1/incidents/{incident.id}",
        json={"status": "investigating", "actor": "lead_analyst", "notes": "Starting triage"},
    )
    assert r1.status_code == 200
    assert r1.json()["status"] == "investigating"

    # Step 2: investigating -> resolved (allowed)
    r2 = client.patch(
        f"/api/v1/incidents/{incident.id}",
        json={"status": "resolved", "actor": "lead_analyst", "notes": "Compromised credential revoked"},
    )
    assert r2.status_code == 200
    assert r2.json()["status"] == "resolved"

    # Step 3: resolved -> closed (allowed)
    r3 = client.patch(
        f"/api/v1/incidents/{incident.id}",
        json={"status": "closed", "actor": "lead_analyst", "notes": "Post-incident review complete"},
    )
    assert r3.status_code == 200
    assert r3.json()["status"] == "closed"

    # Step 4: closed -> investigating (reopening allowed upon new evidence)
    r4 = client.patch(
        f"/api/v1/incidents/{incident.id}",
        json={"status": "investigating", "actor": "lead_analyst", "notes": "Reopening: secondary alert observed"},
    )
    assert r4.status_code == 200
    assert r4.json()["status"] == "investigating"


def test_invalid_status_transition_rejected(client: TestClient, db: Session):
    """Attempting an invalid status transition is rejected with validation error."""
    incident = seed_incident_for_case_tests(db)

    # First close the incident
    client.patch(f"/api/v1/incidents/{incident.id}", json={"status": "investigating"})
    client.patch(f"/api/v1/incidents/{incident.id}", json={"status": "resolved"})
    client.patch(f"/api/v1/incidents/{incident.id}", json={"status": "closed"})

    # Transitioning from closed directly to new is disallowed
    res = client.patch(
        f"/api/v1/incidents/{incident.id}",
        json={"status": "new", "actor": "analyst"},
    )
    assert res.status_code in [400, 422]


# ============================================================================
# 3. INVESTIGATION REPORTS TESTS
# ============================================================================

def test_generate_investigation_report_success(client: TestClient, db: Session):
    """Generates an evidence-grounded report with structured content and standalone HTML."""
    incident = seed_incident_for_case_tests(db)

    payload = {
        "report_type": "investigation_summary",
        "title": "Technical Investigation: Bastion Intrusion",
        "generated_by": "analyst_chen",
        "include_ai_analysis": False,
    }
    response = client.post(f"/api/v1/incidents/{incident.id}/reports", json=payload)
    assert response.status_code == 201

    data = response.json()
    assert data["incident_id"] == incident.id
    assert data["title"] == "Technical Investigation: Bastion Intrusion"
    assert data["generated_by"] == "analyst_chen"
    assert "content" in data
    assert "rendered_html" in data
    assert "<!DOCTYPE html>" in data["rendered_html"]
    assert "SENTINELOPS AI" in data["rendered_html"]

    # Check evidence grounding (Incident -> Alert -> Event traceability)
    content = data["content"]
    assert "evidence_traceability" in content
    assert len(content["evidence_traceability"]) > 0
    first_alert = content["evidence_traceability"][0]
    assert first_alert["rule_id"] == "RULE-001"
    assert len(first_alert["supporting_events"]) == 2
    assert first_alert["supporting_events"][0]["source_ip"] == "198.51.100.42"

    # Verify audit log
    history = client.get(f"/api/v1/incidents/{incident.id}/history").json()
    report_audit = next((h for h in history if h["action"] == "REPORT_GENERATED"), None)
    assert report_audit is not None


def test_report_versioning_preserves_history(client: TestClient, db: Session):
    """Generating multiple reports preserves historical reports with version tracking."""
    incident = seed_incident_for_case_tests(db)

    # First report (v1)
    r1 = client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        json={"title": "Report Version 1", "generated_by": "analyst_a"},
    ).json()
    assert r1["metadata"]["version"] == 1

    # Second report (v2)
    r2 = client.post(
        f"/api/v1/incidents/{incident.id}/reports",
        json={"title": "Report Version 2", "generated_by": "analyst_b"},
    ).json()
    assert r2["metadata"]["version"] == 2

    # Listing reports shows both versions
    list_res = client.get(f"/api/v1/incidents/{incident.id}/reports")
    assert list_res.status_code == 200
    all_reports = list_res.json()["reports"]
    assert len(all_reports) == 2
    assert all_reports[0]["id"] == r2["id"]  # Ordered latest first
    assert all_reports[1]["id"] == r1["id"]


def test_get_specific_report(client: TestClient, db: Session):
    """Retrieves a specific report by ID."""
    incident = seed_incident_for_case_tests(db)
    created = client.post(f"/api/v1/incidents/{incident.id}/reports", json={}).json()

    res = client.get(f"/api/v1/incidents/{incident.id}/reports/{created['id']}")
    assert res.status_code == 200
    assert res.json()["id"] == created["id"]


def test_export_report_html_and_json(client: TestClient, db: Session):
    """Export endpoint returns downloadable HTML and JSON with attachment headers."""
    incident = seed_incident_for_case_tests(db)
    created = client.post(f"/api/v1/incidents/{incident.id}/reports", json={}).json()
    report_id = created["id"]

    # 1. Export HTML
    html_export = client.get(f"/api/v1/incidents/{incident.id}/reports/{report_id}/export?format=html")
    assert html_export.status_code == 200
    assert "text/html" in html_export.headers.get("content-type", "")
    assert "attachment" in html_export.headers.get("content-disposition", "")
    assert "<!DOCTYPE html>" in html_export.text

    # 2. Export JSON
    json_export = client.get(f"/api/v1/incidents/{incident.id}/reports/{report_id}/export?format=json")
    assert json_export.status_code == 200
    assert "application/json" in json_export.headers.get("content-type", "")
    assert "attachment" in json_export.headers.get("content-disposition", "")
    data = json_export.json()
    assert data["id"] == report_id

    # 3. Verify export audit
    history = client.get(f"/api/v1/incidents/{incident.id}/history").json()
    export_audit = next((h for h in history if h["action"] == "REPORT_EXPORTED"), None)
    assert export_audit is not None


def test_investigation_history_endpoint(client: TestClient, db: Session):
    """Investigation history endpoint returns ordered audit logs without exposing secrets."""
    incident = seed_incident_for_case_tests(db)
    client.post(f"/api/v1/incidents/{incident.id}/notes", json={"content": "Triage check"})

    res = client.get(f"/api/v1/incidents/{incident.id}/history")
    assert res.status_code == 200
    logs = res.json()
    assert len(logs) >= 2

    # Verify no secrets or credentials leaked
    for log in logs:
        for val in [log.get("notes"), log.get("previous_value"), log.get("new_value")]:
            if val:
                assert "password" not in val.lower() or "redacted" in val.lower() or "ssh" in val.lower()
                assert "AIza" not in val
                assert "eyJ" not in val
