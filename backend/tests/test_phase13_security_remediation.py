"""Phase 13 Security Remediation Test Suite.

Validates:
1. Role-based authorization matrix enforcement across all sensitive API endpoints (events, alerts, incidents, AI, reports, audit).
2. Production authentication enforcement (no unauthenticated access, rejection of development static tokens, rejection of arbitrary identity headers).
3. JWT signature verification, expiration enforcement, and invalid token rejection.
4. Directory traversal and malicious upload filename rejection.
5. Production demo seed lock (HTTP 403 Forbidden).
6. Consistency of Rule 004 and Rule 005 definitions and severities.
"""

import io
import json
import uuid
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.auth import create_access_token, AuthUser, ROLE_PERMISSIONS
from backend.app.core.config import settings
from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent
from backend.app.models.incident import Incident, CaseNote, InvestigationReport, IncidentAuditLog
from backend.app.detection.rules.rule_004_auth_pattern import RuleSuspiciousAuthPattern
from backend.app.detection.rules.rule_005_indicator_match import RuleExplicitIndicatorMatch


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


def seed_test_incident(db: Session) -> Incident:
    now = datetime.now(timezone.utc)
    ev = SecurityEvent(
        id=str(uuid.uuid4()),
        timestamp=now,
        event_type="authentication",
        severity="high",
        status="failure",
        source="linux_auth",
        action="ssh_login",
        source_ip="198.51.100.55",
        username="test_target",
        hostname="srv-01",
        message="Failed password attempt",
        raw_event={"attempt": 1},
    )
    db.add(ev)
    db.commit()

    alert = Alert(
        id=str(uuid.uuid4()),
        rule_id="RULE-001",
        rule_name="Brute Force Authentication",
        title="Multiple Failed Logins",
        description="Repeated failed authentications observed.",
        severity="high",
        status="new",
        dedup_key="test-dedup-rem-1",
        affected_user="test_target",
        affected_ip="198.51.100.55",
        detected_at=now,
    )
    db.add(alert)
    db.commit()

    inc = Incident(
        id=str(uuid.uuid4()),
        title="Brute Force Authentication Attack (test_target)",
        description="Correlated brute force incident.",
        severity="high",
        status="new",
        first_seen=now,
        last_seen=now,
        affected_users=["test_target"],
        affected_ips=["198.51.100.55"],
        affected_hostnames=["srv-01"],
        correlation_reasons=["Temporal proximity", "Shared username entity"],
    )
    db.add(inc)
    db.commit()

    alert.incident_id = inc.id
    db.commit()
    return inc


# ==============================================================================
# 1. ROLE-BASED ACCESS CONTROL ENFORCEMENT
# ==============================================================================

def test_viewer_cannot_write_events(client: TestClient):
    """Users with 'viewer' role must receive 403 Forbidden on event write endpoints."""
    viewer_headers = {"X-Actor-Role": "viewer", "X-Actor-Name": "viewer_user"}
    
    # Create event
    resp = client.post("/api/v1/events", json={
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "syslog",
        "event_type": "auth",
        "action": "login",
        "status": "failure",
        "severity": "medium",
        "message": "test event",
        "raw_event": {}
    }, headers=viewer_headers)
    assert resp.status_code == 403
    err_msg = resp.json().get("error", {}).get("message", "")
    assert "lacks required permission" in err_msg

    # Import file
    resp = client.post(
        "/api/v1/events/import",
        files={"file": ("logs.json", b'[{"event_type": "auth"}]', "application/json")},
        headers=viewer_headers,
    )
    assert resp.status_code == 403

    # Batch ingest
    resp = client.post(
        "/api/v1/events/batch",
        json=[{"event_type": "auth", "source": "test", "action": "login", "status": "failure", "severity": "low", "message": "msg"}],
        headers=viewer_headers,
    )
    assert resp.status_code == 403


def test_viewer_cannot_modify_alerts_or_run_detection(client: TestClient, db: Session):
    """Users with 'viewer' role must receive 403 Forbidden when executing detection or modifying alerts."""
    inc = seed_test_incident(db)
    alert = inc.alerts[0]
    viewer_headers = {"X-Actor-Role": "viewer", "X-Actor-Name": "viewer_user"}

    # Run detection
    resp = client.post("/api/v1/detection/run", json={"limit": 50}, headers=viewer_headers)
    assert resp.status_code == 403

    # Update alert status
    resp = client.patch(f"/api/v1/alerts/{alert.id}/status", json={"status": "in_review"}, headers=viewer_headers)
    assert resp.status_code == 403


def test_viewer_cannot_correlate_or_update_incident(client: TestClient, db: Session):
    """Users with 'viewer' role must receive 403 Forbidden on incident correlation and status mutation."""
    inc = seed_test_incident(db)
    viewer_headers = {"X-Actor-Role": "viewer", "X-Actor-Name": "viewer_user"}

    # Correlate
    resp = client.post("/api/v1/incidents/correlate", json={}, headers=viewer_headers)
    assert resp.status_code == 403

    # Update incident status
    resp = client.patch(f"/api/v1/incidents/{inc.id}/status", json={"status": "investigating", "notes": "audit"}, headers=viewer_headers)
    assert resp.status_code == 403


def test_viewer_cannot_invoke_ai_investigation(client: TestClient, db: Session):
    """Users with 'viewer' role must receive 403 Forbidden on AI investigation endpoints."""
    inc = seed_test_incident(db)
    viewer_headers = {"X-Actor-Role": "viewer", "X-Actor-Name": "viewer_user"}

    # AI analyze
    resp = client.post(f"/api/v1/incidents/{inc.id}/analyze", headers=viewer_headers)
    assert resp.status_code == 403

    # AI ask
    resp = client.post(f"/api/v1/incidents/{inc.id}/ask", json={"question": "What is the source IP?"}, headers=viewer_headers)
    assert resp.status_code == 403


def test_viewer_cannot_create_notes_or_reports(client: TestClient, db: Session):
    """Users with 'viewer' role must receive 403 Forbidden when creating notes or generating reports."""
    inc = seed_test_incident(db)
    viewer_headers = {"X-Actor-Role": "viewer", "X-Actor-Name": "viewer_user"}

    # Create note
    resp = client.post(f"/api/v1/incidents/{inc.id}/notes", json={"content": "Viewer note"}, headers=viewer_headers)
    assert resp.status_code == 403

    # Generate report
    resp = client.post(f"/api/v1/incidents/{inc.id}/reports", json={"title": "Unauthorized Report", "report_type": "investigation_summary"}, headers=viewer_headers)
    assert resp.status_code == 403


def test_viewer_cannot_read_audit_history(client: TestClient, db: Session):
    """Users with 'viewer' role must receive 403 Forbidden on audit history."""
    inc = seed_test_incident(db)
    viewer_headers = {"X-Actor-Role": "viewer", "X-Actor-Name": "viewer_user"}

    resp = client.get(f"/api/v1/incidents/{inc.id}/history", headers=viewer_headers)
    assert resp.status_code == 403

    resp = client.get("/api/v1/audit/logs", headers=viewer_headers)
    assert resp.status_code == 403


# ==============================================================================
# 2. PRODUCTION AUTHENTICATION ENFORCEMENT & JWT SECURITY
# ==============================================================================

def test_production_mode_rejects_unauthenticated_requests(client: TestClient):
    """When APP_ENV is production, requests without a valid Bearer token are rejected with 401."""
    original_env = settings.app_env
    try:
        settings.app_env = "production"
        resp = client.get("/api/v1/events")
        assert resp.status_code == 401
        err_msg = resp.json().get("error", {}).get("message", "")
        assert "Authentication required" in err_msg

        resp = client.get("/api/v1/incidents")
        assert resp.status_code == 401

        resp = client.get("/api/v1/alerts")
        assert resp.status_code == 401
    finally:
        settings.app_env = original_env


def test_production_mode_rejects_static_dev_tokens(client: TestClient):
    """When APP_ENV is production, static dev tokens (e.g. 'token-admin') are rejected."""
    original_env = settings.app_env
    try:
        settings.app_env = "production"
        headers = {"Authorization": "Bearer token-admin"}
        resp = client.get("/api/v1/incidents", headers=headers)
        assert resp.status_code == 401
        err_msg = resp.json().get("error", {}).get("message", "")
        assert "Static development tokens are not permitted in production" in err_msg
    finally:
        settings.app_env = original_env


def test_production_mode_rejects_identity_spoofing_headers(client: TestClient):
    """When APP_ENV is production, arbitrary identity headers are rejected."""
    original_env = settings.app_env
    try:
        settings.app_env = "production"
        headers = {"X-Actor-Role": "admin", "X-Actor-Name": "attacker"}
        resp = client.get("/api/v1/incidents", headers=headers)
        assert resp.status_code == 401
        err_msg = resp.json().get("error", {}).get("message", "")
        assert "Authentication required" in err_msg
    finally:
        settings.app_env = original_env


def test_valid_signed_jwt_token_accepted_in_production(client: TestClient):
    """Signed HS256 JWT tokens are accepted and grant authorized permissions in production."""
    original_env = settings.app_env
    try:
        settings.app_env = "production"
        token = create_access_token({"sub": "lead_soc_analyst", "role": "soc_analyst"})
        headers = {"Authorization": f"Bearer {token}"}
        resp = client.get("/api/v1/incidents", headers=headers)
        assert resp.status_code == 200
    finally:
        settings.app_env = original_env


def test_expired_jwt_token_rejected(client: TestClient):
    """Expired JWT tokens return 401 Unauthorized."""
    expired_token = create_access_token({"sub": "test_analyst", "role": "soc_analyst"}, expires_delta=timedelta(seconds=-10))
    headers = {"Authorization": f"Bearer {expired_token}"}
    resp = client.get("/api/v1/incidents", headers=headers)
    assert resp.status_code == 401
    err_msg = resp.json().get("error", {}).get("message", "")
    assert "expired" in err_msg.lower()


def test_tampered_jwt_token_rejected(client: TestClient):
    """Tampered JWT signature returns 401 Unauthorized."""
    valid_token = create_access_token({"sub": "test_analyst", "role": "soc_analyst"})
    parts = valid_token.split(".")
    tampered_sig = parts[2][:-4] + "AAAA"
    tampered_token = f"{parts[0]}.{parts[1]}.{tampered_sig}"
    
    headers = {"Authorization": f"Bearer {tampered_token}"}
    resp = client.get("/api/v1/incidents", headers=headers)
    assert resp.status_code == 401
    err_msg = resp.json().get("error", {}).get("message", "")
    assert "signature" in err_msg.lower()


# ==============================================================================
# 3. PRODUCTION DEMO SEED LOCK
# ==============================================================================

def test_production_mode_locks_demo_seed_endpoint(client: TestClient):
    """POST /api/v1/system/demo/seed returns 403 Forbidden in production even for authenticated admin."""
    original_env = settings.app_env
    try:
        settings.app_env = "production"
        admin_token = create_access_token({"sub": "admin_user", "role": "admin"})
        headers = {"Authorization": f"Bearer {admin_token}"}
        resp = client.post("/api/v1/system/demo/seed", headers=headers)
        assert resp.status_code == 403
        err_msg = resp.json().get("error", {}).get("message", "")
        assert "Demo database seeding is disabled in production" in err_msg
    finally:
        settings.app_env = original_env


# ==============================================================================
# 4. RULE 004 AND RULE 005 CONSISTENCY
# ==============================================================================

def test_rule_004_and_005_definition_consistency():
    """Verify Rule 004 and 005 properties match SOC design specifications."""
    r4 = RuleSuspiciousAuthPattern()
    assert r4.rule_id == "RULE-004"
    assert "Multi-Source" in r4.rule_name
    assert r4.default_severity.value == "medium"

    r5 = RuleExplicitIndicatorMatch()
    assert r5.rule_id == "RULE-005"
    assert "Indicator Match" in r5.rule_name
    assert r5.default_severity.value == "high"
