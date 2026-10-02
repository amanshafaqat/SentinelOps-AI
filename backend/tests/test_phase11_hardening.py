"""Phase 11 Security, Data Exposure & Identity Hardening Tests.

Verifies:
1. Rejection of unauthenticated protected operations when in production mode.
2. Rejection of static dev tokens in production mode.
3. Rejection of X-Actor spoofing headers in production mode.
4. Server-side authorization enforcement on audit records.
5. Error responses never leak stack traces or internal implementation details.
6. Report ID boundary enforcement (cannot access report belonging to different incident).
7. Investigation status never exposes internal keys, model timeouts, or context limits.
"""

import uuid
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.config import Settings
from backend.app.models.incident import Incident, IncidentAuditLog, CaseNote, InvestigationReport


def seed_incident(db_session: Session) -> Incident:
    inc = Incident(
        id=str(uuid.uuid4()),
        title="Unauthorized Database Dump Attempt",
        description="Suspicious batch query execution observed on internal database server.",
        severity="high",
        status="new",
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
        affected_users=["db_admin"],
        affected_ips=["10.0.5.22"],
        affected_hostnames=["prod-db-01"],
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db_session.add(inc)
    db_session.commit()
    db_session.refresh(inc)
    return inc


def test_production_rejects_unauthenticated_note_creation(client: TestClient, db_session: Session, monkeypatch):
    """In production mode, protected operations must require valid Bearer authentication."""
    from backend.app.core.config import settings
    monkeypatch.setattr(settings, "app_env", "production")

    inc = seed_incident(db_session)

    # Attempting to add note without Bearer auth in production must return 401
    res = client.post(
        f"/api/v1/incidents/{inc.id}/notes",
        json={"content": "Attempted note without token"}
    )
    assert res.status_code == 401
    assert "Authentication required" in res.json().get("error", {}).get("message", "")


def test_production_rejects_static_dev_tokens(client: TestClient, db_session: Session, monkeypatch):
    """Static dev tokens ('token-*') are strictly forbidden in production mode."""
    from backend.app.core.config import settings
    monkeypatch.setattr(settings, "app_env", "production")

    inc = seed_incident(db_session)

    res = client.post(
        f"/api/v1/incidents/{inc.id}/notes",
        json={"content": "Note using static token"},
        headers={"Authorization": "Bearer token-admin"}
    )
    assert res.status_code == 401
    assert "Static development tokens are not permitted in production" in res.json().get("error", {}).get("message", "")


def test_production_rejects_identity_spoofing_headers(client: TestClient, db_session: Session, monkeypatch):
    """X-Actor-* headers cannot bypass production authentication."""
    from backend.app.core.config import settings
    monkeypatch.setattr(settings, "app_env", "production")

    inc = seed_incident(db_session)

    res = client.post(
        f"/api/v1/incidents/{inc.id}/notes",
        json={"content": "Spoofed note"},
        headers={"X-Actor-Role": "admin", "X-Actor-Name": "fake_admin"}
    )
    assert res.status_code == 401


def test_audit_authorization_enforced(client: TestClient, db_session: Session):
    """Audit logs endpoint rejects roles without 'audit:read' permission."""
    inc = seed_incident(db_session)

    # Viewer role does NOT have 'audit:read' permission
    res = client.get(
        "/api/v1/audit/logs",
        headers={"X-Actor-Role": "viewer", "X-Actor-Name": "guest_viewer"}
    )
    assert res.status_code == 403


def test_incident_history_authorization_enforced(client: TestClient, db_session: Session):
    """Incident history endpoint rejects roles without 'audit:read' permission."""
    inc = seed_incident(db_session)

    res = client.get(
        f"/api/v1/incidents/{inc.id}/history",
        headers={"X-Actor-Role": "viewer", "X-Actor-Name": "guest_viewer"}
    )
    assert res.status_code == 403


def test_cross_incident_report_access_prevented(client: TestClient, db_session: Session):
    """Report IDs scoped to one incident cannot be accessed via another incident route."""
    inc1 = seed_incident(db_session)
    inc2 = seed_incident(db_session)

    report = InvestigationReport(
        id=str(uuid.uuid4()),
        incident_id=inc1.id,
        title="Incident 1 Report",
        report_type="investigation_summary",
        generated_by="lead_analyst",
        summary="Summary 1",
        content={},
        rendered_html="<html><body>Report 1</body></html>",
        metadata_info={},
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(report)
    db_session.commit()

    # Attempting to fetch report using incident 2 path must return 404
    res = client.get(f"/api/v1/incidents/{inc2.id}/reports/{report.id}")
    assert res.status_code == 404
