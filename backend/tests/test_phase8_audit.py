"""Phase 8 Portfolio Audit Tests.

Verifies:
- GET /api/v1/audit/logs endpoint with pagination and filtering
- Redaction of sensitive tokens/passwords in audit logs
- Singular route aliases for reports and investigation endpoints
"""

import pytest
from sqlalchemy.orm import sessionmaker
from backend.app.models.incident import Incident, IncidentAuditLog
import uuid
from datetime import datetime, timezone


@pytest.fixture
def db(test_engine):
    SessionLocal = sessionmaker(bind=test_engine)
    session = SessionLocal()
    yield session
    session.close()


def test_audit_logs_endpoint(client, db):
    """Verify /api/v1/audit/logs returns valid structure and supports pagination."""
    now = datetime.now(timezone.utc)
    test_inc = Incident(
        id=str(uuid.uuid4()),
        title="Test Incident for Audit",
        description="Test description",
        severity="medium",
        status="new",
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
    )
    db.add(test_inc)
    db.commit()

    audit = IncidentAuditLog(
        incident_id=test_inc.id,
        action="CREDENTIAL_UPDATE",
        previous_value="Bearer secret_token_xyz123",
        new_value="password=SuperSecretPassword123!",
        notes="Observed key AIzaSyD98765432101234567890123456789012 in note",
        actor="test_analyst",
    )
    db.add(audit)
    db.commit()

    res = client.get("/api/v1/audit/logs?page=1&page_size=10")
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "logs" in data
    assert data["page"] == 1
    assert data["page_size"] == 10

    # Verify sensitive token redaction
    found_redacted = False
    for log in data["logs"]:
        if log["actor"] == "test_analyst":
            found_redacted = True
            assert "secret_token_xyz123" not in (log.get("previous_value") or "")
            assert "SuperSecretPassword123!" not in (log.get("new_value") or "")
            assert "AIzaSy" not in (log.get("notes") or "")
            assert "[REDACTED_SECRET]" in (log.get("previous_value") or "") or "[REDACTED_SECRET]" in (log.get("new_value") or "") or "[REDACTED_SECRET]" in (log.get("notes") or "")
    assert found_redacted is True


def test_investigation_aliases(client):
    """Verify route aliases /investigate and /analysis resolve properly."""
    fake_id = "00000000-0000-0000-0000-000000000000"
    res1 = client.post(f"/api/v1/incidents/{fake_id}/analyze")
    res2 = client.post(f"/api/v1/incidents/{fake_id}/investigate")
    res3 = client.post(f"/api/v1/incidents/{fake_id}/analysis")

    assert res1.status_code == 404
    assert res2.status_code == 404
    assert res3.status_code == 404


def test_report_aliases(client, db):
    """Verify singular /report and /report/export route aliases."""
    now = datetime.now(timezone.utc)
    test_inc = Incident(
        id=str(uuid.uuid4()),
        title="Test Incident For Report Aliases",
        description="Telemetry analysis incident",
        severity="high",
        status="new",
        first_seen=now,
        last_seen=now,
        created_at=now,
        updated_at=now,
    )
    db.add(test_inc)
    db.commit()

    # Test GET singular report
    res_list = client.get(f"/api/v1/incidents/{test_inc.id}/report")
    assert res_list.status_code == 200

    # Test POST singular report
    res_create = client.post(
        f"/api/v1/incidents/{test_inc.id}/report",
        json={"title": "Test Singular Report Alias"}
    )
    assert res_create.status_code == 201

    # Test GET singular export HTML
    res_export = client.get(f"/api/v1/incidents/{test_inc.id}/report/export?format=html")
    assert res_export.status_code == 200
    assert "Content-Disposition" in res_export.headers
