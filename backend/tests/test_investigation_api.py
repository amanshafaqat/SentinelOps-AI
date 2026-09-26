"""API Integration tests for Gemini Investigation Copilot endpoints.

Tests /api/v1/investigation/status, /api/v1/incidents/{id}/analyze,
/api/v1/incidents/{id}/ask, error responses, security headers, and secret exclusion.
"""

from datetime import datetime, timezone, timedelta
import json
import uuid
import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.models.alert import Alert, AlertEvidence
from backend.app.models.event import SecurityEvent
from backend.app.models.incident import Incident, IncidentAuditLog, IncidentAIAnalysis
from backend.app.investigation.gemini_client import (
    GeminiConfigurationError,
    GeminiRateLimitError,
    GeminiTimeoutError,
    GeminiServiceUnavailableError,
)


@pytest.fixture(autouse=True)
def clean_database(db_session: Session):
    db_session.query(IncidentAIAnalysis).delete()
    db_session.query(IncidentAuditLog).delete()
    db_session.query(AlertEvidence).delete()
    db_session.query(Alert).delete()
    db_session.query(Incident).delete()
    db_session.query(SecurityEvent).delete()
    db_session.commit()
    yield
    db_session.query(IncidentAIAnalysis).delete()
    db_session.query(IncidentAuditLog).delete()
    db_session.query(AlertEvidence).delete()
    db_session.query(Alert).delete()
    db_session.query(Incident).delete()
    db_session.query(SecurityEvent).delete()
    db_session.commit()


def seed_test_incident(db: Session) -> Incident:
    now = datetime.now(timezone.utc)
    incident = Incident(
        id=str(uuid.uuid4()),
        title="Unauthorized Admin Access Attempt",
        description="Multiple failed auth events from untrusted IP followed by suspicious privilege change.",
        severity="critical",
        status="new",
        first_seen=now - timedelta(minutes=10),
        last_seen=now,
        affected_users=["admin"],
        affected_ips=["203.0.113.195"],
        affected_hostnames=["prod-db-01"],
        correlation_reasons=["Same username: admin", "Same IP: 203.0.113.195"],
    )
    db.add(incident)

    alert = Alert(
        id=str(uuid.uuid4()),
        incident_id=incident.id,
        rule_id="RULE-003",
        rule_name="Privilege Escalation",
        title="Admin privilege grant",
        description="User added to sudoers",
        severity="critical",
        status="new",
        dedup_key=f"RULE-003-{incident.id}",
        affected_user="admin",
        affected_ip="203.0.113.195",
        detected_at=now,
    )
    db.add(alert)
    db.flush()

    ev = SecurityEvent(
        id=str(uuid.uuid4()),
        timestamp=now,
        event_type="privilege_escalation",
        source="auditd",
        source_ip="203.0.113.195",
        username="admin",
        hostname="prod-db-01",
        action="grant",
        status="success",
        severity="critical",
        message="User admin granted wheel privileges",
        raw_event={"ip": "203.0.113.195", "user": "admin", "action": "grant"},
    )
    db.add(ev)
    db.flush()

    db.add(AlertEvidence(alert_id=alert.id, event_id=ev.id, evidence_role="privilege_escalation"))
    db.commit()
    db.refresh(incident)
    return incident


# ==============================================================================
# Status & Security Tests
# ==============================================================================

def test_investigation_status_never_exposes_api_key(client: TestClient):
    """Critical security test: Verify that GEMINI_API_KEY is never leaked in status."""
    res = client.get("/api/v1/investigation/status")
    assert res.status_code == 200
    data = res.json()
    assert "model" in data
    assert "api_key_configured" in data
    assert "status" in data
    assert "api_key" not in data
    assert "gemini_api_key" not in data
    # Ensure raw secret string is not in JSON text
    if settings.gemini_api_key:
        assert settings.gemini_api_key not in res.text


# ==============================================================================
# Analyze Incident API Tests
# ==============================================================================

def test_analyze_incident_endpoint_success(client: TestClient, db_session: Session):
    incident = seed_test_incident(db_session)
    valid_ev_id = incident.alerts[0].evidence[0].event_id

    mock_gemini_output = json.dumps({
        "summary": "Privilege escalation activity observed on prod-db-01 by admin account.",
        "observed_facts": [
            "User admin was granted wheel privileges at prod-db-01",
            "Activity originated from external IP 203.0.113.195"
        ],
        "potential_explanations": [
            "Compromised credential usage by external attacker",
            "Emergency off-hours maintenance by authorized sysadmin"
        ],
        "evidence_references": [
            {"id": valid_ev_id, "type": "event", "description": "Auditd privilege escalation record"}
        ],
        "missing_information": [
            "Change management ticket reference",
            "VPN / bastion session authentication logs"
        ],
        "recommended_next_steps": [
            "Contact administrator to verify if maintenance was scheduled",
            "Inspect active SSH sessions on prod-db-01"
        ],
        "uncertainty_assessment": "High confidence in privilege change event; unconfirmed whether authorized or malicious."
    })

    with patch("backend.app.investigation.gemini_client.GeminiClient.generate_content_async", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = mock_gemini_output

        res = client.post(f"/api/v1/incidents/{incident.id}/analyze")
        assert res.status_code == 200
        data = res.json()

        assert data["incident_id"] == incident.id
        assert "privilege escalation" in data["summary"].lower()
        assert len(data["observed_facts"]) == 2
        assert len(data["evidence_references"]) == 1
        assert data["evidence_references"][0]["id"] == valid_ev_id
        assert data["evidence_references"][0]["valid"] is True
        assert "disclaimer" in data


def test_analyze_nonexistent_incident_returns_404(client: TestClient):
    fake_id = str(uuid.uuid4())
    res = client.post(f"/api/v1/incidents/{fake_id}/analyze")
    assert res.status_code == 404
    body = res.json()
    assert "error" in body
    assert body["error"]["code"] == "INCIDENT_NOT_FOUND"


def test_analyze_incident_unconfigured_key_returns_503(client: TestClient, db_session: Session):
    incident = seed_test_incident(db_session)

    with patch("backend.app.investigation.gemini_client.GeminiClient.generate_content_async", new_callable=AsyncMock) as mock_gen:
        mock_gen.side_effect = GeminiConfigurationError()

        res = client.post(f"/api/v1/incidents/{incident.id}/analyze")
        assert res.status_code == 503
        data = res.json()
        assert data["error"]["code"] == "AI_COPILOT_UNCONFIGURED"


def test_analyze_incident_rate_limit_returns_429(client: TestClient, db_session: Session):
    incident = seed_test_incident(db_session)

    with patch("backend.app.investigation.gemini_client.GeminiClient.generate_content_async", new_callable=AsyncMock) as mock_gen:
        mock_gen.side_effect = GeminiRateLimitError()

        res = client.post(f"/api/v1/incidents/{incident.id}/analyze")
        assert res.status_code == 429
        data = res.json()
        assert data["error"]["code"] == "AI_PROVIDER_RATE_LIMIT"


def test_analyze_incident_timeout_returns_504(client: TestClient, db_session: Session):
    incident = seed_test_incident(db_session)

    with patch("backend.app.investigation.gemini_client.GeminiClient.generate_content_async", new_callable=AsyncMock) as mock_gen:
        mock_gen.side_effect = GeminiTimeoutError()

        res = client.post(f"/api/v1/incidents/{incident.id}/analyze")
        assert res.status_code == 504
        data = res.json()
        assert data["error"]["code"] == "AI_PROVIDER_TIMEOUT"


# ==============================================================================
# Analyst Question API Tests
# ==============================================================================

def test_ask_analyst_question_success(client: TestClient, db_session: Session):
    incident = seed_test_incident(db_session)

    mock_gemini_output = json.dumps({
        "answer": "The critical severity is driven by the wheel group privilege grant to admin from an external IP.",
        "observed_facts": ["Privilege escalation observed on prod-db-01"],
        "evidence_references": [],
        "missing_information": ["Bastion logs"],
        "recommended_next_steps": ["Verify change ticket"],
        "uncertainty_assessment": "Grounded in single event."
    })

    with patch("backend.app.investigation.gemini_client.GeminiClient.generate_content_async", new_callable=AsyncMock) as mock_gen:
        mock_gen.return_value = mock_gemini_output

        payload = {"question": "Why is this incident marked as critical severity?"}
        res = client.post(f"/api/v1/incidents/{incident.id}/ask", json=payload)
        assert res.status_code == 200
        data = res.json()

        assert data["incident_id"] == incident.id
        assert data["question"] == payload["question"]
        assert "critical" in data["answer"].lower()


def test_ask_analyst_question_too_long_returns_422(client: TestClient, db_session: Session):
    incident = seed_test_incident(db_session)
    excessive_question = "A" * 600
    res = client.post(f"/api/v1/incidents/{incident.id}/ask", json={"question": excessive_question})
    assert res.status_code == 422


def test_ask_analyst_question_empty_returns_422(client: TestClient, db_session: Session):
    incident = seed_test_incident(db_session)
    res = client.post(f"/api/v1/incidents/{incident.id}/ask", json={"question": "   "})
    assert res.status_code == 422


def test_get_ai_history_endpoint(client: TestClient, db_session: Session):
    incident = seed_test_incident(db_session)

    # Seed an AI record
    record = IncidentAIAnalysis(
        incident_id=incident.id,
        analysis_type="incident_summary",
        model="gemini-3.8-flash",
        summary="Historical summary test",
        observed_facts=["Fact 1"],
        potential_explanations=[],
        evidence_references=[],
        missing_information=[],
        recommended_next_steps=[],
        uncertainty_assessment="",
        actor="soc_analyst",
    )
    db_session.add(record)
    db_session.commit()

    res = client.get(f"/api/v1/incidents/{incident.id}/ai-history")
    assert res.status_code == 200
    history = res.json()
    assert len(history) >= 1
    assert history[0]["summary"] == "Historical summary test"
