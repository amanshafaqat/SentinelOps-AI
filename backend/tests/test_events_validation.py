"""Tests for SecurityEvent Schema and Normalization Validation."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError
from backend.app.schemas.event import SecurityEventCreate
from backend.app.services.normalizer import normalize_event_dict, _parse_port


def test_valid_event_creation():
    """Verify that a well-formed event passes validation."""
    event_data = {
        "timestamp": "2026-09-24T10:00:00Z",
        "event_type": "authentication",
        "source": "linux_auth",
        "source_ip": "198.51.100.42",
        "destination_ip": "10.0.1.15",
        "source_port": 51234,
        "destination_port": 22,
        "username": "alice",
        "hostname": "bastion-01",
        "action": "login",
        "status": "failure",
        "severity": "medium",
        "message": "Authentication failed for alice",
    }
    event = SecurityEventCreate(**event_data)
    assert event.username == "alice"
    assert event.source_ip == "198.51.100.42"
    assert event.destination_port == 22
    assert event.timestamp.tzinfo is not None
    assert event.status == "failure"
    assert event.severity == "medium"


def test_invalid_ip_rejection():
    """Verify that malformed IP addresses are rejected."""
    with pytest.raises(ValidationError) as exc:
        SecurityEventCreate(
            timestamp="2026-09-24T10:00:00Z",
            event_type="authentication",
            source="linux_auth",
            source_ip="999.999.999.999",  # Invalid IPv4
            action="login",
            status="failure",
        )
    assert "source_ip" in str(exc.value)


def test_invalid_port_rejection():
    """Verify that ports out of range (1-65535) are rejected."""
    with pytest.raises(ValidationError):
        SecurityEventCreate(
            timestamp="2026-09-24T10:00:00Z",
            event_type="authentication",
            source="linux_auth",
            source_port=70000,  # Exceeds max port
            action="login",
            status="failure",
        )

    with pytest.raises(ValidationError):
        SecurityEventCreate(
            timestamp="2026-09-24T10:00:00Z",
            event_type="authentication",
            source="linux_auth",
            destination_port=0,  # Sub-minimum port
            action="login",
            status="failure",
        )


def test_malformed_timestamp_rejection():
    """Verify that unparseable timestamps fail validation."""
    with pytest.raises(ValidationError):
        SecurityEventCreate(
            timestamp="not-a-valid-date-time",
            event_type="network",
            source="firewall",
            action="drop",
            status="blocked",
        )


def test_missing_required_fields_rejection():
    """Verify that omitting required fields triggers validation error."""
    with pytest.raises(ValidationError) as exc:
        SecurityEventCreate(
            timestamp="2026-09-24T10:00:00Z",
            # Missing event_type, source, action, status
        )
    errors = str(exc.value)
    assert "event_type" in errors
    assert "source" in errors
    assert "action" in errors
    assert "status" in errors


def test_normalizer_heterogeneous_aliases():
    """Verify that common security log field aliases are mapped properly."""
    raw_log = {
        "@timestamp": "2026-09-24 10:15:00",
        "category": "privilege_escalation",
        "sensor": "auditd",
        "client_ip": "203.0.113.15",
        "server_ip": "10.0.1.20",
        "src_port": "54321",
        "dst_port": "443",
        "actor": "bob_admin",
        "computer_name": "srv-db-01",
        "operation": "sudo",
        "outcome": "succ",  # Normalizes to success
        "level": "warn",    # Normalizes to medium
        "details": "User executed sudo su",
        "extra_custom_tag": "critical_asset",
    }
    normalized = normalize_event_dict(raw_log)
    assert normalized.event_type == "privilege_escalation"
    assert normalized.source == "auditd"
    assert normalized.source_ip == "203.0.113.15"
    assert normalized.destination_ip == "10.0.1.20"
    assert normalized.source_port == 54321
    assert normalized.destination_port == 443
    assert normalized.username == "bob_admin"
    assert normalized.hostname == "srv-db-01"
    assert normalized.action == "sudo"
    assert normalized.status == "success"
    assert normalized.severity == "medium"
    assert normalized.message == "User executed sudo su"
    assert normalized.metadata.get("extra_custom_tag") == "critical_asset"
    assert normalized.raw_event["@timestamp"] == "2026-09-24 10:15:00"
