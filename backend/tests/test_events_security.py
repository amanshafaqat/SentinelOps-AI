"""Security and Input Sanitization Tests for SentinelOps AI."""

import io
import json
import pytest
from fastapi import status
from backend.app.services.importer import MAX_UPLOAD_SIZE_BYTES


def test_hostile_input_safety(client):
    """Verify SQL injection strings and XSS vectors are treated as pure data."""
    hostile_event = {
        "timestamp": "2026-09-24T12:00:00Z",
        "event_type": "web_attack",
        "source": "waf",
        "username": "admin' OR '1'='1'; DROP TABLE security_events; --",
        "action": "<script>alert('xss')</script>",
        "status": "blocked",
        "severity": "high",
        "message": "{{ 7 * 7 }} ${{system('id')}} UNION SELECT NULL, NULL",
        "metadata": {
            "payload": "../../../etc/passwd",
            "cmd": "rm -rf /",
        },
    }

    res = client.post("/api/v1/events/batch", json=[hostile_event])
    assert res.status_code == status.HTTP_201_CREATED
    data = res.json()
    assert data["imported_records"] == 1

    event_id = data["sample_imported_ids"][0]
    get_res = client.get(f"/api/v1/events/{event_id}")
    assert get_res.status_code == status.HTTP_200_OK
    retrieved = get_res.json()
    # Confirm exact string preservation without evaluation
    assert retrieved["username"] == "admin' OR '1'='1'; DROP TABLE security_events; --"
    assert retrieved["action"] == "<script>alert('xss')</script>"
    assert retrieved["message"] == "{{ 7 * 7 }} ${{system('id')}} UNION SELECT NULL, NULL"


def test_path_traversal_filename_resilience(client):
    """Verify uploaded filenames containing path traversal characters are handled safely."""
    payload = json.dumps([
        {
            "timestamp": "2026-09-24T12:00:00Z",
            "event_type": "authentication",
            "source": "linux_auth",
            "action": "login",
            "status": "failure",
        }
    ]).encode("utf-8")

    # Hostile path traversal filename
    files = {"file": ("../../../../etc/passwd.json", io.BytesIO(payload), "application/json")}
    res = client.post("/api/v1/events/import", files=files)
    assert res.status_code == status.HTTP_201_CREATED
    assert res.json()["imported_records"] == 1


def test_oversized_upload_rejection(client):
    """Verify uploads exceeding MAX_UPLOAD_SIZE_BYTES are rejected before memory exhaustion."""
    # Generate dummy oversized stream chunk exceeding 10MB
    oversized_data = b" " * (MAX_UPLOAD_SIZE_BYTES + 1024)
    files = {"file": ("huge_logs.json", io.BytesIO(oversized_data), "application/json")}

    res = client.post("/api/v1/events/import", files=files)
    assert res.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    assert "exceeds maximum allowed upload size" in res.json()["error"]["message"]
