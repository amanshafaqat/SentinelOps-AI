"""Tests for File Ingestion and Import APIs (JSON and CSV)."""

import io
import json
import pytest
from fastapi import status


def test_import_valid_json_file(client):
    """Verify importing events from a valid JSON file."""
    events_payload = [
        {
            "timestamp": "2026-09-24T12:00:00Z",
            "event_type": "authentication",
            "source": "linux_auth",
            "source_ip": "198.51.100.11",
            "username": "user1",
            "action": "login",
            "status": "failure",
            "severity": "medium",
            "message": "Invalid password",
        },
        {
            "timestamp": "2026-09-24T12:00:05Z",
            "event_type": "authentication",
            "source": "linux_auth",
            "source_ip": "198.51.100.11",
            "username": "user1",
            "action": "login",
            "status": "success",
            "severity": "high",
            "message": "Successful login after failure",
        },
    ]

    json_bytes = json.dumps(events_payload).encode("utf-8")
    files = {"file": ("test_logs.json", io.BytesIO(json_bytes), "application/json")}

    response = client.post("/api/v1/events/import", files=files)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["total_records"] == 2
    assert data["imported_records"] == 2
    assert data["rejected_records"] == 0
    assert len(data["sample_imported_ids"]) == 2


def test_import_valid_csv_file(client):
    """Verify importing events from a valid CSV file."""
    csv_content = (
        "timestamp,event_type,source,source_ip,username,action,status,severity,message\n"
        "2026-09-24T12:01:00Z,network,firewall,203.0.113.88,network_svc,drop,blocked,low,Blocked inbound traffic\n"
        "2026-09-24T12:01:10Z,network,firewall,203.0.113.89,network_svc,drop,blocked,low,Blocked inbound traffic\n"
    ).encode("utf-8")

    files = {"file": ("network_logs.csv", io.BytesIO(csv_content), "text/csv")}

    response = client.post("/api/v1/events/import", files=files)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["total_records"] == 2
    assert data["imported_records"] == 2
    assert data["rejected_records"] == 0


def test_import_mixed_valid_and_invalid_records(client):
    """Verify that malformed records are rejected while valid records are imported."""
    mixed_payload = [
        {
            "timestamp": "2026-09-24T12:05:00Z",
            "event_type": "authentication",
            "source": "okta",
            "username": "valid_user",
            "action": "login",
            "status": "success",
        },
        {
            # Invalid: Missing timestamp
            "event_type": "authentication",
            "source": "okta",
            "username": "broken_record",
            "action": "login",
            "status": "failure",
        },
        {
            # Invalid: Malformed IP address
            "timestamp": "2026-09-24T12:05:30Z",
            "event_type": "authentication",
            "source": "okta",
            "source_ip": "not_an_ip",
            "username": "broken_ip_user",
            "action": "login",
            "status": "failure",
        },
    ]

    json_bytes = json.dumps(mixed_payload).encode("utf-8")
    files = {"file": ("mixed_logs.json", io.BytesIO(json_bytes), "application/json")}

    response = client.post("/api/v1/events/import", files=files)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["total_records"] == 3
    assert data["imported_records"] == 1
    assert data["rejected_records"] == 2
    assert len(data["errors"]) == 2
    assert data["errors"][0]["record_index"] == 2
    assert data["errors"][1]["record_index"] == 3


def test_import_unsupported_file_extension(client):
    """Verify rejection of executable or disallowed file types."""
    files = {"file": ("malicious.exe", io.BytesIO(b"MZ\x90\x00"), "application/octet-stream")}
    response = client.post("/api/v1/events/import", files=files)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data = response.json()
    assert "Unsupported file format" in data["error"]["message"]


def test_import_malformed_json_syntax(client):
    """Verify structured error when JSON syntax is corrupted."""
    bad_json = b"{ invalid json syntax: missing quotes"
    files = {"file": ("broken.json", io.BytesIO(bad_json), "application/json")}
    response = client.post("/api/v1/events/import", files=files)
    assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
    data = response.json()
    assert "Malformed JSON file" in data["error"]["message"]


def test_batch_json_body_ingest(client):
    """Verify batch JSON endpoint ingesting event objects directly."""
    batch_data = [
        {
            "timestamp": "2026-09-24T12:10:00Z",
            "event_type": "privilege_change",
            "source": "sudo_audit",
            "username": "dev_ops",
            "action": "sudo",
            "status": "success",
            "severity": "critical",
            "message": "COMMAND=/bin/bash executed",
        }
    ]
    response = client.post("/api/v1/events/batch", json=batch_data)
    assert response.status_code == status.HTTP_201_CREATED
    data = response.json()
    assert data["imported_records"] == 1
