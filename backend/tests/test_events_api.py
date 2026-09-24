"""Tests for Security Events Retrieval, Filtering, and Pagination APIs."""

import pytest
from fastapi import status


@pytest.fixture(scope="function")
def seed_test_events(client):
    """Seed distinct events for filtering and pagination tests."""
    events = [
        {
            "timestamp": "2026-09-24T08:00:00Z",
            "event_type": "authentication",
            "source": "linux_auth",
            "source_ip": "198.51.100.10",
            "username": "alice",
            "action": "login",
            "status": "failure",
            "severity": "medium",
            "message": "Failed login for alice",
        },
        {
            "timestamp": "2026-09-24T08:05:00Z",
            "event_type": "authentication",
            "source": "linux_auth",
            "source_ip": "198.51.100.10",
            "username": "alice",
            "action": "login",
            "status": "success",
            "severity": "high",
            "message": "Successful login for alice",
        },
        {
            "timestamp": "2026-09-24T09:00:00Z",
            "event_type": "network",
            "source": "palo_alto",
            "source_ip": "203.0.113.50",
            "destination_ip": "10.0.1.200",
            "username": "system_daemon",
            "action": "block",
            "status": "blocked",
            "severity": "low",
            "message": "Inbound port 445 blocked",
        },
        {
            "timestamp": "2026-09-24T09:30:00Z",
            "event_type": "privilege_change",
            "source": "linux_auth",
            "source_ip": "198.51.100.10",
            "username": "alice",
            "action": "sudo",
            "status": "success",
            "severity": "critical",
            "message": "sudo /bin/bash by alice",
        },
    ]
    res = client.post("/api/v1/events/batch", json=events)
    assert res.status_code == status.HTTP_201_CREATED
    return res.json()["sample_imported_ids"]


def test_list_events_pagination(client, seed_test_events):
    """Verify pagination controls (page, page_size, total_pages)."""
    response = client.get("/api/v1/events?page=1&page_size=2")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["page"] == 1
    assert data["page_size"] == 2
    assert data["total"] >= 4
    assert len(data["items"]) == 2
    assert data["total_pages"] >= 2


def test_filter_by_username(client, seed_test_events):
    """Verify filtering events by subject username."""
    response = client.get("/api/v1/events?username=alice")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert all(item["username"] == "alice" for item in data["items"])
    assert data["total"] >= 3


def test_filter_by_event_type(client, seed_test_events):
    """Verify filtering events by event_type."""
    response = client.get("/api/v1/events?event_type=network")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert all(item["event_type"] == "network" for item in data["items"])
    assert data["total"] >= 1


def test_filter_by_severity(client, seed_test_events):
    """Verify filtering events by severity level."""
    response = client.get("/api/v1/events?severity=critical")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert all(item["severity"] == "critical" for item in data["items"])


def test_get_event_by_id(client, seed_test_events):
    """Verify fetching full event details by ID."""
    event_id = seed_test_events[0]
    response = client.get(f"/api/v1/events/{event_id}")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["id"] == event_id
    assert "raw_event" in data
    assert "metadata" in data


def test_get_nonexistent_event_404(client):
    """Verify 404 response for unknown event UUID."""
    response = client.get("/api/v1/events/00000000-0000-0000-0000-000000000000")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    data = response.json()
    assert data["error"]["code"] == "NOT_FOUND"


def test_event_stats_summary(client, seed_test_events):
    """Verify aggregate counts for severity, status, and sources."""
    response = client.get("/api/v1/events/stats/summary")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["total_events"] >= 4
    assert "by_severity" in data
    assert "by_status" in data
    assert "top_sources" in data
