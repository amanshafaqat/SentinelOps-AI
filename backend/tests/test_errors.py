"""Tests for Error Handling and Structured Response Envelopes."""

from fastapi import status


def test_not_found_endpoint(client):
    """Verify 404 handler returns structured error envelope."""
    response = client.get("/api/v1/non-existent-endpoint")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert data["error"]["status_code"] == 404
    assert "message" in data["error"]


def test_security_headers_present(client):
    """Verify essential security headers are injected."""
    response = client.get("/")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert "Content-Security-Policy" in response.headers
