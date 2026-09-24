"""Tests for Health Check Endpoints."""

import pytest
from fastapi import status


def test_root_endpoint(client):
    """Test the root service index endpoint."""
    response = client.get("/")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "SentinelOps" in data["name"]
    assert data["status"] == "operational"
    assert "health" in data


def test_health_endpoint(client):
    """Test the basic health check endpoint."""
    response = client.get("/api/v1/health")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "healthy"
    assert "SentinelOps" in data["service"]
    assert "timestamp" in data
    assert "version" in data


def test_detailed_health_endpoint(client):
    """Test the detailed health check endpoint."""
    response = client.get("/api/v1/health/detailed")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "status" in data
    assert "database" in data
    assert "dialect" in data["database"]
    assert "latency_ms" in data["database"]


def test_system_info_endpoint(client):
    """Test the system info and architecture metadata endpoint."""
    response = client.get("/api/v1/system/info")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "SentinelOps" in data["name"]
    assert "Phase" in data["current_phase"]
    assert "architecture" in data
    assert data["architecture"]["style"] == "Modular Monolith"
    assert len(data["security_features"]) > 0
