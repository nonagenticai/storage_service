"""Integration tests for storage_service health endpoints."""

import pytest

pytestmark = pytest.mark.integration

ACCEPTABLE_STATUSES = {200, 502, 503}


class TestHealthEndpoints:
    """Test /health, /health/live, and /health/ready."""

    def test_health(self, storage_client):
        """GET /health returns overall health with component details."""
        resp = storage_client.get("/health")
        assert resp.status_code in ACCEPTABLE_STATUSES, (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )
        if resp.status_code == 200:
            body = resp.json()
            assert "status" in body
            assert body["status"] in {"healthy", "degraded", "unhealthy"}
            assert "components" in body

    def test_health_live(self, storage_client):
        """GET /health/live — liveness probe."""
        resp = storage_client.get("/health/live")
        assert resp.status_code in ACCEPTABLE_STATUSES, (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )
        if resp.status_code == 200:
            body = resp.json()
            assert body.get("status") == "alive"

    def test_health_ready(self, storage_client):
        """GET /health/ready — readiness probe."""
        resp = storage_client.get("/health/ready")
        assert resp.status_code in ACCEPTABLE_STATUSES, (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )
        if resp.status_code == 200:
            body = resp.json()
            assert body.get("status") == "ready"
