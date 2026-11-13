"""
Tests for health check endpoints.

Uses FakeMinioClient for the healthy path; MagicMock for simulating failures.
Every test asserts on response body content.
"""

import os
from unittest.mock import MagicMock, patch


class TestHealthEndpoint:
    """Test /health endpoint."""

    def test_health_all_healthy(self, app_client, fake_minio, mock_virus_scanner):
        """Test health check when all components are healthy."""
        response = app_client.get("/health")
        assert response.status_code == 200

        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "storage-service"
        assert data["version"] == "1.0.0"
        assert "minio" in data["components"]
        assert data["components"]["minio"]["healthy"] is True
        assert data["components"]["minio"]["latency_ms"] is not None

    def test_health_minio_unhealthy(self, app_client):
        """Test health check when MinIO is unhealthy."""
        mock_minio = MagicMock()
        mock_minio.health_check.return_value = (False, "Connection refused", 0.0)

        with patch("routes.health.get_minio_client", return_value=mock_minio):
            response = app_client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "unhealthy"
        assert data["components"]["minio"]["healthy"] is False
        assert data["components"]["minio"]["message"] == "Connection refused"

    def test_health_minio_exception(self, app_client):
        """Test health check when MinIO raises exception."""
        mock_minio = MagicMock()
        mock_minio.health_check.side_effect = Exception("Connection failed")

        with patch("routes.health.get_minio_client", return_value=mock_minio):
            response = app_client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["components"]["minio"]["healthy"] is False
        assert "Connection failed" in data["components"]["minio"]["message"]


class TestLivenessEndpoint:
    """Test /health/live endpoint."""

    def test_liveness(self, app_client):
        """Test liveness probe returns alive."""
        response = app_client.get("/health/live")
        assert response.status_code == 200
        body = response.json()
        assert body == {"status": "alive"}


class TestReadinessEndpoint:
    """Test /health/ready endpoint."""

    def test_readiness_ready(self, app_client, fake_minio):
        """Test readiness when MinIO is accessible (fake always healthy)."""
        response = app_client.get("/health/ready")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ready"

    def test_readiness_not_ready(self, app_client):
        """Test readiness when MinIO is not accessible."""
        mock_minio = MagicMock()
        mock_minio.health_check.return_value = (False, "MinIO down", 0.0)

        with patch("routes.health.get_minio_client", return_value=mock_minio):
            response = app_client.get("/health/ready")

        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "not_ready"
        assert body["reason"] == "MinIO down"

    def test_readiness_exception(self, app_client):
        """Test readiness when health check raises exception."""
        mock_minio = MagicMock()
        mock_minio.health_check.side_effect = Exception("Network error")

        with patch("routes.health.get_minio_client", return_value=mock_minio):
            response = app_client.get("/health/ready")

        assert response.status_code == 503
        body = response.json()
        assert body["status"] == "not_ready"
        assert "Network error" in body["reason"]


class TestHealthDegradedState:
    """Test degraded health state (ClamAV down, MinIO up)."""

    def test_health_degraded_clamav_down(self):
        """Test health returns degraded when ClamAV is down but MinIO is up."""
        mock_minio = MagicMock()
        mock_minio.health_check.return_value = (True, "MinIO is healthy", 5.0)

        mock_scanner = MagicMock()
        mock_scanner.health_check.return_value = (False, "ClamAV ping failed", 0.0)

        from config import get_settings

        old_val = os.environ.get("ENABLE_VIRUS_SCANNING")
        os.environ["ENABLE_VIRUS_SCANNING"] = "true"
        get_settings.cache_clear()

        try:
            with (
                patch("services.minio_client._minio_client", mock_minio),
                patch("services.minio_client.get_minio_client", return_value=mock_minio),
                patch("services.virus_scanner._virus_scanner", mock_scanner),
                patch("services.virus_scanner.get_virus_scanner", return_value=mock_scanner),
                patch("routes.files.get_minio_client", return_value=mock_minio),
                patch("routes.files.get_virus_scanner", return_value=mock_scanner),
                patch("routes.buckets.get_minio_client", return_value=mock_minio),
                patch("routes.health.get_minio_client", return_value=mock_minio),
                patch("routes.health.get_virus_scanner", return_value=mock_scanner),
            ):
                from fastapi.testclient import TestClient

                from main import app

                client = TestClient(app)
                response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "degraded"
            assert data["components"]["minio"]["healthy"] is True
            assert data["components"]["minio"]["message"] == "MinIO is healthy"
            assert data["components"]["clamav"]["healthy"] is False
            assert data["components"]["clamav"]["message"] == "ClamAV ping failed"
        finally:
            get_settings.cache_clear()
            if old_val is None:
                os.environ.pop("ENABLE_VIRUS_SCANNING", None)
            else:
                os.environ["ENABLE_VIRUS_SCANNING"] = old_val

    def test_health_clamav_exception(self):
        """Test health when ClamAV scanner raises exception."""
        mock_minio = MagicMock()
        mock_minio.health_check.return_value = (True, "MinIO is healthy", 5.0)

        mock_scanner = MagicMock()
        mock_scanner.health_check.side_effect = Exception("ClamAV connection refused")

        from config import get_settings

        old_val = os.environ.get("ENABLE_VIRUS_SCANNING")
        os.environ["ENABLE_VIRUS_SCANNING"] = "true"
        get_settings.cache_clear()

        try:
            with (
                patch("services.minio_client._minio_client", mock_minio),
                patch("services.minio_client.get_minio_client", return_value=mock_minio),
                patch("services.virus_scanner._virus_scanner", mock_scanner),
                patch("services.virus_scanner.get_virus_scanner", return_value=mock_scanner),
                patch("routes.files.get_minio_client", return_value=mock_minio),
                patch("routes.files.get_virus_scanner", return_value=mock_scanner),
                patch("routes.buckets.get_minio_client", return_value=mock_minio),
                patch("routes.health.get_minio_client", return_value=mock_minio),
                patch("routes.health.get_virus_scanner", return_value=mock_scanner),
            ):
                from fastapi.testclient import TestClient

                from main import app

                client = TestClient(app)
                response = client.get("/health")

            assert response.status_code == 200
            data = response.json()
            assert data["components"]["clamav"]["healthy"] is False
            assert "ClamAV" in data["components"]["clamav"]["message"]
            assert "connection refused" in data["components"]["clamav"]["message"].lower()
        finally:
            get_settings.cache_clear()
            if old_val is None:
                os.environ.pop("ENABLE_VIRUS_SCANNING", None)
            else:
                os.environ["ENABLE_VIRUS_SCANNING"] = old_val
