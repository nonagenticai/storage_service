"""
Tests for configuration module.
"""

import os
from unittest.mock import patch


class TestSettings:
    """Test Settings class."""

    def test_default_values(self, settings):
        """Test default configuration values."""
        assert settings.service_name == "storage-service"
        assert settings.version == "1.0.0"
        assert settings.port == 8391

    def test_allowed_bucket_list_parsing(self, settings):
        """Test that allowed_buckets string is parsed to list."""
        buckets = settings.allowed_bucket_list
        assert isinstance(buckets, list)
        assert "kag-ingestion" in buckets
        assert "kag-processed" in buckets
        assert "artifacts" in buckets

    def test_max_upload_size_bytes(self, settings):
        """Test max upload size conversion to bytes."""
        expected_bytes = settings.max_upload_size_mb * 1024 * 1024
        assert settings.max_upload_size_bytes == expected_bytes

    def test_minio_credentials_from_env(self, settings):
        """Test MinIO credentials are loaded from environment."""
        assert settings.minio_access_key == "test_access_key"
        assert settings.minio_secret_key == "test_secret_key"

    def test_get_settings_cached(self):
        """Test that get_settings returns cached instance."""
        from config import get_settings

        get_settings.cache_clear()

        settings1 = get_settings()
        settings2 = get_settings()
        assert settings1 is settings2

    def test_clamav_defaults(self, settings):
        """Test ClamAV default configuration."""
        assert settings.clamav_host == "clamav"
        assert settings.clamav_port == 3310
        assert settings.clamav_timeout == 30.0


class TestSettingsEnvironmentOverride:
    """Test environment variable overrides."""

    def test_port_override(self):
        """Test port can be overridden via environment."""
        from config import Settings

        with patch.dict(os.environ, {"PORT": "9999"}):
            # Create new settings instance
            settings = Settings()
            assert settings.port == 9999

    def test_log_level_override(self):
        """Test log level can be overridden."""
        from config import Settings

        with patch.dict(os.environ, {"LOG_LEVEL": "DEBUG"}):
            settings = Settings()
            assert settings.log_level == "DEBUG"

    def test_allowed_buckets_override(self):
        """Test allowed buckets can be overridden."""
        from config import Settings

        with patch.dict(os.environ, {"ALLOWED_BUCKETS": "bucket1,bucket2"}):
            settings = Settings()
            assert settings.allowed_bucket_list == ["bucket1", "bucket2"]

    def test_virus_scanning_disabled(self):
        """Test virus scanning can be disabled."""
        from config import Settings

        with patch.dict(os.environ, {"ENABLE_VIRUS_SCANNING": "false"}):
            settings = Settings()
            assert settings.enable_virus_scanning is False


class TestProductionValidator:
    """Verify Settings.model_post_init enforces required URLs in production.

    Mirrors inference-router/src/settings.py _REQUIRED_IN_PRODUCTION
    pattern (memory: feedback-no-hardcoded-urls-ports-in-code).
    """

    def test_missing_minio_endpoint_raises_in_production(self):
        """Empty minio_endpoint crashes boot when environment=production."""
        import pytest

        from config import Settings

        with patch.dict(
            os.environ,
            {
                "ENVIRONMENT": "production",
                "MINIO_ENDPOINT": "",
                "LICENSE_INTROSPECT_URL": "http://licenses.example.com/license/introspect",
            },
            clear=False,
        ):
            with pytest.raises(RuntimeError, match="missing required fields in production"):
                Settings()

    def test_missing_license_introspect_url_raises_in_production(self):
        """Empty license_introspect_url crashes boot when environment=production."""
        import pytest

        from config import Settings

        with patch.dict(
            os.environ,
            {
                "ENVIRONMENT": "production",
                "MINIO_ENDPOINT": "minio.example.com:9000",
                "LICENSE_INTROSPECT_URL": "",
            },
            clear=False,
        ):
            with pytest.raises(RuntimeError, match="missing required fields in production"):
                Settings()

    def test_all_required_fields_pass_in_production(self):
        """Production boots cleanly when every required URL is set."""
        from config import Settings

        with patch.dict(
            os.environ,
            {
                "ENVIRONMENT": "production",
                "MINIO_ENDPOINT": "minio.example.com:9000",
                "LICENSE_INTROSPECT_URL": "http://licenses.example.com/license/introspect",
            },
            clear=False,
        ):
            settings = Settings()
            assert settings.environment == "production"
            assert settings.minio_endpoint == "minio.example.com:9000"

    def test_non_production_tolerates_empty_required_fields(self):
        """Dev/test environments allow empty URL defaults."""
        from config import Settings

        for env in ("development", "test", "local", "ci"):
            with patch.dict(
                os.environ,
                {
                    "ENVIRONMENT": env,
                    "MINIO_ENDPOINT": "",
                    "LICENSE_INTROSPECT_URL": "",
                },
                clear=False,
            ):
                settings = Settings()
                assert settings.environment == env
