"""Tests for auth module imports and models."""

from typing import Any


class TestAuthImports:
    """Test auth module exports are correct types."""

    def test_auth_middleware_is_middleware_subclass(self):
        from starlette.middleware.base import BaseHTTPMiddleware

        from auth import AuthMiddleware

        assert issubclass(AuthMiddleware, BaseHTTPMiddleware)

    def test_user_type_is_dict_alias(self):
        from auth import User

        # User is typed as dict[str, Any] -- verify it accepts dict values
        user: User = {"user_id": "abc", "tenant_id": "t1", "sub": "abc"}
        assert user["user_id"] == "abc"
        assert user["tenant_id"] == "t1"

    def test_user_model_is_dict_str_any(self):
        from auth.models import User

        # User should be dict[str, Any]
        assert User == dict[str, Any]


class TestModuleInit:
    """Test src __init__ module."""

    def test_version_is_semver(self):
        from src import __version__

        parts = __version__.split(".")
        assert len(parts) == 3, f"Expected semver x.y.z, got {__version__}"
        for part in parts:
            assert part.isdigit(), f"Non-numeric version part: {part}"

    def test_version_matches_config(self):
        from config import get_settings
        from src import __version__

        get_settings.cache_clear()
        settings = get_settings()
        assert __version__ == settings.version
