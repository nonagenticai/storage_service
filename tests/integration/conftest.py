"""Integration test fixtures for a live storage_service endpoint.

These tests hit a REAL running service; nothing defaults to a remote host.

Run with:  STORAGE_URL=http://localhost:8391 uv run pytest tests/integration/ -v -m integration
"""

import os

import httpx
import pytest

pytestmark = pytest.mark.integration

STORAGE_URL = (os.environ.get("STORAGE_URL") or "").strip()


@pytest.fixture(scope="session")
def storage_client():
    """httpx client pointed at storage_service (no auth needed)."""
    if not STORAGE_URL:
        pytest.skip("STORAGE_URL is not set — integration tests never default to a live host")
    with httpx.Client(
        base_url=STORAGE_URL,
        timeout=30.0,
    ) as client:
        yield client
