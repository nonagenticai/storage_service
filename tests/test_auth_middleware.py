"""Integration-shape tests for the license-token AuthMiddleware.

Complementary to ``tests/test_auth_middleware_internals.py`` (which mocks
internals + exercises CIDR/cache logic). These tests exercise the middleware
end-to-end against a minimal isolated ASGI app.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

import auth.middleware as auth_middleware
from auth.middleware import AuthMiddleware, _license_cache


def _make_app() -> FastAPI:
    """Build a minimal app with one public + one protected route."""
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/health")
    async def _health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/api/files/echo")
    async def _echo(request: Request) -> JSONResponse:
        return JSONResponse(
            {
                "tenant_id": getattr(request.state, "tenant_id", None),
                "user": getattr(request.state, "user", None),
            },
        )

    return app


@pytest.fixture(autouse=True)
def _clear_license_cache() -> None:
    """Each test starts with a fresh introspection cache."""
    _license_cache.clear()


@pytest.fixture
async def client() -> AsyncGenerator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def test_health_is_public(client: httpx.AsyncClient) -> None:
    resp = await client.get("/health")
    assert resp.status_code == 200


async def test_protected_route_from_trusted_network_bypasses_auth(
    client: httpx.AsyncClient,
) -> None:
    """RFC1918 peer (httpx ASGI 127.0.0.1) is a trusted network."""
    resp = await client.get("/api/files/echo")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tenant_id"] == "0195f48b-d000-7000-8000-000000000001"


async def test_protected_route_with_valid_license_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A valid Bearer token in X-Tenant-Id is introspected and admitted."""
    introspect_payload: dict[str, Any] = {
        "active": True,
        "tenant_id": "tenant-uuid-1",
        "subject_id": "subject-uuid-9",
    }

    async def _fake(token: str) -> dict[str, Any]:
        assert token == "abc.def.ghi"
        return introspect_payload

    monkeypatch.setattr(auth_middleware, "_introspect_license", _fake)

    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/api/files/echo",
            headers={"X-Tenant-Id": "Bearer abc.def.ghi"},
        )

    assert resp.status_code == 200, resp.text
    body = resp.json()
    # tenant_id wins over subject_id: they are DIFFERENT fields upstream.
    assert body["tenant_id"] == "tenant-uuid-1"
    assert body["user"]["tenant_id"] == "tenant-uuid-1"
    # The subject is kept on the principal, never used as the tenant.
    assert body["user"]["sub"] == "subject-uuid-9"
    assert body["user"]["user_id"] == "subject-uuid-9"


async def _echo_with_licence(
    monkeypatch: pytest.MonkeyPatch, payloads: dict[str, dict[str, Any]], token: str
) -> dict[str, Any]:
    async def _fake(tok: str) -> dict[str, Any]:
        return payloads[tok]

    monkeypatch.setattr(auth_middleware, "_introspect_license", _fake)
    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/files/echo", headers={"X-Tenant-Id": f"Bearer {token}"})
    assert resp.status_code == 200, resp.text
    result: dict[str, Any] = resp.json()
    return result


async def test_one_subject_two_tenants_resolve_to_different_tenants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: one subject holding licences in two tenants must be
    attributed to two DIFFERENT tenants. Deriving the tenant from subject_id
    collapsed both onto the subject — a cross-tenant attribution."""
    payloads = {
        "tok-a": {"active": True, "subject_id": "subj-shared", "tenant_id": "tenant-a"},
        "tok-b": {"active": True, "subject_id": "subj-shared", "tenant_id": "tenant-b"},
    }
    a = await _echo_with_licence(monkeypatch, payloads, "tok-a")
    b = await _echo_with_licence(monkeypatch, payloads, "tok-b")
    assert a["tenant_id"] == "tenant-a"
    assert b["tenant_id"] == "tenant-b"
    assert a["tenant_id"] != b["tenant_id"]
    assert a["user"]["sub"] == b["user"]["sub"] == "subj-shared"


async def test_subject_only_licence_falls_back_to_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A licence with no tenant_id still authenticates, on its subject."""
    body = await _echo_with_licence(
        monkeypatch, {"tok": {"active": True, "subject_id": "subj-only"}}, "tok"
    )
    assert body["tenant_id"] == "subj-only"
    assert body["user"]["sub"] == "subj-only"


async def test_protected_route_with_invalid_license_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An inactive introspection result returns 401 with the envelope shape."""

    async def _fake(_token: str) -> dict[str, Any]:
        return {"active": False}

    monkeypatch.setattr(auth_middleware, "_introspect_license", _fake)

    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/api/files/echo",
            headers={"X-Tenant-Id": "Bearer dud-token"},
        )

    assert resp.status_code == 401
    body = resp.json()
    assert body["error"]["code"] == "AUTHENTICATION_REQUIRED"
    assert body["error"]["status"] == 401
    assert resp.headers["WWW-Authenticate"] == "Bearer"


async def test_protected_route_missing_tenant_in_introspection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Active token but no tenant_id and no subject_id → 401."""

    async def _fake(_token: str) -> dict[str, Any]:
        return {"active": True}

    monkeypatch.setattr(auth_middleware, "_introspect_license", _fake)

    transport = httpx.ASGITransport(app=_make_app())
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get(
            "/api/files/echo",
            headers={"X-Tenant-Id": "Bearer no-tenant"},
        )

    assert resp.status_code == 401
    assert "tenant" in resp.json()["error"]["message"].lower()
