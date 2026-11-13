"""Error-envelope shape regression tests.

Every error response — 404 for an unknown path, 422 from request validation,
500 from an unhandled exception — must use the shared shape:

    {
        "error": {
            "code": "...",
            "message": "...",
            "status": <int>,
            "request_id": "<uuid7>",
            "timestamp": "YYYY-MM-DDTHH:MM:SSZ"
        }
    }
"""

from __future__ import annotations

import re
from collections.abc import AsyncGenerator

import httpx
import pytest

UUID7_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def _assert_envelope(body: dict, *, expected_status: int) -> None:
    assert set(body.keys()) == {"error"}, body
    err = body["error"]
    assert isinstance(err.get("code"), str) and err["code"], err
    assert isinstance(err.get("message"), str) and err["message"], err
    assert err.get("status") == expected_status, err
    assert UUID7_RE.match(err.get("request_id", "")), err
    assert TIMESTAMP_RE.match(err.get("timestamp", "")), err


@pytest.fixture
async def envelope_client() -> AsyncGenerator[httpx.AsyncClient]:
    """Client against the real app — full middleware stack including RequestId."""
    from main import app

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


async def test_404_uses_envelope(envelope_client: httpx.AsyncClient) -> None:
    """A request to an unknown path returns 404 in the new envelope shape."""
    resp = await envelope_client.get("/this-path-does-not-exist")
    assert resp.status_code == 404
    _assert_envelope(resp.json(), expected_status=404)


async def test_response_includes_request_id_header(envelope_client: httpx.AsyncClient) -> None:
    """The X-Request-ID response header is set on every response, even errors."""
    resp = await envelope_client.get("/this-path-does-not-exist")
    assert resp.headers.get("X-Request-ID"), "X-Request-ID missing on response"
    assert UUID7_RE.match(resp.headers["X-Request-ID"])


async def test_handled_http_exception_uses_envelope() -> None:
    """A raised HTTPException from a route flows through the http handler."""
    from fastapi import FastAPI, HTTPException
    from starlette.exceptions import HTTPException as StarletteHTTPException

    from main import http_exception_handler

    app = FastAPI()
    app.exception_handler(StarletteHTTPException)(http_exception_handler)

    @app.get("/boom")
    async def _boom() -> None:
        raise HTTPException(status_code=418, detail="i am a teapot")

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/boom")

    assert resp.status_code == 418
    body = resp.json()
    _assert_envelope(body, expected_status=418)
    assert body["error"]["message"] == "i am a teapot"
    assert body["error"]["code"] == "HTTP_418"
