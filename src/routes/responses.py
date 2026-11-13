"""Common response definitions for OpenAPI documentation.

Provides the error-envelope Pydantic models used across the service plus a few
ready-made response dictionaries for the per-route ``responses=`` argument.

The envelope shape matches the canonical ``{error: {code, message, status}}``
core, extended with optional ``request_id``, ``timestamp``, and ``details``
fields populated by the exception handlers in ``main.py``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    """Inner error payload."""

    code: str = Field(..., description="Stable machine-readable error code")
    message: str = Field(..., description="Human-readable error description")
    status: int = Field(..., description="HTTP status code")
    request_id: str | None = Field(default=None, description="Request UUID7 for log correlation")
    timestamp: str | None = Field(
        default=None, description="ISO-8601 UTC timestamp the error was emitted"
    )
    details: str | None = Field(
        default=None,
        description="Optional debug detail; only populated when LEAK_EXCEPTION_DETAILS=true",
    )


class ErrorResponse(BaseModel):
    """Standard error response envelope."""

    error: ErrorDetail


AUTH_RESPONSES: dict[int | str, dict[str, Any]] = {
    401: {"description": "Authentication required", "model": ErrorResponse},
}

NOT_FOUND_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: {"description": "Resource not found", "model": ErrorResponse},
}

AUTH_AND_NOT_FOUND: dict[int | str, dict[str, Any]] = {
    **AUTH_RESPONSES,
    **NOT_FOUND_RESPONSES,
}

CONFLICT_RESPONSES: dict[int | str, dict[str, Any]] = {
    409: {"description": "Resource conflict", "model": ErrorResponse},
}

VALIDATION_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"description": "Invalid request format", "model": ErrorResponse},
    413: {"description": "Payload too large", "model": ErrorResponse},
    422: {"description": "Validation error", "model": ErrorResponse},
}

STORAGE_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    500: {"description": "Storage backend error", "model": ErrorResponse},
}

HEALTH_RESPONSES: dict[int | str, dict[str, Any]] = {
    503: {"description": "Service not ready", "model": ErrorResponse},
}
