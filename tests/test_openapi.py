"""Guardrail tests for the OpenAPI surface.

Asserts that every route has an explicit ``operation_id`` matching
``OPERATION_ID_PLAN.md`` and that the OpenAPI schema exposes the standard
metadata (security scheme, tag groups, reusable header parameter).
"""

from __future__ import annotations

import pytest

from main import app

EXPECTED_OPERATION_IDS: frozenset[str] = frozenset(
    {
        "service_root",
        "health_check",
        "health_live",
        "health_ready",
        "files_upload",
        "files_exists",
        "files_metadata",
        "files_download",
        "files_delete",
        "files_list",
        "buckets_list",
        "buckets_create",
        "buckets_get",
        "buckets_delete",
        "notifications_register",
        "notifications_deregister",
        "notifications_list",
    }
)


@pytest.fixture(scope="module")
def openapi_schema() -> dict:
    """Build the OpenAPI schema once per module."""
    app.openapi_schema = None
    return app.openapi()


def test_every_route_has_explicit_operation_id(openapi_schema: dict) -> None:
    """No path/method should rely on FastAPI's auto-generated operationId."""
    auto_generated_pattern_suffixes = ("_post", "_get", "_put", "_delete", "_patch")
    offenders: list[tuple[str, str, str]] = []
    for path, item in openapi_schema.get("paths", {}).items():
        for method, op in item.items():
            if not isinstance(op, dict):
                continue
            op_id: str = op.get("operationId", "")
            if (
                op_id.endswith(auto_generated_pattern_suffixes)
                and op_id not in EXPECTED_OPERATION_IDS
            ):
                offenders.append((method.upper(), path, op_id))
    assert not offenders, f"Routes without explicit operation_id (auto-generated): {offenders}"


def test_operation_ids_match_plan(openapi_schema: dict) -> None:
    """The set of operationIds in the schema must equal the plan."""
    actual: set[str] = set()
    for item in openapi_schema.get("paths", {}).values():
        for op in item.values():
            if isinstance(op, dict) and op.get("operationId"):
                actual.add(op["operationId"])

    missing = EXPECTED_OPERATION_IDS - actual
    unexpected = actual - EXPECTED_OPERATION_IDS
    assert not missing and not unexpected, (
        f"operationId drift — missing: {sorted(missing)}, unexpected: {sorted(unexpected)}"
    )


def test_operation_ids_are_unique(openapi_schema: dict) -> None:
    """Every operationId must be unique across the whole schema."""
    seen: dict[str, tuple[str, str]] = {}
    duplicates: list[tuple[str, tuple[str, str], tuple[str, str]]] = []
    for path, item in openapi_schema.get("paths", {}).items():
        for method, op in item.items():
            if not isinstance(op, dict):
                continue
            op_id = op.get("operationId")
            if not op_id:
                continue
            if op_id in seen:
                duplicates.append((op_id, seen[op_id], (method.upper(), path)))
            else:
                seen[op_id] = (method.upper(), path)
    assert not duplicates, f"Duplicate operationIds: {duplicates}"


def test_bearer_auth_scheme_is_declared(openapi_schema: dict) -> None:
    """BearerAuth security scheme must be present (license-token transport)."""
    schemes = openapi_schema.get("components", {}).get("securitySchemes", {})
    assert "BearerAuth" in schemes, "BearerAuth scheme missing from OpenAPI"
    scheme = schemes["BearerAuth"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"


def test_tenant_id_header_parameter_is_declared(openapi_schema: dict) -> None:
    """The reusable TenantIdHeader parameter must be in components.parameters."""
    parameters = openapi_schema.get("components", {}).get("parameters", {})
    assert "TenantIdHeader" in parameters, "TenantIdHeader parameter missing"
    param = parameters["TenantIdHeader"]
    assert param["in"] == "header"
    assert param["name"].lower() == "x-tenant-id"


def test_tag_groups_are_defined(openapi_schema: dict) -> None:
    """``openapi_tags`` must declare Health, Files, Buckets."""
    tag_names = {t["name"] for t in openapi_schema.get("tags", [])}
    assert {"Health", "Files", "Buckets"} <= tag_names, (
        f"Missing required tag groups; have {sorted(tag_names)}"
    )


def test_protected_routes_have_security_requirement(openapi_schema: dict) -> None:
    """Every /api/files/* and /api/buckets/* operation must require BearerAuth."""
    protected_paths = [
        p
        for p in openapi_schema.get("paths", {})
        if p.startswith("/api/files") or p.startswith("/api/buckets")
    ]
    assert protected_paths, "No /api/files/* or /api/buckets/* paths found in schema"
    for path in protected_paths:
        for method, op in openapi_schema["paths"][path].items():
            if not isinstance(op, dict):
                continue
            security = op.get("security", [])
            assert any("BearerAuth" in entry for entry in security), (
                f"{method.upper()} {path} is missing BearerAuth security requirement"
            )


def test_public_routes_have_no_security_requirement(openapi_schema: dict) -> None:
    """Health + root paths must not require auth in the schema."""
    public_paths = {"/", "/health", "/health/ready", "/health/live"}
    for path in public_paths:
        item = openapi_schema.get("paths", {}).get(path)
        if item is None:
            continue
        for method, op in item.items():
            if not isinstance(op, dict):
                continue
            security = op.get("security", [])
            assert not security, (
                f"Public route {method.upper()} {path} unexpectedly has security={security}"
            )
