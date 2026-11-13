"""Storage Service - FastAPI Application.

Central storage API that proxies all file operations to MinIO. The ONLY
service that holds MinIO credentials.

Auth: license token via ``X-Tenant-Id: Bearer <token>``, validated against
LICENSE_INTROSPECT_URL. Trusted-network clients (RFC 1918 / loopback) bypass
token requirement with the configured default tenant.
"""

import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from auth.middleware import PROTECTED_PREFIXES, PUBLIC_ENDPOINTS, AuthMiddleware
from config import get_settings
from middleware.logging import RequestLoggingMiddleware
from middleware.request_id import RequestIdMiddleware
from middleware.security_headers import SecurityHeadersMiddleware
from routes import buckets_router, files_router, health_router, notifications_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

settings = get_settings()

LEAK_EXCEPTION_DETAILS = os.getenv(
    "LEAK_EXCEPTION_DETAILS", ""
).lower() == "true" or settings.environment.lower() in {"development", "dev"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    logger.info(f"Starting {settings.service_name} v{settings.version}")
    logger.info(f"MinIO endpoint: {settings.minio_endpoint}")
    logger.info(f"Allowed buckets: {settings.allowed_bucket_list}")
    logger.info(f"Virus scanning: {'enabled' if settings.enable_virus_scanning else 'disabled'}")

    try:
        from services.minio_client import get_minio_client

        get_minio_client()
        logger.info("MinIO client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize MinIO client: {e}")

    if settings.enable_virus_scanning:
        try:
            from services.virus_scanner import get_virus_scanner

            scanner = get_virus_scanner()
            if scanner.ping():
                logger.info("ClamAV scanner initialized and responding")
            else:
                logger.warning("ClamAV scanner initialized but not responding")
        except Exception as e:
            logger.warning(f"ClamAV initialization failed: {e}")

    yield

    logger.info(f"Shutting down {settings.service_name}")


app = FastAPI(
    title="Storage Service",
    description=(
        "Centralized storage proxy for MinIO object storage with optional ClamAV virus scanning. "
        "This service is the ONLY holder of MinIO credentials — all other services access storage "
        "through this API. Auth: license token via `X-Tenant-Id: Bearer <token>`, or "
        "trusted-network pass-through for internal cluster traffic. Health/docs endpoints public."
    ),
    version=settings.version,
    lifespan=lifespan,
    redirect_slashes=False,
    swagger_ui_parameters={"persistAuthorization": True},
    # Fallback unique-ID generator. Every route declares operation_id= per
    # OPERATION_ID_PLAN.md; this exists so a forgotten ID degrades to
    # `<tag>_<func>` (readable) instead of FastAPI's default.
    generate_unique_id_function=lambda route: (
        f"{route.tags[0] if route.tags else 'default'}_{route.name}"
    ),
    openapi_tags=[
        {"name": "Health", "description": "Liveness, readiness, and root probes."},
        {"name": "Files", "description": "Object upload/download/list/delete operations."},
        {"name": "Buckets", "description": "Bucket lifecycle: list, create, get, delete."},
    ],
)

# --- Middleware ---
# Starlette executes in reverse-registration order. Target request-side order:
#   RequestId -> Auth -> SecurityHeaders -> RequestLogging -> CORS -> handler
raw_origins = settings.cors_allow_origins
allowed_origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
allow_credentials = "*" not in allowed_origins

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if "*" in allowed_origins else allowed_origins,
    allow_credentials=allow_credentials,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Processing-Time"],
)

app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

if settings.enable_auth:
    app.add_middleware(AuthMiddleware)
    logger.info("Authentication middleware enabled")
else:
    logger.warning("Authentication middleware DISABLED (ENABLE_AUTH=false)")

app.add_middleware(RequestIdMiddleware)


# --- Global exception handlers ---
def _error_envelope(
    code: str,
    message: str,
    http_status: int,
    *,
    request_id: str,
    details: str | None = None,
) -> dict[str, Any]:
    """Build the standardized error envelope."""
    payload: dict[str, Any] = {
        "code": code,
        "message": message,
        "status": http_status,
        "request_id": request_id,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if details is not None:
        payload["details"] = details
    return {"error": payload}


def _http_exception_to_response(exc: StarletteHTTPException, request_id: str) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_envelope(
            f"HTTP_{exc.status_code}", str(exc.detail), exc.status_code, request_id=request_id
        ),
        headers=exc.headers,
    )


def _find_http_exception(exc: BaseException) -> HTTPException | None:
    """Walk nested ExceptionGroups to find the first HTTPException."""
    if isinstance(exc, HTTPException):
        return exc
    if isinstance(exc, BaseExceptionGroup):
        for sub in exc.exceptions:
            found = _find_http_exception(sub)
            if found is not None:
                return found
    return None


def _request_id_from(request: Request) -> str:
    return request.state.request_id if hasattr(request.state, "request_id") else str(uuid.uuid7())


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Render HTTPException (incl. FastAPI's 404 for unknown routes) into the envelope."""
    return _http_exception_to_response(exc, _request_id_from(request))


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Render pydantic request-validation errors into the envelope (HTTP 422)."""
    request_id = _request_id_from(request)
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=_error_envelope(
            "VALIDATION_ERROR",
            "Request validation failed",
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            request_id=request_id,
            details=str(exc.errors()) if LEAK_EXCEPTION_DETAILS else None,
        ),
    )


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all for uncaught exceptions; returns the standardized envelope."""
    request_id: str = _request_id_from(request)

    http_exc = _find_http_exception(exc)
    if http_exc is not None:
        return _http_exception_to_response(http_exc, request_id)

    logger.error(f"unhandled_error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=_error_envelope(
            "INTERNAL_SERVER_ERROR",
            "An unexpected error occurred",
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            request_id=request_id,
            details=str(exc) if LEAK_EXCEPTION_DETAILS else None,
        ),
    )


# --- OpenAPI schema with per-path security ---
def custom_openapi() -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )

    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes.setdefault(
        "BearerAuth",
        {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "License",
            "description": (
                "License token. Transport: `X-Tenant-Id: Bearer <token>` "
                "(not the Authorization header — that is reserved for caller-side auth)."
            ),
        },
    )

    parameters = components.setdefault("parameters", {})
    parameters.setdefault(
        "TenantIdHeader",
        {
            "name": "X-Tenant-Id",
            "in": "header",
            "required": False,
            "description": "Tenant identifier (defaults to configured DEFAULT_TENANT_ID).",
            "schema": {"type": "string", "default": settings.default_tenant_id},
            "example": settings.default_tenant_id,
        },
    )

    for path, path_item in openapi_schema.get("paths", {}).items():
        normalized = path.rstrip("/") or "/"
        # Segment-anchored, matching auth.middleware._is_public_endpoint. A bare
        # startswith here would annotate `/health-secrets` as public in the spec
        # even once the middleware (correctly) protects it.
        is_public = normalized in PUBLIC_ENDPOINTS or any(
            normalized == prefix or normalized.startswith(prefix + "/")
            for prefix in ("/docs", "/redoc", "/static", "/openapi.json", "/favicon.ico", "/health")
        )
        is_protected = any(normalized.startswith(prefix) for prefix in PROTECTED_PREFIXES)

        for operation in list(path_item.values()):
            if not isinstance(operation, dict):
                continue
            if is_protected and not is_public:
                operation.setdefault("security", [{"BearerAuth": []}])
            elif is_public:
                operation.pop("security", None)

            op_params = operation.setdefault("parameters", [])
            has_tenant = any(
                p.get("name", "").lower() == "x-tenant-id" and p.get("in") == "header"
                for p in op_params
            )
            if not has_tenant:
                op_params.append({"$ref": "#/components/parameters/TenantIdHeader"})

    app.openapi_schema = openapi_schema
    return app.openapi_schema


object.__setattr__(app, "openapi", custom_openapi)

app.include_router(health_router)
app.include_router(files_router)
app.include_router(buckets_router)
app.include_router(notifications_router)


@app.get(
    "/",
    operation_id="service_root",
    tags=["Health"],
    summary="Service banner",
)
async def root():
    """Root endpoint with service info (public)."""
    return {
        "service": settings.service_name,
        "version": settings.version,
        "docs": "/docs",
    }
