"""License Token Authentication Middleware.

Uses license token (`X-Tenant-Id: Bearer <token>`) as the ONLY auth method.
No Keycloak, no JWT, no RBAC - valid license = full access.
"""

import asyncio
import hashlib
import ipaddress
import logging
import os
from typing import Any, Callable, cast

import httpx
from cachetools import TTLCache
from fastapi import Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# License introspection cache (5 min TTL, 1000 entries max)
_license_cache: TTLCache = TTLCache(maxsize=1000, ttl=300)
# Negative cache for ``active: false`` so a revoked token can't pin every
# request against the licenses endpoint. Short TTL so re-issuance is picked up.
_license_neg_cache: TTLCache = TTLCache(
    maxsize=1000, ttl=int(os.getenv("LICENSE_INTROSPECT_NEG_TTL", "60"))
)

# Licence introspection endpoint. No hardcoded fallback in source. Settings.license_introspect_url is the
# canonical source; this module-level read is a backwards-compat
# convenience for tests that monkey-patch the constant.
LICENSE_INTROSPECT_URL = os.getenv("LICENSE_INTROSPECT_URL", "")

# Wall-clock budget for a single introspection POST. Default 10s (was a
# hardcoded 2s): on a CPU-saturated host the loop can starve long enough that a
# tighter budget fires before the licenses endpoint replies → spurious 401.
LICENSE_INTROSPECT_TIMEOUT = float(os.getenv("LICENSE_INTROSPECT_TIMEOUT", "10.0"))

# Per-token single-flight locks. A cold-cache burst of concurrent requests for
# the SAME token would otherwise each miss the cache and independently POST the
# licenses endpoint; on a CPU-saturated box that stampede starves the loop and
# trips the introspect timeout → spurious 401 (the 2026-06-27 TTS bug class).
# The lock collapses the burst into one upstream call; the rest read the cache.
#
# ⚠️ BOUNDED, and it must stay bounded. This was a plain ``dict`` with a
# ``setdefault`` and no deletion anywhere in the module. Its key is derived from
# the CALLER-SUPPLIED bearer token, so anyone looping
# ``X-Tenant-Id: Bearer <random>`` minted one permanent entry per request — an
# unauthenticated, un-rate-limited path to unbounded memory growth, since each
# such request still 401s and nothing throttles a 401. Both sibling caches above
# were already ``TTLCache(maxsize=1000)``; the locks were the one unbounded
# structure of the three.
#
# ⚠️ Eviction race, stated explicitly because it is a real and DELIBERATE trade.
# An entry can now be evicted (by TTL, or by size pressure past ``maxsize``)
# while a coroutine still holds it. A later arrival for the same token then
# ``setdefault``s a FRESH lock and does not wait on the held one, so two
# coroutines can introspect the same cold token concurrently. That is the
# correct thing to accept: the lock is a single-flight OPTIMISATION, not a
# correctness barrier — losing it costs one extra upstream POST, never a wrong
# auth decision, because the verdict is whatever the licenses endpoint returns
# and the loser simply overwrites the cache with an identical payload. An
# unbounded dict, by contrast, is a remote memory-exhaustion primitive. The TTL
# is chosen to sit comfortably above ``LICENSE_INTROSPECT_TIMEOUT`` so that
# expiry cannot plausibly fire mid-introspection; size pressure needs 1000
# distinct cold tokens in flight to bite.
_INTROSPECT_LOCK_TTL = max(300.0, LICENSE_INTROSPECT_TIMEOUT * 10)
_introspect_locks: TTLCache = TTLCache(maxsize=1000, ttl=_INTROSPECT_LOCK_TTL)

# Public endpoints that don't require authentication
PUBLIC_ENDPOINTS = {
    "/",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/health",
    "/health/ready",
    "/health/live",
    "/healthz",
    "/ready",
    "/readyz",
    "/metrics",
    "/favicon.ico",
}

# Implicit public trees, in addition to the exact PUBLIC_ENDPOINTS above.
# Matching is anchored to a path SEGMENT: `/docs` and `/docs/oauth2-redirect`
# are public, `/docsecret` is NOT. A bare `startswith` here was an auth-bypass
# class — the same unanchored shape that let `/storage/api/buckets/ready` reach
# MinIO unauthenticated (gitops #2204), and the one fixed in kag_common #23.
# Every probe path this service serves (`/health`, `/health/live`,
# `/health/ready`, `/healthz`, `/ready`, `/readyz`) is either listed explicitly
# in PUBLIC_ENDPOINTS or under the `/health/` segment, so the tightening cannot
# auth-wall a liveness probe.
PUBLIC_PREFIXES = ("/docs", "/redoc", "/static", "/health")

# Protected prefixes - storage operations require auth
PROTECTED_PREFIXES = {"/api/files", "/api/buckets"}

DEFAULT_TENANT_ID = os.getenv("DEFAULT_TENANT_ID", "0195f48b-d000-7000-8000-000000000001")

_TRUSTED_CIDRS_RAW = os.getenv(
    "TRUSTED_CIDRS",
    "127.0.0.1/32,::1/128,192.168.0.0/16,172.16.0.0/12,10.0.0.0/8",
)
TRUSTED_NETWORKS: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = [
    ipaddress.ip_network(cidr.strip(), strict=False)
    for cidr in _TRUSTED_CIDRS_RAW.split(",")
    if cidr.strip()
]


def _is_trusted_network(host: str | None) -> bool:
    """Check if the client IP is within a trusted CIDR range."""
    if not host:
        return False
    try:
        addr = ipaddress.ip_address(host)
        return any(addr in net for net in TRUSTED_NETWORKS)
    except ValueError:
        return False


def _cached_license(cache_key: str) -> dict[str, Any] | None:
    """Return a positive- or negative-cache hit for ``cache_key`` (or ``None``)."""
    if cache_key in _license_cache:
        return cast(dict[str, Any], _license_cache[cache_key])
    if cache_key in _license_neg_cache:
        return cast(dict[str, Any], _license_neg_cache[cache_key])
    return None


async def _introspect_license(token: str) -> dict[str, Any] | None:
    """Introspect license token to get tenant context.

    ``active`` payloads are cached 5 min; ``active: false`` payloads are cached
    briefly in the negative cache. A cold-cache burst for the same token is
    collapsed into a single upstream POST via a per-token single-flight lock.
    """
    cache_key = f"lic:{hashlib.sha256(token.encode()).hexdigest()[:16]}"
    hit = _cached_license(cache_key)
    if hit is not None:
        return hit

    if not LICENSE_INTROSPECT_URL:
        logger.warning("LICENSE_INTROSPECT_URL not configured; rejecting token")
        return None

    # Cache miss: single-flight so a concurrent burst for the same cold token
    # collapses into ONE upstream introspection. Re-check inside the lock — a
    # prior waiter may have populated the cache while we were blocked.
    lock = _introspect_locks.setdefault(cache_key, asyncio.Lock())
    async with lock:
        hit = _cached_license(cache_key)
        if hit is not None:
            return hit
        return await _introspect_license_uncached(token, cache_key)


async def _introspect_license_uncached(token: str, cache_key: str) -> dict[str, Any] | None:
    """Perform the introspection POST and populate the caches.

    Always called under the per-token single-flight lock held by
    :func:`_introspect_license`.
    """
    try:
        async with httpx.AsyncClient(timeout=LICENSE_INTROSPECT_TIMEOUT) as client:
            resp = await client.post(LICENSE_INTROSPECT_URL, json={"token": token})
            if resp.status_code == 200:
                data: dict[str, Any] = resp.json()
                if data.get("active"):
                    _license_cache[cache_key] = data
                else:
                    _license_neg_cache[cache_key] = data
                return data
    except Exception as e:
        logger.warning(f"License introspection failed: {e}")
    return None


class AuthMiddleware(BaseHTTPMiddleware):
    """License Token Authentication Middleware."""

    def __init__(self, app: Any, bypass_auth: bool = False):
        super().__init__(app)
        self.bypass_auth = bypass_auth

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process authentication via license token."""
        try:
            path = request.url.path.rstrip("/") or "/"

            # Skip auth for public/non-protected endpoints
            if self._is_public_endpoint(path) or not self._is_protected(path):
                return cast(Response, await call_next(request))

            # Skip auth if bypassed (for testing) - but still use X-Tenant-Id if provided
            if self.bypass_auth or os.getenv("AUTH_ENABLED", "true").lower() == "false":
                # Use X-Tenant-Id header if provided, otherwise the configured
                # platform tenant. Minting a literal here invented an owner for
                # every row written under bypass.
                tenant_id = request.headers.get("X-Tenant-Id", DEFAULT_TENANT_ID)
                request.state.user = {"user_id": tenant_id, "tenant_id": tenant_id}
                request.state.tenant_id = tenant_id
                return cast(Response, await call_next(request))

            # Extract token from X-Tenant-Id header (Bearer format)
            token = self._extract_license_token(request)
            x_tenant_id = request.headers.get("X-Tenant-Id")

            # If a token is provided, always validate it (even from trusted networks)
            if token:
                license_result = await _introspect_license(token)
                if not license_result or not license_result.get("active"):
                    return self._unauthorized_response("Invalid or expired license token")

                # tenant_id FIRST. The licences service returns subject_id and
                # tenant_id as DIFFERENT fields (a subject is the licence holder,
                # and one subject can hold licences in several tenants), so
                # preferring subject_id attributed every request to the wrong
                # tenant. subject_id is only a fallback for a licence that
                # carries no tenant_id at all.
                # Reference: webscraper_service#64, requirements_management 43dc8f1.
                license_tenant_id = license_result.get("tenant_id") or license_result.get(
                    "subject_id"
                )
                if not license_tenant_id:
                    return self._unauthorized_response("License token missing tenant context")
                # The principal keeps the subject separately; it never stands in
                # for the tenant when a tenant_id is present.
                license_subject_id = license_result.get("subject_id") or license_tenant_id

                request.state.user = {
                    "user_id": str(license_subject_id),
                    "tenant_id": str(license_tenant_id),
                    "sub": str(license_subject_id),
                }
                request.state.tenant_id = str(license_tenant_id)
                logger.debug(f"Authenticated via license token: {license_tenant_id}")
                return cast(Response, await call_next(request))

            # No token — check if request is from a trusted network.
            #
            # ⚠️ An unauthenticated caller does NOT get to name its own tenant.
            # This used to read the tenant straight off the caller-supplied
            # ``X-Tenant-Id`` header, so any pod inside TRUSTED_CIDRS could
            # assert any identity it liked — and one live caller (the
            # commonpractice audit exporter) sends the bare string
            # ``commonpractice``, MINTING a tenant that exists in no registry.
            # That is the same "an arbitrary string is a licence to mint a
            # tenant" class as the ``n8n-dev`` literal removed in #28. A tenant
            # is only ever the subject of a validated licence token; without
            # one the caller is the configured platform tenant, full stop.
            # Any authorization built on ``request.state.tenant_id`` is
            # worthless until this holds.
            client_host = request.client.host if request.client else None
            if _is_trusted_network(client_host):
                if x_tenant_id:
                    logger.warning(
                        "Ignoring caller-asserted X-Tenant-Id from trusted network "
                        f"{client_host}: an unauthenticated caller cannot select a tenant"
                    )
                tenant_id = DEFAULT_TENANT_ID
                request.state.user = {
                    "user_id": str(tenant_id),
                    "tenant_id": str(tenant_id),
                    "sub": str(tenant_id),
                }
                request.state.tenant_id = str(tenant_id)
                request.state.license = None
                logger.debug(f"Trusted network access from {client_host}: tenant={tenant_id}")
                return cast(Response, await call_next(request))

            # Not trusted, no token — reject
            return self._unauthorized_response("Missing authentication token")

        except Exception as e:
            logger.error(f"Authentication middleware error: {e}")
            return self._internal_error_response("Authentication service error")

    def _is_public_endpoint(self, path: str) -> bool:
        """Check if endpoint is public."""
        if path in PUBLIC_ENDPOINTS:
            return True
        return any(path == prefix or path.startswith(prefix + "/") for prefix in PUBLIC_PREFIXES)

    def _is_protected(self, path: str) -> bool:
        """Check if path requires authentication."""
        return any(path.startswith(prefix) for prefix in PROTECTED_PREFIXES)

    def _extract_license_token(self, request: Request) -> str | None:
        """Extract Bearer token from X-Tenant-Id header."""
        x_tenant_id = request.headers.get("X-Tenant-Id")
        if x_tenant_id and x_tenant_id.lower().startswith("bearer "):
            return x_tenant_id[7:].strip()
        return None

    def _unauthorized_response(self, detail: str) -> Response:
        """Return 401 Unauthorized response."""
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={
                "error": {
                    "code": "AUTHENTICATION_REQUIRED",
                    "message": detail,
                    "status": 401,
                }
            },
            headers={"WWW-Authenticate": "Bearer"},
        )

    def _internal_error_response(self, detail: str) -> Response:
        """Return 500 Internal Server Error response."""
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "AUTHENTICATION_SERVICE_ERROR",
                    "message": detail,
                    "status": 500,
                }
            },
        )
