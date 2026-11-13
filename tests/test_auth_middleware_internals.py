"""Tests for authentication middleware."""

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from auth import middleware as auth_mw
from auth.middleware import (
    AuthMiddleware,
    _introspect_license,
    _is_trusted_network,
    _license_cache,
)


class TestIsTrustedNetwork:
    """Test trusted network detection."""

    def test_localhost_ipv4_trusted(self):
        assert _is_trusted_network("127.0.0.1") is True

    def test_private_192_168_trusted(self):
        assert _is_trusted_network("192.168.1.100") is True

    def test_private_10_trusted(self):
        assert _is_trusted_network("10.42.0.5") is True

    def test_private_172_16_trusted(self):
        assert _is_trusted_network("172.16.0.1") is True

    def test_public_ip_not_trusted(self):
        assert _is_trusted_network("8.8.8.8") is False

    def test_none_host(self):
        assert _is_trusted_network(None) is False

    def test_invalid_host(self):
        assert _is_trusted_network("not-an-ip") is False

    def test_ipv6_localhost(self):
        assert _is_trusted_network("::1") is True


class TestIntrospectLicense:
    """Test license token introspection."""

    @pytest.fixture(autouse=True)
    def clear_cache(self):
        _license_cache.clear()
        auth_mw._license_neg_cache.clear()
        auth_mw._introspect_locks.clear()
        yield
        _license_cache.clear()
        auth_mw._license_neg_cache.clear()
        auth_mw._introspect_locks.clear()

    @pytest.mark.asyncio
    async def test_single_flight_cold_burst(self, monkeypatch):
        """A cold-cache burst of concurrent calls for the same token yields one
        upstream POST and twelve correct verdicts.

        ⚠️ This is NOT the control for the single-flight lock, despite reading
        like one, and this PR's description was wrong to cite it as one.
        ``mock_client.post`` is an ``AsyncMock``: awaiting it completes without
        ever suspending, so the first coroutine runs from cache-miss to
        cache-populate without the loop switching tasks, and the other eleven
        find a warm cache whether or not a lock exists. Measured: deleting the
        lock from ``auth/middleware.py`` entirely leaves this test — and the
        whole suite — green.

        It still earns its place as a plumbing/verdict check. The property it
        was credited with is pinned by
        ``test_the_burst_collapses_because_of_the_lock_not_the_scheduler``.
        """
        monkeypatch.setattr(auth_mw, "LICENSE_INTROSPECT_URL", "http://lic/introspect")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"active": True, "subject_id": "tenant-1"}

        with patch("auth.middleware.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            results = await asyncio.gather(*[_introspect_license("tok") for _ in range(12)])

        assert all(r is not None and r["active"] for r in results)
        assert mock_client.post.call_count == 1  # 12-way burst → one introspection

    @pytest.mark.asyncio
    async def test_the_burst_collapses_because_of_the_lock_not_the_scheduler(self, monkeypatch):
        """The real control for single-flight: the stand-in upstream SUSPENDS.

        A real introspection POST is network I/O and always yields to the loop
        between "we decided to call upstream" and "the cache is populated". That
        window is the entire reason the lock exists, and a stand-in that never
        suspends closes it for free — which is why the ``AsyncMock``-based test
        above cannot distinguish a working lock from a deleted one.

        ``await asyncio.sleep(0)`` reintroduces exactly one suspension point in
        exactly that window. With the lock: the first caller holds it across the
        suspension and the other eleven wait, re-check the cache on entry, and
        return the cached verdict — one upstream call. Without it: all twelve are
        already past the cache check when the first suspends, so all twelve call
        upstream — measured 12, which is the 2026-06-27 stampede itself.
        """
        monkeypatch.setattr(auth_mw, "LICENSE_INTROSPECT_URL", "http://lic/introspect")

        calls = 0
        payload = {"active": True, "subject_id": "tenant-1"}

        async def _yielding_upstream(token: str, cache_key: str):
            nonlocal calls
            calls += 1
            # The suspension a real ``httpx`` POST always has, and an AsyncMock
            # never does.
            await asyncio.sleep(0)
            _license_cache[cache_key] = payload
            return payload

        monkeypatch.setattr(auth_mw, "_introspect_license_uncached", _yielding_upstream)

        burst = 12
        results = await asyncio.gather(*[_introspect_license("tok") for _ in range(burst)])

        # Non-vacuity: all twelve must have taken the cache-MISS path. If the
        # cache had been warm, "1 upstream call" would be true for the wrong
        # reason and the lock would again be unmeasured.
        assert calls >= 1, "no caller reached the upstream path; this test proves nothing"
        assert all(r is not None and r["active"] for r in results)
        assert calls == 1, (
            f"{burst} concurrent cold-cache callers made {calls} upstream introspections; "
            "the per-token single-flight lock is not collapsing the burst"
        )

    @pytest.mark.asyncio
    async def test_lock_map_is_bounded_under_attacker_supplied_tokens(self, monkeypatch):
        """``_introspect_locks`` must not grow once per distinct bearer token.

        It was a plain ``dict`` with a ``setdefault`` and no deletion anywhere in
        the module, keyed by ``sha256(token)[:16]`` — a value the CALLER picks.
        Looping ``X-Tenant-Id: Bearer <random>`` therefore minted one permanent
        entry per request, unauthenticated and unthrottled (every one of those
        requests still 401s, and nothing rate-limits a 401). Its two siblings,
        ``_license_cache`` and ``_license_neg_cache``, were already
        ``TTLCache(maxsize=1000)``; this was the odd one out.

        Note the tokens here are deliberately ones that never introspect
        successfully, so neither sibling cache absorbs them: the lock map is the
        only structure that grows, which is exactly the attacker's cheapest path.
        """
        monkeypatch.setattr(auth_mw, "LICENSE_INTROSPECT_URL", "http://lic/introspect")

        calls = 0

        async def _never_valid(token: str, cache_key: str):
            nonlocal calls
            calls += 1
            return None

        monkeypatch.setattr(auth_mw, "_introspect_license_uncached", _never_valid)

        attempts = 2500
        for i in range(attempts):
            assert await _introspect_license(f"junk-token-{i}") is None

        # Non-vacuity: every attempt really did take the cache-miss path that
        # creates a lock. Without this, a change that short-circuited earlier
        # would satisfy the bound while proving nothing.
        assert calls == attempts, f"only {calls}/{attempts} attempts reached the lock path"
        assert len(auth_mw._introspect_locks) <= 1000, (
            f"{attempts} distinct caller-supplied tokens left "
            f"{len(auth_mw._introspect_locks)} permanent lock entries"
        )

    @pytest.mark.asyncio
    async def test_evicting_a_held_lock_costs_one_extra_call_not_an_auth_error(self, monkeypatch):
        """Pins the DELIBERATE trade the bound introduces.

        Bounding the map means an entry can be evicted while a coroutine still
        holds it, so a later arrival for the same token takes a different lock
        and introspects concurrently. This asserts the consequence is exactly
        what the comment in ``auth/middleware.py`` claims — one extra upstream
        POST, and both callers still get the correct verdict — and not a wrong
        or failed auth decision. If this ever fails, the trade recorded in the
        source is no longer the trade being made.
        """
        monkeypatch.setattr(auth_mw, "LICENSE_INTROSPECT_URL", "http://lic/introspect")

        payload = {"active": True, "subject_id": "tenant-1"}
        entered = asyncio.Semaphore(0)
        release = asyncio.Event()
        calls = 0

        async def _slow(token: str, cache_key: str):
            nonlocal calls
            calls += 1
            entered.release()
            await release.wait()
            auth_mw._license_cache[cache_key] = payload
            return payload

        monkeypatch.setattr(auth_mw, "_introspect_license_uncached", _slow)

        first = asyncio.create_task(_introspect_license("victim"))
        await asyncio.wait_for(entered.acquire(), timeout=5)

        # Evict the held lock by size pressure.
        # ``TTLCache.maxsize`` is typed ``int | float`` (``Cache`` allows an
        # unbounded float maxsize); this one is an int, so narrow it explicitly
        # rather than let ``range()`` take a ``float``.
        for i in range(int(auth_mw._introspect_locks.maxsize) + 5):
            auth_mw._introspect_locks[f"filler-{i}"] = asyncio.Lock()

        second = asyncio.create_task(_introspect_license("victim"))
        await asyncio.wait_for(entered.acquire(), timeout=5)

        release.set()
        r1, r2 = await asyncio.gather(first, second)

        assert r1 == payload and r2 == payload, "an evicted lock must not change the verdict"
        assert calls == 2, f"the documented cost is one extra upstream call, got {calls}"

    @pytest.mark.asyncio
    async def test_inactive_token_negative_cached(self, monkeypatch):
        """active:false is held in the negative cache, so a second call within
        the TTL does not re-hit the licenses endpoint."""
        monkeypatch.setattr(auth_mw, "LICENSE_INTROSPECT_URL", "http://lic/introspect")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"active": False}

        with patch("auth.middleware.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            first = await _introspect_license("tok")
            second = await _introspect_license("tok")

        assert first == {"active": False}
        assert second == first
        assert mock_client.post.call_count == 1

    @pytest.mark.asyncio
    async def test_valid_active_license(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "active": True,
            "subject_id": "tenant-1",
        }

        with patch("auth.middleware.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _introspect_license("valid-token")
            assert result is not None
            assert result["active"] is True

    @pytest.mark.asyncio
    async def test_inactive_license(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"active": False}

        with patch("auth.middleware.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _introspect_license("inactive-token")
            assert result is not None
            assert result["active"] is False

    @pytest.mark.asyncio
    async def test_introspection_failure(self):
        with patch("auth.middleware.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.side_effect = Exception("fail")
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _introspect_license("some-token")
            assert result is None

    @pytest.mark.asyncio
    async def test_non_200_returns_none(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("auth.middleware.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result = await _introspect_license("bad-token")
            assert result is None

    @pytest.mark.asyncio
    async def test_cached_result(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"active": True, "subject_id": "cached"}

        with patch("auth.middleware.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=False)

            result1 = await _introspect_license("cache-tok")
            assert result1 is not None
            assert result1["subject_id"] == "cached"

        # Second call uses cache
        result2 = await _introspect_license("cache-tok")
        assert result2 is not None
        assert result2["subject_id"] == "cached"


class TestAuthMiddleware:
    """Test AuthMiddleware dispatch logic."""

    def _make_request(self, path="/api/files/test", headers=None, client_host="127.0.0.1"):
        request = MagicMock()
        request.url.path = path
        request.headers = headers or {}
        if client_host:
            request.client.host = client_host
        else:
            request.client = None
        request.state = MagicMock(spec=[])
        return request

    def _make_middleware(self, bypass=False):
        return AuthMiddleware(MagicMock(), bypass_auth=bypass)

    @pytest.mark.asyncio
    async def test_public_endpoint_skipped(self):
        mw = self._make_middleware()
        request = self._make_request(path="/health")
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_non_protected_path_skipped(self):
        mw = self._make_middleware()
        request = self._make_request(path="/some/other")
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        call_next.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_bypass_auth_sets_tenant(self):
        mw = self._make_middleware(bypass=True)
        request = self._make_request(headers={"X-Tenant-Id": "my-tenant"})
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        assert request.state.tenant_id == "my-tenant"

    @pytest.mark.asyncio
    async def test_bypass_auth_default(self):
        """Bypass falls back to the configured platform tenant, never a minted literal."""
        mw = self._make_middleware(bypass=True)
        request = self._make_request(headers={})
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        assert request.state.tenant_id == auth_mw.DEFAULT_TENANT_ID
        uuid.UUID(request.state.tenant_id)

    @pytest.mark.asyncio
    async def test_trusted_network_no_token(self):
        """A trusted, tokenless caller is the platform tenant — not one it names.

        This test used to assert ``tenant_id == "trusted"``, i.e. it pinned the
        defect: whatever string an unauthenticated in-mesh pod put in
        ``X-Tenant-Id`` became its identity. Every in-cluster caller sits inside
        the default ``TRUSTED_CIDRS`` (which covers the whole 10.0.0.0/8 pod and
        service CIDR), so that made ``request.state.tenant_id`` attacker-chosen
        and unusable as an authorization input.
        """
        mw = self._make_middleware()
        request = self._make_request(
            headers={"X-Tenant-Id": "trusted"},
            client_host="192.168.1.50",
        )
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        assert request.state.tenant_id == auth_mw.DEFAULT_TENANT_ID
        uuid.UUID(request.state.tenant_id)
        assert request.state.user["tenant_id"] == auth_mw.DEFAULT_TENANT_ID

    @pytest.mark.asyncio
    async def test_trusted_network_cannot_assert_another_uuid_tenant(self):
        """A well-formed UUID in the header is refused just the same.

        Rejecting only non-UUID strings would leave the hole wide open: an
        attacker who can read one tenant uuid could then claim it.
        """
        other_tenant = "0195f48b-d000-7000-8000-0000000000ff"
        assert other_tenant != auth_mw.DEFAULT_TENANT_ID
        mw = self._make_middleware()
        request = self._make_request(
            headers={"X-Tenant-Id": other_tenant},
            client_host="10.42.7.9",
        )
        call_next = AsyncMock(return_value=MagicMock())

        await mw.dispatch(request, call_next)
        assert request.state.tenant_id == auth_mw.DEFAULT_TENANT_ID

    @pytest.mark.asyncio
    async def test_license_token_still_selects_its_own_subject(self):
        """Control: the tenant DOES move when it is backed by a valid licence.

        Without this, pinning every trusted-network request to the platform
        tenant would also pass if the middleware had simply stopped setting a
        tenant from tokens at all.
        """
        mw = self._make_middleware()
        request = self._make_request(
            headers={"X-Tenant-Id": "Bearer real-token"},
            client_host="10.42.7.9",
        )
        call_next = AsyncMock(return_value=MagicMock())

        with patch.object(
            auth_mw,
            "_introspect_license",
            AsyncMock(return_value={"active": True, "subject_id": "subject-uuid-42"}),
        ):
            await mw.dispatch(request, call_next)

        assert request.state.tenant_id == "subject-uuid-42"

    @pytest.mark.asyncio
    async def test_untrusted_no_token_rejected(self):
        mw = self._make_middleware()
        request = self._make_request(headers={}, client_host="8.8.8.8")
        call_next = AsyncMock()

        response = await mw.dispatch(request, call_next)
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_bearer_token(self):
        mw = self._make_middleware()
        request = self._make_request(
            headers={"X-Tenant-Id": "Bearer valid-token"},
            client_host="8.8.8.8",
        )
        call_next = AsyncMock(return_value=MagicMock())

        with patch("auth.middleware._introspect_license", new_callable=AsyncMock) as mock_intro:
            mock_intro.return_value = {"active": True, "subject_id": "lic-tenant"}
            await mw.dispatch(request, call_next)

        assert request.state.tenant_id == "lic-tenant"

    @pytest.mark.asyncio
    async def test_invalid_token_rejected(self):
        mw = self._make_middleware()
        request = self._make_request(
            headers={"X-Tenant-Id": "Bearer bad"},
            client_host="8.8.8.8",
        )
        call_next = AsyncMock()

        with patch("auth.middleware._introspect_license", new_callable=AsyncMock) as mock_intro:
            mock_intro.return_value = {"active": False}
            response = await mw.dispatch(request, call_next)

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_token_missing_tenant_rejected(self):
        mw = self._make_middleware()
        request = self._make_request(
            headers={"X-Tenant-Id": "Bearer some"},
            client_host="8.8.8.8",
        )
        call_next = AsyncMock()

        with patch("auth.middleware._introspect_license", new_callable=AsyncMock) as mock_intro:
            mock_intro.return_value = {"active": True}
            response = await mw.dispatch(request, call_next)

        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_dispatch_exception_returns_500(self):
        mw = self._make_middleware()
        request = self._make_request(client_host="8.8.8.8")

        with patch.object(mw, "_is_public_endpoint", side_effect=Exception("boom")):
            response = await mw.dispatch(request, AsyncMock())
        assert response.status_code == 500


class TestMiddlewareHelpers:
    """Test middleware helper methods."""

    def _make_middleware(self):
        return AuthMiddleware(MagicMock())

    def test_is_public_endpoint(self):
        mw = self._make_middleware()
        assert mw._is_public_endpoint("/health") is True
        assert mw._is_public_endpoint("/docs") is True
        assert mw._is_public_endpoint("/") is True
        assert mw._is_public_endpoint("/ready") is True

    def test_is_public_endpoint_prefix(self):
        mw = self._make_middleware()
        assert mw._is_public_endpoint("/health/live") is True
        assert mw._is_public_endpoint("/static/file.js") is True

    def test_is_public_endpoint_anchors_to_segment_boundary(self):
        """An unanchored prefix match is an auth-bypass class: any route merely
        STARTING with a public prefix would be exempted from auth. Anchor to a
        path SEGMENT. Same shape as the ingress carve-out that let
        `/storage/api/buckets/ready` reach MinIO unauthenticated (gitops #2204).
        """
        mw = self._make_middleware()
        # Real public trees stay public.
        assert mw._is_public_endpoint("/health/ready") is True
        assert mw._is_public_endpoint("/docs/oauth2-redirect") is True
        assert mw._is_public_endpoint("/static/logo.svg") is True
        # Look-alikes that merely share a prefix must NOT be exempted.
        for bypass in (
            "/healthcheck-admin",
            "/health-secrets/dump",
            "/staticfiles/../etc/passwd",
            "/docsecret",
            "/redocs-internal",
        ):
            assert mw._is_public_endpoint(bypass) is False, bypass

    def test_is_public_endpoint_keeps_probe_paths_public(self):
        """The k8s probes (/health/live, /health/ready) and /healthz must stay
        public — segment anchoring must never auth-wall a liveness probe."""
        mw = self._make_middleware()
        for probe in ("/health", "/health/live", "/health/ready", "/healthz", "/ready", "/readyz"):
            assert mw._is_public_endpoint(probe) is True, probe

    def test_is_public_endpoint_does_not_widen(self):
        """A bypass fix must not quietly widen the exemption it exists to
        narrow: /livez never matched the old rule and no probe uses it."""
        mw = self._make_middleware()
        assert mw._is_public_endpoint("/livez") is False

    def test_is_protected(self):
        mw = self._make_middleware()
        assert mw._is_protected("/api/files/test") is True
        assert mw._is_protected("/api/buckets") is True
        assert mw._is_protected("/health") is False

    def test_extract_license_token_bearer(self):
        mw = self._make_middleware()
        request = MagicMock()
        request.headers = {"X-Tenant-Id": "Bearer my-token"}
        assert mw._extract_license_token(request) == "my-token"

    def test_extract_license_token_no_bearer(self):
        mw = self._make_middleware()
        request = MagicMock()
        request.headers = {"X-Tenant-Id": "plain-value"}
        assert mw._extract_license_token(request) is None

    def test_extract_license_token_empty(self):
        mw = self._make_middleware()
        request = MagicMock()
        request.headers = {}
        assert mw._extract_license_token(request) is None

    def test_unauthorized_response(self):
        mw = self._make_middleware()
        resp = mw._unauthorized_response("test")
        assert resp.status_code == 401

    def test_internal_error_response(self):
        mw = self._make_middleware()
        resp = mw._internal_error_response("error")
        assert resp.status_code == 500
