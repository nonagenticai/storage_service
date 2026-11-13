"""Delete protection must cover the namespace, not seven literal strings.

``DELETE /api/buckets/{name}?force=true`` removes every object and then the
bucket. The only thing in front of it was ``if name in
settings.protected_bucket_list`` — an exact match over a comma-separated env
var — and ``auth/middleware.py`` admits an unauthenticated caller from a
trusted CIDR as the platform tenant, so that call is reachable tokenless from
any pod in the cluster.

The measured numbers on the live estate: 40 buckets in MinIO on worker4, 7 in
the running pod's ``PROTECTED_BUCKETS``. The gap is not incidental. This service
MINTS the ``cp-<tenant>-…`` self-serve dataset buckets itself, so an exact list
can never enumerate them — the live bucket ``cp-7748f050dab2-datasets`` was
deletable while the entry ``cp-datasets`` covered a bucket of a different name.
``metering-backups`` was deletable too, and per the estate's own
documentation its WAL is DELIBERATELY excluded from the sole offsite mirror, so
destroying it destroys data that has no complete copy anywhere.

⚠️ These tests are written in BOTH directions on purpose. A guard that refuses
everything would satisfy every refusal assertion here while breaking bucket
deletion entirely, so the deletable cases below are not filler — they are what
makes the refusals mean something.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from config import Settings, get_settings

# Measured live on the storage-api pod, 2026-09-07. Every one of these is now
# expected to be refused; only the first seven were before.
PRODUCTION_PROTECTED_BUCKETS = [
    "kag-ingestion",
    "kag-processed",
    "kag-quarantine",
    "artifacts",
    "ingestion",
    "book-common-practice",
    "cp-datasets",
]

# Measured live in MinIO on worker4: real buckets that were NOT protected.
PREVIOUSLY_UNPROTECTED_BUT_MUST_BE = [
    "metering-backups",
    "backups",
    "neo4j-backups",
    "redis-backups",
    "twenty-backups",
    "verdaccio-backups",
    "pypiserver-backups",
    "phi-audit-exports",
    # The concrete proof that an exact-match list cannot keep up with a
    # namespace this service itself mints one bucket at a time.
    "cp-7748f050dab2-datasets",
]

# Real buckets that are deliberately still deletable. Without these the guard
# could be "refuse everything" and every test above would still pass.
MUST_STAY_DELETABLE = [
    "models",
    "training-data",
    "specra-media",
    "w2v-audio",
    "temp-bucket",
    "scratch",
]


class TestProtectionPredicate:
    """The predicate itself, independent of the route."""

    @pytest.mark.parametrize(
        "name", PRODUCTION_PROTECTED_BUCKETS + PREVIOUSLY_UNPROTECTED_BUT_MUST_BE
    )
    def test_protected(self, name: str) -> None:
        assert Settings().is_protected_bucket(name) is True

    @pytest.mark.parametrize("name", MUST_STAY_DELETABLE)
    def test_not_protected(self, name: str) -> None:
        """Non-vacuity. A predicate that returns True for everything is not a
        guard, it is an outage."""
        assert Settings().is_protected_bucket(name) is False

    def test_the_floor_survives_the_env_var_being_unset(self) -> None:
        """The failure mode the built-in patterns exist for.

        ``PROTECTED_BUCKETS`` REPLACES its default when set, so a drifted or
        empty deployment value used to leave the delete route with no guard at
        all. The pattern floor is not reachable from env and must hold anyway.
        """
        with patch.dict(os.environ, {"PROTECTED_BUCKETS": ""}, clear=False):
            settings = Settings()
            assert settings.protected_bucket_list == []
            for name in ["metering-backups", "kag-ingestion", "cp-7748f050dab2-datasets"]:
                assert settings.is_protected_bucket(name) is True, name
            assert settings.is_protected_bucket("models") is False

    def test_an_operator_can_extend_but_not_narrow_the_policy(self) -> None:
        """``PROTECTED_BUCKET_PATTERNS`` is a union, never an override."""
        with patch.dict(os.environ, {"PROTECTED_BUCKET_PATTERNS": "models,w2v-*"}, clear=False):
            settings = Settings()
            assert settings.is_protected_bucket("models") is True
            assert settings.is_protected_bucket("w2v-audio") is True
            # The floor is untouched by the extension.
            assert settings.is_protected_bucket("metering-backups") is True
            # And it is still not a blanket refusal.
            assert settings.is_protected_bucket("scratch") is False


class TestDeleteRouteRefusesProtectedBuckets:
    """End-to-end through the route, with the bucket really present."""

    @staticmethod
    def _create(app_client, name: str) -> None:
        resp = app_client.post("/api/buckets", json={"name": name})
        assert resp.status_code == 201, resp.text

    def test_a_protected_prefix_is_refused_and_the_bucket_survives(
        self, app_client, fake_minio
    ) -> None:
        """The concrete live regression case: a real self-serve dataset bucket.

        It is created first so that the mutant — reverting to the exact-match
        guard — does not merely 404; it actually deletes it, which is what
        makes this a data-loss test rather than a status-code test.
        """
        name = "cp-7748f050dab2-datasets"
        self._create(app_client, name)
        assert fake_minio.bucket_exists(name)

        response = app_client.delete(f"/api/buckets/{name}")

        assert response.status_code == 403, response.text
        assert "protected" in response.json()["error"]["message"]
        assert fake_minio.bucket_exists(name), "the bucket was deleted despite the 403 contract"

    def test_force_true_does_not_bypass_the_guard(self, app_client, fake_minio) -> None:
        """``?force=true`` is the destructive path: it removes every object
        first. The guard must run before it, not after."""
        name = "metering-backups"
        self._create(app_client, name)
        upload = app_client.post(
            "/api/files/upload",
            data={"bucket": name, "object_key": "wal/000000010000000000000042"},
            files={"file": ("seg", b"irreplaceable", "application/octet-stream")},
        )
        assert upload.status_code == 200, upload.text

        response = app_client.delete(f"/api/buckets/{name}?force=true")

        assert response.status_code == 403, response.text
        assert fake_minio.bucket_exists(name)
        assert fake_minio.file_exists(name, "wal/000000010000000000000042"), (
            "force=true destroyed the objects of a protected bucket"
        )

    def test_an_exact_listed_name_is_still_refused(self, app_client) -> None:
        """Regression control: the pre-existing exact-match behaviour is kept,
        not replaced."""
        response = app_client.delete("/api/buckets/kag-ingestion")
        assert response.status_code == 403
        assert "protected" in response.json()["error"]["message"]

    @pytest.mark.parametrize("name", ["models", "training-data", "scratch"])
    def test_an_unlisted_bucket_is_still_deletable(self, app_client, fake_minio, name) -> None:
        """Non-vacuity through the route. If this reddens, the fix broke the
        feature rather than protecting it."""
        self._create(app_client, name)
        response = app_client.delete(f"/api/buckets/{name}")
        assert response.status_code == 200, response.text
        assert response.json()["deleted"] is True
        assert not fake_minio.bucket_exists(name)


def test_settings_cache_is_not_left_dirty() -> None:
    """Housekeeping: the env-patching tests above construct Settings directly
    rather than through the lru_cache, so the shared cache must be untouched."""
    get_settings.cache_clear()
    assert get_settings().is_protected_bucket("metering-backups") is True
