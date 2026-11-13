"""
Pytest fixtures for storage_service tests.

Uses a FakeMinioClient that stores objects in memory so that upload/download/
delete operations go through the real FastAPI routes with real data flowing
end-to-end.
"""

import hashlib
import os
from datetime import datetime, timedelta, timezone
from typing import BinaryIO
from unittest.mock import MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Set test environment variables before importing app.
#
# ENVIRONMENT=test exempts the storage_service production URL validator
# (Settings.model_post_init) from firing on empty defaults — required
# now that minio_endpoint and license_introspect_url carry no hardcoded
# in-cluster fallbacks.
os.environ.setdefault("ENVIRONMENT", "test")
os.environ["MINIO_ACCESS_KEY"] = "test_access_key"
os.environ["MINIO_SECRET_KEY"] = "test_secret_key"
os.environ["MINIO_ENDPOINT"] = "localhost:9000"
os.environ["ENABLE_VIRUS_SCANNING"] = "false"
os.environ["ENABLE_AUTH"] = "false"
# License introspection URL placeholder — auth.middleware tests mock
# httpx.AsyncClient so this URL is never actually POSTed to. Required
# because the no-fallback guard in _introspect_license rejects tokens
# when LICENSE_INTROSPECT_URL is empty.
os.environ.setdefault(
    "LICENSE_INTROSPECT_URL",
    "http://license-introspect.invalid:0/license/introspect",
)


# ---------------------------------------------------------------------------
# FakeMinioClient -- in-memory object store that mirrors MinioClient's API
# ---------------------------------------------------------------------------


class FakeMinioClient:
    """In-memory storage backend matching the MinioClient interface.

    Stores objects as dicts keyed by (bucket, object_key).
    Buckets are tracked as a set with creation dates.
    """

    def __init__(self):
        from config import get_settings

        settings = get_settings()
        self.allowed_buckets: list[str] = settings.allowed_bucket_list

        # {bucket_name: datetime}
        self._buckets: dict[str, datetime] = {}
        # {(bucket, key): {"data": bytes, "content_type": str, "metadata": dict}}
        self._objects: dict[tuple[str, str], dict] = {}
        # {bucket: [{"config_id": str, "prefix": str, "arn": str, "events": list}]}
        self._notifications: dict[str, list[dict]] = {}

        # Auto-create allowed buckets
        for b in self.allowed_buckets:
            if b not in self._buckets:
                self._buckets[b] = datetime.now(timezone.utc)

    def _validate_bucket(self, bucket: str) -> None:
        if bucket in self.allowed_buckets:
            return
        if bucket in self._buckets:
            return
        raise ValueError(f"Bucket '{bucket}' not found")

    def upload_file(
        self,
        bucket: str,
        object_key: str,
        data: BinaryIO,
        size: int,
        content_type: str = "application/octet-stream",
        metadata: dict[str, str] | None = None,
    ) -> dict:
        self._validate_bucket(bucket)
        raw = data.read()
        etag = hashlib.md5(raw).hexdigest()  # noqa: S324
        self._objects[(bucket, object_key)] = {
            "data": raw,
            "content_type": content_type,
            "metadata": metadata or {},
            "size": len(raw),
            "last_modified": datetime.now(timezone.utc),
            "etag": etag,
        }
        return {
            "bucket": bucket,
            "object_key": object_key,
            "etag": etag,
            "size": len(raw),
            "content_type": content_type,
        }

    def download_file(self, bucket: str, object_key: str) -> tuple[bytes, dict]:
        self._validate_bucket(bucket)
        key = (bucket, object_key)
        if key not in self._objects:
            raise KeyError(f"Object {object_key} not found in {bucket}")
        obj = self._objects[key]
        return obj["data"], {"content_type": obj["content_type"]}

    def stream_file(self, bucket: str, object_key: str, chunk_size: int = 1024 * 1024):
        self._validate_bucket(bucket)
        key = (bucket, object_key)
        if key not in self._objects:
            raise KeyError(f"Object {object_key} not found in {bucket}")
        obj = self._objects[key]
        data = obj["data"]

        def _iter():
            for i in range(0, len(data), chunk_size):
                yield data[i : i + chunk_size]

        return _iter(), {
            "content_type": obj["content_type"],
            "content_length": str(len(data)),
        }

    def file_exists(self, bucket: str, object_key: str) -> bool:
        self._validate_bucket(bucket)
        return (bucket, object_key) in self._objects

    def delete_file(self, bucket: str, object_key: str) -> bool:
        self._validate_bucket(bucket)
        key = (bucket, object_key)
        if key in self._objects:
            del self._objects[key]
        return True

    def get_file_metadata(self, bucket: str, object_key: str) -> dict | None:
        self._validate_bucket(bucket)
        key = (bucket, object_key)
        if key not in self._objects:
            return None
        obj = self._objects[key]
        return {
            "bucket": bucket,
            "object_key": object_key,
            "size": obj["size"],
            "last_modified": obj["last_modified"],
            "etag": obj["etag"],
            "content_type": obj["content_type"],
            "metadata": obj["metadata"],
        }

    def list_files(
        self,
        bucket: str,
        prefix: str = "",
        recursive: bool = True,
        max_keys: int = 1000,
    ) -> list[dict]:
        self._validate_bucket(bucket)
        files: list[dict] = []
        for (b, k), obj in self._objects.items():
            if b != bucket:
                continue
            if prefix and not k.startswith(prefix):
                continue
            files.append(
                {
                    "object_key": k,
                    "size": obj["size"],
                    "last_modified": obj["last_modified"],
                    "etag": obj["etag"],
                }
            )
            if len(files) >= max_keys:
                break
        return files

    def list_buckets(self) -> list[dict]:
        return [{"name": name, "creation_date": dt} for name, dt in self._buckets.items()]

    def create_bucket(self, name: str) -> dict:
        if name in self._buckets:
            return {"name": name, "created": False, "message": "Bucket already exists"}
        self._buckets[name] = datetime.now(timezone.utc)
        return {"name": name, "created": True, "message": "Bucket created"}

    def delete_bucket(self, name: str, force: bool = False) -> dict:
        if name not in self._buckets:
            raise ValueError(f"Bucket '{name}' does not exist")

        bucket_objects = [(b, k) for (b, k) in self._objects if b == name]
        if bucket_objects and not force:
            raise ValueError(f"Bucket '{name}' is not empty (use force=true)")

        if force:
            for key in bucket_objects:
                del self._objects[key]

        del self._buckets[name]
        return {"name": name, "deleted": True, "message": "Bucket deleted"}

    def bucket_exists(self, name: str) -> bool:
        return name in self._buckets

    def ensure_bucket(self, name: str) -> dict:
        return self.create_bucket(name)

    @staticmethod
    def _notification_config_id(prefix: str) -> str:
        digest = hashlib.sha1(prefix.encode("utf-8"), usedforsecurity=False).hexdigest()[:16]
        return f"cp-{digest}"

    def set_bucket_notification(
        self, bucket: str, prefix: str, arn: str, events: list[str]
    ) -> dict:
        self._validate_bucket(bucket)
        config_id = self._notification_config_id(prefix)
        rules = [r for r in self._notifications.get(bucket, []) if r["config_id"] != config_id]
        rules.append({"config_id": config_id, "prefix": prefix, "arn": arn, "events": events})
        self._notifications[bucket] = rules
        return {"bucket": bucket, "prefix": prefix, "config_id": config_id, "rules": len(rules)}

    def get_bucket_notifications(self, bucket: str) -> list[dict]:
        if not self.bucket_exists(bucket):
            return []
        return [
            {
                "config_id": r["config_id"],
                "prefix": r["prefix"],
                "events": list(r["events"]),
                "arn": r["arn"],
            }
            for r in self._notifications.get(bucket, [])
        ]

    def remove_bucket_notification(self, bucket: str, prefix: str) -> dict:
        self._validate_bucket(bucket)
        config_id = self._notification_config_id(prefix)
        existing = self._notifications.get(bucket, [])
        rules = [r for r in existing if r["config_id"] != config_id]
        removed = len(existing) - len(rules)
        self._notifications[bucket] = rules
        return {
            "bucket": bucket,
            "prefix": prefix,
            "config_id": config_id,
            "removed": removed,
            "rules": len(rules),
        }

    def health_check(self) -> tuple[bool, str, float]:
        return True, "MinIO is healthy", 1.0


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_minio():
    """Create a fresh FakeMinioClient for each test."""
    from config import get_settings

    get_settings.cache_clear()
    return FakeMinioClient()


@pytest.fixture
def mock_virus_scanner():
    """Mock virus scanner returning a REAL ``ScanResult``.

    The verdict object is deliberately not a ``MagicMock``: every attribute of
    a MagicMock is truthy, so a route asking ``result.completed`` and a route
    asking ``result.typo`` would both read "scan finished" and every
    fail-closed test would pass under a broken implementation. The real
    dataclass makes ``completed``/``is_clean`` derive from ``error``, exactly
    as production does.
    """
    from services.virus_scanner import ScanResult

    mock = MagicMock()
    mock.ping.return_value = True
    mock.health_check.return_value = (True, "ClamAV is healthy", 10.0)
    mock.scan_bytes.return_value = ScanResult(
        is_infected=False,
        virus_name=None,
        scan_time_ms=1.0,
        file_size=0,
    )
    return mock


@pytest.fixture
def mock_minio_client():
    """Legacy mock MinIO client -- used by tests that need to simulate errors.

    For normal operations prefer fake_minio which does real in-memory storage.
    """
    mock = MagicMock()
    mock.upload_file.return_value = {"etag": "test-etag-123"}
    mock.download_file.return_value = (
        b"test file content",
        {"content_type": "text/plain"},
    )
    mock.file_exists.return_value = True
    mock.delete_file.return_value = True
    mock.get_file_metadata.return_value = {
        "bucket": "kag-ingestion",
        "object_key": "test.txt",
        "size": 1024,
        "last_modified": "2024-01-01T00:00:00Z",
        "etag": "test-etag",
        "content_type": "text/plain",
        "metadata": {},
    }
    mock.list_files.return_value = [
        {
            "object_key": "file1.txt",
            "size": 100,
            "last_modified": "2024-01-01T00:00:00Z",
            "etag": "etag1",
        },
        {
            "object_key": "file2.txt",
            "size": 200,
            "last_modified": "2024-01-02T00:00:00Z",
            "etag": "etag2",
        },
    ]
    mock.health_check.return_value = (True, "MinIO is healthy", 5.0)
    mock.list_buckets.return_value = [
        {"name": "kag-ingestion", "creation_date": "2024-01-01T00:00:00Z"},
        {"name": "artifacts", "creation_date": "2024-01-02T00:00:00Z"},
    ]
    mock.create_bucket.return_value = {
        "name": "new-bucket",
        "created": True,
        "message": "Bucket created",
    }
    mock.delete_bucket.return_value = {
        "name": "old-bucket",
        "deleted": True,
        "message": "Bucket deleted",
    }
    mock.bucket_exists.return_value = True
    return mock


@pytest.fixture
def app_client(fake_minio, mock_virus_scanner):
    """Create test client backed by FakeMinioClient for real storage ops.

    ⚠️ ``main`` is imported BEFORE the patches are entered, and the order is
    load-bearing. Each route module binds the factory with
    ``from services.minio_client import get_minio_client``; importing them for
    the first time INSIDE this patch context (which ``from main import app``
    used to do) makes them bind the MagicMock that
    ``patch("services.minio_client.get_minio_client")`` has just installed.
    ``patch("routes.files.get_minio_client", …)`` then records that mock as the
    original and restores it on exit — so ``routes.files.get_minio_client`` and
    ``routes.health.get_minio_client`` stayed stubbed with a stale fake for the
    REST OF THE SESSION, silently, after the first test to use this fixture.
    Measured: it defeated the cold-singleton regression test in
    ``test_event_loop_not_blocked.py``, whose whole point is to exercise the real
    factory — it recorded 0 constructions and would have gone green against a
    reintroduced blocker.
    """
    from fastapi.testclient import TestClient

    from config import get_settings
    from main import app  # noqa: F401  — import BEFORE patching; see above

    get_settings.cache_clear()

    with (
        patch("services.minio_client._minio_client", fake_minio),
        patch("services.minio_client.get_minio_client", return_value=fake_minio),
        patch("services.virus_scanner._virus_scanner", mock_virus_scanner),
        patch("services.virus_scanner.get_virus_scanner", return_value=mock_virus_scanner),
        patch("routes.files.get_minio_client", return_value=fake_minio),
        patch("routes.files.get_virus_scanner", return_value=mock_virus_scanner),
        patch("routes.buckets.get_minio_client", return_value=fake_minio),
        patch("routes.notifications.get_minio_client", return_value=fake_minio),
        patch("routes.health.get_minio_client", return_value=fake_minio),
        patch("routes.health.get_virus_scanner", return_value=mock_virus_scanner),
    ):
        from main import app

        client = TestClient(app)
        yield client


@pytest.fixture
def settings():
    """Get test settings."""
    from config import get_settings

    get_settings.cache_clear()
    return get_settings()


# ============================================================================
# CRYPTOGRAPHY FIXTURES
# ============================================================================


@pytest.fixture(scope="session")
def rsa_key_pair_session():
    """
    Generate RSA key pair for entire test session.

    Using session scope for performance - generating keys is expensive.
    Creates a 2048-bit RSA key pair used for JWT signing and verification.

    Returns:
        dict: {"private": str, "public": str} - PEM-encoded keys
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    public_pem = (
        private_key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("utf-8")
    )

    return {"private": private_pem, "public": public_pem}


@pytest.fixture
def rsa_key_pair(rsa_key_pair_session):
    """
    Function-scoped RSA key pair fixture.

    References the session-scoped key pair. Use this in tests that
    don't require key isolation between tests.

    Returns:
        dict: {"private": str, "public": str} - PEM-encoded keys
    """
    return rsa_key_pair_session


# ============================================================================
# JWT TOKEN GENERATION HELPERS
# ============================================================================


def create_jwt_token(
    user_id: str,
    private_key: str,
    expires_delta: timedelta = timedelta(hours=1),
    additional_claims: dict | None = None,
) -> str:
    """
    Helper function to create JWT tokens for testing.

    Args:
        user_id: Subject claim (creator_id)
        private_key: RSA private key for signing
        expires_delta: Time until expiration (default: 1 hour)
        additional_claims: Optional additional claims to include

    Returns:
        str: Encoded JWT token
    """
    payload = {
        "sub": user_id,
        "exp": int((datetime.now(timezone.utc) + expires_delta).timestamp()),
        "iat": int(datetime.now(timezone.utc).timestamp()),
        "email": f"{user_id}@example.com",
        "preferred_username": user_id,
    }

    if additional_claims:
        payload.update(additional_claims)

    return jwt.encode(payload, private_key, algorithm="RS256")


# ============================================================================
# TEST USER FIXTURES
# ============================================================================


@pytest.fixture
def user_a_token(rsa_key_pair):
    """Generate valid JWT token for test user A."""
    return create_jwt_token("user_a_id", rsa_key_pair["private"])


@pytest.fixture
def user_b_token(rsa_key_pair):
    """Generate valid JWT token for test user B."""
    return create_jwt_token("user_b_id", rsa_key_pair["private"])


@pytest.fixture
def admin_token(rsa_key_pair):
    """Generate valid JWT token for admin user with additional claims."""
    return create_jwt_token(
        "admin_user_id",
        rsa_key_pair["private"],
        additional_claims={
            "roles": ["admin", "user"],
            "permissions": ["read", "write", "delete"],
        },
    )


@pytest.fixture
def expired_token(rsa_key_pair):
    """Generate expired JWT token for testing expiration handling."""
    return create_jwt_token(
        "expired_user",
        rsa_key_pair["private"],
        expires_delta=timedelta(hours=-1),  # Expired 1 hour ago
    )


# ============================================================================
# ENVIRONMENT SETUP FIXTURES
# ============================================================================


@pytest.fixture
def setup_jwt_env(rsa_key_pair):
    """
    Setup JWT environment with test configuration.

    Configures environment variables needed for JWT authentication
    using the test RSA key pair.

    Yields:
        dict: RSA key pair for use in tests
    """
    os.environ["JWT_PUBLIC_KEY"] = rsa_key_pair["public"]
    os.environ["JWT_ALGORITHM"] = "RS256"

    yield rsa_key_pair

    # Cleanup
    os.environ.pop("JWT_PUBLIC_KEY", None)
    os.environ.pop("JWT_ALGORITHM", None)


# ============================================================================
# AUTH HEADERS FIXTURES
# ============================================================================


@pytest.fixture
def auth_headers_user_a(user_a_token):
    """Generate authorization headers for user A."""
    return {"Authorization": f"Bearer {user_a_token}"}


@pytest.fixture
def auth_headers_admin(admin_token):
    """Generate authorization headers for admin user."""
    return {"Authorization": f"Bearer {admin_token}"}
