"""
Storage Service configuration using Pydantic Settings.

Service URLs must come from the deployment environment, not from
code-side fallbacks. Required URL/host fields
default to "" and are enforced in production by ``model_post_init``;
missing values crash boot loudly instead of silently routing traffic
to a dead in-cluster service name.
"""

import fnmatch
import uuid
from functools import lru_cache
from typing import ClassVar

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Service metadata
    service_name: str = "storage-service"
    version: str = "1.0.0"
    environment: str = "production"
    log_level: str = "INFO"
    port: int = 8391

    # Authentication
    enable_auth: bool = True  # ENABLE_AUTH env var
    default_tenant_id: str = "0195f48b-d000-7000-8000-000000000001"  # DEFAULT_TENANT_ID env var
    license_introspect_url: str = ""  # LICENSE_INTROSPECT_URL env var

    # CORS — localhost defaults are intentional dev-mode allowances and are
    # explicitly out of scope for the no-hardcoded-URLs policy (which targets
    # in-cluster and internal service URLs).
    cors_allow_origins: str = "http://localhost:8921,http://localhost:3000,http://127.0.0.1:3000"

    # MinIO Configuration. ``minio_endpoint`` defaults to "" and is validated
    # in production by ``model_post_init`` below.
    minio_endpoint: str = ""
    minio_access_key: str = ""  # loaded from MINIO_ACCESS_KEY env var
    minio_secret_key: str = ""  # loaded from MINIO_SECRET_KEY env var
    minio_secure: bool = False

    # Allowed buckets (comma-separated in env) — auto-created at startup
    allowed_buckets: str = "kag-ingestion,kag-processed,kag-quarantine,artifacts"

    # Protected buckets (comma-separated in env) — cannot be deleted via API.
    # ⚠️ This env var REPLACES its default when set, so it is not, by itself, a
    # safe floor. See ``_PROTECTED_BUCKET_PATTERNS`` below.
    protected_buckets: str = "kag-ingestion,kag-processed,kag-quarantine,artifacts"

    # Additional protected-bucket glob patterns (comma-separated in env). These
    # EXTEND the built-in floor below; they never replace it.
    protected_bucket_patterns: str = ""  # PROTECTED_BUCKET_PATTERNS env var

    # Self-serve dataset connectors: buckets matching ``dataset_bucket_prefix`` may be
    # created on demand and have MinIO bucket-notification rules registered via
    # ``/api/buckets/{bucket}/notifications/register`` (commonpractice → storage_service).
    # ``shared_notification_arn`` is the ONE pre-provisioned ``notify_webhook`` target the
    # rules point at (MinIO webhook targets are static — a new target needs a server
    # restart, so we share one and vary only the per-bucket rules). See the self-serve
    # MinIO bucket-notifications plan.
    dataset_bucket_prefix: str = "cp-"  # DATASET_BUCKET_PREFIX env var
    shared_notification_arn: str = (
        "arn:minio:sqs::cpdatasets:webhook"  # SHARED_NOTIFICATION_ARN env var
    )
    notification_events: str = "s3:ObjectCreated:*,s3:ObjectRemoved:*"  # NOTIFICATION_EVENTS

    # ClamAV Configuration
    clamav_host: str = "clamav"
    clamav_port: int = 3310
    clamav_timeout: float = 30.0
    enable_virus_scanning: bool = True

    # Upload limits
    max_upload_size_mb: int = 500

    @field_validator("default_tenant_id")
    @classmethod
    def _tenant_id_must_be_uuid(cls, v: str) -> str:
        """Reject a tenant id that is not a UUID.

        A boundary that accepts an arbitrary string is a licence to MINT a
        tenant: whatever DEFAULT_TENANT_ID happens to hold becomes a real
        owner of rows. Parsing here turns a bad env var into a startup
        crash instead of a per-request surprise. Kept dependency-free on
        purpose (inline ``uuid.UUID``) so constructing Settings cannot
        re-enter Settings construction via the auth package.
        """
        try:
            uuid.UUID(v)
        except (ValueError, AttributeError, TypeError) as exc:
            raise ValueError(
                f"DEFAULT_TENANT_ID must be a UUID, got {v!r}. "
                "The platform tenant is 0195f48b-d000-7000-8000-000000000001."
            ) from exc
        return v

    @property
    def allowed_bucket_list(self) -> list[str]:
        """Parse allowed buckets from comma-separated string."""
        return [b.strip() for b in self.allowed_buckets.split(",") if b.strip()]

    # ⚠️ Non-overridable floor for delete protection. Read this before touching it.
    #
    # ``DELETE /api/buckets/{name}?force=true`` removes every object and then
    # the bucket (``minio_client.delete_bucket``), and ``auth/middleware.py``
    # admits an unauthenticated caller from a trusted CIDR as the platform
    # tenant — so that call is reachable tokenless from any pod in the cluster.
    # The only thing standing in front of it was an EXACT-STRING match over
    # ``protected_buckets``.
    #
    # Exact matching cannot keep up with the namespace it was extended to
    # serve. Measured on the live estate: 40 buckets in MinIO, 7 protected. The
    # self-serve dataset feature mints per-tenant buckets named ``cp-<id>-…``,
    # and the entry ``cp-datasets`` protects exactly one of them — the real
    # bucket ``cp-7748f050dab2-datasets`` was deletable. Unprotected also:
    # ``metering-backups`` (whose WAL is DELIBERATELY excluded from the only
    # offsite mirror, so destroying it destroys data with no complete copy),
    # every other ``*-backups`` bucket, and ``phi-audit-exports``.
    #
    # These patterns are matched IN ADDITION to ``protected_bucket_list`` and
    # cannot be switched off by env, so protection survives the deployed
    # ``PROTECTED_BUCKETS`` drifting or being unset — which is the failure mode
    # that made the exact list unsafe in the first place. Operators extend the
    # policy through ``PROTECTED_BUCKET_PATTERNS``; they cannot narrow this.
    # Adding protection only ever denies a destructive call, so the safe
    # direction of failure is "refuse", not "allow".
    _PROTECTED_BUCKET_PATTERNS: ClassVar[tuple[str, ...]] = (
        "kag-*",  # kag-ingestion / -processed / -quarantine and future siblings
        "cp-*",  # the self-serve dataset namespace, per-tenant and unenumerable
        "*-backups",  # metering-, neo4j-, redis-, twenty-, verdaccio-, pypiserver-…
        "backups",
        "artifacts",
        "ingestion",
        "book-common-practice",
        "phi-audit-exports",
    )

    @property
    def protected_bucket_list(self) -> list[str]:
        """Parse protected buckets from comma-separated string."""
        return [b.strip() for b in self.protected_buckets.split(",") if b.strip()]

    @property
    def protected_bucket_pattern_list(self) -> list[str]:
        """The built-in floor plus any operator-supplied extensions.

        Deliberately a UNION rather than an override: an env var that can
        REMOVE protection reintroduces exactly the drift this exists to survive.
        """
        extra = [p.strip() for p in self.protected_bucket_patterns.split(",") if p.strip()]
        return [*self._PROTECTED_BUCKET_PATTERNS, *extra]

    def is_protected_bucket(self, name: str) -> bool:
        """True if ``name`` may not be deleted through the API.

        ``fnmatchcase`` rather than ``fnmatch``: the latter normalises case
        using the *local* filesystem's rules, which would make the answer
        depend on the machine the pod happens to run on. S3 bucket names are
        lowercase by specification, so case-sensitive matching is also correct.
        """
        if name in self.protected_bucket_list:
            return True
        return any(fnmatch.fnmatchcase(name, pat) for pat in self.protected_bucket_pattern_list)

    @property
    def notification_event_list(self) -> list[str]:
        """Parse the S3 notification event types from a comma-separated string."""
        return [e.strip() for e in self.notification_events.split(",") if e.strip()]

    @property
    def max_upload_size_bytes(self) -> int:
        """Max upload size in bytes."""
        return self.max_upload_size_mb * 1024 * 1024

    _REQUIRED_IN_PRODUCTION: ClassVar[tuple[str, ...]] = (
        "minio_endpoint",
        "license_introspect_url",
    )

    def model_post_init(self, __context: object) -> None:
        if self.environment != "production":
            return
        missing = [n for n in self._REQUIRED_IN_PRODUCTION if not getattr(self, n)]
        if missing:
            raise RuntimeError(
                f"storage_service settings missing required fields in production: {missing}. "
                "Set them as environment variables on the deployment."
            )


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
