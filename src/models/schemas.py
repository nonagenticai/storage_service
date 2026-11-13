"""
Pydantic schemas for request/response models.
"""

import re
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from custom_types import SAFE_STRING_PATTERN, SafeString, SafeStringShort

# =============================================================================
# File Operations
# =============================================================================


class FileUploadResponse(BaseModel):
    """Response after successful file upload."""

    bucket: SafeStringShort
    object_key: str = Field(min_length=1, max_length=1024, pattern=SAFE_STRING_PATTERN)
    size: int
    etag: SafeStringShort
    content_type: SafeStringShort
    virus_scanned: bool = False
    scan_result: SafeString | None = None  # "clean" or virus name


class FileExistsResponse(BaseModel):
    """Response for file existence check."""

    bucket: SafeStringShort
    object_key: str = Field(min_length=1, max_length=1024, pattern=SAFE_STRING_PATTERN)
    exists: bool


class FileMetadataResponse(BaseModel):
    """Response with file metadata."""

    bucket: SafeStringShort
    object_key: str = Field(min_length=1, max_length=1024, pattern=SAFE_STRING_PATTERN)
    size: int
    last_modified: datetime
    etag: SafeStringShort
    content_type: SafeStringShort
    metadata: dict[str, str] = Field(default_factory=dict)


class FileInfo(BaseModel):
    """Single file info for list response."""

    object_key: str = Field(min_length=1, max_length=1024, pattern=SAFE_STRING_PATTERN)
    size: int
    last_modified: datetime
    etag: SafeStringShort


class FileListResponse(BaseModel):
    """Response for file listing."""

    bucket: SafeStringShort
    prefix: SafeString = ""
    files: list[FileInfo]
    count: int


# Canonical fleet error envelope (`ErrorDetail` + `ErrorResponse(error: ErrorDetail)`)
# lives in ``src.routes.responses`` — don't redefine here. The old flat
# `{error, detail}` shape was non-canonical and unused.


# =============================================================================
# Bucket Operations
# =============================================================================

_S3_BUCKET_BASE = re.compile(r"^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$")


class BucketCreateRequest(BaseModel):
    """Request to create a new bucket."""

    name: str = Field(
        min_length=3,
        max_length=63,
        description="S3-compatible bucket name",
    )

    @field_validator("name")
    @classmethod
    def validate_bucket_name(cls, v: str) -> str:
        if not _S3_BUCKET_BASE.match(v):
            raise ValueError(
                "Bucket name must contain only lowercase letters, numbers, and hyphens"
            )
        if "--" in v:
            raise ValueError("Bucket name must not contain consecutive hyphens")
        if v.startswith("xn--"):
            raise ValueError("Bucket name must not start with 'xn--'")
        if v.startswith("sthree-"):
            raise ValueError("Bucket name must not start with 'sthree-'")
        return v


class BucketInfo(BaseModel):
    """Information about a single bucket."""

    name: SafeStringShort
    creation_date: datetime | None = None


class BucketListResponse(BaseModel):
    """Response for bucket listing."""

    buckets: list[BucketInfo]
    count: int


class BucketCreateResponse(BaseModel):
    """Response after creating a bucket."""

    name: SafeStringShort
    created: bool
    message: SafeString


class BucketDeleteResponse(BaseModel):
    """Response after deleting a bucket."""

    name: SafeStringShort
    deleted: bool
    message: SafeString


# =============================================================================
# Health Check
# =============================================================================


class HealthComponentStatus(BaseModel):
    """Status of a single component."""

    healthy: bool
    message: SafeString | None = None
    latency_ms: float | None = None


class HealthResponse(BaseModel):
    """Health check response."""

    status: SafeStringShort  # "healthy", "degraded", "unhealthy"
    service: SafeStringShort
    version: SafeStringShort
    components: dict[str, HealthComponentStatus] = Field(default_factory=dict)


# =============================================================================
# Bucket Notifications (self-serve dataset connectors)
# =============================================================================


class NotificationRuleRequest(BaseModel):
    """Register/deregister one bucket-notification rule for a dataset connector."""

    prefix: str = Field(
        default="",
        max_length=1024,
        description=(
            "Object-key prefix the rule filters on (the connector's object key). "
            "Empty string registers a whole-bucket rule."
        ),
    )


class NotificationRegisterResponse(BaseModel):
    """Response after registering a bucket-notification rule."""

    bucket: SafeStringShort
    prefix: str
    config_id: str  # machine token "cp-<hex>"; may be empty on a no-op
    rules: int


class NotificationDeregisterResponse(BaseModel):
    """Response after deregistering a bucket-notification rule."""

    bucket: SafeStringShort
    prefix: str
    config_id: str  # machine token "cp-<hex>"; empty when the bucket did not exist
    removed: int
    rules: int


class NotificationRuleOut(BaseModel):
    """One live bucket-notification rule (read-only ground truth)."""

    config_id: str  # machine token "cp-<hex>"
    prefix: str
    events: list[str]
    arn: str


class NotificationListResponse(BaseModel):
    """Response listing a bucket's live notification rules.

    ``rules`` is empty for a bucket that does not exist or carries no rules — the caller
    treats both as "no rule registered" and never as an error.
    """

    bucket: SafeStringShort
    rules: list[NotificationRuleOut]
