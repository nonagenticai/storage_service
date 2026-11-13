"""
Tests for Pydantic models/schemas.
"""

from datetime import datetime

import pydantic
import pytest


class TestFileUploadResponse:
    """Test FileUploadResponse model."""

    def test_create_response(self):
        """Test creating a file upload response."""
        from models.schemas import FileUploadResponse

        response = FileUploadResponse(
            bucket="test-bucket",
            object_key="path/to/file.txt",
            size=1024,
            etag="abc123",
            content_type="text/plain",
        )
        assert response.bucket == "test-bucket"
        assert response.object_key == "path/to/file.txt"
        assert response.size == 1024
        assert response.virus_scanned is False
        assert response.scan_result is None

    def test_with_virus_scan(self):
        """Test response with virus scan result."""
        from models.schemas import FileUploadResponse

        response = FileUploadResponse(
            bucket="test-bucket",
            object_key="file.txt",
            size=512,
            etag="def456",
            content_type="application/pdf",
            virus_scanned=True,
            scan_result="clean",
        )
        assert response.virus_scanned is True
        assert response.scan_result == "clean"


class TestFileExistsResponse:
    """Test FileExistsResponse model."""

    def test_file_exists(self):
        """Test file exists response."""
        from models.schemas import FileExistsResponse

        response = FileExistsResponse(
            bucket="bucket1",
            object_key="file.txt",
            exists=True,
        )
        assert response.exists is True

    def test_file_not_exists(self):
        """Test file not exists response."""
        from models.schemas import FileExistsResponse

        response = FileExistsResponse(
            bucket="bucket1",
            object_key="missing.txt",
            exists=False,
        )
        assert response.exists is False


class TestFileMetadataResponse:
    """Test FileMetadataResponse model."""

    def test_full_metadata(self):
        """Test response with all metadata fields."""
        from models.schemas import FileMetadataResponse

        response = FileMetadataResponse(
            bucket="test-bucket",
            object_key="path/file.txt",
            size=2048,
            last_modified=datetime(2024, 1, 15, 10, 30, 0),
            etag="xyz789",
            content_type="text/plain",
            metadata={"author": "test"},
        )
        assert response.size == 2048
        assert response.metadata == {"author": "test"}

    def test_default_metadata(self):
        """Test default empty metadata."""
        from models.schemas import FileMetadataResponse

        response = FileMetadataResponse(
            bucket="bucket",
            object_key="file.txt",
            size=100,
            last_modified=datetime.now(),
            etag="abc",
            content_type="text/plain",
        )
        assert response.metadata == {}


class TestFileInfo:
    """Test FileInfo model."""

    def test_file_info(self):
        """Test file info creation."""
        from models.schemas import FileInfo

        info = FileInfo(
            object_key="documents/report.pdf",
            size=4096,
            last_modified=datetime(2024, 6, 1),
            etag="file-etag",
        )
        assert info.object_key == "documents/report.pdf"
        assert info.size == 4096


class TestFileListResponse:
    """Test FileListResponse model."""

    def test_file_list(self):
        """Test file list response."""
        from models.schemas import FileInfo, FileListResponse

        files = [
            FileInfo(object_key="f1.txt", size=100, last_modified=datetime.now(), etag="e1"),
            FileInfo(object_key="f2.txt", size=200, last_modified=datetime.now(), etag="e2"),
        ]
        response = FileListResponse(
            bucket="test-bucket",
            prefix="docs/",
            files=files,
            count=2,
        )
        assert response.count == 2
        assert len(response.files) == 2

    def test_empty_list(self):
        """Test empty file list."""
        from models.schemas import FileListResponse

        response = FileListResponse(
            bucket="empty-bucket",
            prefix="",
            files=[],
            count=0,
        )
        assert response.count == 0
        assert response.files == []


class TestHealthModels:
    """Test health check models."""

    def test_component_status_healthy(self):
        """Test healthy component status."""
        from models.schemas import HealthComponentStatus

        status = HealthComponentStatus(
            healthy=True,
            message="Service is running",
            latency_ms=5.5,
        )
        assert status.healthy is True
        assert status.latency_ms == 5.5

    def test_component_status_unhealthy(self):
        """Test unhealthy component status."""
        from models.schemas import HealthComponentStatus

        status = HealthComponentStatus(
            healthy=False,
            message="Connection refused",
        )
        assert status.healthy is False
        assert status.latency_ms is None

    def test_health_response(self):
        """Test full health response."""
        from models.schemas import HealthComponentStatus, HealthResponse

        response = HealthResponse(
            status="healthy",
            service="storage-service",
            version="1.0.0",
            components={
                "minio": HealthComponentStatus(healthy=True, message="OK"),
                "clamav": HealthComponentStatus(healthy=True, message="OK"),
            },
        )
        assert response.status == "healthy"
        assert len(response.components) == 2


class TestBucketCreateRequest:
    """Test BucketCreateRequest validation."""

    def test_valid_name(self):
        """Test valid bucket names."""
        from models.schemas import BucketCreateRequest

        for name in ["my-bucket", "test123", "a-b-c-d", "abc"]:
            req = BucketCreateRequest(name=name)
            assert req.name == name

    def test_uppercase_rejected(self):
        """Test uppercase names are rejected."""
        from models.schemas import BucketCreateRequest

        with pytest.raises(pydantic.ValidationError):
            BucketCreateRequest(name="MyBucket")

    def test_special_chars_rejected(self):
        """Test special characters are rejected."""
        from models.schemas import BucketCreateRequest

        with pytest.raises(pydantic.ValidationError):
            BucketCreateRequest(name="my_bucket!")

    def test_too_short_rejected(self):
        """Test names shorter than 3 chars are rejected."""
        from models.schemas import BucketCreateRequest

        with pytest.raises(pydantic.ValidationError):
            BucketCreateRequest(name="ab")

    def test_consecutive_hyphens_rejected(self):
        """Test consecutive hyphens are rejected."""
        from models.schemas import BucketCreateRequest

        with pytest.raises(pydantic.ValidationError):
            BucketCreateRequest(name="my--bucket")

    def test_sthree_prefix_rejected(self):
        """Test sthree- prefix is rejected."""
        from models.schemas import BucketCreateRequest

        with pytest.raises(pydantic.ValidationError):
            BucketCreateRequest(name="sthree-bucket")

    def test_xn_prefix_rejected(self):
        """Test xn-- prefix is rejected."""
        from models.schemas import BucketCreateRequest

        with pytest.raises(pydantic.ValidationError):
            BucketCreateRequest(name="xn--bucket")


# Error-envelope tests live in tests/test_error_envelope.py — they exercise
# the canonical `ErrorDetail` + `ErrorResponse(error: ErrorDetail)` pair in
# `src.routes.responses`.
