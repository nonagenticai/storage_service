"""
Tests for file operation endpoints.

Uses FakeMinioClient (in-memory) so uploads/downloads actually store and
retrieve real bytes.  Every test asserts on response body content, not
just status codes.
"""

import os
from unittest.mock import patch

from services.virus_scanner import ScanResult

# The standard EICAR anti-malware test string, split so this file is not
# itself quarantined by an on-access scanner.
_EICAR_HEAD = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-"
_EICAR_TAIL = b"ANTIVIRUS-TEST-FILE!$H+H*"
EICAR = _EICAR_HEAD + _EICAR_TAIL


class TestFileUpload:
    """Test file upload endpoint."""

    def test_upload_success(self, app_client, fake_minio):
        """Test successful file upload -- verify response fields and storage."""
        response = app_client.post(
            "/api/files/upload",
            data={
                "bucket": "kag-ingestion",
                "object_key": "test/file.txt",
            },
            files={"file": ("file.txt", b"test content", "text/plain")},
        )
        assert response.status_code == 200

        data = response.json()
        assert data["bucket"] == "kag-ingestion"
        assert data["object_key"] == "test/file.txt"
        assert data["size"] == len(b"test content")
        assert data["content_type"] == "text/plain"
        assert len(data["etag"]) > 0

        # Verify the file is actually in the fake store
        assert fake_minio.file_exists("kag-ingestion", "test/file.txt")
        stored, meta = fake_minio.download_file("kag-ingestion", "test/file.txt")
        assert stored == b"test content"
        assert meta["content_type"] == "text/plain"

    def test_upload_invalid_bucket(self, app_client, fake_minio):
        """Test upload to non-existent bucket returns 400 with detail."""
        response = app_client.post(
            "/api/files/upload",
            data={
                "bucket": "invalid-bucket",
                "object_key": "file.txt",
            },
            files={"file": ("file.txt", b"content", "text/plain")},
        )
        assert response.status_code == 400
        body = response.json()
        assert "not found" in body["error"]["message"]
        assert "invalid-bucket" in body["error"]["message"]

    def test_upload_with_content_type(self, app_client, fake_minio):
        """Test upload with explicit content type overrides file content type."""
        response = app_client.post(
            "/api/files/upload",
            data={
                "bucket": "kag-ingestion",
                "object_key": "doc.pdf",
                "content_type": "application/pdf",
            },
            files={"file": ("doc.pdf", b"pdf content", "application/octet-stream")},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["content_type"] == "application/pdf"
        assert body["size"] == len(b"pdf content")

        # Verify stored content type
        meta = fake_minio.get_file_metadata("kag-ingestion", "doc.pdf")
        assert meta is not None
        assert meta["content_type"] == "application/pdf"

    def test_upload_minio_error(self, app_client, mock_minio_client):
        """Test upload when MinIO fails returns 500 with error detail."""
        mock_minio_client.upload_file.side_effect = Exception("MinIO error")

        with patch("routes.files.get_minio_client", return_value=mock_minio_client):
            response = app_client.post(
                "/api/files/upload",
                data={
                    "bucket": "kag-ingestion",
                    "object_key": "file.txt",
                },
                files={"file": ("file.txt", b"content", "text/plain")},
            )
        assert response.status_code == 500
        body = response.json()
        assert "Upload failed" in body["error"]["message"]
        assert "MinIO error" in body["error"]["message"]


class TestFileDownload:
    """Test file download endpoint."""

    def test_download_success(self, app_client, fake_minio):
        """Upload then download -- verify content matches byte-for-byte."""
        content = b"download me please"
        # Upload first
        app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "path/to/file.txt"},
            files={"file": ("file.txt", content, "text/plain")},
        )

        # Download
        response = app_client.get("/api/files/kag-ingestion/path/to/file.txt")
        assert response.status_code == 200
        assert response.content == content
        assert "attachment" in response.headers.get("content-disposition", "")
        assert 'filename="file.txt"' in response.headers.get("content-disposition", "")
        assert response.headers.get("content-length") == str(len(content))

    def test_download_not_found(self, app_client, fake_minio):
        """Test download of non-existent file returns 404 with detail."""
        response = app_client.get("/api/files/kag-ingestion/missing.txt")
        assert response.status_code == 404
        body = response.json()
        assert "not found" in body["error"]["message"].lower()

    def test_download_invalid_bucket(self, app_client, fake_minio):
        """Test download from non-existent bucket returns 400."""
        response = app_client.get("/api/files/bad-bucket/file.txt")
        assert response.status_code == 400
        body = response.json()
        assert "not found" in body["error"]["message"]
        assert "bad-bucket" in body["error"]["message"]


class TestFileDelete:
    """Test file delete endpoint."""

    def test_delete_success(self, app_client, fake_minio):
        """Upload, delete, then verify file is gone."""
        # Upload
        app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "deleteme.txt"},
            files={"file": ("deleteme.txt", b"bye", "text/plain")},
        )
        assert fake_minio.file_exists("kag-ingestion", "deleteme.txt")

        # Delete
        response = app_client.delete("/api/files/kag-ingestion/deleteme.txt")
        assert response.status_code == 204

        # Verify gone
        assert not fake_minio.file_exists("kag-ingestion", "deleteme.txt")

    def test_delete_not_found(self, app_client, fake_minio):
        """Test delete of non-existent file returns 404."""
        response = app_client.delete("/api/files/kag-ingestion/missing.txt")
        assert response.status_code == 404
        body = response.json()
        assert "not found" in body["error"]["message"].lower()

    def test_delete_invalid_bucket(self, app_client, fake_minio):
        """Test delete from non-existent bucket returns 400."""
        response = app_client.delete("/api/files/bad-bucket/file.txt")
        assert response.status_code == 400
        body = response.json()
        assert "not found" in body["error"]["message"]


class TestFileExists:
    """Test file exists endpoint."""

    def test_file_exists(self, app_client, fake_minio):
        """Upload a file, then check it exists via the API."""
        app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "exists-test.txt"},
            files={"file": ("exists-test.txt", b"hi", "text/plain")},
        )

        response = app_client.get("/api/files/kag-ingestion/exists-test.txt/exists")
        assert response.status_code == 200

        data = response.json()
        assert data["exists"] is True
        assert data["bucket"] == "kag-ingestion"
        assert data["object_key"] == "exists-test.txt"

    def test_file_not_exists(self, app_client, fake_minio):
        """Test checking non-existent file returns exists=false."""
        response = app_client.get("/api/files/kag-ingestion/missing.txt/exists")
        assert response.status_code == 200

        data = response.json()
        assert data["exists"] is False
        assert data["bucket"] == "kag-ingestion"
        assert data["object_key"] == "missing.txt"


class TestFileMetadata:
    """Test file metadata endpoint."""

    def test_get_metadata(self, app_client, fake_minio):
        """Upload a file, then verify its metadata via the API."""
        content = b"metadata test content"
        app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "meta.txt"},
            files={"file": ("meta.txt", content, "text/plain")},
        )

        response = app_client.get("/api/files/kag-ingestion/meta.txt/metadata")
        assert response.status_code == 200

        data = response.json()
        assert data["bucket"] == "kag-ingestion"
        assert data["object_key"] == "meta.txt"
        assert data["size"] == len(content)
        assert data["content_type"] == "text/plain"
        assert "last_modified" in data
        assert len(data["etag"]) > 0

    def test_metadata_not_found(self, app_client, fake_minio):
        """Test metadata for non-existent file returns 404."""
        response = app_client.get("/api/files/kag-ingestion/missing.txt/metadata")
        assert response.status_code == 404
        body = response.json()
        assert "not found" in body["error"]["message"].lower()


class TestFileList:
    """Test file listing endpoint."""

    def test_list_files(self, app_client, fake_minio):
        """Upload two files, then list and verify both appear."""
        app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "list/a.txt"},
            files={"file": ("a.txt", b"aaa", "text/plain")},
        )
        app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "list/b.txt"},
            files={"file": ("b.txt", b"bbb", "text/plain")},
        )

        response = app_client.get("/api/files/kag-ingestion")
        assert response.status_code == 200

        data = response.json()
        assert data["bucket"] == "kag-ingestion"
        assert data["count"] >= 2
        keys = [f["object_key"] for f in data["files"]]
        assert "list/a.txt" in keys
        assert "list/b.txt" in keys

    def test_list_with_prefix(self, app_client, fake_minio):
        """Upload files under different prefixes, filter by prefix."""
        app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "docs/readme.md"},
            files={"file": ("readme.md", b"# Docs", "text/markdown")},
        )
        app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "images/logo.png"},
            files={"file": ("logo.png", b"\x89PNG", "image/png")},
        )

        response = app_client.get("/api/files/kag-ingestion?prefix=docs/")
        assert response.status_code == 200

        data = response.json()
        assert data["prefix"] == "docs/"
        keys = [f["object_key"] for f in data["files"]]
        assert "docs/readme.md" in keys
        assert "images/logo.png" not in keys

    def test_list_invalid_bucket(self, app_client, fake_minio):
        """Test listing from non-existent bucket returns 400."""
        response = app_client.get("/api/files/bad-bucket")
        assert response.status_code == 400
        body = response.json()
        assert "not found" in body["error"]["message"]


class TestObjectKeyValidationAtTheRoutes:
    """The unvalidated ``object_key`` reached MinIO from every route.

    ``tests/test_object_keys.py`` covers the validator and the structural
    guarantee that no handler skips it; these assert the wiring is actually
    live over HTTP and returns the error envelope.
    """

    def test_upload_rejects_a_traversal_key(self, app_client, fake_minio):
        response = app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "../../escape.txt"},
            files={"file": ("escape.txt", b"x", "text/plain")},
        )
        assert response.status_code == 400
        assert "path segments" in response.json()["error"]["message"]
        # And nothing was written under any spelling of that key.
        assert fake_minio.list_files(bucket="kag-ingestion") == []

    def test_upload_rejects_an_absolute_key(self, app_client, fake_minio):
        response = app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "/etc/passwd"},
            files={"file": ("passwd", b"x", "text/plain")},
        )
        assert response.status_code == 400
        assert fake_minio.list_files(bucket="kag-ingestion") == []

    def test_upload_rejects_a_newline_in_the_key(self, app_client, fake_minio):
        """The download route puts the last segment in a response header."""
        response = app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "ok.txt\r\nX-Injected: 1"},
            files={"file": ("ok.txt", b"x", "text/plain")},
        )
        assert response.status_code == 400
        assert "control" in response.json()["error"]["message"]

    def test_upload_rejects_an_over_long_key(self, app_client, fake_minio):
        """Previously stored fine, then 500'd rendering its own 200 response."""
        response = app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "k" * 1025},
            files={"file": ("k", b"x", "text/plain")},
        )
        assert response.status_code == 400
        assert "bytes" in response.json()["error"]["message"]

    def test_list_rejects_a_traversal_prefix(self, app_client, fake_minio):
        response = app_client.get("/api/files/kag-ingestion", params={"prefix": "../"})
        assert response.status_code == 400
        assert "path segments" in response.json()["error"]["message"]

    def test_a_normal_key_still_uploads(self, app_client, fake_minio):
        """Control: the validator must not refuse ordinary traffic."""
        response = app_client.post(
            "/api/files/upload",
            data={"bucket": "kag-ingestion", "object_key": "projects/a/b/v1/report.pdf"},
            files={"file": ("report.pdf", b"pdf", "application/pdf")},
        )
        assert response.status_code == 200
        assert fake_minio.file_exists("kag-ingestion", "projects/a/b/v1/report.pdf")


class TestValidateBucketDynamic:
    """Test validate_bucket when bucket is not in allowed list but exists in MinIO."""

    def test_upload_to_dynamic_bucket(self, app_client, fake_minio):
        """Upload to a dynamically-created bucket not in the allowed list."""
        # Create a bucket via API so it exists in the fake store
        fake_minio.create_bucket("dynamic-bucket")

        response = app_client.post(
            "/api/files/upload",
            data={"bucket": "dynamic-bucket", "object_key": "file.txt"},
            files={"file": ("file.txt", b"content", "text/plain")},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["bucket"] == "dynamic-bucket"
        assert fake_minio.file_exists("dynamic-bucket", "file.txt")


class TestFileUploadVirusScanning:
    """Test file upload with virus scanning enabled."""

    def _make_client_with_scanning(self, fake_minio, mock_virus_scanner):
        """Create a test client with virus scanning enabled."""
        from fastapi.testclient import TestClient

        from config import get_settings

        get_settings.cache_clear()
        old_val = os.environ.get("ENABLE_VIRUS_SCANNING")
        os.environ["ENABLE_VIRUS_SCANNING"] = "true"

        try:
            get_settings.cache_clear()
            with (
                patch("services.minio_client._minio_client", fake_minio),
                patch("services.minio_client.get_minio_client", return_value=fake_minio),
                patch("services.virus_scanner._virus_scanner", mock_virus_scanner),
                patch("services.virus_scanner.get_virus_scanner", return_value=mock_virus_scanner),
                patch("routes.files.get_minio_client", return_value=fake_minio),
                patch("routes.files.get_virus_scanner", return_value=mock_virus_scanner),
                patch("routes.buckets.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_virus_scanner", return_value=mock_virus_scanner),
            ):
                from main import app

                client = TestClient(app)
                yield client
        finally:
            get_settings.cache_clear()
            if old_val is None:
                os.environ.pop("ENABLE_VIRUS_SCANNING", None)
            else:
                os.environ["ENABLE_VIRUS_SCANNING"] = old_val

    def test_upload_virus_scan_clean(self, fake_minio, mock_virus_scanner):
        """Test upload with clean virus scan stores file and reports 'clean'."""
        for client in self._make_client_with_scanning(fake_minio, mock_virus_scanner):
            response = client.post(
                "/api/files/upload",
                data={"bucket": "kag-ingestion", "object_key": "clean.txt"},
                files={"file": ("clean.txt", b"safe content", "text/plain")},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["virus_scanned"] is True
            assert data["scan_result"] == "clean"
            assert data["size"] == len(b"safe content")
            # Verify actually stored
            assert fake_minio.file_exists("kag-ingestion", "clean.txt")

    def test_upload_virus_detected(self, fake_minio, mock_virus_scanner):
        """Test upload rejected when virus detected -- file NOT stored."""
        mock_virus_scanner.scan_bytes.return_value = ScanResult(
            is_infected=True,
            virus_name="EICAR-Test",
            scan_time_ms=1.0,
            file_size=13,
        )

        for client in self._make_client_with_scanning(fake_minio, mock_virus_scanner):
            response = client.post(
                "/api/files/upload",
                data={"bucket": "kag-ingestion", "object_key": "evil.exe"},
                files={"file": ("evil.exe", b"virus content", "application/octet-stream")},
            )
            assert response.status_code == 400
            body = response.json()
            assert "Virus detected" in body["error"]["message"]
            assert "EICAR-Test" in body["error"]["message"]
            # Verify NOT stored
            assert not fake_minio.file_exists("kag-ingestion", "evil.exe")

    def test_upload_refused_when_scanner_raises(self, fake_minio, mock_virus_scanner):
        """A scanner that blows up refuses the upload — it does not wave it through.

        This test used to be ``test_upload_virus_scan_error_allows_upload`` and
        asserted 200 + "file still stored despite scan failure": it pinned the
        fail-OPEN behaviour as the spec. With ClamAV down, an EICAR sample was
        stored and answered 200.
        """
        mock_virus_scanner.scan_bytes.side_effect = RuntimeError("Scanner crashed")

        for client in self._make_client_with_scanning(fake_minio, mock_virus_scanner):
            response = client.post(
                "/api/files/upload",
                data={"bucket": "kag-ingestion", "object_key": "file.txt"},
                files={"file": ("file.txt", b"data", "text/plain")},
            )
            assert response.status_code == 503
            assert "unavail" in response.json()["error"]["message"].lower()
            # Nothing may reach storage.
            assert not fake_minio.file_exists("kag-ingestion", "file.txt")

    def test_upload_refused_when_scan_did_not_complete(self, fake_minio, mock_virus_scanner):
        """An errored verdict is 'not scanned', not 'clean enough to store'.

        ``is_infected=False`` is what EVERY failure path returns — a scanner
        that never ran cannot report an infection — so it is not evidence. Only
        ``ScanResult.error is None`` distinguishes the two, which is what
        ``ScanResult.completed`` exposes.
        """
        mock_virus_scanner.scan_bytes.return_value = ScanResult(
            is_infected=False,
            virus_name=None,
            scan_time_ms=1.0,
            file_size=4,
            error="Error 61 connecting to clamav:3310. Connection refused.",
        )

        for client in self._make_client_with_scanning(fake_minio, mock_virus_scanner):
            response = client.post(
                "/api/files/upload",
                data={"bucket": "kag-ingestion", "object_key": "file.txt"},
                files={"file": ("file.txt", b"data", "text/plain")},
            )
            assert response.status_code == 503
            assert not fake_minio.file_exists("kag-ingestion", "file.txt")

    def test_response_never_claims_a_scan_that_did_not_happen(self, fake_minio, mock_virus_scanner):
        """The misreporting half: the body said ``virus_scanned: true`` next to
        ``scan_result: "Error 61 ... Connection refused."``. No 2xx body may
        ever carry ``virus_scanned: true`` without a real verdict.
        """
        mock_virus_scanner.scan_bytes.return_value = ScanResult(
            is_infected=False,
            virus_name=None,
            scan_time_ms=1.0,
            file_size=len(EICAR),
            error="Error 61 connecting to clamav:3310. Connection refused.",
        )

        for client in self._make_client_with_scanning(fake_minio, mock_virus_scanner):
            response = client.post(
                "/api/files/upload",
                data={"bucket": "kag-ingestion", "object_key": "eicar.com"},
                files={"file": ("eicar.com", EICAR, "application/octet-stream")},
            )
            assert response.status_code >= 400
            body = response.json()
            assert body.get("virus_scanned") is not True
            assert "Connection refused" not in str(body.get("scan_result"))

    def test_clean_scan_still_stores_and_reports(self, fake_minio, mock_virus_scanner):
        """Control for the three refusals above.

        A blanket "refuse every upload" would satisfy them all; this is the
        case that must still succeed, and must still say it was scanned.
        """
        for client in self._make_client_with_scanning(fake_minio, mock_virus_scanner):
            response = client.post(
                "/api/files/upload",
                data={"bucket": "kag-ingestion", "object_key": "ok.txt"},
                files={"file": ("ok.txt", b"safe", "text/plain")},
            )
            assert response.status_code == 200
            data = response.json()
            assert data["virus_scanned"] is True
            assert data["scan_result"] == "clean"
            assert fake_minio.file_exists("kag-ingestion", "ok.txt")


class TestFileUploadSizeLimit:
    """Test file upload size limits."""

    def test_upload_file_too_large(self, app_client, fake_minio):
        """Test upload rejected when file exceeds max size."""
        old_val = os.environ.get("MAX_UPLOAD_SIZE_MB")
        os.environ["MAX_UPLOAD_SIZE_MB"] = "0"

        from config import get_settings

        get_settings.cache_clear()

        try:
            with patch("routes.files.get_settings") as mock_settings:
                settings = get_settings()
                mock_settings.return_value = settings

                response = app_client.post(
                    "/api/files/upload",
                    data={"bucket": "kag-ingestion", "object_key": "big.bin"},
                    files={"file": ("big.bin", b"x" * 100, "application/octet-stream")},
                )
                assert response.status_code == 413
                body = response.json()
                assert "too large" in body["error"]["message"].lower()
                assert "Max size" in body["error"]["message"]
        finally:
            get_settings.cache_clear()
            if old_val is None:
                os.environ.pop("MAX_UPLOAD_SIZE_MB", None)
            else:
                os.environ["MAX_UPLOAD_SIZE_MB"] = old_val


class TestFileExistsError:
    """Test file exists endpoint error handling."""

    def test_exists_check_error(self, app_client, mock_minio_client):
        """Test exists check when MinIO raises an error."""
        mock_minio_client.file_exists.side_effect = Exception("Connection error")
        with patch("routes.files.get_minio_client", return_value=mock_minio_client):
            response = app_client.get("/api/files/kag-ingestion/file.txt/exists")
        assert response.status_code == 500
        body = response.json()
        assert "Check failed" in body["error"]["message"]
        assert "Connection error" in body["error"]["message"]


class TestFileMetadataError:
    """Test file metadata endpoint error handling."""

    def test_metadata_minio_error(self, app_client, mock_minio_client):
        """Test metadata fetch when MinIO raises an error."""
        mock_minio_client.get_file_metadata.side_effect = Exception("Connection error")
        with patch("routes.files.get_minio_client", return_value=mock_minio_client):
            response = app_client.get("/api/files/kag-ingestion/file.txt/metadata")
        assert response.status_code == 500
        body = response.json()
        assert "Metadata fetch failed" in body["error"]["message"]


class TestFileDownloadError:
    """Test file download error handling."""

    def test_download_minio_error(self, app_client, mock_minio_client):
        """Test download when MinIO raises an error after exists check."""
        mock_minio_client.file_exists.return_value = True
        mock_minio_client.stream_file.side_effect = Exception("Connection error")
        with patch("routes.files.get_minio_client", return_value=mock_minio_client):
            response = app_client.get("/api/files/kag-ingestion/file.txt")
        assert response.status_code == 500
        body = response.json()
        assert "Download failed" in body["error"]["message"]


class TestFileDeleteError:
    """Test file delete error handling."""

    def test_delete_minio_error(self, app_client, mock_minio_client):
        """Test delete when MinIO raises an error after exists check."""
        mock_minio_client.file_exists.return_value = True
        mock_minio_client.delete_file.side_effect = Exception("Connection error")
        with patch("routes.files.get_minio_client", return_value=mock_minio_client):
            response = app_client.delete("/api/files/kag-ingestion/file.txt")
        assert response.status_code == 500
        body = response.json()
        assert "Delete failed" in body["error"]["message"]


class TestFileListError:
    """Test file list error handling."""

    def test_list_minio_error(self, app_client, mock_minio_client):
        """Test list when MinIO raises an error."""
        mock_minio_client.list_files.side_effect = Exception("Connection error")
        with patch("routes.files.get_minio_client", return_value=mock_minio_client):
            response = app_client.get("/api/files/kag-ingestion")
        assert response.status_code == 500
        body = response.json()
        assert "List failed" in body["error"]["message"]


class TestRootEndpoint:
    """Test root endpoint."""

    def test_root(self, app_client):
        """Test root endpoint returns service info."""
        response = app_client.get("/")
        assert response.status_code == 200

        data = response.json()
        assert data["service"] == "storage-service"
        assert data["version"] == "1.0.0"
        assert data["docs"] == "/docs"


class TestFullLifecycle:
    """End-to-end lifecycle: upload -> exists -> metadata -> download -> delete -> verify gone."""

    def test_full_file_lifecycle(self, app_client, fake_minio):
        """Complete lifecycle test with content verification at every step."""
        content = b"lifecycle test data with special chars: \xc3\xa9\xc3\xa0"
        bucket = "artifacts"
        key = "lifecycle/test-file.bin"

        # 1. Upload
        upload_resp = app_client.post(
            "/api/files/upload",
            data={"bucket": bucket, "object_key": key},
            files={"file": ("test-file.bin", content, "application/octet-stream")},
        )
        assert upload_resp.status_code == 200
        upload_data = upload_resp.json()
        assert upload_data["bucket"] == bucket
        assert upload_data["object_key"] == key
        assert upload_data["size"] == len(content)
        etag = upload_data["etag"]
        assert len(etag) > 0

        # 2. Exists
        exists_resp = app_client.get(f"/api/files/{bucket}/{key}/exists")
        assert exists_resp.status_code == 200
        assert exists_resp.json()["exists"] is True

        # 3. Metadata
        meta_resp = app_client.get(f"/api/files/{bucket}/{key}/metadata")
        assert meta_resp.status_code == 200
        meta_data = meta_resp.json()
        assert meta_data["size"] == len(content)
        assert meta_data["etag"] == etag
        assert meta_data["content_type"] == "application/octet-stream"

        # 4. Download and verify exact content
        dl_resp = app_client.get(f"/api/files/{bucket}/{key}")
        assert dl_resp.status_code == 200
        assert dl_resp.content == content

        # 5. Delete
        del_resp = app_client.delete(f"/api/files/{bucket}/{key}")
        assert del_resp.status_code == 204

        # 6. Verify gone
        exists_resp2 = app_client.get(f"/api/files/{bucket}/{key}/exists")
        assert exists_resp2.status_code == 200
        assert exists_resp2.json()["exists"] is False

        # 7. Download after delete -> 404
        dl_resp2 = app_client.get(f"/api/files/{bucket}/{key}")
        assert dl_resp2.status_code == 404


class TestLifespan:
    """Test main.py lifespan handler covers startup/shutdown branches."""

    def test_lifespan_minio_ok_scanning_disabled(self, fake_minio, mock_virus_scanner):
        """Lifespan with successful MinIO init and virus scanning disabled."""
        from config import get_settings

        old_scanning = os.environ.get("ENABLE_VIRUS_SCANNING")
        os.environ["ENABLE_VIRUS_SCANNING"] = "false"
        get_settings.cache_clear()

        try:
            with (
                patch("services.minio_client._minio_client", fake_minio),
                patch("services.minio_client.get_minio_client", return_value=fake_minio),
                patch("services.virus_scanner._virus_scanner", mock_virus_scanner),
                patch("services.virus_scanner.get_virus_scanner", return_value=mock_virus_scanner),
                patch("routes.files.get_minio_client", return_value=fake_minio),
                patch("routes.files.get_virus_scanner", return_value=mock_virus_scanner),
                patch("routes.buckets.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_virus_scanner", return_value=mock_virus_scanner),
            ):
                import asyncio

                from main import app, lifespan

                async def _run():
                    async with lifespan(app):
                        pass  # startup and shutdown run

                asyncio.run(_run())
        finally:
            get_settings.cache_clear()
            if old_scanning is None:
                os.environ.pop("ENABLE_VIRUS_SCANNING", None)
            else:
                os.environ["ENABLE_VIRUS_SCANNING"] = old_scanning

    def test_lifespan_minio_failure(self, fake_minio, mock_virus_scanner):
        """Lifespan handles MinIO initialization failure gracefully."""
        from config import get_settings

        old_scanning = os.environ.get("ENABLE_VIRUS_SCANNING")
        os.environ["ENABLE_VIRUS_SCANNING"] = "false"
        get_settings.cache_clear()

        try:
            with (
                patch(
                    "services.minio_client.get_minio_client",
                    side_effect=Exception("MinIO down"),
                ),
                patch("services.virus_scanner._virus_scanner", mock_virus_scanner),
                patch("services.virus_scanner.get_virus_scanner", return_value=mock_virus_scanner),
                patch("routes.files.get_minio_client", return_value=fake_minio),
                patch("routes.files.get_virus_scanner", return_value=mock_virus_scanner),
                patch("routes.buckets.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_virus_scanner", return_value=mock_virus_scanner),
            ):
                import asyncio

                from main import app, lifespan

                async def _run():
                    async with lifespan(app):
                        pass

                asyncio.run(_run())
        finally:
            get_settings.cache_clear()
            if old_scanning is None:
                os.environ.pop("ENABLE_VIRUS_SCANNING", None)
            else:
                os.environ["ENABLE_VIRUS_SCANNING"] = old_scanning

    def test_lifespan_scanning_enabled_scanner_responds(self, fake_minio, mock_virus_scanner):
        """Lifespan with scanning enabled and scanner responding."""
        from config import get_settings

        old_scanning = os.environ.get("ENABLE_VIRUS_SCANNING")
        os.environ["ENABLE_VIRUS_SCANNING"] = "true"
        get_settings.cache_clear()

        mock_virus_scanner.ping.return_value = True

        try:
            with (
                patch("services.minio_client._minio_client", fake_minio),
                patch("services.minio_client.get_minio_client", return_value=fake_minio),
                patch("services.virus_scanner._virus_scanner", mock_virus_scanner),
                patch("services.virus_scanner.get_virus_scanner", return_value=mock_virus_scanner),
                patch("routes.files.get_minio_client", return_value=fake_minio),
                patch("routes.files.get_virus_scanner", return_value=mock_virus_scanner),
                patch("routes.buckets.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_virus_scanner", return_value=mock_virus_scanner),
            ):
                import asyncio

                from main import app, lifespan

                async def _run():
                    async with lifespan(app):
                        pass

                asyncio.run(_run())
        finally:
            get_settings.cache_clear()
            if old_scanning is None:
                os.environ.pop("ENABLE_VIRUS_SCANNING", None)
            else:
                os.environ["ENABLE_VIRUS_SCANNING"] = old_scanning

    def test_lifespan_scanning_enabled_scanner_not_responding(self, fake_minio, mock_virus_scanner):
        """Lifespan with scanning enabled but scanner not responding."""
        from config import get_settings

        old_scanning = os.environ.get("ENABLE_VIRUS_SCANNING")
        os.environ["ENABLE_VIRUS_SCANNING"] = "true"
        get_settings.cache_clear()

        mock_virus_scanner.ping.return_value = False

        try:
            with (
                patch("services.minio_client._minio_client", fake_minio),
                patch("services.minio_client.get_minio_client", return_value=fake_minio),
                patch("services.virus_scanner._virus_scanner", mock_virus_scanner),
                patch("services.virus_scanner.get_virus_scanner", return_value=mock_virus_scanner),
                patch("routes.files.get_minio_client", return_value=fake_minio),
                patch("routes.files.get_virus_scanner", return_value=mock_virus_scanner),
                patch("routes.buckets.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_virus_scanner", return_value=mock_virus_scanner),
            ):
                import asyncio

                from main import app, lifespan

                async def _run():
                    async with lifespan(app):
                        pass

                asyncio.run(_run())
        finally:
            get_settings.cache_clear()
            if old_scanning is None:
                os.environ.pop("ENABLE_VIRUS_SCANNING", None)
            else:
                os.environ["ENABLE_VIRUS_SCANNING"] = old_scanning

    def test_lifespan_scanner_init_exception(self, fake_minio, mock_virus_scanner):
        """Lifespan handles scanner initialization failure gracefully."""
        from config import get_settings

        old_scanning = os.environ.get("ENABLE_VIRUS_SCANNING")
        os.environ["ENABLE_VIRUS_SCANNING"] = "true"
        get_settings.cache_clear()

        try:
            with (
                patch("services.minio_client._minio_client", fake_minio),
                patch("services.minio_client.get_minio_client", return_value=fake_minio),
                patch(
                    "services.virus_scanner.get_virus_scanner",
                    side_effect=Exception("ClamAV unavailable"),
                ),
                patch("routes.files.get_minio_client", return_value=fake_minio),
                patch("routes.files.get_virus_scanner", return_value=mock_virus_scanner),
                patch("routes.buckets.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_minio_client", return_value=fake_minio),
                patch("routes.health.get_virus_scanner", return_value=mock_virus_scanner),
            ):
                import asyncio

                from main import app, lifespan

                async def _run():
                    async with lifespan(app):
                        pass

                asyncio.run(_run())
        finally:
            get_settings.cache_clear()
            if old_scanning is None:
                os.environ.pop("ENABLE_VIRUS_SCANNING", None)
            else:
                os.environ["ENABLE_VIRUS_SCANNING"] = old_scanning
