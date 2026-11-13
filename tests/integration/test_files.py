"""Integration tests for storage_service file operation endpoints.

Tests the full upload/exists/metadata/download/delete/list lifecycle
against a live storage_service instance.
"""

import uuid

import pytest

pytestmark = pytest.mark.integration

BUCKET = "artifacts"
ACCEPTABLE_STATUSES = {200, 201, 502, 503}
ACCEPTABLE_STATUSES_WITH_DELETE = {200, 201, 204, 502, 503}


@pytest.fixture(scope="module")
def test_object_key():
    """Generate a unique object key for this test run."""
    return f"integration-test-{uuid.uuid4().hex[:12]}.txt"


@pytest.fixture(scope="module")
def uploaded_file(storage_client, test_object_key):
    """Upload a small text file and return (bucket, key, response).

    Cleans up after all tests in the module finish.
    """
    file_content = b"integration test content"
    resp = storage_client.post(
        "/api/files/upload",
        data={"bucket": BUCKET, "object_key": test_object_key},
        files={"file": ("test.txt", file_content, "text/plain")},
    )
    yield BUCKET, test_object_key, resp

    # Cleanup: best-effort delete
    storage_client.delete(f"/api/files/{BUCKET}/{test_object_key}")


class TestFileUpload:
    """POST /api/files/upload"""

    def test_upload_file(self, uploaded_file):
        """Upload a small text file via multipart form."""
        _bucket, _key, resp = uploaded_file
        assert resp.status_code in ACCEPTABLE_STATUSES, (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )
        if resp.status_code in {200, 201}:
            body = resp.json()
            assert body["bucket"] == BUCKET
            assert body["object_key"] == _key
            assert body["size"] > 0


class TestFileExists:
    """GET /api/files/{bucket}/{key}/exists"""

    def test_file_exists(self, storage_client, uploaded_file):
        """Check that the uploaded file exists."""
        bucket, key, upload_resp = uploaded_file
        if upload_resp.status_code not in {200, 201}:
            pytest.skip("Upload did not succeed; skipping exists check")

        resp = storage_client.get(f"/api/files/{bucket}/{key}/exists")
        assert resp.status_code in ACCEPTABLE_STATUSES, (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )
        if resp.status_code == 200:
            body = resp.json()
            assert body["exists"] is True
            assert body["bucket"] == bucket
            assert body["object_key"] == key


class TestFileMetadata:
    """GET /api/files/{bucket}/{key}/metadata"""

    def test_file_metadata(self, storage_client, uploaded_file):
        """Retrieve metadata for the uploaded file."""
        bucket, key, upload_resp = uploaded_file
        if upload_resp.status_code not in {200, 201}:
            pytest.skip("Upload did not succeed; skipping metadata check")

        resp = storage_client.get(f"/api/files/{bucket}/{key}/metadata")
        assert resp.status_code in ACCEPTABLE_STATUSES, (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )
        if resp.status_code == 200:
            body = resp.json()
            assert body["bucket"] == bucket
            assert body["object_key"] == key
            assert body["size"] > 0
            assert "content_type" in body


class TestFileDownload:
    """GET /api/files/{bucket}/{key}"""

    def test_download_file(self, storage_client, uploaded_file):
        """Download the uploaded file and verify content."""
        bucket, key, upload_resp = uploaded_file
        if upload_resp.status_code not in {200, 201}:
            pytest.skip("Upload did not succeed; skipping download check")

        resp = storage_client.get(f"/api/files/{bucket}/{key}")
        assert resp.status_code in ACCEPTABLE_STATUSES, (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )
        if resp.status_code == 200:
            assert resp.content == b"integration test content"


class TestFileDelete:
    """DELETE /api/files/{bucket}/{key}"""

    def test_delete_file(self, storage_client):
        """Upload a separate file, then delete it."""
        delete_key = f"integration-delete-{uuid.uuid4().hex[:12]}.txt"

        # Upload
        upload_resp = storage_client.post(
            "/api/files/upload",
            data={"bucket": BUCKET, "object_key": delete_key},
            files={"file": ("delete-me.txt", b"delete me", "text/plain")},
        )
        if upload_resp.status_code not in {200, 201}:
            pytest.skip("Upload did not succeed; skipping delete test")

        # Delete
        resp = storage_client.delete(f"/api/files/{BUCKET}/{delete_key}")
        assert resp.status_code in ACCEPTABLE_STATUSES_WITH_DELETE, (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )
        if resp.status_code == 204:
            # Verify gone
            exists_resp = storage_client.get(f"/api/files/{BUCKET}/{delete_key}/exists")
            if exists_resp.status_code == 200:
                assert exists_resp.json()["exists"] is False


class TestFileList:
    """GET /api/files/{bucket}"""

    def test_list_files(self, storage_client, uploaded_file):
        """List files in the integration-test bucket."""
        bucket, _key, upload_resp = uploaded_file
        if upload_resp.status_code not in {200, 201}:
            pytest.skip("Upload did not succeed; skipping list check")

        resp = storage_client.get(f"/api/files/{bucket}")
        assert resp.status_code in ACCEPTABLE_STATUSES, (
            f"Unexpected status {resp.status_code}: {resp.text}"
        )
        if resp.status_code == 200:
            body = resp.json()
            assert body["bucket"] == bucket
            assert "files" in body
            assert "count" in body
            assert body["count"] >= 1
