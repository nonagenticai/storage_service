"""
Tests for bucket management endpoints.

Uses FakeMinioClient for real bucket CRUD operations.  Every test asserts on
response body content, not just status codes.
"""

from unittest.mock import MagicMock, patch


class TestListBuckets:
    """Test GET /api/buckets."""

    def test_list_buckets(self, app_client, fake_minio):
        """Test listing all buckets -- default allowed buckets exist."""
        response = app_client.get("/api/buckets")
        assert response.status_code == 200
        data = response.json()
        # FakeMinioClient auto-creates allowed buckets
        assert data["count"] >= 4  # kag-ingestion, kag-processed, kag-quarantine, artifacts
        names = [b["name"] for b in data["buckets"]]
        assert "kag-ingestion" in names
        assert "artifacts" in names

    def test_list_buckets_after_create(self, app_client, fake_minio):
        """Create a bucket, then verify it appears in list."""
        app_client.post("/api/buckets", json={"name": "new-test-bucket"})
        response = app_client.get("/api/buckets")
        assert response.status_code == 200
        data = response.json()
        names = [b["name"] for b in data["buckets"]]
        assert "new-test-bucket" in names

    def test_list_buckets_minio_error(self, app_client):
        """Test listing when MinIO raises an error returns 500."""
        mock_minio = MagicMock()
        mock_minio.list_buckets.side_effect = Exception("Connection refused")
        with patch("routes.buckets.get_minio_client", return_value=mock_minio):
            response = app_client.get("/api/buckets")
        assert response.status_code == 500
        body = response.json()
        assert "List buckets failed" in body["error"]["message"]


class TestCreateBucket:
    """Test POST /api/buckets."""

    def test_create_bucket(self, app_client, fake_minio):
        """Test creating a new bucket -- verify it exists afterward."""
        response = app_client.post("/api/buckets", json={"name": "my-new-bucket"})
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "my-new-bucket"
        assert data["created"] is True
        assert data["message"] == "Bucket created"

        # Verify bucket actually exists
        assert fake_minio.bucket_exists("my-new-bucket")

    def test_create_bucket_already_exists(self, app_client, fake_minio):
        """Test creating a bucket that already exists returns 409."""
        # kag-ingestion is auto-created by FakeMinioClient
        response = app_client.post("/api/buckets", json={"name": "kag-ingestion"})
        assert response.status_code == 409
        body = response.json()
        assert "already exists" in body["error"]["message"]

    def test_create_bucket_invalid_name_uppercase(self, app_client):
        """Test that uppercase bucket names are rejected by validation."""
        response = app_client.post("/api/buckets", json={"name": "MyBucket"})
        assert response.status_code == 422

    def test_create_bucket_invalid_name_special_chars(self, app_client):
        """Test that special characters are rejected."""
        response = app_client.post("/api/buckets", json={"name": "my_bucket!"})
        assert response.status_code == 422

    def test_create_bucket_too_short(self, app_client):
        """Test that names shorter than 3 chars are rejected."""
        response = app_client.post("/api/buckets", json={"name": "ab"})
        assert response.status_code == 422

    def test_create_bucket_consecutive_hyphens(self, app_client):
        """Test that consecutive hyphens are rejected."""
        response = app_client.post("/api/buckets", json={"name": "my--bucket"})
        assert response.status_code == 422

    def test_create_bucket_xn_prefix(self, app_client):
        """Test that xn-- prefix is rejected."""
        response = app_client.post("/api/buckets", json={"name": "xn--bucket"})
        assert response.status_code == 422


class TestGetBucket:
    """Test GET /api/buckets/{name}."""

    def test_get_bucket_exists(self, app_client, fake_minio):
        """Test getting an existing bucket returns its info."""
        response = app_client.get("/api/buckets/kag-ingestion")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "kag-ingestion"
        assert "creation_date" in data

    def test_get_bucket_not_found(self, app_client, fake_minio):
        """Test getting a non-existent bucket returns 404 with detail."""
        response = app_client.get("/api/buckets/nonexistent")
        assert response.status_code == 404
        body = response.json()
        assert "not found" in body["error"]["message"]


class TestDeleteBucket:
    """Test DELETE /api/buckets/{name}."""

    def test_delete_bucket(self, app_client, fake_minio):
        """Create a bucket, delete it, verify it's gone."""
        # Create an unprotected bucket
        fake_minio.create_bucket("temp-bucket")
        assert fake_minio.bucket_exists("temp-bucket")

        response = app_client.delete("/api/buckets/temp-bucket")
        assert response.status_code == 200
        data = response.json()
        assert data["deleted"] is True
        assert data["name"] == "temp-bucket"
        assert data["message"] == "Bucket deleted"

        # Verify gone
        assert not fake_minio.bucket_exists("temp-bucket")

    def test_delete_protected_bucket(self, app_client):
        """Test that protected buckets return 403 with detail."""
        response = app_client.delete("/api/buckets/kag-ingestion")
        assert response.status_code == 403
        body = response.json()
        assert "protected" in body["error"]["message"]

    def test_delete_bucket_not_found(self, app_client, fake_minio):
        """Test deleting a non-existent bucket returns 404."""
        response = app_client.delete("/api/buckets/gone")
        assert response.status_code == 404
        body = response.json()
        assert "does not exist" in body["error"]["message"]

    def test_delete_bucket_not_empty(self, app_client, fake_minio):
        """Test deleting a non-empty bucket without force returns 409."""
        # Create bucket and add a file
        fake_minio.create_bucket("full-bucket")
        import io

        fake_minio.upload_file("full-bucket", "file.txt", io.BytesIO(b"data"), 4)

        response = app_client.delete("/api/buckets/full-bucket")
        assert response.status_code == 409
        body = response.json()
        assert "not empty" in body["error"]["message"]

    def test_delete_bucket_force(self, app_client, fake_minio):
        """Test force-deleting a non-empty bucket removes files too."""
        # Create bucket and add a file
        fake_minio.create_bucket("force-bucket")
        import io

        fake_minio.upload_file("force-bucket", "file.txt", io.BytesIO(b"data"), 4)

        response = app_client.delete("/api/buckets/force-bucket?force=true")
        assert response.status_code == 200
        data = response.json()
        assert data["deleted"] is True

        # Verify bucket is gone (file was inside it, so also gone)
        assert not fake_minio.bucket_exists("force-bucket")

    def test_delete_bucket_generic_value_error(self, app_client, mock_minio_client):
        """Test deleting a bucket when ValueError has unknown message returns 400."""
        mock_minio_client.delete_bucket.side_effect = ValueError("Unknown error")
        with patch("routes.buckets.get_minio_client", return_value=mock_minio_client):
            response = app_client.delete("/api/buckets/some-bucket")
        assert response.status_code == 400
        body = response.json()
        assert "Unknown error" in body["error"]["message"]

    def test_delete_bucket_minio_error(self, app_client, mock_minio_client):
        """Test deleting a bucket when MinIO raises a non-ValueError exception."""
        mock_minio_client.delete_bucket.side_effect = Exception("S3 error")
        with patch("routes.buckets.get_minio_client", return_value=mock_minio_client):
            response = app_client.delete("/api/buckets/some-bucket")
        assert response.status_code == 500
        body = response.json()
        assert "Delete bucket failed" in body["error"]["message"]


class TestCreateBucketError:
    """Test POST /api/buckets error paths."""

    def test_create_bucket_minio_error(self, app_client, mock_minio_client):
        """Test creating a bucket when MinIO raises an error returns 500."""
        mock_minio_client.create_bucket.side_effect = Exception("Connection refused")
        with patch("routes.buckets.get_minio_client", return_value=mock_minio_client):
            response = app_client.post("/api/buckets", json={"name": "test-bucket"})
        assert response.status_code == 500
        body = response.json()
        assert "Create bucket failed" in body["error"]["message"]


class TestGetBucketError:
    """Test GET /api/buckets/{name} error paths."""

    def test_get_bucket_minio_error(self, app_client, mock_minio_client):
        """Test getting a bucket when MinIO raises an error returns 500."""
        mock_minio_client.bucket_exists.side_effect = Exception("Connection refused")
        with patch("routes.buckets.get_minio_client", return_value=mock_minio_client):
            response = app_client.get("/api/buckets/test-bucket")
        assert response.status_code == 500
        body = response.json()
        assert "Get bucket failed" in body["error"]["message"]

    def test_get_bucket_not_in_list(self, app_client, fake_minio):
        """Test getting a bucket that exists but its creation_date still shows."""
        # Create a bucket so it exists with a creation date
        fake_minio.create_bucket("orphan-bucket")
        response = app_client.get("/api/buckets/orphan-bucket")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "orphan-bucket"
        # FakeMinioClient stores creation_date, so it should be present
        assert data["creation_date"] is not None

    def test_get_bucket_exists_but_not_in_list_buckets(self, app_client, mock_minio_client):
        """Test bucket that exists but is missing from list_buckets returns BucketInfo without date."""
        mock_minio_client.bucket_exists.return_value = True
        mock_minio_client.list_buckets.return_value = []  # Empty list -- bucket not in it
        with patch("routes.buckets.get_minio_client", return_value=mock_minio_client):
            response = app_client.get("/api/buckets/ghost-bucket")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "ghost-bucket"
        assert data["creation_date"] is None
