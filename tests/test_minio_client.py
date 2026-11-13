"""Tests for MinioClient wrapper."""

import threading
import time
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest
from minio.error import S3Error

# If a racing thread never reaches the barrier, fail the test rather than hang the
# suite: ``threading.Barrier.wait()`` with no timeout blocks forever, and there is no
# global ``--timeout`` in this repo's default pytest lane (see ``addopts`` in
# pyproject.toml), so a partial thread-start failure would hang the whole session with
# no output. On timeout the barrier breaks, every waiter raises ``BrokenBarrierError``,
# and ``_race`` records it as an error — which every caller already asserts against.
# Matches ``tests/test_notification_write_race.py``.
_BARRIER_TIMEOUT = 15.0


@pytest.fixture
def mock_minio():
    """Create a mock Minio client object."""
    return MagicMock()


@pytest.fixture
def minio_client(mock_minio):
    """Create a MinioClient with mocked Minio SDK."""
    mock_minio.bucket_exists.return_value = True
    mock_minio.list_buckets.return_value = []

    with patch("services.minio_client.Minio", return_value=mock_minio):
        from services.minio_client import MinioClient

        client = MinioClient()
        return client, mock_minio


class TestMinioClientInit:
    """Test MinioClient initialization."""

    def test_init_creates_client(self, minio_client):
        client, mock = minio_client
        assert client.client is mock

    def test_init_creates_missing_buckets(self):
        mock = MagicMock()
        mock.bucket_exists.return_value = False
        mock.list_buckets.return_value = []

        with patch("services.minio_client.Minio", return_value=mock):
            from services.minio_client import MinioClient

            _client = MinioClient()
            # Should have called make_bucket for each allowed bucket
            assert mock.make_bucket.called

    def test_init_handles_bucket_creation_error(self):
        mock = MagicMock()
        mock.bucket_exists.return_value = False
        mock.make_bucket.side_effect = S3Error(
            MagicMock(), "BucketError", "resource", "1", "host", "msg"
        )
        mock.list_buckets.return_value = []

        with patch("services.minio_client.Minio", return_value=mock):
            from services.minio_client import MinioClient

            # Should not raise - logs error instead
            client = MinioClient()
            assert client is not None


class TestValidateBucket:
    """Test bucket validation."""

    def test_allowed_bucket_passes(self, minio_client):
        client, mock = minio_client
        # Allowed buckets should pass without checking MinIO
        client.allowed_buckets = ["test-bucket"]
        client._validate_bucket("test-bucket")  # Should not raise

    def test_existing_bucket_passes(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = []
        mock.bucket_exists.return_value = True
        client._validate_bucket("other-bucket")  # Should not raise

    def test_nonexistent_bucket_raises(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = []
        mock.bucket_exists.return_value = False
        with pytest.raises(ValueError, match="not found"):
            client._validate_bucket("bad-bucket")


class TestUploadFile:
    """Test file upload."""

    def test_upload_success(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]

        mock_result = MagicMock()
        mock_result.etag = "test-etag"
        mock.put_object.return_value = mock_result

        result = client.upload_file(
            bucket="test-bucket",
            object_key="path/file.txt",
            data=BytesIO(b"content"),
            size=7,
            content_type="text/plain",
        )

        assert result["etag"] == "test-etag"
        assert result["bucket"] == "test-bucket"
        assert result["size"] == 7
        mock.put_object.assert_called_once()

    def test_upload_with_metadata(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]

        mock_result = MagicMock()
        mock_result.etag = "etag2"
        mock.put_object.return_value = mock_result

        result = client.upload_file(
            bucket="test-bucket",
            object_key="file.txt",
            data=BytesIO(b"data"),
            size=4,
            metadata={"key": "val"},
        )
        assert result["etag"] == "etag2"

    def test_upload_s3_error(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]
        mock.put_object.side_effect = S3Error(MagicMock(), "PutError", "res", "1", "host", "msg")

        with pytest.raises(S3Error):
            client.upload_file(
                bucket="test-bucket",
                object_key="file.txt",
                data=BytesIO(b"data"),
                size=4,
            )


class TestDownloadFile:
    """Test file download."""

    def test_download_success(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]

        mock_response = MagicMock()
        mock_response.read.return_value = b"file data"
        mock_response.headers = {"Content-Type": "text/plain"}
        mock.get_object.return_value = mock_response

        data, metadata = client.download_file("test-bucket", "path/file.txt")
        assert data == b"file data"
        assert metadata["content_type"] == "text/plain"
        mock_response.close.assert_called_once()
        mock_response.release_conn.assert_called_once()

    def test_download_s3_error(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]
        mock.get_object.side_effect = S3Error(MagicMock(), "GetError", "res", "1", "host", "msg")

        with pytest.raises(S3Error):
            client.download_file("test-bucket", "missing.txt")

    def test_stream_success(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]

        mock_response = MagicMock()
        mock_response.stream.return_value = iter([b"chunk1", b"chunk2"])
        mock_response.headers = {"Content-Type": "audio/mpeg", "Content-Length": "12"}
        mock.get_object.return_value = mock_response

        stream, metadata = client.stream_file("test-bucket", "big.mp3", chunk_size=6)
        # Connection is only released once the stream is fully consumed.
        chunks = b"".join(stream)
        assert chunks == b"chunk1chunk2"
        assert metadata["content_type"] == "audio/mpeg"
        assert metadata["content_length"] == "12"
        mock_response.stream.assert_called_once_with(6)
        mock_response.close.assert_called_once()
        mock_response.release_conn.assert_called_once()


class TestFileExists:
    """Test file existence check."""

    def test_exists_true(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]
        mock.stat_object.return_value = MagicMock()

        assert client.file_exists("test-bucket", "file.txt") is True

    def test_exists_false_no_such_key(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]
        err = S3Error(MagicMock(), "NoSuchKey", "not found", "res", "1", "host")
        mock.stat_object.side_effect = err

        assert client.file_exists("test-bucket", "missing.txt") is False

    def test_exists_other_error_raises(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]
        err = S3Error(MagicMock(), "AccessDenied", "denied", "res", "1", "host")
        mock.stat_object.side_effect = err

        with pytest.raises(S3Error):
            client.file_exists("test-bucket", "file.txt")


class TestDeleteFile:
    """Test file deletion."""

    def test_delete_success(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]

        result = client.delete_file("test-bucket", "file.txt")
        assert result is True
        mock.remove_object.assert_called_once()

    def test_delete_s3_error(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]
        mock.remove_object.side_effect = S3Error(
            MagicMock(), "DeleteError", "res", "1", "host", "msg"
        )

        with pytest.raises(S3Error):
            client.delete_file("test-bucket", "file.txt")


class TestGetFileMetadata:
    """Test file metadata retrieval."""

    def test_metadata_success(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]

        stat = MagicMock()
        stat.size = 1024
        stat.last_modified = "2024-01-01T00:00:00Z"
        stat.etag = "abc123"
        stat.content_type = "text/plain"
        stat.metadata = {"x-custom": "val"}
        mock.stat_object.return_value = stat

        result = client.get_file_metadata("test-bucket", "file.txt")
        assert result["size"] == 1024
        assert result["etag"] == "abc123"
        assert result["metadata"]["x-custom"] == "val"

    def test_metadata_not_found(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]
        err = S3Error(MagicMock(), "NoSuchKey", "not found", "res", "1", "host")
        mock.stat_object.side_effect = err

        result = client.get_file_metadata("test-bucket", "missing.txt")
        assert result is None

    def test_metadata_no_custom_metadata(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]

        stat = MagicMock()
        stat.size = 500
        stat.last_modified = "2024-01-01"
        stat.etag = "xyz"
        stat.content_type = "application/pdf"
        stat.metadata = None
        mock.stat_object.return_value = stat

        result = client.get_file_metadata("test-bucket", "file.pdf")
        assert result["metadata"] == {}

    def test_metadata_other_s3_error_raises(self, minio_client):
        """Non-NoSuchKey S3Error should propagate, not return None."""
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]
        err = S3Error(MagicMock(), "AccessDenied", "denied", "res", "1", "host")
        mock.stat_object.side_effect = err

        with pytest.raises(S3Error):
            client.get_file_metadata("test-bucket", "file.txt")


class TestListFiles:
    """Test file listing."""

    def test_list_files_success(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]

        obj1 = MagicMock()
        obj1.object_name = "file1.txt"
        obj1.size = 100
        obj1.last_modified = "2024-01-01"
        obj1.etag = "etag1"

        obj2 = MagicMock()
        obj2.object_name = "file2.txt"
        obj2.size = 200
        obj2.last_modified = "2024-01-02"
        obj2.etag = "etag2"

        mock.list_objects.return_value = iter([obj1, obj2])

        result = client.list_files("test-bucket", prefix="", recursive=True)
        assert len(result) == 2
        assert result[0]["object_key"] == "file1.txt"

    def test_list_files_with_max_keys(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]

        objects = []
        for i in range(10):
            obj = MagicMock()
            obj.object_name = f"file{i}.txt"
            obj.size = 100
            obj.last_modified = "2024-01-01"
            obj.etag = f"etag{i}"
            objects.append(obj)

        mock.list_objects.return_value = iter(objects)

        result = client.list_files("test-bucket", max_keys=3)
        assert len(result) == 3

    def test_list_files_s3_error(self, minio_client):
        client, mock = minio_client
        client.allowed_buckets = ["test-bucket"]
        mock.list_objects.side_effect = S3Error(MagicMock(), "ListError", "res", "1", "host", "msg")

        with pytest.raises(S3Error):
            client.list_files("test-bucket")


class TestListBuckets:
    """Test bucket listing."""

    def test_list_buckets(self, minio_client):
        client, mock = minio_client

        b1 = MagicMock()
        b1.name = "bucket1"
        b1.creation_date = "2024-01-01"
        b2 = MagicMock()
        b2.name = "bucket2"
        b2.creation_date = "2024-01-02"
        mock.list_buckets.return_value = [b1, b2]

        result = client.list_buckets()
        assert len(result) == 2
        assert result[0]["name"] == "bucket1"

    def test_list_buckets_error(self, minio_client):
        client, mock = minio_client
        mock.list_buckets.side_effect = S3Error(MagicMock(), "ListError", "res", "1", "host", "msg")

        with pytest.raises(S3Error):
            client.list_buckets()


class TestCreateBucket:
    """Test bucket creation."""

    def test_create_new_bucket(self, minio_client):
        client, mock = minio_client
        mock.bucket_exists.return_value = False

        result = client.create_bucket("new-bucket")
        assert result["created"] is True
        mock.make_bucket.assert_called_once_with("new-bucket")

    def test_create_existing_bucket(self, minio_client):
        client, mock = minio_client
        mock.bucket_exists.return_value = True

        result = client.create_bucket("existing")
        assert result["created"] is False

    def test_create_bucket_error(self, minio_client):
        client, mock = minio_client
        mock.bucket_exists.return_value = False
        mock.make_bucket.side_effect = S3Error(
            MagicMock(), "CreateError", "res", "1", "host", "msg"
        )

        with pytest.raises(S3Error):
            client.create_bucket("fail-bucket")


class TestDeleteBucket:
    """Test bucket deletion."""

    def test_delete_empty_bucket(self, minio_client):
        client, mock = minio_client
        mock.bucket_exists.return_value = True
        mock.list_objects.return_value = iter([])

        result = client.delete_bucket("empty-bucket")
        assert result["deleted"] is True
        mock.remove_bucket.assert_called_once()

    def test_delete_nonexistent_bucket(self, minio_client):
        client, mock = minio_client
        mock.bucket_exists.return_value = False

        with pytest.raises(ValueError, match="does not exist"):
            client.delete_bucket("gone-bucket")

    def test_delete_non_empty_bucket_without_force(self, minio_client):
        client, mock = minio_client
        mock.bucket_exists.return_value = True

        obj = MagicMock()
        obj.object_name = "file.txt"
        mock.list_objects.return_value = [obj]

        with pytest.raises(ValueError, match="not empty"):
            client.delete_bucket("full-bucket")

    def test_delete_force(self, minio_client):
        client, mock = minio_client
        mock.bucket_exists.return_value = True

        obj = MagicMock()
        obj.object_name = "file.txt"
        mock.list_objects.return_value = [obj]

        result = client.delete_bucket("full-bucket", force=True)
        assert result["deleted"] is True
        mock.remove_object.assert_called()

    def test_delete_s3_error(self, minio_client):
        client, mock = minio_client
        mock.bucket_exists.return_value = True
        mock.list_objects.return_value = iter([])
        mock.remove_bucket.side_effect = S3Error(
            MagicMock(), "DeleteError", "res", "1", "host", "msg"
        )

        with pytest.raises(S3Error):
            client.delete_bucket("err-bucket")


class TestBucketExists:
    """Test bucket existence check."""

    def test_exists_true(self, minio_client):
        client, mock = minio_client
        mock.bucket_exists.return_value = True
        assert client.bucket_exists("test") is True

    def test_exists_false(self, minio_client):
        client, mock = minio_client
        mock.bucket_exists.return_value = False
        assert client.bucket_exists("nope") is False

    def test_exists_error(self, minio_client):
        client, mock = minio_client
        mock.bucket_exists.side_effect = S3Error(
            MagicMock(), "CheckError", "res", "1", "host", "msg"
        )
        with pytest.raises(S3Error):
            client.bucket_exists("err")


class TestHealthCheck:
    """Test MinIO health check."""

    def test_healthy(self, minio_client):
        client, mock = minio_client
        mock.list_buckets.return_value = []

        healthy, message, latency = client.health_check()
        assert healthy is True
        assert "healthy" in message.lower()
        assert latency >= 0

    def test_unhealthy(self, minio_client):
        client, mock = minio_client
        mock.list_buckets.side_effect = Exception("Connection refused")

        healthy, message, latency = client.health_check()
        assert healthy is False
        assert "failed" in message.lower()


class TestGetMinioClient:
    """Test singleton getter."""

    def test_returns_singleton(self):
        """Verify get_minio_client returns the same instance on repeated calls."""
        import services.minio_client as mod

        mock = MagicMock()
        mock.bucket_exists.return_value = True
        mock.list_buckets.return_value = []

        # Reset global so the singleton is re-created
        original = mod._minio_client
        mod._minio_client = None
        try:
            with patch("services.minio_client.Minio", return_value=mock):
                first = mod.get_minio_client()
                second = mod.get_minio_client()
                assert first is second
        finally:
            mod._minio_client = original

    def test_creates_minio_client_type(self):
        """Verify get_minio_client returns a MinioClient instance."""
        import services.minio_client as mod

        mock = MagicMock()
        mock.bucket_exists.return_value = True
        mock.list_buckets.return_value = []

        original = mod._minio_client
        mod._minio_client = None
        try:
            with patch("services.minio_client.Minio", return_value=mock):
                client = mod.get_minio_client()
                assert isinstance(client, mod.MinioClient)
        finally:
            mod._minio_client = original


class TestGetMinioClientBuildsExactlyOneClient:
    """The cold-start stampede: a concurrent cold start must build ONE client.

    ⚠️ These tests deliberately do NOT use the ``app_client`` fixture. That
    fixture patches ``routes.*.get_minio_client`` with a fake, so a test sitting
    on it cannot observe the real factory at all and would go green against a
    completely unlocked ``get_minio_client``. Everything below drives
    ``services.minio_client.get_minio_client`` directly and asserts on an
    OBSERVABLE COUNT of real constructions — the number of times the underlying
    ``Minio`` SDK object was actually built — never on a mock having been called.

    Why this matters is timing, not correctness: the singleton is ``None``
    exactly when MinIO has just come back, requests and probes arrive
    concurrently, and every construction runs ``_ensure_buckets_exist`` (one
    ``bucket_exists``/``make_bucket`` round trip per allowed bucket). Unlocked,
    60 concurrent callers measured **60** constructions — a stampede aimed at a
    dependency that is by definition already struggling, per replica.
    """

    @staticmethod
    def _counting_slow_minio(delay: float = 0.05):
        """A ``Minio`` stand-in that counts constructions and is slow to build.

        The delay is what makes the race observable: it holds the window between
        "saw ``None``" and "assigned the global" open long enough that an
        unlocked check-then-set loses it every time. It stands in for the bucket
        round trips a real cold start makes.
        """
        counter = {"built": 0}
        counter_lock = threading.Lock()

        def factory(*_args, **_kwargs):
            with counter_lock:
                counter["built"] += 1
            time.sleep(delay)
            sdk = MagicMock()
            sdk.bucket_exists.return_value = True
            sdk.list_buckets.return_value = []
            return sdk

        return counter, factory

    @staticmethod
    def _race(target, threads: int):
        """Run ``target`` on ``threads`` threads released from one barrier.

        The barrier wait is BOUNDED (``_BARRIER_TIMEOUT``): an unbounded
        ``gate.wait()`` turns a partial thread-start failure into a hung pytest
        session, since this repo's default lane sets no ``--timeout``.
        """
        gate = threading.Barrier(threads)
        results: list = []
        errors: list = []
        results_lock = threading.Lock()

        def run():
            try:
                gate.wait(timeout=_BARRIER_TIMEOUT)
                value = target()
            except BaseException as exc:  # noqa: BLE001 — recorded, re-raised below
                with results_lock:
                    errors.append(exc)
            else:
                with results_lock:
                    results.append(value)

        workers = [threading.Thread(target=run) for _ in range(threads)]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join()
        return results, errors

    def test_a_concurrent_cold_start_builds_exactly_one_client(self):
        """60 concurrent callers, one construction. Unlocked this measured 60."""
        import services.minio_client as mod

        counter, factory = self._counting_slow_minio()
        original = mod._minio_client
        mod._minio_client = None
        try:
            with patch("services.minio_client.Minio", side_effect=factory):
                results, errors = self._race(mod.get_minio_client, threads=60)
        finally:
            mod._minio_client = original

        assert not errors, f"cold start raised: {errors[:3]}"
        assert len(results) == 60
        assert counter["built"] == 1, (
            f"a concurrent cold start built {counter['built']} MinIO clients, expected 1"
        )
        # ...and every caller got the SAME one, not just a small number of them.
        assert len({id(r) for r in results}) == 1

    def test_the_built_client_is_not_rebuilt_by_later_concurrent_callers(self):
        """The fast path: once built, concurrent callers add zero constructions."""
        import services.minio_client as mod

        counter, factory = self._counting_slow_minio()
        original = mod._minio_client
        mod._minio_client = None
        try:
            with patch("services.minio_client.Minio", side_effect=factory):
                first = mod.get_minio_client()
                assert counter["built"] == 1
                results, errors = self._race(mod.get_minio_client, threads=40)
        finally:
            mod._minio_client = original

        assert not errors
        assert counter["built"] == 1, "the warm path rebuilt the client"
        assert all(r is first for r in results)

    def test_a_failed_construction_leaves_the_singleton_none_and_is_retryable(self):
        """A raising constructor must not poison the lock or the global.

        This is the behaviour the unlocked version had and the locked version
        must keep: MinIO unreachable raises out of ``MinioClient.__init__``
        (``_ensure_buckets_exist`` catches only ``S3Error``; a connect failure
        is not one), the assignment never happens, and the NEXT caller — which
        may be minutes later, once MinIO is back — retries and succeeds.
        A lock left held, or a cached failure, would turn a transient outage
        into a permanently dead replica.
        """
        import services.minio_client as mod

        original = mod._minio_client
        mod._minio_client = None
        try:
            # Every concurrent caller fails, and fails independently.
            with patch("services.minio_client.Minio", side_effect=OSError("connection refused")):
                results, errors = self._race(mod.get_minio_client, threads=8)
            assert not results
            assert len(errors) == 8, "a caller silently got a client from a failed build"
            assert all(isinstance(e, OSError) for e in errors)
            assert mod._minio_client is None, "a failed construction cached something"

            # MinIO comes back: the very next caller must succeed, not inherit
            # a held lock or a poisoned global.
            counter, factory = self._counting_slow_minio(delay=0.0)
            with patch("services.minio_client.Minio", side_effect=factory):
                recovered = mod.get_minio_client()
            assert isinstance(recovered, mod.MinioClient)
            assert counter["built"] == 1
            assert mod._minio_client is recovered
        finally:
            mod._minio_client = original
