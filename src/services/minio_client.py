"""
MinIO client wrapper for storage service.
"""

import hashlib
import logging
import threading
from typing import BinaryIO, Iterator

from minio import Minio
from minio.error import S3Error
from minio.helpers import DictType
from minio.notificationconfig import (
    NotificationConfig,
    PrefixFilterRule,
    QueueConfig,
)

from config import get_settings

logger = logging.getLogger(__name__)


class MinioClient:
    """
    MinIO client wrapper providing file operations.

    This is the ONLY place in the system that has MinIO credentials.
    All other services must go through this API.
    """

    def __init__(self):
        """Initialize MinIO client from settings."""
        settings = get_settings()

        self.client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )
        self.allowed_buckets = settings.allowed_bucket_list

        logger.info(f"MinIO client initialized for endpoint: {settings.minio_endpoint}")

        # Ensure all allowed buckets exist
        self._ensure_buckets_exist()

    def _ensure_buckets_exist(self) -> None:
        """Create allowed buckets if they don't exist."""
        for bucket in self.allowed_buckets:
            try:
                if not self.client.bucket_exists(bucket):
                    self.client.make_bucket(bucket)
                    logger.info(f"Created bucket: {bucket}")
            except S3Error as e:
                logger.error(f"Failed to ensure bucket {bucket}: {e}")

    def _validate_bucket(self, bucket: str) -> None:
        """Validate bucket is allowed or exists in MinIO."""
        if bucket in self.allowed_buckets:
            return
        if self.client.bucket_exists(bucket):
            return
        raise ValueError(f"Bucket '{bucket}' not found")

    def upload_file(
        self,
        bucket: str,
        object_key: str,
        data: BinaryIO,
        size: int,
        content_type: str = "application/octet-stream",
        metadata: DictType | None = None,
    ) -> dict:
        """
        Upload file to MinIO.

        Args:
            bucket: Target bucket name
            object_key: Object key/path
            data: File data as binary stream
            size: Size of data in bytes
            content_type: MIME type
            metadata: Optional metadata dict

        Returns:
            Dict with upload result including etag
        """
        self._validate_bucket(bucket)

        try:
            result = self.client.put_object(
                bucket,
                object_key,
                data,
                size,
                content_type=content_type,
                metadata=metadata,
            )

            logger.info(f"Uploaded {object_key} to {bucket} ({size} bytes)")

            return {
                "bucket": bucket,
                "object_key": object_key,
                "etag": result.etag,
                "size": size,
                "content_type": content_type,
            }

        except S3Error as e:
            logger.error(f"Upload failed for {bucket}/{object_key}: {e}")
            raise

    def download_file(self, bucket: str, object_key: str) -> tuple[bytes, dict]:
        """
        Download file from MinIO.

        Args:
            bucket: Source bucket name
            object_key: Object key/path

        Returns:
            Tuple of (file_data, metadata_dict)
        """
        self._validate_bucket(bucket)

        try:
            response = self.client.get_object(bucket, object_key)
            data = response.read()

            # Get content type from response headers
            content_type = response.headers.get("Content-Type", "application/octet-stream")

            response.close()
            response.release_conn()

            logger.info(f"Downloaded {object_key} from {bucket} ({len(data)} bytes)")

            return data, {"content_type": content_type}

        except S3Error as e:
            logger.error(f"Download failed for {bucket}/{object_key}: {e}")
            raise

    def stream_file(
        self, bucket: str, object_key: str, chunk_size: int = 1024 * 1024
    ) -> tuple[Iterator[bytes], dict]:
        """
        Stream a file from MinIO in chunks without buffering it in memory.

        Opens the object and returns a generator that yields `chunk_size`-byte
        chunks plus metadata (content_type, content_length) read from the
        response headers. Peak memory is bounded by `chunk_size` regardless of
        object size, so large files (audiobooks, video) that would OOM a
        buffered `download_file` read stream safely.

        Args:
            bucket: Source bucket name
            object_key: Object key/path
            chunk_size: Bytes per yielded chunk (default 1 MiB)

        Returns:
            Tuple of (chunk_iterator, metadata_dict)
        """
        self._validate_bucket(bucket)

        response = self.client.get_object(bucket, object_key)
        content_type = response.headers.get("Content-Type", "application/octet-stream")
        content_length = response.headers.get("Content-Length")

        def _iter() -> Iterator[bytes]:
            try:
                yield from response.stream(chunk_size)
            finally:
                response.close()
                response.release_conn()

        logger.info(f"Streaming {object_key} from {bucket} (content-length={content_length})")
        return _iter(), {"content_type": content_type, "content_length": content_length}

    def file_exists(self, bucket: str, object_key: str) -> bool:
        """
        Check if file exists in MinIO.

        Args:
            bucket: Bucket name
            object_key: Object key/path

        Returns:
            True if file exists
        """
        self._validate_bucket(bucket)

        try:
            self.client.stat_object(bucket, object_key)
            return True
        except S3Error as e:
            if e.code == "NoSuchKey":
                return False
            raise

    def delete_file(self, bucket: str, object_key: str) -> bool:
        """
        Delete file from MinIO.

        Args:
            bucket: Bucket name
            object_key: Object key/path

        Returns:
            True if deleted successfully
        """
        self._validate_bucket(bucket)

        try:
            self.client.remove_object(bucket, object_key)
            logger.info(f"Deleted {object_key} from {bucket}")
            return True
        except S3Error as e:
            logger.error(f"Delete failed for {bucket}/{object_key}: {e}")
            raise

    def get_file_metadata(self, bucket: str, object_key: str) -> dict | None:
        """
        Get file metadata from MinIO.

        Args:
            bucket: Bucket name
            object_key: Object key/path

        Returns:
            Metadata dict or None if not found
        """
        self._validate_bucket(bucket)

        try:
            stat = self.client.stat_object(bucket, object_key)
            return {
                "bucket": bucket,
                "object_key": object_key,
                "size": stat.size,
                "last_modified": stat.last_modified,
                "etag": stat.etag,
                "content_type": stat.content_type,
                "metadata": dict(stat.metadata) if stat.metadata else {},
            }
        except S3Error as e:
            if e.code == "NoSuchKey":
                return None
            raise

    def list_files(
        self,
        bucket: str,
        prefix: str = "",
        recursive: bool = True,
        max_keys: int = 1000,
    ) -> list[dict]:
        """
        List files in bucket with optional prefix.

        Args:
            bucket: Bucket name
            prefix: Object key prefix filter
            recursive: Include subdirectories
            max_keys: Maximum number of results

        Returns:
            List of file info dicts
        """
        self._validate_bucket(bucket)

        try:
            objects = self.client.list_objects(
                bucket,
                prefix=prefix,
                recursive=recursive,
            )

            files: list[dict[str, object]] = []
            for obj in objects:
                if len(files) >= max_keys:
                    break
                files.append(
                    {
                        "object_key": obj.object_name,
                        "size": obj.size,
                        "last_modified": obj.last_modified,
                        "etag": obj.etag,
                    }
                )

            logger.debug(f"Listed {len(files)} files in {bucket} with prefix '{prefix}'")
            return files

        except S3Error as e:
            logger.error(f"List failed for {bucket}: {e}")
            raise

    def list_buckets(self) -> list[dict]:
        """List all buckets."""
        try:
            buckets = self.client.list_buckets()
            return [
                {
                    "name": b.name,
                    "creation_date": b.creation_date,
                }
                for b in buckets
            ]
        except S3Error as e:
            logger.error(f"List buckets failed: {e}")
            raise

    def create_bucket(self, name: str) -> dict:
        """Create a new bucket. Returns dict with created status."""
        try:
            if self.client.bucket_exists(name):
                return {"name": name, "created": False, "message": "Bucket already exists"}
            self.client.make_bucket(name)
            logger.info(f"Created bucket: {name}")
            return {"name": name, "created": True, "message": "Bucket created"}
        except S3Error as e:
            logger.error(f"Create bucket failed for {name}: {e}")
            raise

    def delete_bucket(self, name: str, force: bool = False) -> dict:
        """Delete a bucket. If force=True, remove all objects first."""
        try:
            if not self.client.bucket_exists(name):
                raise ValueError(f"Bucket '{name}' does not exist")

            if force:
                objects = self.client.list_objects(name, recursive=True)
                for obj in objects:
                    self.client.remove_object(name, obj.object_name)
                logger.info(f"Force-removed all objects from bucket: {name}")
            else:
                # Check if bucket is empty
                objects = list(self.client.list_objects(name, recursive=True))
                if objects:
                    raise ValueError(f"Bucket '{name}' is not empty (use force=true)")

            self.client.remove_bucket(name)
            logger.info(f"Deleted bucket: {name}")
            return {"name": name, "deleted": True, "message": "Bucket deleted"}
        except ValueError:
            raise
        except S3Error as e:
            logger.error(f"Delete bucket failed for {name}: {e}")
            raise

    def bucket_exists(self, name: str) -> bool:
        """Check if a bucket exists."""
        try:
            return self.client.bucket_exists(name)
        except S3Error as e:
            logger.error(f"Bucket exists check failed for {name}: {e}")
            raise

    def ensure_bucket(self, name: str) -> dict:
        """Create the bucket if it does not exist (on-demand dataset buckets).

        Idempotent; returns the same shape as ``create_bucket``.
        """
        return self.create_bucket(name)

    @staticmethod
    def _notification_config_id(prefix: str) -> str:
        """Deterministic, stable per-prefix config id so register/deregister is idempotent.

        MinIO ``QueueConfig`` ids must be unique within a bucket; we derive one from the
        object-key prefix so multiple connectors on one bucket coexist and a deregister can
        find exactly the rule it added.
        """
        # Not a security hash — just a stable, collision-resistant-enough id for the rule.
        digest = hashlib.sha1(prefix.encode("utf-8"), usedforsecurity=False).hexdigest()[:16]
        return f"cp-{digest}"

    def get_bucket_notifications(self, bucket: str) -> list[dict]:
        """List the bucket's live queue-notification rules (read-only ground truth).

        Surfaces MinIO's actual ``GetBucketNotificationConfiguration`` so a caller can detect
        drift between a connector's stored ``notifyRegistered`` flag and the rule that really
        exists. Returns ``[]`` for a bucket that does not exist (a never-provisioned dataset
        bucket has no rules — the same shape as one with its rule removed out-of-band).

        Unlike the write paths this does NOT ``_validate_bucket`` (which raises on a missing
        bucket): a never-provisioned dataset bucket is a valid "no rule" answer, not an error.
        The ``cp-*`` convention is already enforced by the route guard.
        """
        if not self.bucket_exists(bucket):
            return []
        try:
            current = self.client.get_bucket_notification(bucket)
            return [
                {
                    "config_id": q.config_id or "",
                    "prefix": q.prefix_filter_rule.value if q.prefix_filter_rule else "",
                    "events": list(q.events),
                    "arn": q.queue or "",
                }
                for q in (current.queue_config_list or [])
            ]
        except S3Error as e:
            logger.error(f"get_bucket_notifications failed for {bucket}: {e}")
            raise

    # ⚠️ KNOWN, DELIBERATELY UNFIXED: this read-modify-write and the identical one
    # in ``remove_bucket_notification`` below can LOSE AN UPDATE. Two concurrent
    # registrations on the same bucket both read the config, both append their own
    # rule to the version they read, and the second write destroys the first rule.
    #
    # Measured on this code, 5 runs out of 5, driving the real route with two
    # concurrent registrations for different prefixes: both answered **201**, both
    # reported ``rules: 1``, the server saw **2** PUTs and **1** rule survived. The
    # winner varied between runs. Note the response body specifically — each caller
    # is told ``rules: 1`` when the correct answer after two registrations is 2, so
    # the API does not merely fail silently, it actively reports a consistent-looking
    # lie to both callers.
    #
    # It is NEWLY REACHABLE in-process. Before the event-loop fix these calls ran on
    # the loop, which serialised them for free; offloading them to the threadpool is
    # what made two of them genuinely concurrent. That is a real consequence of that
    # fix and it is recorded here rather than quietly.
    #
    # WHY THERE IS NO CONDITIONAL WRITE TO USE. There is no optimistic-concurrency
    # primitive for this operation at ANY layer, so "just add an If-Match" is not an
    # option that was passed over:
    #   * S3 protocol — PutBucketNotificationConfiguration documents exactly two
    #     request headers, ``x-amz-expected-bucket-owner`` and
    #     ``x-amz-skip-destination-validation``. Neither is a precondition.
    #     ⚠️ ``x-amz-expected-bucket-owner`` is an OWNERSHIP guard, and "403 on
    #     mismatch" is AWS S3 behaviour, NOT what we run on: measured against MinIO
    #     ``RELEASE.2025-09-07T16-13-09Z``, the server IGNORES the header entirely
    #     and answers **200** on a deliberate account-ID mismatch. So on this server
    #     it is not even an ownership guard, let alone a concurrency one — do not
    #     reach for it in either role.
    #     GetBucketNotificationConfiguration returns no ETag, so even if a
    #     precondition header existed there would be nothing to put in it. AWS's
    #     conditional writes (Nov 2024) are scoped verbatim to PutObject,
    #     CompleteMultipartUpload and CopyObject — object operations. Bucket
    #     sub-resource config endpoints are in none of those lists.
    #     (The AWS docs do say "The PUT notification is an atomic operation", but
    #     that sentence is about destination VALIDATION being all-or-nothing within
    #     one request. It is not isolation between concurrent PUTs. Do not let it be
    #     quoted as protection.)
    #   * minio-py 7.2.20, the version pinned here and the latest released (there is
    #     no 8.x) — ``set_bucket_notification(bucket_name, config)`` takes no
    #     ``headers``/``extra_headers`` parameter at all and hardcodes
    #     ``Content-MD5``, which is a body-integrity checksum, not a precondition.
    #     ``get_bucket_notification`` discards the HTTP response headers entirely and
    #     returns only the unmarshalled config. Grepping the whole package for
    #     ``If-Match``/``if_match``/``IfMatch`` returns zero hits.
    #     ⚠️ The obvious next thought — "wrap the private call and pass the header
    #     yourself" — is BUILDABLE, and was built rather than argued about:
    #     ``Minio._execute()`` does take a ``headers: DictType`` argument, so a
    #     conditional-write wrapper is a few lines. Measured against MinIO
    #     ``RELEASE.2025-09-07T16-13-09Z``, that wrapper's ``If-Match`` and
    #     ``If-None-Match`` were ignored outright: **200** in every case, and GET
    #     returns no ETag to condition on in the first place. The client-library gap
    #     is therefore not the binding constraint — the SERVER is. Do not re-open
    #     this by patching around minio-py.
    #   * MinIO server — ``PutBucketNotificationHandler`` reads no precondition
    #     header, and its own persistence path
    #     (``globalBucketMetadataSys.Update`` -> ``updateAndParse``) is ITSELF an
    #     unlocked load-modify-save: no lock spans its read and its write, and the
    #     final ``saveConfig`` is unconditional. So the server is last-writer-wins by
    #     construction, not by omission we could ask it to fix.
    #
    # AND THE WRITER POPULATION IS WIDER THAN THIS ROUTE. MinIO stores every
    # bucket-scoped config in ONE blob (``.minio.sys/buckets/<bucket>/.metadata.bin``),
    # re-serialised whole from a stale read. So a concurrent ``PUT ?policy``,
    # ``?lifecycle``, ``?tagging``, ``?versioning`` or ``?replication`` on the same
    # bucket can destroy a notification rule too, and ``mc event add`` is the same
    # client-side read-modify-write with no precondition and no retry. The racing
    # writers are not only "two callers of this method".
    #
    # That cross-writer clobber is MEASURED, not inferred. 300 rounds against live
    # MinIO ``RELEASE.2025-09-07T16-13-09Z``, issuing a concurrent ``PUT ?tagging``
    # and ``PUT ?policy`` on ONE bucket: the tagging was destroyed in **105 of 300
    # rounds (35%)**. Two writers that have nothing to do with notifications, and
    # nothing to do with each other, lose one another's config a third of the time.
    #
    # WHY NOT AN IN-PROCESS LOCK — the fix that suggests itself, and the reason it is
    # NOT here. A ``threading.Lock`` around this method would serialise two callers
    # that happen to land on the SAME replica. It would not serialise anything else:
    #   * this service runs 2 replicas, so roughly HALF of concurrent pairs land on
    #     different replicas and the lock is inert for them;
    #   * it cannot touch ``mc``, another service, or an operator, all of which write
    #     the same blob — and per the 105/300 measurement above, an unrelated
    #     ``PUT ?policy`` alone defeats it in ~a third of concurrent pairs, BEFORE
    #     the two-replica halving is applied on top.
    # So its real coverage is "some of one of several writer populations" — while at
    # the call site it reads exactly like the operation is now safe. That is the
    # objection. It would not make the operation correct; it would make the residual
    # failures rarer and harder to reproduce, and it would retire the question in the
    # reader's mind. A rare, unreproducible, silently-wrong write that everyone
    # believes is guarded is strictly worse than a documented hazard, which is why
    # this comment exists instead of a lock.
    #
    # WHAT WOULD ACTUALLY FIX IT, for whoever picks this up:
    #   1. An external mutual-exclusion point OWNED BY US and covering every
    #      bucket-config writer for a bucket — e.g. a Postgres advisory lock keyed on
    #      bucket name, or funnelling all bucket-config writes through a single
    #      writer. Note this service today has no database, no Redis and no lock
    #      manager of any kind, so this means introducing a new infrastructure
    #      dependency: an architectural decision, not a follow-up patch.
    #   2. Read-after-write verification with bounded retry: after the PUT, re-read
    #      the config and confirm our rule is present; retry the whole
    #      read-modify-write if it is not, and answer an honest error rather than 201
    #      if it still is not. This is NOT linearizable — a later writer can still
    #      clobber us after we verify — but unlike a lock it works ACROSS replicas
    #      and across external writers, because it checks the real server rather than
    #      a local mutex, and it converts a silent lost update into either
    #      convergence or an attributable failure.
    # Neither is in scope for the change that added this note; the behaviour below is
    # the measured status quo, pinned by
    # ``tests/test_notification_write_race.py`` so it cannot change unnoticed.
    def set_bucket_notification(
        self, bucket: str, prefix: str, arn: str, events: list[str]
    ) -> dict:
        """Add/replace ONE queue-notification rule via read-modify-write.

        MinIO's ``PutBucketNotificationConfiguration`` overwrites the WHOLE bucket config,
        so we read the current config, drop any rule with the same (prefix-derived)
        ``config_id``, append the new rule, and write the merged config back. This keeps
        rules for other connectors on the same bucket intact. Idempotent on (bucket, prefix).
        """
        self._validate_bucket(bucket)
        config_id = self._notification_config_id(prefix)
        try:
            current = self.client.get_bucket_notification(bucket)
            queue_list = [q for q in (current.queue_config_list or []) if q.config_id != config_id]
            prefix_rule = PrefixFilterRule(prefix) if prefix else None
            queue_list.append(
                QueueConfig(
                    events,
                    config_id=config_id,
                    prefix_filter_rule=prefix_rule,
                    queue=arn,
                )
            )
            new_config = NotificationConfig(
                cloud_func_config_list=current.cloud_func_config_list,
                queue_config_list=queue_list,
                topic_config_list=current.topic_config_list,
            )
            self.client.set_bucket_notification(bucket, new_config)
            logger.info(
                "Set bucket notification on %s prefix='%s' arn=%s (%s)",
                bucket,
                prefix,
                arn,
                config_id,
            )
            return {
                "bucket": bucket,
                "prefix": prefix,
                "config_id": config_id,
                "rules": len(queue_list),
            }
        except S3Error as e:
            logger.error(f"set_bucket_notification failed for {bucket}: {e}")
            raise

    def remove_bucket_notification(self, bucket: str, prefix: str) -> dict:
        """Remove the single queue-notification rule for (bucket, prefix). Idempotent.

        Read-modify-write: drop only the rule whose ``config_id`` matches this prefix and
        write the remainder back, leaving other connectors' rules untouched.
        """
        self._validate_bucket(bucket)
        config_id = self._notification_config_id(prefix)
        try:
            current = self.client.get_bucket_notification(bucket)
            existing = current.queue_config_list or []
            queue_list = [q for q in existing if q.config_id != config_id]
            removed = len(existing) - len(queue_list)
            new_config = NotificationConfig(
                cloud_func_config_list=current.cloud_func_config_list,
                queue_config_list=queue_list,
                topic_config_list=current.topic_config_list,
            )
            self.client.set_bucket_notification(bucket, new_config)
            logger.info(
                "Removed %d notification rule(s) on %s prefix='%s'", removed, bucket, prefix
            )
            return {
                "bucket": bucket,
                "prefix": prefix,
                "config_id": config_id,
                "removed": removed,
                "rules": len(queue_list),
            }
        except S3Error as e:
            logger.error(f"remove_bucket_notification failed for {bucket}: {e}")
            raise

    def health_check(self) -> tuple[bool, str, float]:
        """
        Check MinIO health.

        Returns:
            Tuple of (is_healthy, message, latency_ms)
        """
        import time

        start = time.time()
        try:
            # Try to list buckets as health check
            list(self.client.list_buckets())
            latency = (time.time() - start) * 1000
            return True, "MinIO is healthy", latency
        except Exception as e:
            latency = (time.time() - start) * 1000
            return False, f"MinIO health check failed: {e}", latency


# Singleton instance
_minio_client: MinioClient | None = None

# ⚠️ ``threading.Lock``, NOT ``asyncio.Lock``. Since the event-loop fix every
# construction happens inside ``run_in_threadpool`` — i.e. on an anyio worker
# THREAD, not on the loop — so the racing callers are OS threads. An
# ``asyncio.Lock`` is not thread-safe and guards nothing here; it would also
# have to be awaited, which a synchronous factory called from a worker thread
# cannot do.
_minio_client_lock = threading.Lock()


def get_minio_client() -> MinioClient:
    """Get global MinIO client instance.

    Double-checked locking. The unguarded check-then-set this replaces was a
    lost-wakeup stampede in exactly the situation that matters: after a MinIO
    outage the singleton is ``None`` (see the note in ``routes/health.py`` — a
    connect failure escapes ``MinioClient.__init__`` and the assignment never
    completes), probes and requests then arrive CONCURRENTLY, and every one of
    them saw ``None`` and built its own client. Measured on the unlocked code:
    60 concurrent callers produced **60** constructions, each running
    ``_ensure_buckets_exist`` — one ``bucket_exists``/``make_bucket`` round trip
    per allowed bucket — against a MinIO that is by definition already
    struggling. Nothing corrupted, which is why it was not a blocker; it just
    hammered a recovering dependency, per replica.

    Two properties matter here. ⚠️ Only ONE of them is pinned by a test, and it
    is worth knowing which, so nobody "simplifies" the other believing a test
    will catch them:

    * **Exactly one construction, and a failed construction does not poison
      later attempts — PINNED.** ``tests/test_minio_client.py`` races 60 callers
      into a cold start and asserts one construction and one shared object, and
      races 8 callers into a raising constructor and asserts that all 8 fail,
      the global is still ``None``, the lock is not left held, and the next
      caller succeeds. The assignment happens only if ``MinioClient()`` returns;
      if it raises, the exception propagates, the global is still ``None``, the
      ``with`` releases the lock, and the NEXT caller retries from scratch —
      the same failure behaviour as the unlocked version, deliberately. Remove
      the lock, or the re-check under it, and those tests go red.
    * **The lock-free fast path is an OPTIMISATION, not a guarded invariant —
      NOT pinned, and it cannot be.** Once built, the read is a plain global
      load, so steady-state request handling is uncontended. But deleting that
      prelude is an EQUIVALENT MUTANT: every caller would then take the lock,
      the re-check would hand back the same already-built object, and nothing
      observable changes — only contention, which no test in this suite
      measures. Measured: with the prelude deleted, this file's tests still pass
      44/44. Keep it for the contention; do not expect a test to defend it.
      The unsynchronised read is safe by construction rather than by test:
      ``_minio_client`` is only ever assigned an already-constructed object —
      Python evaluates ``MinioClient()`` fully before binding it — so a caller
      observes the global as either ``None`` or a finished client, never a
      half-built one.

    THE LOCK IS HELD ACROSS THE CONSTRUCTION, which is blocking network I/O.
    That is deliberate, but it is NOT free, and the cost falls on exactly the
    scenario this docstring is about, so it is stated rather than waved at:

    * **Success path — near-free.** N callers pay one construction instead of
      N; the queued ones hit the re-check and get the finished client. That is
      the whole point of the change.
    * **Failure path — the callers pay SERIALLY.** This service passes no
      ``http_client``, so minio-py 7.2.20 builds its own ``urllib3.PoolManager``
      with ``Timeout(connect=300, read=300)`` and ``Retry(total=5,
      backoff_factor=0.2)`` — six attempts. A connect failure is not an
      ``S3Error``, so it escapes ``_ensure_buckets_exist`` and out of
      ``__init__``. Measured, connection REFUSED (closed local port, the
      ordinary "MinIO process is down" case): ``T_fail`` = **6.0 s** — the
      refusals return instantly, so essentially all of it is urllib3's backoff
      across the five retries. Measured, packets DROPPED (blackholed address,
      connect timeout scaled to 1 s and multiplied back out): 12.0 s at
      ``connect=1 s``, i.e. six connect attempts plus the same ~6 s of backoff,
      so **~1806 s** at the real ``connect=300 s``. Unlocked, N callers each pay
      ``T_fail`` in PARALLEL; locked, they pay it one after another, so the last
      of anyio's 40 default worker threads waits up to ``40 x T_fail`` — ~4 min
      refused, pathological blackholed. This is a real behavioural trade
      introduced by the lock, not a wording detail.

    Why it is still the right trade:

    * **The outcome per caller is unchanged.** On the failure path every caller
      fails in BOTH designs. The lock changes when each learns it, not whether.
      The callers made to wait were getting a 5xx either way, and by their turn
      their client and the ingress have long since given up.
    * **The queue cannot be refilled.** ``/health/ready`` goes through this same
      path, so it fails or times out too, the replica leaves the Service, and no
      NEW caller arrives to queue behind the lock. The serialised set is bounded
      by the threads already in flight, and each terminates: urllib3's retry
      budget is finite, and nothing reachable from ``MinioClient.__init__``
      re-enters this function or the threadpool, so it cannot deadlock.
    * **It cannot cost liveness.** ``/health/live`` is a plain ``async def`` that
      returns a dict and never touches the threadpool, so saturating anyio's
      workers here does not stop the pod answering it — which is precisely the
      failure mode #33 fixed. The threadpool is saturated for ``T_fail`` in the
      unlocked design too; the lock extends the duration, it does not create
      the saturation.
    * **The thing being protected is real.** Unlocked, 40 threads x 6 attempts
      is 240 connect storms per replica against a MinIO that is by definition
      already struggling. Six is the recovering server's problem; 240 is ours.

    ON BOUNDING ``T_fail`` WITH A SHORTER CONNECT TIMEOUT — considered here and
    deliberately NOT done, so it is not silently passed over:

    * It is not scopable to the construction. minio-py takes a ``PoolManager``,
      not a per-call timeout, and that pool is the client's transport for its
      whole lifetime — shortening connect would change every subsequent upload,
      download and delete, not just cold start.
    * Passing ``http_client=`` means re-implementing minio-py's default TLS
      setup (``cert_reqs``, ``ca_certs=SSL_CERT_FILE or certifi.where()``).
      Getting that wrong is a live TLS failure against the internal CA — far
      worse than a slow cold start.
    * Any value would be a guess. Nobody has measured what connect latency a
      RECOVERING MinIO actually shows, and this is the recovery path the change
      exists to protect; picking a number blind is how you turn a slow recovery
      into a failed one.

    If the blackholed case is ever OBSERVED in production, that is the trigger
    to pass an explicit ``http_client`` with a bounded connect timeout — sized
    against a measurement of a recovering server, not against this paragraph.
    """
    global _minio_client
    # Fast path: already built, no lock.
    client = _minio_client
    if client is not None:
        return client
    with _minio_client_lock:
        # Re-check under the lock — the winner of the race built it while we
        # waited, and without this second check we would build a second one.
        if _minio_client is None:
            _minio_client = MinioClient()
        return _minio_client
