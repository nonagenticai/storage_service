"""Pins the MEASURED, KNOWN-BROKEN behaviour of concurrent notification writes.

⚠️ Read this before "fixing" anything here. These tests assert that a lost update
HAPPENS. They are not a specification of desired behaviour — they are a tripwire on
a documented hazard, so that it cannot change (in either direction) unnoticed.

``MinioClient.set_bucket_notification`` is a read-modify-write, because MinIO's
``PutBucketNotificationConfiguration`` replaces the WHOLE bucket config and offers no
conditional-write primitive to make the sequence atomic. The full analysis — why no
``If-Match`` exists at the protocol, client or server layer, why MinIO's own
persistence path is itself an unlocked load-modify-save over one shared blob, why the
racing writer population is wider than this route, and why an in-process lock was
deliberately NOT added — is in the block comment above that method in
``src/services/minio_client.py``. Do not re-derive it; read it.

If you have made this operation genuinely atomic, ``test_two_concurrent_registrations_
lose_one_rule`` SHOULD fail. Delete it, and delete the analysis comment with it.
"""

import asyncio
import threading
from unittest.mock import patch

import httpx
import pytest
from minio.notificationconfig import NotificationConfig

REGISTER = "/api/buckets/{bucket}/notifications/register"

# If a request never reaches the read, fail the test rather than hang the suite.
_BARRIER_TIMEOUT = 15.0


class FakeMinioServer:
    """Stands in for the MinIO SERVER, not for ``MinioClient``.

    The behaviour that matters is that a PUT stores the submitted config WHOLESALE —
    last writer wins. That is what MinIO really does: its bucket-metadata ``Update()``
    re-serialises the entire ``.metadata.bin`` blob from its own stale read, with no
    lock spanning read and write and no precondition on the save.

    ``read_barrier``, when set, holds every reader at the GET until the expected
    number of them have arrived. That makes the interleaving DETERMINISTIC instead of
    timing-dependent: without it this test would be a flake, and a flaky test pinning
    a race is worse than no test at all.
    """

    def __init__(self, read_barrier: threading.Barrier | None = None):
        self.buckets: set[str] = set()
        self.config = NotificationConfig()
        self.puts = 0
        self.gets = 0
        self.read_barrier = read_barrier
        self._lock = threading.Lock()

    # --- bucket plumbing the route touches on the way in ---
    def bucket_exists(self, bucket: str) -> bool:
        return bucket in self.buckets

    def make_bucket(self, bucket: str) -> None:
        with self._lock:
            self.buckets.add(bucket)

    def list_buckets(self) -> list:
        return []

    # --- the read-modify-write under test ---
    def get_bucket_notification(self, bucket: str) -> NotificationConfig:
        with self._lock:
            self.gets += 1
            # ⚠️ SNAPSHOT BEFORE THE BARRIER, and return the snapshot. Reading
            # ``self.config`` *after* the barrier released let whichever racer got to
            # its PUT first be observed by the other, which is the opposite of the
            # interleaving being pinned — one caller then legitimately merged 2 rules
            # and nothing was lost. The stale read is the whole point.
            snapshot = self.config
        if self.read_barrier is not None:
            # Every racer has now read; none may write until all have.
            self.read_barrier.wait(timeout=_BARRIER_TIMEOUT)
        return snapshot

    def set_bucket_notification(self, bucket: str, config: NotificationConfig) -> None:
        with self._lock:
            self.puts += 1
            self.config = config  # wholesale replace — last writer wins

    # --- assertions read this ---
    def live_prefixes(self) -> list[str]:
        rules = self.config.queue_config_list or []
        return sorted(q.prefix_filter_rule.value if q.prefix_filter_rule else "" for q in rules)


def _register(server: FakeMinioServer):
    """Run the REAL app against ``server``, returning an async caller.

    Patches the ``Minio`` SDK class, NOT ``get_minio_client`` and NOT via the
    ``app_client`` fixture. That is deliberate: ``app_client`` replaces
    ``routes.notifications.get_minio_client`` with an in-memory fake whose
    ``set_bucket_notification`` is a single uninterruptible dict update, so a test
    sitting on it exercises none of the read-modify-write this file is about and
    would report "no race" no matter how broken the real client was. Everything here
    drives the real ``MinioClient`` and asserts on OBSERVABLE SERVER STATE — the rules
    that actually survived — never on a mock having been called.
    """
    import services.minio_client as mod
    from main import app  # imported before patching; see the note in conftest.app_client

    original = mod._minio_client

    class _Ctx:
        async def __aenter__(self):
            self._patch = patch("services.minio_client.Minio", return_value=server)
            self._patch.start()
            mod._minio_client = None
            # Build the singleton up front so the construction is not itself part of
            # the interleaving under test.
            mod.get_minio_client()
            transport = httpx.ASGITransport(app=app)
            self._client = httpx.AsyncClient(transport=transport, base_url="http://test")
            return self._client

        async def __aexit__(self, *exc):
            await self._client.aclose()
            mod._minio_client = original
            self._patch.stop()
            return False

    return _Ctx()


class TestConcurrentNotificationRegistration:
    async def test_two_sequential_registrations_keep_both_rules(self):
        """CONTROL. The merge logic is correct when the writes do not interleave.

        Without this, the race test below would pass just as happily against a fake
        that dropped every rule, or against a ``set_bucket_notification`` that had
        stopped merging at all — it asserts "one rule survived", which is also what a
        wholly broken merge produces. This control is what makes that assertion mean
        "the second write clobbered the first" rather than "writes do not work".
        """
        server = FakeMinioServer()  # no barrier: fully sequential
        bucket = "cp-race-control"

        async with _register(server) as client:
            first = await client.post(REGISTER.format(bucket=bucket), json={"prefix": "alpha.csv"})
            second = await client.post(REGISTER.format(bucket=bucket), json={"prefix": "beta.csv"})

        assert first.status_code == 201
        assert second.status_code == 201
        assert first.json()["rules"] == 1
        assert second.json()["rules"] == 2, "sequential merge did not accumulate"
        assert server.live_prefixes() == ["alpha.csv", "beta.csv"]
        assert server.puts == 2

    async def test_two_concurrent_registrations_lose_one_rule(self):
        """⚠️ ASSERTS THE BUG. Both callers get 201; one rule is silently destroyed.

        Deterministic via the read barrier: both requests are held at the GET until
        both have read, then both write their own merge of the same stale config.

        Note ``rules: 1`` in BOTH response bodies. After two registrations the honest
        answer is 2, so the API does not just lose the write — it reports a
        consistent-looking count to each caller that is wrong for both. A caller has
        no way to detect the loss from the response.

        Newly reachable in-process: before the event-loop fix these calls ran ON the
        loop, which serialised them for free. Offloading them to the threadpool is
        what made two of them genuinely concurrent. The same race already existed
        ACROSS the 2 replicas, and still does — which is exactly why an in-process
        lock was rejected rather than shipped. See the analysis comment on
        ``MinioClient.set_bucket_notification``.
        """
        barrier = threading.Barrier(2)
        server = FakeMinioServer(read_barrier=barrier)
        bucket = "cp-race-demo"

        async with _register(server) as client:
            url = REGISTER.format(bucket=bucket)
            first, second = await asyncio.gather(
                client.post(url, json={"prefix": "alpha.csv"}),
                client.post(url, json={"prefix": "beta.csv"}),
            )

        # Both callers were told they succeeded.
        assert first.status_code == 201
        assert second.status_code == 201
        assert first.json()["rules"] == 1
        assert second.json()["rules"] == 1

        # Both writes reached the server...
        assert server.gets == 2
        assert server.puts == 2

        # ...and exactly one rule survived: the lost update.
        survivors = server.live_prefixes()
        assert len(survivors) == 1, (
            f"expected the documented lost update (1 surviving rule), got {survivors}. "
            f"If this operation is now genuinely atomic, delete this test AND the "
            f"analysis comment on MinioClient.set_bucket_notification."
        )
        # Which one wins is genuinely nondeterministic — do not pin it.
        assert survivors[0] in {"alpha.csv", "beta.csv"}

    @pytest.mark.parametrize("prefix", ["alpha.csv", "beta.csv"])
    async def test_a_single_registration_is_unaffected(self, prefix: str):
        """The uncontended path is correct — the hazard is concurrency, not the merge."""
        server = FakeMinioServer()
        bucket = "cp-race-single"

        async with _register(server) as client:
            resp = await client.post(REGISTER.format(bucket=bucket), json={"prefix": prefix})

        assert resp.status_code == 201
        assert resp.json()["rules"] == 1
        assert server.live_prefixes() == [prefix]
