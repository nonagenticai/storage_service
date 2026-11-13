"""The event loop must survive a hung dependency.

``routes/files.py`` used to call the SYNCHRONOUS ``VirusScanner.scan_bytes``
directly from an ``async def`` handler, and every ``MinioClient`` call the same
way. A blocking call made on the event loop does not slow one request down, it
stops the process serving *any* request — ``/health/live`` included — for as
long as it lasts.

The bound is not small. ``scan_bytes`` retries ``max_retries`` (3) times against
a ``clamav_timeout`` (30 s) socket, sleeping ``1 * (attempt + 1)`` seconds
between attempts, so a blackholed clamd costs ~93 s of dead loop per upload.
That is far past any sane ``livenessProbe``, so kubelet kills the pod: a clamd
blip escalates from "uploads answer 503" — the deliberate fail-closed trade
made in #32 — to "the pod CrashLoops", which #32 never intended and which takes
downloads, listings and deletes down with it.

⚠️ These tests deliberately do NOT assert "``run_in_threadpool`` was called".
That would pass against an implementation that offloads the wrong thing, or
that offloads it and then awaits it under a lock. They instead run a REAL
blocking ``time.sleep`` inside the dependency and require that a second,
independent HTTP request is answered *while that sleep is still running* —
the property that actually matters. ``TestClient`` cannot show this (it drives
the app from its own thread), so they use ``httpx.ASGITransport``, which runs
the app on the test's own event loop, exactly as uvicorn does.
"""

from __future__ import annotations

import ast
import asyncio
import contextlib
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import patch

import httpx
import pytest

from services.virus_scanner import ScanResult

ROUTES_DIR = Path(__file__).resolve().parent.parent / "src" / "routes"

# How long the fake dependency blocks for. Long enough that a blocked loop is
# unambiguous, short enough to keep the suite fast.
BLOCK_SECONDS = 2.0
# When the probe is fired, measured from the moment the slow request starts.
PROBE_DELAY = 0.2


class _SlowBlockingScanner:
    """A scanner whose ``scan_bytes`` blocks the calling thread for real.

    ``time.sleep`` is used on purpose rather than ``asyncio.sleep``: the defect
    is that a *synchronous* dependency is called on the loop, and only a
    genuinely synchronous sleep reproduces it.
    """

    def __init__(self, seconds: float = BLOCK_SECONDS) -> None:
        self.seconds = seconds
        self.calls = 0
        self.started_at: float | None = None
        self.finished_at: float | None = None

    def scan_bytes(self, data: bytes, filename: str = "stream") -> ScanResult:
        self.calls += 1
        self.started_at = time.perf_counter()
        time.sleep(self.seconds)
        self.finished_at = time.perf_counter()
        return ScanResult(
            is_infected=False,
            virus_name=None,
            scan_time_ms=self.seconds * 1000,
            file_size=len(data),
        )

    def ping(self) -> bool:
        return True

    def health_check(self) -> tuple[bool, str, float]:
        return True, "ClamAV is healthy", 1.0


class _SlowUploadMinio:
    """Wraps the in-memory fake so that ``upload_file`` blocks for real.

    Stands in for a large ``put_object``, which has no timeout at all: it is
    bounded only by how long the body takes to move.
    """

    def __init__(self, inner: Any, seconds: float = BLOCK_SECONDS) -> None:
        # ``Any``, not ``object``: this is a ``__getattr__`` proxy over the
        # conftest fake, whose surface is the whole ``MinioClient`` API. Typed as
        # ``object`` the delegation below is an unresolved attribute.
        self._inner = inner
        self.seconds = seconds
        self.started_at: float | None = None
        self.finished_at: float | None = None

    def __getattr__(self, item: str) -> object:
        return getattr(self._inner, item)

    def upload_file(self, *args: object, **kwargs: object) -> dict:
        self.started_at = time.perf_counter()
        time.sleep(self.seconds)
        result = self._inner.upload_file(*args, **kwargs)
        self.finished_at = time.perf_counter()
        return result


@contextlib.contextmanager
def _app_with(minio: Any, scanner: Any, *, scanning: bool) -> Iterator[Any]:
    """Build the real app with the given backends, honouring ``scanning``.

    ⚠️ ``main`` is imported BEFORE the patches are entered, and that order is
    load-bearing. ``routes.health`` and ``routes.files`` bind the factory with
    ``from services.minio_client import get_minio_client``, so if importing them
    first happens *inside* the patch context — which it did, via ``from main
    import app`` below — they bind the MagicMock that
    ``patch("services.minio_client.get_minio_client")`` had just installed.
    ``patch("routes.health.get_minio_client", …)`` then records THAT mock as the
    original and faithfully restores it on exit, leaving every subsequent test in
    the session with ``routes.health.get_minio_client`` permanently stubbed to a
    stale fake from a finished test. It reproduced exactly once per session (on
    whichever test imported the routes first), which is precisely the shape of
    bug that makes a later test pass for a reason nobody chose.
    """
    from config import get_settings
    from main import app  # noqa: F401  — import BEFORE patching; see above

    old = os.environ.get("ENABLE_VIRUS_SCANNING")
    os.environ["ENABLE_VIRUS_SCANNING"] = "true" if scanning else "false"
    get_settings.cache_clear()
    try:
        with (
            patch("services.minio_client._minio_client", minio),
            patch("services.minio_client.get_minio_client", return_value=minio),
            patch("services.virus_scanner._virus_scanner", scanner),
            patch("services.virus_scanner.get_virus_scanner", return_value=scanner),
            patch("routes.files.get_minio_client", return_value=minio),
            patch("routes.files.get_virus_scanner", return_value=scanner),
            patch("routes.buckets.get_minio_client", return_value=minio),
            patch("routes.notifications.get_minio_client", return_value=minio),
            patch("routes.health.get_minio_client", return_value=minio),
            patch("routes.health.get_virus_scanner", return_value=scanner),
        ):
            from main import app

            yield app
    finally:
        if old is None:
            os.environ.pop("ENABLE_VIRUS_SCANNING", None)
        else:
            os.environ["ENABLE_VIRUS_SCANNING"] = old
        get_settings.cache_clear()


async def _upload_while_probing(app: Any) -> tuple[httpx.Response, httpx.Response, float]:
    """POST an upload and, ``PROBE_DELAY`` later, GET ``/health/live``.

    Returns ``(upload_response, liveness_response, liveness_answered_at)`` where
    the timestamp is relative to the moment the upload was issued.
    """
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        start = time.perf_counter()

        async def _upload() -> httpx.Response:
            return await ac.post(
                "/api/files/upload",
                data={"bucket": "kag-ingestion", "object_key": "slow.txt"},
                files={"file": ("slow.txt", b"payload", "text/plain")},
            )

        async def _probe() -> tuple[httpx.Response, float]:
            await asyncio.sleep(PROBE_DELAY)
            resp = await ac.get("/health/live")
            return resp, time.perf_counter() - start

        upload, (live, answered_at) = await asyncio.gather(_upload(), _probe())
    return upload, live, answered_at


@pytest.mark.timeout(60)
async def test_a_slow_virus_scan_does_not_stall_the_whole_process(fake_minio) -> None:
    """``/health/live`` must be answered WHILE a slow scan is still running.

    Without the fix the scan runs on the loop, so the probe coroutine cannot
    even be resumed until the scan returns: the liveness response lands after
    ``BLOCK_SECONDS``, which is precisely the window in which kubelet restarts
    the pod.
    """
    scanner = _SlowBlockingScanner()

    with _app_with(fake_minio, scanner, scanning=True) as app:
        upload, live, answered_at = await _upload_while_probing(app)

    # Non-vacuity: the slow path must actually have been exercised. If virus
    # scanning were off, or the route stopped scanning, every assertion below
    # would pass for the wrong reason.
    assert scanner.calls == 1, "the scan never ran; this test would prove nothing"
    assert scanner.started_at is not None and scanner.finished_at is not None
    assert scanner.finished_at - scanner.started_at >= BLOCK_SECONDS * 0.9

    assert upload.status_code == 200, upload.text
    assert upload.json()["virus_scanned"] is True

    # The property under test: the liveness probe was answered while the scan
    # was still running, not after it.
    assert live.status_code == 200
    assert answered_at < BLOCK_SECONDS, (
        f"/health/live was only answered {answered_at:.2f}s in, after the "
        f"{BLOCK_SECONDS}s scan — the event loop was blocked by it"
    )


@pytest.mark.timeout(60)
async def test_a_slow_minio_upload_does_not_stall_the_whole_process(fake_minio) -> None:
    """The same property for MinIO: ``put_object`` is blocking socket I/O too.

    A large upload has no timeout bounding it at all, so on the loop it is an
    unbounded outage of every other endpoint.
    """
    slow_minio = _SlowUploadMinio(fake_minio)

    with _app_with(slow_minio, _SlowBlockingScanner(seconds=0.0), scanning=False) as app:
        upload, live, answered_at = await _upload_while_probing(app)

    assert slow_minio.started_at is not None, "the slow upload path never ran"
    assert upload.status_code == 200, upload.text
    assert live.status_code == 200
    assert answered_at < BLOCK_SECONDS, (
        f"/health/live was only answered {answered_at:.2f}s in, after the "
        f"{BLOCK_SECONDS}s put_object — the event loop was blocked by it"
    )


class _BlockingConstructionMinio:
    """A stand-in for the ``MinioClient`` *class* whose CONSTRUCTION blocks.

    The real one does: ``__init__`` calls ``_ensure_buckets_exist``, which makes
    a ``bucket_exists`` round trip per allowed bucket under urllib3's
    ``Retry(total=5)`` × ``Timeout(connect=300, read=300)``. ``time.sleep`` is
    used rather than ``asyncio.sleep`` for the same reason as elsewhere in this
    file: only a genuinely synchronous block reproduces the defect.
    """

    def __init__(self, seconds: float = BLOCK_SECONDS) -> None:
        self.seconds = seconds
        self.constructions = 0
        self.started_at: float | None = None
        self.finished_at: float | None = None

    def __call__(self) -> _BlockingConstructionMinio:
        self.constructions += 1
        self.started_at = time.perf_counter()
        time.sleep(self.seconds)
        self.finished_at = time.perf_counter()
        return self

    def health_check(self) -> tuple[bool, str, float]:
        return True, "MinIO is healthy", 1.0


@contextlib.contextmanager
def _app_with_a_cold_singleton(construct: _BlockingConstructionMinio) -> Iterator[Any]:
    """The real ``get_minio_client`` over a ``None`` singleton and a slow build.

    ⚠️ Deliberately does NOT patch ``get_minio_client`` itself — unlike
    ``_app_with`` above. The whole defect lives inside the factory, so a test
    that stubs the factory out cannot see it. Only ``MinioClient`` (the class the
    factory constructs) and the ``_minio_client`` global are replaced.
    """
    from config import get_settings

    old = os.environ.get("ENABLE_VIRUS_SCANNING")
    os.environ["ENABLE_VIRUS_SCANNING"] = "false"
    get_settings.cache_clear()
    try:
        with (
            patch("services.minio_client.MinioClient", construct),
            patch("services.minio_client._minio_client", None),
        ):
            from main import app

            yield app
    finally:
        if old is None:
            os.environ.pop("ENABLE_VIRUS_SCANNING", None)
        else:
            os.environ["ENABLE_VIRUS_SCANNING"] = old
        get_settings.cache_clear()


@pytest.mark.timeout(60)
async def test_a_cold_client_build_does_not_stall_the_liveness_probe() -> None:
    """``/health/live`` must be answered WHILE ``/health/ready`` builds the client.

    This is the exact production sequence the branch's own incident ended in,
    and it is NOT covered by the two tests above — both of those patch
    ``get_minio_client`` to return a ready-made fake, so the factory never runs
    and its cost is invisible to them.

    The sequence: MinIO is unreachable, so ``MinioClient.__init__`` raises
    ``MaxRetryError`` out of ``_ensure_buckets_exist`` (which catches only
    ``S3Error``), the assignment in ``get_minio_client`` never completes, and the
    global stays ``None``. ``main.lifespan`` logs and starts the pod anyway. The
    first readiness tick then constructs the client from scratch — and the branch
    shipped that construction on the event loop, one line above the
    ``run_in_threadpool`` that correctly offloaded the call it feeds.

    Measured against a real blackholed endpoint (a socket that accepts and never
    answers) with the factory hoisted: ``/health/live`` was never answered at all
    — not late, never; even ``asyncio.wait_for`` could not fire, because firing
    it needs the loop. The process had to be SIGKILLed. With the factory inside
    the offloaded callable: 0.21 s, while readiness was still stuck in a worker
    thread. This test asserts on ELAPSED TIME rather than on "the factory was
    called in a thread", because the latter passes against an implementation
    that offloads the factory and then blocks on something else.
    """
    construct = _BlockingConstructionMinio()

    with _app_with_a_cold_singleton(construct) as app:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            start = time.perf_counter()

            async def _ready() -> httpx.Response:
                return await ac.get("/health/ready")

            async def _probe() -> tuple[httpx.Response, float]:
                await asyncio.sleep(PROBE_DELAY)
                resp = await ac.get("/health/live")
                return resp, time.perf_counter() - start

            ready, (live, answered_at) = await asyncio.gather(_ready(), _probe())

    # Non-vacuity: the cold-build path must actually have been exercised. If the
    # singleton had been warm, or the route had stopped calling the factory,
    # every assertion below would pass for the wrong reason.
    assert construct.constructions == 1, (
        f"the client was built {construct.constructions} times, expected exactly 1 — "
        "the cold-singleton path this test exists for did not run"
    )
    assert construct.started_at is not None and construct.finished_at is not None
    assert construct.finished_at - construct.started_at >= BLOCK_SECONDS * 0.9

    assert ready.status_code == 200, ready.text

    assert live.status_code == 200
    assert answered_at < BLOCK_SECONDS, (
        f"/health/live was only answered {answered_at:.2f}s in, after the "
        f"{BLOCK_SECONDS}s client construction — the factory is on the event loop"
    )


# ---------------------------------------------------------------------------
# Structural guard: a future edit must not put a blocking call back on the loop
# ---------------------------------------------------------------------------

_BLOCKING_BACKENDS = {"minio", "scanner"}
_OFFLOADERS = {"run_in_threadpool", "to_thread"}

# ⚠️ The FACTORIES are blocking too, and this is not a lesser case than the
# methods — it is the worse one.
#
# ``get_minio_client()`` is a lazy singleton. When the singleton is ``None`` it
# constructs a ``MinioClient``, whose ``_ensure_buckets_exist`` makes one
# ``bucket_exists`` (and possibly ``make_bucket``) round trip per allowed
# bucket. minio-py 7.2.x is handed no ``http_client``, so urllib3's defaults
# apply: ``Retry(total=5)`` over ``Timeout(connect=300, read=300)``. Against a
# blackholed MinIO that is hours of blocked loop for a single call.
#
# And the singleton is ``None`` in exactly that scenario. ``_ensure_buckets_exist``
# catches only ``S3Error``; a connect failure raises
# ``urllib3.exceptions.MaxRetryError``, which escapes ``__init__``, so the
# assignment inside ``get_minio_client`` never completes. ``main.lifespan``
# swallows the exception (``except Exception``, log only) so the pod still
# starts. The first ``/health/ready`` tick then pays the whole construction ON
# THE LOOP, ``/health/live`` stops being answered, and kubelet SIGKILLs the pod
# — into the same unreachable MinIO. That is the restart path of the very
# incident this branch is about.
#
# The original guard matched only ``Call(Attribute(Name in _BLOCKING_BACKENDS))``,
# i.e. ``minio.method()``. ``get_minio_client()`` is a ``Call(Name)`` and was
# invisible to it, so the hoisted-factory shape
#
#     minio = get_minio_client()                                    # ON THE LOOP
#     await run_in_threadpool(lambda: minio.health_check())
#
# passed the guard while containing the outage. It no longer does.
_BLOCKING_FACTORIES = {"get_minio_client", "get_virus_scanner"}


def _router_handlers(tree: ast.AST) -> dict[str, ast.AsyncFunctionDef | ast.FunctionDef]:
    return {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and isinstance(d.func.value, ast.Name)
            and d.func.value.id == "router"
            for d in node.decorator_list
        )
    }


def _offloaded_node_ids(func: ast.AST) -> set[int]:
    """Every AST node lexically inside a ``run_in_threadpool(...)`` argument."""
    offloaded: set[int] = set()
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        name = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else node.func.attr
            if isinstance(node.func, ast.Attribute)
            else None
        )
        if name not in _OFFLOADERS:
            continue
        for arg in [*node.args, *(kw.value for kw in node.keywords)]:
            for inner in ast.walk(arg):
                offloaded.add(id(inner))
    return offloaded


def _is_factory_call(node: ast.AST) -> bool:
    """``get_minio_client()`` / ``get_virus_scanner()`` — a lazy, blocking build."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _BLOCKING_FACTORIES
    )


def _backend_receiver(node: ast.AST) -> str | None:
    """For a call on a blocking backend, a readable name for its receiver.

    Two receiver shapes count: a local bound to the client (``minio.x()``) and
    the factory called inline (``get_minio_client().x()``), which is the shape
    the fix uses so that the construction happens inside the offloaded callable.
    """
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
        return None
    recv = node.func.value
    if isinstance(recv, ast.Name) and recv.id in _BLOCKING_BACKENDS:
        return recv.id
    if _is_factory_call(recv):
        assert isinstance(recv, ast.Call) and isinstance(recv.func, ast.Name)
        return f"{recv.func.id}()"
    return None


def touches_a_blocking_backend(func: ast.AST) -> bool:
    """Whether this handler reaches MinIO/clamd at all — offloaded or not.

    Used as the non-vacuity floor. It must recognise the *fixed* shape too:
    keyed only on ``Name`` receivers it would have read 0 once the factory moved
    inside the lambdas, and the floor would have failed for the wrong reason.
    """
    return any(_is_factory_call(n) or _backend_receiver(n) is not None for n in ast.walk(func))


def blocking_calls_on_the_loop(func: ast.AST) -> list[str]:
    """Calls on a blocking backend that are NOT inside an offloader's arguments.

    Both a backend METHOD call and a bare FACTORY call count; see the note on
    ``_BLOCKING_FACTORIES`` for why the factory is the sharper of the two.
    """
    offloaded = _offloaded_node_ids(func)
    # A factory call that is itself the receiver of a reported method call is
    # not reported twice — ``get_minio_client().health_check()`` on the loop is
    # one defect, not two.
    receivers: set[int] = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if _backend_receiver(node) is not None:
                receivers.add(id(node.func.value))

    bad: list[str] = []
    for node in ast.walk(func):
        if not isinstance(node, ast.Call) or id(node) in offloaded:
            continue
        if isinstance(node.func, ast.Attribute):
            recv = _backend_receiver(node)
            if recv is not None:
                bad.append(f"{recv}.{node.func.attr}()")
        elif isinstance(node.func, ast.Name):
            if _is_factory_call(node) and id(node) not in receivers:
                bad.append(f"{node.func.id}()")
    return bad


# Every route module, not a hand-kept list of two. The object-key guard learned
# this the hard way (``tests/test_object_keys.py`` was scoped to ``files.py`` and
# a leaky route in another module sailed past it); the same scoping bug here
# would have left ``buckets.py`` and ``notifications.py`` — which called MinIO
# wholly on the loop — permanently unguarded.
def _modules_defining_handlers() -> list[str]:
    """Every file under ``src/routes/`` that actually defines a ``@router`` handler.

    Discovered, not listed: a route module added tomorrow is covered without
    anyone remembering to extend a constant. ``responses.py`` and ``__init__.py``
    hold no handlers and drop out on their own.
    """
    found = []
    for path in sorted(ROUTES_DIR.glob("*.py")):
        if _router_handlers(ast.parse(path.read_text(encoding="utf-8"))):
            found.append(path.name)
    return found


_ROUTE_MODULES = _modules_defining_handlers()

# Handlers touching a blocking backend, per module, at the time this floor was
# written. A module dropping below its own count means the scan stopped seeing
# calls it used to see — the guard is what needs fixing then, not this number.
#
# ⚠️ EVERY module in ``_ROUTE_MODULES`` must appear here, and that is enforced
# in both directions below. An entry of ``0`` is legitimate — a route module
# that genuinely touches no blocking backend — but it has to be written down.
# The point is that ``0`` is a DECISION someone made and a reviewer can see,
# never a default nobody chose.
_MIN_CHECKED_HANDLERS = {"buckets.py": 4, "files.py": 5, "health.py": 2, "notifications.py": 3}


def _floor_for(module: str) -> int:
    """This module's non-vacuity floor. Strict — there is no defaulted zero.

    ⚠️ This used to be ``_MIN_CHECKED_HANDLERS.get(module, 0)``, and the default
    was the hole. ``_ROUTE_MODULES`` is DISCOVERED from the filesystem, so a new
    ``src/routes/foo.py`` is picked up and parametrized automatically — but it
    was picked up with a floor of ``0``, and ``checked >= 0`` is true no matter
    what the scan saw, including nothing at all. So the offender check ran on
    the new module (that part was always real) while the check that the scan is
    LOOKING at anything silently did not. A guard that cannot fail is not a
    guard, and this one would have reported itself green while being vacuous on
    exactly the module most likely to be wrong: the one just written.

    Failing loudly instead costs the author of a new route module one line in
    ``_MIN_CHECKED_HANDLERS`` and forces them to answer the question the floor
    exists to ask — how many of this module's handlers reach MinIO or clamd,
    and does the scan actually see them?
    """
    if module not in _MIN_CHECKED_HANDLERS:
        pytest.fail(
            f"{module}: route module has no entry in _MIN_CHECKED_HANDLERS, so its "
            f"non-vacuity floor would default to 0 and the check would pass trivially. "
            f"Count the handlers in src/routes/{module} that touch MinIO or clamd and add "
            f"'{module}': <count> to _MIN_CHECKED_HANDLERS (0 is a valid answer for a "
            f"module that touches neither — but write it down deliberately)."
        )
    return _MIN_CHECKED_HANDLERS[module]


def test_the_route_module_list_is_not_vacuous() -> None:
    # Exact equality, not ``<=``. The ``<=`` direction alone caught a listed
    # module that had been deleted, but not the direction that actually
    # disarmed the floor: a discovered module that nobody listed.
    assert set(_MIN_CHECKED_HANDLERS) == set(_ROUTE_MODULES), (
        f"_MIN_CHECKED_HANDLERS and the discovered route modules disagree: "
        f"unlisted={sorted(set(_ROUTE_MODULES) - set(_MIN_CHECKED_HANDLERS))}, "
        f"stale={sorted(set(_MIN_CHECKED_HANDLERS) - set(_ROUTE_MODULES))}"
    )
    assert len(_ROUTE_MODULES) >= 4, _ROUTE_MODULES


@pytest.mark.parametrize("module", _ROUTE_MODULES)
def test_no_route_handler_calls_a_blocking_backend_on_the_loop(module: str) -> None:
    tree = ast.parse((ROUTES_DIR / module).read_text(encoding="utf-8"))
    handlers = _router_handlers(tree)
    assert handlers, f"no @router handlers found in {module} — the scan is vacuous"

    checked = 0
    offenders: dict[str, list[str]] = {}
    for name, node in handlers.items():
        found = blocking_calls_on_the_loop(node)
        if touches_a_blocking_backend(node):
            checked += 1
        if found:
            offenders[name] = found
    floor = _floor_for(module)
    assert checked >= floor, (
        f"{module}: only {checked} handlers seen touching a blocking backend, expected >= {floor}"
    )
    assert not offenders, f"{module}: blocking calls left on the event loop: {offenders}"


def test_module_level_helpers_do_not_block_either(module: str = "files.py") -> None:
    """``validate_bucket`` is not decorated with ``@router`` but every handler
    awaits it, so a blocking call there is on the loop just the same and the
    handler-scoped scan above cannot see it."""
    tree = ast.parse((ROUTES_DIR / module).read_text(encoding="utf-8"))
    helpers = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.decorator_list
    }
    assert "validate_bucket" in helpers, "validate_bucket vanished; this scan is vacuous"
    assert touches_a_blocking_backend(helpers["validate_bucket"]), (
        "validate_bucket no longer reaches MinIO — the scan proves nothing"
    )
    assert blocking_calls_on_the_loop(helpers["validate_bucket"]) == []


def test_the_blocking_guard_fires_on_a_direct_call() -> None:
    """Negative control. A guard that cannot go red is not a guard."""
    sample = ast.parse(
        "@router.get('/x')\n"
        "async def leaky(bucket: str):\n"
        "    minio = get_minio_client()\n"
        "    return minio.list_buckets()\n"
    )
    handler = _router_handlers(sample)["leaky"]
    # Both halves are on the loop here, and the guard names both.
    assert sorted(blocking_calls_on_the_loop(handler)) == [
        "get_minio_client()",
        "minio.list_buckets()",
    ]


def test_the_blocking_guard_fires_on_a_factory_call_left_on_the_loop() -> None:
    """The negative control for THIS PR's blocker.

    This is byte-for-byte the shape ``routes/health.py`` shipped with: the
    blocking call correctly offloaded, and the factory that builds the client —
    the expensive half on a cold singleton — hoisted out of the lambda and left
    on the loop. The pre-extension guard returned ``[]`` here, which is how a
    two-hour loop stall passed a green "no blocking calls on the loop" test.
    """
    sample = ast.parse(
        "@router.get('/ready')\n"
        "async def readiness():\n"
        "    minio = get_minio_client()\n"
        "    return await run_in_threadpool(lambda: minio.health_check())\n"
    )
    handler = _router_handlers(sample)["readiness"]
    assert blocking_calls_on_the_loop(handler) == ["get_minio_client()"]


def test_the_blocking_guard_fires_on_a_hoisted_scanner_factory() -> None:
    """Same shape on the other factory — the guard is not minio-specific."""
    sample = ast.parse(
        "@router.post('/upload')\n"
        "async def upload(data: bytes):\n"
        "    scanner = get_virus_scanner()\n"
        "    return await run_in_threadpool(lambda: scanner.scan_bytes(data))\n"
    )
    handler = _router_handlers(sample)["upload"]
    assert blocking_calls_on_the_loop(handler) == ["get_virus_scanner()"]


def test_the_blocking_guard_accepts_the_offloaded_form() -> None:
    """Control on the control: the fixed shape must stay green.

    Note the factory is INSIDE the lambda — the whole point of the fix. If this
    ever goes red the guard has become unusable, not the code.
    """
    sample = ast.parse(
        "@router.get('/x')\n"
        "async def fine(bucket: str):\n"
        "    return await run_in_threadpool(lambda: get_minio_client().list_buckets())\n"
    )
    handler = _router_handlers(sample)["fine"]
    assert blocking_calls_on_the_loop(handler) == []
    assert touches_a_blocking_backend(handler), "the fixed shape must still COUNT as touching MinIO"


def test_the_blocking_guard_fires_on_the_offloaded_shape_left_unoffloaded() -> None:
    """``get_minio_client().x()`` is only safe because of the offloader around it."""
    sample = ast.parse(
        "@router.get('/x')\n"
        "async def leaky2(bucket: str):\n"
        "    return get_minio_client().list_buckets()\n"
    )
    handler = _router_handlers(sample)["leaky2"]
    assert blocking_calls_on_the_loop(handler) == ["get_minio_client().list_buckets()"]
