"""Tests for the object-key validation choke point.

``object_key`` used to be an entirely unvalidated ``Form(...)`` string on
upload and an unvalidated ``{object_key:path}`` segment on every read route —
it went straight to MinIO. These tests cover the validator itself, its use by
every route that reaches MinIO with a key or prefix, and (AST-based, in the
style of ``test_tenant_default.py``) the structural guarantee that a newly
added route cannot skip it.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from services.minio_client import MinioClient
from services.object_keys import (
    MAX_OBJECT_KEY_BYTES,
    InvalidObjectKeyError,
    validate_object_key,
    validate_prefix,
)

ROUTES_DIR = Path(__file__).resolve().parent.parent / "src" / "routes"
FILES_ROUTES = ROUTES_DIR / "files.py"


class TestValidateObjectKey:
    """The validator itself."""

    @pytest.mark.parametrize(
        "key",
        [
            "projects/8f1/main/artifact/v1/report.pdf",  # artifact_service
            "uploads/019a2b3c4d/contract.pdf",  # ingestion staged upload
            "kag-images/0195f48b-d000-7000-8000-000000000001/job7/img-0001.png",
            "audit/2026/09/06/audit_log.ndjson",  # commonpractice audit export
            "analytics-exports/2026/report.xlsx",
            "en.epub",  # book-fulfillment, flat key
            "a//b.txt",  # empty segments are legal S3 and a live caller shape
            "spaces and (parens).txt",
            "unicode-Ω-ключ.bin",
        ],
    )
    def test_live_caller_key_shapes_are_accepted(self, key: str) -> None:
        """Control: the keys production actually sends must keep working.

        A validator that rejects real traffic is a worse outcome than the
        unvalidated string it replaced, so these are asserted explicitly rather
        than assumed.
        """
        assert validate_object_key(key) == key

    def test_empty_key_is_rejected(self) -> None:
        with pytest.raises(InvalidObjectKeyError, match="empty"):
            validate_object_key("")

    @pytest.mark.parametrize(
        "key",
        ["../etc/passwd", "a/../../b", "projects/../audit/x", "..", "a/./b", "."],
    )
    def test_traversal_segments_are_rejected(self, key: str) -> None:
        with pytest.raises(InvalidObjectKeyError, match=r"'\.' or '\.\.'"):
            validate_object_key(key)

    def test_a_dotted_filename_is_not_traversal(self) -> None:
        """Only whole segments count — ``..`` inside a name is fine."""
        assert validate_object_key("reports/v1..2/summary.txt")
        assert validate_object_key(".hidden")

    def test_absolute_key_is_rejected(self) -> None:
        with pytest.raises(InvalidObjectKeyError, match="'/'"):
            validate_object_key("/etc/passwd")

    def test_control_characters_are_rejected(self) -> None:
        """A key the response model cannot echo back was a guaranteed 500."""
        with pytest.raises(InvalidObjectKeyError, match="control"):
            validate_object_key("a\x00b")
        with pytest.raises(InvalidObjectKeyError, match="control"):
            validate_object_key("log\ninjected")

    def test_key_at_the_byte_limit_is_accepted(self) -> None:
        assert validate_object_key("k" * MAX_OBJECT_KEY_BYTES)

    def test_over_long_key_is_rejected(self) -> None:
        with pytest.raises(InvalidObjectKeyError, match="bytes"):
            validate_object_key("k" * (MAX_OBJECT_KEY_BYTES + 1))

    def test_limit_is_bytes_not_characters(self) -> None:
        """S3 caps keys at 1024 *bytes* of UTF-8."""
        key = "Ω" * MAX_OBJECT_KEY_BYTES  # 2 bytes each
        with pytest.raises(InvalidObjectKeyError, match="bytes"):
            validate_object_key(key)


class TestValidatePrefix:
    """The list route's ``prefix`` query parameter."""

    def test_empty_prefix_is_allowed(self) -> None:
        """Existing callers list a whole bucket with ``prefix=``."""
        assert validate_prefix("") == ""

    def test_normal_prefix_is_allowed(self) -> None:
        assert validate_prefix("projects/") == "projects/"

    def test_traversal_prefix_is_rejected(self) -> None:
        with pytest.raises(InvalidObjectKeyError):
            validate_prefix("../")


_VALIDATOR_CALL_NAMES = {
    "validate_object_key",
    "validate_prefix",
    "checked_object_key",
    "checked_prefix",
}

_GUARDED_PARAMS = {"object_key", "prefix"}


def _client_sink_params() -> dict[str, list[str]]:
    """``MinioClient`` method name -> its parameter names (excluding ``self``),
    for every method whose real signature names ``object_key`` or ``prefix``.

    Discovered from the live class via ``inspect``, not a hand-maintained list of
    "dangerous method names" — the whole point is that the set of sinks tracks
    the client's actual surface, the same way the original guard's parameter-name
    list was supposed to track callers but didn't.
    """
    sinks: dict[str, list[str]] = {}
    for name, member in inspect.getmembers(MinioClient, predicate=inspect.isfunction):
        params = list(inspect.signature(member).parameters)
        if params and params[0] == "self":
            params = params[1:]
        if _GUARDED_PARAMS & set(params):
            sinks[name] = params
    return sinks


_SINK_PARAMS = _client_sink_params()


def _router_handlers(tree: ast.Module) -> dict[str, ast.AsyncFunctionDef | ast.FunctionDef]:
    return {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and any(
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and isinstance(d.func.value, ast.Name)
            and d.func.value.id == "router"
            for d in node.decorator_list
        )
    }


_CLIENT_FACTORY = "get_minio_client"


def _is_factory_call(node: ast.AST) -> bool:
    """``get_minio_client()`` — the client, built inline."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == _CLIENT_FACTORY
    )


def _client_var_names(func: ast.AST) -> set[str]:
    """Local names bound directly to ``get_minio_client()`` inside ``func``."""
    names = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Assign) and _is_factory_call(node.value):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)
    return names


def _is_client_receiver(node: ast.AST, client_vars: set[str]) -> bool:
    """Whether ``node`` evaluates to the MinIO client, as the receiver of a call.

    Two shapes are equivalent for this guard's purposes and BOTH must be
    recognised:

    * ``minio.file_exists(...)`` — a local bound to the factory's result;
    * ``get_minio_client().file_exists(...)`` — the factory called inline.

    The second is the shape the routes use, because the factory itself blocks:
    on a cold singleton it constructs a ``MinioClient``, whose
    ``_ensure_buckets_exist`` does a round trip per allowed bucket under
    urllib3's ``Retry(total=5)`` × ``Timeout(connect=300, read=300)``, so it has
    to happen inside the offloaded callable rather than one line above it (see
    ``tests/test_event_loop_not_blocked.py``). ⚠️ Keyed only on ``Name``
    receivers this guard read **0 sink calls across all four route modules** the
    moment that fix landed — every one of its per-call assertions would have
    passed vacuously. The two floors below are what caught it; they are the only
    reason this function exists.
    """
    if isinstance(node, ast.Name) and node.id in client_vars:
        return True
    return _is_factory_call(node)


def _is_validated_expr(node: ast.AST, validated: set[str]) -> bool:
    """True if ``node`` is itself a validator call, or a name already known-validated."""
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in _VALIDATOR_CALL_NAMES
    ):
        return True
    return isinstance(node, ast.Name) and node.id in validated


def _validated_names(func: ast.AST) -> set[str]:
    """Names that, somewhere in ``func``, are assigned the result of a validator
    call (directly, or via a simple alias of an already-validated name).

    Not order-sensitive against the sink call — like the guard it replaces, this
    is a structural check ("did the value pass through the choke point on some
    path in this handler"), not a full flow analysis.
    """
    assigns = [
        (node.targets[0].id, node.value)
        for node in ast.walk(func)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    ]
    validated: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, value in assigns:
            if name not in validated and _is_validated_expr(value, validated):
                validated.add(name)
                changed = True
    return validated


def _sink_calls(func: ast.AST, client_vars: set[str]) -> list[ast.Call]:
    """Calls in ``func`` on the MinIO client, into a method that takes an
    ``object_key`` or ``prefix`` argument."""
    return [
        node
        for node in ast.walk(func)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and _is_client_receiver(node.func.value, client_vars)
        and node.func.attr in _SINK_PARAMS
    ]


def _reaches_minio(func: ast.AST) -> bool:
    """Whether the handler gets hold of the client at all, in either shape."""
    return bool(_client_var_names(func)) or any(_is_factory_call(n) for n in ast.walk(func))


def _unguarded_sink_args(func: ast.AsyncFunctionDef | ast.FunctionDef) -> list[str]:
    """Every ``method(param=...)`` reach in ``func`` whose ``object_key``/``prefix``
    argument was not produced by a validator call anywhere in the handler.

    This is the core of the guard, and it is deliberately blind to what the
    *handler's own* parameter is called — it follows the value all the way to the
    keyword/positional slot on the real ``MinioClient`` call, which is named
    ``object_key``/``prefix`` because that is how the client itself is written,
    not because of any convention a route author has to remember.
    """
    if not _reaches_minio(func):
        return []
    client_vars = _client_var_names(func)
    validated = _validated_names(func)
    offenders = []
    for call in _sink_calls(func, client_vars):
        assert isinstance(call.func, ast.Attribute)  # guaranteed by _sink_calls's filter
        method = call.func.attr
        param_names = _SINK_PARAMS[method]
        bound: dict[str, ast.AST] = dict(zip(param_names, call.args))
        for kw in call.keywords:
            if kw.arg is not None:
                bound[kw.arg] = kw.value
        for param in _GUARDED_PARAMS & bound.keys():
            if not _is_validated_expr(bound[param], validated):
                offenders.append(f"{method}({param}=...)")
    return offenders


class TestRoutesUseTheChokePoint:
    """Structural guard: no handler may hand MinIO an unvalidated object_key/prefix.

    An earlier version of this guard matched on a handler's *parameter being
    named* ``object_key``/``prefix`` in *``routes/files.py`` specifically*. A
    verifier defeated it: a new route in ``files.py`` whose parameter was named
    ``key`` reached MinIO unvalidated while all 28 guard tests stayed green.

    This version instead follows the *value*: for every ``@router``-decorated
    handler in every file under ``src/routes/``, it finds each call into a real
    ``MinioClient`` method (discovered via ``inspect.signature``, not a hardcoded
    name list) that accepts ``object_key``/``prefix``, and checks whether the
    value landing in that slot passed through ``validate_object_key`` /
    ``validate_prefix`` / ``checked_object_key`` / ``checked_prefix`` anywhere in
    the handler — regardless of the handler's own parameter name and regardless
    of which route module it lives in.
    """

    @staticmethod
    def _all_handlers() -> dict[Path, dict[str, ast.AsyncFunctionDef | ast.FunctionDef]]:
        return {
            path: _router_handlers(ast.parse(path.read_text(encoding="utf-8")))
            for path in sorted(ROUTES_DIR.glob("*.py"))
        }

    def test_sink_discovery_is_not_vacuous(self) -> None:
        """If ``MinioClient``'s real signatures ever stopped naming
        ``object_key``/``prefix``, the scan would silently check nothing."""
        assert _SINK_PARAMS, "no MinioClient method takes object_key or prefix"
        assert "object_key" in _SINK_PARAMS.get("file_exists", [])
        assert "prefix" in _SINK_PARAMS.get("list_files", [])

    def test_sink_call_discovery_is_not_vacuous(self) -> None:
        """The scan must still FIND the MinIO calls, not just the handlers.

        ``test_sink_discovery_is_not_vacuous`` above proves the *signatures*
        still name ``object_key``/``prefix``; this proves the AST matcher still
        recognises the call SITES. Those are different failure modes, and the
        second one is live: the sink matcher keys on the shape
        ``Call(func=Attribute(value=Name(<client var>)))``, so rewriting a call
        as ``run_in_threadpool(minio.file_exists, bucket, key)`` — passing the
        bound method as a value instead of calling it — hides every sink from
        this guard while every one of its assertions stays green. The routes
        are deliberately written as ``run_in_threadpool(lambda: minio.…(…))``
        so the call survives; ``ast.walk`` descends into a lambda body. If this
        floor ever trips, the offload was rewritten into a shape the guard
        cannot see, and the guard — not the floor — is what needs fixing.
        """
        total = 0
        per_module: dict[str, int] = {}
        for path, handlers in self._all_handlers().items():
            for node in handlers.values():
                n = len(_sink_calls(node, _client_var_names(node)))
                total += n
                per_module[path.name] = per_module.get(path.name, 0) + n
        assert total >= 8, f"only {total} MinIO key/prefix call sites discovered: {per_module}"
        assert per_module.get("files.py", 0) >= 7, per_module

    def test_every_handler_validates_before_reaching_minio(self) -> None:
        offenders: dict[str, list[str]] = {}
        checked_handlers = 0
        for path, handlers in self._all_handlers().items():
            for name, node in handlers.items():
                if _reaches_minio(node):
                    checked_handlers += 1
                bad = _unguarded_sink_args(node)
                if bad:
                    offenders[f"{path.name}::{name}"] = bad
        # Floor: if the scan stops finding MinIO-calling handlers, it stops being a control.
        assert checked_handlers >= 5, (
            f"expected several handlers calling MinIO, only found {checked_handlers}"
        )
        assert not offenders, f"handlers reaching MinIO with an unvalidated key/prefix: {offenders}"

    def test_the_guard_fires_on_a_differently_named_unvalidated_parameter(
        self, tmp_path: Path
    ) -> None:
        """Negative control reproducing the exact defeat a verifier found: a new
        route whose parameter is named ``key``, not ``object_key``, and skips
        validation. The old name-scoped guard stayed green on this; this one must not.
        """
        sample = tmp_path / "sample_leaky.py"
        sample.write_text(
            "@router.get('/y')\n"
            "async def leaky(bucket: str, key: str):\n"
            "    minio = get_minio_client()\n"
            "    return minio.file_exists(bucket, key)\n",
            encoding="utf-8",
        )
        handlers = _router_handlers(ast.parse(sample.read_text(encoding="utf-8")))
        assert "leaky" in handlers
        offenders = _unguarded_sink_args(handlers["leaky"])
        assert offenders, "guard failed to flag an unvalidated key reached under a different name"

    def test_the_guard_does_not_flag_a_validated_differently_named_parameter(
        self, tmp_path: Path
    ) -> None:
        """Control on the control: the same shape, but validated, must stay green —
        the guard follows the value, it does not just reject an unfamiliar name."""
        sample = tmp_path / "sample_safe.py"
        sample.write_text(
            "@router.get('/y')\n"
            "async def safe(bucket: str, key: str):\n"
            "    key = checked_object_key(key)\n"
            "    minio = get_minio_client()\n"
            "    return minio.file_exists(bucket, key)\n",
            encoding="utf-8",
        )
        handlers = _router_handlers(ast.parse(sample.read_text(encoding="utf-8")))
        offenders = _unguarded_sink_args(handlers["safe"])
        assert not offenders, offenders

    def test_the_guard_fires_on_the_inline_factory_receiver(self, tmp_path: Path) -> None:
        """Negative control for the receiver shape the routes now use.

        ``get_minio_client().file_exists(bucket, key)`` reaches MinIO exactly as
        ``minio.file_exists(bucket, key)`` does. A guard that recognised only the
        second read 0 sink calls across every route module once the offload fix
        landed — green, and blind.
        """
        sample = tmp_path / "sample_inline_factory.py"
        sample.write_text(
            "@router.get('/y')\n"
            "async def leaky(bucket: str, key: str):\n"
            "    return await run_in_threadpool(lambda: get_minio_client().file_exists(bucket, key))\n",
            encoding="utf-8",
        )
        handlers = _router_handlers(ast.parse(sample.read_text(encoding="utf-8")))
        assert _reaches_minio(handlers["leaky"]), "the inline factory must count as reaching MinIO"
        offenders = _unguarded_sink_args(handlers["leaky"])
        assert offenders, "guard failed to flag an unvalidated key on an inline-factory receiver"

    def test_the_guard_does_not_flag_a_validated_inline_factory_receiver(
        self, tmp_path: Path
    ) -> None:
        """Control on the control: the same shape, validated, stays green."""
        sample = tmp_path / "sample_inline_factory_ok.py"
        sample.write_text(
            "@router.get('/y')\n"
            "async def safe(bucket: str, key: str):\n"
            "    key = checked_object_key(key)\n"
            "    return await run_in_threadpool(lambda: get_minio_client().file_exists(bucket, key))\n",
            encoding="utf-8",
        )
        handlers = _router_handlers(ast.parse(sample.read_text(encoding="utf-8")))
        assert not _unguarded_sink_args(handlers["safe"])

    def test_the_guard_fires_across_modules_not_just_files_py(self, tmp_path: Path) -> None:
        """The old guard only ever read ``routes/files.py``. A leaky handler in
        any other route module must be caught too."""
        sample = tmp_path / "sample_other_module.py"
        sample.write_text(
            "@router.post('/z')\n"
            "async def register(bucket: str, body):\n"
            "    minio = get_minio_client()\n"
            "    return minio.set_bucket_notification(bucket, body.prefix, arn, events)\n",
            encoding="utf-8",
        )
        handlers = _router_handlers(ast.parse(sample.read_text(encoding="utf-8")))
        offenders = _unguarded_sink_args(handlers["register"])
        assert offenders, "guard failed to flag an unvalidated prefix outside files.py"
