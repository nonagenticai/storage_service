"""Validation choke point for caller-supplied object keys and prefixes.

``object_key`` reaches this service from a multipart ``Form`` field on upload
and a ``{object_key:path}`` path segment on read/delete; ``prefix`` reaches it
from a query parameter on list and from the JSON body of the two
bucket-notification routes in ``routes/notifications.py``. All of it used to go
straight to MinIO unchecked. Every handler that names an object or a
notification-rule prefix must run the value through :func:`checked_object_key`
/ :func:`checked_prefix` (which wrap :func:`validate_object_key` /
:func:`validate_prefix` and turn a failure into an HTTP 400) before it reaches
:mod:`services.minio_client`, so a key rule cannot be forgotten by the next
route someone adds.

The guard that enforces this (``tests/test_object_keys.py::
TestRoutesUseTheChokePoint``) does not key on a parameter being named
``object_key`` or ``prefix``, or on which module the handler lives in — an
earlier, name-and-file-scoped version of that guard was defeated by exactly
that (a new route with a parameter called ``key``). It instead follows the
*value* into the ``MinioClient`` call and asks whether what reached the
``object_key``/``prefix`` slot there was produced by one of the four functions
below, discovering the dangerous call sites via the real client signatures
rather than a hardcoded method list.

⚠️ Scope, stated plainly: this module validates the *shape* of a key. It does
NOT authorize the caller against it — see ``docs`` in the branch description
and the module note in ``auth/middleware.py``. Tenant authorization needs a
per-caller identity that in-cluster callers do not currently carry.
"""

from __future__ import annotations

from fastapi import HTTPException

# S3 object keys are capped at 1024 *bytes* of UTF-8, not characters. The
# response models (``models.schemas``) already cap ``object_key`` at 1024, so
# without this an over-long upload key stored fine and then blew up rendering
# its own 200 response as a 500.
MAX_OBJECT_KEY_BYTES = 1024

# Control characters are rejected for the same reason the response models
# reject them (``custom_types.SAFE_STRING_PATTERN``): a key containing them
# cannot be echoed back in a response body, and it mangles logs.
#
# ⚠️ Deliberately STRICTER than SAFE_STRING_PATTERN, which permits \t, \n and
# \r. The download route derives a ``Content-Disposition`` header value from
# the key's last segment, so a newline in a key is a response-header
# construction bug, and no legitimate caller has ever sent one — every live
# caller composes keys from ids, dates and sanitized filenames.
_CONTROL_CHARS = frozenset(chr(c) for c in [*range(0x00, 0x20), 0x7F])

# Traversal segments. MinIO stores a key literally, so ``a/../b`` is simply a
# key with that name rather than an escape out of the bucket — but callers
# build keys by joining user-controlled parts (commonpractice's dataset
# connector takes bucket AND key from user-supplied connector config and
# carries its own client-side ``..`` guard), and a key that means one thing to
# the caller and another to a local filesystem cache is a mismatch worth
# refusing at the boundary rather than storing.
_TRAVERSAL_SEGMENTS = frozenset({".", ".."})


class InvalidObjectKeyError(ValueError):
    """Raised when a caller-supplied object key is malformed."""


def _reject_common(value: str, *, label: str) -> None:
    """Checks shared by keys and prefixes."""
    if len(value.encode("utf-8")) > MAX_OBJECT_KEY_BYTES:
        raise InvalidObjectKeyError(f"{label} exceeds {MAX_OBJECT_KEY_BYTES} bytes")

    if any(ch in _CONTROL_CHARS for ch in value):
        raise InvalidObjectKeyError(f"{label} contains control characters")

    if value.startswith("/"):
        raise InvalidObjectKeyError(f"{label} must not start with '/'")

    for segment in value.split("/"):
        if segment in _TRAVERSAL_SEGMENTS:
            raise InvalidObjectKeyError(f"{label} must not contain '.' or '..' path segments")


def validate_object_key(object_key: str) -> str:
    """Return ``object_key`` unchanged, or raise :class:`InvalidObjectKeyError`.

    Deliberately a validator, not a normalizer: silently rewriting a caller's
    key would mean the object lands somewhere other than where the caller was
    told it landed. Empty path *segments* (``a//b``) are allowed on purpose —
    they are legal S3 and a live caller composes keys from parts that can be
    empty; only the checks in :func:`_reject_common` plus a non-empty key are
    enforced.
    """
    if not object_key:
        raise InvalidObjectKeyError("object_key must not be empty")

    _reject_common(object_key, label="object_key")
    return object_key


def validate_prefix(prefix: str) -> str:
    """Validate a list ``prefix``. Same rules, except empty is allowed.

    An empty prefix means "list the whole bucket", which existing callers rely
    on; it is not made an error here.
    """
    if not prefix:
        return prefix

    _reject_common(prefix, label="prefix")
    return prefix


def checked_object_key(object_key: str) -> str:
    """Validate a caller-supplied object key, or raise HTTP 400.

    The single choke point every route handler must call before it lets an
    ``object_key`` reach :mod:`services.minio_client` — the AST guard in
    ``tests/test_object_keys.py`` checks for exactly this, by following the
    value into the MinIO client call rather than by the caller's parameter
    name, so it does not matter what a new route calls its own variable.
    """
    try:
        return validate_object_key(object_key)
    except InvalidObjectKeyError as e:
        raise HTTPException(status_code=400, detail=str(e))


def checked_prefix(prefix: str) -> str:
    """Validate a caller-supplied prefix (list filter or notification-rule
    prefix), or raise HTTP 400. See :func:`checked_object_key`."""
    try:
        return validate_prefix(prefix)
    except InvalidObjectKeyError as e:
        raise HTTPException(status_code=400, detail=str(e))
