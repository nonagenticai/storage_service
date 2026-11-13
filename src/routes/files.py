"""
File operation endpoints for storage service.

All file uploads/downloads are proxied through this service.
MinIO credentials are ONLY known to this service.
"""

import io
import logging
from urllib.parse import quote

from fastapi import APIRouter, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.responses import StreamingResponse
from starlette.concurrency import run_in_threadpool

from config import get_settings
from models.schemas import (
    FileExistsResponse,
    FileInfo,
    FileListResponse,
    FileMetadataResponse,
    FileUploadResponse,
)
from routes.responses import (
    AUTH_AND_NOT_FOUND,
    AUTH_RESPONSES,
    STORAGE_ERROR_RESPONSES,
    VALIDATION_RESPONSES,
    ErrorResponse,
)
from services.minio_client import get_minio_client
from services.object_keys import checked_object_key, checked_prefix
from services.virus_scanner import get_virus_scanner

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/files", tags=["Files"])

# ⚠️ EVERY blocking call in this module is offloaded with ``run_in_threadpool``.
#
# ``VirusScanner.scan_bytes`` and the whole of ``MinioClient`` are synchronous
# socket I/O. Called directly from an ``async def`` handler they run ON the
# event loop, so one slow call stops the process from serving ANYTHING —
# including ``/health/live``. That is not a theoretical bound: a blackholed
# clamd costs ``clamav_timeout`` (30 s) × ``max_retries`` (3) plus the
# ``time.sleep(1 * (attempt + 1))`` backoff between them, i.e. ~93 s of a dead
# loop per upload, which is far past any sane ``livenessProbe`` and turns
# "uploads answer 503" (the deliberate fail-closed trade from #32) into
# "the pod CrashLoops". A large ``put_object``/``get_object`` stalls the loop
# the same way, just without a timeout to bound it.
#
# ⚠️ The offloaded call is written as ``lambda: get_minio_client().method(...)``
# rather than the shorter ``run_in_threadpool(minio.method, ...)`` ON PURPOSE.
# The object-key choke-point guard (``tests/test_object_keys.py::
# TestRoutesUseTheChokePoint``) finds a MinIO sink by the AST shape
# ``Call(func=Attribute(value=<client expression>)))``; passing the bound method
# as a value instead of calling it would hide every sink from the guard and
# silently disarm it while all its tests stayed green. ``ast.walk`` descends
# into a lambda body, so this form keeps the guard armed. There is a floor
# assertion on the number of discovered sink calls to catch a future refactor
# that breaks this again.
#
# ⚠️ The FACTORY call belongs inside the lambda, not on the line above it.
# ``get_minio_client()`` is not a cheap accessor: on a cold singleton it runs
# ``MinioClient()``, whose ``_ensure_buckets_exist`` does one round trip per
# allowed bucket under urllib3's defaults (``Retry(total=5)``,
# ``Timeout(connect=300, read=300)`` — minio-py is given no ``http_client``).
# The singleton is cold in precisely the case that matters: a connect failure
# raises ``MaxRetryError``, which ``_ensure_buckets_exist`` does not catch
# (only ``S3Error``), so ``__init__`` escapes, the global is never assigned,
# and ``main.lifespan`` logs and starts anyway. Hoisting the factory out of the
# lambda therefore puts hours of blocking socket I/O back on the event loop and
# reproduces this PR's own incident's restart path. The AST guard in
# ``tests/test_event_loop_not_blocked.py`` now fires on that shape.

# An invalid object_key / prefix is refused with 400 on every route that takes
# one, so the read routes declare it too — previously only the upload route
# could answer 400 at all.
_INVALID_KEY_RESPONSE: dict[int | str, dict] = {
    400: {"description": "Invalid bucket or object key", "model": ErrorResponse},
}

_FILES_UPLOAD_RESPONSES: dict[int | str, dict] = {
    **AUTH_RESPONSES,
    **VALIDATION_RESPONSES,
    **STORAGE_ERROR_RESPONSES,
    # Virus scanning fails closed: no verdict, no upload.
    503: {"description": "Virus scanning unavailable; upload refused", "model": ErrorResponse},
}

_FILES_READ_RESPONSES: dict[int | str, dict] = {
    **AUTH_AND_NOT_FOUND,
    **_INVALID_KEY_RESPONSE,
    **STORAGE_ERROR_RESPONSES,
}


def _content_disposition(filename: str) -> str:
    """Build an ``attachment`` Content-Disposition that a caller cannot extend.

    The header used to be built as ``f'attachment; filename="{filename}"'`` from
    the object key's last segment, with nothing escaped. ``object_keys`` rejects
    control characters — so there is no CRLF header-splitting here — but it does
    NOT reject ``"``, and neither does ``SAFE_STRING_PATTERN``. A key such as
    ``a";x="b`` therefore closed the quoted-string early and injected an extra
    header PARAMETER, which is a parser-dependent way to influence how a client
    or an intermediary names and treats the downloaded file.

    Rejecting ``"`` in object keys would be the wrong fix: it is a legal S3 key
    byte, this is a read path, and any such object already in a bucket would
    become undownloadable. The header is what was malformed, so the header is
    what is fixed.

    Two parameters are emitted, per RFC 6266:

    * ``filename=`` — an ASCII-only quoted-string. Backslash and ``"`` are
      backslash-escaped (RFC 9110 quoted-string), so a ``"`` in the key stays
      one character of the value instead of terminating it. Non-ASCII is
      dropped here because Starlette encodes header values as latin-1, and a
      UTF-8 key (which ``validate_object_key`` explicitly allows, e.g.
      ``unicode-Ω-ключ.bin``) would otherwise raise on the way out.
    * ``filename*=UTF-8''…`` — RFC 5987 percent-encoding, which carries the
      full name losslessly for every client that understands it. ``quote`` with
      ``safe=""`` leaves no character that could end the parameter.
    """
    ascii_name = filename.encode("ascii", "ignore").decode("ascii")
    # ⚠️ Control characters are dropped HERE, not relied on being absent.
    # ``\r`` and ``\n`` in a header value are a response-splitting primitive, and
    # ``.encode("ascii", "ignore")`` above does not remove them — they are ASCII.
    # Today they cannot arrive: ``validate_object_key`` rejects every byte below
    # 0x20 and 0x7F, so this filter removes nothing on any reachable input (a
    # test asserts that non-vacuity holds by feeding it a raw CRLF name, which is
    # the only way to reach this line with one). But the safety of THIS function
    # would otherwise be a property of a validator in a different module, one
    # refactor away from being untrue — and the failure mode is header injection,
    # not a bad filename. So it is enforced where the header is built.
    ascii_name = "".join(c for c in ascii_name if " " <= c < "\x7f")
    escaped = ascii_name.replace("\\", "\\\\").replace('"', '\\"')
    # A key may legitimately end in "/" (empty last segment), and an all-non-ASCII
    # name reduces to "" above; neither may produce a nameless attachment.
    if not escaped:
        escaped = "download"
    disposition = f'attachment; filename="{escaped}"'
    if filename:
        # Omitted rather than emitted empty: an empty ``filename*`` is worse
        # than none, since a client that prefers it would end up with no name.
        disposition += f"; filename*=UTF-8''{quote(filename, safe='')}"
    return disposition


async def validate_bucket(bucket: str) -> None:
    """Validate bucket is in allowed list or exists in MinIO."""
    settings = get_settings()
    if bucket in settings.allowed_bucket_list:
        return
    if await run_in_threadpool(lambda: get_minio_client().bucket_exists(bucket)):
        return
    raise HTTPException(
        status_code=400,
        detail=f"Bucket '{bucket}' not found",
    )


@router.post(
    "/upload",
    operation_id="files_upload",
    summary="Upload a file to a bucket",
    response_model=FileUploadResponse,
    responses=_FILES_UPLOAD_RESPONSES,
)
async def upload_file(
    bucket: str = Form(...),
    object_key: str = Form(...),
    file: UploadFile = File(...),
    content_type: str | None = Form(None),
) -> FileUploadResponse:
    """
    Upload a file to storage with optional virus scanning.

    - Validates bucket is in allowed list
    - Scans file for viruses (if ClamAV enabled)
    - Uploads to MinIO
    """
    await validate_bucket(bucket)
    object_key = checked_object_key(object_key)
    settings = get_settings()

    # Read file content
    file_data = await file.read()
    file_size = len(file_data)

    # Check size limit
    if file_size > settings.max_upload_size_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Max size: {settings.max_upload_size_mb}MB",
        )

    # Determine content type
    actual_content_type = content_type or file.content_type or "application/octet-stream"

    # Virus scan (if enabled). This fails CLOSED.
    #
    # Every failure mode of the scanner — daemon unreachable, retries
    # exhausted, malformed reply — yields ``is_infected=False``, because a
    # scanner that never ran cannot report an infection. Treating that as
    # permission to store the file meant an EICAR sample was accepted with
    # HTTP 200 while ClamAV was down. ``ScanResult.completed`` is the only
    # field that separates "scanned and clean" from "never scanned", so the
    # upload is refused unless a verdict actually came back, and
    # ``virus_scanned`` is set to True only on that same condition.
    virus_scanned = False
    scan_result: str | None = None

    if settings.enable_virus_scanning:
        try:
            # Off the event loop: see the module note. ``scan_bytes`` blocks for
            # up to ~93 s against a hung clamd, and the fail-closed contract is
            # unchanged — only WHERE the wait happens moves.
            result = await run_in_threadpool(
                lambda: get_virus_scanner().scan_bytes(file_data, filename=object_key)
            )
        except Exception as e:
            logger.error(f"Virus scan raised, refusing upload of {object_key}: {e}")
            raise HTTPException(
                status_code=503,
                detail="Virus scanning is unavailable; upload refused",
            )

        if not result.completed:
            logger.error(f"Virus scan did not complete for {object_key}: {result.error}")
            raise HTTPException(
                status_code=503,
                detail="Virus scanning is unavailable; upload refused",
            )

        if result.is_infected:
            logger.warning(f"Virus detected in upload: {object_key} - {result.virus_name}")
            raise HTTPException(
                status_code=400,
                detail=f"Virus detected: {result.virus_name}",
            )

        virus_scanned = True
        scan_result = "clean"

    # Upload to MinIO
    try:
        upload_result = await run_in_threadpool(
            lambda: get_minio_client().upload_file(
                bucket=bucket,
                object_key=object_key,
                data=io.BytesIO(file_data),
                size=file_size,
                content_type=actual_content_type,
            )
        )
    except Exception as e:
        logger.error(f"Upload failed: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {e}")

    return FileUploadResponse(
        bucket=bucket,
        object_key=object_key,
        size=file_size,
        etag=upload_result["etag"],
        content_type=actual_content_type,
        virus_scanned=virus_scanned,
        scan_result=scan_result,
    )


@router.get(
    "/{bucket}/{object_key:path}/exists",
    operation_id="files_exists",
    summary="Check if an object exists",
    response_model=FileExistsResponse,
    responses={**AUTH_RESPONSES, **_INVALID_KEY_RESPONSE, **STORAGE_ERROR_RESPONSES},
)
async def check_file_exists(bucket: str, object_key: str) -> FileExistsResponse:
    """
    Check if a file exists in storage.
    """
    await validate_bucket(bucket)
    object_key = checked_object_key(object_key)

    try:
        exists = await run_in_threadpool(lambda: get_minio_client().file_exists(bucket, object_key))

        return FileExistsResponse(
            bucket=bucket,
            object_key=object_key,
            exists=exists,
        )

    except Exception as e:
        logger.error(f"Exists check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Check failed: {e}")


@router.get(
    "/{bucket}/{object_key:path}/metadata",
    operation_id="files_metadata",
    summary="Get object metadata",
    response_model=FileMetadataResponse,
    responses=_FILES_READ_RESPONSES,
)
async def get_file_metadata(bucket: str, object_key: str) -> FileMetadataResponse:
    """
    Get file metadata from storage.
    """
    await validate_bucket(bucket)
    object_key = checked_object_key(object_key)

    try:
        metadata = await run_in_threadpool(
            lambda: get_minio_client().get_file_metadata(bucket, object_key)
        )

        if metadata is None:
            raise HTTPException(status_code=404, detail="File not found")

        return FileMetadataResponse(
            bucket=metadata["bucket"],
            object_key=metadata["object_key"],
            size=metadata["size"],
            last_modified=metadata["last_modified"],
            etag=metadata["etag"],
            content_type=metadata["content_type"],
            metadata=metadata.get("metadata", {}),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Metadata fetch failed: {e}")
        raise HTTPException(status_code=500, detail=f"Metadata fetch failed: {e}")


@router.get(
    "/{bucket}/{object_key:path}",
    operation_id="files_download",
    summary="Download an object",
    responses=_FILES_READ_RESPONSES,
)
async def download_file(bucket: str, object_key: str) -> StreamingResponse:
    """
    Download a file from storage.

    Returns the file content as a streaming response.
    """
    await validate_bucket(bucket)
    object_key = checked_object_key(object_key)

    try:
        # Check if file exists
        if not await run_in_threadpool(lambda: get_minio_client().file_exists(bucket, object_key)):
            raise HTTPException(status_code=404, detail="File not found")

        # Stream the object straight through in chunks — never buffer the whole
        # file in memory. Large objects (e.g. a 146 MB audiobook) would OOM the
        # pod on a buffered read; streaming keeps peak memory bounded by the
        # chunk size regardless of file size.
        # Only the initial ``get_object`` is offloaded here; the body itself is
        # a SYNC iterator, which Starlette already runs via ``iterate_in_threadpool``.
        stream, metadata = await run_in_threadpool(
            lambda: get_minio_client().stream_file(bucket, object_key)
        )
        content_type = metadata.get("content_type", "application/octet-stream")

        # Extract filename from object_key for Content-Disposition. It is
        # caller-controlled, so it is escaped rather than interpolated raw —
        # see ``_content_disposition``.
        filename = object_key.split("/")[-1]

        headers = {"Content-Disposition": _content_disposition(filename)}
        content_length = metadata.get("content_length")
        if content_length:
            headers["Content-Length"] = str(content_length)

        return StreamingResponse(stream, media_type=content_type, headers=headers)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download failed: {e}")
        raise HTTPException(status_code=500, detail=f"Download failed: {e}")


@router.delete(
    "/{bucket}/{object_key:path}",
    operation_id="files_delete",
    summary="Delete an object",
    status_code=204,
    responses=_FILES_READ_RESPONSES,
)
async def delete_file(bucket: str, object_key: str) -> Response:
    """
    Delete a file from storage.

    Returns 204 No Content on success.
    """
    await validate_bucket(bucket)
    object_key = checked_object_key(object_key)

    try:
        # Check if file exists first
        if not await run_in_threadpool(lambda: get_minio_client().file_exists(bucket, object_key)):
            raise HTTPException(status_code=404, detail="File not found")

        await run_in_threadpool(lambda: get_minio_client().delete_file(bucket, object_key))
        return Response(status_code=204)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete failed: {e}")
        raise HTTPException(status_code=500, detail=f"Delete failed: {e}")


@router.get(
    "/{bucket}",
    operation_id="files_list",
    summary="List objects in a bucket",
    response_model=FileListResponse,
    responses={**AUTH_RESPONSES, **_INVALID_KEY_RESPONSE, **STORAGE_ERROR_RESPONSES},
)
async def list_files(
    bucket: str,
    prefix: str = Query(default="", description="Object key prefix filter"),
    recursive: bool = Query(default=True, description="Include subdirectories"),
    max_keys: int = Query(default=1000, le=10000, description="Maximum results"),
) -> FileListResponse:
    """
    List files in a bucket with optional prefix filter.
    """
    await validate_bucket(bucket)
    prefix = checked_prefix(prefix)

    try:
        files = await run_in_threadpool(
            lambda: get_minio_client().list_files(
                bucket=bucket,
                prefix=prefix,
                recursive=recursive,
                max_keys=max_keys,
            )
        )

        file_infos = [
            FileInfo(
                object_key=f["object_key"],
                size=f["size"],
                last_modified=f["last_modified"],
                etag=f["etag"],
            )
            for f in files
        ]

        return FileListResponse(
            bucket=bucket,
            prefix=prefix,
            files=file_infos,
            count=len(file_infos),
        )

    except Exception as e:
        logger.error(f"List files failed: {e}")
        raise HTTPException(status_code=500, detail=f"List failed: {e}")
