"""
Bucket management endpoints for storage service.

Allows dynamic creation/deletion of MinIO buckets.
Protected buckets cannot be deleted via API.
"""

import logging

from fastapi import APIRouter, HTTPException, Query
from starlette.concurrency import run_in_threadpool

from config import get_settings
from models.schemas import (
    BucketCreateRequest,
    BucketCreateResponse,
    BucketDeleteResponse,
    BucketInfo,
    BucketListResponse,
)
from routes.responses import (
    AUTH_AND_NOT_FOUND,
    AUTH_RESPONSES,
    CONFLICT_RESPONSES,
    STORAGE_ERROR_RESPONSES,
)
from services.minio_client import get_minio_client

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/buckets", tags=["Buckets"])

# ⚠️ Every MinIO call here is offloaded, and the factory call is INSIDE the
# offloaded callable — see the long note in ``routes/files.py`` for why the
# factory in particular is the dangerous one (a cold singleton means a full
# ``MinioClient()`` construction, i.e. one bucket round trip per allowed bucket
# under ``Retry(total=5)`` × ``Timeout(connect=300, read=300)``).
#
# ⚠️ ``delete_bucket(force=True)`` is the sharpest call in this module and it is
# NOT the metadata-only operation the route name suggests: it pages the bucket
# with ``list_objects(recursive=True)`` and issues one ``remove_object`` per
# object, serially, with no bound. On the event loop that is an outage of every
# other endpoint for as long as the bucket takes to empty — proportional to the
# object count, so an operator emptying a large bucket takes the pod down.


@router.get(
    "",
    operation_id="buckets_list",
    summary="List all buckets",
    response_model=BucketListResponse,
    responses={**AUTH_RESPONSES, **STORAGE_ERROR_RESPONSES},
)
async def list_buckets() -> BucketListResponse:
    """List all buckets."""
    try:
        buckets = await run_in_threadpool(lambda: get_minio_client().list_buckets())
        bucket_infos = [
            BucketInfo(name=b["name"], creation_date=b.get("creation_date")) for b in buckets
        ]
        return BucketListResponse(buckets=bucket_infos, count=len(bucket_infos))
    except Exception as e:
        logger.error(f"List buckets failed: {e}")
        raise HTTPException(status_code=500, detail=f"List buckets failed: {e}")


@router.post(
    "",
    operation_id="buckets_create",
    summary="Create a new bucket",
    response_model=BucketCreateResponse,
    status_code=201,
    responses={**AUTH_RESPONSES, **CONFLICT_RESPONSES, **STORAGE_ERROR_RESPONSES},
)
async def create_bucket(body: BucketCreateRequest) -> BucketCreateResponse:
    """Create a new bucket."""
    try:
        result = await run_in_threadpool(lambda: get_minio_client().create_bucket(body.name))

        if not result["created"]:
            raise HTTPException(status_code=409, detail=f"Bucket '{body.name}' already exists")

        return BucketCreateResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Create bucket failed: {e}")
        raise HTTPException(status_code=500, detail=f"Create bucket failed: {e}")


@router.get(
    "/{name}",
    operation_id="buckets_get",
    summary="Get bucket info",
    response_model=BucketInfo,
    responses={**AUTH_AND_NOT_FOUND, **STORAGE_ERROR_RESPONSES},
)
async def get_bucket(name: str) -> BucketInfo:
    """Check if a bucket exists and return its info."""
    try:
        if not await run_in_threadpool(lambda: get_minio_client().bucket_exists(name)):
            raise HTTPException(status_code=404, detail=f"Bucket '{name}' not found")

        # Get creation date from list_buckets
        buckets = await run_in_threadpool(lambda: get_minio_client().list_buckets())
        for b in buckets:
            if b["name"] == name:
                return BucketInfo(name=name, creation_date=b.get("creation_date"))

        return BucketInfo(name=name)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Get bucket failed: {e}")
        raise HTTPException(status_code=500, detail=f"Get bucket failed: {e}")


@router.delete(
    "/{name}",
    operation_id="buckets_delete",
    summary="Delete a bucket",
    response_model=BucketDeleteResponse,
    responses={
        **AUTH_AND_NOT_FOUND,
        **CONFLICT_RESPONSES,
        **STORAGE_ERROR_RESPONSES,
        403: {"description": "Bucket is protected"},
    },
)
async def delete_bucket(
    name: str,
    force: bool = Query(default=False, description="Force delete non-empty bucket"),
) -> BucketDeleteResponse:
    """Delete a bucket. Protected buckets cannot be deleted."""
    settings = get_settings()

    # Prefix-aware, not an exact-string match. The exact list could not cover
    # the ``cp-<tenant>-…`` buckets this service itself mints, nor the
    # ``*-backups`` family; see ``Settings._PROTECTED_BUCKET_PATTERNS``.
    # ⚠️ This check must stay ABOVE the try block: ``force=true`` deletes every
    # object before removing the bucket, so a guard that ran afterwards would
    # guard nothing.
    if settings.is_protected_bucket(name):
        raise HTTPException(
            status_code=403, detail=f"Bucket '{name}' is protected and cannot be deleted"
        )

    try:
        result = await run_in_threadpool(
            lambda: get_minio_client().delete_bucket(name, force=force)
        )
        return BucketDeleteResponse(**result)
    except ValueError as e:
        msg = str(e)
        if "does not exist" in msg:
            raise HTTPException(status_code=404, detail=msg)
        if "not empty" in msg:
            raise HTTPException(status_code=409, detail=msg)
        raise HTTPException(status_code=400, detail=msg)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Delete bucket failed: {e}")
        raise HTTPException(status_code=500, detail=f"Delete bucket failed: {e}")
