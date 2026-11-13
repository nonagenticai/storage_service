"""Bucket-notification registration endpoints for self-serve storage connectors.

Common Practice's ``commonpractice`` backend calls these (in-cluster, trusted-network) when a
user creates or deletes a ``storage`` connector. Registering auto-provisions the dataset
bucket (on demand, ``cp-*`` convention) and adds a MinIO bucket-notification rule pointing at
the ONE shared, pre-provisioned ``notify_webhook`` target — so object changes push to
commonpractice and the connector refreshes live, with no operator ``mc`` step.

MinIO webhook *targets* are static (a new target needs a server restart), so the design shares
one target and varies only the per-bucket *rules* — which ``svc-storage-api`` can set with its
``s3:*`` grant on ``cp-*`` (verified live). Mounted under ``/api/buckets`` so it inherits the
existing protected-prefix auth (license token, or in-cluster trusted-network pass-through).
"""

import logging

from fastapi import APIRouter, HTTPException
from starlette.concurrency import run_in_threadpool

from config import get_settings
from models.schemas import (
    NotificationDeregisterResponse,
    NotificationListResponse,
    NotificationRegisterResponse,
    NotificationRuleOut,
    NotificationRuleRequest,
)
from routes.responses import (
    AUTH_RESPONSES,
    STORAGE_ERROR_RESPONSES,
    VALIDATION_RESPONSES,
)
from services.minio_client import get_minio_client
from services.object_keys import checked_prefix

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/buckets", tags=["Notifications"])

# ⚠️ Offloaded with the factory INSIDE the callable, for the reasons spelled out
# at the top of ``routes/files.py``. These are admin-ish, low-traffic routes, but
# "low traffic" is not a defence: ONE call on the event loop stops the process
# answering ``/health/live``, and a cold ``get_minio_client()`` against an
# unreachable MinIO blocks for hours, not seconds.


def _require_dataset_bucket(bucket: str) -> None:
    """Reject buckets outside the dataset-connector convention.

    Only ``cp-*`` buckets are covered by the wildcard IAM grant and may be auto-created +
    have rules registered. Anything else is an operator-managed bucket — never touch it here.
    """
    prefix = get_settings().dataset_bucket_prefix
    if not bucket.startswith(prefix):
        raise HTTPException(
            status_code=400,
            detail=f"bucket '{bucket}' must start with '{prefix}' to register notifications",
        )


@router.post(
    "/{bucket}/notifications/register",
    operation_id="notifications_register",
    summary="Register a dataset bucket-notification rule",
    response_model=NotificationRegisterResponse,
    status_code=201,
    responses={**AUTH_RESPONSES, **VALIDATION_RESPONSES, **STORAGE_ERROR_RESPONSES},
)
async def register_notification(
    bucket: str, body: NotificationRuleRequest
) -> NotificationRegisterResponse:
    """Ensure the dataset bucket exists and register/replace its notification rule.

    Idempotent on (bucket, prefix): re-registering the same prefix replaces the rule.
    """
    _require_dataset_bucket(bucket)
    prefix = checked_prefix(body.prefix)
    settings = get_settings()
    try:
        await run_in_threadpool(lambda: get_minio_client().ensure_bucket(bucket))
        result = await run_in_threadpool(
            lambda: get_minio_client().set_bucket_notification(
                bucket,
                prefix,
                settings.shared_notification_arn,
                settings.notification_event_list,
            )
        )
        return NotificationRegisterResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Register notification failed for {bucket}: {e}")
        raise HTTPException(status_code=500, detail=f"Register notification failed: {e}")


@router.delete(
    "/{bucket}/notifications/register",
    operation_id="notifications_deregister",
    summary="Deregister a dataset bucket-notification rule",
    response_model=NotificationDeregisterResponse,
    responses={**AUTH_RESPONSES, **VALIDATION_RESPONSES, **STORAGE_ERROR_RESPONSES},
)
async def deregister_notification(
    bucket: str, body: NotificationRuleRequest
) -> NotificationDeregisterResponse:
    """Remove the notification rule for (bucket, prefix). Idempotent (no-op if absent)."""
    _require_dataset_bucket(bucket)
    prefix = checked_prefix(body.prefix)
    try:
        if not await run_in_threadpool(lambda: get_minio_client().bucket_exists(bucket)):
            # Nothing to remove — treat as already-deregistered.
            return NotificationDeregisterResponse(
                bucket=bucket, prefix=prefix, config_id="", removed=0, rules=0
            )
        result = await run_in_threadpool(
            lambda: get_minio_client().remove_bucket_notification(bucket, prefix)
        )
        return NotificationDeregisterResponse(**result)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Deregister notification failed for {bucket}: {e}")
        raise HTTPException(status_code=500, detail=f"Deregister notification failed: {e}")


@router.get(
    "/{bucket}/notifications",
    operation_id="notifications_list",
    summary="List a dataset bucket's live notification rules",
    response_model=NotificationListResponse,
    responses={**AUTH_RESPONSES, **VALIDATION_RESPONSES, **STORAGE_ERROR_RESPONSES},
)
async def list_notifications(bucket: str) -> NotificationListResponse:
    """Read the bucket's live MinIO notification rules (ground truth for drift detection).

    Read-only. A bucket that does not exist (or has no rules) returns an empty list, never a
    404 — the caller treats "no rule" uniformly whether the bucket was never provisioned or its
    rule was removed out-of-band.
    """
    _require_dataset_bucket(bucket)
    try:
        rules = await run_in_threadpool(lambda: get_minio_client().get_bucket_notifications(bucket))
        return NotificationListResponse(
            bucket=bucket,
            rules=[NotificationRuleOut(**r) for r in rules],
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"List notifications failed for {bucket}: {e}")
        raise HTTPException(status_code=500, detail=f"List notifications failed: {e}")
