"""
Health check endpoints for storage service.
"""

import logging

from fastapi import APIRouter, Response
from starlette.concurrency import run_in_threadpool

from config import get_settings
from models.schemas import HealthComponentStatus, HealthResponse
from routes.responses import HEALTH_RESPONSES
from services.minio_client import get_minio_client
from services.virus_scanner import get_virus_scanner

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Health"])

# ⚠️ ``minio.health_check()`` and ``scanner.health_check()`` are both blocking
# socket I/O, so they are offloaded for the same reason as in ``routes/files.py``:
# on the event loop they stop the process serving anything, ``/health/live``
# included. ``scanner.health_check()`` is the sharper edge — it is a clamd
# ``PING`` on a socket whose timeout is ``clamav_timeout`` (30 s), so against a
# BLACKHOLED clamd every probe of this endpoint froze the loop for 30 s. That is
# the same defect as the synchronous upload scan, reached through the probe
# rather than through a request, and it fires on a timer without any traffic.
#
# The ``lambda:`` form (rather than passing the bound method) keeps the call
# visible to the AST guards in ``tests/test_event_loop_not_blocked.py`` and
# ``tests/test_object_keys.py``, which match on a call, not on a reference.
#
# ⚠️ The FACTORY call is inside the lambda too, not hoisted above it. That is
# the sharpest edge on this path and it is not cosmetic. ``get_minio_client()``
# is not a cheap accessor on a cold process: when the singleton is ``None`` it
# runs ``MinioClient()``, which calls ``_ensure_buckets_exist`` — one
# ``bucket_exists``/``make_bucket`` round trip per allowed bucket. minio-py
# passes no ``http_client``, so urllib3's defaults apply: ``Retry(total=5)``
# over ``Timeout(connect=300, read=300)``. Against a blackholed MinIO that is
# hours of dead loop, per bucket.
#
# And the singleton IS ``None`` in exactly the situation that matters.
# ``_ensure_buckets_exist`` catches only ``S3Error``; a connect failure raises
# ``urllib3.exceptions.MaxRetryError``, which escapes ``MinioClient.__init__``,
# so the assignment in ``get_minio_client`` never completes and the global stays
# ``None``. ``main.lifespan`` swallows that (``except Exception``, log only) and
# starts the app anyway — deliberately, so a MinIO blip does not stop the pod
# booting. The consequence is that on a pod that started during a MinIO outage
# the FIRST ``/health/ready`` tick pays the full construction cost ON THE LOOP,
# ``/health/live`` stops being answered, kubelet fails it three times at 20 s
# and SIGKILLs the pod — which then restarts into the same unreachable MinIO.
# That is this PR's own incident's restart path, and hoisting the factory one
# line up is all it takes to put it back.


@router.get(
    "/health",
    operation_id="health_check",
    summary="Service health summary",
    response_model=HealthResponse,
)
async def health_check() -> HealthResponse:
    """
    Full health check including all components.

    Returns overall status and individual component status.
    """
    settings = get_settings()
    components = {}

    try:
        healthy, message, latency = await run_in_threadpool(
            lambda: get_minio_client().health_check()
        )
        components["minio"] = HealthComponentStatus(
            healthy=healthy,
            message=message,
            latency_ms=latency,
        )
    except Exception as e:
        components["minio"] = HealthComponentStatus(
            healthy=False,
            message=f"MinIO check failed: {e}",
        )

    if settings.enable_virus_scanning:
        try:
            healthy, message, latency = await run_in_threadpool(
                lambda: get_virus_scanner().health_check()
            )
            components["clamav"] = HealthComponentStatus(
                healthy=healthy,
                message=message,
                latency_ms=latency,
            )
        except Exception as e:
            components["clamav"] = HealthComponentStatus(
                healthy=False,
                message=f"ClamAV check failed: {e}",
            )

    all_healthy = all(c.healthy for c in components.values())
    minio_healthy = components.get("minio", HealthComponentStatus(healthy=False)).healthy

    if all_healthy:
        status = "healthy"
    elif minio_healthy:
        status = "degraded"
    else:
        status = "unhealthy"

    return HealthResponse(
        status=status,
        service=settings.service_name,
        version=settings.version,
        components=components,
    )


@router.get(
    "/health/live",
    operation_id="health_live",
    summary="Liveness probe",
)
async def liveness() -> dict:
    """
    Kubernetes liveness probe.

    Returns 200 if the service is running.
    """
    return {"status": "alive"}


@router.get(
    "/health/ready",
    operation_id="health_ready",
    summary="Readiness probe",
    responses=HEALTH_RESPONSES,
)
async def readiness(response: Response) -> dict:
    """
    Kubernetes readiness probe.

    Returns 200 only if MinIO is accessible.

    ⚠️ DELIBERATELY does NOT consider the virus scanner, even though a dead
    clamd means every upload is guaranteed to 503. Readiness answers "should
    the Service route to THIS replica", and it can only ever help when the
    fault is per-replica so that traffic has a healthy peer to land on. clamd
    is a SINGLE-replica Deployment shared by every storage-api pod, so a clamd
    outage is perfectly correlated: gating readiness on it would take every
    replica out of the Service at once, leaving the Service with zero
    endpoints. The observable result would be that download, metadata, list
    and delete — none of which touch the scanner at all — go from working to
    connection-refused, and that uploads answer an unattributable transport
    error instead of the deliberate ``503 Virus scanning is unavailable;
    upload refused`` from #32. That is strictly worse on both counts: it
    widens the blast radius from one endpoint to all of them, and it destroys
    the only signal that names the cause.

    The right instruments for a shared-dependency outage are the ones that
    already exist: ``GET /health`` reports ``status: "degraded"`` with the
    ``clamav`` component unhealthy, and the upload route's 503 is a
    per-request, attributable refusal. Alert on those; do not un-Ready the pod.
    """
    try:
        healthy, message, _ = await run_in_threadpool(lambda: get_minio_client().health_check())
        if healthy:
            return {"status": "ready"}
        else:
            response.status_code = 503
            return {"status": "not_ready", "reason": message}
    except Exception as e:
        response.status_code = 503
        return {"status": "not_ready", "reason": str(e)}
