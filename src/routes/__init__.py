"""Routes package for storage service."""

from routes.buckets import router as buckets_router
from routes.files import router as files_router
from routes.health import router as health_router
from routes.notifications import router as notifications_router

__all__ = ["health_router", "files_router", "buckets_router", "notifications_router"]
