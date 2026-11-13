"""Authentication module - License-based auth only."""

from .middleware import AuthMiddleware
from .models import User

__all__ = ["AuthMiddleware", "User"]
