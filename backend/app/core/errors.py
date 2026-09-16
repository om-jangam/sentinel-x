"""Application error hierarchy.

Framework-free on purpose: domain and application layers raise these, and the HTTP layer
(`core.http.problems`) renders them as RFC 9457 problem documents.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, ClassVar


class AppError(Exception):
    status: ClassVar[int] = 500
    type_slug: ClassVar[str] = "internal-error"
    title: ClassVar[str] = "Internal server error"

    def __init__(
        self,
        detail: str | None = None,
        *,
        errors: Sequence[Mapping[str, Any]] = (),
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.detail = detail or self.title
        self.errors = [dict(e) for e in errors]
        self.headers = dict(headers or {})
        super().__init__(self.detail)


class NotFoundError(AppError):
    status = 404
    type_slug = "not-found"
    title = "Resource not found"


class ConflictError(AppError):
    status = 409
    type_slug = "conflict"
    title = "Conflict"


class ValidationFailedError(AppError):
    status = 422
    type_slug = "validation-failed"
    title = "Validation failed"


class AuthenticationError(AppError):
    status = 401
    type_slug = "authentication-required"
    title = "Authentication required"

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(detail, headers={"WWW-Authenticate": "Bearer"})


class PermissionDeniedError(AppError):
    status = 403
    type_slug = "insufficient-permission"
    title = "Insufficient permission"

    def __init__(self, permission: str, detail: str | None = None) -> None:
        self.permission = permission
        super().__init__(detail or f"Requires '{permission}'")


class PayloadTooLargeError(AppError):
    status = 413
    type_slug = "payload-too-large"
    title = "Payload too large"


class ServiceUnavailableError(AppError):
    status = 503
    type_slug = "service-unavailable"
    title = "Service unavailable"


class RateLimitedError(AppError):
    status = 429
    type_slug = "rate-limited"
    title = "Too many requests"

    def __init__(self, retry_after_seconds: int) -> None:
        self.retry_after_seconds = max(1, retry_after_seconds)
        super().__init__(
            f"Retry after {self.retry_after_seconds}s",
            headers={"Retry-After": str(self.retry_after_seconds)},
        )
