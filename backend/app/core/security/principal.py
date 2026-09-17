"""The authenticated caller, as seen by application-layer authorisation checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from app.core.errors import PermissionDeniedError


@dataclass(frozen=True, slots=True)
class Principal:
    user_id: UUID
    org_id: UUID
    email: str
    roles: frozenset[str]
    permissions: frozenset[str]
    token_jti: str | None = None
    token_expires_at: datetime | None = None

    def has(self, permission: str) -> bool:
        return permission in self.permissions

    def require(self, permission: str) -> None:
        """Authorisation lives in the use-case, so no entry point (API, worker, CLI) can skip it."""
        if permission not in self.permissions:
            raise PermissionDeniedError(permission)


@dataclass(frozen=True, slots=True)
class ClientInfo:
    ip: str | None
    user_agent: str | None

    def as_audit_context(self) -> dict[str, str | None]:
        return {"ip": self.ip, "user_agent": self.user_agent}
