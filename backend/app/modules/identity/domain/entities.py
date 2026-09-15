from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID


@dataclass(slots=True)
class Org:
    id: UUID
    name: str
    slug: str
    created_at: datetime


@dataclass(slots=True)
class User:
    id: UUID
    org_id: UUID
    email: str
    full_name: str
    hashed_password: str
    is_active: bool
    role_names: frozenset[str]
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime

    def audit_view(self) -> dict[str, Any]:
        """What the audit log may record about a user — never credential material."""
        return {
            "email": self.email,
            "full_name": self.full_name,
            "is_active": self.is_active,
            "roles": sorted(self.role_names),
        }


@dataclass(slots=True)
class Role:
    id: UUID
    org_id: UUID
    name: str
    description: str
    is_system: bool
    permissions: frozenset[str]
    created_at: datetime

    def audit_view(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "is_system": self.is_system,
            "permissions": sorted(self.permissions),
        }


@dataclass(frozen=True, slots=True)
class PermissionInfo:
    name: str
    description: str


@dataclass(slots=True)
class RefreshToken:
    """Opaque refresh token; only its SHA-256 hash is persisted.

    Tokens rotate on every use. All tokens descending from one login share a `family_id`, so
    replaying a spent token revokes the whole family (theft detection, docs/07 §2).
    """

    id: UUID
    org_id: UUID
    user_id: UUID
    family_id: UUID
    token_hash: str
    issued_at: datetime
    expires_at: datetime
    used_at: datetime | None = None
    revoked_at: datetime | None = None
