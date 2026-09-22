"""Request/response contracts. Separate Create/Update/Read models; ORM objects never leak out."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr

from app.modules.identity.domain.entities import PermissionInfo, Role, User


class _Request(BaseModel):
    model_config = ConfigDict(extra="forbid")  # rejects over-posting


# ------------------------------------------------------------------ auth
class LoginRequest(_Request):
    # Deliberately not EmailStr: login must not reveal which addresses are syntactically "valid".
    email: str = Field(min_length=3, max_length=320)
    password: SecretStr = Field(min_length=1, max_length=128)


class PasswordChange(_Request):
    current_password: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 — OAuth token type, not a secret
    expires_in: int
    expires_at: datetime


class MeResponse(BaseModel):
    id: UUID
    org_id: UUID
    email: str
    full_name: str
    roles: list[str]
    permissions: list[str]
    last_login_at: datetime | None


# ----------------------------------------------------------------- users
class UserRead(BaseModel):
    id: UUID
    org_id: UUID
    email: str
    full_name: str
    is_active: bool
    roles: list[str]
    last_login_at: datetime | None
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_entity(cls, user: User) -> UserRead:
        return cls(
            id=user.id,
            org_id=user.org_id,
            email=user.email,
            full_name=user.full_name,
            is_active=user.is_active,
            roles=sorted(user.role_names),
            last_login_at=user.last_login_at,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )


class UserCreate(_Request):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=200)
    password: SecretStr = Field(max_length=128)
    roles: list[str] = Field(default_factory=list, max_length=20)


class UserUpdate(_Request):
    full_name: str | None = Field(default=None, min_length=1, max_length=200)
    is_active: bool | None = None
    password: SecretStr | None = Field(default=None, max_length=128)


class RoleAssignment(_Request):
    roles: list[str] = Field(max_length=20)


# ----------------------------------------------------------------- roles
class RoleRead(BaseModel):
    id: UUID
    name: str
    description: str
    is_system: bool
    permissions: list[str]

    @classmethod
    def from_entity(cls, role: Role) -> RoleRead:
        return cls(
            id=role.id,
            name=role.name,
            description=role.description,
            is_system=role.is_system,
            permissions=sorted(role.permissions),
        )


class RoleCreate(_Request):
    name: str = Field(min_length=3, max_length=64)
    description: str = Field(default="", max_length=255)
    permissions: list[str] = Field(default_factory=list, max_length=100)


class RoleUpdate(_Request):
    description: str | None = Field(default=None, max_length=255)
    permissions: list[str] | None = Field(default=None, max_length=100)


class PermissionRead(BaseModel):
    name: str
    description: str

    @classmethod
    def from_entity(cls, permission: PermissionInfo) -> PermissionRead:
        return cls(name=permission.name, description=permission.description)
