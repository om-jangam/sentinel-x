from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, Column, ForeignKey, Index, String, Table, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.db.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Uuid, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
    Column("role_id", Uuid, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
)

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", Uuid, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True),
    Column(
        "permission_name",
        String(64),
        ForeignKey("permissions.name", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class OrgModel(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Tenant boundary — a single org in v1, the multi-tenant seam later (docs/05 §2.2)."""

    __tablename__ = "orgs"

    name: Mapped[str] = mapped_column(String(200))
    slug: Mapped[str] = mapped_column(String(64), unique=True)


class PermissionModel(Base):
    __tablename__ = "permissions"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    description: Mapped[str] = mapped_column(String(255))


class RoleModel(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "roles"
    __table_args__ = (UniqueConstraint("org_id", "name"),)

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"))
    name: Mapped[str] = mapped_column(String(64))
    description: Mapped[str] = mapped_column(String(255))
    is_system: Mapped[bool] = mapped_column(Boolean, default=False)

    permissions: Mapped[list[PermissionModel]] = relationship(
        secondary=role_permissions, lazy="selectin", order_by=PermissionModel.name
    )


class UserModel(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"
    __table_args__ = (Index("ix_users_org_id_id", "org_id", "id"),)

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"))
    email: Mapped[str] = mapped_column(String(320), unique=True)
    full_name: Mapped[str] = mapped_column(String(200))
    hashed_password: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None]

    roles: Mapped[list[RoleModel]] = relationship(secondary=user_roles, lazy="selectin", order_by=RoleModel.name)


class RefreshTokenModel(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "refresh_tokens"

    org_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orgs.id", ondelete="RESTRICT"))
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    family_id: Mapped[uuid.UUID] = mapped_column(index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    issued_at: Mapped[datetime]
    expires_at: Mapped[datetime]
    used_at: Mapped[datetime | None]
    revoked_at: Mapped[datetime | None]
