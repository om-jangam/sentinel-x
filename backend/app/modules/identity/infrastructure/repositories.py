"""SQLAlchemy adapters for the identity ports. Every query is scoped by `org_id` (docs/07 §3)."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from sqlalchemy import CursorResult, distinct, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.clock import utcnow
from app.core.errors import NotFoundError
from app.modules.identity.domain.entities import Org, PermissionInfo, RefreshToken, Role, User
from app.modules.identity.infrastructure.models import (
    OrgModel,
    PermissionModel,
    RefreshTokenModel,
    RoleModel,
    UserModel,
    role_permissions,
    user_roles,
)


def _org(model: OrgModel) -> Org:
    return Org(id=model.id, name=model.name, slug=model.slug, created_at=model.created_at)


def _user(model: UserModel) -> User:
    return User(
        id=model.id,
        org_id=model.org_id,
        email=model.email,
        full_name=model.full_name,
        hashed_password=model.hashed_password,
        is_active=model.is_active,
        role_names=frozenset(r.name for r in model.roles),
        last_login_at=model.last_login_at,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _role(model: RoleModel) -> Role:
    return Role(
        id=model.id,
        org_id=model.org_id,
        name=model.name,
        description=model.description,
        is_system=model.is_system,
        permissions=frozenset(p.name for p in model.permissions),
        created_at=model.created_at,
    )


def _refresh(model: RefreshTokenModel) -> RefreshToken:
    return RefreshToken(
        id=model.id,
        org_id=model.org_id,
        user_id=model.user_id,
        family_id=model.family_id,
        token_hash=model.token_hash,
        issued_at=model.issued_at,
        expires_at=model.expires_at,
        used_at=model.used_at,
        revoked_at=model.revoked_at,
    )


class SqlOrgRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, org_id: UUID) -> Org | None:
        model = await self._session.get(OrgModel, org_id)
        return None if model is None else _org(model)

    async def get_by_slug(self, slug: str) -> Org | None:
        model = await self._session.scalar(select(OrgModel).where(OrgModel.slug == slug))
        return None if model is None else _org(model)

    async def add(self, org: Org) -> None:
        self._session.add(
            OrgModel(id=org.id, name=org.name, slug=org.slug, created_at=org.created_at, updated_at=org.created_at)
        )
        await self._session.flush()


class SqlUserRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _model(self, org_id: UUID, user_id: UUID) -> UserModel | None:
        model: UserModel | None = await self._session.scalar(
            select(UserModel).where(UserModel.id == user_id, UserModel.org_id == org_id)
        )
        return model

    async def _require(self, org_id: UUID, user_id: UUID) -> UserModel:
        model = await self._model(org_id, user_id)
        if model is None:
            raise NotFoundError("User not found")
        return model

    async def get(self, org_id: UUID, user_id: UUID) -> User | None:
        model = await self._model(org_id, user_id)
        return None if model is None else _user(model)

    async def get_by_email(self, email: str) -> User | None:
        model = await self._session.scalar(select(UserModel).where(UserModel.email == email))
        return None if model is None else _user(model)

    async def list_page(self, org_id: UUID, *, limit: int, after_id: UUID | None) -> list[User]:
        stmt = select(UserModel).where(UserModel.org_id == org_id)
        if after_id is not None:
            stmt = stmt.where(UserModel.id > after_id)
        rows = await self._session.scalars(stmt.order_by(UserModel.id).limit(limit))
        return [_user(m) for m in rows.all()]

    async def add(self, user: User) -> None:
        self._session.add(
            UserModel(
                id=user.id,
                org_id=user.org_id,
                email=user.email,
                full_name=user.full_name,
                hashed_password=user.hashed_password,
                is_active=user.is_active,
                last_login_at=user.last_login_at,
                created_at=user.created_at,
                updated_at=user.updated_at,
                roles=[],
            )
        )
        await self._session.flush()

    async def update(self, user: User) -> None:
        model = await self._require(user.org_id, user.id)
        model.full_name = user.full_name
        model.hashed_password = user.hashed_password
        model.is_active = user.is_active
        model.last_login_at = user.last_login_at
        model.updated_at = user.updated_at = utcnow()
        await self._session.flush()

    async def set_roles(self, org_id: UUID, user_id: UUID, role_names: Collection[str]) -> None:
        model = await self._require(org_id, user_id)
        roles = await self._session.scalars(
            select(RoleModel).where(RoleModel.org_id == org_id, RoleModel.name.in_(list(role_names)))
        )
        model.roles = list(roles.all())
        model.updated_at = utcnow()
        await self._session.flush()

    async def effective_permissions(self, org_id: UUID, user_id: UUID) -> frozenset[str]:
        rows = await self._session.scalars(
            select(distinct(role_permissions.c.permission_name))
            .select_from(UserModel)
            .join(user_roles, user_roles.c.user_id == UserModel.id)
            .join(role_permissions, role_permissions.c.role_id == user_roles.c.role_id)
            .where(UserModel.id == user_id, UserModel.org_id == org_id)
        )
        return frozenset(rows.all())

    async def count_active_with_permissions(self, org_id: UUID, permissions: Collection[str]) -> int:
        wanted = list(set(permissions))
        holders = (
            select(UserModel.id)
            .join(user_roles, user_roles.c.user_id == UserModel.id)
            .join(role_permissions, role_permissions.c.role_id == user_roles.c.role_id)
            .where(
                UserModel.org_id == org_id,
                UserModel.is_active.is_(True),
                role_permissions.c.permission_name.in_(wanted),
            )
            .group_by(UserModel.id)
            .having(func.count(distinct(role_permissions.c.permission_name)) == len(wanted))
            .subquery()
        )
        return int(await self._session.scalar(select(func.count()).select_from(holders)) or 0)

    async def count_with_all_roles(self, org_id: UUID, role_names: Collection[str]) -> int:
        wanted = list(set(role_names))
        holders = (
            select(UserModel.id)
            .join(user_roles, user_roles.c.user_id == UserModel.id)
            .join(RoleModel, RoleModel.id == user_roles.c.role_id)
            .where(UserModel.org_id == org_id, RoleModel.name.in_(wanted))
            .group_by(UserModel.id)
            .having(func.count(distinct(RoleModel.name)) == len(wanted))
            .subquery()
        )
        return int(await self._session.scalar(select(func.count()).select_from(holders)) or 0)


class SqlRoleRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def _permission_models(self, names: Collection[str]) -> list[PermissionModel]:
        rows = await self._session.scalars(select(PermissionModel).where(PermissionModel.name.in_(list(names))))
        return list(rows.all())

    async def list_for_org(self, org_id: UUID) -> list[Role]:
        rows = await self._session.scalars(
            select(RoleModel).where(RoleModel.org_id == org_id).order_by(RoleModel.is_system.desc(), RoleModel.name)
        )
        return [_role(m) for m in rows.all()]

    async def get(self, org_id: UUID, role_id: UUID) -> Role | None:
        model = await self._session.scalar(select(RoleModel).where(RoleModel.id == role_id, RoleModel.org_id == org_id))
        return None if model is None else _role(model)

    async def get_by_names(self, org_id: UUID, names: Collection[str]) -> list[Role]:
        if not names:
            return []
        rows = await self._session.scalars(
            select(RoleModel).where(RoleModel.org_id == org_id, RoleModel.name.in_(list(names)))
        )
        return [_role(m) for m in rows.all()]

    async def add(self, role: Role) -> None:
        self._session.add(
            RoleModel(
                id=role.id,
                org_id=role.org_id,
                name=role.name,
                description=role.description,
                is_system=role.is_system,
                created_at=role.created_at,
                updated_at=role.created_at,
                permissions=await self._permission_models(role.permissions),
            )
        )
        await self._session.flush()

    async def update(self, role: Role) -> None:
        model = await self._session.scalar(
            select(RoleModel).where(RoleModel.id == role.id, RoleModel.org_id == role.org_id)
        )
        if model is None:
            raise NotFoundError("Role not found")
        model.description = role.description
        model.is_system = role.is_system
        model.permissions = await self._permission_models(role.permissions)
        model.updated_at = utcnow()
        await self._session.flush()


class SqlPermissionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_all(self) -> list[PermissionInfo]:
        rows = await self._session.scalars(select(PermissionModel).order_by(PermissionModel.name))
        return [PermissionInfo(name=m.name, description=m.description) for m in rows.all()]

    async def sync_catalogue(self, catalogue: Mapping[str, str]) -> None:
        """Code is the source of truth: add new permissions, refresh descriptions, drop stale ones."""
        existing = {m.name: m for m in (await self._session.scalars(select(PermissionModel))).all()}
        for name, description in catalogue.items():
            model = existing.pop(name, None)
            if model is None:
                self._session.add(PermissionModel(name=name, description=description))
            elif model.description != description:
                model.description = description
        for stale in existing.values():
            await self._session.delete(stale)
        await self._session.flush()


class SqlRefreshTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, token: RefreshToken) -> None:
        self._session.add(
            RefreshTokenModel(
                id=token.id,
                org_id=token.org_id,
                user_id=token.user_id,
                family_id=token.family_id,
                token_hash=token.token_hash,
                issued_at=token.issued_at,
                expires_at=token.expires_at,
                used_at=token.used_at,
                revoked_at=token.revoked_at,
            )
        )
        await self._session.flush()

    async def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        model = await self._session.scalar(select(RefreshTokenModel).where(RefreshTokenModel.token_hash == token_hash))
        return None if model is None else _refresh(model)

    async def mark_used(self, token_id: UUID, used_at: datetime) -> bool:
        result = cast(
            CursorResult[Any],
            await self._session.execute(
                update(RefreshTokenModel)
                .where(
                    RefreshTokenModel.id == token_id,
                    RefreshTokenModel.used_at.is_(None),
                    RefreshTokenModel.revoked_at.is_(None),
                )
                .values(used_at=used_at)
                .execution_options(synchronize_session=False)
            ),
        )
        return result.rowcount == 1

    async def revoke_family(self, family_id: UUID, revoked_at: datetime) -> int:
        return await self._revoke(RefreshTokenModel.family_id == family_id, revoked_at)

    async def revoke_all_for_user(self, user_id: UUID, revoked_at: datetime) -> int:
        return await self._revoke(RefreshTokenModel.user_id == user_id, revoked_at)

    async def _revoke(self, condition: Any, revoked_at: datetime) -> int:
        result = cast(
            CursorResult[Any],
            await self._session.execute(
                update(RefreshTokenModel)
                .where(condition, RefreshTokenModel.revoked_at.is_(None))
                .values(revoked_at=revoked_at)
                .execution_options(synchronize_session=False)
            ),
        )
        return int(result.rowcount)
