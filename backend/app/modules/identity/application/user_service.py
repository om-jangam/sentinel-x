"""User administration use-cases. Every mutation is authorised here and audited in-transaction."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from uuid import UUID

from app.core.audit.port import AuditEvent
from app.core.clock import Clock, utcnow
from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.core.ids import uuid7
from app.core.security.passwords import PasswordHasher
from app.core.security.permissions import Permission
from app.core.security.principal import Principal
from app.modules.identity.application.guards import (
    ensure_org_remains_administrable,
    ensure_service_role_separation,
)
from app.modules.identity.domain.entities import Role, User
from app.modules.identity.domain.policies import normalize_email, validate_password
from app.modules.identity.domain.ports import IdentityUnitOfWork


@dataclass(frozen=True, slots=True)
class CreateUserCommand:
    email: str
    full_name: str
    password: str
    roles: Collection[str] = ()


@dataclass(frozen=True, slots=True)
class UpdateUserCommand:
    full_name: str | None = None
    is_active: bool | None = None
    password: str | None = None


@dataclass(frozen=True, slots=True)
class UserPage:
    items: list[User]
    next_after: UUID | None


class UserAdminService:
    def __init__(self, uow: IdentityUnitOfWork, *, hasher: PasswordHasher, clock: Clock = utcnow) -> None:
        self._uow = uow
        self._hasher = hasher
        self._clock = clock

    async def list_users(self, principal: Principal, *, limit: int, after: UUID | None) -> UserPage:
        principal.require(Permission.USER_READ)
        rows = await self._uow.users.list_page(principal.org_id, limit=limit + 1, after_id=after)
        has_more = len(rows) > limit
        items = rows[:limit]
        return UserPage(items=items, next_after=items[-1].id if has_more and items else None)

    async def get_user(self, principal: Principal, user_id: UUID) -> User:
        principal.require(Permission.USER_READ)
        return await self._require_user(principal.org_id, user_id)

    async def create_user(self, principal: Principal, command: CreateUserCommand) -> User:
        principal.require(Permission.USER_MANAGE)
        email = normalize_email(command.email)
        validate_password(command.password, email=email)
        if await self._uow.users.get_by_email(email) is not None:
            raise ConflictError("A user with this email already exists")
        roles = await self._resolve_roles(principal.org_id, command.roles)

        now = self._clock()
        user = User(
            id=uuid7(),
            org_id=principal.org_id,
            email=email,
            full_name=command.full_name.strip(),
            hashed_password=self._hasher.hash(command.password),
            is_active=True,
            role_names=frozenset(r.name for r in roles),
            last_login_at=None,
            created_at=now,
            updated_at=now,
        )
        await self._uow.users.add(user)
        await self._uow.users.set_roles(user.org_id, user.id, user.role_names)
        await self._audit(principal, "user.created", user, after=user.audit_view())
        await self._uow.commit()
        return user

    async def update_user(self, principal: Principal, user_id: UUID, command: UpdateUserCommand) -> User:
        principal.require(Permission.USER_MANAGE)
        user = await self._require_user(principal.org_id, user_id)
        before = user.audit_view()
        now = self._clock()
        revoke_sessions = False
        changes: dict[str, object] = {}

        if command.full_name is not None:
            user.full_name = command.full_name.strip()
        if command.is_active is not None and command.is_active != user.is_active:
            if not command.is_active and user.id == principal.user_id:
                raise ConflictError("You cannot deactivate your own account")
            user.is_active = command.is_active
            revoke_sessions = revoke_sessions or not command.is_active
        if command.password is not None:
            validate_password(command.password, email=user.email)
            user.hashed_password = self._hasher.hash(command.password)
            changes["password_changed"] = True
            revoke_sessions = True

        await self._uow.users.update(user)
        if revoke_sessions:
            changes["sessions_revoked"] = await self._uow.refresh_tokens.revoke_all_for_user(user.id, now)
        if not user.is_active:
            await ensure_org_remains_administrable(self._uow, principal.org_id)
        await self._audit(principal, "user.updated", user, before=before, after={**user.audit_view(), **changes})
        await self._uow.commit()
        return user

    async def deactivate_user(self, principal: Principal, user_id: UUID) -> User:
        return await self.update_user(principal, user_id, UpdateUserCommand(is_active=False))

    async def set_roles(self, principal: Principal, user_id: UUID, role_names: Collection[str]) -> User:
        principal.require(Permission.USER_MANAGE)
        user = await self._require_user(principal.org_id, user_id)
        roles = await self._resolve_roles(principal.org_id, role_names)
        ensure_service_role_separation(roles)
        before = user.audit_view()

        user.role_names = frozenset(r.name for r in roles)
        await self._uow.users.set_roles(user.org_id, user.id, user.role_names)
        await ensure_org_remains_administrable(self._uow, principal.org_id)
        await self._audit(principal, "user.roles_changed", user, before=before, after=user.audit_view())
        await self._uow.commit()
        return user

    async def _require_user(self, org_id: UUID, user_id: UUID) -> User:
        user = await self._uow.users.get(org_id, user_id)
        if user is None:  # other orgs' users are indistinguishable from nonexistent ones
            raise NotFoundError("User not found")
        return user

    async def _resolve_roles(self, org_id: UUID, names: Collection[str]) -> list[Role]:
        wanted = set(names)
        roles = await self._uow.roles.get_by_names(org_id, wanted)
        missing = wanted - {r.name for r in roles}
        if missing:
            raise ValidationFailedError(
                "Unknown roles",
                errors=[
                    {"loc": ["roles"], "msg": f"unknown role '{n}'", "type": "unknown_role"} for n in sorted(missing)
                ],
            )
        return roles

    async def _audit(
        self,
        principal: Principal,
        action: str,
        user: User,
        *,
        before: dict[str, object] | None = None,
        after: dict[str, object] | None = None,
    ) -> None:
        await self._uow.audit.record(
            AuditEvent(
                org_id=principal.org_id,
                action=action,
                resource_type="user",
                resource_id=str(user.id),
                actor_id=principal.user_id,
                before=before,
                after=after,
            )
        )
