"""Role and permission administration use-cases."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from uuid import UUID

from app.core.audit.port import AuditEvent
from app.core.clock import Clock, utcnow
from app.core.errors import ConflictError, NotFoundError, ValidationFailedError
from app.core.ids import uuid7
from app.core.security.permissions import PRIVILEGED_PERMISSIONS, Permission, SystemRole
from app.core.security.principal import Principal
from app.modules.identity.application.guards import ensure_org_remains_administrable
from app.modules.identity.domain.entities import PermissionInfo, Role
from app.modules.identity.domain.policies import validate_role_name
from app.modules.identity.domain.ports import IdentityUnitOfWork


@dataclass(frozen=True, slots=True)
class CreateRoleCommand:
    name: str
    description: str
    permissions: Collection[str]


@dataclass(frozen=True, slots=True)
class UpdateRoleCommand:
    description: str | None = None
    permissions: Collection[str] | None = None


class RoleAdminService:
    def __init__(self, uow: IdentityUnitOfWork, *, clock: Clock = utcnow) -> None:
        self._uow = uow
        self._clock = clock

    async def list_roles(self, principal: Principal) -> list[Role]:
        principal.require(Permission.ROLE_READ)
        return await self._uow.roles.list_for_org(principal.org_id)

    async def list_permissions(self, principal: Principal) -> list[PermissionInfo]:
        principal.require(Permission.ROLE_READ)
        return await self._uow.permissions.list_all()

    async def create_role(self, principal: Principal, command: CreateRoleCommand) -> Role:
        principal.require(Permission.ROLE_MANAGE)
        validate_role_name(command.name)
        if command.name in set(SystemRole):
            raise ConflictError("That name is reserved for a system role")
        if await self._uow.roles.get_by_names(principal.org_id, [command.name]):
            raise ConflictError("A role with this name already exists")
        permissions = self._validate_permissions(command.permissions)

        role = Role(
            id=uuid7(),
            org_id=principal.org_id,
            name=command.name,
            description=command.description.strip(),
            is_system=False,
            permissions=permissions,
            created_at=self._clock(),
        )
        await self._uow.roles.add(role)
        await self._audit(principal, "role.created", role, after=role.audit_view())
        await self._uow.commit()
        return role

    async def update_role(self, principal: Principal, role_id: UUID, command: UpdateRoleCommand) -> Role:
        principal.require(Permission.ROLE_MANAGE)
        role = await self._uow.roles.get(principal.org_id, role_id)
        if role is None:
            raise NotFoundError("Role not found")
        if role.is_system:
            raise ConflictError("System roles are defined by the platform and cannot be modified")
        before = role.audit_view()

        if command.description is not None:
            role.description = command.description.strip()
        if command.permissions is not None:
            permissions = self._validate_permissions(command.permissions)
            if permissions & PRIVILEGED_PERMISSIONS and await self._uow.users.count_with_all_roles(
                principal.org_id, [role.name, SystemRole.SERVICE]
            ):
                raise ValidationFailedError(
                    "This role is held by service principals and cannot grant user or role management"
                )
            role.permissions = permissions

        await self._uow.roles.update(role)
        await ensure_org_remains_administrable(self._uow, principal.org_id)
        await self._audit(principal, "role.updated", role, before=before, after=role.audit_view())
        await self._uow.commit()
        return role

    @staticmethod
    def _validate_permissions(requested: Collection[str]) -> frozenset[str]:
        known = {p.value for p in Permission}
        unknown = set(requested) - known
        if unknown:
            raise ValidationFailedError(
                "Unknown permissions",
                errors=[
                    {"loc": ["permissions"], "msg": f"unknown permission '{p}'", "type": "unknown_permission"}
                    for p in sorted(unknown)
                ],
            )
        return frozenset(requested)

    async def _audit(
        self,
        principal: Principal,
        action: str,
        role: Role,
        *,
        before: dict[str, object] | None = None,
        after: dict[str, object] | None = None,
    ) -> None:
        await self._uow.audit.record(
            AuditEvent(
                org_id=principal.org_id,
                action=action,
                resource_type="role",
                resource_id=str(role.id),
                actor_id=principal.user_id,
                before=before,
                after=after,
            )
        )
