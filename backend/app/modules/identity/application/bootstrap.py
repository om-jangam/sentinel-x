"""Idempotent platform bootstrap: permission catalogue, org, system roles, first administrator."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.audit.port import AuditEvent
from app.core.clock import Clock, utcnow
from app.core.errors import ConflictError
from app.core.ids import uuid7
from app.core.security.passwords import PasswordHasher
from app.core.security.permissions import (
    PERMISSION_DESCRIPTIONS,
    SYSTEM_ROLE_DESCRIPTIONS,
    SYSTEM_ROLE_PERMISSIONS,
    SystemRole,
)
from app.modules.identity.domain.entities import Org, Role, User
from app.modules.identity.domain.policies import normalize_email, validate_org_slug, validate_password
from app.modules.identity.domain.ports import IdentityUnitOfWork


@dataclass(frozen=True, slots=True)
class BootstrapResult:
    org: Org
    org_created: bool
    roles_created: list[str]
    roles_updated: list[str]


async def bootstrap_platform(
    uow: IdentityUnitOfWork, *, org_name: str, org_slug: str, clock: Clock = utcnow
) -> BootstrapResult:
    """Safe to run on every deploy: system roles are reconciled to their code definition."""
    validate_org_slug(org_slug)
    await uow.permissions.sync_catalogue({p.value: d for p, d in PERMISSION_DESCRIPTIONS.items()})

    org = await uow.orgs.get_by_slug(org_slug)
    org_created = org is None
    if org is None:
        org = Org(id=uuid7(), name=org_name, slug=org_slug, created_at=clock())
        await uow.orgs.add(org)
        await _system_audit(uow, org, "org.created", "org", str(org.id), after={"name": org_name, "slug": org_slug})

    existing = {r.name: r for r in await uow.roles.list_for_org(org.id)}
    created: list[str] = []
    updated: list[str] = []
    for system_role in SystemRole:
        permissions = frozenset(p.value for p in SYSTEM_ROLE_PERMISSIONS[system_role])
        description = SYSTEM_ROLE_DESCRIPTIONS[system_role]
        role = existing.get(system_role.value)
        if role is None:
            role = Role(
                id=uuid7(),
                org_id=org.id,
                name=system_role.value,
                description=description,
                is_system=True,
                permissions=permissions,
                created_at=clock(),
            )
            await uow.roles.add(role)
            created.append(role.name)
            await _system_audit(uow, org, "role.created", "role", str(role.id), after=role.audit_view())
        elif role.permissions != permissions or role.description != description or not role.is_system:
            before = role.audit_view()
            role.permissions, role.description, role.is_system = permissions, description, True
            await uow.roles.update(role)
            updated.append(role.name)
            await _system_audit(
                uow, org, "role.system_synced", "role", str(role.id), before=before, after=role.audit_view()
            )

    await uow.commit()
    return BootstrapResult(org=org, org_created=org_created, roles_created=created, roles_updated=updated)


async def create_initial_admin(
    uow: IdentityUnitOfWork,
    hasher: PasswordHasher,
    *,
    org: Org,
    email: str,
    full_name: str,
    password: str,
    clock: Clock = utcnow,
) -> User:
    normalized = normalize_email(email)
    if await uow.users.get_by_email(normalized) is not None:
        raise ConflictError("A user with this email already exists")
    validate_password(password, email=normalized)
    now = clock()
    user = User(
        id=uuid7(),
        org_id=org.id,
        email=normalized,
        full_name=full_name,
        hashed_password=hasher.hash(password),
        is_active=True,
        role_names=frozenset({SystemRole.ADMIN.value}),
        last_login_at=None,
        created_at=now,
        updated_at=now,
    )
    await uow.users.add(user)
    await uow.users.set_roles(org.id, user.id, user.role_names)
    await _system_audit(uow, org, "user.created", "user", str(user.id), after=user.audit_view())
    await uow.commit()
    return user


async def _system_audit(
    uow: IdentityUnitOfWork,
    org: Org,
    action: str,
    resource_type: str,
    resource_id: str,
    *,
    before: dict[str, object] | None = None,
    after: dict[str, object] | None = None,
) -> None:
    await uow.audit.record(
        AuditEvent(
            org_id=org.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_type="system",
            before=before,
            after=after,
            context={"source": "bootstrap"},
        )
    )
