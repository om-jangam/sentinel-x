"""Cross-cutting RBAC safety invariants enforced by several use-cases."""

from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from app.core.errors import ConflictError, ValidationFailedError
from app.core.security.permissions import PRIVILEGED_PERMISSIONS, Permission, SystemRole
from app.modules.identity.domain.entities import Role
from app.modules.identity.domain.ports import IdentityUnitOfWork

ADMINISTRATION_PERMISSIONS = frozenset({Permission.USER_MANAGE, Permission.ROLE_MANAGE})


async def ensure_org_remains_administrable(uow: IdentityUnitOfWork, org_id: UUID) -> None:
    """Refuse any change that would leave no active user able to manage users and roles.

    Called after the change is flushed and before commit, so it sees the would-be state.
    """
    if await uow.users.count_active_with_permissions(org_id, ADMINISTRATION_PERMISSIONS) == 0:
        await uow.rollback()
        raise ConflictError("This change would leave the organisation without an active administrator")


def ensure_service_role_separation(roles: Iterable[Role]) -> None:
    """Machine principals must never hold RBAC-management power (docs/07 §3)."""
    role_list = list(roles)
    if not any(r.name == SystemRole.SERVICE for r in role_list):
        return
    granted: set[str] = set()
    for role in role_list:
        granted |= role.permissions
    if granted & PRIVILEGED_PERMISSIONS:
        raise ValidationFailedError("The service role cannot be combined with roles that grant user or role management")
