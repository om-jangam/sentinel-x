"""The seam between core authentication and the identity module that resolves principals."""

from __future__ import annotations

from typing import Protocol

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security.principal import Principal
from app.core.security.tokens import AccessTokenClaims


class PrincipalLoader(Protocol):
    """Loads the *current* user, roles and permissions for verified claims.

    Resolved from the database on every request, so deactivation and role changes take effect
    immediately rather than when the access token expires.
    """

    async def load(self, session: AsyncSession, claims: AccessTokenClaims) -> Principal: ...
