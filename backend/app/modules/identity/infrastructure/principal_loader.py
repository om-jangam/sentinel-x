from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import AuthenticationError
from app.core.security.principal import Principal
from app.core.security.tokens import AccessTokenClaims
from app.modules.identity.infrastructure.repositories import SqlUserRepository


class SqlPrincipalLoader:
    """Implements `core.http.auth.PrincipalLoader` from live database state."""

    async def load(self, session: AsyncSession, claims: AccessTokenClaims) -> Principal:
        users = SqlUserRepository(session)
        user = await users.get(claims.org_id, claims.subject)
        if user is None or not user.is_active:
            raise AuthenticationError("Account is inactive or no longer exists")
        return Principal(
            user_id=user.id,
            org_id=user.org_id,
            email=user.email,
            roles=user.role_names,
            permissions=await users.effective_permissions(user.org_id, user.id),
            token_jti=claims.jti,
            token_expires_at=claims.expires_at,
        )
