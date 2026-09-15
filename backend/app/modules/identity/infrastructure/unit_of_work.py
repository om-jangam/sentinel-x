from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.writer import SqlAuditRecorder
from app.modules.identity.infrastructure.repositories import (
    SqlOrgRepository,
    SqlPermissionRepository,
    SqlRefreshTokenRepository,
    SqlRoleRepository,
    SqlUserRepository,
)


class SqlIdentityUnitOfWork:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._orgs = SqlOrgRepository(session)
        self._users = SqlUserRepository(session)
        self._roles = SqlRoleRepository(session)
        self._permissions = SqlPermissionRepository(session)
        self._refresh_tokens = SqlRefreshTokenRepository(session)
        self._audit = SqlAuditRecorder(session)

    @property
    def orgs(self) -> SqlOrgRepository:
        return self._orgs

    @property
    def users(self) -> SqlUserRepository:
        return self._users

    @property
    def roles(self) -> SqlRoleRepository:
        return self._roles

    @property
    def permissions(self) -> SqlPermissionRepository:
        return self._permissions

    @property
    def refresh_tokens(self) -> SqlRefreshTokenRepository:
        return self._refresh_tokens

    @property
    def audit(self) -> SqlAuditRecorder:
        return self._audit

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()
