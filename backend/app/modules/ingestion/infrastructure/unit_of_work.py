from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.writer import SqlAuditRecorder
from app.modules.ingestion.infrastructure.repositories import SqlSourceRepository


class SqlIngestionUnitOfWork:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._sources = SqlSourceRepository(session)
        self._audit = SqlAuditRecorder(session)

    @property
    def sources(self) -> SqlSourceRepository:
        return self._sources

    @property
    def audit(self) -> SqlAuditRecorder:
        return self._audit

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()
