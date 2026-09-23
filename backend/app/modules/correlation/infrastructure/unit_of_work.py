from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.writer import SqlAuditRecorder
from app.core.db.session import Database
from app.modules.correlation.domain.ports import CorrelationUnitOfWork, UnitOfWorkFactory
from app.modules.correlation.infrastructure.repositories import SqlBaselineRepository, SqlIncidentRepository


class SqlCorrelationUnitOfWork:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._incidents = SqlIncidentRepository(session)
        self._baselines = SqlBaselineRepository(session)
        self._audit = SqlAuditRecorder(session)

    @property
    def incidents(self) -> SqlIncidentRepository:
        return self._incidents

    @property
    def baselines(self) -> SqlBaselineRepository:
        return self._baselines

    @property
    def audit(self) -> SqlAuditRecorder:
        return self._audit

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()


def sql_uow_factory(database: Database) -> UnitOfWorkFactory:
    """A fresh session per bus message: correlation runs outside any request."""

    @asynccontextmanager
    async def factory() -> AsyncIterator[CorrelationUnitOfWork]:
        async with database.sessionmaker() as session:
            yield SqlCorrelationUnitOfWork(session)

    return factory
