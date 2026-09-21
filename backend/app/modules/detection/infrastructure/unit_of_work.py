from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db.session import Database
from app.modules.detection.domain.ports import DetectionUnitOfWork, UnitOfWorkFactory
from app.modules.detection.infrastructure.repositories import SqlFindingRepository


class SqlDetectionUnitOfWork:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._findings = SqlFindingRepository(session)

    @property
    def findings(self) -> SqlFindingRepository:
        return self._findings

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()


def sql_uow_factory(database: Database) -> UnitOfWorkFactory:
    """A fresh session per bus message: detection runs outside any request."""

    @asynccontextmanager
    async def factory() -> AsyncIterator[DetectionUnitOfWork]:
        async with database.sessionmaker() as session:
            yield SqlDetectionUnitOfWork(session)

    return factory
