from __future__ import annotations

from collections.abc import AsyncIterator, Iterable
from contextlib import asynccontextmanager
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db.session import Database
from app.modules.threatintel.domain.indicators import Indicator, IndicatorType
from app.modules.threatintel.domain.intel import IntelResult, LookupStatus, RelatedIndicator, Verdict
from app.modules.threatintel.domain.ports import IntelUnitOfWork, UnitOfWorkFactory
from app.modules.threatintel.infrastructure.models import IntelResultModel


def _to_result(model: IntelResultModel) -> IntelResult:
    return IntelResult(
        provider=model.provider,
        indicator=Indicator(IndicatorType(model.indicator_type), model.value),
        status=LookupStatus(model.status),
        verdict=Verdict(model.verdict),
        summary=model.summary,
        retrieved_at=model.retrieved_at,
        expires_at=model.expires_at,
        confidence=model.confidence,
        tags=tuple(model.tags),
        related=tuple(RelatedIndicator(r["type"], r["value"], r["relation"]) for r in model.related),
        references=tuple(model.references),
        provider_first_seen=model.provider_first_seen,
        provider_last_seen=model.provider_last_seen,
        error=model.error,
    )


class SqlIntelRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_many(self, org_id: UUID, indicators: Iterable[Indicator]) -> list[IntelResult]:
        wanted = sorted(set(indicators))
        if not wanted:
            return []
        rows = await self._session.scalars(
            select(IntelResultModel).where(
                IntelResultModel.org_id == org_id,
                or_(
                    *(
                        and_(IntelResultModel.indicator_type == i.type.value, IntelResultModel.value == i.value)
                        for i in wanted
                    )
                ),
            )
        )
        return [_to_result(row) for row in rows]

    async def upsert(self, org_id: UUID, result: IntelResult) -> None:
        key = (org_id, result.provider, result.indicator.type.value, result.indicator.value)
        model = await self._session.get(IntelResultModel, key)
        if model is None:
            model = IntelResultModel(
                org_id=org_id,
                provider=result.provider,
                indicator_type=result.indicator.type.value,
                value=result.indicator.value,
            )
            self._session.add(model)
        model.status = result.status.value
        model.verdict = result.verdict.value
        model.confidence = result.confidence
        model.summary = result.summary
        model.tags = list(result.tags)
        model.related = [r.as_json() for r in result.related]
        model.references = list(result.references)
        model.provider_first_seen = result.provider_first_seen
        model.provider_last_seen = result.provider_last_seen
        model.retrieved_at = result.retrieved_at
        model.expires_at = result.expires_at
        model.error = result.error
        await self._session.flush()


class SqlIntelUnitOfWork:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._results = SqlIntelRepository(session)

    @property
    def results(self) -> SqlIntelRepository:
        return self._results

    async def commit(self) -> None:
        await self._session.commit()

    async def rollback(self) -> None:
        await self._session.rollback()


def sql_uow_factory(database: Database) -> UnitOfWorkFactory:
    @asynccontextmanager
    async def factory() -> AsyncIterator[IntelUnitOfWork]:
        async with database.sessionmaker() as session:
            yield SqlIntelUnitOfWork(session)

    return factory
