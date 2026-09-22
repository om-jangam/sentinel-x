from __future__ import annotations

from collections.abc import Callable, Iterable
from contextlib import AbstractAsyncContextManager
from typing import Protocol
from uuid import UUID

from app.modules.threatintel.domain.indicators import Indicator, IndicatorType
from app.modules.threatintel.domain.intel import IntelResult, ProviderAnswer, ProviderInfo


class IntelProvider(Protocol):
    @property
    def info(self) -> ProviderInfo: ...

    def supports(self, kind: IndicatorType) -> bool: ...

    async def lookup(self, indicator: Indicator) -> ProviderAnswer | None:
        """What the provider says, or None when it has nothing on the indicator. Raises when it can't be asked."""
        ...

    async def aclose(self) -> None: ...


class IntelRepository(Protocol):
    async def get_many(self, org_id: UUID, indicators: Iterable[Indicator]) -> list[IntelResult]: ...

    async def upsert(self, org_id: UUID, result: IntelResult) -> None: ...


class IntelUnitOfWork(Protocol):
    @property
    def results(self) -> IntelRepository: ...

    async def commit(self) -> None: ...

    async def rollback(self) -> None: ...


UnitOfWorkFactory = Callable[[], AbstractAsyncContextManager[IntelUnitOfWork]]
