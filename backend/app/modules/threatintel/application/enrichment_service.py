"""Enrichment consumer: look up the indicators of changed incidents with every configured provider, and cache.

Runs in its own consumer group, so slow or failing providers never delay detection or correlation. A result
is cached per organisation, provider and indicator until it expires. A provider that fails is recorded as an
error (retried later), and the others still run. Lookups are sequential: external providers rate-limit.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import timedelta
from time import perf_counter
from uuid import UUID

from app.core.clock import Clock, utcnow
from app.core.events.bus import Event
from app.core.observability.metrics import INTEL_LOOKUPS
from app.modules.threatintel.domain.indicators import Indicator
from app.modules.threatintel.domain.intel import IntelResult
from app.modules.threatintel.domain.ports import IntelProvider, UnitOfWorkFactory

logger = logging.getLogger(__name__)

MAX_INDICATORS_PER_EVENT = 50


class EnrichmentService:
    def __init__(
        self,
        providers: Sequence[IntelProvider],
        *,
        uow_factory: UnitOfWorkFactory,
        cache_ttl: timedelta = timedelta(hours=24),
        clock: Clock = utcnow,
    ) -> None:
        self._providers = list(providers)
        self._uow_factory = uow_factory
        self._ttl = cache_ttl
        self._clock = clock

    async def handle(self, event: Event) -> None:
        if event.org_id is None or not self._providers:
            return
        raw = event.payload.get("indicators", [])
        parsed = {Indicator.parse(key) for key in raw if isinstance(key, str)} if isinstance(raw, list) else set()
        indicators = sorted(ind for ind in parsed if ind is not None)[:MAX_INDICATORS_PER_EVENT]
        if not indicators:
            return
        await self.enrich(event.org_id, indicators)

    async def enrich(self, org_id: UUID, indicators: Sequence[Indicator]) -> int:
        """Look up whatever isn't cached and fresh; returns how many lookups were made."""
        now = self._clock()
        async with self._uow_factory() as uow:
            cached = {
                (result.provider, result.indicator): result for result in await uow.results.get_many(org_id, indicators)
            }
        made = 0
        for provider in self._providers:
            name = provider.info.name
            for indicator in indicators:
                if not provider.supports(indicator.type):
                    continue
                known = cached.get((name, indicator))
                if known is not None and known.is_fresh(now):
                    continue
                started = perf_counter()
                try:
                    answer = await provider.lookup(indicator)
                    ttl = provider.info.cache_ttl or self._ttl
                    result = IntelResult.from_answer(name, indicator, answer, now=self._clock(), ttl=ttl)
                except Exception as exc:  # one provider failing must not stop the others
                    logger.warning(
                        "intel lookup failed",
                        extra={"provider": name, "indicator_type": indicator.type.value, "reason": type(exc).__name__},
                    )
                    result = IntelResult.failed(name, indicator, type(exc).__name__, now=self._clock())
                INTEL_LOOKUPS.labels(provider=name, status=result.status.value).observe(perf_counter() - started)
                # One short transaction per result: a slow provider never holds a database connection open.
                async with self._uow_factory() as uow:
                    await uow.results.upsert(org_id, result)
                    await uow.commit()
                made += 1
        if made:
            logger.info("indicators enriched", extra={"intel_lookups": made, "org_id": str(org_id)})
        return made
