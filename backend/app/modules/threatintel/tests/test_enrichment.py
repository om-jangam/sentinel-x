from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.conftest import Seeded
from app.core.container import Container
from app.core.events.bus import Event
from app.core.events.topics import INCIDENTS_CHANGED
from app.modules.threatintel.application.enrichment_service import EnrichmentService
from app.modules.threatintel.domain.indicators import Indicator, IndicatorType
from app.modules.threatintel.domain.intel import LookupStatus, ProviderAnswer, ProviderInfo, Verdict
from app.modules.threatintel.infrastructure.repositories import SqlIntelUnitOfWork, sql_uow_factory


class FakeProvider:
    def __init__(self, name: str = "fake", *, types: tuple[str, ...] = ("ip", "domain", "hash"), fail: bool = False):
        self.name = name
        self.types = types
        self.fail = fail
        self.asked: list[str] = []

    @property
    def info(self) -> ProviderInfo:
        return ProviderInfo(name=self.name, title=self.name, kind="external", supports=self.types)

    def supports(self, kind: IndicatorType) -> bool:
        return kind.value in self.types

    async def lookup(self, indicator: Indicator) -> ProviderAnswer | None:
        self.asked.append(indicator.key)
        if self.fail:
            raise TimeoutError("provider timed out")
        if indicator.value.startswith("203."):
            return ProviderAnswer(verdict=Verdict.MALICIOUS, summary="known bad", confidence=150, tags=("x", "x"))
        return None

    async def aclose(self) -> None:
        return None


class Clock:
    def __init__(self) -> None:
        self.now = datetime(2026, 9, 22, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def changed(seeded: Seeded, *keys: str) -> Event:
    return Event(topic=INCIDENTS_CHANGED, org_id=seeded.org.id, payload={"indicators": list(keys)})


async def _stored(container: Container, seeded: Seeded) -> dict[tuple[str, str], LookupStatus]:
    async with container.database.sessionmaker() as session:
        indicators = [
            Indicator(IndicatorType.IP, "203.0.113.45"),
            Indicator(IndicatorType.IP, "192.0.2.66"),
            Indicator(IndicatorType.DOMAIN, "cdn-telemetry-sync.example"),
        ]
        results = await SqlIntelUnitOfWork(session).results.get_many(seeded.org.id, indicators)
    return {(r.provider, r.indicator.key): r.status for r in results}


async def test_lookups_are_cached_until_they_expire(container: Container, seeded: Seeded) -> None:
    provider, clock = FakeProvider(), Clock()
    service = EnrichmentService(
        [provider], uow_factory=sql_uow_factory(container.database), cache_ttl=timedelta(hours=24), clock=clock
    )
    await service.handle(changed(seeded, "ip:203.0.113.45", "ip:192.0.2.66"))
    await service.handle(changed(seeded, "ip:203.0.113.45", "ip:192.0.2.66"))
    assert provider.asked == ["ip:192.0.2.66", "ip:203.0.113.45"], "the second event is answered from the cache"

    assert await _stored(container, seeded) == {
        ("fake", "ip:203.0.113.45"): LookupStatus.FOUND,
        ("fake", "ip:192.0.2.66"): LookupStatus.NOT_FOUND,
    }
    async with container.database.sessionmaker() as session:
        [bad] = await SqlIntelUnitOfWork(session).results.get_many(
            seeded.org.id, [Indicator(IndicatorType.IP, "203.0.113.45")]
        )
    assert (bad.confidence, bad.tags, bad.retrieved_at) == (100, ("x",), clock.now), "clamped and de-duplicated"

    clock.now += timedelta(hours=25)
    await service.handle(changed(seeded, "ip:203.0.113.45"))
    assert provider.asked[-1] == "ip:203.0.113.45", "expired results are asked again"


async def test_a_failing_provider_is_recorded_and_the_others_still_run(container: Container, seeded: Seeded) -> None:
    broken, working, clock = FakeProvider("broken", fail=True), FakeProvider("working"), Clock()
    service = EnrichmentService([broken, working], uow_factory=sql_uow_factory(container.database), clock=clock)
    await service.handle(changed(seeded, "ip:203.0.113.45"))

    stored = await _stored(container, seeded)
    assert stored == {
        ("broken", "ip:203.0.113.45"): LookupStatus.ERROR,
        ("working", "ip:203.0.113.45"): LookupStatus.FOUND,
    }

    await service.handle(changed(seeded, "ip:203.0.113.45"))
    assert broken.asked == ["ip:203.0.113.45"], "errors are not retried at once"
    clock.now += timedelta(minutes=16)
    await service.handle(changed(seeded, "ip:203.0.113.45"))
    assert broken.asked == ["ip:203.0.113.45", "ip:203.0.113.45"], "but are retried after the short error period"


async def test_only_valid_external_indicators_reach_a_provider(container: Container, seeded: Seeded) -> None:
    provider = FakeProvider(types=("ip",))
    service = EnrichmentService([provider], uow_factory=sql_uow_factory(container.database))
    await service.handle(
        changed(
            seeded,
            "ip:10.0.5.17",
            "host:ws-fin-07",
            "user:acme\\jsmith",
            "domain:cdn-telemetry-sync.example",  # valid, but this provider doesn't do domains
            "ip:203.0.113.45",
            "garbage",
        )
    )
    assert provider.asked == ["ip:203.0.113.45"]


async def test_nothing_happens_without_providers_or_an_org(container: Container, seeded: Seeded) -> None:
    await EnrichmentService([], uow_factory=sql_uow_factory(container.database)).handle(
        changed(seeded, "ip:203.0.113.45")
    )
    provider = FakeProvider()
    service = EnrichmentService([provider], uow_factory=sql_uow_factory(container.database))
    await service.handle(Event(topic=INCIDENTS_CHANGED, payload={"indicators": ["ip:203.0.113.45"]}))
    await service.handle(
        Event(topic=INCIDENTS_CHANGED, org_id=seeded.org.id, payload={"indicators": "ip:203.0.113.45"})
    )
    assert provider.asked == []
    assert await _stored(container, seeded) == {}
