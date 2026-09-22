"""What leaves the platform: correlation announces only external indicators, and enrichment only asks about them."""

from __future__ import annotations

from app.analysis import build_analysis
from app.conftest import Seeded
from app.core.container import Container
from app.core.events.bus import InMemoryEventBus
from app.core.events.topics import EVENTS_NORMALIZED, INCIDENTS_CHANGED
from app.modules.detection.infrastructure.rule_loader import load_rules
from app.modules.detection.infrastructure.window_store import InMemoryWindowStore
from app.modules.detection.tests.conftest import bus_event
from app.modules.threatintel.application.enrichment_service import EnrichmentService
from app.modules.threatintel.infrastructure.repositories import sql_uow_factory
from app.modules.threatintel.tests.test_enrichment import FakeProvider
from app.tests.test_correlation_pipeline import _stories

STORY_INDICATORS = ["domain:cdn-telemetry-sync.example", "ip:192.0.2.66", "ip:198.51.100.23", "ip:203.0.113.45"]


async def test_only_the_incidents_external_indicators_are_looked_up(container: Container, seeded: Seeded) -> None:
    bus = InMemoryEventBus()
    announced: list[list[str]] = []

    async def record(event: object) -> None:
        announced.append(list(event.payload["indicators"]))  # type: ignore[attr-defined]

    provider = FakeProvider()
    enrichment = EnrichmentService([provider], uow_factory=sql_uow_factory(container.database))
    analysis = build_analysis(load_rules(), container.database, InMemoryWindowStore(), publish=bus.publish)
    bus.subscribe(EVENTS_NORMALIZED, analysis.handle)
    bus.subscribe(INCIDENTS_CHANGED, record)
    bus.subscribe(INCIDENTS_CHANGED, enrichment.handle)

    stories = list(_stories(seeded).values())
    for documents in stories:
        await bus.publish(bus_event(documents, org_id=seeded.org.id))

    assert sorted({key for keys in announced for key in keys}) == STORY_INDICATORS
    assert sorted(provider.asked) == STORY_INDICATORS, "no host, user, internal address or DNS resolver"

    # A redelivered batch links nothing new but announces again; enrichment answers from its cache.
    announced.clear()
    for documents in stories:
        await bus.publish(bus_event(documents, org_id=seeded.org.id))
    assert sorted({key for keys in announced for key in keys}) == STORY_INDICATORS
    assert sorted(provider.asked) == STORY_INDICATORS, "nothing is looked up twice while cached"
