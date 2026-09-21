"""The production detection path: Redis Streams consumer group → rules → Redis windows → findings in SQL.

The worker process wires exactly these pieces (`app/worker.py`); its own glue — signal handling and running
the indexer and detection loops side by side — is not exercised here.
"""

from __future__ import annotations

import fakeredis.aioredis

from app.conftest import Seeded
from app.core.container import Container
from app.core.events.redis_streams import RedisStreamsEventBus
from app.core.events.topics import EVENTS_NORMALIZED
from app.modules.detection.application.detection_service import DetectionService
from app.modules.detection.domain.findings import FindingQuery
from app.modules.detection.infrastructure.rule_loader import load_rules
from app.modules.detection.infrastructure.unit_of_work import SqlDetectionUnitOfWork, sql_uow_factory
from app.modules.detection.infrastructure.window_store import RedisWindowStore
from app.modules.detection.tests.conftest import bus_event, sample_documents

WINDOWS_TITLES = {
    "Burst of authentication failures for one account from one source",
    "PowerShell started with an encoded command",
    "whoami used to list privileges or groups",
    "net.exe lists the Domain Admins group",
}


async def test_detection_consumes_the_stream_and_persists_findings(container: Container, seeded: Seeded) -> None:
    redis = fakeredis.aioredis.FakeRedis()
    bus = RedisStreamsEventBus(redis)
    await bus.ensure_group(EVENTS_NORMALIZED, "detection")
    detection = DetectionService(
        load_rules(), uow_factory=sql_uow_factory(container.database), windows=RedisWindowStore(redis)
    )
    documents = sample_documents("windows_security.jsonl", "windows_security", org_id=seeded.org.id)

    async def drain() -> int:
        return await bus.consume_once(
            EVENTS_NORMALIZED, group="detection", consumer="test", handler=detection.handle, block_ms=1
        )

    # The same batch published twice, as a producer retry would: one set of findings.
    for _ in range(2):
        await bus.publish(bus_event(documents, org_id=seeded.org.id))
        assert await drain() == 1

    async with container.database.sessionmaker() as session:
        page = await SqlDetectionUnitOfWork(session).findings.search(seeded.org.id, FindingQuery(limit=50))
    assert sorted(finding.rule_title for finding in page.items) == sorted(WINDOWS_TITLES)
    delivered = {doc["sx"]["event_uid"] for doc in documents}
    for finding in page.items:
        assert set(finding.evidence) <= delivered
