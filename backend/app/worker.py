"""Background worker: consumes normalised events from the bus for indexing and detection.

Run with: `sentinelx worker`. Each concern has its own consumer group, so replicas share the work and a
slow index never delays detection. Deployments without Redis have no bus to consume; the API then indexes
and detects in-process (see `create_app`).
"""

from __future__ import annotations

import asyncio
import logging
import signal
import socket
from collections.abc import Coroutine
from contextlib import suppress
from typing import Any

from redis.asyncio import Redis

from app.core.config import Settings, get_settings
from app.core.db.session import Database
from app.core.events.redis_streams import RedisStreamsEventBus
from app.core.events.topics import EVENTS_NORMALIZED
from app.core.observability.logging import configure_logging
from app.modules.detection.application.detection_service import DetectionService
from app.modules.detection.infrastructure.rule_loader import load_rules
from app.modules.detection.infrastructure.unit_of_work import sql_uow_factory
from app.modules.detection.infrastructure.window_store import RedisWindowStore
from app.modules.ingestion.application.indexing_service import IndexingService
from app.modules.ingestion.infrastructure.opensearch_store import event_store_from_settings

logger = logging.getLogger(__name__)

INDEXER_GROUP = "indexer"
DETECTION_GROUP = "detection"


def _install_stop_handlers(stop: asyncio.Event) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:  # Windows
            signal.signal(sig, lambda *_: stop.set())


async def run_worker(settings: Settings | None = None) -> int:
    settings = settings or get_settings()
    configure_logging(level=settings.log_level, json_output=settings.log_json)

    if not settings.redis_url:
        logger.error("the worker consumes the Redis Streams bus; set SENTINELX_REDIS_URL")
        return 1
    rules = load_rules()
    store = event_store_from_settings(settings)
    if store is None:
        logger.warning("no event store configured (SENTINELX_OPENSEARCH_URL): detection only, events not indexed")

    redis = Redis.from_url(settings.redis_url)
    bus = RedisStreamsEventBus(redis)
    database = Database(settings.database_url)
    stop = asyncio.Event()
    _install_stop_handlers(stop)
    consumer = f"{socket.gethostname()}-{id(stop):x}"

    loops: list[Coroutine[Any, Any, None]] = []
    if store is not None:
        await store.ensure_ready()
        loops.append(
            bus.run(
                EVENTS_NORMALIZED,
                group=INDEXER_GROUP,
                consumer=consumer,
                handler=IndexingService(store).handle,
                stop=stop,
            )
        )
    detection = DetectionService(rules, uow_factory=sql_uow_factory(database), windows=RedisWindowStore(redis))
    loops.append(
        bus.run(EVENTS_NORMALIZED, group=DETECTION_GROUP, consumer=consumer, handler=detection.handle, stop=stop)
    )

    logger.info(
        "worker started",
        extra={"consumer": consumer, "indexing": store is not None, "rules": len(rules.all())},
    )
    try:
        await asyncio.gather(*loops)
    finally:
        if store is not None:
            with suppress(Exception):
                await store.aclose()
        await database.dispose()
        await redis.aclose()
    logger.info("worker stopped")
    return 0


def main() -> int:
    return asyncio.run(run_worker())


if __name__ == "__main__":
    raise SystemExit(main())
