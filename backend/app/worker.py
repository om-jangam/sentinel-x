"""Indexer worker: consumes normalised events from the bus and writes them to the event store.

Run with: `sentinelx worker`. Deployments without Redis have no bus to consume, so the API indexes
in-process instead (see `create_app`).
"""

from __future__ import annotations

import asyncio
import logging
import signal
import socket
from contextlib import suppress

from redis.asyncio import Redis

from app.core.config import Settings, get_settings
from app.core.events.redis_streams import RedisStreamsEventBus
from app.core.events.topics import EVENTS_NORMALIZED
from app.core.observability.logging import configure_logging
from app.modules.ingestion.application.indexing_service import IndexingService
from app.modules.ingestion.infrastructure.opensearch_store import event_store_from_settings

logger = logging.getLogger(__name__)

CONSUMER_GROUP = "indexer"


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

    store = event_store_from_settings(settings)
    if store is None:
        logger.error("the worker needs an event store; set SENTINELX_OPENSEARCH_URL")
        return 1
    if not settings.redis_url:
        logger.error("the worker consumes the Redis Streams bus; set SENTINELX_REDIS_URL")
        return 1

    redis = Redis.from_url(settings.redis_url)
    bus = RedisStreamsEventBus(redis)
    stop = asyncio.Event()
    _install_stop_handlers(stop)

    await store.ensure_ready()
    consumer = f"{socket.gethostname()}-{id(stop):x}"
    logger.info("indexer worker started", extra={"consumer": consumer, "topic": EVENTS_NORMALIZED})
    try:
        await bus.run(
            EVENTS_NORMALIZED,
            group=CONSUMER_GROUP,
            consumer=consumer,
            handler=IndexingService(store).handle,
            stop=stop,
        )
    finally:
        with suppress(Exception):
            await store.aclose()
        await redis.aclose()
    logger.info("indexer worker stopped")
    return 0


def main() -> int:
    return asyncio.run(run_worker())


if __name__ == "__main__":
    raise SystemExit(main())
