"""Redis Streams transport — the MVP bus (docs/02 §5)."""

from __future__ import annotations

import asyncio
import logging
from typing import cast

from redis.asyncio import Redis
from redis.exceptions import ResponseError

from app.core.events.bus import Event, EventHandler

logger = logging.getLogger(__name__)

# XREADGROUP reply shape: [(stream, [(message_id, {field: value})])]
StreamResponse = list[tuple[bytes, list[tuple[bytes, dict[bytes, bytes]]]]]


class RedisStreamsEventBus:
    """At-least-once delivery via consumer groups.

    A message is acknowledged only after its handler succeeds; failures stay in the group's
    pending list for redelivery, so handlers must be idempotent (key on `Event.id`).
    """

    def __init__(self, redis: Redis, *, stream_prefix: str = "sx:events:", max_len: int = 100_000) -> None:
        self._redis = redis
        self._prefix = stream_prefix
        self._max_len = max_len

    def stream_name(self, topic: str) -> str:
        return self._prefix + topic

    async def publish(self, event: Event) -> None:
        await self._redis.xadd(
            self.stream_name(event.topic),
            {"event": event.to_json()},
            maxlen=self._max_len,
            approximate=True,
        )

    async def ensure_group(self, topic: str, group: str) -> None:
        try:
            await self._redis.xgroup_create(self.stream_name(topic), group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    async def consume_once(
        self,
        topic: str,
        *,
        group: str,
        consumer: str,
        handler: EventHandler,
        count: int = 100,
        block_ms: int = 1000,
    ) -> int:
        stream = self.stream_name(topic)
        response = cast(
            StreamResponse | None,
            await self._redis.xreadgroup(group, consumer, {stream: ">"}, count=count, block=block_ms),
        )
        processed = 0
        for _stream, messages in response or []:
            for message_id, fields in messages:
                raw = fields.get(b"event")
                if raw is None:
                    logger.error("malformed stream message; acknowledging to drop it", extra={"topic": topic})
                    await self._redis.xack(stream, group, message_id)
                    continue
                try:
                    await handler(Event.from_json(raw))
                except Exception:
                    logger.exception("event handler failed; leaving message pending", extra={"topic": topic})
                    continue
                await self._redis.xack(stream, group, message_id)
                processed += 1
        return processed

    async def run(
        self,
        topic: str,
        *,
        group: str,
        consumer: str,
        handler: EventHandler,
        stop: asyncio.Event,
        block_ms: int = 1000,
    ) -> None:
        """Consume until `stop` is set; shutdown latency is bounded by `block_ms`."""
        await self.ensure_group(topic, group)
        while not stop.is_set():
            await self.consume_once(topic, group=group, consumer=consumer, handler=handler, block_ms=block_ms)
            await asyncio.sleep(0)  # yield even when a transport returns immediately
