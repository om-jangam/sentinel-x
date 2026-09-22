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

    A message is acknowledged only after its handler succeeds. A failed message stays pending, and once it
    has been idle for `reclaim_idle_ms` any consumer of the group claims it and tries again. That covers a
    handler error and a consumer that died mid-batch, so handlers must be idempotent. After
    `max_deliveries` attempts the message moves to `<prefix>dead:<topic>` and is acknowledged: one poison
    message never blocks the rest, and it is kept for inspection instead of being retried forever.
    """

    def __init__(
        self,
        redis: Redis,
        *,
        stream_prefix: str = "sx:events:",
        max_len: int = 100_000,
        reclaim_idle_ms: int = 30_000,
        max_deliveries: int = 5,
    ) -> None:
        self._redis = redis
        self._prefix = stream_prefix
        self._max_len = max_len
        self._reclaim_idle_ms = reclaim_idle_ms
        self._max_deliveries = max_deliveries

    def dead_letter_stream(self, topic: str) -> str:
        return f"{self._prefix}dead:{topic}"

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

    async def _reclaim(
        self, stream: str, group: str, consumer: str, count: int
    ) -> list[tuple[bytes, dict[bytes, bytes]]]:
        """Pending messages idle long enough to be retried, now owned by this consumer."""
        reply = await self._redis.xautoclaim(
            stream, group, consumer, min_idle_time=self._reclaim_idle_ms, start_id="0-0", count=count
        )
        messages = reply[1] if isinstance(reply, list | tuple) and len(reply) > 1 else []
        return [(message_id, fields) for message_id, fields in messages if fields]

    async def _deliveries(self, stream: str, group: str, message_id: bytes) -> int:
        entries = await self._redis.xpending_range(stream, group, min=message_id, max=message_id, count=1)
        return int(entries[0]["times_delivered"]) if entries else 1

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
        batch = await self._reclaim(stream, group, consumer, count)
        if not batch:
            response = cast(
                StreamResponse | None,
                await self._redis.xreadgroup(group, consumer, {stream: ">"}, count=count, block=block_ms),
            )
            batch = [message for _stream, messages in response or [] for message in messages]
        processed = 0
        for message_id, fields in batch:
            raw = fields.get(b"event")
            if raw is None:
                logger.error("malformed stream message; acknowledging to drop it", extra={"topic": topic})
                await self._redis.xack(stream, group, message_id)
                continue
            try:
                await handler(Event.from_json(raw))
            except Exception:
                deliveries = await self._deliveries(stream, group, message_id)
                if deliveries >= self._max_deliveries:
                    await self._redis.xadd(
                        self.dead_letter_stream(topic),
                        {"event": raw, "group": group, "deliveries": str(deliveries)},
                        maxlen=self._max_len,
                        approximate=True,
                    )
                    await self._redis.xack(stream, group, message_id)
                    logger.exception(
                        "event handler failed repeatedly; moved to the dead-letter stream",
                        extra={"topic": topic, "group": group, "deliveries": deliveries},
                    )
                else:
                    logger.exception(
                        "event handler failed; the message stays pending and will be retried",
                        extra={"topic": topic, "group": group, "deliveries": deliveries},
                    )
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
