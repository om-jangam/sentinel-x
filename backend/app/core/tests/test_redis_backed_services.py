"""Rate limiter, token blocklist and event bus — in-memory and Redis implementations share contracts."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import timedelta
from uuid import uuid4

import fakeredis
import pytest
from redis.asyncio import Redis

from app.core.clock import utcnow
from app.core.events.bus import Event, InMemoryEventBus
from app.core.events.redis_streams import RedisStreamsEventBus
from app.core.security.blocklist import InMemoryTokenBlocklist, RedisTokenBlocklist, TokenBlocklist
from app.core.security.ratelimit import InMemoryRateLimiter, RateLimiter, RedisRateLimiter


@pytest.fixture
async def redis() -> AsyncIterator[Redis]:
    client = fakeredis.FakeAsyncRedis()
    yield client
    await client.aclose()


@pytest.fixture(params=["memory", "redis"])
def rate_limiter(request: pytest.FixtureRequest, redis: Redis) -> RateLimiter:
    return InMemoryRateLimiter() if request.param == "memory" else RedisRateLimiter(redis)


@pytest.fixture(params=["memory", "redis"])
def blocklist(request: pytest.FixtureRequest, redis: Redis) -> TokenBlocklist:
    return InMemoryTokenBlocklist() if request.param == "memory" else RedisTokenBlocklist(redis)


async def test_rate_limiter_blocks_after_limit(rate_limiter: RateLimiter) -> None:
    decisions = [await rate_limiter.hit("login:a", limit=3, window_seconds=60) for _ in range(4)]
    assert [d.allowed for d in decisions] == [True, True, True, False]
    assert decisions[2].remaining == 0
    assert decisions[3].retry_after_seconds >= 1
    assert (await rate_limiter.hit("login:b", limit=3, window_seconds=60)).allowed, "keys are independent"


async def test_redis_rate_limiter_never_stores_raw_keys(redis: Redis) -> None:
    await RedisRateLimiter(redis).hit("login:account:alice@example.com", limit=3, window_seconds=60)
    keys = [k.decode() if isinstance(k, bytes) else k for k in await redis.keys("*")]
    assert keys
    assert not any("alice" in k for k in keys)


async def test_blocklist(blocklist: TokenBlocklist) -> None:
    await blocklist.block("jti-live", utcnow() + timedelta(minutes=5))
    await blocklist.block("jti-dead", utcnow() - timedelta(minutes=5))
    assert await blocklist.is_blocked("jti-live")
    assert not await blocklist.is_blocked("jti-dead"), "already-expired tokens need no entry"
    assert not await blocklist.is_blocked("jti-other")


def test_event_json_round_trip() -> None:
    event = Event(topic="user.created", payload={"id": "1"}, org_id=uuid4(), correlation_id="c-1")
    assert Event.from_json(event.to_json()) == event


async def test_in_memory_bus_isolates_failing_handlers() -> None:
    bus = InMemoryEventBus()
    received: list[Event] = []

    async def broken(_: Event) -> None:
        raise RuntimeError("boom")

    async def good(event: Event) -> None:
        received.append(event)

    bus.subscribe("t", broken)
    bus.subscribe("t", good)
    await bus.publish(Event(topic="t", payload={}))
    assert len(received) == 1


async def test_redis_streams_bus_acks_success_and_keeps_failures_pending(redis: Redis) -> None:
    bus = RedisStreamsEventBus(redis)
    await bus.ensure_group("incident.opened", "cases")
    await bus.ensure_group("incident.opened", "cases")  # idempotent
    await bus.publish(Event(topic="incident.opened", payload={"n": 1}))
    await bus.publish(Event(topic="incident.opened", payload={"n": 2}))

    seen: list[int] = []

    async def handler(event: Event) -> None:
        if event.payload["n"] == 2:
            raise RuntimeError("transient")
        seen.append(event.payload["n"])

    processed = await bus.consume_once("incident.opened", group="cases", consumer="w1", handler=handler, block_ms=10)
    assert processed == 1
    assert seen == [1]
    pending = await redis.xpending(bus.stream_name("incident.opened"), "cases")
    assert pending["pending"] == 1


async def test_redis_streams_run_stops_on_signal(redis: Redis) -> None:
    bus = RedisStreamsEventBus(redis)
    stop = asyncio.Event()
    got: list[Event] = []

    async def handler(event: Event) -> None:
        got.append(event)
        stop.set()

    # fakeredis implements BLOCK by polling synchronously, so keep the block window tiny.
    task = asyncio.create_task(bus.run("t", group="g", consumer="c", handler=handler, stop=stop, block_ms=1))
    await asyncio.sleep(0.05)
    await bus.publish(Event(topic="t", payload={}))
    await asyncio.wait_for(task, timeout=5)
    assert len(got) == 1
