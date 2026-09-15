"""Fixed-window rate limiting (docs/07 §7), Redis-backed so limits hold across API replicas."""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from typing import Protocol

from redis.asyncio import Redis


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int


class RateLimiter(Protocol):
    async def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitDecision: ...


def _digest(key: str) -> str:
    # Keys often embed emails/IPs; never store them in clear text in the cache.
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _decide(count: int, limit: int, ttl: int) -> RateLimitDecision:
    allowed = count <= limit
    return RateLimitDecision(
        allowed=allowed,
        limit=limit,
        remaining=max(0, limit - count),
        retry_after_seconds=0 if allowed else max(1, ttl),
    )


class RedisRateLimiter:
    def __init__(self, redis: Redis, *, prefix: str = "sx:rl:") -> None:
        self._redis = redis
        self._prefix = prefix

    async def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitDecision:
        redis_key = self._prefix + _digest(key)
        async with self._redis.pipeline(transaction=True) as pipe:
            pipe.set(redis_key, 0, ex=window_seconds, nx=True)
            pipe.incr(redis_key)
            pipe.ttl(redis_key)
            _, count, ttl = await pipe.execute()
        return _decide(int(count), limit, int(ttl))


class InMemoryRateLimiter:
    """Single-process fallback for development and tests (production requires Redis)."""

    def __init__(self) -> None:
        self._windows: dict[str, tuple[float, int]] = {}

    async def hit(self, key: str, *, limit: int, window_seconds: int) -> RateLimitDecision:
        now = time.monotonic()
        digest = _digest(key)
        started, count = self._windows.get(digest, (now, 0))
        if now - started >= window_seconds:
            started, count = now, 0
        count += 1
        self._windows[digest] = (started, count)
        remaining_window = int(window_seconds - (now - started)) or 1
        return _decide(count, limit, remaining_window)
