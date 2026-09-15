"""`jti` blocklist for immediate access-token revocation (docs/07 §2)."""

from __future__ import annotations

import math
import time
from datetime import datetime
from typing import Protocol

from redis.asyncio import Redis

from app.core.clock import utcnow


class TokenBlocklist(Protocol):
    async def block(self, jti: str, expires_at: datetime) -> None: ...

    async def is_blocked(self, jti: str) -> bool: ...


class RedisTokenBlocklist:
    """Entries expire with the token itself, so the set never grows unbounded."""

    def __init__(self, redis: Redis, *, prefix: str = "sx:jti:") -> None:
        self._redis = redis
        self._prefix = prefix

    async def block(self, jti: str, expires_at: datetime) -> None:
        ttl = math.ceil((expires_at - utcnow()).total_seconds())
        if ttl > 0:
            await self._redis.set(self._prefix + jti, "1", ex=ttl)

    async def is_blocked(self, jti: str) -> bool:
        return bool(await self._redis.exists(self._prefix + jti))


class InMemoryTokenBlocklist:
    """Single-process fallback for development and tests (production requires Redis)."""

    def __init__(self) -> None:
        self._entries: dict[str, float] = {}

    async def block(self, jti: str, expires_at: datetime) -> None:
        self._entries[jti] = expires_at.timestamp()

    async def is_blocked(self, jti: str) -> bool:
        now = time.time()
        self._entries = {k: exp for k, exp in self._entries.items() if exp > now}
        return jti in self._entries
